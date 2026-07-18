#!/usr/bin/env python3
"""
mail_audit.py v2 — LLM-in-the-loop anomaly audit for the Postfix/Dovecot mail stack.
Integrated with ask agent: shares ASK_KNOWLEDGE_PATH and supports --escalate flag.

CHANGES FROM v1:
  - LOG_PATH now reads ASK_KNOWLEDGE_PATH env var (shared KB with ask agent)
  - Log records include "type": "mail_audit" for filtered recall
  - --escalate flag: on degraded/critical, prints a formatted escalation string
    to stdout so the orchestrator can pipe it directly into ask
  - Exit codes unchanged: 0=healthy, 1=degraded, 2=critical, 3=unknown

Usage:
    python3 mail_audit.py --once
    python3 mail_audit.py --once --escalate
    python3 mail_audit.py --loop --interval 600
    python3 mail_audit.py --once --ollama-host http://[HOSTNAME]:11434
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_OLLAMA_HOST   = "http://[HOSTNAME]:11434"
DEFAULT_MODEL         = "llama3.2:3b"

# INTEGRATION: reads from ASK_KNOWLEDGE_PATH env var so all three tools
# share one JSONL file. Falls back to the original path if not set.
DEFAULT_LOG_PATH = Path(
    os.environ.get(
        "ASK_KNOWLEDGE_PATH",
        str(Path.home() / "services" / "mail" / "audit_log.jsonl")
    )
)

CONTAINERS          = ["dovecot", "postfix"]
LOG_WINDOW          = "10m"
LOG_TAIL_LINES      = 200
TCP_CHECK_PORTS     = [25, 587, 993]
TCP_CHECK_TIMEOUT   = 2.0
VMAIL_PATH          = "/home/vmail"

# --------------------------------------------------------------------------
# Secret redaction
# --------------------------------------------------------------------------

_SENSITIVE_KV  = re.compile(r"(?i)\b(pass(word)?|secret|api[_-]?key|token|jwt)\b\s*[:=]\s*\S+")
_MAILGUN_SASL  = re.compile(r"(?i)(\[smtp\.mailgun\.org\]:\d+)\s+\S+:\S+")
_LONG_TOKEN    = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")


def redact(text: str) -> str:
    text = _SENSITIVE_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _MAILGUN_SASL.sub(r"\1 [REDACTED]", text)
    text = _LONG_TOKEN.sub("[REDACTED_TOKEN]", text)
    return text


# --------------------------------------------------------------------------
# Collection helpers
# --------------------------------------------------------------------------

def run_cmd(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out: {' '.join(cmd)}"

def systemd_state(service: str) -> dict:
    rc, out, _ = run_cmd(["systemctl", "is-active", service])
    status = out.strip()
    return {"running": status == "active", "systemd_status": status}

def service_logs(service: str) -> str:
    rc, out, err = run_cmd(
        ["journalctl", "-u", service,
         "--since", "2m",
         "--no-pager", "-n", "50"]
    )
    return redact(out if rc == 0 else f"[log fetch failed: {err}]")


def docker_state(container: str) -> dict:
    rc, out, err = run_cmd(["docker", "inspect", "--format", "{{json .State}}", container])
    if rc != 0:
        return {"running": False, "error": redact(err or "container not found")}
    try:
        state = json.loads(out)
        return {
            "running":       state.get("Running", False),
            "status":        state.get("Status"),
            "restart_count": state.get("RestartCount"),
            "exit_code":     state.get("ExitCode"),
            "started_at":    state.get("StartedAt"),
        }
    except json.JSONDecodeError:
        return {"running": False, "error": "could not parse docker state"}


def service_logs(service: str) -> str:
    """Fetch native systemd logs instead of Docker logs"""
    rc, out, err = run_cmd(
        ["journalctl", "-u", f"{service}.service", "--since", "10m", "--no-pager", "-n", "100"]
    )
    return redact(out if rc == 0 else f"[log fetch failed: {err}]")

def resource_snapshot() -> dict:
    _, mem,     _ = run_cmd(["free", "-m"])
    _, disk,    _ = run_cmd(["df", "-h", VMAIL_PATH])
    _, top_mem, _ = run_cmd(["bash", "-c", "ps aux --sort=-%mem | head -n 8"])
    return {"memory": mem, "disk_vmail": disk, "top_processes_by_mem": top_mem}


def tcp_check(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TCP_CHECK_TIMEOUT):
            return True
    except OSError:
        return False


def port_checks() -> dict:
    return {f"tcp_{p}_open": tcp_check("localhost", p) for p in TCP_CHECK_PORTS}


def build_snapshot() -> dict:
    return {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "containers": {
            name: {
                "state":       systemd_state(f"{name}.service"),
                "recent_logs": service_logs(f"{name}.service"),
            }
            for name in CONTAINERS
        },
        "resources":   resource_snapshot(),
        "port_checks": port_checks(),
    }



# --------------------------------------------------------------------------
# Ollama query
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an SRE anomaly classifier for a self-hosted Postfix/Dovecot mail stack running on systemd (not Docker).

You will receive a JSON snapshot with systemd service state, recent journal logs, resource usage, and TCP port checks.

CLASSIFICATION RULES — apply in this strict priority order:
1. If BOTH services have systemd_status="active" AND all TCP ports (25, 587, 993) are open → status MUST be "healthy"
2. If ANY service has systemd_status="inactive", "failed", or "dead" → status MUST be "critical"
3. If services are active but some ports are closed → "degraded"
4. Recent logs may contain historical stop/start/restart entries. A service that was recently restarted but is NOW active with open ports is HEALTHY. Do NOT downgrade a currently-active service based on past log events.

Respond with ONLY a single JSON object, no markdown fences:
{
  "status": "healthy" | "degraded" | "critical",
  "root_cause": "<short phrase, or 'none' if healthy>",
  "confidence": <integer 0-100>,
  "suggested_action": "<short actionable step, or 'none' if healthy>"
}"""

def query_ollama(snapshot: dict, host: str, model: str) -> dict:
    import urllib.request, urllib.error

    payload = {
        "model":  model,
        "system": SYSTEM_PROMPT,
        "prompt": json.dumps(snapshot, indent=2),
        "stream": False,
        "format": "json",
    }
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode())
    except Exception as exc:
        return {
            "status":           "unknown",
            "root_cause":       f"ollama_unreachable: {exc}",
            "confidence":       0,
            "suggested_action": "check Tailscale connectivity to the Ollama host",
        }

    raw = body.get("response", "")
    cleaned = raw.strip().strip("`")
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()
    try:
        verdict = json.loads(cleaned)
        verdict["_raw"] = raw
        return verdict
    except json.JSONDecodeError:
        return {
            "status":           "unknown",
            "root_cause":       "model_response_unparseable",
            "confidence":       0,
            "suggested_action": "inspect _raw field",
            "_raw":             raw,
        }


# --------------------------------------------------------------------------
# Logging — shared KB format
# --------------------------------------------------------------------------

def append_log(snapshot: dict, verdict: dict, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # INTEGRATION: "type" field lets ask --recall filter by source
    record = {
        "timestamp":          snapshot["timestamp"],
        "type":               "mail_audit",
        "hostname":           subprocess.getoutput("hostname"),
        "model":              DEFAULT_MODEL,
        "input":              f"mail_audit: {verdict.get('status','unknown')} — {verdict.get('root_cause','n/a')}",
        "response":           verdict.get("suggested_action", "none"),
        "verdict":            {k: v for k, v in verdict.items() if k != "_raw"},
        "model_raw_response": verdict.get("_raw"),
        "snapshot":           snapshot,
        "ground_truth_label": None,
    }
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Escalation output — designed to be piped into ask
# --------------------------------------------------------------------------

def escalation_string(snapshot: dict, verdict: dict) -> str:
    """
    Formats a rich, keyword-dense summary of the audit finding.
    Designed to pipe directly to ask so it can:
      - Trigger correct model routing (postfix/dovecot keywords → llama3.2:3b)
      - Cross-reference against the knowledge base
      - Provide a second-opinion diagnosis
    """
    ports = snapshot.get("port_checks", {})
    port_summary = " ".join(
        f"{p.replace('tcp_', '').replace('_open', '')}:{'open' if v else 'CLOSED'}"
        for p, v in ports.items()
    )
    containers = snapshot.get("containers", {})
    container_summary = " ".join(
        f"{name}:{'running' if c['state'].get('running') else 'STOPPED'}"
        for name, c in containers.items()
    )
    return (
        f"[mail_audit escalation] STATUS={verdict.get('status','unknown').upper()} "
        f"CONFIDENCE={verdict.get('confidence', 0)}% "
        f"CAUSE={verdict.get('root_cause', 'unknown')} "
        f"PORTS=[{port_summary}] "
        f"CONTAINERS=[{container_summary}] "
        f"ACTION_NEEDED={verdict.get('suggested_action', 'none')} "
        f"HOST={subprocess.getoutput('hostname')} "
        f"postfix dovecot mail-server"
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run_once(args) -> int:
    snapshot = build_snapshot()
    verdict  = query_ollama(snapshot, args.ollama_host, args.model)
    append_log(snapshot, verdict, args.log_path)

    status = verdict.get("status", "unknown")
    cause  = verdict.get("root_cause", "n/a")
    action = verdict.get("suggested_action", "n/a")
    conf   = verdict.get("confidence", "n/a")

    if not args.quiet:
        ts = snapshot["timestamp"]
        print(f"[{ts}] status={status} confidence={conf} root_cause={cause}")
        if status != "healthy":
            print(f"    suggested_action: {action}")

    # INTEGRATION: --escalate prints the escalation string to stdout
    # so the orchestrator can pipe it to ask for deeper analysis
    exit_code = {"healthy": 0, "degraded": 1, "critical": 2}.get(status, 3)
    if args.escalate and exit_code > 0:
        print(escalation_string(snapshot, verdict))

    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once",       action="store_true")
    parser.add_argument("--loop",       action="store_true")
    parser.add_argument("--interval",   type=int, default=600)
    parser.add_argument("--ollama-host", default=DEFAULT_OLLAMA_HOST)
    parser.add_argument("--model",      default=DEFAULT_MODEL)
    parser.add_argument("--log-path",   type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--quiet",      action="store_true")
    # INTEGRATION: escalation flag
    parser.add_argument("--escalate",   action="store_true",
                        help="On degraded/critical, print escalation string to stdout for piping to ask")
    args = parser.parse_args()

    if not args.once and not args.loop:
        args.once = True

    if args.loop:
        while True:
            run_once(args)
            time.sleep(args.interval)
    else:
        sys.exit(run_once(args))


if __name__ == "__main__":
    main()
