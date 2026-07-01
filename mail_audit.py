#!/usr/bin/env python3
"""
mail_audit.py — LLM-in-the-loop anomaly audit for the Postfix/Dovecot mail stack.

Collects container health,
logs, and resource state, redacts secrets, then ships a JSON snapshot over
Tailscale to Ollama running on a heavier node (e.g. the T560) for
classification. Every run is appended to a JSONL file with a blank
`ground_truth_label` field for manual labelling later — that labelled log
is what turns this into actual precision/recall data for the research
report (section 4.3) rather than just a monitoring script.

Usage:
    python3 mail_audit.py --once
    python3 mail_audit.py --once --ollama-host http://your-ollama-node:11434
    python3 mail_audit.py --loop --interval 600

Run via cron or a systemd timer for continuous data collection:
    */10 * * * * /usr/bin/python3 /path/to/mail_audit.py --once
"""

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration (override via CLI flags)
# --------------------------------------------------------------------------

DEFAULT_OLLAMA_HOST = "http://localhost:11434"  # override with --ollama-host
DEFAULT_MODEL = "llama3.1"
DEFAULT_LOG_PATH = Path.home() / "services" / "mail" / "audit_log.jsonl"
CONTAINERS = ["dovecot", "postfix"]
LOG_WINDOW = "10m"          # docker logs --since window
LOG_TAIL_LINES = 200        # cap per container to keep payload small
TCP_CHECK_PORTS = [25, 587, 993]
TCP_CHECK_TIMEOUT = 2.0
VMAIL_PATH = "/home/vmail"

# --------------------------------------------------------------------------
# Secret redaction
# --------------------------------------------------------------------------

# Generic key=value / key
_SENSITIVE_KV = re.compile(
    r"(?i)\b(pass(word)?|secret|api[_-]?key|token|jwt)\b\s*[:=]\s*\S+"
)
# Mailgun-style sasl_passwd line: [smtp.mailgun.org]:587 user:key
_MAILGUN_SASL = re.compile(r"(?i)(\[smtp\.mailgun\.org\]:\d+)\s+\S+:\S+")
# Long hex/base64-looking tokens (32+ chars), e.g. JWT secrets, API keys
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")


def redact(text: str) -> str:
    text = _SENSITIVE_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _MAILGUN_SASL.sub(r"\1 [REDACTED]", text)
    text = _LONG_TOKEN.sub("[REDACTED_TOKEN]", text)
    return text


# --------------------------------------------------------------------------
# Collection helpers
# --------------------------------------------------------------------------
def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Universal execution engine for system commands."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out: {' '.join(cmd)}"


def service_state(service: str) -> dict:
    # Checks systemctl for the service status
    rc, out, err = run_cmd(["systemctl", "is-active", service])
    # rc == 0 means active, others mean inactive/failed
    return {
        "running": rc == 0,
        "status": out.strip(),
        "error": err if rc != 0 else None
    }

def fetch_mail_logs() -> str:
    # Reads the last 50 lines of the real mail log
    rc, out, err = run_cmd(["sudo", "tail", "-n", "50", "/var/log/maillog"])
    return redact(out)


def resource_snapshot() -> dict:
    """Host-level load, memory, and disk usage for the vmail volume."""
    _, load_out, _ = run_cmd(["uptime"])

    mem: dict = {}
    rc, out, _ = run_cmd(["free", "-m"])
    if rc == 0:
        lines = out.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 7:
                mem = {
                    "total_mb": int(parts[1]),
                    "used_mb": int(parts[2]),
                    "free_mb": int(parts[3]),
                    "available_mb": int(parts[6]),
                }

    disk: dict = {}
    rc, out, _ = run_cmd(["df", "-h", VMAIL_PATH])
    if rc == 0:
        lines = out.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk = {
                    "mount": VMAIL_PATH,
                    "size": parts[1],
                    "used": parts[2],
                    "avail": parts[3],
                    "use_pct": parts[4],
                }

    return {
        "load_avg": load_out,
        "memory": mem,
        "disk_vmail": disk,
    }


def port_checks() -> dict:
    """TCP connect check against the mail stack's expected listening ports."""
    results = {}
    for port in TCP_CHECK_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CHECK_TIMEOUT)
        try:
            sock.connect(("127.0.0.1", port))
            results[str(port)] = "open"
        except OSError as exc:
            results[str(port)] = f"closed: {exc}"
        finally:
            sock.close()
    return results


def build_snapshot() -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "dovecot": service_state("dovecot"),
            "postfix": service_state("postfix"),
        },
        "recent_logs": fetch_mail_logs(),
        "resources": resource_snapshot(),
        "port_checks": port_checks(),
    }





# Ollama query
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an SRE anomaly classifier for a self-hosted Postfix/Dovecot mail stack.
You will receive a JSON snapshot containing container state, recent logs, resource
usage, and TCP port checks. Classify the overall health of the mail stack.


Respond with ONLY a single JSON object, no markdown fences, no commentary, in this 
exact shape:
{
  "status": "healthy" | "degraded" | "critical",
  "root_cause": "<short phrase, or 'none' if healthy>",
  "confidence": <integer 0-100>,
  "suggested_action": "<short actionable step, or 'none' if healthy>"
}"""


def query_ollama(snapshot: dict, host: str, model: str) -> dict:
    import urllib.request
    import urllib.error

    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": json.dumps(snapshot, indent=2),
        "stream": False,
        "format": "json",
    }
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status": "unknown",
            "root_cause": f"ollama_unreachable: {exc}",
            "confidence": 0,
            "suggested_action": "check Tailscale connectivity to the Ollama host",
            "_raw": None,
        }

    raw_text = body.get("response", "")
    cleaned = raw_text.strip().strip("`")
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()

    try:
        verdict = json.loads(cleaned)
        verdict["_raw"] = raw_text
        return verdict
    except json.JSONDecodeError:
        return {
            "status": "unknown",
            "root_cause": "model_response_unparseable",
            "confidence": 0,
            "suggested_action": "inspect _raw field",
            "_raw": raw_text,
        }


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def append_log(snapshot: dict, verdict: dict, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": snapshot["timestamp"],
        "verdict": {k: v for k, v in verdict.items() if k != "_raw"},
        "model_raw_response": verdict.get("_raw"),
        "snapshot": snapshot,
        "ground_truth_label": None,  # fill in by hand after the fact
    }
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run_once(ollama_host: str, model: str, log_path: Path, quiet: bool = False) -> int:
    snapshot = build_snapshot()
    verdict = query_ollama(snapshot, ollama_host, model)
    append_log(snapshot, verdict, log_path)

    if not quiet:
        ts = snapshot["timestamp"]
        status = verdict.get("status", "unknown")
        cause = verdict.get("root_cause", "n/a")
        action = verdict.get("suggested_action", "n/a")
        conf = verdict.get("confidence", "n/a")
        print(f"[{ts}] status={status} confidence={conf} root_cause={cause}")
        if status != "healthy":
            print(f"    suggested_action: {action}")

    # Exit codes useful for alerting integrations (e.g. a cron wrapper that
    # pings Uptime Kuma's push URL only on non-zero).
    return {"healthy": 0, "degraded": 1, "critical": 2}.get(
        verdict.get("status", "unknown"), 3
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run a single audit pass")
    parser.add_argument("--loop", action="store_true", help="run continuously")
    parser.add_argument("--interval", type=int, default=600, help="seconds between loop iterations")
    parser.add_argument("--ollama-host", default=DEFAULT_OLLAMA_HOST,
                         help="Ollama base URL, e.g. http://node.your-tailnet.ts.net:11434")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not args.once and not args.loop:
        args.once = True  # default behaviour

    if args.loop:
        while True:
            run_once(args.ollama_host, args.model, args.log_path, args.quiet)
            time.sleep(args.interval)
    else:
        exit_code = run_once(args.ollama_host, args.model, args.log_path, args.quiet)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
