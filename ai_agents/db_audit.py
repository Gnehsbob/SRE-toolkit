#!/usr/bin/env python3
from __future__ import annotations
"""
db_audit.py v2 — LLM-in-the-loop slow-query auditor for MariaDB.
Integrated with ask agent: shares ASK_KNOWLEDGE_PATH and supports --escalate flag.

CHANGES FROM v1:
  - LOG_PATH now reads ASK_KNOWLEDGE_PATH env var (shared KB with ask agent)
  - Log records include "type": "db_audit" for filtered recall
  - --escalate flag: on High-impact findings, prints escalation string to stdout
  - STATE_PATH unchanged (separate state tracking file, not part of shared KB)

Prerequisites:
    1. slow_query_log enabled:
         sudo mariadb -e "SET GLOBAL slow_query_log = 'ON';"
         sudo mariadb -e "SET GLOBAL long_query_time = 0.5;"
         sudo mariadb -e "SET GLOBAL log_queries_not_using_indexes = 'ON';"
    2. Read-only monitoring credentials in ~/.my.cnf (chmod 600):
         [client]
         user=aiops_monitor
         password=********
    3. Run WITHOUT sudo — sudo resolves $HOME as /root, breaking ~/.my.cnf lookup

Usage:
    python3 db_audit.py --once
    python3 db_audit.py --once --escalate
    python3 db_audit.py --loop --interval 300
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_OLLAMA_HOST = "http://[HOSTNAME]:11434"
DEFAULT_MODEL       = "llama3.2:3b"
DEFAULT_SLOW_LOG    = Path("/var/lib/mysql/[HOSTNAME]-slow.log")
DEFAULT_STATE_PATH  = Path.home() / "services" / "db_audit_state.json"
DEFAULT_MY_CNF      = Path.home() / ".my.cnf"
MAX_QUERIES_PER_RUN = 10

# INTEGRATION: reads from ASK_KNOWLEDGE_PATH env var — shared KB with ask agent
DEFAULT_LOG_PATH = Path(
    os.environ.get(
        "ASK_KNOWLEDGE_PATH",
        str(Path.home() / "services" / "db_audit_log.jsonl")
    )
)

# --------------------------------------------------------------------------
# Secret redaction
# --------------------------------------------------------------------------

_SENSITIVE_KV = re.compile(r"(?i)\b(pass(word)?|secret|api[_-]?key|token)\b\s*[:=]\s*\S+")
_LONG_TOKEN   = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")


def redact(text: str) -> str:
    text = _SENSITIVE_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _LONG_TOKEN.sub("[REDACTED_TOKEN]", text)
    return text


# --------------------------------------------------------------------------
# MariaDB helpers
# --------------------------------------------------------------------------

def run_mysql(my_cnf: Path, sql: str, timeout: int = 15) -> tuple[int, str, str]:
    cmd = ["mysql", f"--defaults-extra-file={my_cnf}", "-N", "-e", sql]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "mysql client not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out: {sql[:80]}"


def get_slow_query_count(my_cnf: Path) -> int | None:
    rc, out, _ = run_mysql(my_cnf, "SHOW GLOBAL STATUS LIKE 'Slow_queries';")
    if rc != 0 or not out:
        return None
    try:
        return int(out.split()[-1])
    except (IndexError, ValueError):
        return None


def run_explain(my_cnf: Path, sql_text: str) -> str:
    cleaned = sql_text.strip().rstrip(";")
    rc, out, err = run_mysql(my_cnf, f"EXPLAIN {cleaned};")
    return out if rc == 0 else f"[EXPLAIN failed: {redact(err)}]"


def show_create_table(my_cnf: Path, table: str) -> str:
    if not re.match(r"^[A-Za-z0-9_]+$", table):
        return f"[skipped: unsafe table name '{table}']"
    rc, out, err = run_mysql(my_cnf, f"SHOW CREATE TABLE `{table}`;")
    return out if rc == 0 else f"[SHOW CREATE TABLE failed: {redact(err)}]"


_TABLE_REF = re.compile(r"(?i)\b(?:FROM|JOIN)\s+`?([A-Za-z0-9_]+)`?")


def extract_tables(sql_text: str) -> list[str]:
    return sorted({m.group(1) for m in _TABLE_REF.finditer(sql_text)})


# --------------------------------------------------------------------------
# Slow log parsing
# --------------------------------------------------------------------------

_QUERY_TIME_RE = re.compile(
    r"# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)"
)


def read_new_log_bytes(log_path: Path, last_offset: int) -> tuple[str, int]:
    if not log_path.exists():
        return "", last_offset
    size = log_path.stat().st_size
    if size < last_offset:
        last_offset = 0
    with log_path.open("r", errors="replace") as f:
        f.seek(last_offset)
        data = f.read()
    return data, size


def parse_slow_log(text: str) -> list[dict]:
    entries = []
    blocks  = re.split(r"(?=^# Time: )", text, flags=re.MULTILINE)
    for block in blocks:
        m = _QUERY_TIME_RE.search(block)
        if not m:
            continue
        lines    = block.splitlines()
        sql_lines = [
            ln for ln in lines
            if ln.strip()
            and not ln.startswith("#")
            and not ln.strip().lower().startswith("set timestamp")
            and not ln.strip().lower().startswith("use ")
        ]
        sql_text = " ".join(sql_lines).strip()
        if not sql_text:
            continue
        entries.append({
            "query_time":     float(m.group(1)),
            "lock_time":      float(m.group(2)),
            "rows_sent":      int(m.group(3)),
            "rows_examined":  int(m.group(4)),
            "sql":            redact(sql_text),
        })
    return entries


def normalize_signature(sql_text: str) -> str:
    sig = re.sub(r"'[^']*'", "?", sql_text)
    sig = re.sub(r"\b\d+\b", "?", sig)
    return re.sub(r"\s+", " ", sig).strip().lower()


def dedupe_entries(entries: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for e in entries:
        sig = normalize_signature(e["sql"])
        if sig not in grouped:
            grouped[sig] = {**e, "occurrences": 1}
        else:
            grouped[sig]["occurrences"] += 1
            grouped[sig]["query_time"]   = max(grouped[sig]["query_time"], e["query_time"])
    return sorted(grouped.values(), key=lambda e: e["query_time"], reverse=True)


# --------------------------------------------------------------------------
# Ollama query
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a Database Administrator analyzing slow queries on a MariaDB server.
You will receive a JSON object containing: the slow query text, execution metrics
(query_time, lock_time, rows_sent, rows_examined, occurrences), the EXPLAIN plan,
and CREATE TABLE statements for the tables involved.

A large gap between rows_examined and rows_sent, or EXPLAIN showing type=ALL on a
sizeable table, indicates a missing or unused index.

Respond with ONLY a single JSON object, no markdown fences:
{
  "missing_index_suggestion": "<CREATE INDEX statement, or 'none'>",
  "rationale": "<short technical explanation grounded in EXPLAIN and schema>",
  "estimated_impact": "Low" | "Medium" | "High",
  "alternative_optimization": "<query rewrite or config suggestion, or 'none'>"
}"""


def query_ollama(payload: dict, host: str, model: str) -> dict:
    import urllib.request, urllib.error

    body = {
        "model":  model,
        "system": SYSTEM_PROMPT,
        "prompt": json.dumps(payload, indent=2),
        "stream": False,
        "format": "json",
    }
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp_body = json.loads(resp.read().decode())
    except Exception as exc:
        return {
            "missing_index_suggestion": "unknown",
            "rationale":                f"ollama_unreachable: {exc}",
            "estimated_impact":         "Low",
            "alternative_optimization": "none",
        }

    raw = resp_body.get("response", "")
    cleaned = raw.strip().strip("`")
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()
    try:
        verdict = json.loads(cleaned)
        verdict["_raw"] = raw
        return verdict
    except json.JSONDecodeError:
        return {
            "missing_index_suggestion": "unknown",
            "rationale":                "model_response_unparseable",
            "estimated_impact":         "Low",
            "alternative_optimization": "none",
            "_raw":                     raw,
        }


# --------------------------------------------------------------------------
# Logging — shared KB format
# --------------------------------------------------------------------------

def load_state(state_path: Path) -> dict:
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except json.JSONDecodeError:
            pass
    return {"last_offset": 0, "last_slow_query_count": None}


def save_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state))


def append_log(query_payload: dict, verdict: dict, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # INTEGRATION: "type" field + shared input/response schema
    record = {
        "timestamp": query_payload["timestamp"],
        "type":      "db_audit",
        "hostname":  subprocess.getoutput("hostname"),
        "model":     DEFAULT_MODEL,
        "input":     f"db_audit: slow query rows_examined={query_payload.get('rows_examined')} — {query_payload.get('sql','')[:120]}",
        "response":  verdict.get("missing_index_suggestion", "none"),
        "verdict":   {k: v for k, v in verdict.items() if k != "_raw"},
        "query":     query_payload,
        "model_raw_response": verdict.get("_raw"),
        "ground_truth_label": None,
    }
    with log_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Escalation output — designed to be piped into ask
# --------------------------------------------------------------------------

def escalation_string(entry: dict, verdict: dict) -> str:
    """
    Formats a rich, keyword-dense summary for the orchestrator to pipe to ask.
    MariaDB keywords in the string trigger llama3.2:3b routing automatically.
    """
    return (
        f"[db_audit escalation] IMPACT={verdict.get('estimated_impact','?').upper()} "
        f"QUERY_TIME={entry.get('query_time','?')}s "
        f"ROWS_EXAMINED={entry.get('rows_examined','?')} "
        f"ROWS_SENT={entry.get('rows_sent','?')} "
        f"OCCURRENCES={entry.get('occurrences','?')} "
        f"SQL={entry.get('sql','')[:150]} "
        f"SUGGESTION={verdict.get('missing_index_suggestion','none')} "
        f"RATIONALE={verdict.get('rationale','n/a')} "
        f"HOST={subprocess.getoutput('hostname')} "
        f"MariaDB database slow-query index missing"
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run_once(args) -> int:
    state = load_state(args.state_path)

    current_count = get_slow_query_count(args.my_cnf)
    if current_count is not None and state.get("last_slow_query_count") is not None:
        delta = current_count - state["last_slow_query_count"]
    else:
        delta = None
    state["last_slow_query_count"] = current_count

    raw_text, new_offset = read_new_log_bytes(args.slow_log_path, state["last_offset"])
    state["last_offset"] = new_offset
    save_state(args.state_path, state)

    if not raw_text.strip():
        if not args.quiet:
            print(f"[{datetime.now(timezone.utc).isoformat()}] no new slow-log entries "
                  f"(Slow_queries delta: {delta})")
        return 0

    entries = dedupe_entries(parse_slow_log(raw_text))[:MAX_QUERIES_PER_RUN]
    if not entries:
        return 0

    worst_impact = "Low"
    escalations  = []

    for entry in entries:
        tables         = extract_tables(entry["sql"])
        schemas        = {t: redact(show_create_table(args.my_cnf, t)) for t in tables}
        explain_output = redact(run_explain(args.my_cnf, entry["sql"]))

        payload = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "query_time":   entry["query_time"],
            "lock_time":    entry["lock_time"],
            "rows_sent":    entry["rows_sent"],
            "rows_examined":entry["rows_examined"],
            "occurrences":  entry["occurrences"],
            "sql":          entry["sql"],
            "explain":      explain_output,
            "table_schemas":schemas,
        }

        verdict = query_ollama(payload, args.ollama_host, args.model)
        append_log(payload, verdict, args.log_path)

        impact     = verdict.get("estimated_impact", "Low")
        suggestion = verdict.get("missing_index_suggestion", "none")

        if not args.quiet:
            print(f"[{payload['timestamp']}] query_time={entry['query_time']}s "
                  f"rows_examined={entry['rows_examined']} "
                  f"occurrences={entry['occurrences']} impact={impact}")
            print(f"    suggestion: {suggestion}")

        if impact == "High":
            worst_impact = "High"
            escalations.append(escalation_string(entry, verdict))
        elif impact == "Medium" and worst_impact != "High":
            worst_impact = "Medium"
            escalations.append(escalation_string(entry, verdict))

    # INTEGRATION: --escalate prints escalation strings to stdout
    if args.escalate and escalations:
        for esc in escalations:
            print(esc)

    return {"Low": 0, "Medium": 1, "High": 2}[worst_impact]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once",          action="store_true")
    parser.add_argument("--loop",          action="store_true")
    parser.add_argument("--interval",      type=int, default=300)
    parser.add_argument("--ollama-host",   default=DEFAULT_OLLAMA_HOST)
    parser.add_argument("--model",         default=DEFAULT_MODEL)
    parser.add_argument("--slow-log-path", type=Path, default=DEFAULT_SLOW_LOG)
    parser.add_argument("--state-path",    type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--log-path",      type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--my-cnf",        type=Path, default=DEFAULT_MY_CNF)
    parser.add_argument("--quiet",         action="store_true")
    # INTEGRATION: escalation flag
    parser.add_argument("--escalate",      action="store_true",
                        help="On High/Medium impact, print escalation string to stdout for piping to ask")
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
