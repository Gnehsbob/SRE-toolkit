#!/usr/bin/env python3
"""
db_audit.py — LLM-in-the-loop slow-query auditor for MariaDB.

Reads new entries from the MariaDB slow query log, runs EXPLAIN and
SHOW CREATE TABLE for the tables involved, then ships the real query +
execution plan + schema (not just a counter) to Ollama for an index/
optimization recommendation. Designed for the same node pattern as
mail_audit.py: run this on whichever box is light, point --ollama-host
at wherever Ollama actually lives (e.g. the T560 over Tailscale).

Prerequisites:
    1. Slow query log enabled in MariaDB (see SET GLOBAL slow_query_log etc.)
    2. A read-only DB user's credentials in ~/.my.cnf (chmod 600), e.g.:
         [client]
         user=aiops_monitor
         password=...

Usage:
    python3 db_audit.py --once --slow-log-path /var/log/mariadb/mariadb-slow.log
    python3 db_audit.py --loop --interval 300
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1"
DEFAULT_SLOW_LOG_PATH = Path("/var/log/mariadb/mariadb-slow.log")
DEFAULT_STATE_PATH = Path.home() / "services" / "db_audit_state.json"
DEFAULT_LOG_PATH = Path.home() / "services" / "db_audit_log.jsonl"
DEFAULT_MY_CNF = Path.home() / ".my.cnf"
MAX_QUERIES_PER_RUN = 10  # cap LLM calls per pass even if log has more

# --------------------------------------------------------------------------
# Secret redaction (same approach as mail_audit.py)
# --------------------------------------------------------------------------

_SENSITIVE_KV = re.compile(
    r"(?i)\b(pass(word)?|secret|api[_-]?key|token)\b\s*[:=]\s*\S+"
)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b")


def redact(text: str) -> str:
    text = _SENSITIVE_KV.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _LONG_TOKEN.sub("[REDACTED_TOKEN]", text)
    return text


# --------------------------------------------------------------------------
# MySQL/MariaDB client helpers
# --------------------------------------------------------------------------

def run_mysql(my_cnf: Path, sql: str, timeout: int = 15) -> tuple[int, str, str]:
    cmd = [
        "mysql",
        f"--defaults-extra-file={my_cnf}",
        "-N",  # skip column header
        "-e", sql,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "mysql client not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out running: {sql[:80]}"


from typing import Optional

def get_slow_query_count(my_cnf: Path) -> Optional[int]:
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
    if rc != 0:
        return f"[EXPLAIN failed: {redact(err)}]"
    return out


def show_create_table(my_cnf: Path, table: str) -> str:
    # Basic guard against accidental injection via a malformed table name
    if not re.match(r"^[A-Za-z0-9_]+$", table):
        return f"[skipped: unsafe table name '{table}']"
    rc, out, err = run_mysql(my_cnf, f"SHOW CREATE TABLE `{table}`;")
    if rc != 0:
        return f"[SHOW CREATE TABLE failed: {redact(err)}]"
    return out


_TABLE_REF = re.compile(r"(?i)\b(?:FROM|JOIN)\s+`?([A-Za-z0-9_]+)`?")


def extract_tables(sql_text: str) -> list[str]:
    found = {m.group(1) for m in _TABLE_REF.finditer(sql_text)}
    return sorted(found)


# --------------------------------------------------------------------------
# Slow log parsing
# --------------------------------------------------------------------------

_QUERY_TIME_RE = re.compile(
    r"# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)"
)


from typing import Tuple

def read_new_log_bytes(log_path: Path, last_offset: int) -> Tuple[str, int]:
    if not log_path.exists():
        return "", last_offset
    size = log_path.stat().st_size
    if size < last_offset:
        last_offset = 0  # log was rotated/truncated
    with log_path.open("r", errors="replace") as f:
        f.seek(last_offset)
        data = f.read()
    return data, size


def parse_slow_log(text: str) -> list[dict]:
    """Split the slow log into per-query records and pull out metrics + SQL."""
    entries = []
    blocks = re.split(r"(?=^# Time: )", text, flags=re.MULTILINE)
    for block in blocks:
        m = _QUERY_TIME_RE.search(block)
        if not m:
            continue
        lines = block.splitlines()
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
            "query_time": float(m.group(1)),
            "lock_time": float(m.group(2)),
            "rows_sent": int(m.group(3)),
            "rows_examined": int(m.group(4)),
            "sql": redact(sql_text),
        })
    return entries


def normalize_signature(sql_text: str) -> str:
    """Collapse literals so repeated identical-shape queries dedupe together."""
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
            grouped[sig]["query_time"] = max(grouped[sig]["query_time"], e["query_time"])
    # Worst offenders first
    return sorted(grouped.values(), key=lambda e: e["query_time"], reverse=True)


# --------------------------------------------------------------------------
# Ollama query
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a Database Administrator analyzing slow queries on a MariaDB
server backing a financial backtesting application. You will receive a JSON object
containing: the slow query text, its execution metrics (query_time, lock_time,
rows_sent, rows_examined, occurrences), the EXPLAIN plan, and CREATE TABLE statements
for the tables involved.

A large gap between rows_examined and rows_sent, or an EXPLAIN plan showing type ALL
on a sizeable table, generally indicates a missing or unused index.

Respond with ONLY a single JSON object, no markdown fences, no commentary, in this
exact shape:
{
  "missing_index_suggestion": "<a CREATE INDEX statement, or 'none' if no index would help>",
  "rationale": "<short technical explanation grounded in the EXPLAIN output and schema>",
  "estimated_impact": "Low" | "Medium" | "High",
  "alternative_optimization": "<query rewrite or config suggestion, or 'none'>"
}"""


def query_ollama(payload: dict, host: str, model: str) -> dict:
    import urllib.request
    import urllib.error

    body = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": json.dumps(payload, indent=2),
        "stream": False,
        "format": "json",
    }
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
                return {
            "status": "error",
            "confidence": 0,
            "root_cause": f"ollama_unreachable: {exc}",
            "suggested_action": "check Tailscale connectivity to the Ollama host"
        }

    try:
        raw_text = resp_body.get("response", "").strip()
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "status": "error",
            "confidence": 0,
            "root_cause": "malformed_llm_json",
            "raw_response": redact(resp_body.get("response", ""))
        }


# --------------------------------------------------------------------------
# Main audit run loop
# --------------------------------------------------------------------------

def run_pass(args) -> int:
    my_cnf = Path(args.my_cnf)
    slow_log = Path(args.slow_log_path)
    state_path = Path(args.state_path)
    log_path = Path(args.log_path)

    # 1. Read last processed offset position
    last_offset = 0
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
            last_offset = state.get("last_offset", 0)
        except json.JSONDecodeError:
            pass

    # 2. Extract unread raw log data
    raw_data, current_size = read_new_log_bytes(slow_log, last_offset)
    
    # Write down updated offset state immediately
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"last_offset": current_size}))

    if not raw_data.strip():
        return 0

    # 3. Parse out, clean up, and deduplicate queries
    entries = parse_slow_log(raw_data)
    deduped = dedupe_entries(entries)
    
    processed_count = 0
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as out_f:
        for idx, item in enumerate(deduped):
            if idx >= MAX_QUERIES_PER_RUN:
                break
            
            # 4. Gather execution blueprints (EXPLAIN & CREATE TABLE)
            tables = extract_tables(item["sql"])
            explain_output = run_explain(my_cnf, item["sql"])
            
            schemas = {}
            for t in tables:
                schemas[t] = show_create_table(my_cnf, t)

            # Assemble structured audit packet for Ollama context injection
            payload = {
                "metrics": {
                    "query_time_max_sec": item["query_time"],
                    "lock_time_sec": item["lock_time"],
                    "rows_sent": item["rows_sent"],
                    "rows_examined": item["rows_examined"],
                    "occurrences": item["occurrences"]
                },
                "sql": item["sql"],
                "explain_plan": explain_output,
                "table_schemas": schemas
            }

            # 5. Query Ollama for automated optimization schema ideas
            analysis = query_ollama(payload, args.ollama_host, args.model)

            # Generate final combined audit record
            audit_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "query_signature": normalize_signature(item["sql"]),
                "analysis": analysis,
                "context": payload
            }
            
            out_f.write(json.dumps(audit_record) + "\n")
            processed_count += 1
            
            # Print analysis directly onto stdout for active CLI tracking
            print(f"[{audit_record['timestamp']}] processed query {idx+1}/{len(deduped)}")
            print(json.dumps(analysis, indent=2))
            print("-" * 60)

    return processed_count


# --------------------------------------------------------------------------
# CLI Engine
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MariaDB LLM Slow-Query Auditor")
    parser.add_argument("--once", action="store_true", help="Run once against new logs and exit.")
    parser.add_argument("--loop", action="store_true", help="Continuously tail the slow log file.")
    parser.add_argument("--interval", type=int, default=300, help="Seconds to sleep between loop iterations.")
    parser.add_argument("--ollama-host", default=DEFAULT_OLLAMA_HOST, help="Ollama listen address.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Target LLM model to request recommendations from.")
    
    # Configured to look inside /var/lib/mysql/xor-slow.log based on your system configuration discovery
    parser.add_argument("--slow-log-path", default="/var/lib/mysql/xor-slow.log", help="Path to MariaDB slow query log.")
    parser.add_argument("--my-cnf", default=str(DEFAULT_MY_CNF), help="Path to config containing credentials.")
    parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH), help="State tracking JSON path.")
    parser.add_argument("--log_path", default=str(DEFAULT_LOG_PATH), help="Audit ledger tracking output destination.")

    args = parser.parse_args()

    if not args.once and not args.loop:
        print("Error: You must specify either --once or --loop to execute this auditor configuration script.")
        parser.print_help()
        sys.exit(1)

    if args.once:
        print(f"Starting single database audit sweep across log path: {args.slow_log_path}")
        count = run_pass(args)
        print(f"Sweep finished. Processed {count} unique slow-query structures.")
    
    elif args.loop:
        print(f"Auditor actively watching slow log file: {args.slow_log_path} every {args.interval}s...")
        try:
            while True:
                run_pass(args)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nShutting down audit monitoring loop smoothly. Exiting.")


if __name__ == "__main__":
    main()

