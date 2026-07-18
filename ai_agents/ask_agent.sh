#!/bin/bash

# =============================================================================

# =============================================================================
# AIOps Ask Agent v2 — [HOSTNAME] homelab
# Session memory + persistent knowledge infrastructure
# =============================================================================
#
# BUGS FIXED vs previous version:
#   1. Stop tokens removed — ["\\n\\n", "CAUSE:", "FIX:"] were preventing the
#      model from outputting the very words the instruction asked for.
#   2. ANSI escape codes fixed — \\033 in Python heredoc was printing literal
#      backslash-033 instead of the ESC character. Changed to \033.
#   3. kb_context newlines fixed — \\n in f-strings was literal text.
#      Changed to \n for real newlines in injected context.
#   4. Execution status logging rewritten — sed '$ s/}$/,...}/' silently
#      fails because Python writes a trailing newline after each JSON record.
#      Replaced with a Python one-liner that parses and rewrites correctly.
#
# INSTALL:
#   1. Add the export lines below to your ~/.bashrc (outside the function)
#   2. Paste the ask() function below into ~/.bashrc
#   3. source ~/.bashrc
#
# ENVIRONMENT (set these in ~/.bashrc before the function):
#   export ASK_KNOWLEDGE_PATH="/mnt/vault/ask_knowledge.jsonl"
#   export ASK_OLLAMA_HOST="http://[HOSTNAME]:11434"
#
# USAGE:
#   ask [-y] <error message>
#   <command> 2>&1 | ask [-y]
#   ask --clear              Clear current session history
#   ask --stats              Knowledge base statistics
#   ask --recall <term>      Search knowledge base for past fixes
# =============================================================================

ask() {
    # ------------------------------------------------------------------
    # Special commands
    # ------------------------------------------------------------------
    case "${1:-}" in
        --clear)
            rm -f "/tmp/ask_session_$$.json"
            printf "\e[1;33m[ask]\e[0m Session history cleared.\n"
            return 0
            ;;
        --stats)
            local kb="${ASK_KNOWLEDGE_PATH:-$HOME/.ask_knowledge.jsonl}"
            if [ -f "$kb" ]; then
                local count; count=$(wc -l < "$kb")
                local size; size=$(du -sh "$kb" | cut -f1)
                printf "\e[1;33m[ask]\e[0m Knowledge base: \e[1;32m%s entries\e[0m (%s) at %s\n" \
                    "$count" "$size" "$kb"
            else
                printf "\e[1;33m[ask]\e[0m Knowledge base not yet initialised at: %s\n" \
                    "${ASK_KNOWLEDGE_PATH:-$HOME/.ask_knowledge.jsonl}"
            fi
            return 0
            ;;
        --recall)
            shift
            local term="$*"
            local kb="${ASK_KNOWLEDGE_PATH:-$HOME/.ask_knowledge.jsonl}"
            if [ ! -f "$kb" ]; then
                printf "\e[1;31m[ask]\e[0m Knowledge base not found.\n" >&2
                return 1
            fi
            grep -i "$term" "$kb" | python3 -c '
import json, sys
results = []
for line in sys.stdin:
    try:
        r = json.loads(line)
        results.append(r)
    except:
        pass
if not results:
    print("No matching entries found.")
else:
    for r in results[-10:]:
        ts    = r.get("timestamp","?")[:19]
        host  = r.get("hostname","?")
        model_name = r.get("model","?")
        inp   = r.get("input","")[:100]
        resp  = r.get("response","")[:200]
        print("\n\033[1;34m[" + ts + "]\033[0m " + host + " (" + model_name + ")")
        print("  \033[1;33mInput:\033[0m  " + inp)
        print("  \033[1;32mFix:\033[0m    " + resp)

'
            return 0
            ;;
    esac

    # ------------------------------------------------------------------
    # Parse flags and input
    # ------------------------------------------------------------------
    local exec_mode=false
    if [ "${1:-}" = "-y" ]; then
        exec_mode=true
        shift
    fi

    local input
    if [ -p /dev/stdin ]; then
        input=$(cat)
    else
        input="$*"
    fi

    if [ -z "$input" ]; then
        printf "\e[1;33mUsage:\e[0m ask [-y] <error>  OR  <command> 2>&1 | ask [-y]\n" >&2
        printf "       ask --clear            Clear session history\n" >&2
        printf "       ask --stats            Knowledge base info\n" >&2
        printf "       ask --recall <term>    Search past fixes\n" >&2
        return 1
    fi

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    local OLLAMA_HOST="${ASK_OLLAMA_HOST:-http://[HOSTNAME]:11434}"
    local KNOWLEDGE_PATH="${ASK_KNOWLEDGE_PATH:-$HOME/.ask_knowledge.jsonl}"
    local SESSION_FILE="/tmp/ask_session_$$.json"

    # ------------------------------------------------------------------
    # Model routing — complex faults escalate to llama3.2:3b on T560
    # ------------------------------------------------------------------
    local LLM_MODEL="${ASK_LLM_MODEL:-}"
    if [ -z "$LLM_MODEL" ]; then
        if echo "$input" | grep -qiE \
            "selinux|avc denied|tls|ssl|certif|iptables|nftables|segfault|kernel|oops|panic|\
corrupt|ldap|kerberos|dependency.cycle|postfix|dovecot|authelia|wireguard|tailscale|\
permission denied.*docker|journal.*space|no space left|authentication fail|dpkg lock|apt lock"; then
            LLM_MODEL="llama3.2:3b"
            printf "\e[1;34m[ask]\e[0m Complex fault signature → routing to llama3.2:3b\n" >&2
        else
            LLM_MODEL="qwen2.5-coder:1.5b"
        fi
    fi

    # ------------------------------------------------------------------
    # Core: session memory + knowledge lookup + LLM call
    # ------------------------------------------------------------------
    local llm_response
    llm_response=$(
        SESSION_FILE="$SESSION_FILE" \
        KNOWLEDGE_PATH="$KNOWLEDGE_PATH" \
        ASK_INPUT="$input" \
        ASK_EXEC="$exec_mode" \
        ASK_MODEL="$LLM_MODEL" \
        ASK_ENDPOINT="${OLLAMA_HOST}/api/chat" \
        python3 << 'PYEOF'
import json, os, sys, subprocess, re
from datetime import datetime, timezone
from pathlib import Path

user_input   = os.environ["ASK_INPUT"]
exec_mode    = os.environ.get("ASK_EXEC", "false") == "true"
model        = os.environ["ASK_MODEL"]
endpoint     = os.environ["ASK_ENDPOINT"]
session_file = Path(os.environ["SESSION_FILE"])
kb_path      = Path(os.environ["KNOWLEDGE_PATH"])

hostname   = subprocess.getoutput("hostname")
username   = subprocess.getoutput("whoami")
os_release = subprocess.getoutput("grep PRETTY_NAME /etc/os-release | cut -d= -f2").strip('"')
cwd        = subprocess.getoutput("pwd")

# --- Load session history ---
if session_file.exists():
    try:
        messages = json.loads(session_file.read_text())
    except Exception:
        messages = []
else:
    messages = []

# --- Knowledge base lookup (Jaccard similarity) ---
# FIX 3: use \n (real newline) not \\n (literal backslash-n) in kb_context
kb_context = ""
if kb_path.exists():
    input_tokens = set(re.findall(r'[a-z0-9_/.-]{3,}', user_input.lower()))
    best_score, best_entry = 0.0, None
    try:
        with kb_path.open() as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    past_tokens = set(re.findall(r'[a-z0-9_/.-]{3,}',
                                                  entry.get("input", "").lower()))
                    if not past_tokens:
                        continue
                    score = len(input_tokens & past_tokens) / len(input_tokens | past_tokens)
                    if score > best_score:
                        best_score, best_entry = score, entry
                except Exception:
                    continue
    except Exception:
        pass

    if best_entry and best_score >= 0.25:
        # FIX 3: \n here is a real newline inside the f-string
        kb_context = (
            f"\n[KNOWLEDGE BASE — {best_score:.0%} match from {best_entry.get('timestamp','?')[:10]}]\n"
            f"Prior error:      {best_entry.get('input','')[:150]}\n"
            f"Prior resolution: {best_entry.get('response','')[:300]}\n"
        )
        # FIX 2: \033 here is the ESC character, not a literal backslash
        sys.stderr.write(
            f"\033[1;35m[ask]\033[0m Knowledge base match "
            f"({best_score:.0%}) — prior fix injected as context.\n"
        )

# --- Build instruction and system prompt ---
if exec_mode:
    instruction = (
        "OUTPUT ONLY the exact bash command(s). "
        "No explanation, no markdown, no backticks, no extra lines. "
        "If multiple commands are needed, separate with newlines."
    )
else:
    instruction = (
        "OUTPUT EXACTLY:\n"
        "CAUSE: <root cause in 10 words or fewer>\n"
        "FIX:\n```bash\n<commands>\n```\n"
        "NO OTHER TEXT. No introduction, no commentary, no warnings."
    )

system_prompt = (
    f"Unix specialist in homelab. OS: {os_release} | Host: {hostname} | User: {username} | Dir: {cwd}\n"
    f"{instruction}\n{kb_context}"
)

if not messages:
    messages = [{"role": "system", "content": system_prompt}]

messages.append({"role": "user", "content": user_input})

# --- Call Ollama /api/chat ---
import urllib.request

# FIX 1: stop tokens removed — they were blocking the model from ever
# writing "CAUSE:" or "FIX:" which the instruction explicitly requires.
payload = {
    "model":   model,
    "messages": messages,
    "stream":  False,
    "options": {
        "num_predict": 256,
        "temperature": 0,
        "num_thread": 2
    }
}

try:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read())
except Exception as exc:
    sys.stderr.write(f"[!] Ollama unreachable: {exc}\n")
    sys.exit(1)

assistant_content = body.get("message", {}).get("content", "").strip()

# Strip markdown fences if model added them despite the instruction
assistant_content = re.sub(r"^```[a-zA-Z0-9]*\s*", "", assistant_content)
assistant_content = re.sub(r"\s*```$", "", assistant_content).strip()

# Exec mode: take only the first non-empty command line, strip stray backticks
if exec_mode:
    lines = [l.strip() for l in assistant_content.splitlines() if l.strip()]
    assistant_content = lines[0].replace("`", "").strip() if lines else ""

if not assistant_content:
    sys.stderr.write("ask: empty response from model.\n")
    sys.exit(1)

# --- Persist session history ---
messages.append({"role": "assistant", "content": assistant_content})
try:
    session_file.write_text(json.dumps(messages))
except Exception:
    pass

# --- Append to knowledge base ---
try:
    kb_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname":  hostname,
        "model":     model,
        "input":     user_input,
        "response":  assistant_content,
    }
    with kb_path.open("a") as f:
        f.write(json.dumps(record) + "\n")
except Exception:
    pass

print(assistant_content)
PYEOF
    )

    local exit_code=$?
    if [ $exit_code -ne 0 ] || [ -z "$llm_response" ]; then
        printf "\e[1;31m[!] FALLBACK TRIPPED:\e[0m LLM host unreachable or returned empty response.\n" >&2
        return 1
    fi

    # ------------------------------------------------------------------
    # Auto-execute mode (-y): safety guards then eval
    # ------------------------------------------------------------------
    if [ "$exec_mode" = true ]; then
        # Catastrophic command blocklist
        if [[ "$llm_response" =~ (rm[[:space:]]+-rf[[:space:]]+/|mkfs|dd[[:space:]]+if=) ]] || \
           [[ "$llm_response" == *"I cannot"* ]] || \
           [[ "$llm_response" =~ (sudo[[:space:]]+-i|su[[:space:]]+root) ]] || \
           [[ "$llm_response" =~ (someone else|unauthorized|private.*account) ]]; then
            printf "\e[1;31m[!] SECURITY ABORT:\e[0m Refusing dangerous or non-conforming output.\n" >&2
            printf "Raw output: %s\n" "$llm_response" >&2
            return 1
        fi
        # Bash syntax check
        if ! bash -n <(echo "$llm_response") 2>/dev/null; then
            printf "\e[1;31m[!] SYNTAX ABORT:\e[0m Output failed bash syntax check.\n" >&2
            printf "Raw output: %s\n" "$llm_response" >&2
            return 1
        fi

        printf "\e[1;32m[*] AUTO-EXECUTING:\e[0m %s\n" "$llm_response"
        printf -- "------------------------------------------------\n"
        eval "set -e; $llm_response"
        local cmd_status=$?

        # FIX 4: sed -i '$ s/}$/,...}/' silently fails because Python writes
        # a trailing newline after each record, so $ matches the empty line
        # after the JSON object. Rewrite with Python instead.
        local status_label
        if [ $cmd_status -eq 0 ]; then
            status_label="SUCCESS"
            printf "\e[1;32m[ask]\e[0m Executed successfully — logging status=SUCCESS.\n"
        else
            status_label="FAILED"
            printf "\e[1;31m[ask]\e[0m Command failed (exit %s) — logging status=FAILED.\n" "$cmd_status" >&2
        fi

        python3 - "$ASK_KNOWLEDGE_PATH" "$status_label" << 'PYEOF2'
import json, sys
from pathlib import Path
kb = Path(sys.argv[1])
status = sys.argv[2]
if not kb.exists():
    sys.exit(0)
lines = kb.read_text().splitlines()
if not lines:
    sys.exit(0)
try:
    last = json.loads(lines[-1])
    last["execution_status"] = status
    lines[-1] = json.dumps(last)
    kb.write_text("\n".join(lines) + "\n")
except Exception:
    pass
PYEOF2

        return $cmd_status
    else
        printf "%s\n" "$llm_response"
    fi
}
