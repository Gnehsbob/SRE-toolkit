#!/bin/bash
# AIOps Agent: A zero-trust Bash function for LLM-assisted terminal debugging.
# Usage: Add to ~/.bashrc or source directly.


ask() {
    local exec_mode=false
    local input

    if [ "$1" = "-y" ]; then
        exec_mode=true
        shift
    fi

    if [ -p /dev/stdin ]; then
        input=$(cat)
    else
        input="$*"
    fi

    if [ -z "$input" ]; then
        printf "\e[1;33mUsage:\e[0m ask [-y] <error info>  OR  <command> 2>&1 | ask [-y]\n" >&2
        return 1
    fi

    # [OPSEC FIX]: Read from Environment Variables. Never hardcode Tailscale IPs.
    local OLLAMA_HOST="${ASK_OLLAMA_HOST:-http://localhost:11434}"
    local ENDPOINT="${OLLAMA_HOST}/api/generate"
    local LLM_MODEL="${ASK_LLM_MODEL:-qwen2.5-coder:1.5b}"

    local payload
    payload=$(ASK_INPUT="$input" ASK_EXEC="$exec_mode" TARGET_MODEL="$LLM_MODEL" python3 -c '
import json, sys, subprocess, os

current_user = subprocess.getoutput("whoami")
os_release = subprocess.getoutput("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2").strip(chr(34))
current_dir = subprocess.getoutput("pwd")

user_input = os.environ.get("ASK_INPUT", "")
exec_mode_active = os.environ.get("ASK_EXEC", "false") == "true"
target_model = os.environ.get("TARGET_MODEL", "qwen2.5-coder:1.5b")

if exec_mode_active:
    instruction = "Output ONLY the raw executable bash commands. No explanations. No introduction."
else:
    instruction = "Provide a brief explanation (50-80 words), followed by the raw bash commands needed to fix the issue."

dense_prompt = (
    f"CONTEXT ENVIRONMENT LAYER:\n- OS: {os_release}\n- User: {current_user}\n- Dir: {current_dir}\n\n"
    f"ERROR:\n{user_input}\n\n"
    f"INSTRUCTION: You are a silent Unix specialist. {instruction}"
)

print(json.dumps({
    "model": target_model,
    "prompt": dense_prompt,
    "stream": False,
    "options": {"num_predict": 256, "temperature": 0.1}
}))
')

    local response
    response=$(curl -s --connect-timeout 2 --max-time 60 \
        -H "Content-Type: application/json" \
        "$ENDPOINT" -d "$payload" 2>/dev/null)

    if [ -z "$response" ]; then
        printf "\e[1;31m[!] FALLBACK TRIPPED:\e[0m Remote LLM host engine is offline or unreachable.\n" >&2
        return 1
    fi

    local cmd_output
    cmd_output=$(echo "$response" | python3 -c '
import json, sys, re
try:
    res = json.load(sys.stdin).get("response", "").strip()
    res = re.sub(r"```[a-zA-Z0-9]*\n?", "", res).strip()
    print(res)
except Exception:
    pass
')

    if [ -z "$cmd_output" ]; then
        printf "ask: could not cleanly decode response parameters from Ollama node.\n" >&2
        return 1
    fi

    if [ "$exec_mode" = true ]; then
        # [SECURITY GOVERNANCE]: Prevent catastrophic hallucination commands
        if [[ "$cmd_output" =~ (rm[[:space:]]+-rf[[:space:]]+/|mkfs|dd[[:space:]]+if=) ]] || \
           [[ "$cmd_output" =~ ^[[:space:]]*# ]] || \
           [[ "$cmd_output" == *"I cannot"* ]] || \
           [[ "$cmd_output" =~ (sudo[[:space:]]+-i|su[[:space:]]+root) ]] || \
           [[ "$cmd_output" =~ (someone else|another user|private.*account|unauthorized) ]]; then
            printf "\e[1;31m[!] SECURITY ABORT:\e[0m Refusing to execute dangerous, commented, or non-conforming LLM output.\n" >&2
            printf "Raw Output Received: %s\n" "$cmd_output" >&2
            return 1
        fi

        if ! bash -n <(echo "$cmd_output") 2>/dev/null; then
            printf "\e[1;31m[!] SYNTAX ABORT:\e[0m LLM output failed bash syntax check. Aborting.\n" >&2
            printf "Raw Output Received: %s\n" "$cmd_output" >&2
            return 1
        fi

        printf "\e[1;32m[*] AUTO-EXECUTING COMPUTE FIX:\e[0m %s\n" "$cmd_output"
        printf -- "------------------------------------------------\n"
        eval "set -e; $cmd_output"
    else
        printf "%s\n" "$cmd_output"
    fi
}
