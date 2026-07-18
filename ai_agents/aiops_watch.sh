#!/bin/bash
# =============================================================================
# aiops_watch.sh — AIOps Orchestrator for [HOSTNAME] homelab
# =============================================================================
#
# Ties together all three framework components:
#   Layer 1: mail_audit.py + db_audit.py  (scheduled fault detection)
#   Layer 2: ask agent                      (escalation and deeper diagnosis)
#   Layer 3: ask_knowledge.jsonl            (shared persistent knowledge base)
#
# INSTALL:
#   chmod +x ~/aiops_watch.sh
#
# ADD TO CRON (runs every 10 minutes):
#   crontab -e
#   */10 * * * * /home/[USERNAME]/aiops_watch.sh >> /var/log/aiops_watch.log 2>&1
#
# MANUAL RUN:
#   ~/aiops_watch.sh
#   ~/aiops_watch.sh --mail-only
#   ~/aiops_watch.sh --db-only
#   ~/aiops_watch.sh --dry-run    (run audits but skip ask escalation)
#
# ENVIRONMENT:
#   All env vars are set below. Override by exporting before running.
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------------
# Configuration — edit these paths to match your setup
# ------------------------------------------------------------------

export ASK_KNOWLEDGE_PATH="${ASK_KNOWLEDGE_PATH:-/mnt/vault/ask_knowledge.jsonl}"
export ASK_OLLAMA_HOST="${ASK_OLLAMA_HOST:-http://[HOSTNAME]:11434}"

MAIL_AUDIT_SCRIPT="${MAIL_AUDIT_SCRIPT:-$HOME/services/mail/mail_audit.py}"
DB_AUDIT_SCRIPT="${DB_AUDIT_SCRIPT:-$HOME/services/db_audit.py}"
ASK_AGENT_FILE="${ASK_AGENT_FILE:-$HOME/ask_agent.sh}"
SLOW_LOG_PATH="${SLOW_LOG_PATH:-/var/lib/mysql/[HOSTNAME]-slow.log}"
MY_CNF="${MY_CNF:-$HOME/.my.cnf}"
WATCH_LOG="${WATCH_LOG:-/var/log/aiops_watch.log}"
PYTHON="${PYTHON:-python3}"

# ANSI Colour Codes
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[1;31m'
RESET=$'\033[0m'

# ------------------------------------------------------------------
# Parse flags
# ------------------------------------------------------------------

MAIL_ONLY=false
DB_ONLY=false
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --mail-only) MAIL_ONLY=true ;;
        --db-only)   DB_ONLY=true   ;;
        --dry-run)   DRY_RUN=true   ;;
        --help|-h)
            sed -n '/^# /p' "$0" | sed 's/^# //'
            exit 0
            ;;
    esac
done

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------

log() {
    local level="$1"; shift
    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local colour
    
    # 1. Match the $level variable against specific keywords
    case "$level" in
        INFO)  colour="${GREEN}" ;;
        WARN)  colour="${YELLOW}" ;;
        ERROR) colour="${RED}" ;;
        *)     colour="${RESET}" ;; # Default fallback if level doesn't match
    esac
    
    # 2. Print the formatted log message using $RESET instead of literal \e[0m
    printf "${colour}[watch][${level}]${RESET} [%s] %s\n" "$ts" "$*"
}

# ------------------------------------------------------------------
# Source ask agent (so we can call it as a function)
# ------------------------------------------------------------------

load_ask() {
    if [ -f "$ASK_AGENT_FILE" ]; then
        # shellcheck source=/dev/null
        source "$ASK_AGENT_FILE"
        return 0
    elif grep -q "^ask()" "$HOME/.bashrc" 2>/dev/null; then
        # shellcheck source=/dev/null
        source "$HOME/.bashrc" 2>/dev/null
        return 0
    else
        log WARN "ask agent not found at $ASK_AGENT_FILE — escalation disabled"
        return 1
    fi
}

ASK_LOADED=false
if load_ask 2>/dev/null; then
    ASK_LOADED=true
    log INFO "ask agent loaded successfully"
fi

# ------------------------------------------------------------------
# Escalation handler
# ------------------------------------------------------------------

escalate_to_ask() {
    local source="$1"
    local finding="$2"

    if [ "$DRY_RUN" = true ]; then
        log INFO "[dry-run] would escalate to ask: ${finding:0:100}..."
        return 0
    fi

    if [ "$ASK_LOADED" = false ]; then
        log WARN "ask not loaded — skipping escalation of $source finding"
        return 1
    fi

    log INFO "Escalating $source finding to ask for deeper diagnosis..."
    # The finding string contains service-specific keywords (postfix, dovecot,
    # MariaDB) which trigger llama3.2:3b routing in ask automatically.
    echo "$finding" | ask
}

# ------------------------------------------------------------------
# Mail audit runner
# ------------------------------------------------------------------

run_mail_audit() {
    if [ ! -f "$MAIL_AUDIT_SCRIPT" ]; then
        log WARN "mail_audit.py not found at $MAIL_AUDIT_SCRIPT — skipping"
        return 0
    fi

    log INFO "Running mail_audit.py..."

    # Capture stdout (escalation text) separately from stderr (status output)
    local escalation_text
    
    local exit_code=0

    escalation_text=$(
        "$PYTHON" "$MAIL_AUDIT_SCRIPT" \
            --once \
            --quiet \
            --escalate \
            --ollama-host "$ASK_OLLAMA_HOST" \
            --log-path "$ASK_KNOWLEDGE_PATH" \
            2>/dev/null
    ) || exit_code=$?

    case $exit_code in
        0)
            log INFO "mail_audit: ${GREEN}healthy${RESET}"
            ;;
        1)
            log WARN "mail_audit: DEGRADED (exit $exit_code)"
            if [ -n "$escalation_text" ]; then
                escalate_to_ask "mail_audit" "$escalation_text"
            fi
            ;;
        2)
            log ERROR "mail_audit: CRITICAL (exit $exit_code)"
            if [ -n "$escalation_text" ]; then
                escalate_to_ask "mail_audit" "$escalation_text"
            fi
            ;;
        *)
            log WARN "mail_audit: unknown status (exit $exit_code)"
            ;;
    esac

    return 0
}

# ------------------------------------------------------------------
# DB audit runner
# ------------------------------------------------------------------

run_db_audit() {
    if [ ! -f "$DB_AUDIT_SCRIPT" ]; then
        log WARN "db_audit.py not found at $DB_AUDIT_SCRIPT — skipping"
        return 0
    fi

    if [ ! -f "$SLOW_LOG_PATH" ]; then
        log WARN "Slow query log not found at $SLOW_LOG_PATH — skipping db_audit"
        log WARN "Enable with: sudo mariadb -e \"SET GLOBAL slow_query_log = 'ON';\""
        return 0
    fi

    log INFO "Running db_audit.py..."

    local escalation_text
    
   local exit_code=0

    escalation_text=$(
        "$PYTHON" "$DB_AUDIT_SCRIPT" \
            --once \
            --quiet \
            --escalate \
            --slow-log-path "$SLOW_LOG_PATH" \
            --my-cnf "$MY_CNF" \
            --ollama-host "$ASK_OLLAMA_HOST" \
            --log-path "$ASK_KNOWLEDGE_PATH" \
            2>/dev/null
    ) || exit_code=$?

    case $exit_code in
        0)
            log INFO "db_audit: ${GREEN}no high-impact queries${RESET}"
            ;;
        1)
            log WARN "db_audit: MEDIUM impact slow queries detected (exit $exit_code)"
            if [ -n "$escalation_text" ]; then
                escalate_to_ask "db_audit" "$escalation_text"
            fi
            ;;
        2)
            log ERROR "db_audit: HIGH impact slow queries detected (exit $exit_code)"
            if [ -n "$escalation_text" ]; then
                escalate_to_ask "db_audit" "$escalation_text"
            fi
            ;;
        *)
            log WARN "db_audit: unknown status (exit $exit_code)"
            ;;
    esac

    return 0
}

# ------------------------------------------------------------------
# KB stats (shown at end of each run)
# ------------------------------------------------------------------

show_kb_stats() {
    if [ -f "$ASK_KNOWLEDGE_PATH" ]; then
        local count; count=$(wc -l < "$ASK_KNOWLEDGE_PATH")
        local size;  size=$(du -sh "$ASK_KNOWLEDGE_PATH" 2>/dev/null | cut -f1)
        log INFO "Knowledge base: ${count} entries (${size}) at $ASK_KNOWLEDGE_PATH"
    fi
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

log INFO "=== aiops_watch starting ==="
log INFO "KB: $ASK_KNOWLEDGE_PATH | Ollama: $ASK_OLLAMA_HOST"

if [ "$DB_ONLY" = false ]; then
    run_mail_audit
fi

if [ "$MAIL_ONLY" = false ]; then
    run_db_audit
fi

show_kb_stats
log INFO "=== aiops_watch complete ==="
