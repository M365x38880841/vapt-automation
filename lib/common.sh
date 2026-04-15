#!/usr/bin/env bash
# ============================================================================
# lib/common.sh — Shared utilities for all VAPT phase scripts
# Source this at the top of every phase script: source "$(dirname "$0")/../lib/common.sh"
# ============================================================================

# ─── COLOURS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
MAGENTA='\033[0;35m'

# ─── PIP INSTALL HELPER ───────────────────────────────────────────────────────
# Strategy: pipx FIRST — installs each tool in its own isolated venv and exposes
# the binary globally on PATH. No venv activation required, no system package
# conflicts, no PEP 668 errors (Kali 2023.1+).
# pipx is bootstrapped in phase0_setup.sh before any pip_install call.
# pip3 --break-system-packages is the fallback for packages that don't work well
# under pipx (e.g. libraries rather than standalone tools).
pip_install() {
    local package="$1"
    if command -v pipx &>/dev/null; then
        # Install — if already present, upgrade instead (pipx install errors on duplicates)
        if pipx install "${package}" 2>/dev/null \
           || pipx upgrade "${package}" 2>/dev/null; then
            return 0
        fi
    fi
    # pip3 fallback: handles PEP 668 (externally-managed-environment on Kali 2023.1+)
    if pip3 install "${package}" --quiet --break-system-packages 2>/dev/null; then
        return 0
    fi
    pip3 install "${package}" --quiet 2>/dev/null
    return $?
}

# ─── SCOUTSUITE INVOCATION HELPER ─────────────────────────────────────────────
# ScoutSuite's CLI is "scout suite" (two words), not "scout".
# Sets global SCOUT_CMD_ARRAY for use as: "${SCOUT_CMD_ARRAY[@]}" azure ...
set_scout_cmd() {
    if command -v scout &>/dev/null; then
        SCOUT_CMD_ARRAY=( scout suite )
    elif python3 -c "import ScoutSuite" 2>/dev/null; then
        SCOUT_CMD_ARRAY=( python3 -m ScoutSuite )
    else
        SCOUT_CMD_ARRAY=( scout suite )  # will fail with clear "not found" message
    fi
}

# ─── CME/NXC BINARY DETECTION ─────────────────────────────────────────────────
# CrackMapExec was renamed to NetExec (nxc) in Kali 2024+. Auto-detect.
detect_cme() {
    CME_BIN="${CME_BIN:-}"
    if [[ -n "${CME_BIN}" ]] && command -v "${CME_BIN}" &>/dev/null; then
        return 0
    fi
    CME_BIN=$(command -v nxc 2>/dev/null \
        || command -v crackmapexec 2>/dev/null \
        || echo "nxc")
    export CME_BIN
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────
LOG_FILE="${OUTPUT_BASE_DIR:-$HOME/vapt}/engagement_log.md"

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "## [${ts}] [${level}] ${msg}" >> "${LOG_FILE}"
    case "$level" in
        INFO)    echo -e "${CYAN}[${ts}] [INFO]${RESET}  ${msg}" ;;
        OK)      echo -e "${GREEN}[${ts}] [OK]${RESET}    ${msg}" ;;
        WARN)    echo -e "${YELLOW}[${ts}] [WARN]${RESET}   ${msg}" ;;
        ERROR)   echo -e "${RED}[${ts}] [ERROR]${RESET}  ${msg}" ;;
        PHASE)   echo -e "\n${BOLD}${MAGENTA}[${ts}] ══════ ${msg} ══════${RESET}\n" ;;
        CMD)     echo -e "${BLUE}[${ts}] [CMD]${RESET}   ${msg}" ;;
        MANUAL)  echo -e "\n${BOLD}${YELLOW}┌─────────────────────────────────────────────────┐${RESET}" 
                 echo -e "${BOLD}${YELLOW}│  👤 HUMAN ACTION REQUIRED                       │${RESET}"
                 echo -e "${BOLD}${YELLOW}│  ${msg}${RESET}"
                 echo -e "${BOLD}${YELLOW}└─────────────────────────────────────────────────┘${RESET}\n" ;;
    esac
}

log_cmd() {
    # Log a command before running it
    log CMD "$*"
    echo "\`\`\`" >> "${LOG_FILE}"
    echo "$*" >> "${LOG_FILE}"
    echo "\`\`\`" >> "${LOG_FILE}"
}

# ─── HUMAN CHECKPOINT ─────────────────────────────────────────────────────────
# Call this before any destructive or sensitive action
# Usage: checkpoint "Description of what you're about to do" [--auto-proceed]
checkpoint() {
    local description="$1"
    local auto="${2:-}"
    echo -e "\n${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${YELLOW}  CHECKPOINT — Human Review Required${RESET}"
    echo -e "${BOLD}  Action:${RESET} ${description}"
    echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    if [[ "$auto" == "--auto-proceed" ]]; then
        echo -e "${CYAN}  Auto-proceeding (--auto-proceed flag set)${RESET}"
        log INFO "Checkpoint auto-proceeded: ${description}"
        return 0
    fi
    echo -e "${BOLD}  Press [ENTER] to proceed, [s] to skip, [q] to abort:${RESET} \c"
    read -r choice
    case "$choice" in
        q|Q) log WARN "Aborted at checkpoint: ${description}"; echo -e "${RED}Aborted.${RESET}"; exit 1 ;;
        s|S) log WARN "Skipped at checkpoint: ${description}"; echo -e "${YELLOW}Skipped.${RESET}"; return 1 ;;
        *)   log INFO "Proceeded at checkpoint: ${description}"; return 0 ;;
    esac
}

# ─── BUSINESS HOURS ENFORCEMENT ───────────────────────────────────────────────
check_testing_window() {
    [[ "${ENFORCE_TESTING_WINDOW:-false}" != "true" ]] && return 0
    local current_time; current_time=$(date '+%H:%M')
    local start="${TESTING_WINDOW_START:-09:00}"
    local end="${TESTING_WINDOW_END:-17:00}"
    # Convert HH:MM to minutes-since-midnight for reliable numeric comparison
    _hm_to_min() { local h m; IFS=: read -r h m <<< "$1"; echo $(( 10#$h * 60 + 10#$m )); }
    local cur_min start_min end_min
    cur_min=$(_hm_to_min "${current_time}")
    start_min=$(_hm_to_min "${start}")
    end_min=$(_hm_to_min "${end}")
    if (( cur_min < start_min || cur_min > end_min )); then
        echo -e "${RED}[SAFETY] Current time ${current_time} is outside testing window (${start}–${end}).${RESET}"
        echo -e "${YELLOW}Override? This may violate the Rules of Engagement. [y/N]:${RESET} \c"
        read -r override
        [[ "$override" != "y" && "$override" != "Y" ]] && { log WARN "Testing blocked outside hours at ${current_time}"; exit 1; }
        log WARN "Testing window overridden by operator at ${current_time}"
    fi
}

# ─── BACKGROUND JOB MANAGER ───────────────────────────────────────────────────
BG_JOB_PIDS=()
BG_JOB_NAMES=()

bg_run() {
    # Usage: bg_run "job_name" "log_file" command [args...]
    local name="$1"; local logfile="$2"; shift 2
    log_cmd "$*"
    "$@" >> "${logfile}" 2>&1 &
    local pid=$!
    BG_JOB_PIDS+=("$pid")
    BG_JOB_NAMES+=("$name")
    log INFO "Background job started: ${name} (PID: ${pid}) → ${logfile}"
    echo -e "${GREEN}  [BG] ${name} started (PID: ${pid})${RESET}"
}

wait_for_bg_jobs() {
    local label="${1:-all background jobs}"
    echo -e "\n${CYAN}Waiting for: ${label}${RESET}"
    for i in "${!BG_JOB_PIDS[@]}"; do
        local pid="${BG_JOB_PIDS[$i]}"
        local name="${BG_JOB_NAMES[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${YELLOW}⏳ Waiting for: ${name} (PID: ${pid})${RESET}"
            wait "$pid"
            local rc=$?
            [[ $rc -eq 0 ]] && log OK "${name} completed successfully" \
                            || log WARN "${name} exited with code ${rc}"
        fi
    done
    BG_JOB_PIDS=(); BG_JOB_NAMES=()
    notify_complete "$label"
}

status_bg_jobs() {
    echo -e "\n${CYAN}Background Job Status:${RESET}"
    for i in "${!BG_JOB_PIDS[@]}"; do
        local pid="${BG_JOB_PIDS[$i]}"
        local name="${BG_JOB_NAMES[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${YELLOW}⏳ Running:  ${name} (PID: ${pid})${RESET}"
        else
            echo -e "  ${GREEN}✅ Done:     ${name} (PID: ${pid})${RESET}"
        fi
    done
}

# ─── NOTIFICATION ─────────────────────────────────────────────────────────────
notify_complete() {
    local msg="$1"
    [[ "${NOTIFY_ON_JOB_COMPLETE:-false}" != "true" ]] && return
    # Desktop notification (Linux)
    command -v notify-send &>/dev/null && notify-send "VAPT" "✅ Done: ${msg}"
    # Slack webhook (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"✅ VAPT Job Complete: ${msg}\"}" \
            "${SLACK_WEBHOOK_URL}" &>/dev/null
    fi
}

# ─── RUNTIME SECRET PROMPT ────────────────────────────────────────────────────
# Usage: prompt_secret VAR_NAME "Prompt text"
# Sets the variable in the calling environment
prompt_secret() {
    local var_name="$1"
    local prompt_text="$2"
    local value
    echo -e "${BOLD}  ${prompt_text}:${RESET} \c"
    read -rs value; echo
    [[ -z "$value" ]] && { echo -e "${RED}Value cannot be empty.${RESET}"; exit 1; }
    export "${var_name}=${value}"
    log INFO "Secret '${var_name}' provided at runtime (not logged)"
}

# ─── PREREQUISITE CHECKS ──────────────────────────────────────────────────────
require_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null || {
        log ERROR "Required tool not found: ${tool}. Run phase0_setup.sh first."
        exit 1
    }
}

require_var() {
    local var_name="$1"
    [[ -z "${!var_name:-}" ]] && {
        log ERROR "Required config variable not set: ${var_name}. Check config.env."
        exit 1
    }
}

require_file() {
    local filepath="$1"
    [[ -f "$filepath" ]] || {
        log ERROR "Required file not found: ${filepath}"
        exit 1
    }
}

# ─── OUTPUT DIRECTORY HELPER ──────────────────────────────────────────────────
phase_dir() {
    local phase="$1"; local subdir="${2:-}"
    local dir="${OUTPUT_BASE_DIR}/${phase}${subdir:+/${subdir}}"
    mkdir -p "$dir"
    echo "$dir"
}

# ─── SKIP IF OUTPUT EXISTS ────────────────────────────────────────────────────
# Usage: skip_if_exists "filepath" "description"
skip_if_exists() {
    local filepath="$1"; local desc="$2"
    if [[ -f "$filepath" ]]; then
        log INFO "Skipping (already exists): ${desc} → ${filepath}"
        echo -e "${GREEN}  [SKIP] ${desc} — output already exists.${RESET}"
        return 0  # signal: skip
    fi
    return 1  # signal: proceed
}

# ─── SAFE EXIT ON CTRL+C ──────────────────────────────────────────────────────
cleanup_on_exit() {
    echo -e "\n${YELLOW}Interrupt received. Stopping background jobs...${RESET}"
    for pid in "${BG_JOB_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            # Kill the entire process group to catch sudo/child wrappers (e.g. Responder)
            local pgid
            pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' | head -1)
            if [[ -n "$pgid" && "$pgid" -ne "$$" && "$pgid" -ne "0" ]]; then
                sudo kill -- "-${pgid}" 2>/dev/null \
                    || kill -- "-${pgid}" 2>/dev/null \
                    || kill "$pid" 2>/dev/null
            else
                kill "$pid" 2>/dev/null
            fi
            log WARN "Killed background job PID: ${pid} (pgid: ${pgid:-unknown})"
        fi
    done
    log WARN "Session interrupted by operator"
    exit 1
}
trap cleanup_on_exit SIGINT SIGTERM
