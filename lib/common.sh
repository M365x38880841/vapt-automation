#!/usr/bin/env bash
# ============================================================================
# lib/common.sh — Shared utilities for all VAPT phase scripts
# Source this at the top of every phase script: source "$(dirname "$0")/../lib/common.sh"
# ============================================================================

# ─── IMPACKET COMPATIBILITY ───────────────────────────────────────────────────
# Root cause: script/library version skew inside the installed impacket package.
#   1. setdumpHashes() was removed from NTLMRelayxConfig in newer library builds,
#      but older ntlmrelayx.py scripts still call c.setdumpHashes(options.dump_hashes)
#   2. setRPCOptions() gained a required 'icpr_ca_name' 6th arg in newer library
#      builds, but older scripts call it with 5 args
# Swapping impacket versions does not help when both the script AND library ship
# together in the same apt/pip package — the skew is internal.
# The correct fix is a targeted source patch on the actual ntlmrelayx.py module
# file (NOT /usr/share/doc/…/examples/ which is documentation and never executed).
#
# _impacket_relay_broken — returns 0 (true) if broken, non-zero if healthy.
# fix_impacket_compat    — locates the live module file, inspects the library API
#                          at runtime, and applies only the patches that are needed.

_impacket_relay_broken() {
    local _script
    _script=$(_find_ntlmrelayx_script)
    [[ -z "${_script}" ]] && return 0  # can't find script → treat as broken

    ! python3 - "${_script}" 2>/dev/null <<'PYTEST'
import sys, re, inspect
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

src = open(sys.argv[1]).read()

# Check 1: script calls setdumpHashes but it is no longer a method on the class
if 'setdumpHashes' in src and not hasattr(NTLMRelayxConfig, 'setdumpHashes'):
    raise AttributeError('script calls setdumpHashes; method absent from NTLMRelayxConfig')

# Check 2: count required positional args on setRPCOptions and compare to call site.
# inspect.signature on an unbound class method includes 'self'; exclude it so
# the counts represent the args that appear at the call site (c.setRPCOptions(...)).
sig = inspect.signature(NTLMRelayxConfig.setRPCOptions)
params = [p for name, p in sig.parameters.items() if name != 'self']
n_required = sum(
    1 for p in params
    if p.default is inspect.Parameter.empty
    and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
)
n_accepts = len(params)
for call in re.findall(r'c\.setRPCOptions\(([^)]+)\)', src):
    n_passed = len(call.split(','))
    if n_passed < n_required:
        raise TypeError(
            f'setRPCOptions called with {n_passed} arg(s) but library requires {n_required}'
        )
    if n_passed > n_accepts:
        raise TypeError(
            f'setRPCOptions called with {n_passed} arg(s) but library only accepts {n_accepts}'
        )

# Check 3: any bare c.setXxx( call where the method is absent from NTLMRelayxConfig.
# Handles ALL version-mismatch setter names (setIsSCCMPoliciesAttack, setIsSCCMDPAttack,
# etc.) without needing per-method checks.  A call is "bare" if it is not already
# on a line that contains a hasattr() guard — the guard string is the canonical
# marker written by Patch 3 below.
for _method in set(re.findall(r'c\.(set\w+)\(', src)):
    if not hasattr(NTLMRelayxConfig, _method):
        if f'hasattr(c, "{_method}")' not in src:
            raise AttributeError(
                f'c.{_method}() calls NTLMRelayxConfig method absent from installed library'
            )
PYTEST
}

_find_ntlmrelayx_script() {
    local _f _bin

    # Strategy 1: importlib — works when impacket is installed as a proper package
    _f=$(python3 -c "
import importlib.util
spec = importlib.util.find_spec('impacket.examples.ntlmrelayx.ntlmrelayx')
if spec is not None and getattr(spec, 'origin', None):
    print(spec.origin)
" 2>/dev/null)
    [[ -n "${_f}" && -f "${_f}" ]] && echo "${_f}" && return 0

    # Strategy 2: Kali shell-wrapper pattern.
    # /usr/bin/impacket-ntlmrelayx is a #!/bin/sh script that strips the
    # 'impacket-' prefix and runs the matching .py file from a examples directory.
    # Parse the wrapper to find that directory, then reconstruct the full path.
    _bin=$(command -v impacket-ntlmrelayx 2>/dev/null)
    if [[ -n "${_bin}" ]]; then
        if head -1 "${_bin}" 2>/dev/null | grep -q '#!/bin/sh\|#!/bin/bash'; then
            # Extract any absolute path that contains 'examples' from the wrapper body
            _f=$(grep -oP '/[^\s"$]+examples[^\s"$]*' "${_bin}" 2>/dev/null \
                 | sed 's|/$||' \
                 | head -1)
            if [[ -n "${_f}" ]]; then
                # _f is the examples directory; append the script name
                _f="${_f}/ntlmrelayx.py"
                [[ -f "${_f}" ]] && echo "${_f}" && return 0
            fi
        elif head -1 "${_bin}" 2>/dev/null | grep -q 'python'; then
            # Binary is itself a Python script
            echo "${_bin}" && return 0
        fi
    fi

    # Strategy 3: filesystem search — include all paths.
    # On Kali's shell-wrapper layout the doc example IS the executed script,
    # so /doc/ paths are intentionally not excluded here.
    find /usr /opt -name "ntlmrelayx.py" 2>/dev/null | head -1
}

_patch_ntlmrelayx_script() {
    local _script
    _script=$(_find_ntlmrelayx_script)

    if [[ -z "${_script}" || ! -f "${_script}" ]]; then
        log WARN "Could not locate impacket ntlmrelayx module — patch skipped"
        return 1
    fi
    log INFO "Patching: ${_script}"
    sudo cp "${_script}" "${_script}.bak.$(date +%s)"

    # Patch 1 — setdumpHashes removed: replace with direct attribute write
    if grep -q 'setdumpHashes' "${_script}"; then
        sudo sed -i \
            's/c\.setdumpHashes(\(options\.[^)]*\))/c.dumpHashes = \1/g' \
            "${_script}"
        log OK "Patched: setdumpHashes → direct attribute assignment"
    fi

    # Patch 2 — align setRPCOptions call-site arg count with the live library.
    # The method signature has changed across impacket releases (sometimes gains
    # icpr_ca_name, sometimes loses it). Count what the library currently accepts
    # and rewrite the call to match exactly, padding with None or trimming extras.
    if grep -q 'c\.setRPCOptions(' "${_script}"; then
        sudo python3 - "${_script}" <<'PYFIX'
import sys, re, inspect
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

path = sys.argv[1]
src  = open(path).read()

# inspect.signature on an unbound method includes 'self'; strip it so n_accepts
# and n_required reflect only the args that appear at the call site.
sig        = inspect.signature(NTLMRelayxConfig.setRPCOptions)
params     = [p for name, p in sig.parameters.items() if name != 'self']
n_accepts  = len(params)
n_required = sum(
    1 for p in params
    if p.default is inspect.Parameter.empty
)

def fix_call(m):
    args   = [a.strip() for a in m.group(1).split(',')]
    n_have = len(args)
    if n_have < n_required:
        args += ['None'] * (n_required - n_have)
    elif n_have > n_accepts:
        args = args[:n_accepts]
    return 'c.setRPCOptions(' + ', '.join(args) + ')'

new_src = re.sub(r'c\.setRPCOptions\(([^)]+)\)', fix_call, src)
if new_src != src:
    open(path, 'w').write(new_src)
    print(f'Patched setRPCOptions → {n_accepts} arg(s)')
PYFIX
        log OK "Patched: setRPCOptions call aligned to library signature"
    fi

    # Patch 3 — guard any c.setXxx( call whose method is absent from the installed
    # NTLMRelayxConfig.  Handles all version-mismatch names in one pass
    # (setIsSCCMPoliciesAttack, setIsSCCMDPAttack, etc.) without per-method logic.
    # Lines already containing a hasattr() guard are skipped for idempotency.
    if grep -q 'c\.set' "${_script}"; then
        sudo python3 - "${_script}" <<'PYFIX3'
import sys, re
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

path = sys.argv[1]
src  = open(path).read()

lines   = src.splitlines(keepends=True)
changed = []
patched = []
for line in lines:
    if 'c.set' in line and 'hasattr(' not in line:
        for method in re.findall(r'c\.(set\w+)\(', line):
            if not hasattr(NTLMRelayxConfig, method):
                line = line.replace(
                    f'c.{method}(',
                    f'hasattr(c, "{method}") and c.{method}('
                )
                patched.append(method)
    changed.append(line)

if patched:
    open(path, 'w').write(''.join(changed))
    for m in patched:
        print(f'Patched: c.{m}() → hasattr short-circuit')
PYFIX3
        log OK "Patched: missing NTLMRelayxConfig setter calls guarded with hasattr"
    fi
}

fix_impacket_compat() {
    if ! _impacket_relay_broken; then
        log OK "impacket relay API healthy"
        return 0
    fi
    log WARN "impacket relay API broken — applying source patch to live module"

    _patch_ntlmrelayx_script

    if ! _impacket_relay_broken; then
        log OK "impacket relay API fixed via source patch"
        return 0
    fi

    log WARN "Source patch did not fully resolve the issue — check manually:"
    log WARN "  python3 -c \"import importlib.util; spec = importlib.util.find_spec('impacket.examples.ntlmrelayx.ntlmrelayx'); print(spec.origin)\""
    return 1
}

# ─── AZURE CLI AUTH GUARD ─────────────────────────────────────────────────────
# All Azure/Entra steps (inventory, ScoutSuite, security checks) run az commands
# inside bg_run background jobs where interactive prompts are impossible.
# Call require_az_login before any bg_run that uses az — it verifies the session
# and handles re-auth interactively in the foreground before the job is launched.
# Uses --use-device-code so it works on headless pentest boxes with no browser.
require_az_login() {
    if az account show &>/dev/null 2>&1; then
        local _acct
        _acct=$(az account show --query '[name, user.name]' -o tsv 2>/dev/null \
                | tr '\n' ' ' | xargs)
        log OK "Azure CLI authenticated: ${_acct}"
        return 0
    fi
    log WARN "Azure CLI session not found or expired."
    log INFO "A URL and one-time code will appear below — open the URL in any browser and enter the code."
    # Pass --tenant if configured so multi-tenant accounts authenticate to the right directory
    if [[ -n "${AZURE_TENANT_ID:-}" ]]; then
        az login --use-device-code --tenant "${AZURE_TENANT_ID}"
    else
        az login --use-device-code
    fi
    if az account show &>/dev/null 2>&1; then
        log OK "Azure CLI authenticated successfully"
        return 0
    fi
    log ERROR "Azure CLI authentication failed — Azure/Entra cloud steps will be skipped"
    return 1
}

# ─── DOCKER COMPOSE WRAPPER ───────────────────────────────────────────────────
# Resolves the correct docker compose invocation at runtime.
# - Prefers   "docker compose" (v2 plugin — docker-ce + docker-compose-plugin)
# - Falls back "docker-compose" (v1 standalone — older apt/pip installs)
# Call as: "${DC[@]}" -f file.yml up -d
# Exported so subshells (bg_run jobs) inherit it.
detect_docker_compose() {
    if docker compose version &>/dev/null 2>&1; then
        DC=( docker compose )
    elif command -v docker-compose &>/dev/null; then
        DC=( docker-compose )
    else
        DC=( docker compose )   # will fail with a clear "unknown command" message
    fi
    export DC
}
# Auto-detect on source so every phase that sources common.sh gets DC immediately.
detect_docker_compose

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
# ScoutSuite's CLI entry point is `scout` (single word), invoked as:
#   scout azure --tenant <id> --subscription <id> ...
# Sets global SCOUT_CMD_ARRAY for use as: "${SCOUT_CMD_ARRAY[@]}" azure ...
set_scout_cmd() {
    if command -v scout &>/dev/null; then
        SCOUT_CMD_ARRAY=( scout )
    elif python3 -c "import ScoutSuite" 2>/dev/null; then
        SCOUT_CMD_ARRAY=( python3 -m ScoutSuite )
    else
        SCOUT_CMD_ARRAY=( scout )  # will fail with clear "command not found" message
    fi
}

# ─── SYSTEM RESOURCE DETECTION ────────────────────────────────────────────────
# Detects vCPU count and available RAM, then derives tuning constants used across
# all phase scripts.  Call once at the top of each phase that launches parallel work.
# Exports: SYS_VCPUS  SYS_RAM_GB  NMAP_MIN_PARALLEL  NMAP_MAX_PARALLEL
#          HC_WORKLOAD  BH_WORKERS
detect_system_resources() {
    SYS_VCPUS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
    SYS_RAM_GB=$(awk '/MemTotal/{printf "%d",$2/1024/1024}' /proc/meminfo 2>/dev/null || echo 8)
    export SYS_VCPUS SYS_RAM_GB

    # Nmap parallelism — scales with vCPU count; cap at 500 to avoid flooding IDS.
    NMAP_MIN_PARALLEL=$(( SYS_VCPUS * 10 ))
    NMAP_MAX_PARALLEL=$(( SYS_VCPUS * 50 ))
    [[ ${NMAP_MAX_PARALLEL} -gt 500 ]] && NMAP_MAX_PARALLEL=500
    export NMAP_MIN_PARALLEL NMAP_MAX_PARALLEL

    # Hashcat workload profile: 3 = high (dedicated box), 2 = medium (<4 vCPUs)
    HC_WORKLOAD=3
    [[ ${SYS_VCPUS} -lt 4 ]] && HC_WORKLOAD=2
    export HC_WORKLOAD

    # BloodHound-python collection workers — network-bound, 5×vCPUs is safe
    BH_WORKERS=$(( SYS_VCPUS * 5 ))
    [[ ${BH_WORKERS} -gt 40 ]] && BH_WORKERS=40
    export BH_WORKERS

    log INFO "System: ${SYS_VCPUS} vCPU(s) | ${SYS_RAM_GB} GB RAM"
    log INFO "Tuned: nmap_parallel=${NMAP_MIN_PARALLEL}–${NMAP_MAX_PARALLEL} | hashcat_workload=-w ${HC_WORKLOAD} | bh_workers=${BH_WORKERS}"
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
# Ensure the log directory exists once at source time so the first `log` call
# does not fail when a phase script is invoked before phase0 has created dirs.
mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    # `>>` to a missing directory would fail under `set -e`; this guard keeps
    # logging non-fatal even if OUTPUT_BASE_DIR was mistyped.
    echo "## [${ts}] [${level}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
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
    {
        echo "\`\`\`"
        echo "$*"
        echo "\`\`\`"
    } >> "${LOG_FILE}" 2>/dev/null || true
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
    if [[ "$auto" == "--auto-proceed" || "${AUTO_APPROVE:-false}" == "true" ]]; then
        echo -e "${CYAN}  Auto-proceeding (AUTO_APPROVE=true)${RESET}"
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
# Usage:
#   check_testing_window            — active mode: prompts and may block outside hours
#   check_testing_window --passive  — passive mode: logs but never blocks (use for
#                                     offline/non-network jobs: Hashcat, log parsing).
#                                     The RoE testing window governs active network
#                                     attacks; local CPU jobs are not constrained by it.
check_testing_window() {
    local mode="${1:-active}"
    [[ "${ENFORCE_TESTING_WINDOW:-false}" != "true" ]] && return 0
    local current_time; current_time=$(date '+%H:%M')
    local start="${TESTING_WINDOW_START:-09:00}"
    local end="${TESTING_WINDOW_END:-17:00}"
    # Convert HH:MM to minutes-since-midnight for reliable numeric comparison
    _hm_to_min() {
        local h m
        IFS=: read -r h m <<< "$1"
        h="${h:-0}"; m="${m:-0}"
        echo $(( 10#$h * 60 + 10#$m ))
    }
    local cur_min start_min end_min
    cur_min=$(_hm_to_min "${current_time}")
    start_min=$(_hm_to_min "${start}")
    end_min=$(_hm_to_min "${end}")
    if (( cur_min < start_min || cur_min > end_min )); then
        if [[ "$mode" == "--passive" ]]; then
            log INFO "Outside testing window (${current_time}) — offline/passive job continues regardless"
            return 0
        fi
        # AUTO_APPROVE covers non-interactive pipeline runs where reading stdin
        # is impossible.  Orchestrator sets this when --auto-approve is passed.
        if [[ "${AUTO_APPROVE:-false}" == "true" ]]; then
            log WARN "Outside testing window (${current_time}) — auto-approved via AUTO_APPROVE=true"
            return 0
        fi
        echo -e "${RED}[SAFETY] Current time ${current_time} is outside testing window (${start}–${end}).${RESET}"
        echo -e "${YELLOW}Override? This may violate the Rules of Engagement. [y/N]:${RESET} \c"
        # Guard read against a non-interactive stdin (e.g. piped invocation) so the
        # phase script does not abort on EOF with a confusing exit-1 trace.
        local override=""
        read -r override || override=""
        if [[ "$override" != "y" && "$override" != "Y" ]]; then
            log WARN "Testing blocked outside hours at ${current_time}"
            exit 1
        fi
        log WARN "Testing window overridden by operator at ${current_time}"
    fi
}

# ─── BACKGROUND JOB MANAGER ───────────────────────────────────────────────────
# .bg_jobs — persistent PID record used by --status to track job completion.
# Format: PID|name|logfile|started_at
BG_JOBS_FILE="${OUTPUT_BASE_DIR:-${HOME}/vapt}/.bg_jobs"
BG_JOB_PIDS=()
BG_JOB_NAMES=()

bg_run() {
    # Usage: bg_run "job_name" "log_file" command [args...]
    #
    # Session-persistence: nohup ignores SIGHUP so the job continues if the terminal
    # closes.  disown removes it from bash's job table.  The PID is persisted to
    # BG_JOBS_FILE so orchestrator --status can track completion at any time.
    local name="$1"; local logfile="$2"; shift 2
    # Make sure the log file's parent directory exists before the child writes to it.
    mkdir -p "$(dirname "${logfile}")" 2>/dev/null || true
    log_cmd "$*"
    # Redirect stdin from /dev/null explicitly. nohup only does this automatically
    # when stdin IS a terminal; when invoked from the orchestrator's subprocess.run
    # stdin is a pipe, not a TTY, so nohup leaves it open. The orphaned background
    # job then holds a reference to the shell's stdin, preventing the terminal from
    # returning control cleanly after the phase script exits ("frozen terminal").
    nohup "$@" >> "${logfile}" 2>&1 < /dev/null &
    local pid=$!
    # `disown` fails (exit 1) if the child already exited before we got here —
    # e.g. nmap aborted instantly on a bad flag.  Under `set -e` that failure
    # would kill the whole phase script.  Suppress both the non-zero exit and
    # the "no such job" stderr so a fast-failing child surfaces via its own
    # logfile, not via a silent phase-script abort.
    disown "$pid" 2>/dev/null || true
    BG_JOB_PIDS+=("$pid")
    BG_JOB_NAMES+=("$name")
    # Ensure the persistent job record file and its parent directory exist.
    mkdir -p "$(dirname "${BG_JOBS_FILE}")" 2>/dev/null || true
    echo "${pid}|${name}|${logfile}|$(date '+%Y-%m-%d %H:%M:%S')" >> "${BG_JOBS_FILE}"
    log INFO "Background job started: ${name} (PID: ${pid}) → ${logfile}"
    echo -e "${GREEN}  [BG] ${name} (PID: ${pid}) running — terminal-safe (nohup/disown)${RESET}"
    echo -e "${CYAN}       Track progress: python3 orchestrator.py --status${RESET}"
}

wait_for_bg_jobs() {
    local label="${1:-all background jobs}"
    echo -e "\n${CYAN}Waiting for: ${label}${RESET}"
    # Guard against empty array under `set -u` — older bash treats "${!arr[@]}"
    # on an unset/empty array as an unbound-variable error.  When every sweep in
    # the loop was skipped (e.g. all .gnmap files already exist), BG_JOB_PIDS is
    # empty and this would otherwise abort the phase script.
    if [[ ${#BG_JOB_PIDS[@]} -eq 0 ]]; then
        log INFO "No background jobs to wait for (${label})"
        notify_complete "$label"
        return 0
    fi
    for i in "${!BG_JOB_PIDS[@]}"; do
        local pid="${BG_JOB_PIDS[$i]}"
        local name="${BG_JOB_NAMES[$i]}"
        # Use /proc/$pid (Linux procfs) instead of `kill -0`.
        # `kill -0` to a root-owned process (e.g. nmap -sS) from a non-root caller
        # returns exit 1 (EPERM) — indistinguishable from "process not found" —
        # so the loop exits immediately and LIVE_COUNT is checked before nmap writes
        # its .gnmap output.  /proc/$pid exists for any live process regardless of
        # ownership.  Fall back to kill -0 on non-Linux (macOS, BSD).
        _proc_alive() {
            local p="$1"
            if [[ -d /proc ]]; then
                [[ -d "/proc/${p}" ]]
            else
                kill -0 "$p" 2>/dev/null
            fi
        }
        if _proc_alive "$pid"; then
            echo -e "  ${YELLOW}⏳ Waiting for: ${name} (PID: ${pid})${RESET}"
            while _proc_alive "$pid"; do sleep 2; done
            log OK "${name} completed"
        else
            log OK "${name} already finished (PID: ${pid})"
        fi
        unset -f _proc_alive
    done
    BG_JOB_PIDS=(); BG_JOB_NAMES=()
    notify_complete "$label"
}

status_bg_jobs() {
    echo -e "\n${CYAN}Background Job Status (in-session):${RESET}"
    if [[ ${#BG_JOB_PIDS[@]} -eq 0 ]]; then
        echo -e "  No jobs tracked in this session."
        return 0
    fi
    for i in "${!BG_JOB_PIDS[@]}"; do
        local pid="${BG_JOB_PIDS[$i]}"
        local name="${BG_JOB_NAMES[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${YELLOW}⏳ Running:  ${name} (PID: ${pid})${RESET}"
        else
            echo -e "  ${GREEN}✔  Done:     ${name} (PID: ${pid})${RESET}"
        fi
    done
}

# morning_briefing — reads the persistent .bg_jobs file and reports current status.
# Usage: morning_briefing
morning_briefing() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  Background Job Status Report${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"

    if [[ ! -f "${BG_JOBS_FILE}" ]]; then
        echo -e "  ${YELLOW}No persistent job records found (${BG_JOBS_FILE} does not exist).${RESET}"
        echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}\n"
        return
    fi

    local running=0 done_count=0 seen_pids=()
    while IFS='|' read -r pid name logfile started_at; do
        [[ -z "$pid" || "$pid" =~ ^# ]] && continue
        # Deduplicate — if the same PID appears twice (phase re-run), show once
        local already_seen=false
        if [[ ${#seen_pids[@]} -gt 0 ]]; then
            for s in "${seen_pids[@]}"; do
                [[ "$s" == "$pid" ]] && already_seen=true && break
            done
        fi
        $already_seen && continue
        seen_pids+=("$pid")

        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${YELLOW}⏳ STILL RUNNING${RESET}  ${BOLD}${name}${RESET} (PID: ${pid})"
            echo -e "     Started:  ${started_at}"
            echo -e "     Log:      ${logfile}"
            running=$(( running + 1 ))
        else
            echo -e "  ${GREEN}✔  COMPLETED${RESET}    ${BOLD}${name}${RESET} (PID: ${pid})"
            echo -e "     Started:  ${started_at}"
            if [[ -f "${logfile}" ]]; then
                local tail_lines
                tail_lines=$(tail -3 "${logfile}" 2>/dev/null | grep -v '^$' | sed 's/^/             /')
                [[ -n "$tail_lines" ]] && echo -e "${tail_lines}"
            fi
            done_count=$(( done_count + 1 ))
        fi
        echo ""
    done < "${BG_JOBS_FILE}"

    echo -e "  ${GREEN}Completed: ${done_count}${RESET}   ${YELLOW}Still running: ${running}${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
    echo -e "  To re-run any failed phase: ${BOLD}python3 orchestrator.py --phase N${RESET}"
    echo -e "  Idempotency: completed steps are skipped automatically.\n"
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

# ─── CREDENTIAL NORMALISATION ─────────────────────────────────────────────────
# Users sometimes enter DOMAIN_USER as a UPN (jamiush@ha-shem.com) instead of
# just the sAMAccountName (jamiush). Every tool that takes both -u and -d builds
# the UPN internally, so passing the full UPN produces jamiush@ha-shem.com@ha-shem.com
# which every authenticator rejects. Strip the @domain suffix if present.
# Call after require_var "DOMAIN_USER" in every phase that uses credentials.
normalise_domain_user() {
    if [[ "${DOMAIN_USER:-}" == *@* ]]; then
        local _raw="${DOMAIN_USER}"
        DOMAIN_USER="${DOMAIN_USER%%@*}"
        export DOMAIN_USER
        log INFO "DOMAIN_USER normalised: '${_raw}' → '${DOMAIN_USER}' (use DOMAIN_NAME for the domain part)"
    fi
}

# ─── PRIMARY DC HELPER ────────────────────────────────────────────────────────
# DC_IP is a space-separated list (e.g. "10.10.1.10 10.10.1.11").
# Most tools accept only a single -dc-ip / -ns / ldap:// target — use the
# first IP for those.  Iterate over ${DC_IP} for checks covering every DC.
# Call this once near the top of each phase script after require_var "DC_IP".
set_primary_dc() {
    PRIMARY_DC="${DC_IP%% *}"
    export PRIMARY_DC
    if [[ "${DC_IP}" != "${PRIMARY_DC}" ]]; then
        log INFO "Multiple DCs configured. Primary DC: ${PRIMARY_DC}"
        log INFO "All DCs: ${DC_IP}"
    else
        log INFO "DC: ${PRIMARY_DC}"
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
    # if/fi ensures the function returns 0 when the var IS set.
    # The && form returns 1 (from the [[ ]] test) when the var is present,
    # which trips set -e in the caller even though nothing is wrong.
    if [[ -z "${!var_name:-}" ]]; then
        log ERROR "Required config variable not set: ${var_name}. Check config.env."
        exit 1
    fi
}

require_file() {
    local filepath="$1"
    [[ -f "$filepath" ]] || {
        log ERROR "Required file not found: ${filepath}"
        exit 1
    }
}

# prompt_credential VAR_NAME
# Use when the variable may legitimately be absent from config.env because the
# operator wants to supply it securely at runtime rather than storing it on disk.
# If the variable is already set (from config.env or a shell export) it is used
# as-is — no prompt is shown.  If it is unset or empty, the user is prompted:
# variables whose name contains PASS or SECRET are read with echo suppressed so
# the value never appears on screen or in shell history.
prompt_credential() {
    local varname="$1"
    if [[ -n "${!varname:-}" ]]; then return 0; fi
    if [[ "${varname}" == *PASS* || "${varname}" == *SECRET* || "${varname}" == *pass* ]]; then
        read -rsp "  [?] Enter ${varname}: " "${varname}"
        echo
    else
        read -rp  "  [?] Enter ${varname}: " "${varname}"
    fi
    if [[ -z "${!varname:-}" ]]; then
        log ERROR "${varname} is required but was not provided — aborting."
        exit 1
    fi
    export "${varname?}"
}

# ─── OUTPUT DIRECTORY HELPER ──────────────────────────────────────────────────
phase_dir() {
    local phase="$1"; local subdir="${2:-}"
    local dir="${OUTPUT_BASE_DIR}/${phase}${subdir:+/${subdir}}"
    mkdir -p "$dir"
    echo "$dir"
}

# ─── STEP SKIP CONTROLS ───────────────────────────────────────────────────────
# Driven by SKIP_STEPS and ONLY_STEPS env vars set by orchestrator --skip / --only.
#
# SKIP_STEPS="kerberoast,scoutsuite"  → run everything except those two steps
# ONLY_STEPS="bloodhound,roadrecon"   → run only those two steps, skip all others
#
# _step_is_skipped "key" [quiet]      → 0 = skip, 1 = proceed.
#   If the second arg is the literal string "quiet", no log/stdout line is
#   emitted.  Used by pre-flight checks (credential requirement scan) that
#   iterate many step keys and would otherwise flood the log with "Skipping".
_step_is_skipped() {
    local key="$1"
    local quiet="${2:-}"
    # --only mode: skip anything NOT in the list
    if [[ -n "${ONLY_STEPS:-}" ]]; then
        local item
        for item in ${ONLY_STEPS//,/ }; do
            [[ "${item// /}" == "$key" ]] && return 1  # in list → proceed
        done
        if [[ "${quiet}" != "quiet" ]]; then
            log INFO "Skipping (not in --only list): ${key}"
            echo -e "${YELLOW}  [SKIP] ${key} — not in --only list${RESET}"
        fi
        return 0  # not in list → skip
    fi
    # --skip mode: skip anything IN the list
    if [[ -n "${SKIP_STEPS:-}" ]]; then
        local item
        for item in ${SKIP_STEPS//,/ }; do
            if [[ "${item// /}" == "$key" ]]; then
                if [[ "${quiet}" != "quiet" ]]; then
                    log INFO "Skipping (--skip): ${key}"
                    echo -e "${YELLOW}  [SKIP] ${key} — excluded via --skip${RESET}"
                fi
                return 0  # in list → skip
            fi
        done
    fi
    return 1  # proceed
}

# ─── SKIP IF OUTPUT EXISTS ────────────────────────────────────────────────────
# Usage: skip_if_exists "filepath" "description" ["step_key"]
# If step_key is supplied it is also checked against SKIP_STEPS / ONLY_STEPS.
skip_if_exists() {
    local filepath="$1"; local desc="$2"; local key="${3:-}"
    # Explicit skip/only check takes priority over file existence
    if [[ -n "$key" ]] && _step_is_skipped "$key"; then
        return 0
    fi
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
    # Empty-array guard under `set -u`: older bash errors on "${arr[@]}" when arr
    # is empty/unset.  If no background jobs were launched, there's nothing to kill.
    if [[ ${#BG_JOB_PIDS[@]:-0} -eq 0 ]]; then
        log WARN "Session interrupted by operator (no background jobs to kill)"
        exit 1
    fi
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
