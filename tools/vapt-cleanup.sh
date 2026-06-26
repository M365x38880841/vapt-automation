#!/usr/bin/env bash
# =============================================================================
#  vapt-cleanup.sh
#  Post-Engagement Artifact Purge -- Ha-Shem VAPT Framework
#  Targets: Responder, Impacket, NXC/CrackMapExec, BloodHound CE,
#           bloodhound-python, Certipy, ROADrecon, ScoutSuite, Azure CLI,
#           Hashcat, nmap, ldap-utils, PingCastle, PurpleKnight
#
#  Usage:
#    sudo ./vapt-cleanup.sh [OPTIONS]
#
#  Options:
#    --dry-run        Show what would be deleted; delete nothing
#    --purge-tools    Also uninstall offensive tools from the system
#    --no-history     Skip shell history sanitization
#    --target-user    User whose home directory to clean (default: $SUDO_USER)
#    --help           Show this help
#
#  Output:
#    Audit log written to /var/log/vapt-cleanup-<DATE>.log
# =============================================================================

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
SCRIPT_VERSION="1.0.0"
DATE=$(date +%Y%m%d_%H%M%S)
AUDIT_LOG="/var/log/vapt-cleanup-${DATE}.log"
DRY_RUN=false
PURGE_TOOLS=false
SKIP_HISTORY=false
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
TARGET_HOME=""
DELETED_COUNT=0
SKIPPED_COUNT=0
SECTION_ERRORS=0

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Argument Parsing ─────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${BOLD}vapt-cleanup.sh v${SCRIPT_VERSION}${RESET}
Post-engagement artifact purge for Ha-Shem VAPT Kali framework.

${BOLD}USAGE:${RESET}
  sudo ./vapt-cleanup.sh [OPTIONS]

${BOLD}OPTIONS:${RESET}
  --dry-run        Print all actions without deleting anything
  --purge-tools    Uninstall offensive tools after artifact cleanup
  --no-history     Skip shell history sanitization
  --target-user    Username whose home to clean (default: \$SUDO_USER)
  --help           Show this message

${BOLD}EXAMPLES:${RESET}
  sudo ./vapt-cleanup.sh --dry-run
  sudo ./vapt-cleanup.sh
  sudo ./vapt-cleanup.sh --purge-tools --target-user kali
EOF
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)      DRY_RUN=true ;;
        --purge-tools)  PURGE_TOOLS=true ;;
        --no-history)   SKIP_HISTORY=true ;;
        --target-user=*) TARGET_USER="${arg#*=}" ;;
        --help)         usage ;;
        *)
            echo -e "${RED}[!] Unknown option: $arg${RESET}"
            usage
            ;;
    esac
done

# ── Privilege Check ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (sudo).${RESET}"
    exit 1
fi

# Resolve target home directory
if id "$TARGET_USER" &>/dev/null; then
    TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
else
    echo -e "${RED}[!] User '${TARGET_USER}' not found. Use --target-user=<username>${RESET}"
    exit 1
fi

# ── Logging Setup ────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$AUDIT_LOG")"
exec > >(tee -a "$AUDIT_LOG") 2>&1

log()     { echo -e "${DIM}[$(date +%H:%M:%S)]${RESET} $*"; }
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; SECTION_ERRORS=$((SECTION_ERRORS+1)); }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

# ── Core Helpers ─────────────────────────────────────────────────────────────

# Safely remove a file or directory, log it, count it
purge() {
    local target="$1"
    local desc="${2:-}"
    if [[ -e "$target" || -L "$target" ]]; then
        local label="${desc:-$target}"
        if [[ "$DRY_RUN" == true ]]; then
            warn "[DRY-RUN] Would delete: ${label}"
            SKIPPED_COUNT=$((SKIPPED_COUNT+1))
        else
            if rm -rf "$target" 2>/dev/null; then
                success "Deleted: ${label}"
                DELETED_COUNT=$((DELETED_COUNT+1))
            else
                error "Failed to delete: ${label}"
            fi
        fi
    fi
}

# Find and purge files matching a glob pattern under a base dir
purge_glob() {
    local basedir="$1"
    local pattern="$2"
    local desc="${3:-}"
    [[ -d "$basedir" ]] || return 0
    while IFS= read -r -d '' match; do
        purge "$match" "${desc:-$match}"
    done < <(find "$basedir" -maxdepth 4 -name "$pattern" -print0 2>/dev/null)
}

# Kill a process by name if running
kill_proc() {
    local proc="$1"
    if pgrep -x "$proc" &>/dev/null || pgrep -f "$proc" &>/dev/null; then
        if [[ "$DRY_RUN" == true ]]; then
            warn "[DRY-RUN] Would kill process: ${proc}"
        else
            pkill -9 -f "$proc" 2>/dev/null && success "Killed process: ${proc}" || \
                warn "Could not kill ${proc} (may have already exited)"
        fi
    else
        log "Process not running: ${proc}"
    fi
}

# Run a shell command (suppressed in dry-run)
run_cmd() {
    local desc="$1"; shift
    if [[ "$DRY_RUN" == true ]]; then
        warn "[DRY-RUN] Would run: $*"
    else
        if eval "$@" 2>/dev/null; then
            success "${desc}"
        else
            warn "${desc} -- command returned non-zero (may be harmless)"
        fi
    fi
}

# ── Banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${RED}"
cat << 'BANNER'
 _   _   _    ____ _____    ____ _     _____    _   _ _   _ ____
| | | | / \  |  _ \_   _|  / ___| |   | ____|  | | | | | | |  _ \
| |_| |/ _ \ | |_) || |   | |   | |   |  _|    | | | | |_| | |_) |
|  _  / ___ \|  __/ | |   | |___| |___| |___   | |_| |  _  |  __/
|_| |_/_/   \_\_|   |_|    \____|_____|_____|   \___/|_| |_|_|

BANNER
echo -e "${RESET}${BOLD}  Post-Engagement Artifact Cleanup  |  v${SCRIPT_VERSION}${RESET}"
echo -e "${DIM}  Audit log: ${AUDIT_LOG}${RESET}"
echo -e "${DIM}  Target user home: ${TARGET_HOME}${RESET}"
[[ "$DRY_RUN" == true ]] && echo -e "\n  ${YELLOW}${BOLD}DRY-RUN MODE -- Nothing will be deleted${RESET}"
echo ""

# ── PHASE 1: Kill Active Processes ───────────────────────────────────────────
section "PHASE 1: Terminating Active Tool Processes"

PROCESSES=(
    "responder"
    "Responder.py"
    "hashcat"
    "nmap"
    "netexec"
    "crackmapexec"
    "bloodhound"
    "roadrecon"
    "scoutsuite"
    "certipy"
    "bloodhound-python"
    "ldapsearch"
    "PingCastle"
)

for proc in "${PROCESSES[@]}"; do
    kill_proc "$proc"
done

# ── PHASE 2: Docker Teardown ─────────────────────────────────────────────────
section "PHASE 2: Docker -- BloodHound CE Stack Teardown"

if command -v docker &>/dev/null; then
    # Stop all running containers derived from BloodHound/ZAP images
    info "Stopping BloodHound CE containers..."
    BH_CONTAINERS=$(docker ps -q --filter "name=bloodhound" --filter "name=neo4j" \
                    --filter "name=postgres" --filter "name=zap" 2>/dev/null || true)

    if [[ -n "$BH_CONTAINERS" ]]; then
        run_cmd "Stopped BloodHound/ZAP containers" \
            "docker stop $BH_CONTAINERS"
        run_cmd "Removed BloodHound/ZAP containers" \
            "docker rm $BH_CONTAINERS"
    else
        log "No BloodHound/ZAP containers currently running"
    fi

    # Find and purge BloodHound docker-compose data directories
    info "Scanning for BloodHound docker-compose project directories..."
    BH_COMPOSE_DIRS=(
        "${TARGET_HOME}/BloodHound"
        "${TARGET_HOME}/bloodhound"
        "${TARGET_HOME}/bhce"
        "/opt/BloodHound"
        "/opt/bloodhound"
    )
    for dir in "${BH_COMPOSE_DIRS[@]}"; do
        if [[ -f "${dir}/docker-compose.yml" || -f "${dir}/docker-compose.yaml" ]]; then
            info "Found BloodHound compose project at: ${dir}"
            if [[ "$DRY_RUN" == false ]]; then
                (cd "$dir" && docker compose down -v --remove-orphans 2>/dev/null) && \
                    success "docker compose down completed for ${dir}" || \
                    warn "docker compose down failed at ${dir} -- continuing"
            else
                warn "[DRY-RUN] Would run: docker compose down -v at ${dir}"
            fi
        fi
    done

    # Purge named Docker volumes associated with BloodHound
    info "Removing BloodHound-related Docker volumes..."
    BH_VOLUMES=$(docker volume ls -q 2>/dev/null | \
        grep -iE "bloodhound|neo4j|bhce" || true)
    if [[ -n "$BH_VOLUMES" ]]; then
        for vol in $BH_VOLUMES; do
            run_cmd "Removed Docker volume: ${vol}" "docker volume rm $vol"
        done
    else
        log "No BloodHound-related Docker volumes found"
    fi

    # Remove ZAP Docker image data
    info "Removing OWASP ZAP Docker images..."
    ZAP_IMAGES=$(docker images -q "ghcr.io/zaproxy/zaproxy" "owasp/zap2docker-stable" \
                 "owasp/zap2docker-weekly" 2>/dev/null || true)
    if [[ -n "$ZAP_IMAGES" ]]; then
        run_cmd "Removed ZAP images" "docker rmi -f $ZAP_IMAGES"
    else
        log "No ZAP images found"
    fi

    # Prune dangling images and build cache
    run_cmd "Pruned dangling Docker images and build cache" \
        "docker image prune -f && docker builder prune -f"
else
    warn "Docker not found -- skipping container teardown"
fi

# ── PHASE 3: Responder ───────────────────────────────────────────────────────
section "PHASE 3: Responder -- NTLMv2 Hashes, Logs, Database"

RESPONDER_DIRS=(
    "/usr/share/responder/logs"
    "/usr/lib/python3/dist-packages/responder/logs"
    "${TARGET_HOME}/.responder"
)

for dir in "${RESPONDER_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        info "Purging Responder logs at: ${dir}"
        while IFS= read -r -d '' f; do
            purge "$f"
        done < <(find "$dir" -type f -print0 2>/dev/null)
    fi
done

# Responder SQLite DB (stores all captured hashes)
RESPONDER_DB_PATHS=(
    "/usr/share/responder/Responder.db"
    "/usr/lib/python3/dist-packages/responder/Responder.db"
    "${TARGET_HOME}/Responder.db"
)
for db in "${RESPONDER_DB_PATHS[@]}"; do
    purge "$db" "Responder hash database: $db"
done

# Responder challenge files
purge_glob "/usr/share/responder" "*.log" "Responder log"
purge_glob "/usr/share/responder" "*.txt" "Responder capture text"

# ── PHASE 4: Impacket ────────────────────────────────────────────────────────
section "PHASE 4: Impacket -- Kerberos Tickets, Hash Files, Output"

# Kerberos ccache tickets (KRB5CCNAME artifacts)
info "Scanning for Kerberos .ccache ticket files..."
CCACHE_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "/tmp"
    "/var/tmp"
    "/root"
)
for sdir in "${CCACHE_SEARCH_DIRS[@]}"; do
    purge_glob "$sdir" "*.ccache" "Kerberos TGT/TGS ticket"
    purge_glob "$sdir" "krb5cc_*" "Kerberos credential cache"
done

# Also clear system KRB5CCNAME if set
KRB5CC="${KRB5CCNAME:-}"
if [[ -n "$KRB5CC" && -f "$KRB5CC" ]]; then
    purge "$KRB5CC" "Active KRB5CCNAME ticket file"
fi

# Keytab files
purge_glob "${TARGET_HOME}" "*.keytab" "Kerberos keytab"
purge_glob "/tmp" "*.keytab" "Kerberos keytab"

# secretsdump output (common naming conventions)
info "Scanning for secretsdump output files..."
DUMP_PATTERNS=("*.ntds" "*.dit" "*SAM*" "*SYSTEM*" "*SECURITY*" \
               "*secretsdump*" "*hashes*" "*ntlm*" "*.hash")
for pattern in "${DUMP_PATTERNS[@]}"; do
    purge_glob "${TARGET_HOME}" "$pattern" "secretsdump/hash dump output"
    purge_glob "/tmp" "$pattern" "secretsdump/hash dump output"
    purge_glob "/root" "$pattern" "secretsdump/hash dump output"
done

# Impacket-generated SMB server drop directories
purge_glob "/tmp" "*.tmp" "Impacket temporary file"
purge_glob "${TARGET_HOME}" "impacket_*" "Impacket working file"
purge_glob "${TARGET_HOME}" "*.ldt" "Impacket NTDS/VSS artifact"

# ── PHASE 5: NXC / CrackMapExec ─────────────────────────────────────────────
section "PHASE 5: NXC / CrackMapExec -- Credential Database"

NXC_WORKSPACE_DIRS=(
    "${TARGET_HOME}/.nxc/workspaces"
    "${TARGET_HOME}/.cme/workspaces"
    "/root/.nxc/workspaces"
    "/root/.cme/workspaces"
)

for dir in "${NXC_WORKSPACE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        info "Purging NXC/CME workspace (credential cache) at: ${dir}"
        purge "$dir" "NXC/CME workspace credential database"
    fi
done

# NXC logs
NXC_LOG_DIRS=(
    "${TARGET_HOME}/.nxc/logs"
    "${TARGET_HOME}/.cme/logs"
    "/root/.nxc/logs"
    "/root/.cme/logs"
)
for dir in "${NXC_LOG_DIRS[@]}"; do
    [[ -d "$dir" ]] && purge "$dir" "NXC/CME logs"
done

# CME/NXC screenshots (if rdp module was used)
purge_glob "${TARGET_HOME}/.nxc" "*.png" "NXC screenshot"
purge_glob "${TARGET_HOME}/.cme" "*.png" "CME screenshot"

# ── PHASE 6: BloodHound CE Local Data ───────────────────────────────────────
section "PHASE 6: BloodHound CE -- Graph Data, JSON Ingestors, ZIP Files"

# SharpHound/bloodhound-python output ZIPs and JSON
BH_DATA_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "${TARGET_HOME}/Downloads"
    "/tmp"
    "/root"
)

info "Scanning for BloodHound ingestor output files..."
BH_PATTERNS=(
    "*BloodHound*.zip"
    "*bloodhound*.zip"
    "*SharpHound*.zip"
    "*sharphound*.zip"
    "*.bloodhound.zip"
    "20[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_BloodHound.zip"
    "*_computers.json"
    "*_users.json"
    "*_groups.json"
    "*_domains.json"
    "*_gpos.json"
    "*_ous.json"
    "*_containers.json"
    "*_sessions.json"
    "*_acls.json"
    "*_localadmins.json"
    "*_dconly.json"
)

for basedir in "${BH_DATA_SEARCH_DIRS[@]}"; do
    for pattern in "${BH_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "BloodHound ingestor data"
    done
done

# BloodHound CLI config / local state
BH_CLI_DIRS=(
    "${TARGET_HOME}/.config/bloodhound-cli"
    "${TARGET_HOME}/.local/share/bloodhound-cli"
    "${TARGET_HOME}/.bloodhound"
)
for dir in "${BH_CLI_DIRS[@]}"; do
    [[ -d "$dir" ]] && purge "$dir" "bloodhound-cli local config/state"
done

# ── PHASE 7: Certipy ─────────────────────────────────────────────────────────
section "PHASE 7: Certipy -- Certificates, PFX Files, PKINIT Hashes"

info "Scanning for Certipy certificate artifacts..."
CERT_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "/tmp"
    "/root"
)

CERT_PATTERNS=("*.pfx" "*.crt" "*.p12" "*.b64" \
               "*certipy*" "*_cert*" "*_ca*")

for basedir in "${CERT_SEARCH_DIRS[@]}"; do
    for pattern in "${CERT_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "Certipy certificate/key artifact"
    done
done

# .key and .pem scoped to /tmp only — avoids nuking legitimate SSH keys or TLS certs in $HOME
purge_glob "/tmp" "*.key" "Private key in /tmp"
purge_glob "/tmp" "*.pem" "PEM file in /tmp"

# AS-REP hash files output by Certipy
purge_glob "${TARGET_HOME}" "*asrep*" "AS-REP hash file"
purge_glob "/tmp" "*asrep*" "AS-REP hash file"

# Certipy output text files
purge_glob "${TARGET_HOME}" "*.txt.certipy" "Certipy output"
purge_glob "${TARGET_HOME}" "certipy_*" "Certipy output"

# ── PHASE 8: ROADrecon ───────────────────────────────────────────────────────
section "PHASE 8: ROADrecon -- Entra ID Graph Database"

ROAD_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "/tmp"
    "/root"
)

info "Scanning for ROADrecon database and output files..."
ROAD_PATTERNS=("roadrecon.db" "roadrecon-gui*" "roadtools*" "*.roadrecon")

for basedir in "${ROAD_SEARCH_DIRS[@]}"; do
    for pattern in "${ROAD_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "ROADrecon Entra ID database/output"
    done
done

# ROADrecon output directory
ROAD_OUTPUT_DIRS=(
    "${TARGET_HOME}/roadrecon-gui"
    "${TARGET_HOME}/roadtools"
    "/tmp/roadrecon-gui"
)
for dir in "${ROAD_OUTPUT_DIRS[@]}"; do
    [[ -d "$dir" ]] && purge "$dir" "ROADrecon output directory"
done

# ── PHASE 9: ScoutSuite ──────────────────────────────────────────────────────
section "PHASE 9: ScoutSuite -- Azure/Cloud Security Audit Reports"

SCOUT_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "/root"
)

info "Scanning for ScoutSuite report directories..."
# ScoutSuite creates scoutsuite-report/ and scoutsuite-results/
for basedir in "${SCOUT_SEARCH_DIRS[@]}"; do
    purge_glob "$basedir" "scoutsuite-report" "ScoutSuite HTML report"
    purge_glob "$basedir" "scoutsuite-results" "ScoutSuite results"
    purge_glob "$basedir" "scoutsuite_results*" "ScoutSuite results"
    purge_glob "$basedir" "*.scout" "ScoutSuite scan file"
done

# ScoutSuite credentials / exception files
SCOUT_CONFIG_DIRS=(
    "${TARGET_HOME}/.scoutsuite"
    "${TARGET_HOME}/.config/scoutsuite"
)
for dir in "${SCOUT_CONFIG_DIRS[@]}"; do
    [[ -d "$dir" ]] && purge "$dir" "ScoutSuite config/exceptions"
done

# ── PHASE 10: Azure CLI Tokens ───────────────────────────────────────────────
section "PHASE 10: Azure CLI -- Persistent Auth Tokens and Session Cache"

AZURE_DIRS=(
    "${TARGET_HOME}/.azure"
    "/root/.azure"
)

for dir in "${AZURE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        info "Revoking and purging Azure CLI session: ${dir}"
        if [[ "$DRY_RUN" == false ]]; then
            # Gracefully log out first (best effort)
            su -c "az logout 2>/dev/null; az account clear 2>/dev/null" \
                "$TARGET_USER" || true
        else
            warn "[DRY-RUN] Would run: az logout && az account clear"
        fi
        purge "$dir" "Azure CLI token/session cache"
    fi
done

# Azure PowerShell token cache (if Az module was used)
AZPS_TOKEN_DIRS=(
    "${TARGET_HOME}/.azure-ps"
    "${TARGET_HOME}/.AzurePowerShell"
)
for dir in "${AZPS_TOKEN_DIRS[@]}"; do
    [[ -d "$dir" ]] && purge "$dir" "Azure PowerShell token cache"
done

# ── PHASE 11: Hashcat ────────────────────────────────────────────────────────
section "PHASE 11: Hashcat -- Potfile, Cracked Passwords, Session Files"

HASHCAT_DIRS=(
    "${TARGET_HOME}/.hashcat"
    "/root/.hashcat"
    "${TARGET_HOME}/.local/share/hashcat"
)

for dir in "${HASHCAT_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        info "Purging Hashcat data at: ${dir}"
        # Potfile holds all cracked plaintext passwords
        purge "${dir}/hashcat.potfile" "Hashcat potfile (cracked plaintexts)"
        purge_glob "$dir" "*.session" "Hashcat restore session"
        purge_glob "$dir" "*.restore" "Hashcat restore file"
        purge_glob "$dir" "*.log" "Hashcat log"
    fi
done

# Standalone hash input files in common locations
HASH_FILE_PATTERNS=("*.hashes" "*.hash" "*ntlm*.txt" "*kerberoast*" \
                    "*asrep*.txt" "*hccapx" "*.hcmask")
for pattern in "${HASH_FILE_PATTERNS[@]}"; do
    purge_glob "${TARGET_HOME}" "$pattern" "Hashcat input hash file"
    purge_glob "/tmp" "$pattern" "Hashcat input hash file"
    purge_glob "/root" "$pattern" "Hashcat input hash file"
done

# ── PHASE 12: Nmap ───────────────────────────────────────────────────────────
section "PHASE 12: Nmap -- Scan Output Files (XML, grepable, normal)"

NMAP_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/scans"
    "/tmp"
    "/root"
)

NMAP_PATTERNS=("*.nmap.xml" "*.gnmap" "*.nmap" "*nmap*")

info "Scanning for Nmap output files..."
for basedir in "${NMAP_SEARCH_DIRS[@]}"; do
    for pattern in "${NMAP_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "Nmap scan output"
    done
done

# ── PHASE 13: ldap-utils ─────────────────────────────────────────────────────
section "PHASE 13: ldap-utils -- ldapsearch Output Files"

LDAP_SEARCH_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "/tmp"
    "/root"
)

LDAP_PATTERNS=("*.ldif" "*ldap*dump*" "*ldap*output*" "*ldapsearch*")

info "Scanning for ldapsearch output files..."
for basedir in "${LDAP_SEARCH_DIRS[@]}"; do
    for pattern in "${LDAP_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "ldapsearch output file"
    done
done

# ── PHASE 14: PingCastle / PurpleKnight ─────────────────────────────────────
section "PHASE 14: PingCastle and PurpleKnight -- AD Audit Reports"

AUDIT_REPORT_DIRS=(
    "${TARGET_HOME}"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "/tmp"
    "/root"
    "/mnt"
)

PC_PATTERNS=("*ad_hc_*" "*PingCastle*" "*pingcastle*" "*.xml.healthcheck" \
             "ad_hc_*.html" "ad_hc_*.xml")
PK_PATTERNS=("*PurpleKnight*" "*purpleknight*" "PKResults*" "*.purple")

info "Scanning for PingCastle output..."
for basedir in "${AUDIT_REPORT_DIRS[@]}"; do
    for pattern in "${PC_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "PingCastle AD audit report"
    done
done

info "Scanning for PurpleKnight output..."
for basedir in "${AUDIT_REPORT_DIRS[@]}"; do
    for pattern in "${PK_PATTERNS[@]}"; do
        purge_glob "$basedir" "$pattern" "PurpleKnight AD audit report"
    done
done

# ── PHASE 15: Shell History Sanitization ─────────────────────────────────────
section "PHASE 15: Shell History -- Credential and Command Sanitization"

if [[ "$SKIP_HISTORY" == true ]]; then
    warn "Skipping shell history sanitization (--no-history flag set)"
else
    # Patterns that may appear in history with plaintext credentials
    SENSITIVE_HISTORY_PATTERNS=(
        'responder'
        'secretsdump'
        'GetNPUsers'
        'GetUserSPNs'
        'psexec'
        'wmiexec'
        'smbexec'
        'ntlmrelayx'
        'crackmapexec'
        'netexec'
        ' nxc '
        'certipy'
        'bloodhound'
        'roadrecon'
        'scoutsuite'
        'hashcat'
        'az login'
        'ldapsearch'
        '\-p [^\-]'
        '\-password'
        'Password@'
        'password='
        'passwd'
    )

    HISTORY_FILES=(
        "${TARGET_HOME}/.bash_history"
        "${TARGET_HOME}/.zsh_history"
        "${TARGET_HOME}/.zhistory"
        "/root/.bash_history"
        "/root/.zsh_history"
        "/root/.zhistory"
    )

    for hfile in "${HISTORY_FILES[@]}"; do
        if [[ -f "$hfile" ]]; then
            info "Processing history file: ${hfile}"
            if [[ "$DRY_RUN" == true ]]; then
                COUNT=0
                for pattern in "${SENSITIVE_HISTORY_PATTERNS[@]}"; do
                    MATCHES=$(grep -cE "$pattern" "$hfile" 2>/dev/null || true)
                    COUNT=$((COUNT + MATCHES))
                done
                warn "[DRY-RUN] Found ~${COUNT} sensitive command lines in ${hfile}"
            else
                # Build sed expression to strip all sensitive lines
                SED_EXPR=""
                for pattern in "${SENSITIVE_HISTORY_PATTERNS[@]}"; do
                    SED_EXPR="${SED_EXPR}/${pattern}/d;"
                done
                BEFORE=$(wc -l < "$hfile")
                sed -i -E "$SED_EXPR" "$hfile" 2>/dev/null && \
                    AFTER=$(wc -l < "$hfile") && \
                    success "Sanitized ${hfile}: removed $((BEFORE - AFTER)) sensitive lines"
                DELETED_COUNT=$((DELETED_COUNT+1))
            fi
        fi
    done

    # Fish shell history
    FISH_HISTORY="${TARGET_HOME}/.local/share/fish/fish_history"
    if [[ -f "$FISH_HISTORY" ]]; then
        if [[ "$DRY_RUN" == true ]]; then
            warn "[DRY-RUN] Would sanitize fish shell history: ${FISH_HISTORY}"
        else
            # Fish history is YAML-like; remove cmd blocks containing sensitive terms
            python3 - "$FISH_HISTORY" <<'PYEOF' 2>/dev/null && \
                success "Sanitized fish shell history" || \
                warn "Fish history sanitization skipped (non-fatal)"
import sys, re

sensitive = re.compile(
    r'responder|secretsdump|crackmapexec|netexec|certipy|bloodhound|'
    r'roadrecon|scoutsuite|hashcat|az login|ldapsearch|GetNPUsers|'
    r'GetUserSPNs|ntlmrelayx|psexec|wmiexec|password=|passwd',
    re.IGNORECASE
)

path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Split into entry blocks (each starts with "- cmd:")
blocks = re.split(r'(?=^- cmd:)', content, flags=re.MULTILINE)
clean = [b for b in blocks if not sensitive.search(b)]

with open(path, 'w') as f:
    f.write(''.join(clean))
PYEOF
        fi
    fi

    # Clear in-memory history for current shell sessions (best effort)
    if [[ "$DRY_RUN" == false ]]; then
        run_cmd "Cleared root bash in-memory history" "history -c 2>/dev/null || true"
    fi
fi

# ── PHASE 16: /tmp and /var/tmp Sweep ────────────────────────────────────────
section "PHASE 16: /tmp and /var/tmp -- Engagement Working Files"

TMP_SENSITIVE_PATTERNS=(
    "*.ccache"
    "*.pfx"
    "*.hash"
    "*.hashes"
    "*.ntds"
    "*BloodHound*"
    "*SharpHound*"
    "*responder*"
    "*impacket*"
    "krb5cc_*"
    "*.keytab"
    "roadrecon*"
    "scoutsuite*"
    "certipy*"
    "nmap*"
    "*.gnmap"
    "*.ldif"
)

for pattern in "${TMP_SENSITIVE_PATTERNS[@]}"; do
    purge_glob "/tmp" "$pattern" "/tmp engagement artifact"
    purge_glob "/var/tmp" "$pattern" "/var/tmp engagement artifact"
done

# ── PHASE 17: SSH known_hosts Cleanup ────────────────────────────────────────
section "PHASE 17: SSH known_hosts -- Test Segment Host Entries"

KNOWN_HOSTS_FILES=(
    "${TARGET_HOME}/.ssh/known_hosts"
    "/root/.ssh/known_hosts"
)

for kh in "${KNOWN_HOSTS_FILES[@]}"; do
    if [[ -f "$kh" ]]; then
        info "Review SSH known_hosts: ${kh}"
        info "Manual action needed -- inspect and remove test segment IPs:"
        grep -vE "^(#|$)" "$kh" 2>/dev/null | \
            awk '{print "  " $1}' | head -20 || true
        warn "To remove a specific host: ssh-keygen -R <target-ip> -f ${kh}"
        warn "Automated removal skipped -- requires your test subnet CIDR"
    fi
done

# ── PHASE 18: Config Files with Embedded Credentials ────────────────────────
section "PHASE 18: Config Files -- Embedded Credential Sweep"

# Responder.conf (may have analysis-mode settings revealing scope)
purge_glob "/usr/share/responder" "Responder.conf.bak" "Responder config backup"

# Git config credential caches
if [[ -f "${TARGET_HOME}/.git-credentials" ]]; then
    purge "${TARGET_HOME}/.git-credentials" "Git plaintext credential store"
fi

# netrc file (may have AD/SMB creds)
if [[ -f "${TARGET_HOME}/.netrc" ]]; then
    warn "Found .netrc file -- review manually: ${TARGET_HOME}/.netrc"
    info "If it contains engagement credentials, run: purge ${TARGET_HOME}/.netrc"
fi

# pipx environments containing tool state
PIPX_TOOL_DIRS=(
    "${TARGET_HOME}/.local/pipx/venvs/bloodhound"
    "${TARGET_HOME}/.local/pipx/venvs/roadrecon"
    "${TARGET_HOME}/.local/pipx/venvs/scoutsuite"
    "${TARGET_HOME}/.local/pipx/venvs/certipy-ad"
    "${TARGET_HOME}/.local/pipx/venvs/impacket"
)
# Note: these are tool installs, not data -- only purge if --purge-tools
if [[ "$PURGE_TOOLS" == true ]]; then
    for pdir in "${PIPX_TOOL_DIRS[@]}"; do
        [[ -d "$pdir" ]] && purge "$pdir" "pipx tool environment (--purge-tools)"
    done
fi

# ── PHASE 19: Tool Uninstall (optional) ──────────────────────────────────────
if [[ "$PURGE_TOOLS" == true ]]; then
    section "PHASE 19: Tool Uninstall (--purge-tools)"

    warn "Uninstalling offensive tools from system..."

    # pipx tools
    PIPX_TOOLS=(
        "bloodhound"
        "impacket"
        "certipy-ad"
        "roadrecon"
        "scoutsuite"
    )
    if command -v pipx &>/dev/null; then
        for tool in "${PIPX_TOOLS[@]}"; do
            run_cmd "Uninstalled pipx tool: ${tool}" "pipx uninstall $tool 2>/dev/null || true"
        done
    fi

    # apt packages
    APT_TOOLS=(
        "responder"
        "nxc"
        "crackmapexec"
        "hashcat"
        "ldap-utils"
        "nmap"
        "bloodhound-cli"
    )
    if command -v apt-get &>/dev/null; then
        run_cmd "Removed apt offensive tools" \
            "apt-get remove --purge -y ${APT_TOOLS[*]} 2>/dev/null || true"
        run_cmd "Autoremoving orphaned packages" "apt-get autoremove -y 2>/dev/null || true"
    fi
else
    info "Skipping tool uninstall (pass --purge-tools to enable)"
fi

# ── PHASE 20: Final Verification ─────────────────────────────────────────────
section "PHASE 20: Post-Cleanup Verification"

VERIFY_CHECKS=(
    "Responder logs|/usr/share/responder/logs|*.log"
    "Responder DB|/usr/share/responder|Responder.db"
    "NXC workspace|${TARGET_HOME}/.nxc/workspaces|*"
    "NXC workspace|${TARGET_HOME}/.cme/workspaces|*"
    "Azure CLI tokens|${TARGET_HOME}/.azure|*"
    "Hashcat potfile|${TARGET_HOME}/.hashcat|*.potfile"
    "BloodHound ZIPs|${TARGET_HOME}|*BloodHound*.zip"
    "Certipy PFX|${TARGET_HOME}|*.pfx"
    "ROADrecon DB|${TARGET_HOME}|roadrecon.db"
)

ALL_CLEAR=true
for check in "${VERIFY_CHECKS[@]}"; do
    IFS='|' read -r label basedir pattern <<< "$check"
    REMAINING=$(find "$basedir" -name "$pattern" 2>/dev/null | wc -l)
    if [[ "$REMAINING" -gt 0 ]]; then
        warn "VERIFY FAIL: ${label} -- ${REMAINING} file(s) still present in ${basedir}"
        ALL_CLEAR=false
    else
        success "VERIFY OK: ${label} -- clean"
    fi
done

# Check for running processes
for proc in "responder" "bloodhound" "hashcat"; do
    if pgrep -f "$proc" &>/dev/null; then
        warn "VERIFY FAIL: Process still running -- ${proc}"
        ALL_CLEAR=false
    else
        success "VERIFY OK: ${proc} not running"
    fi
done

# Check Azure CLI is logged out
if command -v az &>/dev/null; then
    AZ_ACCOUNT=$(az account show 2>/dev/null || true)
    if [[ -n "$AZ_ACCOUNT" ]]; then
        warn "VERIFY FAIL: Azure CLI session still active -- run 'az logout' manually"
        ALL_CLEAR=false
    else
        success "VERIFY OK: Azure CLI -- no active session"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "CLEANUP SUMMARY"

echo ""
if [[ "$DRY_RUN" == true ]]; then
    echo -e "  ${YELLOW}${BOLD}Mode:${RESET}              DRY RUN (nothing deleted)"
    echo -e "  ${YELLOW}${BOLD}Would skip:${RESET}        ${SKIPPED_COUNT} items"
else
    echo -e "  ${GREEN}${BOLD}Mode:${RESET}              LIVE"
    echo -e "  ${GREEN}${BOLD}Items purged:${RESET}      ${DELETED_COUNT}"
fi
echo -e "  ${BOLD}Section errors:${RESET}    ${SECTION_ERRORS}"
echo -e "  ${BOLD}Audit log:${RESET}         ${AUDIT_LOG}"
echo ""

if [[ "$ALL_CLEAR" == true && "$DRY_RUN" == false ]]; then
    echo -e "  ${GREEN}${BOLD}[✓] All verified checks passed. Environment is clean.${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}[!] Some items require manual attention (see warnings above).${RESET}"
fi

echo ""
echo -e "${BOLD}${CYAN}Manual actions still required:${RESET}"
echo -e "  1. Revoke any test accounts / service principals in ${BOLD}Entra ID portal${RESET}"
echo -e "     (Entra ID > Users > [test user] > Revoke sessions)"
echo -e "  2. Rotate passwords for any AD accounts whose hashes were captured"
echo -e "  3. Remove test segment SSH entries: ${BOLD}ssh-keygen -R <host>${RESET}"
echo -e "  4. Review ${BOLD}~/.ssh/known_hosts${RESET} and remove test segment entries"
echo -e "  5. If BloodHound CE data was uploaded to a hosted instance, ${BOLD}purge it from the UI${RESET}"
echo -e "  6. Shred this machine's disk if decommissioning: ${BOLD}shred -vfz /dev/sdX${RESET}"
echo -e "  7. File the cleanup audit log (${AUDIT_LOG}) in your engagement closure package"
echo ""
echo -e "${DIM}  Completed at: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo ""
