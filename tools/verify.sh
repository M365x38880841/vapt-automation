#!/usr/bin/env bash
# ============================================================================
# tools/verify.sh — Pre-engagement environment verification
# Run this 48 hours before Day 1 to catch issues while there is still time.
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BOLD='\033[1m'; RESET='\033[0m'

PASS=0; WARN=0; FAIL=0

ok()   { echo -e "  ${GREEN}✔${RESET}  $*"; (( PASS++ )); }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; (( WARN++ )); }
fail() { echo -e "  ${RED}✘${RESET}  $*"; (( FAIL++ )); }

section() { echo -e "\n${BOLD}$*${RESET}"; }

# ─── TOOL AVAILABILITY ───────────────────────────────────────────────────────
section "Tool availability"
for tool in nmap responder hashcat ldapsearch az; do
    command -v "$tool" &>/dev/null \
        && ok "${tool} → $(command -v "$tool")" \
        || fail "${tool} not found — run Phase 0 to install"
done

# nxc / crackmapexec
if command -v nxc &>/dev/null; then
    ok "nxc (NetExec) → $(command -v nxc)"
elif command -v crackmapexec &>/dev/null; then
    ok "crackmapexec → $(command -v crackmapexec)"
else
    fail "nxc / crackmapexec not found — run Phase 0 to install"
fi

# bloodhound-python
if command -v bloodhound-python &>/dev/null; then
    ok "bloodhound-python → $(command -v bloodhound-python)"
elif pipx list 2>/dev/null | grep -q bloodhound; then
    warn "bloodhound-python installed via pipx but not on PATH — run: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
else
    fail "bloodhound-python not found — run Phase 0 to install"
fi

# roadrecon
command -v roadrecon &>/dev/null \
    && ok "roadrecon → $(command -v roadrecon)" \
    || fail "roadrecon not found — run Phase 0 to install"

# Impacket tools
for tool in impacket-GetUserSPNs impacket-GetNPUsers impacket-secretsdump impacket-ntlmrelayx; do
    command -v "$tool" &>/dev/null \
        && ok "${tool}" \
        || fail "${tool} not found — run Phase 0 to install impacket"
done

# certipy-ad
if command -v certipy-ad &>/dev/null || command -v certipy &>/dev/null; then
    ok "certipy-ad → $(command -v certipy-ad 2>/dev/null || command -v certipy)"
else
    warn "certipy-ad not found — AD CS checks will be skipped in Phase 2"
fi

# ─── SCOUTSUITE ──────────────────────────────────────────────────────────────
section "ScoutSuite"
if scout suite --help &>/dev/null 2>&1; then
    ok "ScoutSuite: 'scout suite' invocation works"
elif python3 -c "import ScoutSuite" &>/dev/null 2>&1; then
    ok "ScoutSuite: available as 'python3 -m ScoutSuite'"
else
    fail "ScoutSuite not installed or not invokable — run Phase 0 to install"
fi

# ─── DOCKER ──────────────────────────────────────────────────────────────────
section "Docker"
if command -v docker &>/dev/null; then
    if docker info &>/dev/null 2>&1; then
        ok "Docker daemon running — $(docker version --format 'v{{.Server.Version}}' 2>/dev/null || echo 'version unknown')"
    else
        fail "Docker binary found but daemon not running — run: sudo service docker start"
    fi
else
    fail "Docker not installed — run Phase 0"
fi

if docker compose version &>/dev/null 2>&1; then
    ok "docker compose plugin — $(docker compose version --short 2>/dev/null || echo 'ok')"
else
    fail "docker compose plugin missing — run: sudo apt-get install docker-compose-plugin"
fi

if groups "$USER" 2>/dev/null | grep -q '\bdocker\b'; then
    ok "User '${USER}' is in the docker group (passwordless docker)"
else
    warn "User '${USER}' not in docker group — docker commands require sudo"
fi

# ─── BLOODHOUND CE STACK ─────────────────────────────────────────────────────
section "BloodHound CE"
BHCE_COMPOSE="${PROJECT_ROOT}/tools/bloodhound-ce/docker-compose.yml"
BHCE_CONFIG="${PROJECT_ROOT}/tools/bloodhound-ce/bloodhound.config.json"

[[ -f "${BHCE_COMPOSE}" ]] \
    && ok "docker-compose.yml present" \
    || fail "docker-compose.yml missing — check tools/bloodhound-ce/"

[[ -f "${BHCE_CONFIG}" ]] \
    && ok "bloodhound.config.json present" \
    || fail "bloodhound.config.json missing — check tools/bloodhound-ce/"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    if docker compose -f "${BHCE_COMPOSE}" ps 2>/dev/null | grep -qE 'running|Up|healthy'; then
        ok "BloodHound CE stack is running → http://localhost:8080"
    else
        warn "BloodHound CE stack not running — start with: docker compose -f ${BHCE_COMPOSE} up -d"
    fi
fi

# ─── AZURE CLI ───────────────────────────────────────────────────────────────
section "Azure CLI"
if command -v az &>/dev/null; then
    az_user=$(az account show --query 'user.name' -o tsv 2>/dev/null || echo "")
    if [[ -n "${az_user}" ]]; then
        ok "Azure CLI authenticated as: ${az_user}"
    else
        warn "Azure CLI not authenticated — run: az login --use-device-code"
    fi
else
    fail "Azure CLI not installed — run Phase 0"
fi

# ─── WORDLISTS ────────────────────────────────────────────────────────────────
section "Wordlists"
[[ -f /usr/share/wordlists/rockyou.txt ]] \
    && ok "rockyou.txt ($(wc -l < /usr/share/wordlists/rockyou.txt | tr -d ' ') lines)" \
    || fail "rockyou.txt missing — run Phase 0 to decompress or download"

[[ -f /usr/share/hashcat/rules/best64.rule ]] \
    && ok "best64.rule" \
    || fail "best64.rule missing — install hashcat: sudo apt-get install hashcat"

# ─── CONFIG ───────────────────────────────────────────────────────────────────
section "config.env"
CONFIG="${PROJECT_ROOT}/config.env"
if [[ ! -f "${CONFIG}" ]]; then
    fail "config.env not found — copy from config.env.example and fill in values"
else
    ok "config.env exists"

    # Check for unfilled placeholders
    placeholder_count=$(grep -c 'xxxxxxxx\|COMPLETE\|TODO\|your-' "${CONFIG}" 2>/dev/null || echo 0)
    [[ "${placeholder_count}" -eq 0 ]] \
        && ok "No obvious unfilled placeholders" \
        || warn "${placeholder_count} possible placeholder value(s) in config.env — review before running"

    # Check required variables are set
    for var in TARGET_SUBNETS DOMAIN_NAME DC_IP AZURE_TENANT_ID ATTACKER_IP ATTACKER_INTERFACE; do
        val=$(grep "^${var}=" "${CONFIG}" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
        [[ -n "${val}" ]] \
            && ok "${var} is set" \
            || fail "${var} is not set in config.env"
    done
fi

# ─── PIPX PATH ────────────────────────────────────────────────────────────────
section "pipx PATH"
if command -v pipx &>/dev/null; then
    ok "pipx available: $(command -v pipx)"
    if echo "$PATH" | tr ':' '\n' | grep -q "${HOME}/.local/bin"; then
        ok "~/.local/bin is on PATH"
    else
        warn "~/.local/bin not on PATH — pipx-installed tools may not be found"
        warn "Fix: add 'export PATH=\"\${HOME}/.local/bin:\${PATH}\"' to ~/.bashrc"
    fi
else
    warn "pipx not installed — Python tools will use pip3 --break-system-packages fallback"
fi

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Verification Summary${RESET}"
echo -e "${GREEN}  Passed:   ${PASS}${RESET}"
echo -e "${YELLOW}  Warnings: ${WARN}${RESET}"
echo -e "${RED}  Failed:   ${FAIL}${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"

if [[ "${FAIL}" -gt 0 ]]; then
    echo -e "${RED}  ✘ ${FAIL} failure(s) must be resolved before running the engagement.${RESET}"
    echo -e "  Run Phase 0 to auto-install missing tools:"
    echo -e "    python3 orchestrator.py --phase 0"
    exit 1
elif [[ "${WARN}" -gt 0 ]]; then
    echo -e "${YELLOW}  ⚠ ${WARN} warning(s) — review above before proceeding.${RESET}"
    exit 0
else
    echo -e "${GREEN}  ✔ All checks passed. Environment is ready.${RESET}"
    exit 0
fi
