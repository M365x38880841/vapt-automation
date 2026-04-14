#!/usr/bin/env bash
# ============================================================================
# phases/phase0_setup.sh — Pre-Engagement Setup
# ============================================================================
# AUTOMATED: tool verification, directory scaffolding, config validation,
#            wordlist check, Azure CLI login check.
# MANUAL:    RoE sign-off, asset inventory handover, stakeholder comms.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 0 — Pre-Engagement Setup"
check_testing_window

# ─── CREATE EVIDENCE DIRECTORY STRUCTURE ─────────────────────────────────────
log INFO "Creating engagement directory structure under: ${OUTPUT_BASE_DIR}"
for phase in phase0 phase1 phase2 phase3 phase4 phase5; do
    for domain in network ad web cloud misc; do
        mkdir -p "${OUTPUT_BASE_DIR}/${phase}/${domain}"
    done
done
mkdir -p "${OUTPUT_BASE_DIR}/tools" "${OUTPUT_BASE_DIR}/report/evidence"
log OK "Directory structure created"

# ─── TOOL VERIFICATION ───────────────────────────────────────────────────────
log INFO "Verifying required tools..."
TOOLS_REQUIRED=(nmap crackmapexec responder hashcat bloodhound-python roadrecon scout az docker)
TOOLS_OPTIONAL=(impacket-GetUserSPNs impacket-GetNPUsers impacket-ntlmrelayx impacket-secretsdump impacket-psexec msfconsole)
MISSING_REQUIRED=(); MISSING_OPTIONAL=()

for tool in "${TOOLS_REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log OK "  ✅ Found: ${tool} ($(command -v "$tool"))"
    else
        MISSING_REQUIRED+=("$tool")
        log WARN "  ❌ Missing (required): ${tool}"
    fi
done

for tool in "${TOOLS_OPTIONAL[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log OK "  ✅ Found: ${tool}"
    else
        MISSING_OPTIONAL+=("$tool")
        log WARN "  ⚠️  Missing (optional): ${tool}"
    fi
done

# Auto-install missing required tools
if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    log WARN "Missing required tools: ${MISSING_REQUIRED[*]}"
    checkpoint "Auto-install missing required tools via apt/pip?"
    sudo apt-get update -qq
    for tool in "${MISSING_REQUIRED[@]}"; do
        case "$tool" in
            nmap)              sudo apt-get install -y nmap ;;
            crackmapexec)      pip3 install crackmapexec --quiet ;;
            responder)         sudo apt-get install -y responder ;;
            hashcat)           sudo apt-get install -y hashcat ;;
            bloodhound-python) pip3 install bloodhound --quiet ;;
            roadrecon)         pip3 install roadrecon --quiet ;;
            scout)             pip3 install scoutsuite --quiet ;;
            az)                curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash ;;
            docker)            sudo apt-get install -y docker.io && sudo systemctl start docker ;;
            *)                 log WARN "Don't know how to auto-install: ${tool}" ;;
        esac
    done
fi

if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
    log WARN "Optional Impacket tools missing. Installing..."
    pip3 install impacket --quiet && log OK "Impacket suite installed"
fi

# ─── WORDLIST CHECK ───────────────────────────────────────────────────────────
log INFO "Checking wordlists..."
if [[ ! -f "${WORDLIST_PRIMARY}" ]]; then
    log WARN "Primary wordlist not found: ${WORDLIST_PRIMARY}"
    checkpoint "Download rockyou.txt wordlist (~60MB)?"
    mkdir -p "$(dirname "${WORDLIST_PRIMARY}")"
    if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        log OK "rockyou.txt decompressed"
    else
        sudo wget -q -O "${WORDLIST_PRIMARY}.gz" \
            https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz
        sudo gunzip "${WORDLIST_PRIMARY}.gz"
        log OK "rockyou.txt downloaded"
    fi
else
    WCOUNT=$(wc -l < "${WORDLIST_PRIMARY}")
    log OK "Primary wordlist ready: ${WORDLIST_PRIMARY} (${WCOUNT} lines)"
fi

# Corporate pattern wordlist generation (passwords like Company2024!)
CORP_WORDLIST="${OUTPUT_BASE_DIR}/tools/corporate_patterns.txt"
if [[ ! -f "${CORP_WORDLIST}" ]]; then
    log INFO "Generating corporate password pattern list..."
    ORG_WORDS=("Hashem" "HaShem" "hashem" "HL" "Admin" "Password" "Welcome" "Summer" "Winter" "Spring" "Autumn")
    YEARS=("2022" "2023" "2024" "2025" "2026")
    SUFFIXES=("!" "!!" "@" "#" "1" "123" "1234" "01")
    {
        for word in "${ORG_WORDS[@]}"; do
            for year in "${YEARS[@]}"; do
                for suffix in "${SUFFIXES[@]}"; do
                    echo "${word}${year}${suffix}"
                    echo "${word}${suffix}${year}"
                done
            done
        done
    } > "${CORP_WORDLIST}"
    CCOUNT=$(wc -l < "${CORP_WORDLIST}")
    log OK "Corporate pattern wordlist generated: ${CORP_WORDLIST} (${CCOUNT} entries)"
fi
export WORDLIST_CORPORATE="${CORP_WORDLIST}"

# ─── BLOODHOUND CE CHECK ──────────────────────────────────────────────────────
log INFO "Checking BloodHound CE Docker image..."
if docker image inspect specterops/bloodhound:latest &>/dev/null; then
    log OK "BloodHound CE image available"
else
    log INFO "Pulling BloodHound CE image..."
    docker pull specterops/bloodhound:latest && log OK "BloodHound CE pulled"
fi

# ─── AZURE CLI LOGIN CHECK ────────────────────────────────────────────────────
log INFO "Checking Azure CLI login state..."
if az account show &>/dev/null; then
    ACCOUNT=$(az account show --query 'user.name' -o tsv 2>/dev/null)
    log OK "Azure CLI already logged in as: ${ACCOUNT}"
else
    log WARN "Azure CLI not logged in. Initiating device code login for tenant: ${AZURE_TENANT_ID}"
    checkpoint "Login to Azure via device code flow?"
    az login --tenant "${AZURE_TENANT_ID}" --use-device-code
fi

# ─── VALIDATE SUBNET REACHABILITY ────────────────────────────────────────────
log INFO "Validating DC reachability: ${DC_IP}"
if ping -c 2 -W 2 "${DC_IP}" &>/dev/null; then
    log OK "DC is reachable: ${DC_IP}"
else
    log WARN "DC not responding to ping (may be ICMP-blocked). Will verify via Nmap in Phase 1."
fi

# ─── WRITE SCOPE FILE FOR SUBSEQUENT PHASES ──────────────────────────────────
SCOPE_FILE="${OUTPUT_BASE_DIR}/phase0/scope.json"
cat > "${SCOPE_FILE}" <<EOF
{
  "generated":       "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "engagement":      "${ENGAGEMENT_NAME:-HaShem-VAPT}",
  "domain":          "${DOMAIN_NAME}",
  "dc_ip":           "${DC_IP}",
  "subnets":         "${TARGET_SUBNETS}",
  "azure_tenant":    "${AZURE_TENANT_ID}",
  "azure_subs":      "${AZURE_SUBSCRIPTION_IDS}",
  "attacker_ip":     "${ATTACKER_IP}",
  "attacker_iface":  "${ATTACKER_INTERFACE}",
  "output_base":     "${OUTPUT_BASE_DIR}"
}
EOF
log OK "Scope file written: ${SCOPE_FILE}"

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Phase 0 Complete — Automated Checks Passed${RESET}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
echo -e "${YELLOW}  Manual items still required:${RESET}"
echo -e "    • Signed RoE from all 6 parties"
echo -e "    • Asset inventory from Networking + Cloud Platform teams"
echo -e "    • Confirm testing window with Management Sponsors"
echo -e "    • Emergency stop contact confirmed"
echo ""
log OK "Phase 0 automated setup complete"
