#!/usr/bin/env bash
# ============================================================================
# phases/phase0_setup.sh — Pre-Engagement Setup
# ============================================================================
# AUTOMATED: tool verification, directory scaffolding, config validation,
#            wordlist check, Azure CLI login check, BloodHound CE startup.
# MANUAL:    RoE sign-off, asset inventory handover, stakeholder comms.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 0 — Pre-Engagement Setup"
check_testing_window

# ─── PIPX BOOTSTRAP ──────────────────────────────────────────────────────────
# pipx must be available BEFORE any pip_install() call. It installs each Python
# pentest tool into its own isolated venv and exposes the binary globally on PATH —
# no venv activation needed, no PEP 668 errors, no system Python conflicts.
log INFO "Bootstrapping pipx..."
if ! command -v pipx &>/dev/null; then
    sudo apt-get install -y pipx 2>/dev/null \
        || pip3 install pipx --break-system-packages 2>/dev/null \
        || pip3 install pipx 2>/dev/null \
        || { log ERROR "Could not install pipx. Falling back to pip3 --break-system-packages for all installs."; }
fi
if command -v pipx &>/dev/null; then
    pipx ensurepath 2>/dev/null || true
    # Ensure ~/.local/bin is on PATH for this session (ensurepath only updates .bashrc)
    export PATH="${HOME}/.local/bin:${PATH}"
    log OK "pipx ready: $(command -v pipx)"
fi

# ─── DOCKER SETUP ────────────────────────────────────────────────────────────
# Handles all three real-world states on Kali:
#   1. Docker fully working (skip everything)
#   2. Docker binary present but daemon not running (start it; check for compose plugin)
#   3. Docker absent / broken (full Docker CE install with GPG key + repo)
#
# Uses Docker CE from upstream (download.docker.com/linux/debian), NOT docker.io.
# docker.io is the outdated Ubuntu/Debian community build — it often lacks the
# compose plugin and lags behind on security fixes on Kali.
ensure_docker() {
    local docker_ok=false

    # ── State 1: Already installed and daemon is reachable ──────────────────
    if command -v docker &>/dev/null; then
        if docker info &>/dev/null 2>&1 || sudo docker info &>/dev/null 2>&1; then
            docker_ok=true
        else
            # ── State 2: Binary present but daemon not running ───────────────
            log WARN "Docker binary found but daemon not running. Attempting to start..."
            sudo systemctl start docker 2>/dev/null \
                || sudo service docker start 2>/dev/null \
                || true
            sleep 3
            if docker info &>/dev/null 2>&1 || sudo docker info &>/dev/null 2>&1; then
                docker_ok=true
                log OK "Docker daemon started"
            else
                log WARN "Daemon did not start — will reinstall Docker CE"
            fi
        fi
    fi

    # ── State 3: Full Docker CE installation on Kali ────────────────────────
    if ! $docker_ok; then
        log INFO "Installing Docker CE (upstream) on Kali Linux..."

        # Remove conflicting/outdated packages (docker.io is replaced by docker-ce)
        sudo apt-get remove -y docker docker.io containerd runc docker-compose 2>/dev/null || true

        # Add Docker's official GPG key (only if not already present)
        sudo install -m 0755 -d /etc/apt/keyrings
        if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
            curl -fsSL https://download.docker.com/linux/debian/gpg \
                | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            log OK "Docker GPG key added → /etc/apt/keyrings/docker.gpg"
        fi

        # Add Docker CE repository — Kali is Debian-based, use bookworm codename
        if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
            local arch; arch=$(dpkg --print-architecture)
            echo \
              "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian bookworm stable" \
                | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            log OK "Docker CE apt repo added (/etc/apt/sources.list.d/docker.list)"
        fi

        sudo apt-get update -qq
        sudo apt-get install -y \
            docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin

        sudo systemctl enable docker 2>/dev/null || true
        sudo systemctl start docker 2>/dev/null \
            || sudo service docker start 2>/dev/null \
            || log WARN "Docker daemon did not start automatically. Run: sudo service docker start"

        sudo usermod -aG docker "$USER" 2>/dev/null || true
        log OK "Docker CE installed. Run 'newgrp docker' or re-login to use docker without sudo."
        docker_ok=true
    fi

    # ── Compose plugin check (independent of whether we just installed Docker) ─
    # docker compose (v2 plugin) is required; docker-compose (v1 binary) is not enough.
    if ! docker compose version &>/dev/null 2>&1; then
        log WARN "docker compose plugin (v2) missing — installing now"
        sudo apt-get install -y docker-compose-plugin 2>/dev/null \
            || log ERROR "Could not install docker-compose-plugin. Run: sudo apt-get install docker-compose-plugin"
    else
        log OK "docker compose plugin: $(docker compose version --short 2>/dev/null || echo 'ok')"
    fi

    # ── Add user to docker group if not already a member ────────────────────
    if ! groups "$USER" 2>/dev/null | grep -q '\bdocker\b'; then
        sudo usermod -aG docker "$USER" 2>/dev/null || true
        log WARN "User '${USER}' added to docker group. Run 'newgrp docker' for passwordless docker in this session."
    fi
}

ensure_docker

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

# Auto-detect nxc (Kali 2024+) vs crackmapexec (older Kali) before the check loop
detect_cme
log INFO "CME binary resolved to: ${CME_BIN}"

TOOLS_REQUIRED=(nmap "${CME_BIN}" responder hashcat bloodhound-python roadrecon az docker ldapsearch)
TOOLS_OPTIONAL=(impacket-GetUserSPNs impacket-GetNPUsers impacket-ntlmrelayx impacket-secretsdump impacket-psexec certipy-ad msfconsole)
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

# ─── AUTO-INSTALL MISSING REQUIRED TOOLS ─────────────────────────────────────
if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    log WARN "Missing required tools: ${MISSING_REQUIRED[*]}"
    checkpoint "Auto-install missing required tools via apt/pip?"
    sudo apt-get update -qq
    for tool in "${MISSING_REQUIRED[@]}"; do
        case "$tool" in
            nmap)
                sudo apt-get install -y nmap ;;
            crackmapexec|nxc)
                # Prefer nxc (NetExec) — the maintained successor to CrackMapExec
                if sudo apt-get install -y netexec 2>/dev/null; then
                    log OK "netexec (nxc) installed via apt"
                elif sudo apt-get install -y crackmapexec 2>/dev/null; then
                    log OK "crackmapexec installed via apt"
                else
                    pip_install netexec || pip_install crackmapexec
                fi
                # Re-detect after install
                detect_cme
                ;;
            responder)
                sudo apt-get install -y responder ;;
            hashcat)
                sudo apt-get install -y hashcat ;;
            bloodhound-python)
                pip_install bloodhound || { log ERROR "Failed to install bloodhound-python"; exit 1; } ;;
            roadrecon)
                pip_install roadrecon || { log ERROR "Failed to install roadrecon"; exit 1; } ;;
            az)
                # Microsoft's official install script — works reliably on Kali.
                # The azure-cli apt package in Kali repos lags behind and frequently
                # breaks because Kali is Debian-based but not a supported distro for
                # Microsoft's own apt repo. The install script pins the correct
                # Microsoft repo, imports the GPG key, and handles it automatically
                # regardless of the underlying Debian base version.
                log INFO "Installing Azure CLI via Microsoft install script..."
                curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash \
                    || { log ERROR "Azure CLI install failed — check network and retry"; exit 1; }
                ;;
            docker)
                # Docker is handled by ensure_docker() at the top of this script.
                # This case should never be reached since ensure_docker runs unconditionally,
                # but it is kept here as a safety net if TOOLS_REQUIRED checking re-adds it.
                ensure_docker
                ;;
            ldapsearch)
                sudo apt-get install -y ldap-utils ;;
            *)
                log WARN "Don't know how to auto-install: ${tool}" ;;
        esac
    done
fi

# ─── AUTO-INSTALL OPTIONAL TOOLS ─────────────────────────────────────────────
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
    log WARN "Missing optional tools: ${MISSING_OPTIONAL[*]}"
    checkpoint "Auto-install missing optional tools (Impacket suite + certipy-ad)?"
    for tool in "${MISSING_OPTIONAL[@]}"; do
        case "$tool" in
            impacket-*)
                pip_install impacket && log OK "Impacket suite installed" || \
                    log WARN "Impacket install failed — try: pip3 install impacket --break-system-packages"
                break  # installing impacket covers all impacket-* tools
                ;;
            certipy-ad)
                pip_install certipy-ad && log OK "certipy-ad installed" || \
                    log WARN "certipy-ad install failed — AD CS checks in Phase 2 will be skipped"
                ;;
            msfconsole)
                log WARN "Metasploit (msfconsole) not auto-installed — install via: sudo apt-get install metasploit-framework"
                ;;
        esac
    done
fi

# ─── VERIFY SCOUTSUITE INVOCATION ─────────────────────────────────────────────
log INFO "Checking ScoutSuite invocation..."
if ! pip_install scoutsuite 2>/dev/null; then
    log WARN "ScoutSuite install failed — Phase 2 cloud audit will be skipped"
fi
# Validate the correct "scout suite" invocation (not bare "scout")
set_scout_cmd
if "${SCOUT_CMD_ARRAY[@]}" --help &>/dev/null 2>&1; then
    log OK "ScoutSuite invocation confirmed: ${SCOUT_CMD_ARRAY[*]}"
else
    log WARN "ScoutSuite invocation '${SCOUT_CMD_ARRAY[*]}' not responding — Phase 2 cloud audit may fail"
fi

# ─── WORDLIST CHECK ───────────────────────────────────────────────────────────
log INFO "Checking wordlists..."
if [[ ! -f "${WORDLIST_PRIMARY}" ]]; then
    log WARN "Primary wordlist not found: ${WORDLIST_PRIMARY}"
    checkpoint "Prepare rockyou.txt wordlist (~60MB)?"
    mkdir -p "$(dirname "${WORDLIST_PRIMARY}")"
    if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        log OK "rockyou.txt decompressed"
    elif sudo apt-get install -y wordlists &>/dev/null 2>&1 && [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        log OK "rockyou.txt installed via apt wordlists package"
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

# ─── BLOODHOUND CE — DOCKER COMPOSE STACK ────────────────────────────────────
BHCE_DIR="${SCRIPT_DIR}/../tools/bloodhound-ce"
BHCE_COMPOSE="${BHCE_DIR}/docker-compose.yml"
BHCE_CONFIG="${BHCE_DIR}/bloodhound.config.json"

log INFO "Checking BloodHound CE Docker stack..."
# ensure_docker() already ran above — Docker is available at this point.
if [[ ! -f "${BHCE_CONFIG}" ]]; then
    log ERROR "BloodHound CE config not found: ${BHCE_CONFIG}"
    log ERROR "Ensure tools/bloodhound-ce/bloodhound.config.json is present in the repo."
    exit 1
fi

# ── JWT signing key: replace placeholder before first start ─────────────────
# The config ships with a placeholder key. BloodHound CE will start with it but
# tokens signed by a known/public key are a security risk — generate a real one.
PLACEHOLDER="vapt-bhce-replace-with-random-32char-string"
if grep -q "${PLACEHOLDER}" "${BHCE_CONFIG}" 2>/dev/null; then
    log WARN "BloodHound CE config contains placeholder JWT signing key — generating secure key..."
    NEW_KEY=$(openssl rand -hex 32)
    # Replace both occurrences (jwt_signing_key top-level + crypto.jwt.signing_key)
    sed -i "s/${PLACEHOLDER}/${NEW_KEY}/g" "${BHCE_CONFIG}"
    log OK "JWT signing key set (${#NEW_KEY}-char hex). Keep ${BHCE_CONFIG} private."
fi

# Check if stack is already running (covers both fresh start and resume after reboot)
if docker compose -f "${BHCE_COMPOSE}" ps 2>/dev/null | grep -qE 'running|Up|healthy'; then
    log OK "BloodHound CE stack already running → http://localhost:8080"
else
    checkpoint "Start BloodHound CE Docker stack (Postgres + Neo4j + BloodHound UI on :8080)?"
    log INFO "Pulling and starting BloodHound CE stack (first run downloads ~1.5 GB, may take 3–5 min)..."
    docker compose -f "${BHCE_COMPOSE}" up -d 2>&1 | tail -5

    # ── Wait for BloodHound HTTP endpoint — not just container status ─────────
    # Container status (healthy/running) reflects Postgres/Neo4j readiness, but
    # BloodHound itself still needs a few seconds after its deps are healthy.
    # We poll the /api/version endpoint (returns 200 when the app is serving).
    log INFO "Waiting for BloodHound CE HTTP endpoint (up to 180s)..."
    bh_wait=0
    bh_ready=false
    while [[ $bh_wait -lt 180 ]]; do
        if curl -sf --max-time 3 "http://localhost:8080/api/version" &>/dev/null; then
            bh_ready=true
            break
        fi
        sleep 5; (( bh_wait += 5 ))
        [[ $(( bh_wait % 30 )) -eq 0 ]] && log INFO "  Still waiting... (${bh_wait}s elapsed)"
    done

    if $bh_ready; then
        log OK "BloodHound CE is serving → http://localhost:8080 (${bh_wait}s)"
    else
        log WARN "BloodHound CE did not respond within 180s. Check container logs:"
        log WARN "  docker compose -f ${BHCE_COMPOSE} logs bloodhound | tail -30"
    fi
    log INFO "Get first-run admin password:"
    log INFO "  docker compose -f ${BHCE_COMPOSE} logs bloodhound 2>&1 | grep -i 'initial password\|password'"
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
echo -e "    • BloodHound CE first-run password → docker compose -f tools/bloodhound-ce/docker-compose.yml logs bloodhound | grep -i password"
echo ""
log OK "Phase 0 automated setup complete"
