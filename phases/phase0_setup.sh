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

    # ── Compose availability check ───────────────────────────────────────────
    # Prefer v2 plugin (docker compose); fall back to v1 standalone (docker-compose).
    # detect_docker_compose() in common.sh already set DC[]; re-detect after any install.
    if docker compose version &>/dev/null 2>&1; then
        log OK "docker compose (v2 plugin): $(docker compose version --short 2>/dev/null || echo 'ok')"
    elif command -v docker-compose &>/dev/null; then
        log OK "docker-compose (v1 standalone): $(docker-compose version --short 2>/dev/null || echo 'ok')"
        log WARN "docker-compose v1 is deprecated. Install the v2 plugin when possible: sudo apt-get install docker-compose-plugin"
    else
        log WARN "No compose tool found — attempting to install docker-compose-plugin..."
        sudo apt-get install -y docker-compose-plugin 2>/dev/null \
            || log ERROR "Could not install docker-compose-plugin. Run: sudo apt-get install docker-compose-plugin"
    fi
    # Re-detect after possible install so DC[] is correct for this session
    detect_docker_compose
    log INFO "Docker Compose command: ${DC[*]}"

    # ── Add user to docker group if not already a member ────────────────────
    if ! groups "$USER" 2>/dev/null | grep -q '\bdocker\b'; then
        sudo usermod -aG docker "$USER" 2>/dev/null || true
        log WARN "User '${USER}' added to docker group. Run 'newgrp docker' for passwordless docker in this session."
    fi

    # ── Force IPv4 for Docker image pulls ───────────────────────────────────
    # On hosts without IPv6 internet routing (common on pentest boxes and VMs),
    # Docker resolves registry hostnames to AAAA records first and tries IPv6,
    # failing with "dial tcp [2606:...]:443: connect: network is unreachable"
    # after 6 attempts.  Setting "ipv6": false in daemon.json makes Docker skip
    # IPv6 addresses entirely so pulls always succeed over IPv4.
    local daemon_json="/etc/docker/daemon.json"
    if [[ ! -f "${daemon_json}" ]]; then
        log INFO "Creating ${daemon_json} with IPv4-only pull preference..."
        echo '{"ipv6": false}' | sudo tee "${daemon_json}" > /dev/null
        sudo systemctl restart docker 2>/dev/null \
            || sudo service docker restart 2>/dev/null || true
        log OK "Docker daemon configured: IPv6 disabled (image pulls use IPv4 only)"
    elif ! grep -q '"ipv6"' "${daemon_json}" 2>/dev/null; then
        log WARN "${daemon_json} exists but has no ipv6 setting — add '\"ipv6\": false' manually if image pulls fail with IPv6 errors."
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
TOOLS_OPTIONAL=(impacket-GetUserSPNs impacket-GetNPUsers impacket-ntlmrelayx impacket-secretsdump impacket-psexec certipy-ad msfconsole targetedKerberoast.py)
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
    if checkpoint "Auto-install missing required tools via apt/pip?"; then
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
    fi  # end checkpoint gate
fi

# ─── AUTO-INSTALL OPTIONAL TOOLS ─────────────────────────────────────────────
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
    log WARN "Missing optional tools: ${MISSING_OPTIONAL[*]}"
    if checkpoint "Auto-install missing optional tools (Impacket suite + certipy-ad)?"; then
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
                targetedKerberoast.py)
                    TKRB_DIR="/opt/targetedKerberoast"
                    if [[ ! -d "${TKRB_DIR}" ]]; then
                        sudo git clone https://github.com/ShutdownRepo/targetedKerberoast "${TKRB_DIR}" \
                            && pip_install -r "${TKRB_DIR}/requirements.txt" \
                            && sudo ln -sf "${TKRB_DIR}/targetedKerberoast.py" /usr/local/bin/targetedKerberoast.py \
                            && log OK "targetedKerberoast installed → ${TKRB_DIR}" \
                            || log WARN "targetedKerberoast install failed"
                    else
                        log OK "targetedKerberoast already cloned at ${TKRB_DIR}"
                        sudo ln -sf "${TKRB_DIR}/targetedKerberoast.py" /usr/local/bin/targetedKerberoast.py || true
                    fi
                    ;;
            esac
        done
    fi
fi

# ─── VERIFY SCOUTSUITE INVOCATION ─────────────────────────────────────────────
log INFO "Checking ScoutSuite invocation..."
if ! pip_install scoutsuite 2>/dev/null; then
    log WARN "ScoutSuite install failed — Phase 2 cloud audit will be skipped"
fi
# Validate scout invocation: ScoutSuite installs as `scout` (single word, not "scout suite")
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
    if checkpoint "Prepare rockyou.txt wordlist (~60MB)?"; then
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
        log WARN "Wordlist skipped — password cracking in Phase 3 will require manual setup"
    fi
else
    # `wc -l` prefixes its count with whitespace on BSD; strip to digits so the
    # display is clean and arithmetic comparisons can't choke under `set -e`.
    WCOUNT=$(wc -l < "${WORDLIST_PRIMARY}" 2>/dev/null || echo 0)
    WCOUNT="${WCOUNT//[^0-9]/}"
    WCOUNT="${WCOUNT:-0}"
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
    CCOUNT=$(wc -l < "${CORP_WORDLIST}" 2>/dev/null || echo 0)
    CCOUNT="${CCOUNT//[^0-9]/}"
    CCOUNT="${CCOUNT:-0}"
    log OK "Corporate pattern wordlist generated: ${CORP_WORDLIST} (${CCOUNT} entries)"
fi
export WORDLIST_CORPORATE="${CORP_WORDLIST}"

# ─── BLOODHOUND CE — VIA BLOODHOUND-CLI ──────────────────────────────────────
# bloodhound-cli is SpecterOps' official tool for managing BloodHound CE.
# It handles container orchestration internally and avoids the Neo4j IPv6
# dual-stack routing table bug that plagued the manual docker-compose approach.
log INFO "Checking bloodhound-cli..."

# ── Locate or install bloodhound-cli ────────────────────────────────────────
BH_CLI=""
for _candidate in \
    "$(command -v bloodhound-cli 2>/dev/null)" \
    "${HOME}/.local/bin/bloodhound-cli" \
    "/usr/local/bin/bloodhound-cli"; do
    if [[ -x "${_candidate}" ]]; then
        BH_CLI="${_candidate}"
        break
    fi
done

if [[ -z "${BH_CLI}" ]]; then
    log INFO "bloodhound-cli not found — downloading from GitHub releases..."
    _arch=$(uname -m)
    case "${_arch}" in
        x86_64)  _bh_arch="amd64" ;;
        aarch64|arm64) _bh_arch="arm64" ;;
        *)        _bh_arch="amd64" ;;
    esac
    _bh_dest="${HOME}/.local/bin"
    mkdir -p "${_bh_dest}"
    _bh_url="https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli_linux_${_bh_arch}.tar.gz"
    log INFO "Downloading: ${_bh_url}"
    if curl -fsSL "${_bh_url}" | tar -xz -C "${_bh_dest}" 2>/dev/null \
       && [[ -f "${_bh_dest}/bloodhound-cli" ]]; then
        chmod +x "${_bh_dest}/bloodhound-cli"
        BH_CLI="${_bh_dest}/bloodhound-cli"
        export PATH="${_bh_dest}:${PATH}"
        log OK "bloodhound-cli installed → ${BH_CLI}"
    else
        log WARN "Auto-download failed. Install manually:"
        log WARN "  https://github.com/SpecterOps/bloodhound-cli/releases"
        log WARN "  Then re-run: python3 orchestrator.py --phase 0"
    fi
    unset _arch _bh_arch _bh_dest _bh_url
fi
unset _candidate

# bloodhound-cli must be invoked from its own directory — it resolves
# docker-compose.yml and other assets relative to CWD, not to the binary path.
bh_cli() { (cd "$(dirname "${BH_CLI}")" && "${BH_CLI}" "$@"); }

if [[ -n "${BH_CLI}" ]]; then
    log OK "bloodhound-cli found: ${BH_CLI} ($(bh_cli version 2>/dev/null || echo 'version unknown'))"

    # ── Check if already running ─────────────────────────────────────────────
    if bh_cli status 2>/dev/null | grep -qiE 'running|healthy|started|Up'; then
        log OK "BloodHound CE already running → http://localhost:8080"
    else
        if checkpoint "Install and start BloodHound CE via bloodhound-cli?"; then
            log INFO "Running bloodhound-cli install (idempotent)..."
            bh_cli install --no-prompt 2>&1 | tail -10 || \
            bh_cli install 2>&1 | tail -10 || true

            log INFO "Starting BloodHound CE..."
            bh_cli start 2>&1 | tail -5

            # ── Wait for HTTP endpoint ────────────────────────────────────────
            log INFO "Waiting for BloodHound CE HTTP endpoint (up to 180s)..."
            bh_wait=0
            bh_ready=false
            while [[ $bh_wait -lt 180 ]]; do
                if curl -sf --max-time 3 "http://localhost:8080/api/version" &>/dev/null; then
                    bh_ready=true
                    break
                fi
                sleep 5; bh_wait=$(( bh_wait + 5 ))
                [[ $(( bh_wait % 30 )) -eq 0 ]] && log INFO "  Still waiting... (${bh_wait}s elapsed)"
            done

            if $bh_ready; then
                log OK "BloodHound CE is serving → http://localhost:8080 (${bh_wait}s)"
            else
                log WARN "BloodHound CE did not respond within 180s."
                log WARN "  Check status: ${BH_CLI} status"
                log WARN "  View logs:   ${BH_CLI} logs"
            fi

            log INFO "First-run admin password: ${BH_CLI} password"
            log INFO "  (or: ${BH_CLI} logs | grep -i 'initial password')"
        else
            log WARN "BloodHound CE startup skipped."
            log WARN "  Start manually: bloodhound-cli start"
            log WARN "  Web UI:         http://localhost:8080"
        fi
    fi
else
    log WARN "bloodhound-cli unavailable — BloodHound CE setup skipped."
    log WARN "  Install: https://github.com/SpecterOps/bloodhound-cli/releases"
fi

# ─── AZURE CLI LOGIN CHECK ────────────────────────────────────────────────────
log INFO "Checking Azure CLI login state..."
if az account show &>/dev/null; then
    # `|| echo unknown` gives a deterministic non-empty value so the log line
    # reads cleanly even when the query field is missing (older CLI versions
    # sometimes return empty string for service-principal logins).
    ACCOUNT=$(az account show --query 'user.name' -o tsv 2>/dev/null || echo unknown)
    log OK "Azure CLI already logged in as: ${ACCOUNT:-unknown}"
else
    log WARN "Azure CLI not logged in. Initiating device code login for tenant: ${AZURE_TENANT_ID}"
    if checkpoint "Login to Azure via device code flow?"; then
        az login --tenant "${AZURE_TENANT_ID}" --use-device-code
    else
        log WARN "Azure login skipped — cloud scans in Phase 2 will fail until authenticated."
        log WARN "Run manually: az login --tenant ${AZURE_TENANT_ID} --use-device-code"
    fi
fi

# ─── VALIDATE DC REACHABILITY ────────────────────────────────────────────────
log INFO "Validating DC reachability (all DCs in DC_IP)..."
for _dc in ${DC_IP}; do
    if ping -c 2 -W 2 "${_dc}" &>/dev/null; then
        log OK "DC reachable: ${_dc}"
    else
        log WARN "DC not responding to ping (may be ICMP-blocked): ${_dc} — will verify via Nmap in Phase 1."
    fi
done
unset _dc

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
echo -e "    • BloodHound CE first-run password → bloodhound-cli password"
echo ""
log OK "Phase 0 automated setup complete"
