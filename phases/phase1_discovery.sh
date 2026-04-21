#!/usr/bin/env bash
# ============================================================================
# phases/phase1_discovery.sh — Reconnaissance & Discovery
# ============================================================================
# AUTOMATED (background): Nmap host sweep, full port scan, CrackMapExec SMB
#                         sweep, LDAP enumeration, BloodHound collection,
#                         ROADrecon Entra ID gather, Azure resource inventory.
# MANUAL (after script):  BloodHound GUI analysis, ROADrecon GUI review.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 1 — Reconnaissance & Discovery"
check_testing_window
detect_system_resources

# ─── RUNTIME REQUIREMENTS ────────────────────────────────────────────────────
require_var "DOMAIN_NAME"; require_var "DC_IP"; require_var "TARGET_SUBNETS"
require_var "ATTACKER_INTERFACE"; require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
detect_cme

OUT_NET="$(phase_dir phase1 network)"
OUT_AD="$(phase_dir phase1 ad)"
OUT_CLOUD="$(phase_dir phase1 cloud)"

# ─── BUILD NMAP EXCLUSION ARG ─────────────────────────────────────────────────
# Converts SCAN_EXCLUDE_RANGES (space-separated) to nmap's comma-separated --exclude.
# Empty string → no exclusion flag (nmap errors on --exclude with empty value).
NMAP_EXCL_ARG=""
if [[ -n "${SCAN_EXCLUDE_RANGES:-}" ]]; then
    NMAP_EXCL_ARG="--exclude $(echo "${SCAN_EXCLUDE_RANGES}" | tr ' ' ',')"
    log INFO "Exclusion list: ${SCAN_EXCLUDE_RANGES}"
fi

# ─── HELPER: extract IPs from gnmap (works for both -sn and -sS --open output) ──
_gnmap_live_ips() {
    local gnmap="$1"
    # "Ports:" lines appear for hosts with at least one open port in -sS --open output.
    # "Status: Up" lines appear in -sn output.  Handle both so skip-branch works
    # against previously collected gnmap files regardless of which mode produced them.
    grep -E 'Ports:.*\/open\/|Status: Up' "${gnmap}" 2>/dev/null \
        | awk '{print $2}' | sort -u
}

# ─── STEP 1.1 — HOST SWEEP (TCP SYN — no ICMP, no ARP false positives) ───────
# WHY TCP instead of -sn (ping sweep):
#   -sn uses ICMP echo + ICMP timestamp + TCP SYN/ACK to ports 80 and 443.
#   Every router, switch, printer, UPS, and IPMI card on the network responds
#   to ICMP → massive false positives.  TCP SYN to SMB/RDP/WinRM ports only
#   respond on real Windows workstations and servers, eliminating infrastructure
#   noise at the sweep stage rather than having to filter it later.
log INFO "Starting TCP host sweep across all subnets (parallel, no ICMP)..."
log INFO "Discovery ports: ${NMAP_DISCOVERY_PORTS:-22,80,135,139,443,445,3389,5985,8080,8443}"
LIVE_HOSTS_MERGED="${OUT_NET}/live_hosts_all.txt"
> "${LIVE_HOSTS_MERGED}"

if _step_is_skipped "host_sweep"; then
    for subnet in ${TARGET_SUBNETS}; do
        safe_name="${subnet//\//_}"
        gnmap="${OUT_NET}/hostsweep_${safe_name}.gnmap"
        [[ -f "${gnmap}" ]] && _gnmap_live_ips "${gnmap}" >> "${LIVE_HOSTS_MERGED}" || true
    done
    sort -u "${LIVE_HOSTS_MERGED}" -o "${LIVE_HOSTS_MERGED}" 2>/dev/null || true
    LIVE_COUNT=$(wc -l < "${LIVE_HOSTS_MERGED}" 2>/dev/null || echo 0)
    log INFO "host_sweep skipped — using cached live hosts (${LIVE_COUNT} hosts)"
else

for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    sweep_out="${OUT_NET}/hostsweep_${safe_name}"
    if skip_if_exists "${sweep_out}.gnmap" "Host sweep ${subnet}" "host_sweep"; then
        _gnmap_live_ips "${sweep_out}.gnmap" >> "${LIVE_HOSTS_MERGED}" || true
        continue
    fi
    log INFO "TCP sweep: ${subnet}"
    bg_run "hostsweep_${safe_name}" \
        "${OUT_NET}/hostsweep_${safe_name}.log" \
        "${NMAP_BIN:-nmap}" \
            -sS --open \
            -p "${NMAP_DISCOVERY_PORTS:-22,80,135,139,443,445,3389,5985,8080,8443}" \
            -T"${NMAP_TIMING:-3}" \
            --max-rate "${NMAP_MAX_RATE:-500}" \
            --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
            --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
            --max-retries 1 \
            --host-timeout 10s \
            ${NMAP_EXCL_ARG} \
            -oA "${sweep_out}" \
            "${subnet}"
done

wait_for_bg_jobs "TCP host sweeps"

for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    gnmap="${OUT_NET}/hostsweep_${safe_name}.gnmap"
    [[ -f "${gnmap}" ]] && _gnmap_live_ips "${gnmap}" >> "${LIVE_HOSTS_MERGED}" || true
done
sort -u "${LIVE_HOSTS_MERGED}" -o "${LIVE_HOSTS_MERGED}" 2>/dev/null || true
LIVE_COUNT=$(wc -l < "${LIVE_HOSTS_MERGED}" 2>/dev/null || echo 0)
log OK "TCP host sweep complete — validated live hosts: ${LIVE_COUNT} → ${LIVE_HOSTS_MERGED}"

fi  # end host_sweep skip gate

if [[ "${LIVE_COUNT:-0}" -eq 0 ]]; then
    if ! _step_is_skipped "nmap_fullscan"; then
        log ERROR "No live hosts found. Verify TARGET_SUBNETS and that NMAP_DISCOVERY_PORTS matches your environment."
        exit 1
    else
        log WARN "No cached live hosts — downstream steps requiring the host list will skip automatically."
    fi
fi

# ─── STEP 1.2 — FULL PORT SCAN (parallel across all vCPUs) ───────────────────
# Splits the live hosts list into SYS_VCPUS chunks and runs one nmap per chunk
# in parallel. On a 4-vCPU box this gives a ~4× wall-clock speedup over a
# single sequential scan. Results are merged into fullscan.gnmap / fullscan.nmap
# by a watcher job that fires automatically when all chunks finish.
FULLSCAN_OUT="${OUT_NET}/fullscan"
CHUNK_DIR="${OUT_NET}/scan_chunks"

# Attempt merge from existing chunks first (idempotent resume after partial run)
if [[ -d "${CHUNK_DIR}" ]] && ls "${CHUNK_DIR}"/fullscan_chunk_*.gnmap &>/dev/null; then
    TOTAL_CHUNKS=$(ls -1 "${CHUNK_DIR}"/chunk_* 2>/dev/null | wc -l)
    DONE_CHUNKS=$(ls -1 "${CHUNK_DIR}"/fullscan_chunk_*.xml 2>/dev/null | wc -l)
    if [[ "${DONE_CHUNKS}" -ge "${TOTAL_CHUNKS}" && "${TOTAL_CHUNKS}" -gt 0 ]]; then
        cat "${CHUNK_DIR}"/fullscan_chunk_*.gnmap | sort -u > "${FULLSCAN_OUT}.gnmap" 2>/dev/null || true
        cat "${CHUNK_DIR}"/fullscan_chunk_*.nmap          > "${FULLSCAN_OUT}.nmap"  2>/dev/null || true
        log OK "Merged ${DONE_CHUNKS}/${TOTAL_CHUNKS} existing scan chunks into ${FULLSCAN_OUT}.gnmap"
    fi
fi

if ! skip_if_exists "${FULLSCAN_OUT}.gnmap" "Full port scan" "nmap_fullscan"; then
    if checkpoint "Start full TCP port scan (-p-) against ${LIVE_COUNT} validated hosts? (${SYS_VCPUS} parallel jobs on ${SYS_VCPUS}-vCPU system)"; then

        mkdir -p "${CHUNK_DIR}"
        SCAN_RATE=$(( ${NMAP_MAX_RATE:-500} * 2 ))  # aggressive on confirmed live hosts

        if [[ "${LIVE_COUNT}" -gt 50 && "${SYS_VCPUS:-1}" -gt 1 ]]; then
            # ── Parallel path: one nmap per vCPU ────────────────────────────
            N_JOBS="${SYS_VCPUS}"
            LINES_PER_CHUNK=$(( LIVE_COUNT / N_JOBS + 1 ))
            split -l "${LINES_PER_CHUNK}" "${LIVE_HOSTS_MERGED}" "${CHUNK_DIR}/chunk_"
            CHUNK_LIST=( "${CHUNK_DIR}"/chunk_* )
            log INFO "Splitting ${LIVE_COUNT} hosts into ${#CHUNK_LIST[@]} chunks (${LINES_PER_CHUNK} hosts/chunk)..."

            for chunk in "${CHUNK_LIST[@]}"; do
                suffix=$(basename "${chunk}")
                bg_run "nmap_fullscan_${suffix}" \
                    "${CHUNK_DIR}/fullscan_${suffix}.log" \
                    "${NMAP_BIN:-nmap}" \
                        -sS -sV -sC -p- --open \
                        -T"${NMAP_TIMING:-3}" \
                        --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
                        --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
                        --max-rate "${SCAN_RATE}" \
                        --max-retries 2 \
                        --host-timeout 30s \
                        ${NMAP_EXCL_ARG} \
                        -iL "${chunk}" \
                        -oA "${CHUNK_DIR}/fullscan_${suffix}"
            done

            log INFO "${#CHUNK_LIST[@]} parallel nmap jobs started."

            # ── Launch a merge-watcher that polls until all chunks complete ──
            MERGE_SCRIPT=$(mktemp /tmp/nmap_merge_XXXXXX.sh)
            chmod +x "${MERGE_SCRIPT}"
            cat > "${MERGE_SCRIPT}" <<MERGE_EOF
#!/usr/bin/env bash
CHUNK_DIR="${CHUNK_DIR}"
FULLSCAN_OUT="${FULLSCAN_OUT}"
N_CHUNKS=${#CHUNK_LIST[@]}
echo "\$(date '+%H:%M:%S') Merge watcher started — waiting for \${N_CHUNKS} chunk(s)"
while true; do
    done_count=\$(ls -1 "\${CHUNK_DIR}"/fullscan_chunk_*.xml 2>/dev/null | wc -l)
    echo "\$(date '+%H:%M:%S') \${done_count}/\${N_CHUNKS} chunks complete"
    [[ \${done_count} -ge \${N_CHUNKS} ]] && break
    sleep 30
done
echo "All chunks done — merging..."
cat "\${CHUNK_DIR}"/fullscan_chunk_*.gnmap 2>/dev/null | sort -u > "\${FULLSCAN_OUT}.gnmap"
cat "\${CHUNK_DIR}"/fullscan_chunk_*.nmap  2>/dev/null > "\${FULLSCAN_OUT}.nmap"
echo "MERGE COMPLETE: \$(wc -l < "\${FULLSCAN_OUT}.gnmap") lines → \${FULLSCAN_OUT}.gnmap"
rm -f "\$0"
MERGE_EOF
            bg_run "nmap_fullscan_merge" "${OUT_NET}/nmap_merge.log" bash "${MERGE_SCRIPT}"
            log INFO "Merge watcher active — results auto-consolidate to ${FULLSCAN_OUT}.gnmap when all chunks finish."
        else
            # ── Single job for small host lists ────────────────────────────
            log INFO "Starting single full-port scan (${LIVE_COUNT} hosts)..."
            bg_run "nmap_fullscan" \
                "${OUT_NET}/fullscan.log" \
                "${NMAP_BIN:-nmap}" \
                    -sS -sV -sC -p- --open \
                    -T"${NMAP_TIMING:-3}" \
                    --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
                    --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
                    --max-rate "${SCAN_RATE}" \
                    --max-retries 2 \
                    --host-timeout 30s \
                    ${NMAP_EXCL_ARG} \
                    -iL "${LIVE_HOSTS_MERGED}" \
                    -oA "${FULLSCAN_OUT}"
        fi
    else
        log INFO "Full port scan skipped — re-run: python3 orchestrator.py --phase 1 --only nmap_fullscan"
    fi
fi

# ─── STEP 1.3 — SMB SWEEP + SIGNING CHECK (background) ──────────────────────
SMB_OUT="${OUT_AD}/smb_sweep.txt"
if ! skip_if_exists "${SMB_OUT}" "CrackMapExec SMB sweep" "smb_sweep"; then
    log INFO "Starting CrackMapExec SMB sweep (signing + host enumeration)..."
    # Use single-quoted bash -c body so DOMAIN_PASS (and other vars) are resolved
    # from the inherited environment at execution time, not expanded here.  Inline
    # double-quoted expansion would break if the password contains ' or \.
    bg_run "cmexec_smb_sweep" \
        "${OUT_AD}/smb_sweep.log" \
        bash -c 'for subnet in $TARGET_SUBNETS; do
            $CME_BIN smb "$subnet" \
                -u "$DOMAIN_USER" -p "$DOMAIN_PASS" -d "$DOMAIN_NAME" \
                2>&1
        done > "$OUTPUT_BASE_DIR/phase1/ad/smb_sweep.txt"'
    log INFO "CME SMB sweep running in background."
fi

# ─── STEP 1.4 — LDAP DC BANNER GRAB (active — quick) ─────────────────────────
LDAP_OUT="${OUT_AD}/ldap_rootdse.txt"
if ! skip_if_exists "${LDAP_OUT}" "LDAP rootdse" "ldap_banner"; then
    log INFO "Grabbing LDAP rootdse from DC: ${DC_IP}"
    log_cmd "${NMAP_BIN} -p 389 --script ldap-rootdse ${DC_IP}"
    "${NMAP_BIN:-nmap}" -p 389 --script ldap-rootdse "${DC_IP}" \
        -oN "${LDAP_OUT}" 2>&1 | tee -a "${OUT_AD}/ldap.log"
    log OK "LDAP rootdse collected → ${LDAP_OUT}"
fi

# ─── STEP 1.5 — LDAP USER ENUMERATION (active — quick) ───────────────────────
LDAP_USERS_OUT="${OUT_AD}/ldap_users.txt"
if ! skip_if_exists "${LDAP_USERS_OUT}" "LDAP user enumeration" "ldap_users"; then
    log INFO "Enumerating domain users via LDAP..."
    log_cmd "ldapsearch -H ldap://${DC_IP} -D ${DOMAIN_USER}@${DOMAIN_NAME} -w *** -b DC=..."
    ldapsearch -H "ldap://${DC_IP}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(objectClass=user)' sAMAccountName mail memberOf userAccountControl \
        2>&1 > "${LDAP_USERS_OUT}" || log WARN "LDAP query failed — check credentials and DC reachability"

    # Extract clean username list for Phase 3 (AS-REP roasting).
    # || true: grep exits 1 when ldapsearch returned nothing (auth failure, empty OU).
    grep 'sAMAccountName:' "${LDAP_USERS_OUT}" | awk '{print $2}' \
        | grep -v -E '^\$' \
        > "${OUT_AD}/userlist.txt" || true
    UCOUNT=$(wc -l < "${OUT_AD}/userlist.txt" 2>/dev/null || echo 0)
    log OK "LDAP users collected: ${UCOUNT} accounts → ${OUT_AD}/userlist.txt"
fi

# ─── STEP 1.6 — SMB NULL SESSION CHECK (active — instant) ───────────────────
if ! _step_is_skipped "null_session"; then
    log INFO "Checking for SMB null session (should be blocked)..."
    log_cmd "${CME_BIN} smb ${DC_IP} --null-session"
    "${CME_BIN}" smb "${DC_IP}" --null-session \
        2>&1 > "${OUT_AD}/nullsession_check.txt" || true
    if grep -q 'STATUS_ACCESS_DENIED\|STATUS_LOGON_FAILURE' "${OUT_AD}/nullsession_check.txt" 2>/dev/null; then
        log OK "Null session blocked (expected)"
    else
        log WARN "Null session may be accessible — review: ${OUT_AD}/nullsession_check.txt"
    fi
fi

# ─── STEP 1.7 — BLOODHOUND DATA COLLECTION (background) ──────────────────────
BH_OUT_DIR="${OUT_AD}/bloodhound"
mkdir -p "${BH_OUT_DIR}"
BH_ZIP=$(ls "${BH_OUT_DIR}"/*.zip 2>/dev/null | head -1)
if _step_is_skipped "bloodhound"; then
    : # skip
elif [[ -n "${BH_ZIP}" ]]; then
    log INFO "BloodHound ZIP already exists: ${BH_ZIP} — skipping collection"
else
    log INFO "Starting BloodHound data collection (-c All)..."
    bg_run "bloodhound_collect" \
        "${OUT_AD}/bloodhound_collect.log" \
        "${BLOODHOUND_BIN:-bloodhound-python}" \
            -u "${DOMAIN_USER}" \
            -p "${DOMAIN_PASS}" \
            -d "${DOMAIN_NAME}" \
            -ns "${DC_IP}" \
            -c All \
            --zip \
            -w "${BH_WORKERS:-20}" \
            -o "${BH_OUT_DIR}"
    log INFO "BloodHound collection running in background."
fi

# ─── STEP 1.8 — ROADRECON ENTRA ID GATHER ────────────────────────────────────
ROAD_DB="${OUT_CLOUD}/roadrecon.db"
if ! skip_if_exists "${ROAD_DB}" "ROADrecon gather" "roadrecon"; then
    log INFO "Starting ROADrecon Entra ID gather..."
    if [[ "${ROADRECON_AUTH_METHOD:-password}" == "devicecode" ]]; then
        # Device code flow: modern tenants with MFA/CA — runs in foreground (interactive)
        log WARN "ROADrecon device code auth requires interactive input — running in foreground."
        log WARN "Complete the browser authentication when prompted, then the script will continue."
        "${ROADRECON_BIN:-roadrecon}" gather \
            --device-code \
            --database "${ROAD_DB}" \
            2>&1 | tee "${OUT_CLOUD}/roadrecon.log"
        log OK "ROADrecon gather complete → ${ROAD_DB}"
    else
        # Legacy password auth — works only on tenants without MFA enforcement.
        # If this fails silently with an empty DB, set ROADRECON_AUTH_METHOD=devicecode in config.env
        bg_run "roadrecon_gather" \
            "${OUT_CLOUD}/roadrecon.log" \
            "${ROADRECON_BIN:-roadrecon}" gather \
                -u "${DOMAIN_USER}@${DOMAIN_NAME}" \
                -p "${DOMAIN_PASS}" \
                --database "${ROAD_DB}"
        log INFO "ROADrecon running in background. If DB is empty after completion, set ROADRECON_AUTH_METHOD=devicecode."
    fi
fi

# ─── STEP 1.9 — AZURE RESOURCE INVENTORY (background) ────────────────────────
AZURE_INV="${OUT_CLOUD}/azure_inventory.json"
if ! skip_if_exists "${AZURE_INV}" "Azure resource inventory" "azure_inventory"; then
    log INFO "Starting Azure resource inventory across all subscriptions..."
    bg_run "azure_inventory" \
        "${OUT_CLOUD}/azure_inventory.log" \
        bash -c "
            set -euo pipefail
            # Collect resources per subscription into separate files, then merge.
            # Using >> inside the loop would concatenate raw JSON arrays (invalid JSON).
            for sub in ${AZURE_SUBSCRIPTION_IDS}; do
                az account set --subscription \"\${sub}\" 2>/dev/null || continue
                az resource list --output json 2>/dev/null \
                    > '${OUT_CLOUD}/inventory_'\"\${sub}\".json || true
            done
            # Merge per-subscription JSON arrays into one (requires jq)
            if command -v jq &>/dev/null; then
                jq -s 'add // []' '${OUT_CLOUD}'/inventory_*.json > '${AZURE_INV}' 2>/dev/null || true
            else
                cat '${OUT_CLOUD}'/inventory_*.json > '${AZURE_INV}' 2>/dev/null || true
            fi
            # Always enumerate against the last active subscription context for tenant-wide resources
            az vm list --output table                    > '${OUT_CLOUD}/vms.txt'              2>&1 || true
            az storage account list --output table       > '${OUT_CLOUD}/storage.txt'          2>&1 || true
            az network nsg list --output table           > '${OUT_CLOUD}/nsgs.txt'             2>&1 || true
            az keyvault list --output table              > '${OUT_CLOUD}/keyvaults.txt'        2>&1 || true
            az sql server list --output table            > '${OUT_CLOUD}/sql_servers.txt'      2>&1 || true
            az network public-ip list --output table     > '${OUT_CLOUD}/public_ips.txt'       2>&1 || true
            az ad user list --output table               > '${OUT_CLOUD}/entra_users.txt'      2>&1 || true
            az ad group list --output table              > '${OUT_CLOUD}/entra_groups.txt'     2>&1 || true
            az ad app list --output table                > '${OUT_CLOUD}/entra_apps.txt'       2>&1 || true
            az ad sp list --output table                 > '${OUT_CLOUD}/entra_sps.txt'        2>&1 || true
            az role assignment list --all --output table > '${OUT_CLOUD}/role_assignments.txt' 2>&1 || true
        "
    log INFO "Azure inventory running in background (one JSON file per subscription → merged into azure_inventory.json)."
fi

# ─── CHECK CRITICAL SMB SIGNING FINDING ──────────────────────────────────────
# Run inline after smb sweep if it's done
if [[ -f "${SMB_OUT}" ]]; then
    SIGNING_NOT_REQ=$(grep -c 'signing:False\|SMB signing: disabled\|signing: False' "${SMB_OUT}" 2>/dev/null || true)
    if [[ "${SIGNING_NOT_REQ}" -gt 0 ]]; then
        log WARN "FINDING: ${SIGNING_NOT_REQ} host(s) with SMB Signing NOT REQUIRED — relay targets for Phase 3"
        grep 'signing:False\|signing: False' "${SMB_OUT}" > "${OUT_AD}/relay_targets.txt" 2>/dev/null || true
        # Extract just IPs for ntlmrelayx
        awk '{print $2}' "${OUT_AD}/relay_targets.txt" 2>/dev/null | grep -E '^[0-9]+\.' \
            > "${OUT_AD}/relay_target_ips.txt" || true
        log WARN "Relay target IPs written to: ${OUT_AD}/relay_target_ips.txt"
    else
        log OK "All enumerated hosts appear to have SMB signing enabled"
    fi
fi

# ─── STEP 1.10 — CONTROLLED PASSWORD SPRAY (optional) ───────────────────────
# Only runs when SPRAY_ENABLED=true in config.env.
# SPRAY_MAX_ATTEMPTS MUST be below the domain lockout threshold (verify via Phase 2
# password policy check first; default guard is 2 attempts, well below typical 5).
if [[ "${SPRAY_ENABLED:-false}" != "true" ]]; then
    log INFO "Password spray disabled (SPRAY_ENABLED=false). Set SPRAY_ENABLED=true in config.env to enable."
else
    SPRAY_OUT="${OUT_AD}/spray_results.txt"
    if skip_if_exists "${SPRAY_OUT}" "Password spray results" "host_sweep"; then
        :
    else
        require_file "${OUT_AD}/userlist.txt"

        MAX_ATTEMPTS="${SPRAY_MAX_ATTEMPTS:-2}"
        DELAY_SECS="${SPRAY_DELAY_SECONDS:-1800}"

        # Safety: refuse to spray if lockout threshold is unknown
        POLFILE="${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/password_policy.txt"
        if [[ -f "${POLFILE}" ]]; then
            LOCKOUT_THRESH=$(grep -i 'Account lockout threshold' "${POLFILE}" | grep -oE '[0-9]+' | head -1 || echo 0)
            if [[ "${LOCKOUT_THRESH:-0}" -gt 0 && "${MAX_ATTEMPTS}" -ge "${LOCKOUT_THRESH}" ]]; then
                log ERROR "SPRAY BLOCKED: SPRAY_MAX_ATTEMPTS (${MAX_ATTEMPTS}) >= lockout threshold (${LOCKOUT_THRESH}). Reduce SPRAY_MAX_ATTEMPTS in config.env."
                log ERROR "This would lock out accounts. Aborting spray."
            else
                log WARN "SPRAY: lockout threshold=${LOCKOUT_THRESH}, max_attempts=${MAX_ATTEMPTS} — safe margin confirmed."
                _do_spray=true
            fi
        else
            log WARN "Password policy not yet collected (run Phase 2 first, or accept risk). Proceeding with SPRAY_MAX_ATTEMPTS=${MAX_ATTEMPTS}."
            _do_spray=true
        fi

        if [[ "${_do_spray:-false}" == "true" ]]; then
            # Commonly used corporate patterns to try
            SPRAY_PASSWORDS=("${DOMAIN_NAME%%.*}2024!" "${DOMAIN_NAME%%.*}2025!" "Welcome1!" "Password1!" "Summer2024!" "Summer2025!")

            attempt=0
            for pwd in "${SPRAY_PASSWORDS[@]}"; do
                [[ ${attempt} -ge ${MAX_ATTEMPTS} ]] && break
                if ! checkpoint "Spray attempt $((attempt+1))/${MAX_ATTEMPTS}: try password '${pwd}' against all domain users (${DELAY_SECS}s delay between attempts)"; then
                    log INFO "Spray attempt skipped by operator."
                    continue
                fi
                log INFO "Spray attempt $((attempt+1)): password = [REDACTED FROM LOG]"
                log_cmd "${CME_BIN} smb ${DC_IP} -u ${OUT_AD}/userlist.txt -p *** -d ${DOMAIN_NAME} --continue-on-success"
                "${CME_BIN}" smb "${DC_IP}" \
                    -u "${OUT_AD}/userlist.txt" \
                    -p "${pwd}" \
                    -d "${DOMAIN_NAME}" \
                    --continue-on-success \
                    2>&1 >> "${SPRAY_OUT}" || true

                HITS=$(grep -c '(Pwn3d)\|[+] ' "${SPRAY_OUT}" 2>/dev/null || echo 0)
                log OK "Spray attempt $((attempt+1)) complete. Hits so far: ${HITS}"
                (( attempt++ ))

                if [[ ${attempt} -lt ${MAX_ATTEMPTS} && ${#SPRAY_PASSWORDS[@]} -gt ${attempt} ]]; then
                    log INFO "Waiting ${DELAY_SECS}s before next spray attempt (anti-lockout delay)..."
                    sleep "${DELAY_SECS}"
                fi
            done
            SPRAY_HITS=$(grep -c '(Pwn3d)\|[+] ' "${SPRAY_OUT}" 2>/dev/null || echo 0)
            [[ "${SPRAY_HITS}" -gt 0 ]] && \
                log WARN "FINDING: ${SPRAY_HITS} account(s) found via password spray → ${SPRAY_OUT}" || \
                log OK "Password spray: no hits with tested passwords"
        fi
    fi
fi

# ─── STATUS SUMMARY ──────────────────────────────────────────────────────────
echo ""
status_bg_jobs
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Phase 1 — Active Steps Complete${RESET}"
echo -e "${BOLD}${CYAN}  Background jobs running — track with: python3 orchestrator.py --status${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${YELLOW}  Background jobs to monitor:${RESET}"
echo -e "    • Nmap full port scan    → ${FULLSCAN_OUT}.gnmap (merged automatically when done)"
echo -e "    • BloodHound collection  → ${BH_OUT_DIR}/*.zip"
echo -e "    • ROADrecon gather       → ${ROAD_DB}"
echo -e "    • Azure inventory        → ${AZURE_INV}"
echo ""
echo -e "${YELLOW}  Manual steps now required:${RESET}"
echo -e "    • Import BloodHound ZIP into BloodHound CE UI (http://localhost:8080)"
echo -e "    • Run BloodHound key queries (see playbook Phase 1)"
echo -e "    • Review ROADrecon GUI: roadrecon analyze && roadrecon gui"
echo -e "    • Review Nmap full scan results when complete"
echo ""
log OK "Phase 1 automated steps complete. Background jobs running."
