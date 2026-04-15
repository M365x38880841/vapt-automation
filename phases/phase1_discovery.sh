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

# ─── RUNTIME REQUIREMENTS ────────────────────────────────────────────────────
require_var "DOMAIN_NAME"; require_var "DC_IP"; require_var "TARGET_SUBNETS"
require_var "ATTACKER_INTERFACE"; require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
detect_cme

OUT_NET="$(phase_dir phase1 network)"
OUT_AD="$(phase_dir phase1 ad)"
OUT_CLOUD="$(phase_dir phase1 cloud)"

# ─── STEP 1.1 — HOST SWEEP (parallel, one per subnet) ───────────────────────
log INFO "Starting host sweep across all subnets (parallel)..."
LIVE_HOSTS_MERGED="${OUT_NET}/live_hosts_all.txt"
> "${LIVE_HOSTS_MERGED}"  # clear/create

for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    sweep_out="${OUT_NET}/hostsweep_${safe_name}"
    if skip_if_exists "${sweep_out}.gnmap" "Host sweep ${subnet}"; then
        grep 'Up' "${sweep_out}.gnmap" 2>/dev/null | awk '{print $2}' >> "${LIVE_HOSTS_MERGED}" || true
        continue
    fi
    log INFO "Sweeping subnet: ${subnet}"
    bg_run "hostsweep_${safe_name}" \
        "${OUT_NET}/hostsweep_${safe_name}.log" \
        "${NMAP_BIN:-nmap}" -sn "${subnet}" \
            -oA "${sweep_out}" \
            --min-hostgroup "${NMAP_MIN_HOSTGROUP:-32}"
done

# Wait for all sweeps before merging
wait_for_bg_jobs "host sweeps"

# Merge all live hosts
for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    gnmap="${OUT_NET}/hostsweep_${safe_name}.gnmap"
    [[ -f "${gnmap}" ]] && grep 'Up' "${gnmap}" | awk '{print $2}' >> "${LIVE_HOSTS_MERGED}"
done
sort -u "${LIVE_HOSTS_MERGED}" -o "${LIVE_HOSTS_MERGED}"
LIVE_COUNT=$(wc -l < "${LIVE_HOSTS_MERGED}")
log OK "Host sweep complete. Live hosts found: ${LIVE_COUNT} → ${LIVE_HOSTS_MERGED}"

[[ "${LIVE_COUNT}" -eq 0 ]] && { log ERROR "No live hosts found. Check subnets and interface."; exit 1; }

# ─── STEP 1.2 — FULL PORT SCAN (background — runs overnight) ────────────────
FULLSCAN_OUT="${OUT_NET}/fullscan"
if ! skip_if_exists "${FULLSCAN_OUT}.xml" "Full port scan"; then
    checkpoint "Start full port scan (-p- against ${LIVE_COUNT} hosts). This runs in background and may take 3–5 hours."
    log INFO "Launching full port scan as background job (overnight-friendly)..."
    bg_run "nmap_fullscan" \
        "${OUT_NET}/fullscan.log" \
        "${NMAP_BIN:-nmap}" \
            -sS -sV -sC -p- --open \
            -T"${NMAP_TIMING:-4}" \
            --min-hostgroup "${NMAP_MIN_HOSTGROUP:-32}" \
            -iL "${LIVE_HOSTS_MERGED}" \
            -oA "${FULLSCAN_OUT}"
    log INFO "Full port scan running in background (PID: ${BG_JOB_PIDS[-1]}). Continuing with other tasks."
fi

# ─── STEP 1.3 — SMB SWEEP + SIGNING CHECK (background) ──────────────────────
SMB_OUT="${OUT_AD}/smb_sweep.txt"
if ! skip_if_exists "${SMB_OUT}" "CrackMapExec SMB sweep"; then
    log INFO "Starting CrackMapExec SMB sweep (signing + host enumeration)..."
    bg_run "cmexec_smb_sweep" \
        "${OUT_AD}/smb_sweep.log" \
        bash -c "for subnet in ${TARGET_SUBNETS}; do \
            ${CME_BIN} smb \"\${subnet}\" \
                -u '${DOMAIN_USER}' -p '${DOMAIN_PASS}' \
                2>&1; \
        done > '${SMB_OUT}'"
    log INFO "CME SMB sweep running in background."
fi

# ─── STEP 1.4 — LDAP DC BANNER GRAB (active — quick) ─────────────────────────
LDAP_OUT="${OUT_AD}/ldap_rootdse.txt"
if ! skip_if_exists "${LDAP_OUT}" "LDAP rootdse"; then
    log INFO "Grabbing LDAP rootdse from DC: ${DC_IP}"
    log_cmd "${NMAP_BIN} -p 389 --script ldap-rootdse ${DC_IP}"
    "${NMAP_BIN:-nmap}" -p 389 --script ldap-rootdse "${DC_IP}" \
        -oN "${LDAP_OUT}" 2>&1 | tee -a "${OUT_AD}/ldap.log"
    log OK "LDAP rootdse collected → ${LDAP_OUT}"
fi

# ─── STEP 1.5 — LDAP USER ENUMERATION (active — quick) ───────────────────────
LDAP_USERS_OUT="${OUT_AD}/ldap_users.txt"
if ! skip_if_exists "${LDAP_USERS_OUT}" "LDAP user enumeration"; then
    log INFO "Enumerating domain users via LDAP..."
    log_cmd "ldapsearch -H ldap://${DC_IP} -D ${DOMAIN_USER}@${DOMAIN_NAME} -w *** -b DC=..."
    ldapsearch -H "ldap://${DC_IP}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(objectClass=user)' sAMAccountName mail memberOf userAccountControl \
        2>&1 > "${LDAP_USERS_OUT}" || log WARN "LDAP query failed — check credentials and DC reachability"

    # Extract clean username list for Phase 3 (AS-REP roasting)
    grep 'sAMAccountName:' "${LDAP_USERS_OUT}" | awk '{print $2}' \
        | grep -v -E '^\$' \
        > "${OUT_AD}/userlist.txt"
    UCOUNT=$(wc -l < "${OUT_AD}/userlist.txt")
    log OK "LDAP users collected: ${UCOUNT} accounts → ${OUT_AD}/userlist.txt"
fi

# ─── STEP 1.6 — SMB NULL SESSION CHECK (active — instant) ───────────────────
log INFO "Checking for SMB null session (should be blocked)..."
log_cmd "${CME_BIN} smb ${DC_IP} --null-session"
"${CME_BIN}" smb "${DC_IP}" --null-session \
    2>&1 > "${OUT_AD}/nullsession_check.txt" || true
if grep -q 'STATUS_ACCESS_DENIED\|STATUS_LOGON_FAILURE' "${OUT_AD}/nullsession_check.txt" 2>/dev/null; then
    log OK "Null session blocked (expected)"
else
    log WARN "Null session may be accessible — review: ${OUT_AD}/nullsession_check.txt"
fi

# ─── STEP 1.7 — BLOODHOUND DATA COLLECTION (background) ──────────────────────
BH_OUT_DIR="${OUT_AD}/bloodhound"
mkdir -p "${BH_OUT_DIR}"
BH_ZIP=$(ls "${BH_OUT_DIR}"/*.zip 2>/dev/null | head -1)
if [[ -z "${BH_ZIP}" ]]; then
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
            -o "${BH_OUT_DIR}"
    log INFO "BloodHound collection running in background."
else
    log INFO "BloodHound ZIP already exists: ${BH_ZIP} — skipping collection"
fi

# ─── STEP 1.8 — ROADRECON ENTRA ID GATHER ────────────────────────────────────
ROAD_DB="${OUT_CLOUD}/roadrecon.db"
if ! skip_if_exists "${ROAD_DB}" "ROADrecon gather"; then
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
if ! skip_if_exists "${AZURE_INV}" "Azure resource inventory"; then
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

# ─── STATUS SUMMARY ──────────────────────────────────────────────────────────
echo ""
status_bg_jobs
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Phase 1 — Active Steps Complete${RESET}"
echo -e "${BOLD}${CYAN}  Background Jobs: Still running (check with --status)${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${YELLOW}  Background jobs to monitor:${RESET}"
echo -e "    • Nmap full port scan    → ${FULLSCAN_OUT}.xml (check tomorrow AM)"
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
