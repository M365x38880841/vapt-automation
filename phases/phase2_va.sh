#!/usr/bin/env bash
# ============================================================================
# phases/phase2_va.sh — Vulnerability Assessment
# ============================================================================
# AUTOMATED (background): ScoutSuite Azure audit, Azure CLI security checks
#                         (NSGs, storage, KV, role assignments, public IPs),
#                         OWASP ZAP DAST web scan (baseline or full-scan mode).
# AUTOMATED (active):     AD CS certipy ESC checks, SMB vuln modules (ms17-010,
#                         nopac, petitpotam), Nessus API trigger.
# MANUAL (after script):  Nessus/OpenVAS UI config, Burp Suite manual testing
#                         (auth/IDOR/session/injection), Purple Knight (Windows),
#                         PingCastle (Windows), report review.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 2 — Vulnerability Assessment"
check_testing_window

require_var "DOMAIN_NAME"; require_var "DC_IP"; require_var "AZURE_TENANT_ID"
require_var "AZURE_SUBSCRIPTION_IDS"; require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
detect_cme
set_scout_cmd  # resolves SCOUT_CMD_ARRAY=( scout suite ) or ( python3 -m ScoutSuite )

OUT_AD="${OUTPUT_BASE_DIR}/phase2/ad"
OUT_CLOUD="${OUTPUT_BASE_DIR}/phase2/cloud"
OUT_WEB="${OUTPUT_BASE_DIR}/phase2/web"
OUT_NET="${OUTPUT_BASE_DIR}/phase2/network"
mkdir -p "${OUT_AD}" "${OUT_CLOUD}" "${OUT_WEB}" "${OUT_NET}"

LIVE_HOSTS="${OUTPUT_BASE_DIR}/phase1/network/live_hosts_all.txt"
require_file "${LIVE_HOSTS}"

# ─── STEP 2.1 — SCOUTSUITE AZURE AUDIT (background — one job per subscription) ─
# Runs against ALL subscriptions, not just the first one.
SCOUT_REPORT_DIR="${OUT_CLOUD}/scoutsuite"
mkdir -p "${SCOUT_REPORT_DIR}"

for sub_id in ${AZURE_SUBSCRIPTION_IDS}; do
    SCOUT_REPORT_SUB="${SCOUT_REPORT_DIR}/${sub_id}"
    SCOUT_DONE_SUB="${SCOUT_REPORT_SUB}/report.html"
    mkdir -p "${SCOUT_REPORT_SUB}"
    if ! skip_if_exists "${SCOUT_DONE_SUB}" "ScoutSuite audit for subscription ${sub_id}" "scoutsuite"; then
        if checkpoint "Launch ScoutSuite audit against subscription ${sub_id} (tenant: ${AZURE_TENANT_ID})?"; then
            log INFO "Starting ScoutSuite for ${sub_id} in background (est. 25–45 min)..."
            bg_run "scoutsuite_${sub_id}" \
                "${OUT_CLOUD}/scoutsuite_${sub_id}.log" \
                "${SCOUT_CMD_ARRAY[@]}" azure \
                    --tenant "${AZURE_TENANT_ID}" \
                    --subscription-id "${sub_id}" \
                    --report-dir "${SCOUT_REPORT_SUB}" \
                    --no-browser
            log INFO "ScoutSuite (${sub_id}) PID: ${BG_JOB_PIDS[-1]}"
        fi
    fi
done

# ─── STEP 2.2 — AZURE SECURITY CHECKS (background — parallel set) ────────────
AZ_SEC="${OUT_CLOUD}/security_checks"
mkdir -p "${AZ_SEC}"

if ! skip_if_exists "${AZ_SEC}/done.flag" "Azure targeted security checks" "azure_security"; then
    log INFO "Running Azure targeted security checks in background..."

    bg_run "azure_sec_checks" \
        "${AZ_SEC}/az_checks.log" \
        bash -c "
            set -euo pipefail

            echo '=== PUBLIC BLOB ACCESS ===' > '${AZ_SEC}/public_blob_access.txt'
            az storage account list \
                --query '[?allowBlobPublicAccess==\`true\`].{Name:name,RG:resourceGroup,Region:location}' \
                --output table 2>&1 >> '${AZ_SEC}/public_blob_access.txt'

            echo '=== NSG ALLOW ANY INBOUND ===' > '${AZ_SEC}/nsg_any_inbound.txt'
            az network nsg list --output json 2>/dev/null | \
                python3 -c \"
import json, sys
nsgs = json.load(sys.stdin)
for nsg in nsgs:
    for rule in nsg.get('securityRules', []):
        if (rule.get('access') == 'Allow' and
            rule.get('direction') == 'Inbound' and
            rule.get('sourceAddressPrefix') in ['*', 'Internet', '0.0.0.0/0']):
            print(f\\\"NSG: {nsg['name']} | Port: {rule.get('destinationPortRange')} | Priority: {rule.get('priority')}\\\")
\" >> '${AZ_SEC}/nsg_any_inbound.txt' 2>&1

            echo '=== KEY VAULT ACCESS POLICIES ===' > '${AZ_SEC}/keyvault_policies.txt'
            az keyvault list --query '[].name' --output tsv 2>/dev/null | while read kv; do
                echo \"--- \${kv} ---\"
                az keyvault show -n \"\${kv}\" \
                    --query 'properties.accessPolicies[].{ObjectId:objectId,Keys:permissions.keys,Secrets:permissions.secrets}' \
                    --output table 2>&1
            done >> '${AZ_SEC}/keyvault_policies.txt'

            echo '=== PUBLIC IP VMs ===' > '${AZ_SEC}/public_ips_vms.txt'
            az vm list-ip-addresses --output table 2>&1 >> '${AZ_SEC}/public_ips_vms.txt'

            echo '=== OVER-PRIVILEGED ROLE ASSIGNMENTS ===' > '${AZ_SEC}/risky_roles.txt'
            az role assignment list --all \
                --query '[?roleDefinitionName==\`Owner\` || roleDefinitionName==\`Contributor\`].{Principal:principalName,Role:roleDefinitionName,Scope:scope}' \
                --output table 2>&1 >> '${AZ_SEC}/risky_roles.txt'

            echo '=== STORAGE ACCOUNTS WITHOUT HTTPS ONLY ===' > '${AZ_SEC}/storage_no_https.txt'
            az storage account list \
                --query '[?supportsHttpsTrafficOnly==\`false\`].{Name:name,RG:resourceGroup}' \
                --output table 2>&1 >> '${AZ_SEC}/storage_no_https.txt'

            echo '=== ENTRA ID MFA GAP (no CA policy) ===' > '${AZ_SEC}/ca_policies.txt'
            az rest --method GET \
                --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
                --query 'value[].{Name:displayName,State:state}' \
                --output table 2>&1 >> '${AZ_SEC}/ca_policies.txt' || \
                echo 'Requires MS Graph permission — check manually in portal' >> '${AZ_SEC}/ca_policies.txt'

            echo '=== DIAGNOSTIC SETTINGS CHECK ===' > '${AZ_SEC}/diagnostics.txt'
            az monitor diagnostic-settings subscription list \
                --output table 2>&1 >> '${AZ_SEC}/diagnostics.txt' || \
                echo 'Run: az monitor diagnostic-settings subscription list' >> '${AZ_SEC}/diagnostics.txt'

            touch '${AZ_SEC}/done.flag'
        "
    log INFO "Azure security checks running in background."
fi

# ─── STEP 2.3 — AD CHECK AUTOMATION (CME-based, no PingCastle dependency) ───
# PingCastle and Purple Knight require Windows — we automate what we can from Linux

AD_CHECKS="${OUT_AD}/ad_checks"
mkdir -p "${AD_CHECKS}"

if ! skip_if_exists "${AD_CHECKS}/done.flag" "Linux-based AD security checks" "ad_checks"; then
    log INFO "Running Linux-based AD security checks..."

    # Kerberoastable accounts check (Phase 2 identification, not yet exploiting)
    log INFO "Identifying Kerberoastable accounts..."
    log_cmd "impacket-GetUserSPNs ${DOMAIN_NAME}/${DOMAIN_USER} -dc-ip ${DC_IP}"
    impacket-GetUserSPNs \
        "${DOMAIN_NAME}/${DOMAIN_USER}:${DOMAIN_PASS}" \
        -dc-ip "${DC_IP}" \
        2>&1 > "${AD_CHECKS}/kerberoastable_accounts.txt" || true
    KERB_COUNT=$(grep -c 'ServicePrincipalName' "${AD_CHECKS}/kerberoastable_accounts.txt" 2>/dev/null || echo 0)
    log OK "Kerberoastable accounts found: ${KERB_COUNT}"

    # AS-REP roastable accounts check
    log INFO "Identifying AS-REP Roastable accounts..."
    log_cmd "impacket-GetNPUsers ${DOMAIN_NAME}/ -no-pass -usersfile ..."
    impacket-GetNPUsers \
        "${DOMAIN_NAME}/" \
        -no-pass \
        -usersfile "${OUTPUT_BASE_DIR}/phase1/ad/userlist.txt" \
        -dc-ip "${DC_IP}" \
        -format hashcat \
        2>&1 > "${AD_CHECKS}/asrep_accounts.txt" || true
    ASREP_COUNT=$(grep -c 'krb5asrep' "${AD_CHECKS}/asrep_accounts.txt" 2>/dev/null || echo 0)
    log OK "AS-REP Roastable accounts found: ${ASREP_COUNT}"

    # Password policy check
    log INFO "Extracting domain password policy..."
    log_cmd "${CME_BIN} smb ${DC_IP} -u ... -d ${DOMAIN_NAME} --pass-pol"
    "${CME_BIN}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --pass-pol \
        2>&1 > "${AD_CHECKS}/password_policy.txt" || true
    log OK "Password policy extracted → ${AD_CHECKS}/password_policy.txt"

    # Enumerate shares
    log INFO "Enumerating accessible shares..."
    "${CME_BIN}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --shares \
        2>&1 > "${AD_CHECKS}/shares.txt" || true

    # Check for accounts with no pre-auth (AS-REP using CME)
    log INFO "Checking admin group members..."
    "${CME_BIN}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --groups "Domain Admins" \
        2>&1 > "${AD_CHECKS}/domain_admins.txt" || true

    # Unconstrained delegation check via LDAP
    log INFO "Checking for unconstrained delegation..."
    ldapsearch -H "ldap://${DC_IP}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
        sAMAccountName dNSHostName \
        2>&1 > "${AD_CHECKS}/unconstrained_delegation.txt" || true
    UNCON_COUNT=$(grep -c 'sAMAccountName:' "${AD_CHECKS}/unconstrained_delegation.txt" 2>/dev/null || echo 0)
    [[ "${UNCON_COUNT}" -gt 0 ]] && \
        log WARN "FINDING: ${UNCON_COUNT} computer(s) with unconstrained delegation — see ${AD_CHECKS}/unconstrained_delegation.txt" || \
        log OK "No unconstrained delegation computers found (excluding DCs)"

    # Accounts with password never expires
    log INFO "Checking for 'password never expires' accounts..."
    ldapsearch -H "ldap://${DC_IP}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' \
        sAMAccountName userAccountControl \
        2>&1 > "${AD_CHECKS}/pwd_never_expires.txt" || true
    PNE_COUNT=$(grep -c 'sAMAccountName:' "${AD_CHECKS}/pwd_never_expires.txt" 2>/dev/null || echo 0)
    [[ "${PNE_COUNT}" -gt 0 ]] && \
        log WARN "FINDING: ${PNE_COUNT} account(s) with 'password never expires'" || \
        log OK "No password-never-expires accounts found"

    # ── AD Certificate Services (AD CS) vulnerability enumeration ──────────────
    # Covers ESC1–ESC8: misconfigured certificate templates & CA permissions.
    # This is one of the highest-value finding classes in modern internal VAPTs.
    ADCS_OUT="${AD_CHECKS}/adcs"
    mkdir -p "${ADCS_OUT}"
    CERTIPY_CMD=$(command -v certipy-ad 2>/dev/null || command -v certipy 2>/dev/null || echo "")
    if [[ -n "${CERTIPY_CMD}" ]]; then
        if ! skip_if_exists "${ADCS_OUT}/adcs_find.txt" "AD CS ESC vulnerability scan"; then
            log INFO "Running Certipy AD CS enumeration (ESC1–ESC8 checks)..."
            log_cmd "${CERTIPY_CMD} find -u ${DOMAIN_USER}@${DOMAIN_NAME} -p *** -dc-ip ${DC_IP} -vulnerable"
            "${CERTIPY_CMD}" find \
                -u "${DOMAIN_USER}@${DOMAIN_NAME}" \
                -p "${DOMAIN_PASS}" \
                -dc-ip "${DC_IP}" \
                -vulnerable \
                -output "${ADCS_OUT}/adcs" \
                2>&1 | tee "${ADCS_OUT}/adcs_find.txt" || true
            ADCS_VULN=$(grep -c 'ESC[0-9]\|Enabled.*True\|Client Authentication' "${ADCS_OUT}/adcs_find.txt" 2>/dev/null || echo 0)
            [[ "${ADCS_VULN}" -gt 0 ]] && \
                log WARN "FINDING: ${ADCS_VULN} potential AD CS misconfiguration(s) — review ${ADCS_OUT}/adcs_find.txt" || \
                log OK "No obvious AD CS ESC misconfigurations detected"
        fi
    else
        log WARN "certipy-ad not installed — AD CS enumeration skipped. Install: pip3 install certipy-ad --break-system-packages"
    fi

    # ── SMB vulnerability module checks (MS17-010, noPac, PetitPotam) ──────────
    SMB_VULN_OUT="${OUT_NET}/smb_vuln_checks.txt"
    if ! skip_if_exists "${SMB_VULN_OUT}" "SMB vulnerability module checks"; then
        log INFO "Running SMB vulnerability checks (ms17-010, nopac, petitpotam)..."
        > "${SMB_VULN_OUT}"
        for module in ms17-010 nopac petitpotam; do
            log_cmd "${CME_BIN} smb -iL ${LIVE_HOSTS} -d ${DOMAIN_NAME} -M ${module}"
            "${CME_BIN}" smb \
                -iL "${LIVE_HOSTS}" \
                -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
                -M "${module}" \
                2>&1 >> "${SMB_VULN_OUT}" || true
        done
        VULN_HITS=$(grep -ci 'vulnerable\|VULNERABLE' "${SMB_VULN_OUT}" 2>/dev/null || echo 0)
        [[ "${VULN_HITS}" -gt 0 ]] && \
            log WARN "FINDING: ${VULN_HITS} SMB vulnerability module hit(s) → ${SMB_VULN_OUT}" || \
            log OK "No SMB vulnerability module hits detected"
    fi

    touch "${AD_CHECKS}/done.flag"
    log OK "Linux AD checks complete → ${AD_CHECKS}/"
fi

# ─── STEP 2.4 — DAST: OWASP ZAP AUTOMATED WEB SCAN ──────────────────────────
# Runs ZAP via Docker — no Java install required, no version conflicts on Kali.
# Targets come from WEB_TARGETS in config.env (space-separated base URLs).
# Scan modes:
#   baseline — passive scan only: no attack payloads, safe, fast, good first pass.
#   full      — active scan: sends attack payloads, confirm RoE explicitly covers this.
ZAP_OUT="${OUT_WEB}/zap"
mkdir -p "${ZAP_OUT}"

if _step_is_skipped "zap"; then
    : # skip ZAP entirely
elif [[ -z "${WEB_TARGETS:-}" ]]; then
    log WARN "WEB_TARGETS not set in config.env — DAST skipped. Set WEB_TARGETS to enable ZAP scans."
else
    if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
        log WARN "Docker not available — OWASP ZAP DAST skipped (Docker required)"
    else
        # Pull ZAP image once (cached on subsequent runs)
        ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
        if ! docker image inspect "${ZAP_IMAGE}" &>/dev/null 2>&1; then
            log INFO "Pulling OWASP ZAP Docker image (one-time, ~200MB)..."
            docker pull "${ZAP_IMAGE}" 2>&1 | tail -3
        fi
        log OK "ZAP image ready: ${ZAP_IMAGE}"

        case "${ZAP_SCAN_MODE:-baseline}" in
            full|active) ZAP_SCRIPT="zap-full-scan.py" ;;
            *)            ZAP_SCRIPT="zap-baseline.py"  ;;
        esac
        log INFO "ZAP scan mode: ${ZAP_SCAN_MODE:-baseline} (script: ${ZAP_SCRIPT})"

        for target in ${WEB_TARGETS}; do
            # Sanitise target URL into a filesystem-safe name for output dirs
            safe_name="${target//[^a-zA-Z0-9._-]/_}"
            ZAP_TARGET_OUT="${ZAP_OUT}/${safe_name}"
            mkdir -p "${ZAP_TARGET_OUT}"
            ZAP_DONE="${ZAP_TARGET_OUT}/zap_report.html"

            if skip_if_exists "${ZAP_DONE}" "ZAP ${ZAP_SCAN_MODE:-baseline} scan: ${target}" "zap"; then
                continue
            fi

            if ! checkpoint "Launch OWASP ZAP ${ZAP_SCAN_MODE:-baseline} scan against ${target}?"; then
                log INFO "ZAP scan skipped for ${target}"
                continue
            fi
            log INFO "Starting ZAP background scan: ${target}"
            log_cmd "docker run ... zaproxy ${ZAP_SCRIPT} -t ${target}"

            # ZAP writes reports relative to /zap/wrk inside the container.
            # --network host: allows ZAP to reach internal hosts on the LAN.
            # -I: don't fail the container on warnings (non-zero exits still logged).
            bg_run "zap_${safe_name}" \
                "${ZAP_TARGET_OUT}/zap.log" \
                docker run --rm \
                    --network host \
                    -v "${ZAP_TARGET_OUT}:/zap/wrk:rw" \
                    "${ZAP_IMAGE}" \
                    "${ZAP_SCRIPT}" \
                        -t "${target}" \
                        -r "zap_report.html" \
                        -J "zap_report.json" \
                        -x "zap_report.xml" \
                        -I

            log INFO "ZAP scanning ${target} in background → ${ZAP_DONE}"
        done
    fi
fi

# ─── STEP 2.5 — NESSUS API TRIGGER (if Nessus configured) ────────────────────
if _step_is_skipped "nessus"; then
    : # skip
elif [[ -n "${NESSUS_URL:-}" && -n "${NESSUS_USER:-}" && -n "${NESSUS_PASS:-}" ]]; then
    log INFO "Triggering Nessus scan via API..."
    NESSUS_SCAN_OUT="${OUT_NET}/nessus_scan.json"

    # Authenticate and get session token
    TOKEN=$(curl -sk -X POST "${NESSUS_URL}/session" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${NESSUS_USER}\",\"password\":\"${NESSUS_PASS}\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")

    if [[ -n "${TOKEN}" ]]; then
        # Save scan list for reference
        curl -sk -X GET "${NESSUS_URL}/scans" \
            -H "X-Cookie: token=${TOKEN}" \
            -o "${NESSUS_SCAN_OUT}" 2>/dev/null
        log OK "Nessus API reachable. Scan list saved → ${NESSUS_SCAN_OUT}"

        if [[ -n "${NESSUS_SCAN_ID:-}" ]]; then
            # Launch the pre-configured credentialed scan by ID
            if checkpoint "Launch Nessus credentialed scan ID=${NESSUS_SCAN_ID} via API?"; then
                LAUNCH_RESP=$(curl -sk -X POST "${NESSUS_URL}/scans/${NESSUS_SCAN_ID}/launch" \
                    -H "X-Cookie: token=${TOKEN}" \
                    -H 'Content-Type: application/json' 2>/dev/null || echo "")
                SCAN_UUID=$(echo "${LAUNCH_RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scan_uuid',''))" 2>/dev/null || echo "")
                if [[ -n "${SCAN_UUID}" ]]; then
                    log OK "Nessus scan launched. UUID: ${SCAN_UUID}"
                    echo "${SCAN_UUID}" > "${OUT_NET}/nessus_scan_uuid.txt"
                    log INFO "Monitor progress: ${NESSUS_URL}/#/scans/${NESSUS_SCAN_ID}"
                else
                    log WARN "Nessus launch returned unexpected response: ${LAUNCH_RESP}"
                    log WARN "Check scan ID ${NESSUS_SCAN_ID} is valid and the policy allows API launch."
                fi
            else
                log WARN "Nessus scan launch skipped by operator — launch manually at ${NESSUS_URL}"
            fi
        else
            log WARN "NESSUS_SCAN_ID not set — cannot auto-launch. Set it in config.env."
            log MANUAL "Launch the Nessus credentialed scan from the UI, then set NESSUS_SCAN_ID to the scan ID for future runs."
        fi

        # Clean up session token
        curl -sk -X DELETE "${NESSUS_URL}/session" -H "X-Cookie: token=${TOKEN}" &>/dev/null || true
    else
        log WARN "Nessus API auth failed. Launch scan manually via UI at ${NESSUS_URL}"
    fi
else
    log WARN "Nessus credentials not configured — scan must be launched manually."
    log WARN "Set NESSUS_URL, NESSUS_USER, NESSUS_PASS in config.env (or prompt at runtime)"
fi

# ─── FINDING SUMMARY ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Phase 2 — Automated Assessment Summary${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${RESET}"

[[ -f "${AD_CHECKS}/kerberoastable_accounts.txt" ]] && \
    echo -e "${YELLOW}  Kerberoastable accounts: ${KERB_COUNT:-?} (→ Phase 3 targets)${RESET}"
[[ -f "${AD_CHECKS}/asrep_accounts.txt" ]] && \
    echo -e "${YELLOW}  AS-REP Roastable accounts: ${ASREP_COUNT:-?} (→ Phase 3 targets)${RESET}"
[[ -f "${AD_CHECKS}/unconstrained_delegation.txt" ]] && \
    echo -e "${RED}  Unconstrained delegation hosts: ${UNCON_COUNT:-?} (→ HIGH finding)${RESET}"
[[ -f "${AD_CHECKS}/pwd_never_expires.txt" ]] && \
    echo -e "${YELLOW}  Password never expires: ${PNE_COUNT:-?} accounts${RESET}"
[[ -f "${AD_CHECKS}/adcs/adcs_find.txt" ]] && \
    echo -e "${RED}  AD CS ESC hits: ${ADCS_VULN:-?} (→ review certipy output for template abuse)${RESET}"
[[ -f "${OUT_NET}/smb_vuln_checks.txt" ]] && \
    echo -e "${RED}  SMB vuln module hits: ${VULN_HITS:-?} (→ ms17-010/nopac/petitpotam)${RESET}"

status_bg_jobs
echo ""
echo -e "${YELLOW}  Manual steps still required:${RESET}"
echo -e "    • Launch Nessus/OpenVAS credentialed scan via UI (start at EOD)"
echo -e "    • Burp Suite: manual auth, IDOR, session, injection checks (ZAP covers passive; Burp covers logic)"
echo -e "    • ZAP reports (when bg jobs finish): ${ZAP_OUT}/<target>/zap_report.html"
echo -e "    • PingCastle: run from a Windows domain-joined machine"
echo -e "    • Purple Knight: run from Windows — collect PDF report"
echo -e "    • Review ScoutSuite HTML reports when background jobs complete"
echo ""
log OK "Phase 2 automated components complete."
