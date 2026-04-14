#!/usr/bin/env bash
# ============================================================================
# phases/phase2_va.sh — Vulnerability Assessment
# ============================================================================
# AUTOMATED (background): ScoutSuite Azure audit, Azure CLI security checks
#                         (NSGs, storage, KV, role assignments, public IPs).
# AUTOMATED (active):     PingCastle remote invocation (if Windows runner
#                         configured), Nessus API-triggered scan.
# MANUAL (after script):  Nessus/OpenVAS UI config, Burp Suite web testing,
#                         Purple Knight (Windows-only), report review.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 2 — Vulnerability Assessment"
check_testing_window

require_var "DOMAIN_NAME"; require_var "DC_IP"; require_var "AZURE_TENANT_ID"
require_var "AZURE_SUBSCRIPTION_IDS"; require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"

OUT_AD="${OUTPUT_BASE_DIR}/phase2/ad"
OUT_CLOUD="${OUTPUT_BASE_DIR}/phase2/cloud"
OUT_WEB="${OUTPUT_BASE_DIR}/phase2/web"
OUT_NET="${OUTPUT_BASE_DIR}/phase2/network"
mkdir -p "${OUT_AD}" "${OUT_CLOUD}" "${OUT_WEB}" "${OUT_NET}"

LIVE_HOSTS="${OUTPUT_BASE_DIR}/phase1/network/live_hosts_all.txt"
require_file "${LIVE_HOSTS}"

# ─── STEP 2.1 — SCOUTSUITE AZURE AUDIT (background — 25–45 min) ──────────────
SCOUT_REPORT_DIR="${OUT_CLOUD}/scoutsuite"
mkdir -p "${SCOUT_REPORT_DIR}"
SCOUT_DONE="${SCOUT_REPORT_DIR}/report.html"

if ! skip_if_exists "${SCOUT_DONE}" "ScoutSuite Azure audit"; then
    checkpoint "Launch ScoutSuite audit against Azure tenant ${AZURE_TENANT_ID}?"
    log INFO "Starting ScoutSuite in background (est. 25–45 min)..."
    bg_run "scoutsuite_audit" \
        "${OUT_CLOUD}/scoutsuite.log" \
        "${SCOUT_BIN:-scout}" azure \
            --tenant "${AZURE_TENANT_ID}" \
            --subscription-id "${AZURE_SUBSCRIPTION_IDS%% *}" \
            --report-dir "${SCOUT_REPORT_DIR}" \
            --no-browser
    log INFO "ScoutSuite running in background. PID: ${BG_JOB_PIDS[-1]}"
fi

# ─── STEP 2.2 — AZURE SECURITY CHECKS (background — parallel set) ────────────
AZ_SEC="${OUT_CLOUD}/security_checks"
mkdir -p "${AZ_SEC}"

if ! skip_if_exists "${AZ_SEC}/done.flag" "Azure targeted security checks"; then
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

if ! skip_if_exists "${AD_CHECKS}/done.flag" "Linux-based AD security checks"; then
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
    log_cmd "${CME_BIN} smb ${DC_IP} -u ... --pass-pol"
    "${CME_BIN:-crackmapexec}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" \
        --pass-pol \
        2>&1 > "${AD_CHECKS}/password_policy.txt" || true
    log OK "Password policy extracted → ${AD_CHECKS}/password_policy.txt"

    # Enumerate shares
    log INFO "Enumerating accessible shares..."
    "${CME_BIN:-crackmapexec}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" \
        --shares \
        2>&1 > "${AD_CHECKS}/shares.txt" || true

    # Check for accounts with no pre-auth (AS-REP using CME)
    log INFO "Checking admin group members..."
    "${CME_BIN:-crackmapexec}" smb "${DC_IP}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" \
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

    touch "${AD_CHECKS}/done.flag"
    log OK "Linux AD checks complete → ${AD_CHECKS}/"
fi

# ─── STEP 2.4 — NESSUS API TRIGGER (if Nessus configured) ────────────────────
if [[ -n "${NESSUS_URL:-}" && -n "${NESSUS_USER:-}" && -n "${NESSUS_PASS:-}" ]]; then
    log INFO "Triggering Nessus scan via API..."
    NESSUS_SCAN_OUT="${OUT_NET}/nessus_scan.json"

    # Get API token
    TOKEN=$(curl -sk -X POST "${NESSUS_URL}/session" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${NESSUS_USER}\",\"password\":\"${NESSUS_PASS}\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")

    if [[ -n "${TOKEN}" ]]; then
        # List existing scans to find or create
        curl -sk -X GET "${NESSUS_URL}/scans" \
            -H "X-Cookie: token=${TOKEN}" \
            -o "${NESSUS_SCAN_OUT}" 2>/dev/null
        log OK "Nessus API reachable. Scan list saved → ${NESSUS_SCAN_OUT}"
        log MANUAL "Launch the Nessus credentialed scan from the UI or configure scan ID in config.env as NESSUS_SCAN_ID and re-run."
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

status_bg_jobs
echo ""
echo -e "${YELLOW}  Manual steps still required:${RESET}"
echo -e "    • Launch Nessus/OpenVAS credentialed scan via UI (start at EOD)"
echo -e "    • Burp Suite: browse all in-scope web apps + run active scan"
echo -e "    • Burp Suite: manual auth, IDOR, session, injection checks"
echo -e "    • PingCastle: run from a Windows domain-joined machine"
echo -e "    • Purple Knight: run from Windows — collect PDF report"
echo -e "    • Review ScoutSuite HTML report when background job completes"
echo ""
log OK "Phase 2 automated components complete."
