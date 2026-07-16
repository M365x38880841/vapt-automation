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

require_var "DOMAIN_NAME"; require_var "DC_IP"
set_primary_dc

# Conditional credential / cloud-var requirements.
# Pre-flight probe: inspect each step's skip state QUIETLY (no SKIP log lines
# emitted — those fire later at the real call sites).  Only require the
# variables the selected steps will actually use.
_needs_domain_creds=false
for _cred_step in ad_checks; do
    if ! _step_is_skipped "${_cred_step}" quiet; then
        _needs_domain_creds=true; break
    fi
done
_needs_cloud_vars=false
for _cloud_step in scoutsuite azure_security; do
    if ! _step_is_skipped "${_cloud_step}" quiet; then
        _needs_cloud_vars=true; break
    fi
done

if [[ "${_needs_domain_creds}" == "true" ]]; then
    require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
    normalise_domain_user
fi
if [[ "${_needs_cloud_vars}" == "true" ]]; then
    require_var "AZURE_TENANT_ID"; require_var "AZURE_SUBSCRIPTION_IDS"
fi
unset _cred_step _cloud_step _needs_domain_creds _needs_cloud_vars

detect_cme

OUT_AD="${OUTPUT_BASE_DIR}/phase2/ad"
OUT_CLOUD="${OUTPUT_BASE_DIR}/phase2/cloud"
OUT_WEB="${OUTPUT_BASE_DIR}/phase2/web"
OUT_NET="${OUTPUT_BASE_DIR}/phase2/network"
mkdir -p "${OUT_AD}" "${OUT_CLOUD}" "${OUT_WEB}" "${OUT_NET}"

LIVE_HOSTS="${OUTPUT_BASE_DIR}/phase1/network/live_hosts_all.txt"
# LIVE_HOSTS is consumed by SMB vuln checks inside the ad_checks step.
# Only require it when ad_checks will actually run — cloud-only runs should
# not demand a Phase 1 output file.
if ! _step_is_skipped "ad_checks" quiet; then
    require_file "${LIVE_HOSTS}"
fi

# ─── AZURE CLI AUTH (covers all az-based steps in this phase) ────────────────
# ScoutSuite, azure_security, and any other az commands in phase 2 all run
# inside bg_run where interactive prompts are impossible. Authenticate once
# here in the foreground before any background jobs are launched.
_az_ready=false
if _step_is_skipped "scoutsuite" quiet && _step_is_skipped "azure_security" quiet; then
    _az_ready=true  # all az steps skipped — no auth needed
elif require_az_login; then
    _az_ready=true
else
    log WARN "Azure CLI auth failed — scoutsuite and azure_security steps will be skipped"
fi

# ─── AZURE TOKEN FRESHNESS PRE-FLIGHT ────────────────────────────────────────
# require_az_login only runs `az account show`, which reads the CACHED account
# profile and succeeds even when the underlying refresh token has been revoked
# (Azure surfaces AADSTS50173 only when a *real* token is requested — e.g. after
# a password reset). During the 2026-07-15 retest this masked a dead session:
# ScoutSuite aborted (its report dir was never created) and the az checks
# appended AADSTS/AuthorizationFailed errors into the findings files, which then
# read as false "clean" results. Force a real token acquisition here so a revoked
# session is caught up front and the dependent steps are skipped with a clear
# ERROR instead of producing misleading empty output.
if "${_az_ready}"; then
    if ! az account get-access-token --output none 2>/dev/null; then
        log ERROR "Azure access-token acquisition failed — the cached CLI session is stale or revoked."
        log ERROR "Re-authenticate before re-running cloud steps:  az login --use-device-code${AZURE_TENANT_ID:+ --tenant ${AZURE_TENANT_ID}}"
        log ERROR "Skipping ScoutSuite and Azure security checks to avoid recording false 'clean' results."
        _az_ready=false
    fi
fi

# ─── STEP 2.1 — SCOUTSUITE AZURE AUDIT (foreground) ─────────────────────────
# scout azure -c inherits the active az login session and discovers all accessible
# subscriptions automatically — no --tenant or --subscription flags are needed or
# accepted by this auth flow.  A single run covers every subscription the
# authenticated account can see, including multi-subscription tenants.
#
# Runs FOREGROUND so that interactive prompts from ScoutSuite reach the operator
# (e.g. "report directory already exists — overwrite?").  Running in the background
# would leave those prompts unanswered and silently fail the audit.
# Use SKIP_STEPS=scoutsuite to skip this step if a prior report is still current.
SCOUT_REPORT_DIR="${OUT_CLOUD}/scoutsuite"
mkdir -p "${SCOUT_REPORT_DIR}"

if ! "${_az_ready}" || _step_is_skipped "scoutsuite" quiet; then
    log INFO "Skipping: scoutsuite"
else
    set_scout_cmd  # resolves SCOUT_CMD_ARRAY=( scout suite ) or ( python3 -m ScoutSuite )
    if checkpoint "Launch ScoutSuite Azure audit across all subscriptions in the active CLI session? (foreground — est. 25–60 min)"; then
        log INFO "Starting ScoutSuite Azure audit — covers all subscriptions visible to the active session..."
        # Capture exit code explicitly — ScoutSuite uses non-zero codes for non-error
        # conditions (e.g. 200 when writing the HTML report over an existing file).
        # Without this, set -e would abort the entire phase on those codes.
        _scout_rc=0
        "${SCOUT_CMD_ARRAY[@]}" azure \
            -c \
            --report-dir "${SCOUT_REPORT_DIR}" \
            --no-browser || _scout_rc=$?
        if [[ "${_scout_rc}" -eq 0 ]]; then
            log OK "ScoutSuite Azure audit complete → ${SCOUT_REPORT_DIR}"
        else
            log WARN "ScoutSuite exited with code ${_scout_rc} — review output above; report may still be usable in ${SCOUT_REPORT_DIR}"
        fi
        unset _scout_rc
    fi
fi  # end scoutsuite guard

# ─── STEP 2.2 — AZURE SECURITY CHECKS (background — parallel set) ────────────
AZ_SEC="${OUT_CLOUD}/security_checks"
mkdir -p "${AZ_SEC}"

if "${_az_ready}" && ! skip_if_exists "${AZ_SEC}/done.flag" "Azure targeted security checks" "azure_security"; then
    log INFO "Running Azure targeted security checks in background (all subscriptions)..."

    bg_run "azure_sec_checks" \
        "${AZ_SEC}/az_checks.log" \
        bash -c "
            set -euo pipefail

            # az_check <outfile> <az cmd...> — run one az query and record the
            # result so a real API error can never be recorded as '0 findings'.
            # On success the finding rows are appended to <outfile>; on failure the
            # az error text (403 / AADSTS / AuthorizationFailed) is written as an
            # explicit CHECK FAILED marker instead of being silently swallowed by
            # '2>&1 >> file' — the root cause of Bug 2, where an errored check left
            # a findings file that Phase 5 consolidation then read as clean/empty.
            az_check() {
                local _outfile=\"\$1\"; shift
                local _out _rc=0
                _out=\"\$(\"\$@\" 2>&1)\" || _rc=\$?
                if [[ \"\${_rc}\" -eq 0 ]]; then
                    printf '%s\\n' \"\${_out}\" >> \"\${_outfile}\"
                else
                    printf 'CHECK FAILED (az exit %s): %s\\n' \"\${_rc}\" \"\${_out}\" >> \"\${_outfile}\"
                fi
            }

            # Initialise output files before the loop so each subscription appends
            > '${AZ_SEC}/public_blob_access.txt'
            > '${AZ_SEC}/nsg_any_inbound.txt'
            > '${AZ_SEC}/keyvault_policies.txt'
            > '${AZ_SEC}/public_ips_vms.txt'
            > '${AZ_SEC}/risky_roles.txt'
            > '${AZ_SEC}/storage_no_https.txt'
            > '${AZ_SEC}/diagnostics.txt'

            for sub in ${AZURE_SUBSCRIPTION_IDS}; do
                az account set --subscription \"\${sub}\" 2>/dev/null || continue
                echo \"--- Subscription: \${sub} ---\"

                echo \"=== PUBLIC BLOB ACCESS [\${sub}] ===\" >> '${AZ_SEC}/public_blob_access.txt'
                az_check '${AZ_SEC}/public_blob_access.txt' \
                    az storage account list \
                    --query '[?allowBlobPublicAccess==\`true\`].{Name:name,RG:resourceGroup,Region:location}' \
                    --output table

                echo \"=== NSG ALLOW ANY INBOUND [\${sub}] ===\" >> '${AZ_SEC}/nsg_any_inbound.txt'
                # Capture az exit status explicitly rather than piping through
                # '2>/dev/null' — a suppressed API error would otherwise feed the
                # python filter empty input and record a false 'no NSGs' result.
                _nsg_rc=0
                _nsg_json=\"\$(az network nsg list --output json 2>&1)\" || _nsg_rc=\$?
                if [[ \"\${_nsg_rc}\" -ne 0 ]]; then
                    printf 'CHECK FAILED (az network nsg list, exit %s): %s\\n' \"\${_nsg_rc}\" \"\${_nsg_json}\" >> '${AZ_SEC}/nsg_any_inbound.txt'
                else
                    printf '%s' \"\${_nsg_json}\" | python3 -c \"
import json, sys
nsgs = json.load(sys.stdin)
for nsg in nsgs:
    for rule in nsg.get('securityRules', []):
        if (rule.get('access') == 'Allow' and
            rule.get('direction') == 'Inbound' and
            rule.get('sourceAddressPrefix') in ['*', 'Internet', '0.0.0.0/0']):
            print(f\\\"NSG: {nsg['name']} | Port: {rule.get('destinationPortRange')} | Priority: {rule.get('priority')}\\\")
\" >> '${AZ_SEC}/nsg_any_inbound.txt' 2>&1
                fi

                echo \"=== KEY VAULT ACCESS POLICIES [\${sub}] ===\" >> '${AZ_SEC}/keyvault_policies.txt'
                # As above: capture the list call's exit status so a revoked-token
                # / AuthorizationFailed error becomes a CHECK FAILED marker rather
                # than a silently-empty (falsely 'clean') key vault inventory.
                _kv_rc=0
                _kv_list=\"\$(az keyvault list --query '[].name' --output tsv 2>&1)\" || _kv_rc=\$?
                if [[ \"\${_kv_rc}\" -ne 0 ]]; then
                    printf 'CHECK FAILED (az keyvault list, exit %s): %s\\n' \"\${_kv_rc}\" \"\${_kv_list}\" >> '${AZ_SEC}/keyvault_policies.txt'
                else
                    printf '%s\\n' \"\${_kv_list}\" | while read kv; do
                        [[ -z \"\${kv}\" ]] && continue
                        echo \"--- \${kv} ---\"
                        az keyvault show -n \"\${kv}\" \
                            --query 'properties.accessPolicies[].{ObjectId:objectId,Keys:permissions.keys,Secrets:permissions.secrets}' \
                            --output table 2>&1
                    done >> '${AZ_SEC}/keyvault_policies.txt'
                fi

                echo \"=== PUBLIC IP VMs [\${sub}] ===\" >> '${AZ_SEC}/public_ips_vms.txt'
                az_check '${AZ_SEC}/public_ips_vms.txt' \
                    az vm list-ip-addresses --output table

                echo \"=== OVER-PRIVILEGED ROLE ASSIGNMENTS [\${sub}] ===\" >> '${AZ_SEC}/risky_roles.txt'
                az_check '${AZ_SEC}/risky_roles.txt' \
                    az role assignment list --all \
                    --query '[?roleDefinitionName==\`Owner\` || roleDefinitionName==\`Contributor\`].{Principal:principalName,Role:roleDefinitionName,Scope:scope}' \
                    --output table

                echo \"=== STORAGE ACCOUNTS WITHOUT HTTPS ONLY [\${sub}] ===\" >> '${AZ_SEC}/storage_no_https.txt'
                az_check '${AZ_SEC}/storage_no_https.txt' \
                    az storage account list \
                    --query '[?supportsHttpsTrafficOnly==\`false\`].{Name:name,RG:resourceGroup}' \
                    --output table

                echo \"=== DIAGNOSTIC SETTINGS [\${sub}] ===\" >> '${AZ_SEC}/diagnostics.txt'
                az monitor diagnostic-settings subscription list \
                    --output table 2>&1 >> '${AZ_SEC}/diagnostics.txt' || \
                    echo 'Run: az monitor diagnostic-settings subscription list' >> '${AZ_SEC}/diagnostics.txt'

            done

            # CA policies are tenant-wide — run once outside the subscription loop
            echo '=== ENTRA ID MFA GAP (no CA policy) ===' > '${AZ_SEC}/ca_policies.txt'
            az rest --method GET \
                --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
                --query 'value[].{Name:displayName,State:state}' \
                --output table 2>&1 >> '${AZ_SEC}/ca_policies.txt' || \
                echo 'Requires MS Graph permission — check manually in portal' >> '${AZ_SEC}/ca_policies.txt'

            touch '${AZ_SEC}/done.flag'
        "
    log INFO "Azure security checks running in background (one pass per subscription)."
fi

# ─── STEP 2.3 — AD CHECK AUTOMATION (CME-based, no PingCastle dependency) ───
# PingCastle and Purple Knight require Windows — we automate what we can from Linux

AD_CHECKS="${OUT_AD}/ad_checks"
mkdir -p "${AD_CHECKS}"

if ! skip_if_exists "${AD_CHECKS}/done.flag" "Linux-based AD security checks" "ad_checks"; then
    log INFO "Running Linux-based AD security checks..."

    # Kerberoastable accounts check (Phase 2 identification, not yet exploiting)
    log INFO "Identifying Kerberoastable accounts..."
    log_cmd "impacket-GetUserSPNs ${DOMAIN_NAME}/${DOMAIN_USER} -dc-ip ${PRIMARY_DC}"
    impacket-GetUserSPNs \
        "${DOMAIN_NAME}/${DOMAIN_USER}:${DOMAIN_PASS}" \
        -dc-ip "${PRIMARY_DC}" \
        2>&1 > "${AD_CHECKS}/kerberoastable_accounts.txt" || true
    # `grep -c` prints "0" and exits 1 on no-match, so `|| echo 0` double-counts
    # the stdout; strip non-digits so the value is a safe scalar for downstream
    # arithmetic under `set -e`.
    # Count SPN-format lines (e.g. HTTP/host.domain, MSSQLSvc/host:port).
    # Do NOT grep for 'ServicePrincipalName' — that word appears exactly once
    # as the column header, so grep -c returns 1 regardless of account count.
    KERB_COUNT=$(grep -cE '\S+/\S+' "${AD_CHECKS}/kerberoastable_accounts.txt" 2>/dev/null || true)
    KERB_COUNT="${KERB_COUNT//[^0-9]/}"
    KERB_COUNT="${KERB_COUNT:-0}"
    if [[ "${KERB_COUNT}" -gt 0 ]]; then
        log OK "Kerberoastable accounts found: ${KERB_COUNT} → ${AD_CHECKS}/kerberoastable_accounts.txt"
    else
        log OK "Kerberoastable accounts found: 0 → ${AD_CHECKS}/kerberoastable_accounts.txt"
    fi

    # AS-REP roastable accounts — enumerate via LDAP, not GetNPUsers.
    # GetNPUsers -no-pass only returns a hash when the KDC issues an AS-REP;
    # accounts with UF_DONT_REQUIRE_PREAUTH set but with revoked/expired
    # credentials return KDC_ERR_CLIENT_REVOKED and produce no output — so
    # GetNPUsers silently undercounts. The LDAP bitmask query (0x400000 =
    # 4194304) reads the userAccountControl attribute directly and finds ALL
    # accounts with the flag, enabled or not. Phase 3 handles actual hash
    # capture via GetNPUsers for the crackable subset.
    log INFO "Identifying AS-REP Roastable accounts via LDAP (UF_DONT_REQUIRE_PREAUTH)..."
    log_cmd "ldapsearch ... (userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    ldapsearch -H "ldap://${PRIMARY_DC}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
        sAMAccountName userAccountControl accountExpires \
        > "${AD_CHECKS}/asrep_accounts.txt" 2>&1 || true
    ASREP_COUNT=$(grep -c 'sAMAccountName:' "${AD_CHECKS}/asrep_accounts.txt" 2>/dev/null || true)
    ASREP_COUNT="${ASREP_COUNT//[^0-9]/}"
    ASREP_COUNT="${ASREP_COUNT:-0}"
    if [[ "${ASREP_COUNT}" -gt 0 ]]; then
        log WARN "FINDING: ${ASREP_COUNT} account(s) with UF_DONT_REQUIRE_PREAUTH set → ${AD_CHECKS}/asrep_accounts.txt"
        log INFO "Phase 3 will attempt hash capture for accounts the KDC responds to (excludes revoked/disabled)"
    else
        log OK "AS-REP Roastable accounts found: 0 → ${AD_CHECKS}/asrep_accounts.txt"
    fi

    # Password policy check
    log INFO "Extracting domain password policy..."
    log_cmd "${CME_BIN} smb ${PRIMARY_DC} -u ... -d ${DOMAIN_NAME} --pass-pol"
    "${CME_BIN}" smb "${PRIMARY_DC}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --pass-pol \
        > "${AD_CHECKS}/password_policy.txt" 2>&1 || true
    log OK "Password policy extracted → ${AD_CHECKS}/password_policy.txt"

    # Enumerate shares
    log INFO "Enumerating accessible shares..."
    "${CME_BIN}" smb "${PRIMARY_DC}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --shares \
        > "${AD_CHECKS}/shares.txt" 2>&1 || true
    log OK "Share enumeration complete → ${AD_CHECKS}/shares.txt"

    # Enumerate privileged group membership.
    # NetExec moved --groups from the smb module to ldap ("Arg moved to the
    # ldap protocol") — smb here silently no-ops with "[REMOVED]" instead of
    # returning membership, which is why this must run as an ldap check.
    log INFO "Checking admin group members..."
    "${CME_BIN}" ldap "${PRIMARY_DC}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --groups "Domain Admins" \
        > "${AD_CHECKS}/domain_admins.txt" 2>&1 || true
    log OK "Domain Admins group members → ${AD_CHECKS}/domain_admins.txt"

    # Backup Operators is the group the original engagement flagged (F026:
    # sccmsvc, Veritasvc, beadmin, HNSAdmin, Administrator) — re-check it
    # explicitly rather than relying on Domain Admins alone to catch drift.
    "${CME_BIN}" ldap "${PRIMARY_DC}" \
        -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
        --groups "Backup Operators" \
        > "${AD_CHECKS}/backup_operators.txt" 2>&1 || true
    log OK "Backup Operators group members → ${AD_CHECKS}/backup_operators.txt"

    # Unconstrained delegation check via LDAP
    log INFO "Checking for unconstrained delegation..."
    ldapsearch -H "ldap://${PRIMARY_DC}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
        sAMAccountName dNSHostName \
        > "${AD_CHECKS}/unconstrained_delegation.txt" 2>&1 || true
    UNCON_COUNT=$(grep -c 'sAMAccountName:' "${AD_CHECKS}/unconstrained_delegation.txt" 2>/dev/null || true)
    UNCON_COUNT="${UNCON_COUNT//[^0-9]/}"
    UNCON_COUNT="${UNCON_COUNT:-0}"
    if [[ "${UNCON_COUNT}" -gt 0 ]]; then
        log WARN "FINDING: ${UNCON_COUNT} computer(s) with unconstrained delegation — see ${AD_CHECKS}/unconstrained_delegation.txt"
    else
        log OK "No unconstrained delegation computers found (excluding DCs)"
    fi

    # Accounts with password never expires
    log INFO "Checking for 'password never expires' accounts..."
    ldapsearch -H "ldap://${PRIMARY_DC}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' \
        sAMAccountName userAccountControl \
        > "${AD_CHECKS}/pwd_never_expires.txt" 2>&1 || true
    PNE_COUNT=$(grep -c 'sAMAccountName:' "${AD_CHECKS}/pwd_never_expires.txt" 2>/dev/null || true)
    PNE_COUNT="${PNE_COUNT//[^0-9]/}"
    PNE_COUNT="${PNE_COUNT:-0}"
    if [[ "${PNE_COUNT}" -gt 0 ]]; then
        log WARN "FINDING: ${PNE_COUNT} account(s) with 'password never expires' → ${AD_CHECKS}/pwd_never_expires.txt"
    else
        log OK "No password-never-expires accounts found"
    fi

    # ── AD Certificate Services (AD CS) vulnerability enumeration ──────────────
    # Covers ESC1–ESC8: misconfigured certificate templates & CA permissions.
    # This is one of the highest-value finding classes in modern internal VAPTs.
    ADCS_OUT="${AD_CHECKS}/adcs"
    mkdir -p "${ADCS_OUT}"
    CERTIPY_CMD=$(command -v certipy-ad 2>/dev/null || command -v certipy 2>/dev/null || echo "")
    if [[ -n "${CERTIPY_CMD}" ]]; then
        if ! skip_if_exists "${ADCS_OUT}/adcs_find.txt" "AD CS ESC vulnerability scan"; then
            log INFO "Running Certipy AD CS enumeration (ESC1–ESC8 checks)..."
            log_cmd "${CERTIPY_CMD} find -u ${DOMAIN_USER}@${DOMAIN_NAME} -p *** -dc-ip ${PRIMARY_DC} -vulnerable"
            # certipy resolves -output relative to CWD, replacing '/' with '_' in
            # absolute paths. Run from ADCS_OUT with a bare basename so the
            # .txt/.json files land in the right directory.
            (cd "${ADCS_OUT}" && "${CERTIPY_CMD}" find \
                -u "${DOMAIN_USER}@${DOMAIN_NAME}" \
                -p "${DOMAIN_PASS}" \
                -dc-ip "${PRIMARY_DC}" \
                -vulnerable \
                -output adcs \
                2>&1 | tee adcs_find.txt) || true
            ADCS_VULN=$(grep -c 'ESC[0-9]\|Enabled.*True\|Client Authentication' "${ADCS_OUT}/adcs_find.txt" 2>/dev/null || true)
            ADCS_VULN="${ADCS_VULN//[^0-9]/}"
            ADCS_VULN="${ADCS_VULN:-0}"
            if [[ "${ADCS_VULN}" -gt 0 ]]; then
                log WARN "FINDING: ${ADCS_VULN} potential AD CS misconfiguration(s) — review ${ADCS_OUT}/adcs_find.txt"
            else
                log OK "No obvious AD CS ESC misconfigurations detected"
            fi
        fi
    else
        log WARN "certipy-ad not installed — AD CS enumeration skipped. Install: pip3 install certipy-ad --break-system-packages"
    fi

    # ── SMB vulnerability module checks (MS17-010, noPac, PetitPotam) ──────────
    SMB_VULN_OUT="${OUT_NET}/smb_vuln_checks.txt"
    if ! skip_if_exists "${SMB_VULN_OUT}" "SMB vulnerability module checks"; then
        log INFO "Running SMB vulnerability checks (ms17-010, nopac, petitpotam)..."
        > "${SMB_VULN_OUT}"
        # nxc does not support -iL (nmap syntax); read hosts into an array instead.
        mapfile -t _smb_targets < "${LIVE_HOSTS}"
        for module in ms17-010 nopac petitpotam; do
            log_cmd "${CME_BIN} smb [${#_smb_targets[@]} hosts] -d ${DOMAIN_NAME} -M ${module}"
            "${CME_BIN}" smb \
                "${_smb_targets[@]}" \
                -u "${DOMAIN_USER}" -p "${DOMAIN_PASS}" -d "${DOMAIN_NAME}" \
                -M "${module}" \
                2>&1 >> "${SMB_VULN_OUT}" || true
        done
        unset _smb_targets
        VULN_HITS=$(grep -ci 'vulnerable\|VULNERABLE' "${SMB_VULN_OUT}" 2>/dev/null || true)
        VULN_HITS="${VULN_HITS//[^0-9]/}"
        VULN_HITS="${VULN_HITS:-0}"
        if [[ "${VULN_HITS}" -gt 0 ]]; then
            log WARN "FINDING: ${VULN_HITS} SMB vulnerability module hit(s) → ${SMB_VULN_OUT}"
        else
            log OK "No SMB vulnerability module hits detected"
        fi
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
        # Max concurrent ZAP containers — configurable via config.env, default 4.
        ZAP_CONCURRENCY="${ZAP_CONCURRENCY:-4}"
        log INFO "ZAP scan mode: ${ZAP_SCAN_MODE:-baseline} (script: ${ZAP_SCRIPT}, concurrency: ${ZAP_CONCURRENCY})"

        # Build list of targets that still need scanning.
        _zap_pending=()
        for _zt in ${WEB_TARGETS}; do
            _zap_safe="${_zt//[^a-zA-Z0-9._-]/_}"
            if [[ -f "${ZAP_OUT}/${_zap_safe}/zap_report.html" ]]; then
                log INFO "ZAP: already scanned, skipping: ${_zt}"
            else
                _zap_pending+=("${_zt}")
            fi
        done

        if [[ ${#_zap_pending[@]} -eq 0 ]]; then
            log OK "All ZAP targets already scanned — skipping"
        else
            log INFO "${#_zap_pending[@]} ZAP target(s) pending. You will be prompted for each one."
            log INFO "Max concurrent scans: ${ZAP_CONCURRENCY} (set ZAP_CONCURRENCY in config.env to change)"
            _zap_pids=()
            for _zt in "${_zap_pending[@]}"; do
                # Per-target gate: wait for any in-flight scans to clear the concurrency
                # slot before prompting — operator sees current load before deciding.
                while [[ ${#_zap_pids[@]} -ge ${ZAP_CONCURRENCY} ]]; do
                    log INFO "Concurrency limit (${ZAP_CONCURRENCY}) reached — waiting for a slot to free..."
                    wait -n 2>/dev/null || true
                    _zap_alive=()
                    for _zp in "${_zap_pids[@]+"${_zap_pids[@]}"}"; do
                        kill -0 "${_zp}" 2>/dev/null && _zap_alive+=("${_zp}") || true
                    done
                    _zap_pids=("${_zap_alive[@]+"${_zap_alive[@]}"}")
                done

                _running=${#_zap_pids[@]}
                if ! checkpoint "Scan ${_zt}? (${_running} scan(s) currently running)"; then
                    log INFO "Skipped: ${_zt}"
                    continue
                fi

                _zap_safe="${_zt//[^a-zA-Z0-9._-]/_}"
                _zap_tgt_out="${ZAP_OUT}/${_zap_safe}"
                mkdir -p "${_zap_tgt_out}"
                log_cmd "docker run ... zaproxy ${ZAP_SCRIPT} -t ${_zt}"
                docker run --rm \
                    --network host \
                    -v "${_zap_tgt_out}:/zap/wrk:rw" \
                    "${ZAP_IMAGE}" \
                    "${ZAP_SCRIPT}" \
                        -t "${_zt}" \
                        -r "zap_report.html" \
                        -J "zap_report.json" \
                        -x "zap_report.xml" \
                        -I \
                    >> "${_zap_tgt_out}/zap.log" 2>&1 &
                _zap_pids+=($!)
                log INFO "ZAP scanning ${_zt} (PID ${_zap_pids[-1]}) → ${_zap_tgt_out}/zap_report.html"
            done

            # Wait for all remaining in-flight scans to finish.
            if [[ ${#_zap_pids[@]} -gt 0 ]]; then
                log INFO "Waiting for ${#_zap_pids[@]} ZAP scan(s) to complete..."
                wait "${_zap_pids[@]}" 2>/dev/null || true
            fi
            log OK "ZAP scans complete → ${ZAP_OUT}/"
            unset _zap_pids _zap_pending _zap_alive _zap_safe _zap_tgt_out _zt _zp
        fi
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
