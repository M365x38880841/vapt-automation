#!/usr/bin/env bash
# ============================================================================
# phases/phase5_consolidate.sh — Evidence Consolidation (Report Scaffold)
# ============================================================================
# Automates evidence organisation and generates a pre-filled report scaffold.
# The actual writing of findings, impact statements, and remediation is MANUAL.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 5 — Evidence Consolidation & Report Scaffolding"

REPORT_DIR="${OUTPUT_BASE_DIR}/report"
EVIDENCE_DIR="${REPORT_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"/{network,ad,cloud,web,cracked}

# ─── COLLECT ALL EVIDENCE FILES ──────────────────────────────────────────────
log INFO "Consolidating evidence files from all phases..."

cp -u "${OUTPUT_BASE_DIR}"/phase1/network/fullscan.* "${EVIDENCE_DIR}/network/" 2>/dev/null \
    && log OK "Nmap full scan copied" || log WARN "Nmap full scan not yet available — skipping"

cp -u "${OUTPUT_BASE_DIR}"/phase1/ad/bloodhound/*.zip "${EVIDENCE_DIR}/ad/" 2>/dev/null \
    && log OK "BloodHound ZIPs copied" || log WARN "BloodHound ZIPs not found — skipping"

# ScoutSuite writes per-subscription: scoutsuite/<sub_id>/report.html — use wildcard.
find "${OUTPUT_BASE_DIR}/phase2/cloud/scoutsuite" -name 'report.html' -exec cp -u {} "${EVIDENCE_DIR}/cloud/" \; 2>/dev/null \
    && log OK "ScoutSuite report(s) copied" || log WARN "ScoutSuite reports not found — skipping"

cp -u "${OUTPUT_BASE_DIR}"/phase3/ad/cracked_*.txt "${EVIDENCE_DIR}/cracked/" 2>/dev/null \
    && log OK "Cracked credentials copied" || log WARN "No cracked credential files yet — skipping"

cp -u "${OUTPUT_BASE_DIR}"/phase3/ad/responder_session.log "${EVIDENCE_DIR}/ad/" 2>/dev/null || true
cp -u "${OUTPUT_BASE_DIR}"/phase3/cloud/public_blob_poc.txt "${EVIDENCE_DIR}/cloud/" 2>/dev/null || true
cp -u "${OUTPUT_BASE_DIR}"/phase4/ad/dcsync_poc.txt "${EVIDENCE_DIR}/ad/" 2>/dev/null || true
cp -u "${OUTPUT_BASE_DIR}"/phase4/blast_radius/summary.md "${EVIDENCE_DIR}/" 2>/dev/null || true

# ─── COUNT FINDINGS FROM AUTOMATED OUTPUTS ────────────────────────────────────
KERB_COUNT=$(grep -c 'krb5tgs'   "${EVIDENCE_DIR}/cracked/cracked_tgs.txt"   2>/dev/null || echo 0)
ASREP_COUNT=$(grep -c 'krb5asrep' "${OUTPUT_BASE_DIR}/phase3/ad/cracked_asrep.txt" 2>/dev/null || echo 0)
CRACKED_NTLM_COUNT=$(wc -l < "${EVIDENCE_DIR}/cracked/cracked_ntlm.txt" 2>/dev/null || echo 0)
PTH_COUNT=$(wc -l < "${OUTPUT_BASE_DIR}/phase3/ad/pth_accessible_hosts.txt" 2>/dev/null || echo 0)
PUBLIC_BLOBS=$(grep -c 'CRITICAL' "${EVIDENCE_DIR}/cloud/public_blob_poc.txt" 2>/dev/null || echo 0)
UNCON_DELEG=$(grep -c 'sAMAccountName' "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/unconstrained_delegation.txt" 2>/dev/null || echo 0)
PNE_COUNT=$(grep -c 'sAMAccountName' "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/pwd_never_expires.txt" 2>/dev/null || echo 0)
ADCS_HITS=$(grep -c 'ESC[0-9]\|Enabled.*True' "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/adcs/adcs_find.txt" 2>/dev/null || echo 0)
SMB_VULN_HITS=$(grep -ci 'vulnerable' "${OUTPUT_BASE_DIR}/phase2/network/smb_vuln_checks.txt" 2>/dev/null || echo 0)

# Copy AD CS and SMB vuln evidence
cp -u "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/adcs/"* "${EVIDENCE_DIR}/ad/" 2>/dev/null && log OK "AD CS certipy output copied" || true
cp -u "${OUTPUT_BASE_DIR}/phase2/network/smb_vuln_checks.txt" "${EVIDENCE_DIR}/network/" 2>/dev/null || true
# ZAP DAST reports — one subdirectory per scanned target
if [[ -d "${OUTPUT_BASE_DIR}/phase2/web/zap" ]]; then
    cp -ur "${OUTPUT_BASE_DIR}/phase2/web/zap" "${EVIDENCE_DIR}/web/" 2>/dev/null && log OK "ZAP DAST reports copied" || true
fi
ZAP_TARGET_COUNT=$(find "${OUTPUT_BASE_DIR}/phase2/web/zap" -name 'zap_report.html' 2>/dev/null | wc -l || echo 0)
ZAP_HIGH_ALERTS=$(find "${OUTPUT_BASE_DIR}/phase2/web/zap" -name 'zap_report.json' \
    -exec python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(s.get('alerts',[])) for s in d.get('site',[]) if s.get('alerts')))" {} \; 2>/dev/null \
    | awk '{s+=$1} END{print s+0}')

# ─── GENERATE REPORT SCAFFOLD ─────────────────────────────────────────────────
SCAFFOLD="${REPORT_DIR}/TECHNICAL_REPORT_SCAFFOLD.md"
cat > "${SCAFFOLD}" <<SCAFFOLD_EOF
# Ha-Shem Limited — VAPT Technical Report
**Classification:** CONFIDENTIAL — Internal Use Only
**Engagement Period:** ${ENGAGEMENT_DATE:-$(date +%Y-%m-%d)} to $(date +%Y-%m-%d)
**Prepared by:** Infrastructure Security Team — HL-VAPT

---

## Executive Summary
> [MANUAL] Replace this section with 2–3 paragraph business-language summary.
> Overall risk rating: [CRITICAL / HIGH / MEDIUM / LOW]
> Top finding in one sentence: [COMPLETE MANUALLY]

---

## Automated Finding Indicators (from scan outputs)

| Category | Count | Evidence File |
|----------|-------|---------------|
| Kerberoast hashes cracked | ${KERB_COUNT} | evidence/cracked/cracked_tgs.txt |
| AS-REP hashes cracked | ${ASREP_COUNT} | evidence/cracked/cracked_asrep.txt |
| NTLMv2 hashes cracked | ${CRACKED_NTLM_COUNT} | evidence/cracked/cracked_ntlm.txt |
| Hosts accessible via PtH | ${PTH_COUNT} | phase3/ad/pth_accessible_hosts.txt |
| Public Azure storage blobs | ${PUBLIC_BLOBS} | evidence/cloud/public_blob_poc.txt |
| Unconstrained delegation hosts | ${UNCON_DELEG} | phase2/ad/ad_checks/unconstrained_delegation.txt |
| Password never expires accounts | ${PNE_COUNT} | phase2/ad/ad_checks/pwd_never_expires.txt |
| AD CS misconfigurations (ESC) | ${ADCS_HITS} | evidence/ad/adcs_find.txt |
| SMB vulnerability hits | ${SMB_VULN_HITS} | evidence/network/smb_vuln_checks.txt |
| Web targets DAST-scanned | ${ZAP_TARGET_COUNT} | evidence/web/zap/<target>/zap_report.html |
| ZAP total alert count | ${ZAP_HIGH_ALERTS} | evidence/web/zap/<target>/zap_report.json |

---

## Findings

> Each finding below needs to be completed manually with: severity, CVSS score,
> affected asset, MITRE mapping, evidence screenshot, business impact, remediation.

### Finding 001 — [TITLE — COMPLETE MANUALLY]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**CVSS 3.1 Score:** [X.X]
**MITRE ATT&CK:** [Txx.xxx — Technique Name]
**Affected Asset(s):** [hostname / IP / resource]

**Evidence:**
\`\`\`
[Paste command output or reference screenshot filename]
\`\`\`

**Business Impact:**
> [MANUAL] What can an attacker achieve? Write in business terms.

**Remediation Steps:**
> [MANUAL] Specific, numbered technical steps for the responsible team.

**Owner:** [Networking / Infrasec / DevSecOps / Cloud Platform]
**References:** [CVE / KB / OWASP / MITRE URL]

---

### Finding 002 — LLMNR/NBT-NS Poisoning — Unauthenticated NTLMv2 Hash Capture
**Severity:** CRITICAL
**CVSS 3.1 Score:** 8.8
**MITRE ATT&CK:** T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay
**Affected Asset(s):** All Windows hosts on internal network segment

**Evidence:**
\`\`\`
[Screenshot reference: evidence/ad/responder_session.log]
[Screenshot: NTLMv2 hash captured for user <username> from host <hostname>]
\`\`\`

**Business Impact:**
> Any host on the internal network segment that uses LLMNR/NBT-NS name resolution
> (default enabled on all Windows systems) will broadcast authentication requests
> that can be intercepted without any credentials, yielding crackable NTLMv2 password
> hashes. Cracked hashes provide plaintext passwords or Pass-the-Hash access.

**Remediation Steps:**
> 1. Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = ENABLED
> 2. Disable NBT-NS: Network adapter properties > TCP/IP > WINS > Disable NetBIOS over TCP/IP
> 3. Enforce SMB Signing domain-wide: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always) = ENABLED
> 4. Deploy Defender for Identity to detect and alert on LLMNR poisoning attempts

**Owner:** Networking / Infrasec
**References:** https://attack.mitre.org/techniques/T1557/001/

---

$(for i in $(seq 3 20); do
    num=$(printf "%03d" "$i")
    echo "### Finding ${num} — [TITLE — COMPLETE MANUALLY]"
    echo "**Severity:** "
    echo "**CVSS 3.1 Score:** "
    echo "**MITRE ATT&CK:** "
    echo "**Affected Asset(s):** "
    echo ""
    echo "**Evidence:**"
    echo "\`\`\`"
    echo "[Reference evidence file]"
    echo "\`\`\`"
    echo ""
    echo "**Business Impact:** > [COMPLETE MANUALLY]"
    echo ""
    echo "**Remediation Steps:** > [COMPLETE MANUALLY]"
    echo ""
    echo "**Owner:** "
    echo "**References:** "
    echo ""
    echo "---"
    echo ""
done)

## MITRE ATT&CK Coverage Matrix

| Technique ID | Tactic | Technique Name | Finding Ref | Severity |
|---|---|---|---|---|
| T1557.001 | Credential Access | LLMNR/NBT-NS Poisoning | Finding 002 | CRITICAL |
| T1558.003 | Credential Access | Kerberoasting | [COMPLETE] | |
| T1558.004 | Credential Access | AS-REP Roasting | [COMPLETE] | |
| T1550.002 | Lateral Movement | Pass-the-Hash | [COMPLETE] | |
| T1003.003 | Credential Access | DCSync | [COMPLETE] | |
| T1526 | Discovery | Cloud Service Discovery | [COMPLETE] | |
| T1530 | Collection | Data from Cloud Storage | [COMPLETE] | |

## Remediation Roadmap

| Timeframe | Priority | Action | Owner |
|-----------|----------|--------|-------|
| 24–48 hrs | CRITICAL | Disable LLMNR + NBT-NS via GPO | Infrasec |
| 24–48 hrs | CRITICAL | Enforce SMB Signing domain-wide | Networking |
| 24–48 hrs | CRITICAL | Disable public Azure storage blobs | Cloud Platform |
| 1 week | HIGH | Reset Kerberoastable service account passwords (25+ chars random) | Infrasec |
| 1 week | HIGH | Disable pre-auth on flagged accounts or rotate passwords | Infrasec |
| 30 days | MEDIUM | Deploy LAPS for local admin randomisation | Infrasec |
| 30 days | MEDIUM | Enforce MFA via Conditional Access on all admin accounts | Cloud Platform |
| 30 days | MEDIUM | Enable Defender for Identity | Infrasec |
| 90 days | LOW | Implement AD tiering model | Infrasec |
| 90 days | LOW | Enable Azure PIM for privileged roles | Cloud Platform |

SCAFFOLD_EOF

log OK "Report scaffold generated → ${SCAFFOLD}"

# ─── EVIDENCE INTEGRITY MANIFEST ─────────────────────────────────────────────
# SHA-256 checksums of all evidence files — proves chain of custody and detects
# accidental modification before the report is delivered.
MANIFEST="${REPORT_DIR}/evidence_manifest.sha256"
log INFO "Generating evidence integrity manifest..."
if command -v sha256sum &>/dev/null; then
    find "${EVIDENCE_DIR}" -type f | sort | xargs sha256sum 2>/dev/null > "${MANIFEST}" || true
    MANIFEST_COUNT=$(wc -l < "${MANIFEST}" 2>/dev/null || echo 0)
    log OK "Evidence manifest: ${MANIFEST_COUNT} files checksummed → ${MANIFEST}"
else
    log WARN "sha256sum not available — evidence integrity manifest skipped"
fi

echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Phase 5 — Evidence Consolidated. Report Scaffold Ready.${RESET}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${RESET}"
echo -e "  Evidence directory:  ${EVIDENCE_DIR}"
echo -e "  Report scaffold:     ${SCAFFOLD}"
echo ""
echo -e "${YELLOW}  Manual steps (all writing is manual — no automation can replace this):${RESET}"
echo -e "    • Complete each Finding 00X section in the scaffold"
echo -e "    • Write the Executive Summary in plain business language"
echo -e "    • Attach screenshot evidence for every finding"
echo -e "    • Have a colleague review the report before delivery"
echo -e "    • Prepare debrief slide deck from top 5 findings"
echo -e "    • Schedule and deliver debrief with Elizabeth A. and Titilope G."
echo ""
log OK "Phase 5 consolidation complete."
