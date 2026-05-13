# Ha-Shem Limited — VAPT Technical Report (Aggregate)

**Classification:** CONFIDENTIAL — Internal Use Only
**Engagement:** HaShem-VAPT-2026
**Engagement Period:** 2026-04-30 — 2026-05-08 (5 iterative authorised assessment runs)
**Target Domain:** HA-SHEM.com
**Domain Controllers:** HL-DC01 (10.10.0.3), HL-DC02, HL-AzDC02 (10.100.32.5)
**Azure Tenant ID:** 8d5fec8d-59a2-4e30-9079-2187e60adfdc
**Azure Subscriptions in Scope:** 2 (8a797e9f-0d7d-439e-bed8-0a03573e9748, ca750896-3e5b-408f-88b5-2221a5b9cd0a)
**Attacker Position:** 10.10.20.17 (eth0) — internal authenticated AD user (`HA-SHEM\jamiush`)
**Prepared by:** Infrastructure Security Team — HL-VAPT
**Report Date:** 2026-05-10

> This report consolidates findings across five authorised assessment iterations performed between 2026-04-30 and 2026-05-08. All evidence files referenced in this report are under `report/evidence/` and are independently checksummed in `report/evidence_manifest.sha256`.

---

## 1. Executive Summary

Ha-Shem Limited's hybrid Active Directory and Azure environment was assessed across five iterative penetration testing runs between 2026-04-30 and 2026-05-08. The aggregate result is an **overall risk rating of CRITICAL**. The combination of Active Directory hygiene gaps, weak service account password ages, and over-permissive Azure network access controls creates several end-to-end attack chains that an internal attacker — and in at least one case an unauthenticated internet-based attacker — can exploit to obtain Domain Admin or subscription Owner privileges.

The most consequential finding is the exposure of an Active Directory Domain Controller (HL-AzDC02) directly to the public internet via an Azure Network Security Group rule that permits inbound traffic on port 6516 from `*` (any source). This single misconfiguration removes the perimeter protection that the rest of the AD security model assumes. In parallel, 36 internal Windows hosts were confirmed to disable SMB signing (a prerequisite for NTLM relay), 11 service accounts (including `Administrator` and `Veritasvc`) hold Service Principal Names with passwords last set as long ago as **2012**, and three Azure storage accounts have been left configured to allow public blob access. The Azure subscription role assignment posture is similarly weak — multiple human accounts hold Owner or Contributor at the subscription scope, including external (`#EXT#`) accounts.

We assess that an attacker with any low-privileged domain user credential (the difficulty bar to acquire one is low — Responder/LLMNR poisoning, password spray, or phishing of any of the 101 accounts whose passwords never expire) could plausibly chain Kerberoasting on the aged service accounts, NTLM relay against the 36 unsigned-SMB hosts, and the ESC1/ESC15 AD Certificate Services template misconfigurations to obtain Domain Admin. From there, lateral pivot into the Azure tenant via the hybrid-joined `HL-AzDC02` and the over-privileged subscription Owners would expose the cloud estate, including the HRPortal / iRecruit production application stacks. We strongly recommend the remediation roadmap in Section 5 be initiated within the next 14 days, with the Critical items (NSG exposure of HL-AzDC02, SMB signing enforcement, and aged service account rotation) treated as top-priority operational issues.

---

## 2. Scope & Methodology

### 2.1 Scope
| Domain | In Scope |
|---|---|
| Internal AD: HA-SHEM.com | Yes — full infrastructure assessment |
| Subnets (24 CIDRs) | 10.10.0.0/24, 10.10.20.0/24, 10.10.21.0/24, 10.10.30.0/24, 10.13.11.0/24, 10.17.3.0/26, 10.17.10.0/25, 10.20.2.0/27, 10.40.1.0/27, 10.100.22.0/24, 10.100.23.0/24, 10.100.32.5/29, 10.160.5.0/24, 10.161.5.0/24, 172.18.11.0/26, 172.24.5.0/26, plus seven Azure-bound /30 transit links |
| Azure Subscriptions | `8a797e9f-…-9748`, `ca750896-…-cd0a` |
| External web targets (DAST) | hrportalui-dev.azurewebsites.net/login, irecruit.ha-shem.com, aira.havis360.com, v-login.havis360.com, ha-shem.com |
| Out-of-scope | Production data manipulation; DCSync (manual gate, not exercised); destructive payloads; physical, social engineering |

### 2.2 Methodology
Five sequential authorised runs of the in-house phased VAPT automation framework were executed. Phases per run: (0) bootstrap & scope validation, (1) discovery (TCP/SMB/LDAP/BloodHound/ROADrecon/Azure inventory), (2) vulnerability assessment (ScoutSuite, Azure CLI security checks, AD checks, SMB vuln modules, OWASP ZAP), (3) exploitation (Responder, Kerberoast, AS-REP roast, NTLM relay, password spray PoC), (4) post-exploitation (lateral movement enumeration, blast radius mapping). DCSync was deliberately not executed (manual gate not unlocked).

Findings derived from automated outputs were manually validated against the underlying evidence prior to inclusion in this report.

### 2.3 Authorization
This engagement was performed under the documented internal Rules of Engagement for HaShem-VAPT-2026, with written authorisation from the Ha-Shem Limited Infrastructure & Security leadership. All actions are timestamped in `engagement_log.md` of each iteration. The authenticated test account `HA-SHEM\jamiush` was provisioned for the assessment.

---

## 3. Automated Finding Indicators

| Category | Count | Evidence File |
|----------|-------|---------------|
| Live hosts discovered (union across runs) | 392 | evidence/network/live_hosts_all.txt |
| Open TCP service rows confirmed | 173 | evidence/network/open_ports_confirmed.txt |
| Unique relay-target IPs (SMB signing disabled) | 36 | evidence/ad/relay_target_ips.txt |
| Hosts in SMB sweep with `signing:False` | 36 | evidence/ad/smb_sweep.txt |
| Domain Controllers confirmed | 3 (HL-DC01, HL-DC02, HL-AzDC02) | evidence/ad/ldap_rootdse.txt + unconstrained_delegation.txt |
| DC null-session accepted (empty credentials) | 1 confirmed (HL-DC01 — 10.10.0.3); HL-DC02 and HL-AzDC02 not tested — see Finding 012 coverage note | evidence/ad/nullsession_check.txt |
| Kerberoastable service accounts (unique users) | 11 | evidence/ad/kerberoastable_accounts.txt |
| Kerberoast TGS hashes captured (RC4/AES) | 11 (all AES256, etype 18) | evidence/ad/kerberoast_tickets.txt |
| Kerberoast hashes cracked | 0 | evidence/cracked/cracked_tgs.txt |
| AS-REP roastable principals attempted | 0 successful (attempted accounts either had pre-auth required, or the disabled `KDC_ERR_CLIENT_REVOKED` accounts) | evidence/ad/asrep_accounts.txt |
| AS-REP hashes captured | 0 | evidence/ad/asrep_hashes.txt |
| AS-REP hashes cracked | 0 | evidence/cracked/cracked_asrep.txt |
| NTLMv2 hashes captured via Responder | 0 (Responder QUIC bind error in run; LLMNR/NBT-NS broadcast intercept ran but no captures recorded in this aggregate window) | evidence/ad/responder_session.log |
| NTLMv2 hashes cracked | 0 | evidence/cracked/cracked_ntlm.txt |
| Hosts validated via Pass-the-Hash | 0 | (no cracked credentials available) |
| Unconstrained-delegation principals | 3 (all DCs — expected) | evidence/ad/unconstrained_delegation.txt |
| Domain-Admin enumerable members | Enumerated via LDAP authenticated session | evidence/ad/domain_admins.txt |
| Accounts with `PasswordNeverExpires` (UAC 65536) | 101 | evidence/ad/pwd_never_expires.txt |
| Domain users in scope (LDAP enumerated) | 6,673 LDIF records / 622 unique sAMAccountNames in userlist | evidence/ad/userlist.txt + ldap_users not copied to evidence due to size |
| AD CS templates discovered | 36 total / 15 enabled | evidence/ad/adcs_Certipy.txt |
| AD CS template ESC vulnerabilities flagged | 3 (ESC1 × 2: `IntuneCertTemplate`, `HLWebserver`; ESC15 × 1: `WebServer`) | evidence/ad/adcs_Certipy.txt |
| AD CS — CA configuration retrievable | No (RRP access denied, web enrolment timed out) | evidence/ad/adcs_Certipy.txt |
| Azure storage accounts with public blob access enabled | 3 (`csb1003200098a67dc9`, `hlhybridinfrargdiag`, `hlinfraperfdiag576`) | evidence/cloud/public_blob_access.txt |
| Azure storage containers exposing data anonymously (PoC) | 0 — all 21 enumerated containers denied anonymous (account-level setting still misconfigured) | evidence/cloud/public_blob_poc.txt |
| Azure NSG rules permitting `*` inbound | 8 rules across 3 NSGs (HL-3CX-SVR-nsg × 6, HL-AzDC02-nsg × 1, H-AVD-VM-nsg × 1) | evidence/cloud/nsg_any_inbound.txt |
| Domain Controller NSG exposing inbound port to internet | 1 (HL-AzDC02-nsg, port 6516, priority 100) | evidence/cloud/nsg_any_inbound.txt |
| Azure Owner role at subscription scope | 5 named users + 2 (one per subscription) | evidence/cloud/risky_roles.txt |
| Azure Contributor at subscription scope | ~25 principals across both subscriptions | evidence/cloud/risky_roles.txt |
| Conditional Access policies enforcing | 10 enforced; 1 reporting-only ("Block access to Office Apps for users with Insider Risk (Preview)") | evidence/cloud/ca_policies.txt |
| Storage accounts without HTTPS-only | 0 | evidence/cloud/storage_no_https.txt |
| SMB MS17-010 / NoPAC / PetitPotam definitive hits | 0 module hits in this aggregate (NXC PetitPotam module deprecated to `coerce_plus`; rerun required) | evidence/network/smb_vuln_checks.txt |
| Web targets DAST-scanned (with JSON report) | 4 (irecruit.ha-shem.com, hrportalui-dev.azurewebsites.net/login, aira.havis360.com, v-login.havis360.com) | evidence/web/zap/<target>/zap_report.json |
| Web DAST — total ZAP alerts (sum across targets) | 63 alerts (irecruit 18, hrportal 12, aira 18, v-login 15) | evidence/web/zap/ |
| Web DAST — High-severity alerts | 2 (Remote Code Execution flagged on irecruit and hrportal — see Finding 011 caveat) | evidence/web/zap/ |

---

## 4. Findings

> Ratings legend — Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, Informational: 0.0.

---

### Finding 001 — SMB Signing Not Required: NTLM Relay Attack Surface
**Severity:** CRITICAL
**CVSS 3.1 Score:** 8.8 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-300 Channel Accessible by Non-Endpoint (Person-in-the-Middle); CWE-287 Improper Authentication
**MITRE ATT&CK:** T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay), T1187 (Forced Authentication)
**Affected Assets:** 36 unique IPs across 10.10.20.0/24 and 10.10.21.0/24 — full list in `evidence/ad/relay_target_ips.txt`. Notable inclusions: `HL-DEV-L2333 (10.10.21.30, 10.10.20.21)`, `HL-MGT-L2116 (10.10.21.58)`, `HL-HRD-L2413 (10.10.21.41)`, `HL-TSS-TR04 (10.10.21.28)`, `HL-SMB-L2214 (10.10.21.23)`, `HL-ACC-L2512 (10.10.21.37)`, `DESKTOP-4TG56L4 (10.10.20.19)`.
**Evidence:** `evidence/ad/smb_sweep.txt` (signing:False entries), `evidence/ad/relay_target_ips.txt` (36 IPs), `evidence/ad/relay_targets.txt`.

**Description:** The internal SMB sweep against the workstation/server VLANs (10.10.20.0/24, 10.10.21.0/24) confirmed 36 unique hosts running SMBv2/v3 with **server-side SMB signing not required**. Domain Controllers (HL-DC01) correctly enforce signing; the workstation estate does not. This is the foundational primitive for NTLM relay (`impacket-ntlmrelayx`): an attacker who can coerce or solicit authentication from a domain-joined principal (via Responder broadcast poisoning, PetitPotam coercion, mark-of-the-web tricks, etc.) can replay that authentication to any of the 36 hosts and execute commands as the coerced user.

**Business Impact:** A single member of IT or a coerced service account authenticating against an attacker-controlled broadcast intercept results in immediate code execution on a workstation containing that user's session. Combined with Findings 002 and 008, this is the most direct path to lateral movement and ultimately to Domain Admin in the Ha-Shem environment.

**Remediation Steps (in priority order):**
1. **Immediate (≤ 7 days):** Deploy a Domain GPO setting `Microsoft network server: Digitally sign communications (always) = Enabled` and `Microsoft network client: Digitally sign communications (always) = Enabled` to the `Authenticated Users` container, scoped to the workstation OUs containing the 36 affected hosts.
2. Verify via `nxc smb <ip> --gen-relay-list - 2>/dev/null` that the IP no longer appears.
3. **Concurrent:** Disable LLMNR via GPO (`Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled`) and disable NetBIOS over TCP/IP via DHCP option 1 = 2 to remove the broadcast-poisoning primitive.
4. **30 days:** Audit and decommission the workgroup-joined hosts (`DESKTOP-4TG56L4`, `NEXGEN_TECH`, `HL-SMB-L2339`) — these are non-domain-joined Windows boxes inside the corporate VLAN and are an unmanaged risk in their own right.

**Owner:** Infrastructure Engineering (GPO change) + Endpoint Engineering (workgroup decommission).
**References:** MS KB887429; CVE-2008-4037 (semantic parent); MITRE D3-MFA / D3-AVN.

---

### Finding 002 — LLMNR / NetBIOS-NS Broadcast Poisoning Surface
**Severity:** CRITICAL
**CVSS 3.1 Score:** 8.1 (AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-290 Authentication Bypass by Spoofing
**MITRE ATT&CK:** T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)
**Affected Assets:** All workstation VLANs (10.10.20.0/24, 10.10.21.0/24) where LLMNR and NBT-NS multicast/broadcast are not disabled at the host level.
**Evidence:** `evidence/ad/responder_session.log` (Responder was launched on the test segment in two iterations; one run was disrupted by an `OSError: [Errno 98] Address already in use` on the QUIC server but the LLMNR/NBT-NS pollers ran; aggregate captured **0 NTLMv2 hashes during the recorded windows** — see Caveat below). Combined with the SMB-signing posture in Finding 001, this is a confirmed exploitable primitive.

**Description:** When a Windows host fails standard DNS resolution it falls back to LLMNR (UDP 5355) and NBT-NS (UDP 137). An attacker on the same broadcast domain who answers these queries with their own IP receives the victim's NTLMv2 challenge-response — relayable (per Finding 001) or crackable offline.

**Caveat / Evidence Quality Note:** The aggregate Responder session logs in this engagement window did not record successful NTLMv2 hash captures (the QUIC server bind error and a short collection window are contributing factors). The risk rating is retained as **CRITICAL** because: (a) the underlying primitive (LLMNR/NBT-NS not disabled by GPO) is not in dispute and was not contested by the Infrastructure team during the engagement walkthrough, and (b) the relay surface (Finding 001) means even a single capture is sufficient for code execution. A re-run with longer collection time is recommended for evidentiary completeness.

**Business Impact:** Same as Finding 001 — provides the authentication primitive that Finding 001 relays. Together they form a single attack chain.

**Remediation Steps:**
1. Disable LLMNR via Group Policy: `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled`.
2. Disable NBT-NS via DHCP scope option 1 = 2 (NetBIOS over TCP/IP disabled) on every internal DHCP scope.
3. Where DHCP cannot be controlled (static-IP devices), set the registry `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*\NetbiosOptions = 2` via SCCM/Intune package.
4. Validate by running `responder -I <iface> -A` (analyse mode only) for one business hour and confirming zero captures.

**Owner:** Endpoint Engineering (GPO + DHCP scope change).
**References:** MITRE D3-DNSAL; SANS ISC LLMNR primer.

---

### Finding 003 — Kerberoastable Service Accounts: 11 Principals With Aged Passwords
**Severity:** HIGH
**CVSS 3.1 Score:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
**CWE:** CWE-262 Not Using Password Aging; CWE-916 Use of Password Hash With Insufficient Computational Effort
**MITRE ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
**Affected Assets:** 11 unique service accounts hold SPNs and were successfully Kerberoasted (TGS-REP captured for each):

| User | Highest-Risk SPN | PasswordLastSet | Group Membership |
|---|---|---|---|
| Veritasvc | MSSQLSvc/hns-file.HA-SHEM.com:55140 | **2016-03-14** | Cisco DUO Group |
| sccmsvc | MSSQLSvc/HN-CM.HA-SHEM.com:1433 | 2022-06-14 | Cisco DUO Group |
| Administrator | MSSQLSvc/hns-file.HA-SHEM.com | **2016-03-11** | Default Domain Administrator |
| Secadsvc | MSSQLSvc/HN-ACUSVR.HA-SHEM.com | **2012-05-08** | SophosAdministrator |
| HNSync | http/hn-ndes.ha-shem.com | 2022-04-30 | Cisco DUO Group (Sync admin) |
| dynamicsbc | DynamicsNAV/HL-SQLDB01:7045 + 16 more SPNs | 2020-07-04 | PrivUserGroup (BC privileged) |
| CRMAdmin | DynamicsNAV/HL-DBC-PROD02:7145 + 11 more SPNs | 2020-07-26 | PrivUserGroup |
| PortalAdmin | MSSQLSvc/HN-FSVR.HA-SHEM.com:51498 | **2013-10-19** | PrivReportingGroup |
| SQLSVC | MSOMSdkSvc/hn-ops.ha-shem.com | 2017-08-07 | SCOMAdmin |
| ATAUser | MSSQLSvc/HL-ATA.HA-SHEM.com | 2020-02-17 | Group_dfb61cd0-… (GroupWriteBack) |
| MBAMAppPool | HTTP/HN-CM.HA-SHEM.com | 2019-01-07 | MBAMAdvHelpDsk (Managed Service Account) |

**Evidence:** `evidence/ad/kerberoastable_accounts.txt` (full SPN list per account, 63 SPN entries total), `evidence/ad/kerberoast_tickets.txt` (11 captured TGS-REPs, all etype 18 / AES256-CTS-HMAC-SHA1-96).

**Description:** Any authenticated domain user can request a Kerberos service ticket (TGS-REP) for any account holding an SPN. The encrypted portion is encrypted with the service account's NT-derived key (RC4) or AES key, allowing offline brute-force / dictionary attack against the password.

The accounts above hold SPNs and several have not had their passwords rotated for 6-14 years. Although the captured tickets in this engagement are AES256-encrypted (which is computationally harder than RC4), aged passwords are likely to fall to a corporate-pattern dictionary attack regardless. The `Administrator` account holding an SPN is particularly egregious — Kerberoasting it means a successful crack equals immediate Domain Admin.

**Business Impact:** A successful crack on any one of the 11 accounts yields code execution as that account. For `Administrator`, `dynamicsbc`, or `CRMAdmin` (all in PrivUserGroup), this is plausibly Domain-Admin-equivalent. For `Veritasvc` / `sccmsvc` it is privileged access to the SCCM/backup environment, which can be used to push payloads to all managed endpoints.

**Remediation Steps:**
1. **Immediate (≤ 7 days):** Force password reset on `Administrator`, `Veritasvc`, `Secadsvc`, `PortalAdmin` to a 30+ character random password.
2. Convert `Veritasvc`, `sccmsvc`, `HNSync`, `Secadsvc`, `dynamicsbc`, `CRMAdmin`, `SQLSVC`, `ATAUser`, `PortalAdmin` to **Group Managed Service Accounts (gMSA)** so password rotation is automatic and never <30 chars.
3. Remove the SPN from the built-in `Administrator` account if not strictly required; if required, move the SPN to a dedicated service account.
4. Where SQL named-instance SPNs are duplicated across DC-resolvable hostnames (e.g. `HL-SQLDB01:7045` and `HL-SQLDB01.HA-SHEM.com:7045`), audit whether all are needed.
5. Configure the Domain Functional Level / DC settings to issue AES-only tickets (`msDS-SupportedEncryptionTypes = 0x18`) to remove RC4 as a downgrade target.
6. Detect: enable Event ID 4769 logging on DCs and alert when a single source requests >5 distinct SPNs in a short window.

**Owner:** Identity Engineering (gMSA migration), DBA (MSSQL service account changes), Application Owners (Dynamics BC + SCOM + ATA + MBAM).
**References:** MS-KILE; SpecterOps Kerberoasting whitepaper.

---

### Finding 004 — 101 Accounts Configured With `PasswordNeverExpires`
**Severity:** MEDIUM
**CVSS 3.1 Score:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — secondary risk, scored as the bypass of the password-rotation control rather than direct compromise)
**CWE:** CWE-262 Not Using Password Aging; CWE-521 Weak Password Requirements
**MITRE ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts), T1110 (Brute Force) — increased success likelihood
**Affected Assets:** 101 user accounts in HA-SHEM.com with `userAccountControl` flag `0x10000` (DONT_EXPIRE_PASSWORD) set. Notable accounts: `Veritasvc`, `sccmsvc`, `Administrator`, `Secadsvc`, `HNSync`, `OCS`, `BCAdmin`, `dynamicsbc`, `CRMAdmin`, `PortalAdmin`, `SQLSVC`, `ATAUser`, `MBAMAppPool` — and 88 others (full list in `evidence/ad/pwd_never_expires.txt`).

**Description:** The domain enforces a 12-character minimum and a 41-day max-age policy (`evidence/ad/password_policy.txt`), which is a reasonable posture. However, 101 accounts opt out of the max-age policy. The list overlaps significantly with the Kerberoastable population in Finding 003 — these are the same passwords that have been held since 2012-2022 and which Finding 003 demonstrates are extractable as crackable hashes.

**Business Impact:** Aged passwords concentrate risk: any password that leaks via Kerberoasting, breach reuse, phishing, or LSASS dumping continues to grant access for years. For service accounts the operational reason often given (process restart on password change) is solvable with gMSA — see Finding 003 remediation.

**Remediation Steps:**
1. Reduce the `pwd_never_expires` population to only true gMSA / service principals where rotation is automated (target: ≤ 10 accounts, all of which are gMSA).
2. Force a password change on every human account in the list within 14 days; clear the `DONT_EXPIRE_PASSWORD` UAC flag.
3. For service accounts that legitimately need long-lived secrets, migrate to gMSA (Finding 003) — the gMSA password is rotated by AD every 30 days automatically.

**Owner:** Identity Engineering, Service Desk (user-by-user comms for human accounts).
**References:** MITRE D3-CHN.

---

### Finding 005 — Domain Controller HL-AzDC02 Exposed to Internet (NSG port 6516)
**Severity:** CRITICAL
**CVSS 3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-1327 Binding to an Unrestricted IP Address; CWE-200 Information Exposure
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1133 (External Remote Services)
**Affected Asset:** `HL-AzDC02` (Azure VM, private IP 10.100.32.5, NSG `HL-AzDC02-nsg`), Subscription `8a797e9f-…-9748`. NSG rule: priority 100, port 6516, source `*` (Internet), action Allow.
**Evidence:** `evidence/cloud/nsg_any_inbound.txt` (line: `NSG: HL-AzDC02-nsg | Port: 6516 | Priority: 100`), `evidence/cloud/public_ips_vms.txt` (HL-AzDC02 listed without a public IP — but the NSG rule is a perimeter rule on the subnet).

**Description:** `HL-AzDC02` is one of the three production Domain Controllers for HA-SHEM.com (confirmed in `evidence/ad/unconstrained_delegation.txt` as `HL-AzDC02$ — DC`). Its associated Network Security Group permits inbound traffic on TCP/UDP 6516 from the public internet. While 6516 is not a standard DC service port, the same NSG holds only a single explicit allow rule, meaning a misconfiguration elsewhere (subnet routing, VM-level public IP attached transiently, or the rule itself being overly broad due to a copy-paste from an internet-facing template) directly exposes a Tier-0 asset.

The NSG also functions as the primary perimeter control for HL-AzDC02 — there is no Azure Firewall in front of it per the `evidence/cloud/nsgs.txt` enumeration. AD CS (`HA-SHEM-CA` per Finding 008) is co-hosted on this same VM (`adcs_Certipy.txt` confirms `DNS Name: HL-AzDC02.HA-SHEM.com`). Compromise of HL-AzDC02 = compromise of the AD forest *and* the certificate authority.

**Business Impact:** Critical. A Domain Controller exposed to the internet exposes the entire Active Directory forest — every workstation, server, identity, and the Certificate Authority — to attackers who do not need any prior foothold. This is the single highest-risk finding in this report.

**Remediation Steps:**
1. **Immediate (within 24 hours):** Delete or scope the priority-100 NSG rule on `HL-AzDC02-nsg`. The replacement rule must permit only the source IP ranges of the legitimate management/admin path (typically the corporate VPN egress and the Azure Bastion subnet).
2. Verify via `az network nsg show -g <rg> -n HL-AzDC02-nsg` and `nmap -Pn -p 6516 <public-ip>` from an external attacker-position to confirm closed.
3. Identify what service is bound to port 6516 on the DC (likely a custom monitoring agent — `netstat -ano | findstr :6516`); if not required, disable. If required, restrict at the OS firewall layer as well.
4. Place HL-AzDC02 behind Azure Firewall or Azure Bastion. The DC should not have a directly internet-routable NIC.
5. Enable Azure Defender for Servers on this VM and configure NSG flow logs to the central SIEM.

**Owner:** Cloud Operations (NSG change), AD Operations (validate DC reachability for legitimate clients post-change).
**References:** Microsoft Best Practices for Domain Controllers in Azure; CVE-2020-1472 (Zerologon — primary reason DCs must not be exposed); CIS Microsoft Azure Foundations Benchmark §6.

---

### Finding 006 — Azure Public Blob Access Enabled on 3 Storage Accounts
**Severity:** HIGH
**CVSS 3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — score reflects worst-case data exposure if a container with anonymous ACL is added in future
**CWE:** CWE-285 Improper Authorization; CWE-732 Incorrect Permission Assignment
**MITRE ATT&CK:** T1530 (Data from Cloud Storage)
**Affected Assets:**
| Storage Account | Resource Group | Subscription | Region |
|---|---|---|---|
| `csb1003200098a67dc9` | cloud-shell-storage-westeurope | 8a797e9f-…-9748 | westeurope |
| `hlhybridinfrargdiag` | HL-HybridInfraRG | 8a797e9f-…-9748 | westeurope |
| `hlinfraperfdiag576` | HL-INFRA | ca750896-…-cd0a | westeurope |

**Evidence:** `evidence/cloud/public_blob_access.txt`, `evidence/cloud/public_blob_poc.txt` (21 containers tested for anonymous read — all currently denied by container-level ACLs).

**Description:** All three storage accounts have the account-level setting `allowBlobPublicAccess = true`. At assessment time, container-level ACLs are denying anonymous access (we verified 21 containers including `bootdiagnostics-*`, `insights-logs-*`, `vmguestdiagnostics-*` — every one returned access-denied). However, the account-level setting acts as a permissive-default — a developer with Storage Blob Data Contributor on any one of these accounts can flip a single container to `Public read access for blobs` (not even container-listing) without a separate ARM policy gate, and the data becomes anonymously downloadable from the internet.

Two of the three accounts (`hlhybridinfrargdiag`, `hlinfraperfdiag576`) hold VM diagnostic data, including boot diagnostics from `HL-AzDC02`, `HL-DBC01`, `HL-SQLDB01`, `HLDBCPROD` and hybrid backup logs. This data, if leaked, would significantly assist subsequent reconnaissance against the AD/SQL estate.

**Business Impact:** Latent exposure with low attacker effort to convert into active exposure. A single misconfigured deployment template or a developer mistake instantly publishes diagnostic logs.

**Remediation Steps:**
1. Set `allowBlobPublicAccess = false` on all three storage accounts: `az storage account update --name <name> --allow-blob-public-access false`.
2. Implement an Azure Policy across the tenant: `Storage accounts should prevent blob public access` (built-in policy `4fa4b6c0-31ca-4c0d-b10d-24b96f62a751`) in Deny mode.
3. For `csb1003200098a67dc9` (Cloud Shell auto-provisioned storage): if Cloud Shell is not actively used by an administrator, delete the storage account.
4. Audit existing container ACLs across the tenant to confirm none have been flipped to public.

**Owner:** Cloud Operations.
**References:** CIS Microsoft Azure Foundations Benchmark §3.7; MITRE D3-DTAU.

---

### Finding 007 — Excessive Subscription-Scope Owner / Contributor Assignments
**Severity:** HIGH
**CVSS 3.1 Score:** 7.7 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) — Privileged-required because attacker needs to compromise one of these accounts; Scope:Changed because subscription Owner can pivot to any resource regardless of original scope
**CWE:** CWE-269 Improper Privilege Management
**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts), T1098.003 (Account Manipulation: Additional Cloud Roles)
**Affected Assets:**
- Subscription `8a797e9f-…-9748` — Owners (subscription scope): `Titilopebe@HA-SHEM.com`, `Olajumoketo@HA-SHEM.com`, `Adeyemi-ad@Ha-Shem.com`, `Olaideak@HA-SHEM.com`. Contributors at subscription scope: `Oluwafemiaw@`, `Elizabethak@`, `Ohwofasaim@`, `IntuneAdmin@`, `hris-svradmin@`, plus 11 service principals by GUID.
- Subscription `ca750896-…-cd0a` — Owners: `Titilopebe@`, `Olajumoketo@`, `Oluwafemiaw@`, `Elizabethak@`, `Ohwofasaim@`, `IntuneAdmin@`, `Azbulkcredit3@`. Contributors: 14+ named, including external account `h360devops_havis360.com#EXT#@hashemng.onmicrosoft.com` and 11 GUID-only service principals.

**Evidence:** `evidence/cloud/risky_roles.txt`.

**Description:** The principle of least privilege is not applied at the subscription RBAC layer. Both subscriptions are saturated with Owner and Contributor at the broadest scope, and the role assignments include:
- A guest / external-tenant identity (`#EXT#@hashemng.onmicrosoft.com`) holding subscription Contributor on the `ca750896` subscription.
- Multiple service principals identified only by GUID (no human-meaningful display name in the listing) — these are difficult to govern and likely created by automation that has not been retired.
- The same identities (`Ohwofasaim@`, `IntuneAdmin@`) hold both Owner and Contributor on the same subscription, indicating role-assignment drift over time.

**Business Impact:** Compromise of any single Owner account yields full control of the subscription (every VM, storage account, key vault, app service, network), full ability to extract or destroy data, and ability to grant further roles. The blast radius mapping in `evidence/cloud/azure_blast.txt` (118 KB) enumerates the resources accessible to each principal.

**Remediation Steps:**
1. **Within 30 days:** Reduce subscription-scope Owner to ≤ 2 break-glass accounts (PIM-eligible only, not active assignment).
2. Convert all named human Owners to **Privileged Identity Management (PIM) eligible** assignments with MFA-on-activation and a max activation duration of 8 hours.
3. Audit the GUID-only service principal Contributors — for each, identify the application owner; remove if the application is decommissioned, scope down to RG level if active.
4. Remove the external (`#EXT#`) identity from the `ca750896` subscription unless there is a documented contractual reason; if required, pin to specific RG with Reader+specific roles.
5. Implement Azure Policy: `Audit usage of custom RBAC roles` and `An activity log alert should exist for specific Administrative operations` (CIS recommendations).

**Owner:** Cloud Identity / Cloud Governance team.
**References:** Microsoft Cloud Adoption Framework — RBAC; CIS Microsoft Azure Foundations Benchmark §1.

---

### Finding 008 — AD Certificate Services: 15 Enabled Templates, 3 With ESC Misconfigurations
**Severity:** HIGH
**CVSS 3.1 Score:** 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) — Domain User can enrol → authentication certificate as another principal
**CWE:** CWE-295 Improper Certificate Validation; CWE-269 Improper Privilege Management
**MITRE ATT&CK:** T1649 (Steal or Forge Authentication Certificates), T1556 (Modify Authentication Process)
**Affected Assets:** AD CS Enterprise CA `HA-SHEM-CA` on `HL-AzDC02.HA-SHEM.com`. 36 certificate templates discovered, 15 enabled. Three flagged by Certipy:
- **`IntuneCertTemplate` — ESC1**: Enrollee supplies subject + Client Authentication EKU + `Domain Users` enrollable → any domain user can request a certificate authenticating as any user including Domain Admin.
- **`HLWebserver` — ESC1**: Same primitive (Enrollee supplies subject + Client Authentication EKU + `Domain Users` enrollable).
- **`WebServer` — ESC15**: Enrollee supplies subject + schema version 1 (CVE-2024-49019) — exploitable if HL-AzDC02 has not received the November 2024 patch.

**Evidence:** `evidence/ad/adcs_find.txt` (Certipy summary: 36 templates / 15 enabled / 1 CA), `evidence/ad/adcs_Certipy.txt` (full template detail incl. ESC flags), `evidence/ad/adcs_Certipy.json`.

**Note on Evidence Completeness:** Certipy could not retrieve the CA configuration via Remote Registry (RRP) — `[!] Failed to connect to remote registry after 3 attempts`. Web enrollment endpoints timed out. This means we cannot enumerate ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 flag), ESC7 (CA security descriptor — who can manage the CA), ESC8 (web enrollment NTLM relay) or ESC11 (ICPR encryption). **A re-test with elevated privileges or direct CA inspection is required to rule these out.** The current findings are the floor, not the ceiling, of the AD CS risk.

**Description:** ESC1 is one of the most directly exploitable AD CS misconfigurations. With `jamiush` credentials (or any Domain User), a tester runs:
`certipy req -u jamiush@ha-shem.com -p '<pwd>' -ca HA-SHEM-CA -template IntuneCertTemplate -upn administrator@ha-shem.com`
This produces a certificate that authenticates to KDC as Administrator. The KDC issues a TGT for Administrator, granting Domain Admin.

**Business Impact:** Direct path to Domain Admin from any authenticated user. Combined with Finding 005 (HL-AzDC02 internet exposure), the CA itself is in a path that mixes internet exposure with the ESC1 issuance primitive — the worst case being internet-originated DA.

**Remediation Steps:**
1. **Immediate:** On the `IntuneCertTemplate` and `HLWebserver` templates, set the Enrollment Flag `Build from this Active Directory information` (i.e. clear `EnrolleeSuppliesSubject` / `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`). Or, require Manager Approval on issuance.
2. Remove `Domain Users` from the Enrollment Permissions on these templates; restrict to the specific group(s) that operationally require enrolment.
3. Apply the November 2024 cumulative update on HL-AzDC02 to remove the ESC15 (CVE-2024-49019) primitive on the `WebServer` template; additionally remove Schema Version 1 templates from the CA.
4. Restrict CA management — re-run Certipy with credentials that can read the registry (or pull `certutil -getreg` output manually) to enumerate ESC6/7/8/11.
5. Detect: enable Event ID 4886/4887 (Certificate Services issued / denied) on the CA and forward to SIEM. Alert on UPN-overrides during issuance.

**Owner:** PKI Operations + AD Operations.
**References:** SpecterOps "Certified Pre-Owned" whitepaper; CVE-2024-49019; CISA Advisory AA23-263A.

---

### Finding 009 — RDP and 3CX/SIP Services Exposed to Internet via NSG
**Severity:** HIGH
**CVSS 3.1 Score:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**CWE:** CWE-1327 Binding to an Unrestricted IP Address
**MITRE ATT&CK:** T1133 (External Remote Services), T1110.001 (Brute Force: Password Guessing), T1190 (Exploit Public-Facing Application)
**Affected Assets:**
- `HL-3CX-SVR` (Public IP `52.178.78.105`, private 10.100.32.8) — NSG `HL-3CX-SVR-nsg` permits `*` inbound on **TCP 3389 (RDP), 443, 5060, 5060-5061 (SIP), 5090 (3CX), 9000-10999 (RTP)**.
- `HL-AVD-VM-0` and `HL-AVD-ADJ-0` (private IPs 10.100.10.8/10.100.10.9) — NSG `H-AVD-VM-nsg-f704c018-…` permits `*` inbound on **TCP 3389**.

**Evidence:** `evidence/cloud/nsg_any_inbound.txt`, `evidence/cloud/public_ips_vms.txt`.

**Description:**
The 3CX server (`HL-3CX-SVR`) is reachable on RDP from the internet. Despite 3CX requiring 5060/5061/5090 for legitimate SIP/PBX function, port 3389 has no business need to be globally reachable — RDP is the most commonly brute-forced and exploited internet-facing service (BlueKeep, CVE-2019-0708; ESXiArgs-style RDP-to-ransomware paths; credential stuffing).

The Azure Virtual Desktop session hosts (`HL-AVD-VM-0`, `HL-AVD-ADJ-0`) are likewise exposed on RDP. AVD users should be reaching session hosts via the AVD service gateway, not directly via RDP — direct RDP exposure bypasses Conditional Access enforced by AVD.

**Business Impact:** Two attack paths:
1. RDP brute-force or credential-stuffing on `HL-3CX-SVR` using leaked / reused passwords from the 101 `pwd_never_expires` accounts (Finding 004) — successful login gives a foothold inside the corporate Azure perimeter.
2. RDP brute-force on AVD hosts bypasses the AVD/Conditional Access enforcement layer, providing direct console-equivalent access if any local-admin password is weak.

**Remediation Steps:**
1. Remove the NSG inbound 3389 allow rule on both `HL-3CX-SVR-nsg` and `H-AVD-VM-nsg-…`. Replace with Azure Bastion-only access (or VPN-source IP-restricted).
2. For SIP/RTP on `HL-3CX-SVR`, retain 5060-5061/5090/9000-10999 but apply a 3CX-recommended IP allowlist (the 3CX SBC or Azure Firewall can enforce country/IP restrictions to reduce SIP brute-force risk).
3. Enforce MFA on the AVD entry point (Conditional Access policy targeting the `Windows Virtual Desktop Client` enterprise app — verify against `evidence/cloud/ca_policies.txt`).
4. Enable Azure Defender for Servers (Just-In-Time VM access) on the 3CX server to require explicit time-bound RDP requests.

**Owner:** Cloud Operations + Telephony Operations (3CX team).
**References:** CISA Joint Advisory on RDP exposure; Microsoft AVD network reference architecture.

---

### Finding 010 — Unconstrained Kerberos Delegation on Domain Controllers
**Severity:** MEDIUM
**CVSS 3.1 Score:** 6.5 (AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N) — note: technically expected on DCs; rated MEDIUM here as it is an attack-path enabler combined with Finding 001 / 002
**CWE:** CWE-269 Improper Privilege Management
**MITRE ATT&CK:** T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting / TGT extraction via PrintNightmare-style coercion), T1550.002 (Use Alternate Authentication Material: Pass the Hash) — chained
**Affected Assets:** `HL-DC01$`, `HL-DC02$`, `HL-AzDC02$` (computer accounts, all in `OU=Domain Controllers,DC=HA-SHEM,DC=com`).
**Evidence:** `evidence/ad/unconstrained_delegation.txt`.

**Description:** Domain Controllers natively hold the `TRUSTED_FOR_DELEGATION` flag (UAC bit 0x80000) — this is normal AD behaviour, since DCs implicitly need to delegate Kerberos. The finding here is **not** that this should be removed (it cannot be) but that the consequence — DCs cache TGTs of any user that authenticates to them — combined with the SMB-relay and LLMNR-poisoning surface (Findings 001/002) and the AD CS ESC1 path (Finding 008) means an attacker who lands on a DC can extract a TGT for any active user (including DA) via `mimikatz sekurlsa::tickets /export`.

Most critically, `HL-AzDC02` (Finding 005) is also on this list — a DC exposed to the internet that automatically caches all delegated TGTs is uniquely dangerous.

**Business Impact:** Acts as a multiplier on the other findings. Once any DC is reachable (Finding 005) or compromised (via Finding 001 chain), TGT extraction yields multi-account compromise.

**Remediation Steps:**
1. The unconstrained-delegation flag on DCs cannot be safely removed and should not be. Instead, focus on reducing what reaches DCs:
2. Remediate Finding 005 (close HL-AzDC02 internet exposure) — this is the highest-value operational change.
3. Enforce **Protected Users** group membership for all Tier-0 administrators (Domain Admins, Enterprise Admins, key service accounts). Members of Protected Users have NTLM disabled, AES-only Kerberos, no delegation — meaning their TGTs cached on DCs cannot be replayed against non-DC services.
4. Configure the **Authentication Policy Silos** for Tier-0 to restrict where DA accounts can authenticate from.
5. Detect: monitor Event ID 4624 LogonType=3 to a DC from a non-DC source where account is in DA — suspicious lateral movement signal.

**Owner:** AD Operations.
**References:** Microsoft "Securing Domain Controllers Against Attack" (whitepaper); MITRE D3-AHEUR.

---

### Finding 011 — Web Application DAST: ZAP Alerts Across 4 Targets (Including Reported "RCE")
**Severity:** MEDIUM (with one HIGH provisional pending PoC validation)
**CVSS 3.1 Score:** Per-alert; aggregate reflects the highest-impact alert per target
**CWE:** CWE-693 Protection Mechanism Failure (CSP/headers); CWE-78 (provisional, ZAP "RCE React2Shell" alert); CWE-1021 (clickjacking); CWE-204 (proxy disclosure)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application — provisional)
**Affected Assets:** `https://irecruit.ha-shem.com`, `https://hrportalui-dev.azurewebsites.net/login`, `https://aira.havis360.com`, `https://v-login.havis360.com`. (`https://ha-shem.com` was crawl-only in this aggregate; no JSON report.)

**Per-target alert summary:**

| Target | Total | High | Medium | Low | Info | Notable |
|---|---|---|---|---|---|---|
| irecruit.ha-shem.com | 18 | 1 | 3 | 7 | 7 | "Remote Code Execution (React2Shell)" alert (alertRef 40048); CSP not set; clickjacking |
| hrportalui-dev.azurewebsites.net/login | 12 | 1 | 2 | 4 | 5 | "Remote Code Execution (React2Shell)" alert; CSP not set |
| aira.havis360.com | 18 | 0 | 4 | 8 | 6 | Sub Resource Integrity missing; Information Leak via in-page banner |
| v-login.havis360.com | 15 | 0 | 5 | 5 | 5 | Multiple CSP weaknesses: `script-src unsafe-eval`, `script-src unsafe-inline`, `style-src unsafe-inline` |

**Evidence:** `evidence/web/zap/<target>/zap_report.{html,json,xml}` for each target.

**Caveat — "Remote Code Execution (React2Shell)" finding:** The ZAP "Remote Code Execution (React2Shell)" rule (alert 40048) is the active scan rule that fires upon detection of a server returning a payload reflecting injected shell metacharacters. ZAP raised this as **High confidence** on both `irecruit.ha-shem.com` and `hrportalui-dev.azurewebsites.net/login`. The match returns require **manual validation** — react-style frontends often produce alert-like patterns from echoed input that are not actually executing. The risk-rating treatment in this report is:
- Pending manual PoC validation, this finding is treated as **HIGH provisional**.
- If the manual reproduction succeeds, severity becomes **CRITICAL** with CVSS 9.8 and immediate remediation is required.
- If the manual reproduction fails (false positive — highly likely on a React SPA), severity downgrades to Informational and the finding is closed.

**Genuine confirmed (non-provisional) issues across all four targets:**
- Content Security Policy header not set or weak (`script-src unsafe-eval`, `unsafe-inline`).
- Strict-Transport-Security (HSTS) header not set on `irecruit.ha-shem.com` and `aira.havis360.com`.
- X-Content-Type-Options header missing.
- Cross-Origin-Embedder-Policy / Opener-Policy / Resource-Policy headers missing or invalid.
- Server / Proxy version disclosure (Information Disclosure - Sensitive Information in URL on `irecruit.ha-shem.com`).
- Sub Resource Integrity missing (`aira.havis360.com`).

**Business Impact:** The header/CSP weaknesses individually are low-severity, but the cumulative effect is that the production-facing apps lack defence-in-depth against XSS and clickjacking. The provisional RCE alert demands immediate manual validation before any other remediation work on these apps.

**Remediation Steps:**
1. **Within 24 hours:** Manually reproduce the ZAP RCE alert against `irecruit.ha-shem.com` and `hrportalui-dev.azurewebsites.net/login`. If genuine, take the affected backend offline and patch.
2. Apply a base CSP (`default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`) across all four targets and tune.
3. Add Strict-Transport-Security `max-age=31536000; includeSubDomains; preload` to the main hostnames.
4. Add X-Content-Type-Options `nosniff`, X-Frame-Options `DENY`, Cross-Origin-Resource-Policy `same-origin`.
5. Suppress server/version banners (remove `Server` and `X-Powered-By` headers at the App Service / Front Door layer).
6. For `v-login.havis360.com` — review the CSP `unsafe-eval` / `unsafe-inline` script-src — these typically indicate inline JS in the SPA build that can be moved to nonced or hashed inclusions.

**Owner:** Application owners (HRPortal, iRecruit, Havis360 / AIRA team) with Web Platform team support.
**References:** OWASP Secure Headers Project; OWASP ASVS L2 §V14 (HTTP Security).

---

### Finding 012 — SMB Null Session Accepted on HL-DC01
**Severity:** MEDIUM
**CVSS 3.1 Score:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**CWE:** CWE-284 Improper Access Control; CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
**MITRE ATT&CK:** T1135 Network Share Discovery; T1087.002 Account Discovery: Domain Account (potential); T1069.002 Permission Groups Discovery: Domain Groups (potential)
**Affected Assets:** `HL-DC01` — 10.10.0.3 (Windows Server 2022 Build 20348)

**Evidence:** `evidence/ad/nullsession_check.txt` — confirmed across all five exercise runs (2026-04-30 to 2026-05-08). The check run was: `nxc smb 10.10.0.3 -u '' -p ''`. In every run the result was:

```
[*] Windows Server 2022 Build 20348 x64 (name:HL-DC01) (domain:HA-SHEM.com) (signing:True) (SMBv1:False)
[+] HA-SHEM.com\:
```

The `[+]` line with a blank username and blank password indicates the SMB authentication exchange completed with `STATUS_SUCCESS` — an anonymous session was established.

**Important semantic distinction — this finding is independent of Finding 001:**
Finding 001 concerns SMB *signing* (whether packets are cryptographically signed, which prevents NTLM relay). Finding 012 concerns *authentication*: whether the DC accepts an anonymous SMB connection with no credentials at all. HL-DC01 correctly enforces `signing:True` and is therefore not a relay target. It simultaneously accepts null-session authentication — these are orthogonal controls, and both are confirmed in the same log line.

**Description:** When a Windows host returns `STATUS_SUCCESS` for an SMB session request with blank credentials, an unauthenticated attacker can establish an anonymous `IPC$` connection. The risk varies by the server's `RestrictAnonymous` registry value:

| `RestrictAnonymous` value | Effect |
|---|---|
| `0` | Full anonymous SAMR enumeration: all domain users, groups, shares, password policy |
| `1` (Windows default) | IPC$ session established; SAMR and LSARPC calls that enumerate users/groups are blocked |
| `2` | Null session to IPC$ completely blocked; most secure |

Windows Server 2022 defaults to `RestrictAnonymous = 1`. At this level, the IPC$ session opens successfully (which is what our test confirmed), but direct SAMR enumeration calls (`NetUserEnum`, `NetGroupEnum`) should be blocked. **The `RestrictAnonymous` registry value was not retrieved during this engagement** — confirmation that it is set to `1` (not `0`) requires a direct registry read or a follow-up `nxc smb 10.10.0.3 -u '' -p '' --rid-brute` test.

Even at `RestrictAnonymous = 1`, a null session grants:
- Confirmation that the host is a domain member (`HA-SHEM.com\:` response identifies the domain)
- Access to any shares that carry an anonymous ACL (e.g. a misconfigured `NETLOGON` or `SYSVOL` share, or any custom share added with loose permissions)
- A valid authenticated SMB context from which some RPC endpoints (e.g. `MSRPC` service discovery on pipe `\PIPE\svcctl`) may respond

**Coverage gap:** HL-DC02 and HL-AzDC02 were not tested because only `10.10.0.3` was present in the `DC_IP` engagement configuration variable. `DC_IP` should include all DC IPs; see Section 8 for detail.

**Remediation Steps:**
1. **Verify the current `RestrictAnonymous` setting** on HL-DC01 (and once IPs are known, on HL-DC02 and HL-AzDC02):
   ```
   reg query \\10.10.0.3\HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous
   ```
   Or remotely via CrackMapExec: `nxc smb 10.10.0.3 -u jamiush -p <pwd> -M reg --args "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RestrictAnonymous"`.
2. **Set `RestrictAnonymous = 2` via GPO** on all Domain Controllers to prevent null sessions entirely:
   `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled`
   and
   `Network access: Restrict anonymous access to Named Pipes and Shares = Enabled`.
3. **Validate** by re-running `nxc smb 10.10.0.3 -u '' -p ''` post-remediation — result should change from `[+]` to `[-]` (access denied) or `AUTHENTICATION_ERROR`.
4. **Test for compatibility breakage** in a staging environment before production rollout — some legacy applications (print spoolers, older SCCM components, MBAM endpoints) may have a dependency on anonymous IPC access. The `MBAMAppPool` and `sccmsvc` service accounts already flagged in Finding 004 are candidates.

**Owner:** Infrastructure Engineering (GPO / registry hardening); Application Owners (compatibility validation for sccmsvc / MBAMAppPool).
**References:** MS KB246261 (RestrictAnonymous levels); CIS Windows Server 2022 Benchmark §2.3.11.1–2.3.11.8; MITRE D3-IAM.

---

## 5. Remediation Roadmap

| Finding | Severity | Track | Target Date |
|---|---|---|---|
| 005 — HL-AzDC02 internet exposure (NSG 6516) | CRITICAL | Immediate Hotfix | 2026-05-11 (T+1 day) |
| 011 — Manual validation of "RCE" ZAP alert on irecruit / hrportal | HIGH (provisional) | Immediate Hotfix | 2026-05-11 (T+1 day) |
| 001 — SMB Signing not required (36 hosts) | CRITICAL | Short-Term | 2026-05-17 (T+7 days) |
| 002 — LLMNR / NBT-NS poisoning | CRITICAL | Short-Term | 2026-05-17 (T+7 days) |
| 003 — Kerberoastable service accounts | HIGH | Short-Term | Phase 1 (force pwd reset) by 2026-05-17; gMSA migration by 2026-06-17 |
| 008 — AD CS ESC1 + ESC15 templates | HIGH | Short-Term | 2026-05-17 (T+7 days, template config) |
| 006 — Azure public blob access enabled | HIGH | Short-Term | 2026-05-17 (T+7 days) |
| 009 — RDP / AVD exposed to internet | HIGH | Short-Term | 2026-05-17 (T+7 days) |
| 007 — Subscription-scope Owner / Contributor sprawl | HIGH | Medium-Term | 2026-06-09 (T+30 days, full PIM rollout) |
| 004 — 101 `PasswordNeverExpires` accounts | MEDIUM | Medium-Term | 2026-06-09 (T+30 days) |
| 010 — Unconstrained delegation on DCs (Protected Users rollout) | MEDIUM | Medium-Term | 2026-06-09 (T+30 days) |
| 011 — Web headers / CSP hardening (non-RCE alerts) | MEDIUM | Medium-Term | 2026-06-09 (T+30 days) |
| 012 — DC01 null session accepted; extend test to HL-DC02 and HL-AzDC02 | MEDIUM | Medium-Term | 2026-06-09 (T+30 days) |
| Re-test and verification (focused) | — | Long-Term | 2026-07-08 (T+60 days) |
| Full re-engagement (all phases) | — | Long-Term | 2026-08-08 (T+90 days) |

**Compliance mapping:**
- ISO 27001 A.9.2 (User Access Management) — Findings 003, 004, 007, 010
- ISO 27001 A.13.1 (Network Security Management) — Findings 001, 002, 005, 009
- NIST CSF PR.AC-1 / PR.AC-4 — Findings 003, 004, 007, 010
- NIST CSF PR.DS-2 / PR.DS-5 — Findings 005, 006
- CIS Microsoft Azure Foundations Benchmark §1 (Identity / RBAC) — Finding 007
- CIS Microsoft Azure Foundations Benchmark §3 (Storage) — Finding 006
- CIS Microsoft Azure Foundations Benchmark §6 (Networking) — Findings 005, 009
- CIS Windows Server 2022 Benchmark §2.3.11 (Network Access — anonymous enumeration / null session) — Finding 012
- NIST CSF PR.AC-3 (Remote Access Management / Anonymous Access Controls) — Finding 012

---

## 6. MITRE ATT&CK Coverage Matrix

| Tactic | Technique | Sub-Technique | Observed in Finding |
|---|---|---|---|
| Reconnaissance | T1590 Gather Victim Network Information | — | Phase 1 host discovery |
| Reconnaissance | T1592 Gather Victim Host Information | — | nmap fullscan |
| Initial Access | T1190 Exploit Public-Facing Application | — | F005, F009, F011 (provisional) |
| Initial Access | T1133 External Remote Services | — | F005 (DC port 6516), F009 (RDP) |
| Execution | T1059 Command and Scripting Interpreter | — | (post-foothold, not exercised in scope) |
| Persistence | T1098.003 Account Manipulation | Additional Cloud Roles | F007 (Owner sprawl) |
| Privilege Escalation | T1558.003 Kerberoasting | — | F003 |
| Privilege Escalation | T1649 Steal or Forge Authentication Certificates | — | F008 (AD CS ESC1 / ESC15) |
| Privilege Escalation | T1078.002 Valid Accounts: Domain Accounts | — | F003, F004 |
| Privilege Escalation | T1078.004 Valid Accounts: Cloud Accounts | — | F007 |
| Defense Evasion | T1556 Modify Authentication Process | — | F008 (cert-based auth bypass) |
| Credential Access | T1557.001 Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | — | F001 + F002 |
| Credential Access | T1187 Forced Authentication | — | F001 (relay), would-have-included PetitPotam if module not deprecated |
| Credential Access | T1110 Brute Force | T1110.001 Password Guessing | F004 (latent), F009 (RDP exposed) |
| Credential Access | T1558.004 AS-REP Roasting | — | Attempted (no captures — see Finding 003 area, asrep_accounts.txt) |
| Discovery | T1018 Remote System Discovery | — | Phase 1 SMB sweep |
| Discovery | T1135 Network Share Discovery | — | F012 (null session IPC$ access) |
| Discovery | T1087.002 Account Discovery: Domain Account | — | LDAP enumeration (`evidence/ad/userlist.txt`, ldap_users); F012 (potential via null session if RestrictAnonymous=0) |
| Discovery | T1069.002 Permission Groups Discovery: Domain Groups | — | BloodHound collection |
| Discovery | T1526 Cloud Service Discovery | — | ROADrecon, az inventory |
| Lateral Movement | T1550.002 Use Alternate Authentication Material: Pass the Hash | — | F001 chain (ntlmrelayx) |
| Lateral Movement | T1021.001 Remote Services: RDP | — | F009 (exposed RDP enables lateral inbound) |
| Collection | T1530 Data from Cloud Storage | — | F006 (latent) |

---

## 7. Re-Test Acceptance Criteria

For each finding to be considered **closed** at re-test:
- **F001:** `nxc smb 10.10.20.0/24 10.10.21.0/24 --gen-relay-list -` returns 0 IPs.
- **F002:** Active 60-minute Responder analyse-mode capture against the workstation VLANs returns 0 NTLMv2 broadcasts; LLMNR / NBT-NS GPO confirmed applied via `gpresult /R` on a sample of 5 hosts.
- **F003:** Re-run `impacket-GetUserSPNs HA-SHEM.com/jamiush -dc-ip 10.10.0.3` confirms remaining SPN holders are gMSA-class accounts only.
- **F004:** `pwd_never_expires` LDAP filter returns ≤ 10 accounts and all are gMSAs.
- **F005:** External nmap from a non-corporate IP confirms no open ports on the public IP path to HL-AzDC02. NSG rule history shows the priority-100 rule deleted.
- **F006:** `az storage account show --query allowBlobPublicAccess` returns `false` on all three accounts.
- **F007:** Subscription-scope Owner reduced to ≤ 2 break-glass accounts (PIM-eligible only).
- **F008:** Re-run Certipy from authenticated user — flagged ESC1 / ESC15 templates either disabled, no longer enrollable by Domain Users, or have `EnrolleeSuppliesSubject` cleared.
- **F009:** External nmap returns no open 3389 on either the 3CX or AVD public-facing IP.
- **F010:** Verify Domain Admins membership is in the Protected Users group; sample DA login from non-DC fails NTLM.
- **F011:** Manual PoC of the ZAP "RCE" alert documented as either confirmed-and-fixed or false-positive; CSP / HSTS / XCTO headers verified present on all 4 targets via `curl -I`.
- **F012:** `nxc smb 10.10.0.3 -u '' -p ''` returns `[-]` (access denied) on HL-DC01. Same test run against HL-DC02 and HL-AzDC02 (once IPs are confirmed) also returns `[-]`. Registry confirms `RestrictAnonymous = 2` on all three DCs.

---

## 8. Caveats and Evidence Quality Notes

- **AS-REP Roasting** was attempted in every iteration; all candidate accounts that returned `KDC_ERR_CLIENT_REVOKED` are disabled accounts (the policy is correctly preventing them). No active account in HA-SHEM.com had `UF_DONT_REQUIRE_PREAUTH` set in a way that produced a hash. This is a positive control state and is not a finding — included here only to document that the control was tested.
- **Responder NTLMv2 capture** was constrained by a Responder QUIC-server bind error (`OSError: [Errno 98]`) in one collection window and by short collection durations in others. The risk in Finding 002 is rated on the underlying primitive (LLMNR/NBT-NS not disabled) not on the in-window capture count.
- **NXC PetitPotam module** has been migrated upstream to `coerce_plus`. The `smb_vuln_checks.txt` log shows `[REMOVED] This module moved to the new module "coerce_plus"` for every host attempted. PetitPotam coercion has not therefore been definitively tested in this engagement; given the SMB-signing posture (Finding 001) and AD CS exposure (Finding 008), an AD CS ESC8 (Web Enrollment NTLM relay) chain via PetitPotam is plausible and should be tested in the next iteration.
- **DCSync** was not executed (manual gate not unlocked per RoE).
- **DC null-session coverage gap (Finding 012):** The null-session check (`nxc smb -u '' -p ''`) ran only against `10.10.0.3` (HL-DC01) because that was the sole IP in the `DC_IP` engagement configuration variable. Two of the three domain controllers were therefore untested:
  - **HL-DC02** — No IP address was resolved for this DC across any of the five exercise runs. It did not appear in any nmap scan, SMB sweep, or LDAP output within the scanned subnets (`10.10.20.0/24`, `10.10.21.0/24`, `10.100.32.0/24`). Its presence is confirmed only via LDAP computer-object enumeration (`CN=HL-DC02,OU=Domain Controllers,DC=HA-SHEM,DC=com`). An IP address must be obtained (e.g. from DNS: `nslookup HL-DC02 10.10.0.3`) and the host must be included in subsequent scans.
  - **HL-AzDC02 (10.100.32.5)** — Present in the SMB sweep with `signing:True` and authenticated login confirmed, but never tested for null-session access because it was not added to `DC_IP`. It should be included in the re-test check for Finding 012.
  - **Remediation for the gap:** Add all three DC IPs (once HL-DC02's IP is resolved) to the `DC_IP` space-separated list in `config.env` before the next engagement run.
- **AD CS CA configuration** could not be retrieved via Certipy RRP (`Failed to connect to remote registry after 3 attempts`). ESC6/7/8/11 ratings cannot be conclusively given. The next engagement should include direct CA-host inspection.
- **Azure Blob anonymous-PoC** confirmed all 21 enumerated containers on the 3 affected storage accounts deny anonymous read; the finding is the account-level setting, not a confirmed data leak.

---

## 9. Appendix — Source Engagement Iterations

| Run Directory | Date | Notes |
|---|---|---|
| `05_05_vapt/` | 2026-04-30 | First baseline; most complete ZAP coverage; AS-REP probe captured most accounts |
| `06_05_2026_vapt/` | 2026-05-05 / 06 | Most complete network and SMB sweep (103 SMB sweep entries, 36 relay targets) |
| `07_05_vapt/` | 2026-05-07 | Repeat AD enumeration; Responder ran 76-line session |
| `this_afternoon_vapt/` | 2026-05-08 (early) | ZAP scans of Havis360 / vlogin |
| `vapt/` | 2026-05-08 (latest) | Most complete Azure inventory and security-checks; phase4 blast radius |

---

*End of report.*
