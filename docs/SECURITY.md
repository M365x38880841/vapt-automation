# Security Design and Controls

**Classification:** INTERNAL — Infrastructure Security Team  
**Applies to:** Ha-Shem VAPT Automation Framework

This document describes the security controls built into the framework itself — how credentials are protected, how the operator is prevented from accidentally exceeding scope, what the audit record looks like, and how to handle a situation where the tool or its output is compromised.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Credential Handling](#2-credential-handling)
3. [Scope Enforcement Controls](#3-scope-enforcement-controls)
4. [Audit Trail Design](#4-audit-trail-design)
5. [Network Footprint](#5-network-footprint)
6. [Data Classification and Handling](#6-data-classification-and-handling)
7. [Responsible Use Policy](#7-responsible-use-policy)
8. [Incident Response — Framework Misuse](#8-incident-response--framework-misuse)

---

## 1. Threat Model

The framework is a high-value target during an engagement. It runs on the attack machine, holds active credentials in memory, and produces output files containing cracked passwords, NTLM hashes, and lateral movement evidence. The threats relevant to the framework itself are:

| Threat | Likelihood | Impact | Control |
|--------|-----------|--------|---------|
| Attack machine compromised during engagement | Low | Critical | Isolated VLAN; full disk encryption on attack machine |
| Operator accidentally scans out-of-scope assets | Medium | High | Scope validated from `config.env`; `TARGET_SUBNETS` and `AZURE_SUBSCRIPTION_IDS` are the only sources |
| Engagement output leaked after engagement | Medium | High | Post-engagement cleanup with `shred`; encrypted archive |
| Credentials exposed in logs or files | Low | Critical | `log_cmd()` masks credential values; `getpass` hides input; no credentials written to any file |
| Framework run against wrong tenant/domain | Low | Critical | RoE confirmation gate at startup; scope JSON written with operator-confirmed values |
| Background job (Responder) left running after engagement | Medium | High | `cleanup_on_exit()` kills process groups; post-engagement cleanup checklist |

---

## 2. Credential Handling

### What is never stored

- Domain passwords
- Azure passwords or tokens
- NTLM hashes (cracked or captured)
- Nessus API credentials
- Any other secret prompted at runtime

These values exist only in:
1. The operator's memory
2. Python's `getpass` hidden input buffer (not echoed to screen)
3. The orchestrator's in-memory `creds` dict during the session
4. The subprocess environment (`/proc/<pid>/environ`) while a phase script runs

### What `/proc/<pid>/environ` exposure means

When the orchestrator invokes a phase script via `subprocess.run()`, credentials are part of the process environment. On Linux, `/proc/<pid>/environ` is readable by the process owner and by root. During the engagement, this risk is accepted because:
- The attack machine is under operator control
- The attack machine should be on an isolated VLAN
- The exposure window is limited to the duration of the phase script execution
- Credentials are not written to swap or core dumps (standard Linux behaviour for environment variables)

### Log masking

`log_cmd()` in `lib/common.sh` logs the command being run to `engagement_log.md`. For commands that include credentials, the credential argument is replaced with `***` or `[creds]` in the log call. Example:

```bash
# In the script:
log_cmd "ldapsearch -H ldap://${DC_IP} -D ${DOMAIN_USER}@${DOMAIN_NAME} -w *** -b DC=..."
# Actual execution uses the real ${DOMAIN_PASS} — the log only records the template
```

This means `engagement_log.md` can be shared with stakeholders as an audit record without exposing credentials.

---

## 3. Scope Enforcement Controls

### Business hours enforcement

When `ENFORCE_TESTING_WINDOW=true`, every phase checks the current time against `TESTING_WINDOW_START` and `TESTING_WINDOW_END` before running. If outside the window, the operator is prompted to confirm an override. The override decision is logged.

The time comparison uses numeric minute-since-midnight arithmetic (not string comparison) to avoid locale-dependent bugs:
```bash
_hm_to_min() { local h m; IFS=: read -r h m <<< "$1"; echo $(( 10#$h * 60 + 10#$m )); }
```

### RoE confirmation gate

At orchestrator startup (before any phase runs), the operator must explicitly confirm:
```
Is the signed RoE document in place? [y/N]:
```
A `n` response exits immediately with a logged message. This gate cannot be bypassed via command-line flags.

### Checkpoint gates on destructive actions

Every destructive or sensitive action requires operator confirmation via `checkpoint()`. The following actions are gated:

| Action | Phase | Gate type |
|--------|-------|-----------|
| Full port scan launch | 1 | Informational checkpoint |
| ScoutSuite audit launch | 2 | Informational checkpoint |
| Responder start | 3 | Explicit confirmation |
| NTLM relay target confirmation | 3 | Explicit confirmation + target list display |
| Pass-the-Hash sweep | 3 | Explicit confirmation per run |
| SAM dump per host | 4 | Explicit confirmation per host |
| Interactive PsExec/WMIexec | 4 | Explicit confirmation per hop |
| DCSync PoC | 4 | Maximum gate (BloodHound confirmation required, krbtgt blocked, account name required) |

### DCSync hard blocks

The DCSync section in Phase 4 includes hard-coded safety checks:
```bash
[[ "${target_account,,}" == "krbtgt" ]] && {
    log ERROR "BLOCKED: Do not DCSync krbtgt during this engagement."
    exit 1
}
```
Targeting `krbtgt` or (with an additional warning) `administrator` requires explicit manual override that is logged. This prevents accidental golden ticket creation during the engagement.

---

## 4. Audit Trail Design

`engagement_log.md` is written by both the orchestrator (Python) and the phase scripts (Bash via `log()`). Every entry includes a UTC timestamp.

### What is logged

| Event | Log level | Example entry |
|-------|-----------|---------------|
| Phase start | PHASE | `## [2026-04-08 09:00:00] PHASE 1 START — Reconnaissance & Discovery` |
| Phase end | (orchestrator) | `## [2026-04-08 14:30:00] PHASE 1 END` |
| Command execution | CMD | `## [2026-04-08 09:05:12] [CMD] nmap -sS -sV -p- ...` |
| Background job start | INFO | `## [2026-04-08 09:05:12] [INFO] Background job started: nmap_fullscan (PID: 12345)` |
| Checkpoint proceed | INFO | `## [2026-04-08 10:15:00] [INFO] Proceeded at checkpoint: Execute Phase 2` |
| Checkpoint skip | WARN | `## [2026-04-08 10:15:00] [WARN] Skipped at checkpoint: ScoutSuite audit` |
| Checkpoint abort | WARN | `## [2026-04-08 10:15:00] [WARN] Aborted at checkpoint: DCSync PoC` |
| Finding identified | WARN | `## [2026-04-08 11:00:00] [WARN] FINDING: 3 Kerberoastable account(s)` |
| Testing window override | WARN | `## [2026-04-08 08:45:00] [WARN] Testing window overridden by operator at 08:45` |
| Session interrupt | WARN | `## [2026-04-08 17:00:00] [WARN] Session interrupted by operator` |

### What is NOT logged

- Credential values (passwords, hashes)
- The content of cracked password files
- Detailed exploit payload content

The log is designed to answer: *what was run, when, by whom (by implication), and what was found* — without constituting a credential exfiltration risk.

### Log integrity

`engagement_log.md` is append-only by design. The framework never truncates or overwrites it. If a phase is re-run, a new START marker is written — the previous run's entries remain. This creates a complete history of all runs.

---

## 5. Network Footprint

### What the framework generates on the wire

| Activity | Traffic type | Approximate volume |
|----------|-------------|-------------------|
| Nmap host sweep | ICMP echo, TCP SYN | ~1 packet per host |
| Nmap full port scan | TCP SYN to all 65535 ports per host | High — run overnight |
| CME SMB sweep | TCP port 445 to all hosts | Moderate |
| LDAP queries | TCP port 389 to DC | Low |
| BloodHound collection | LDAP, Kerberos, SMB (DC only) | Moderate |
| Responder | LLMNR/NBT-NS broadcast responses | Passive, broadcast domain only |
| Hashcat | No network traffic (local CPU/GPU only) | None |
| ZAP baseline scan | HTTP/HTTPS GET requests only | Low-moderate per target |
| ZAP full scan | HTTP/HTTPS including attack payloads | High per target |
| ScoutSuite | HTTPS to Azure API endpoints | Low (rate-limited by Azure) |

### IDS/SIEM considerations

The attack machine's IP (`ATTACKER_IP`) should be communicated to the Infrasec monitoring team before the engagement begins. Nmap SYN scans and Kerberoasting requests will generate IDS alerts if signatures are enabled. This is intentional — it is also a test of detection capability.

If the engagement scope includes testing detection capability (red team element), do not whitelist the attack machine in advance.

---

## 6. Data Classification and Handling

All output produced by the framework is classified as **CONFIDENTIAL — Internal Use Only**.

| Data type | Classification | Storage | Retention |
|-----------|---------------|---------|-----------|
| Cracked credentials | CONFIDENTIAL | `phase3/ad/cracked_*.txt` | Destroy after report delivery |
| Captured NTLM hashes | CONFIDENTIAL | `phase3/ad/ntlmv2_all.txt` | Destroy after report delivery |
| Domain user list | CONFIDENTIAL | `phase1/ad/userlist.txt` | Destroy after report delivery |
| BloodHound database | CONFIDENTIAL | Docker volume (Neo4j) | Destroy after report delivery |
| Full port scan results | INTERNAL | `phase1/network/fullscan.xml` | Archive per retention policy |
| ScoutSuite report | INTERNAL | `phase2/cloud/scoutsuite/` | Archive per retention policy |
| ZAP scan reports | INTERNAL | `phase2/web/zap/` | Archive per retention policy |
| Engagement log | INTERNAL | `engagement_log.md` | Archive per retention policy |
| Technical report | CONFIDENTIAL | `report/TECHNICAL_REPORT_SCAFFOLD.md` | Archive per retention policy |

**Destroy** means: overwrite with `shred -uz` before deletion. Standard `rm` is not sufficient — it leaves file content on disk.

**Archive** means: tar + gpg AES-256 symmetric encryption before storing. The encryption passphrase must be stored separately from the archive.

---

## 7. Responsible Use Policy

This framework is authorised for use **only** under a signed Rules of Engagement agreement against systems that Ha-Shem Limited owns or has explicit written authorisation to test.

**Prohibited uses:**
- Testing systems not explicitly listed in the RoE
- Running against any cloud tenant, subscription, or resource not in `AZURE_SUBSCRIPTION_IDS`
- Running outside the agreed testing window without management authorisation
- Using cracked credentials outside the scope of this engagement
- Sharing output files with any party not named in the RoE
- Running `ZAP_SCAN_MODE=full` against any target without explicit RoE coverage for active web testing

**If you are unsure whether an action is within scope:**
Stop. Contact the Management Sponsor (Elizabeth A.) before proceeding. Document the question and the answer in `engagement_log.md`.

---

## 8. Incident Response — Framework Misuse

If the framework is run against out-of-scope systems, or if the attack machine is compromised during the engagement:

### Out-of-scope execution

1. Immediately halt all activity: press `Ctrl+C` and run the emergency stop procedure in [RUNBOOK.md](RUNBOOK.md).
2. Do not delete any output files — they are evidence.
3. Contact Elizabeth A. (Management Sponsor) immediately.
4. Preserve `engagement_log.md` — it records what was run and when.
5. Prepare a written incident report: what ran, against which systems, for how long, what data was collected.
6. Notify the security operations centre if the affected systems generated alerts.

### Attack machine compromised

1. Disconnect the attack machine from the network immediately (physical cable pull if needed).
2. Assume all credentials collected during the engagement are compromised.
3. Contact Elizabeth A. and initiate credential rotation for:
   - The domain user account used during the engagement
   - The Azure account used during the engagement
   - Any accounts whose hashes were cracked (advise IT to force password reset)
4. Preserve the attack machine image for forensic analysis — do not power off.
5. Notify affected system owners.

### Evidence of lateral movement beyond authorised scope

If Phase 4 activity results in access to systems not explicitly listed in the RoE (e.g. via a compromised domain account that has access to out-of-scope systems):

1. Stop immediately — do not continue exploring.
2. Document the access in `engagement_log.md` with a timestamp.
3. Contact Elizabeth A. before deciding whether to continue.
4. The finding (that the compromised account has access to out-of-scope systems) is itself a reportable finding.
