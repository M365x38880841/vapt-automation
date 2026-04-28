# VAPT Engagement Runbook

**Classification:** INTERNAL — Infrastructure Security Team  
**Applies to:** Ha-Shem VAPT Automation Framework

This runbook translates the framework's phases into concrete day-by-day operator actions. Read this before running any phase for the first time. The framework automates mechanics; this document tells you what to do with the results and how to handle failures.

---

## Table of Contents

1. [Pre-Engagement Checklist](#1-pre-engagement-checklist)
2. [Environment Setup (Day 0)](#2-environment-setup-day-0)
3. [Phase 0 — Pre-Engagement Setup](#3-phase-0--pre-engagement-setup)
4. [Phase 1 — Reconnaissance and Discovery](#4-phase-1--reconnaissance-and-discovery)
5. [Phase 2 — Vulnerability Assessment](#5-phase-2--vulnerability-assessment)
6. [Phase 3 — Exploitation](#6-phase-3--exploitation)
7. [Phase 4 — Post-Exploitation](#7-phase-4--post-exploitation)
8. [Phase 5 — Reporting and Debrief](#8-phase-5--reporting-and-debrief)
9. [Background Job Monitoring Reference](#9-background-job-monitoring-reference)
10. [Troubleshooting](#10-troubleshooting)
11. [Emergency Stop Procedure](#11-emergency-stop-procedure)
12. [Post-Engagement Cleanup](#12-post-engagement-cleanup)

---

## 1. Pre-Engagement Checklist

Complete every item before running Phase 0. The framework enforces the RoE check at startup, but these steps must be done manually.

### Legal and governance

- [ ] Signed Rules of Engagement received from all 6 parties (Infrasec, Networking, Cloud Platform, Legal, Management Sponsor, affected BU head)
- [ ] RoE explicitly states: date range, in-scope subnets, in-scope domains, in-scope Azure subscriptions, exploitation permitted (yes/no/conditional), testing window hours
- [ ] Emergency stop contact agreed and phone number confirmed
- [ ] Out-of-bounds assets listed and confirmed (production payment systems, HR databases, etc.)

### Technical prerequisites

- [ ] Attack machine on internal network with Layer 2 access to at least one target subnet
- [ ] Domain user account provisioned (read-only; must NOT be a service account or shared account)
- [ ] Azure Reader role assigned to the testing account on all in-scope subscriptions
- [ ] All DCs in `DC_IP` confirmed reachable: `for ip in <DC_IP>; do ping -c 2 "$ip"; done`
- [ ] `config.env` filled in from `config.env.example` (all variables, no placeholders remaining)
- [ ] `WEB_TARGETS` set to in-scope web application base URLs (or explicitly left empty)

### Stakeholder communications

- [ ] Email to Management Sponsor: engagement start date, testing window, emergency contact
- [ ] Infrasec monitoring team notified: attack machine IP (`ATTACKER_IP`) whitelisted in SIEM alert suppression (or alerts acknowledged)
- [ ] Networking team notified of Nmap timing template and expected scan volume

---

## 2. Environment Setup (Day 0)

These steps are done before the official engagement start, on the attack machine.

```bash
# Clone the framework
git clone <repo-url> ~/vapt-automation
cd ~/vapt-automation

# Configure engagement
cp config.env.example config.env
nano config.env
# Verify no placeholder values remain:
grep 'xxxxxxxx\|COMPLETE\|TODO' config.env && echo "FIX ABOVE" || echo "Config looks clean"

# Make scripts executable
chmod +x orchestrator.py phases/*.sh lib/common.sh

# Dry-run to verify the framework parses config correctly
python3 orchestrator.py --phase 0 --dry-run
```

If the dry-run shows config errors, fix them before proceeding.

---

## 3. Phase 0 — Pre-Engagement Setup

**Goal:** Verify all tools are installed, BloodHound CE is running, Azure CLI is authenticated, scope file is written.

**Run:**
```bash
python3 orchestrator.py --phase 0
```

**What happens automatically:**
1. pipx is bootstrapped if missing
2. Docker CE is installed (or verified and started) using the upstream Docker CE repository
3. All required tools verified; missing tools auto-installed
4. rockyou.txt decompressed or downloaded if missing
5. Corporate password pattern wordlist generated
6. `bloodhound-cli` located or downloaded from GitHub releases; BloodHound CE installed and started via `bloodhound-cli start`
7. Azure CLI login checked; device code flow initiated if not logged in
8. All DCs in `DC_IP` checked for reachability
9. Scope JSON written to `~/vapt/phase0/scope.json`

**Operator actions during Phase 0:**
- Confirm each checkpoint prompt (tool install, Azure login)
- When Azure device code appears: open the browser, authenticate, return to terminal
- After Phase 0: retrieve BloodHound CE first-run password:
  ```bash
  bloodhound-cli password
  # or: bloodhound-cli logs | grep -i 'initial password'
  ```
- Log into BloodHound CE at http://localhost:8080 and confirm it loads

**Expected output:**
```
Phase 0 Complete — Automated Checks Passed
```

**If Phase 0 fails:**
- See [Troubleshooting](#10-troubleshooting) section for Docker, pip, and Azure CLI issues.

---

## 4. Phase 1 — Reconnaissance and Discovery

**Goal:** Map live hosts accurately, enumerate AD users and structure, collect BloodHound data, enumerate Entra ID and Azure resources.

**Run:**
```bash
python3 orchestrator.py --phase 1

# Skip full-port scan (already running from a previous session)
python3 orchestrator.py --phase 1 --skip nmap_fullscan

# Run only BloodHound and ROADrecon (skip network scanning entirely)
python3 orchestrator.py --phase 1 --only bloodhound,roadrecon

# See all step keys for this phase
python3 orchestrator.py --phase 1 --list-steps
```

**What happens automatically:**
1. `host_sweep` — TCP SYN sweep across all `TARGET_SUBNETS` (parallel, one nmap per subnet). Uses `NMAP_DISCOVERY_PORTS` — **no ICMP or ARP** — to avoid false positives from network infrastructure. Hosts with no open ports on the discovery port list are not included in the live host list.
2. `nmap_fullscan` — Full port scan (`-p-`) split across `SYS_VCPUS` parallel nmap jobs for maximum throughput. A merge-watcher job auto-consolidates chunk results into `fullscan.gnmap` when all chunks finish.
3. `smb_sweep` — CrackMapExec SMB sweep — signing status, host enumeration
4. `ldap_banner` — LDAP rootDSE banner grab from DC
5. `ldap_users` — LDAP user enumeration → `userlist.txt`
6. `null_session` — SMB null session check
7. `bloodhound` — BloodHound data collection (`-c All`, `BH_WORKERS` parallel workers) as background job
8. `roadrecon` — ROADrecon Entra ID gather (background if password auth; foreground if device code)
9. `azure_inventory` — Azure resource inventory across all subscriptions (per-subscription JSON files, merged with `jq`)
10. _(optional)_ `host_sweep` step 10 — **Password spray** if `SPRAY_ENABLED=true`. Guarded against lockout: checks `SPRAY_MAX_ATTEMPTS` against the domain lockout threshold from Phase 2 output.

**Before confirming the full-port scan checkpoint:**
- Verify `live_hosts_all.txt` count is realistic for the network size
- If the count looks inflated, populate `SCAN_EXCLUDE_RANGES` in `config.env` with known infrastructure IPs and re-run `host_sweep`

**After background jobs complete:**
1. Check merge complete: `ls -lh ~/vapt/phase1/network/fullscan.gnmap`
2. Check BloodHound ZIP: `ls ~/vapt/phase1/ad/bloodhound/*.zip`
3. Confirm BloodHound CE is running: `bloodhound-cli status`; import the BloodHound ZIP into the UI at http://localhost:8080 (Administration → File Ingest)
4. Run key BloodHound queries:
   - Shortest path to Domain Admins
   - All Kerberoastable users
   - Users with DCSync rights
   - Computers with unconstrained delegation
5. Check ROADrecon DB: `ls -lh ~/vapt/phase1/cloud/roadrecon.db`
   - If empty/small (<50KB): set `ROADRECON_AUTH_METHOD=devicecode` and re-run Phase 1
6. Review relay targets: `cat ~/vapt/phase1/ad/relay_target_ips.txt`

**Key output files:**
| File | What to look for |
|------|-----------------|
| `phase1/network/live_hosts_all.txt` | Total count; should reflect real workstations/servers only |
| `phase1/network/fullscan.gnmap` | Open ports, service versions; assembled from parallel chunks |
| `phase1/network/nmap_merge.log` | Merge watcher progress; `MERGE COMPLETE` line confirms done |
| `phase1/ad/userlist.txt` | Total user count; service accounts (targets for Kerberoasting) |
| `phase1/ad/relay_target_ips.txt` | Non-empty = NTLM relay viable in Phase 3 |
| `phase1/ad/spray_results.txt` | Created only if `SPRAY_ENABLED=true` |
| `phase1/cloud/azure_inventory.json` | Resource count; unexpected resource types |

---

## 5. Phase 2 — Vulnerability Assessment

**Goal:** Identify vulnerabilities across AD, cloud, and web before attempting exploitation. Background jobs run in parallel.

**Run:**
```bash
python3 orchestrator.py --phase 2

# Skip ScoutSuite (already ran yesterday) and ZAP (no web targets in scope)
python3 orchestrator.py --phase 2 --skip scoutsuite,zap

# Run only AD checks (certipy + SMB vulns + password policy)
python3 orchestrator.py --phase 2 --only ad_checks

# See all step keys for this phase
python3 orchestrator.py --phase 2 --list-steps
```

**What happens automatically:**
1. `scoutsuite` — ScoutSuite Azure audit — one background job per subscription (25–45 min each)
2. `azure_security` — Azure targeted security checks: public blob access, NSG any-inbound rules, Key Vault policies, over-privileged role assignments, storage HTTPS enforcement, Conditional Access policies
3. `ad_checks` — AD security checks: Kerberoastable accounts, AS-REP roastable accounts, password policy, accessible shares, Domain Admins group, unconstrained delegation, password-never-expires accounts; **AD CS certipy** ESC1–ESC8; **SMB vuln modules** ms17-010, nopac, petitpotam
4. `zap` — OWASP ZAP DAST: baseline (passive) or full (active) web scan per URL in `WEB_TARGETS`
5. `nessus` — Nessus API trigger: authenticates, launches the pre-configured scan (`NESSUS_SCAN_ID` via `POST /scans/{ID}/launch`), saves the scan UUID to `nessus_scan_uuid.txt`, then deletes the session token. If `NESSUS_SCAN_ID` is not set, prompts the operator to launch manually.

**Operator actions during Phase 2:**
- Confirm ScoutSuite audit checkpoints
- While background jobs run:
  - Review BloodHound analysis from Phase 1
  - If Nessus was launched automatically, monitor scan progress in the Nessus UI
  - If Nessus was not configured, launch manually via the UI at `NESSUS_URL`
  - Begin Burp Suite manual testing of in-scope web apps
  - Run PingCastle from a Windows domain-joined machine
- Monitor ZAP scans: `tail -f ~/vapt/phase2/web/zap/<target>/zap.log`
- When ScoutSuite completes: `ls ~/vapt/phase2/cloud/scoutsuite/<sub-id>/report.html`

**Key findings to identify before Phase 3:**
| Finding type | Source file | Action if found |
|---|---|---|
| Kerberoastable accounts | `phase2/ad/ad_checks/kerberoastable_accounts.txt` | Note count; queue for Phase 3 |
| AS-REP roastable accounts | `phase2/ad/ad_checks/asrep_accounts.txt` | Note count; queue for Phase 3 |
| Unconstrained delegation | `phase2/ad/ad_checks/unconstrained_delegation.txt` | High finding; document immediately |
| AD CS ESC vulnerabilities | `phase2/ad/ad_checks/adcs/adcs_find.txt` | Critical if exploitable; note template names |
| Weak password policy | `phase2/ad/ad_checks/password_policy.txt` | Informs spray viability and cracking expectations |
| SMB vuln hits | `phase2/network/smb_vuln_checks.txt` | Critical; confirm with manual verification before Phase 3 |
| NSG any-inbound | `phase2/cloud/security_checks/nsg_any_inbound.txt` | Document ports and resources exposed |
| Public blobs | `phase2/cloud/security_checks/public_blob_access.txt` | Evidence; access and document contents |
| ZAP alerts | `phase2/web/zap/<target>/zap_report.html` | Review by severity; queue critical for manual verification |

---

## 6. Phase 3 — Exploitation

**Goal:** Obtain valid credentials, achieve initial access, demonstrate impact of identified vulnerabilities. Every destructive action requires operator confirmation.

> **Before running Phase 3**, confirm with the emergency contact that exploitation activity is starting.

**Run:**
```bash
python3 orchestrator.py --phase 3

# Responder already running from an earlier session — skip it
python3 orchestrator.py --phase 3 --skip responder --only kerberoast,asrep,hashcat

# Hashes cracked — run only PtH sweep (provide hash at OBTAINED_HASH prompt)
python3 orchestrator.py --phase 3 --only pth_sweep

# See all step keys for this phase
python3 orchestrator.py --phase 3 --list-steps
```

**What happens automatically (with checkpoints):**
1. Responder started (background, runs for `RESPONDER_DURATION` seconds)
2. Kerberoasting — TGS ticket request for all Kerberoastable accounts
3. AS-REP Roasting — AS-REP hash request for pre-auth disabled accounts
4. `hashcat` — Hashcat NTLMv2 cracking: 3 parallel background jobs (rockyou, rockyou+rules, corporate patterns), each writing to its own output file. Results merged into `cracked_ntlm.txt`. Jobs use `-w ${HC_WORKLOAD} --optimized-kernel-enable` tuned to detected vCPU count.
5. `hashcat` — Hashcat TGS cracking (if Kerberoast tickets obtained)
6. `hashcat` — Hashcat AS-REP cracking (if AS-REP hashes obtained)
7. `ntlm_relay` — NTLM relay setup (if relay targets exist) — requires operator target confirmation
8. `pth_sweep` — Pass-the-Hash sweep (if `OBTAINED_HASH` was provided at prompt)
9. `azure_storage` — Azure public storage container access check (PoC)

**Operator actions during Phase 3:**
- Confirm Responder start checkpoint
- Monitor Responder for captures: `watch -n 30 'ls /usr/share/responder/logs/SMB-NTLMv2-*.txt 2>/dev/null | wc -l'`
- While cracking runs in background, perform BloodHound attack path analysis
- When NTLM relay checkpoint appears: review `relay_target_ips.txt`, confirm targets with operator judgment
- As hashes are cracked, re-run Phase 3 with `OBTAINED_HASH` to trigger PtH sweep:
  ```bash
  python3 orchestrator.py --phase 3
  # At "OBTAINED_HASH" prompt: paste the cracked NTLM hash
  ```
- Manually select and execute Metasploit CVE PoCs for confirmed CVE findings (one at a time, with human oversight)

**Monitoring cracking jobs:**
```bash
# Per-wordlist progress logs
tail -f ~/vapt/phase3/ad/hashcat_ntlm.log          # rockyou job
tail -f ~/vapt/phase3/ad/hashcat_ntlm_rules.log    # rules job
tail -f ~/vapt/phase3/ad/hashcat_ntlm_corporate.log # corporate patterns job

# Merged results (auto-updated as jobs complete)
cat ~/vapt/phase3/ad/cracked_ntlm.txt

# Kerberoast and AS-REP
tail -f ~/vapt/phase3/ad/hashcat_tgs.log
cat ~/vapt/phase3/ad/cracked_tgs.txt
```

---

## 7. Phase 4 — Post-Exploitation

**Goal:** Demonstrate the blast radius of obtained credentials — lateral movement, SAM dump, DCSync proof-of-concept. Every hop requires explicit operator confirmation.

> **Before running Phase 4**, confirm the blast radius scope with the Management Sponsor. Document which systems are authorised for lateral movement.

**Run:**
```bash
python3 orchestrator.py --phase 4

# Skip DCSync and lateral movement — run blast radius assessment only
python3 orchestrator.py --phase 4 --only azure_blast_radius,blast_summary

# Skip SAM sweep (no PtH hosts confirmed yet)
python3 orchestrator.py --phase 4 --skip sam_sweep

# See all step keys for this phase
python3 orchestrator.py --phase 4 --list-steps
```

**What happens automatically (with checkpoints):**
1. `sam_sweep` — CrackMapExec sweep across all confirmed PtH-accessible hosts (system info + local admins)
2. `sam_sweep` — SAM dump on confirmed admin hosts (per-host checkpoint)
3. Blast radius log initialised (`blast_radius.md`)
4. `lateral_move` — Interactive lateral movement loop (operator selects targets, tool, credentials)
5. `dcsync` — DCSync PoC (maximum gate — BloodHound path confirmation required; krbtgt is blocked)
6. `azure_blast_radius` — Azure blast radius documentation (accessible resources from current identity)
7. `blast_summary` — Blast radius summary report generated

**DCSync gate:**
The framework blocks DCSync against `krbtgt` and requires explicit account name input. Only run DCSync if BloodHound has confirmed a DCSync path exists. Target a **test or non-sensitive account** to prove the capability — do not dump the entire directory.

**Operator actions during Phase 4:**
- For each lateral movement hop: explicitly confirm the target, credential type, and tool
- Document each hop in the blast radius log via the interactive prompts
- After each confirmed access: collect screenshots for evidence
- If access reaches a Tier-0 asset (DC, Certificate Authority, Azure Global Admin): **STOP, document, notify Management Sponsor immediately**

---

## 8. Phase 5 — Reporting and Debrief

**Goal:** Consolidate all evidence into the report directory and generate a pre-filled report scaffold. All writing is manual.

**Run:**
```bash
python3 orchestrator.py --phase 5
```

**What happens automatically:**
1. Evidence files copied from all phases into `~/vapt/report/evidence/{network,ad,cloud,web,cracked}/`
2. Finding counts pre-populated in the scaffold (cracked hashes, PtH hosts, delegation issues, AD CS hits, ZAP alerts, SMB vuln hits, etc.)
3. Report scaffold generated: `~/vapt/report/TECHNICAL_REPORT_SCAFFOLD.md`
4. SHA-256 integrity manifest generated: `~/vapt/report/evidence_manifest.sha256` — checksums every evidence file for chain-of-custody

**Operator actions (all manual):**
1. Open `TECHNICAL_REPORT_SCAFFOLD.md` and complete every `[COMPLETE MANUALLY]` section
2. Write the Executive Summary in plain business language (2–3 paragraphs, no jargon)
3. For each finding:
   - Assign severity (CRITICAL/HIGH/MEDIUM/LOW) and CVSS 3.1 score
   - Reference the specific evidence file and add a screenshot
   - Write business impact in terms of data, financial, or operational risk
   - Write specific, numbered remediation steps with responsible team
   - Map to MITRE ATT&CK technique
4. Proofread and have a colleague review before delivery
5. Prepare debrief slide deck from the top 5 findings
6. Schedule debrief with Elizabeth A. and Titilope G.

**Report delivery checklist:**
- [ ] All `[COMPLETE MANUALLY]` placeholders filled
- [ ] Executive summary reviewed by management sponsor before delivery
- [ ] Evidence files for every finding confirmed present in `report/evidence/`
- [ ] CVSS scores calculated and justified
- [ ] MITRE ATT&CK coverage table completed
- [ ] Remediation roadmap agreed with each responsible team
- [ ] Debrief session scheduled and slide deck prepared
- [ ] Report classified and sent via approved secure channel only

---

## 9. Background Job Monitoring Reference

| Job | Log file | Check command | Done signal |
|-----|----------|--------------|-------------|
| Nmap chunk scans (×vCPUs) | `phase1/network/scan_chunks/fullscan_chunk_<id>.log` | `tail -f <log>` | Per-chunk `.xml` files appear |
| Nmap merge watcher | `phase1/network/nmap_merge.log` | `tail -f <log>` | `MERGE COMPLETE` line; `fullscan.gnmap` appears |
| BloodHound collect | `phase1/ad/bloodhound_collect.log` | `tail -f <log>` | `*.zip` in `phase1/ad/bloodhound/` |
| ROADrecon | `phase1/cloud/roadrecon.log` | `tail -f <log>` | `roadrecon.db` > 50KB |
| Azure inventory | `phase1/cloud/azure_inventory.log` | `tail -f <log>` | `azure_inventory.json` appears |
| ScoutSuite (per sub) | `phase2/cloud/scoutsuite_<sub>.log` | `tail -f <log>` | `scoutsuite/<sub>/report.html` appears |
| ZAP (per target) | `phase2/web/zap/<target>/zap.log` | `tail -f <log>` | `zap_report.html` appears |
| Responder | `/usr/share/responder/logs/` | `watch -n 30 'ls ...NTLMv2*.txt \| wc -l'` | Capture files appear — **stop at `TESTING_WINDOW_END`** |
| Hashcat NTLMv2 (×3 jobs) | `phase3/ad/hashcat_ntlm*.log` | `tail -f <log>` | `cracked_ntlm_*.txt` populated; merged into `cracked_ntlm.txt` |
| Hashcat TGS | `phase3/ad/hashcat_tgs.log` | `tail -f <log>` | `cracked_tgs.txt` populated |

> **Network vs offline jobs:** Hashcat, nmap, and ScoutSuite are all terminal-safe — they survive terminal close via `nohup`/`disown`. Responder is an active network poisoner and **must stop at `TESTING_WINDOW_END`** regardless of terminal state. It is auto-stopped via `atd` scheduling when started.

---

## 9b. Selective Step Execution Reference

Use `--skip` or `--only` to control exactly which steps run within a phase. This is useful when:
- A background job is already running from a previous session (skip it)
- You only need to re-run one specific check (use `--only`)
- Certain steps are out of scope for this engagement
- A step failed and you want to re-run just that step

### Quick reference

```bash
# List every skippable step key across all phases
python3 orchestrator.py --list-steps

# List step keys for one phase only
python3 orchestrator.py --phase 2 --list-steps

# Skip one step
python3 orchestrator.py --phase 1 --skip nmap_fullscan

# Skip multiple steps (comma-separated, no spaces)
python3 orchestrator.py --phase 2 --skip scoutsuite,zap,nessus

# Run only these steps, skip everything else in the phase
python3 orchestrator.py --phase 1 --only bloodhound,roadrecon

# --skip and --only cannot be combined — use one or the other
```

### All step keys by phase

| Phase | Key | Description |
|-------|-----|-------------|
| 1 | `host_sweep` | TCP SYN host sweep across all subnets (no ICMP/ARP — avoids infrastructure false positives) |
| 1 | `nmap_fullscan` | Full port scan -p- split across vCPU parallel jobs; merge watcher auto-consolidates results |
| 1 | `smb_sweep` | CrackMapExec SMB sweep + signing check |
| 1 | `ldap_banner` | LDAP rootDSE banner grab from DC |
| 1 | `ldap_users` | LDAP domain user enumeration |
| 1 | `null_session` | SMB null session check |
| 1 | `bloodhound` | BloodHound data collection |
| 1 | `roadrecon` | ROADrecon Entra ID gather |
| 1 | `azure_inventory` | Azure resource inventory across subscriptions |
| 2 | `scoutsuite` | ScoutSuite Azure audit (per subscription) |
| 2 | `azure_security` | Azure targeted security checks (MFA, RBAC, storage, NSG, KeyVault) |
| 2 | `ad_checks` | AD checks: password policy, Kerberoastable accounts, certipy AD CS, SMB vulns |
| 2 | `zap` | OWASP ZAP web DAST scan |
| 2 | `nessus` | Nessus credentialed scan trigger via API |
| 3 | `responder` | Responder LLMNR/NBT-NS poisoning (background) |
| 3 | `kerberoast` | Kerberoasting — TGS ticket request for SPN accounts |
| 3 | `asrep` | AS-REP Roasting — accounts with pre-auth disabled |
| 3 | `hashcat` | Hashcat cracking jobs (NTLMv2, TGS, AS-REP) |
| 3 | `ntlm_relay` | NTLM relay setup (Responder relay mode + ntlmrelayx) |
| 3 | `pth_sweep` | Pass-the-Hash sweep with obtained hash |
| 3 | `azure_storage` | Azure public storage container check |
| 4 | `sam_sweep` | Automated SAM dump on confirmed PtH hosts |
| 4 | `lateral_move` | Interactive PsExec / WMIexec lateral movement |
| 4 | `dcsync` | DCSync PoC (maximum gate) |
| 4 | `azure_blast_radius` | Azure blast radius assessment from compromised identity |
| 4 | `blast_summary` | Blast radius summary report generation |

### How it interacts with idempotency

`--skip` / `--only` and file-based idempotency (`skip_if_exists`) are independent and layer on top of each other:

- `--skip nmap_fullscan` → skips the step regardless of whether `fullscan.gnmap` exists
- No flag, `fullscan.gnmap` exists → `skip_if_exists` skips it automatically
- No flag, `fullscan.gnmap` missing → step runs normally

To force a full-port scan to re-run even if its output already exists, delete the merged output and the chunk directory:
```bash
rm -rf ~/vapt/phase1/network/fullscan.gnmap ~/vapt/phase1/network/scan_chunks/
python3 orchestrator.py --phase 1 --only nmap_fullscan
```

---

## 9a. Session Management — Terminal Safety and Job Continuity

### Why jobs survive terminal close

All background jobs are launched with `nohup` + `disown` via `bg_run()` in `lib/common.sh`:

- **`nohup`** — blocks SIGHUP so the job continues when the terminal closes
- **`disown`** — removes the job from bash's job table
- **`.bg_jobs`** — every PID is written to `${OUTPUT_BASE_DIR}/.bg_jobs` so `--status` can track completion across sessions

Background jobs run as fast as the system allows — they are not designed to be "set and wait". Check `--status` regularly and proceed to the next phase as soon as current-phase jobs complete.

### tmux (recommended for SSH sessions)

```bash
# Start a named session
tmux new-session -d -s vapt
tmux attach -t vapt

# Run phases inside tmux
python3 orchestrator.py --phase 1

# Detach without stopping anything (Ctrl+B then D)

# Re-attach from any SSH client
tmux attach -t vapt

# Check status without re-attaching
python3 orchestrator.py --status
```

If the machine is local (no SSH), `nohup`/`disown` alone is sufficient — tmux is optional.

### Job status check

```bash
python3 orchestrator.py --status
```

Output example:
```
════════════════════════════════════════════════════════════════
  Phase Completion Summary
════════════════════════════════════════════════════════════════
  Phase 0  ✔  Complete    Pre-Engagement Setup
  Phase 1  ⏳ In Progress  Reconnaissance & Discovery
  Phase 2  ✘  Not Started  Vulnerability Assessment
...
════════════════════════════════════════════════════════════════
  Background Job Status
════════════════════════════════════════════════════════════════

  ✔  COMPLETE   nmap_fullscan_chunk_aa (PID: 12345)
  ✔  COMPLETE   nmap_fullscan_chunk_ab (PID: 12346)
  ⏳ RUNNING    nmap_fullscan_merge (PID: 12400)
     Log:     .../phase1/network/nmap_merge.log
...
  Completed: 5   Still running: 1
════════════════════════════════════════════════════════════════
```

### Resuming interrupted phases

The framework is fully idempotent. Re-running any phase picks up from where it stopped — `skip_if_exists()` skips steps whose output file already exists.

```bash
# Nmap finished, BloodHound was interrupted — re-run phase 1
# nmap steps are skipped (fullscan.gnmap exists), BloodHound resumes
python3 orchestrator.py --phase 1
```

### Responder auto-stop (RoE requirement)

Responder is an active network poisoner and **must stop at `TESTING_WINDOW_END`** (default 17:00) per the RoE. The framework schedules an automatic kill via `atd`:

```bash
# Verify the kill job is queued after starting Responder:
atq

# If atd is not available:
sudo systemctl enable atd --now
```

If `atd` is unavailable, Phase 3 prints the manual kill command and logs a warning. Verify:
```bash
grep 'auto-stop\|REMINDER\|Responder' "${OUTPUT_BASE_DIR}/engagement_log.md"
```

### Re-running a job outside business hours

To restart a non-network job (Hashcat, merge watcher) outside the testing window:

```bash
# Temporarily disable the window gate (edit config.env)
# ENFORCE_TESTING_WINDOW=false
python3 orchestrator.py --phase 3 --only hashcat
```

---

**Recommended daily schedule:**

| Time | Action |
|------|--------|
| Start of day | `python3 orchestrator.py --status` — check what completed |
| +5 min | Start BloodHound CE if not running: `bloodhound-cli start` |
| `TESTING_WINDOW_START` | `python3 orchestrator.py --phase <today>` |
| +5 min | Background jobs start / resume (Nmap chunks, ScoutSuite, Hashcat, ZAP) |
| Active hours | BloodHound analysis, Burp testing, manual AD checks, review cracked hashes as they appear |
| Active hours | Exploitation / lateral movement (phases 3–4, operator-gated) |
| 30 min before `TESTING_WINDOW_END` | Verify Responder `atq` shows stop job queued; update `engagement_log.md` |
| `TESTING_WINDOW_END` | Active attacks stop. Non-network jobs (Hashcat) continue. Detach tmux or close terminal. |

---

## 10. Troubleshooting

### Docker fails to install

**Symptom:** `sudo apt-get install docker-ce` fails with "Package not found"

**Cause:** Docker CE apt repository not added, or GPG key missing.

**Fix:** Phase 0 handles this automatically via `ensure_docker()`. If it fails manually:
```bash
# Verify the Docker apt source was added
cat /etc/apt/sources.list.d/docker.list

# Verify GPG key
ls /etc/apt/keyrings/docker.gpg

# If missing, re-run Phase 0 which will add them
python3 orchestrator.py --phase 0
```

### `docker compose` not found / compose errors

**Symptom A:** `docker compose version` fails but `docker-compose --version` works.

**Cause:** Docker CE compose v2 plugin is not installed. The framework auto-detects and falls back to `docker-compose` v1 via `detect_docker_compose()` in `lib/common.sh`. v1 is functional but deprecated.

**Fix (preferred):**
```bash
sudo apt-get install docker-compose-plugin
docker compose version   # should now work
```

**Symptom B:** Both `docker compose` and `docker-compose` fail with "Permission denied".

**Cause:** Current user is not in the `docker` group (or group membership not yet active in this session).

**Fix:**
```bash
sudo usermod -aG docker "$USER"
newgrp docker   # apply without logging out
docker ps       # should work without sudo
```

**Symptom C:** Phase 0 is using the Ubuntu-packaged Docker (`docker.io`) instead of Docker CE.

**Check:** `apt-cache policy docker-ce` — if "none" is shown, Docker CE is not installed.

**Fix:** Re-run Phase 0 — `ensure_docker()` installs Docker CE from the upstream repo and removes `docker.io`.

### pip_install fails for a tool

**Symptom:** `pipx install bloodhound` fails; tool not found after Phase 0.

**Cause:** pipx `~/.local/bin` not on PATH in current session (pipx ensurepath only updates .bashrc).

**Fix:**
```bash
export PATH="${HOME}/.local/bin:${PATH}"
# Verify
command -v bloodhound-python
```
Add `export PATH="${HOME}/.local/bin:${PATH}"` to `~/.bashrc` or `~/.zshrc` permanently.

### ROADrecon database is empty after Phase 1

**Symptom:** `roadrecon.db` exists but is very small (< 50KB); no data in ROADrecon GUI.

**Cause:** Tenant has MFA or Conditional Access — basic password auth was rejected silently.

**Fix:** Set `ROADRECON_AUTH_METHOD=devicecode` in `config.env` and re-run Phase 1. ROADrecon will prompt for browser authentication interactively.

### ScoutSuite produces empty report

**Symptom:** `report.html` exists but shows 0 services or errors in the ScoutSuite log.

**Cause 1:** Azure CLI session expired. **Fix:** `az login --tenant <AZURE_TENANT_ID> --use-device-code`

**Cause 2:** Service principal / user account lacks Reader access on the subscription.
**Fix:** Confirm Azure Reader role assignment: `az role assignment list --assignee <user> --subscription <sub-id>`

### Responder not capturing hashes

**Symptom:** `/usr/share/responder/logs/SMB-NTLMv2-*.txt` files are empty or not created.

**Cause 1:** Wrong interface in `ATTACKER_INTERFACE`. **Fix:** `ip addr show` and confirm the interface with LAN access. Update config.

**Cause 2:** LLMNR/NBT-NS is already disabled via GPO (good posture — document as finding).

**Cause 3:** Attacker machine is not on the same broadcast domain as targets. **Fix:** Confirm Layer 2 adjacency.

### Hashcat exits immediately with "No hashes loaded"

**Symptom:** `hashcat_ntlm.log` shows "No hashes loaded" on the first line.

**Cause:** `ntlmv2_all.txt` is empty — Responder has not captured any hashes yet.

**Fix:** This is expected if Responder just started. Wait for hashes to accumulate, then re-run Phase 3.

### BloodHound CE: "too many colons in address" (Neo4j IPv6 bolt error)

**Symptom:** BloodHound container log shows a graph migration error with "too many colons in address". Neo4j bolt IS listening (`ss -tlnp | grep 7687`).

**Root cause:** The host kernel has IPv6 enabled. Neo4j's JVM binds a dual-stack socket on `:::7687` and reports the unspecified IPv6 address (`::7687`) in its bolt routing table. BloodHound's Go bolt client rejects this address format.

**Fix (automated):** `tools/bloodhound-ce/docker-compose.yml` now includes `sysctls` to disable IPv6 inside the Neo4j container's network namespace. If BloodHound CE was started via `bloodhound-cli` (Phase 0 default), this compose file is not used directly — `bloodhound-cli` manages its own stack. Restart via `bloodhound-cli`:

```bash
bloodhound-cli stop
bloodhound-cli start

# Check logs if still failing
bloodhound-cli logs
```

If you are running the manual docker-compose stack from `tools/bloodhound-ce/`:
```bash
docker compose -f tools/bloodhound-ce/docker-compose.yml down
docker compose -f tools/bloodhound-ce/docker-compose.yml up -d
# The sysctls in the updated compose file disable IPv6 in the Neo4j container
```

### BloodHound CE cannot be reached at http://localhost:8080

**Symptom:** Browser shows connection refused.

**Fix:**
```bash
# Check stack status
bloodhound-cli status

# Check for port conflict
ss -tlnp | grep 8080

# Restart
bloodhound-cli stop
bloodhound-cli start

# Follow logs
bloodhound-cli logs
```

### Testing window blocked outside business hours

**Symptom:** Framework prints `Testing blocked outside hours` and exits.

**Fix:** Override at the prompt by entering `y`. Document the override in the engagement log with reason.

---

## 11. Emergency Stop Procedure

Use this procedure if you need to halt all testing immediately (incident response, operator error, out-of-bounds access, or explicit management instruction).

1. **In the orchestrator terminal:** Press `Ctrl+C`
   - This triggers `cleanup_on_exit` which kills all tracked background processes.

2. **Kill any remaining background processes:**
   ```bash
   sudo pkill -f "responder" 2>/dev/null
   pkill -f "hashcat|nmap|bloodhound-python|roadrecon|scout|zaproxy" 2>/dev/null
   ```

3. **Stop Docker-based tools:**
   ```bash
   bloodhound-cli stop 2>/dev/null
   docker stop $(docker ps -q) 2>/dev/null
   ```

4. **Document the stop in the engagement log:**
   ```bash
   echo "## [$(date '+%Y-%m-%d %H:%M:%S')] EMERGENCY STOP — Reason: <describe reason>" \
       >> ~/vapt/engagement_log.md
   ```

5. **Contact:** Management Sponsor (Elizabeth A.) immediately. Do not wait to document first.

6. **Preserve evidence:** Do not delete any output files — they may be needed for incident investigation.

---

## 12. Post-Engagement Cleanup

After the final report has been delivered and accepted:

```bash
# 1. Stop BloodHound CE and remove its data
bloodhound-cli stop
# To also wipe collected AD data (volumes), use bloodhound-cli uninstall or remove volumes manually:
# docker volume ls | grep bloodhound | awk '{print $2}' | xargs docker volume rm

# 2. Remove cracked credentials and hashes
shred -uz ~/vapt/phase3/ad/cracked_*.txt
shred -uz ~/vapt/phase3/ad/ntlmv2_all.txt
shred -uz ~/vapt/phase3/ad/*.txt

# 3. Archive the output directory (encrypt before storing)
tar -czf ~/vapt-$(date +%Y%m%d).tar.gz ~/vapt/
gpg --symmetric --cipher-algo AES256 ~/vapt-$(date +%Y%m%d).tar.gz
shred -uz ~/vapt-$(date +%Y%m%d).tar.gz

# 4. Remove config.env (contains engagement details)
shred -uz ~/vapt-automation/config.env

# 5. Remove Responder logs
sudo shred -uz /usr/share/responder/logs/SMB-NTLMv2-*.txt 2>/dev/null || true

# 6. Revoke test accounts
# Notify Infrasec team to disable the test domain account used during the engagement.
# Notify Cloud Platform to remove Azure Reader role from the test account.
```

> Retain the encrypted archive for the period specified in your data retention policy. The plaintext `~/vapt/` directory must not remain on the attack machine after cleanup.
