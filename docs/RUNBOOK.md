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
- [ ] DC IP confirmed reachable: `ping <DC_IP>`
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
6. BloodHound CE Docker stack started (Postgres + Neo4j + BloodHound UI)
7. Azure CLI login checked; device code flow initiated if not logged in
8. DC reachability checked
9. Scope JSON written to `~/vapt/phase0/scope.json`

**Operator actions during Phase 0:**
- Confirm each checkpoint prompt (tool install, Azure login)
- When Azure device code appears: open the browser, authenticate, return to terminal
- After Phase 0: retrieve BloodHound CE first-run password:
  ```bash
  docker compose -f tools/bloodhound-ce/docker-compose.yml logs bloodhound \
      2>&1 | grep -i 'initial password\|password'
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

**Goal:** Map live hosts, enumerate AD users and structure, collect BloodHound data, enumerate Entra ID and Azure resources. Background jobs will run for 3–5 hours.

**Run:**
```bash
python3 orchestrator.py --phase 1
```

**What happens automatically:**
1. Host sweep across all `TARGET_SUBNETS` (parallel, one Nmap `-sn` per subnet)
2. Full port scan launched as background job against live hosts (runs overnight)
3. CrackMapExec SMB sweep — signs, shares, SMB signing status
4. LDAP rootdse banner grab
5. LDAP user enumeration → `userlist.txt`
6. SMB null session check
7. BloodHound data collection (`-c All`) as background job
8. ROADrecon Entra ID gather (background if password auth; foreground if device code)
9. Azure resource inventory across all subscriptions (per-subscription JSON files merged)

**Operator actions during Phase 1:**
- Confirm the full port scan checkpoint (it will run overnight — confirm before EOD)
- While background jobs run, begin manual BloodHound analysis prep
- At EOD: verify background jobs are still running:
  ```bash
  python3 orchestrator.py --status
  tail -f ~/vapt/phase1/network/fullscan.log
  ```

**Next morning (before Phase 2):**
1. Check full scan completed: `ls -lh ~/vapt/phase1/network/fullscan.xml`
2. Check BloodHound ZIP exists: `ls ~/vapt/phase1/ad/bloodhound/*.zip`
3. Import BloodHound ZIP into UI at http://localhost:8080
4. Run key BloodHound queries (see playbook):
   - Shortest path to Domain Admins
   - All Kerberoastable users
   - Users with DCSync rights
   - Computers with unconstrained delegation
5. Check ROADrecon DB: `ls -lh ~/vapt/phase1/cloud/roadrecon.db`
   - If empty or missing: ROADrecon auth failed — re-run with `ROADRECON_AUTH_METHOD=devicecode`
6. Review relay targets: `cat ~/vapt/phase1/ad/relay_target_ips.txt`

**Key output files:**
| File | What to look for |
|------|-----------------|
| `phase1/network/live_hosts_all.txt` | Total count; unexpected ranges |
| `phase1/network/fullscan.xml` | Open ports, service versions, script output |
| `phase1/ad/userlist.txt` | Total user count; service accounts |
| `phase1/ad/relay_target_ips.txt` | Non-empty = NTLM relay is viable in Phase 3 |
| `phase1/cloud/azure_inventory.json` | Resource count; unexpected resource types |

---

## 5. Phase 2 — Vulnerability Assessment

**Goal:** Identify vulnerabilities across AD, cloud, and web before attempting exploitation. Background jobs run in parallel.

**Run:**
```bash
python3 orchestrator.py --phase 2
```

**What happens automatically:**
1. ScoutSuite Azure audit — one background job per subscription (25–45 min each)
2. Azure targeted security checks: public blob access, NSG any-inbound rules, Key Vault policies, over-privileged role assignments, storage HTTPS enforcement, Conditional Access policies
3. AD security checks: Kerberoastable accounts, AS-REP roastable accounts, password policy, accessible shares, Domain Admins group, unconstrained delegation, password-never-expires accounts
4. **AD CS (certipy)**: ESC1–ESC8 certificate template misconfiguration checks
5. **SMB vulnerability modules**: ms17-010, nopac, petitpotam
6. **OWASP ZAP DAST**: baseline (passive) or full (active) web scan per URL in `WEB_TARGETS`
7. Nessus API trigger (if configured)

**Operator actions during Phase 2:**
- Confirm ScoutSuite audit checkpoints
- While background jobs run:
  - Review BloodHound analysis from Phase 1
  - Launch Nessus/OpenVAS credentialed scan via UI (start at beginning of Phase 2 day)
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
```

**What happens automatically (with checkpoints):**
1. Responder started (background, runs for `RESPONDER_DURATION` seconds)
2. Kerberoasting — TGS ticket request for all Kerberoastable accounts
3. AS-REP Roasting — AS-REP hash request for pre-auth disabled accounts
4. Hashcat NTLMv2 cracking (3 background jobs: rockyou, rules, corporate patterns)
5. Hashcat TGS cracking (if tickets obtained)
6. Hashcat AS-REP cracking (if hashes obtained)
7. NTLM relay setup (if relay targets exist) — requires operator target confirmation
8. Pass-the-Hash sweep (if `OBTAINED_HASH` was provided at prompt)
9. Azure public storage container access check (PoC)

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
# Check cracked NTLM hashes
tail -f ~/vapt/phase3/ad/hashcat_ntlm.log
cat ~/vapt/phase3/ad/cracked_ntlm.txt

# Check Kerberoast cracking
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
```

**What happens automatically (with checkpoints):**
1. CrackMapExec sweep across all confirmed PtH-accessible hosts (system info + local admins)
2. SAM dump on confirmed admin hosts (per-host checkpoint)
3. Blast radius log initialised (`blast_radius.md`)
4. Interactive lateral movement loop (operator selects targets, tool, credentials)
5. DCSync PoC (maximum gate — BloodHound path confirmation required; krbtgt is blocked)
6. Azure blast radius documentation (accessible resources from current identity)
7. Blast radius summary report generated

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
- Evidence files copied from all phases into `~/vapt/report/evidence/`
- Finding counts pre-populated (cracked hashes, PtH hosts, delegation issues, AD CS hits, ZAP alerts, etc.)
- Report scaffold generated at `~/vapt/report/TECHNICAL_REPORT_SCAFFOLD.md`

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
| Nmap full scan | `phase1/network/fullscan.log` | `tail -f <log>` | `fullscan.xml` appears |
| BloodHound collect | `phase1/ad/bloodhound_collect.log` | `tail -f <log>` | `*.zip` in `phase1/ad/bloodhound/` |
| ROADrecon | `phase1/cloud/roadrecon.log` | `tail -f <log>` | `roadrecon.db` > 0 bytes |
| Azure inventory | `phase1/cloud/azure_inventory.log` | `tail -f <log>` | `azure_inventory.json` appears |
| ScoutSuite (per sub) | `phase2/cloud/scoutsuite_<sub>.log` | `tail -f <log>` | `scoutsuite/<sub>/report.html` appears |
| ZAP (per target) | `phase2/web/zap/<target>/zap.log` | `tail -f <log>` | `zap_report.html` appears |
| Responder | `/usr/share/responder/logs/` | `watch -n 30 'ls ... \| wc -l'` | Captures appear in logs dir |
| Hashcat NTLMv2 | `phase3/ad/hashcat_ntlm.log` | `tail -f <log>` | `cracked_ntlm.txt` populated |
| Hashcat TGS | `phase3/ad/hashcat_tgs.log` | `tail -f <log>` | `cracked_tgs.txt` populated |

**Recommended daily schedule:**

| Time | Action |
|------|--------|
| 08:50 | Start attack machine, verify Azure login (`az account show`) |
| 08:55 | Start BloodHound CE if not running: `docker compose -f tools/bloodhound-ce/docker-compose.yml up -d` |
| 09:00 | `python3 orchestrator.py --phase <today>` |
| 09:05 | Background jobs start (Nmap, ScoutSuite, Responder, Hashcat, ZAP) |
| 09:10–12:00 | Active work: BloodHound analysis, Burp testing, manual AD checks |
| 12:00 | Check background job status; review any cracked hashes |
| 13:00–16:30 | Active exploitation / lateral movement (with operator gates) |
| 16:30 | Start overnight background jobs (confirm Nmap, Hashcat still running) |
| 16:55 | Log work in `engagement_log.md`; confirm background jobs running |
| 17:00 | Leave overnight jobs running; check logs tomorrow |

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

### `docker compose` not found (only `docker-compose`)

**Symptom:** `docker compose version` fails; `docker-compose --version` works.

**Cause:** docker-compose v1 (standalone binary) is installed, not the v2 plugin.

**Fix:**
```bash
sudo apt-get install docker-compose-plugin
# Verify
docker compose version
```

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

### BloodHound CE cannot be reached at http://localhost:8080

**Symptom:** Browser shows connection refused.

**Fix:**
```bash
# Check if stack is running
docker compose -f tools/bloodhound-ce/docker-compose.yml ps

# Check for port conflict
ss -tlnp | grep 8080

# Restart stack
docker compose -f tools/bloodhound-ce/docker-compose.yml down
docker compose -f tools/bloodhound-ce/docker-compose.yml up -d

# Follow startup logs
docker compose -f tools/bloodhound-ce/docker-compose.yml logs -f bloodhound
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
   docker compose -f tools/bloodhound-ce/docker-compose.yml down 2>/dev/null
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
# 1. Stop BloodHound CE
docker compose -f tools/bloodhound-ce/docker-compose.yml down -v
# The -v flag removes the Postgres and Neo4j volumes (deletes all collected AD data)

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
