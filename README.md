# Ha-Shem VAPT Automation Framework

**Classification:** INTERNAL — Infrastructure Security Team  
**Platform:** Kali Linux (2023.x+)  
**Engagement scope:** Internal network, Active Directory, Azure / Entra ID, Web applications  
**Maintained by:** Infrastructure Security Team

---

## Overview

This framework automates the repeatable, mechanical work of an internal Vulnerability Assessment and Penetration Test (VAPT) so that operator time is spent on analysis, judgment, and reporting — not on typing the same commands across multiple tools. It is not a fire-and-forget scanner. Every destructive or sensitive action has an explicit human checkpoint that requires operator confirmation before proceeding.

The framework covers six phases:

| Phase | Name | Automation level | Timeline |
|-------|------|-----------------|----------|
| 0 | Pre-Engagement Setup | Full | Days 1–2 |
| 1 | Reconnaissance & Discovery | Full (bg jobs) | Days 3–4 |
| 2 | Vulnerability Assessment | Full (bg jobs) | Days 5–7 |
| 3 | Exploitation | Partial | Days 8–11 |
| 4 | Post-Exploitation | Partial | Days 9–11 |
| 5 | Reporting & Debrief | Full (scaffold + evidence) | Days 12–14 |

**What is automated:** host sweeps, full port scans, SMB enumeration, LDAP enumeration, BloodHound collection, ROADrecon Entra ID gather, Azure resource inventory, ScoutSuite cloud audit, AD CS vulnerability checks (certipy), SMB vulnerability modules, Kerberoasting, AS-REP roasting, Responder poisoning, Hashcat cracking, Pass-the-Hash sweeps, Azure public storage proofs-of-concept, OWASP ZAP web scanning, SAM dump sweeps, blast radius documentation, evidence consolidation, report scaffolding.

**What stays manual:** every lateral movement decision, BloodHound path selection, NTLM relay target confirmation, DCSync execution, Metasploit CVE exploitation, Burp Suite manual testing, all report writing.

---

## Prerequisites

### Hardware and OS

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Kali Linux 2023.1 | Kali Linux 2024.x |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB free | 100 GB free |
| CPU | 4 cores | 8 cores (GPU preferred for Hashcat) |
| Network | Internal network access | Dedicated attack VLAN |

### Accounts and access required before Day 1

- [ ] Signed Rules of Engagement document from all 6 parties
- [ ] One domain user account (read-only minimum) for AD enumeration
- [ ] Azure / Entra ID reader-level access for the target tenant
- [ ] Nessus access (if using API trigger) — URL, username, password, pre-configured scan ID
- [ ] Emergency stop contact confirmed (see `EMERGENCY_CONTACT` in `config.env`)

### Tools installed by Phase 0

Phase 0 (`phases/phase0_setup.sh`) installs and verifies everything automatically. The following are installed via apt (Docker CE) or pipx (Python tools):

| Tool | Installed via | Purpose |
|------|--------------|---------|
| nmap | apt | Host sweep, full port scan, LDAP banner grab |
| nxc / crackmapexec | apt | SMB enumeration, PtH sweep, SAM dump |
| responder | apt | LLMNR/NBT-NS poisoning, NTLMv2 capture |
| hashcat | apt | Password cracking (NTLMv2, TGS, AS-REP) |
| ldap-utils | apt | LDAP queries (ldapsearch) |
| docker-ce + compose plugin | Docker CE repo | BloodHound CE, OWASP ZAP |
| azure-cli | apt / Microsoft | Azure / Entra ID enumeration |
| bloodhound-python | pipx | BloodHound data collection |
| roadrecon | pipx | Entra ID / ROADtools gather |
| scoutsuite | pipx | Azure cloud security audit |
| impacket | pipx | Kerberoasting, AS-REP, PsExec, secretsdump |
| certipy-ad | pipx | AD Certificate Services ESC checks |

---

## Quick Start

```bash
# 1. Clone to attack machine
git clone <repo-url> vapt-automation
cd vapt-automation

# 2. Configure the engagement
cp config.env.example config.env
nano config.env          # fill in all non-sensitive values (see Configuration section)

# 3. Make scripts executable
chmod +x orchestrator.py phases/*.sh lib/common.sh

# 4. Verify what will run (dry-run — no commands executed, all gates auto-approved)
python3 orchestrator.py --phase 0,1,2,3,4,5 --dry-run

# 5. Run Phase 0 (installs tools, starts BloodHound CE, validates config)
python3 orchestrator.py --phase 0

# 6. Run a single phase interactively
python3 orchestrator.py --phase 1

# 7. Check background job and phase completion status
python3 orchestrator.py --status

# 8. Run all remaining phases in sequence
python3 orchestrator.py --phase 1,2,3,4,5

# 9. Non-interactive / pipeline run (auto-approves all checkpoints)
python3 orchestrator.py --phase 0,1,2 --auto-approve

# 9. List all phases and their automation level
python3 orchestrator.py --list

# 10. List skippable step keys for a phase
python3 orchestrator.py --phase 2 --list-steps

# 11. Skip specific steps within a phase
python3 orchestrator.py --phase 2 --skip scoutsuite,zap

# 12. Run only specific steps within a phase (skip everything else)
python3 orchestrator.py --phase 1 --only bloodhound,roadrecon
```

### Selective step execution

Every automated step within a phase has a named key. You can include or exclude steps at runtime without editing any script.

```bash
# See all step keys across every phase
python3 orchestrator.py --list-steps

# See keys for one phase only
python3 orchestrator.py --phase 3 --list-steps

# Skip one or more steps  (run everything else)
python3 orchestrator.py --phase 1 --skip nmap_fullscan
python3 orchestrator.py --phase 2 --skip scoutsuite,zap,nessus
python3 orchestrator.py --phase 3 --skip responder,hashcat

# Run only the named steps (skip everything else in that phase)
python3 orchestrator.py --phase 1 --only bloodhound,roadrecon
python3 orchestrator.py --phase 2 --only ad_checks
```

`--skip` and `--only` are mutually exclusive. Idempotency still applies on top — if a step's output file already exists it is skipped regardless.

> **Before running Phase 3 or 4**, ensure you have confirmed with the emergency contact and that the RoE explicitly covers exploitation activities.

### If tool installations are broken

If Phase 0 has been run multiple times or tools were installed manually alongside it, conflicting copies can accumulate (same tool in apt, pip, and pipx simultaneously). Use the purge script to wipe all framework-managed tools and start clean:

```bash
# See what would be removed without touching anything
bash tools/purge_tools.sh --dry-run

# Interactive purge — prompts before each tool group
bash tools/purge_tools.sh

# Full reset without prompts
bash tools/purge_tools.sh --yes

# Then reinstall cleanly
python3 orchestrator.py --phase 0
```

See [docs/MAINTENANCE.md §7](docs/MAINTENANCE.md#7-purging-a-broken-installation) for the full reference.

---

## Configuration Reference

Copy `config.env.example` to `config.env` and set every value before running Phase 0. Credentials are **never** stored in config files — they are prompted at runtime by the orchestrator.

### Engagement metadata

| Variable | Example | Description |
|----------|---------|-------------|
| `ENGAGEMENT_NAME` | `HaShem-VAPT-2026` | Used in log headers and report scaffold |
| `ENGAGEMENT_DATE` | `2026-04-01` | Engagement start date |
| `OUTPUT_BASE_DIR` | `${HOME}/vapt` | Root directory for all evidence output |

### Network scope

| Variable | Example | Description |
|----------|---------|-------------|
| `TARGET_SUBNETS` | `10.10.0.0/24 10.10.1.0/24` | Space-separated CIDR ranges in scope |
| `ATTACKER_INTERFACE` | `eth0` | Interface for Responder (run `ip addr show`) |
| `ATTACKER_IP` | `10.10.0.50` | Attacker machine IP on internal network |

### Active Directory

| Variable | Example | Description |
|----------|---------|-------------|
| `DOMAIN_NAME` | `hashem.local` | FQDN of the target domain |
| `DC_IP` | `10.10.1.10` | Primary domain controller IP |
| `ADDITIONAL_DC_IPS` | `10.10.1.11` | Optional additional DCs (space-separated) |

### Azure / Entra ID

| Variable | Example | Description |
|----------|---------|-------------|
| `AZURE_TENANT_ID` | `xxxxxxxx-...` | Azure tenant ID |
| `AZURE_SUBSCRIPTION_IDS` | `xxxxxxxx-... yyyyyyyy-...` | Space-separated subscription IDs |
| `ROADRECON_AUTH_METHOD` | `password` or `devicecode` | `password` for legacy auth; `devicecode` for MFA-enabled tenants |

### Scanning behaviour

| Variable | Default | Description |
|----------|---------|-------------|
| `NMAP_TIMING` | `3` | Nmap timing template (1=stealth, 5=fastest). `3` is the recommended default — balanced stealth and speed. Avoid `4`/`5` for discovery sweeps: they increase false positives. |
| `NMAP_MAX_RATE` | `500` | Maximum packet rate (packets/sec) for host sweep. `300–500` = stealth-first. `750–1500` = faster on a quiet internal LAN. Full-port scan uses `2×` this value. |
| `NMAP_DISCOVERY_PORTS` | `22,80,135,139,443,445,3389,5985,8080,8443` | TCP ports probed during host discovery sweep. **TCP SYN probes only — no ICMP/ARP.** This eliminates false positives from routers, switches, printers, and IPMI cards that respond to ICMP but do not run SMB/RDP/WinRM. Adjust for your environment. |
| `SCAN_EXCLUDE_RANGES` | _(empty)_ | Space-separated IPs/CIDRs excluded from all nmap scans (e.g. `10.10.0.1 192.168.1.0/28`). Add default gateways, monitoring probes, and printer subnets to avoid known-false-positive infrastructure. |
| `HASHCAT_DEVICE` | `1` | `1`=CPU, `2`=GPU. GPU is dramatically faster when available. Parallelism auto-scales to detected vCPU count. |
| `RESPONDER_DURATION` | `7200` | Responder capture window in seconds (default 2 hours). Responder **must** stop at `TESTING_WINDOW_END` — auto-stop is scheduled via `atd`. |

### Web application testing (DAST)

| Variable | Example | Description |
|----------|---------|-------------|
| `WEB_TARGETS` | `http://intranet.hashem.local` | Space-separated in-scope web URLs for ZAP |
| `ZAP_SCAN_MODE` | `baseline` | `baseline` = passive only; `full` = active (confirm RoE covers active attacks) |

### Wordlists

| Variable | Default | Description |
|----------|---------|-------------|
| `WORDLIST_PRIMARY` | `/usr/share/wordlists/rockyou.txt` | Primary cracking wordlist |
| `WORDLIST_RULES` | `/usr/share/hashcat/rules/best64.rule` | Hashcat rule file |
| `WORDLIST_CORPORATE` | `<OUTPUT_BASE_DIR>/tools/corporate_patterns.txt` | Auto-generated corporate pattern list |

### Operational controls

| Variable | Default | Description |
|----------|---------|-------------|
| `ENFORCE_TESTING_WINDOW` | `true` | Block testing outside business hours |
| `TESTING_WINDOW_START` | `09:00` | Testing window start (HH:MM, 24hr) |
| `TESTING_WINDOW_END` | `17:00` | Testing window end |
| `EMERGENCY_CONTACT` | `Management Sponsor — Elizabeth A.` | Displayed at startup and in logs |

### Optional integrations

| Variable | Description |
|----------|-------------|
| `NESSUS_URL` | Nessus API base URL (e.g. `https://localhost:8834`) |
| `NESSUS_SCAN_ID` | Pre-configured scan policy ID from the Nessus UI. When set alongside `NESSUS_USER`/`NESSUS_PASS`, Phase 2 automatically launches the scan via `POST /scans/{ID}/launch` and saves the resulting scan UUID. |
| `SLACK_WEBHOOK_URL` | Webhook URL for background job completion notifications |
| `SPRAY_ENABLED` | `true` to enable a controlled password spray in Phase 1. Reads `SPRAY_MAX_ATTEMPTS` and `SPRAY_DELAY_SECONDS`. Will refuse to spray if the lockout threshold from Phase 2 password policy is not safely above `SPRAY_MAX_ATTEMPTS`. |
| `SPRAY_MAX_ATTEMPTS` | Max spray attempts per user per run (default `2` — stay well below domain lockout threshold) |
| `SPRAY_DELAY_SECONDS` | Delay between spray rounds in seconds (default `1800` = 30 min) |

---

## Credential Handling

Credentials are **never written to any file**. They are prompted at runtime using Python's `getpass` (hidden terminal input) and stored only in environment variables for the duration of the process. See [docs/SECURITY.md](docs/SECURITY.md) for the full credential lifecycle.

Credentials prompted per phase:

| Secret | Phases | Notes |
|--------|--------|-------|
| `DOMAIN_USER` | 1, 2, 3, 4 | Domain username only — not an email address |
| `DOMAIN_PASS` | 1, 2, 3, 4 | Hidden input via `getpass` |
| `AZURE_USER` | 1 (optional) | Leave blank to use device code flow |
| `AZURE_PASS` | 1 (optional) | Leave blank to use device code flow |
| `OBTAINED_HASH` | 3, 4 | NTLM hash for PtH sweep / lateral move. Phase 4 sam_sweep will abort if this is not set. |
| `NESSUS_USER` | 2 | Required for Nessus API trigger (scan launch + session cleanup) |
| `NESSUS_PASS` | 2 | Required for Nessus API trigger |

All secrets are collected sorted alphabetically at orchestrator startup (once per run, not once per phase). Prompts are hidden using Python's `getpass`.

---

## Output Directory Structure

All output is written under `OUTPUT_BASE_DIR` (default: `~/vapt/`). Phase 0 creates this structure automatically.

```
~/vapt/
├── engagement_log.md              # Full audit trail — every command and decision
├── phase0/
│   ├── scope.json                 # Engagement scope (auto-generated)
│   └── {network,ad,web,cloud,misc}/
├── phase1/
│   ├── network/
│   │   ├── live_hosts_all.txt         # Merged validated live hosts (TCP SYN confirmed)
│   │   ├── hostsweep_<subnet>.*       # Per-subnet TCP discovery scan output
│   │   ├── fullscan.{gnmap,nmap}      # Merged full port scan (auto-assembled by merge watcher)
│   │   └── scan_chunks/               # Parallel scan chunks (one per vCPU) + merge watcher log
│   │       ├── chunk_aa, chunk_ab, …  # Host list splits for parallel nmap jobs
│   │       ├── fullscan_chunk_aa.*    # Per-chunk nmap output
│   │       └── nmap_merge.log         # Merge watcher job log
│   ├── ad/
│   │   ├── userlist.txt               # Clean username list for AS-REP / spray
│   │   ├── bloodhound/                # BloodHound collection ZIPs
│   │   ├── relay_target_ips.txt       # Hosts with SMB signing disabled
│   │   ├── spray_results.txt          # Password spray results (if SPRAY_ENABLED=true)
│   │   └── ldap_users.txt
│   └── cloud/
│       ├── roadrecon.db           # ROADrecon Entra ID database
│       ├── azure_inventory.json   # Merged resource inventory (all subscriptions)
│       ├── inventory_<sub-id>.json
│       └── {vms,storage,nsgs,keyvaults,entra_users,...}.txt
├── phase2/
│   ├── network/
│   │   └── smb_vuln_checks.txt   # ms17-010 / nopac / petitpotam results
│   ├── ad/ad_checks/
│   │   ├── kerberoastable_accounts.txt
│   │   ├── asrep_accounts.txt
│   │   ├── unconstrained_delegation.txt
│   │   ├── pwd_never_expires.txt
│   │   └── adcs/                  # certipy AD CS ESC output
│   ├── web/zap/
│   │   └── <target>/              # One dir per ZAP-scanned URL
│   │       ├── zap_report.html
│   │       ├── zap_report.json
│   │       └── zap_report.xml
│   └── cloud/
│       ├── scoutsuite/<sub-id>/report.html
│       └── security_checks/       # Azure targeted checks output
├── phase3/
│   └── ad/
│       ├── kerberoast_tickets.txt
│       ├── asrep_hashes.txt
│       ├── ntlmv2_all.txt                 # Merged Responder captures (all users, deduped)
│       ├── cracked_ntlm.txt               # Merged NTLMv2 cracks (from all 3 wordlist jobs)
│       ├── cracked_ntlm_rockyou.txt       # rockyou.txt job output
│       ├── cracked_ntlm_rules.txt         # rockyou + best64 rules job output
│       ├── cracked_ntlm_corp.txt          # Corporate patterns job output
│       ├── cracked_tgs.txt                # Kerberoast cracks
│       ├── cracked_asrep.txt              # AS-REP cracks
│       └── pth_accessible_hosts.txt
├── phase4/
│   ├── ad/
│   │   └── dcsync_poc.txt
│   └── blast_radius/
│       ├── blast_radius.md        # Attack hop log
│       └── summary.md             # Full post-exploitation summary
├── report/
│   ├── evidence/                      # Consolidated evidence copies
│   │   ├── {network,ad,cloud,web,cracked}/
│   │   └── summary.md
│   ├── TECHNICAL_REPORT_SCAFFOLD.md   # Pre-populated finding scaffold
│   └── evidence_manifest.sha256       # SHA-256 checksums of all evidence files
└── tools/
    └── corporate_patterns.txt     # Auto-generated password pattern list
```

---

## BloodHound CE

BloodHound Community Edition runs as a Docker Compose stack (started automatically by Phase 0):

```bash
# Check stack status
docker compose -f tools/bloodhound-ce/docker-compose.yml ps

# Get first-run admin password (printed once on initial startup)
docker compose -f tools/bloodhound-ce/docker-compose.yml logs bloodhound \
    2>&1 | grep -i 'initial password\|password'

# Stop the stack when not in use
docker compose -f tools/bloodhound-ce/docker-compose.yml down

# Restart the stack
docker compose -f tools/bloodhound-ce/docker-compose.yml up -d
```

Access the UI at **http://localhost:8080**. Import the BloodHound ZIP from `~/vapt/phase1/ad/bloodhound/` after Phase 1 completes.

---

## Monitoring Background Jobs

Long-running jobs (Nmap, Hashcat, Responder, BloodHound, ROADrecon, ScoutSuite, ZAP) run via `nohup` + `disown` and survive terminal close. All PIDs are persisted to `.bg_jobs` so `--status` can track them across sessions.

```bash
# Phase completion + background job status
python3 orchestrator.py --status

# Nmap: parallel chunk progress (one log per vCPU chunk)
tail -f ~/vapt/phase1/network/scan_chunks/fullscan_chunk_aa.log
# Merge watcher (fires when all chunks complete)
tail -f ~/vapt/phase1/network/nmap_merge.log

# Responder: hash capture count
ls /usr/share/responder/logs/SMB-NTLMv2-*.txt 2>/dev/null | wc -l

# Hashcat: live progress (separate log per wordlist job)
tail -f ~/vapt/phase3/ad/hashcat_ntlm.log        # rockyou job
tail -f ~/vapt/phase3/ad/hashcat_ntlm_rules.log  # rules job
cat  ~/vapt/phase3/ad/cracked_ntlm.txt           # merged results so far

# ZAP scan progress per target
tail -f ~/vapt/phase2/web/zap/<target>/zap.log

# Kill all background jobs (emergency)
sudo pkill -f "responder" 2>/dev/null
pkill -f "hashcat|nmap|bloodhound-python|roadrecon|scout|zaproxy" 2>/dev/null
```

---

## Documentation Index

| Document | Purpose |
|----------|---------|
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Day-by-day operating procedures, monitoring guide, troubleshooting |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, tool selection rationale, extension guide |
| [docs/SECURITY.md](docs/SECURITY.md) | Credential lifecycle, audit trail, responsible use policy |
| [docs/MAINTENANCE.md](docs/MAINTENANCE.md) | Updating dependencies, adding checks, known Kali issues |
| [tools/verify.sh](tools/verify.sh) | Pre-engagement environment verification (run 48h before Day 1) |
| [tools/purge_tools.sh](tools/purge_tools.sh) | Clean-slate removal of all framework-managed tools |

---

## Emergency Stop

If testing must halt immediately at any point:

1. Press `Ctrl+C` in the orchestrator terminal — triggers `cleanup_on_exit`, kills all tracked background processes.
2. Kill any remaining processes: `pkill -f "responder|hashcat|nmap|bloodhound-python|roadrecon|scout|zaproxy"`
3. Contact: **Elizabeth A.** (Management Sponsor) — see `EMERGENCY_CONTACT` in `config.env`.
4. Document the stop time in `~/vapt/engagement_log.md`.
