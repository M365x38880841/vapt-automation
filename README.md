# Ha-Shem VAPT Automation Framework

## Quick Start

```bash
# 1. Clone/copy this directory to the attack machine
# 2. Set up config
cp config.env.example config.env
nano config.env          # fill in non-sensitive values only

# 3. Make scripts executable
chmod +x orchestrator.py phases/*.sh lib/common.sh

# 4. List all phases and automation status
python3 orchestrator.py --list

# 5. Run full engagement (interactive, will prompt for creds)
python3 orchestrator.py

# 6. Run a single phase
python3 orchestrator.py --phase 1

# 7. Dry run — see what would execute without running anything
python3 orchestrator.py --phase 1,2,3 --dry-run

# 8. Check status of running phases
python3 orchestrator.py --status
```

## Automation Coverage Per Phase

| Phase | What's Automated | What's Manual |
|-------|-----------------|---------------|
| **0 — Setup** | Tool install, dir scaffold, Azure login, wordlist gen | RoE sign-off, inventory handoff |
| **1 — Discovery** | Nmap sweep + full scan, CrackMapExec SMB, LDAP enum, BloodHound collection, ROADrecon, Azure inventory | BloodHound GUI analysis, ROADrecon GUI review |
| **2 — VA** | ScoutSuite, all Azure security checks, Linux AD checks (Kerberoastable/AS-REP/delegation/policy), Nessus API trigger | Nessus UI config, Burp Suite testing, PingCastle (Windows), Purple Knight (Windows) |
| **3 — Exploit** | Responder (background), Hashcat all modes (background), Kerberoasting, AS-REP Roasting, PtH sweep, Azure public blob PoC | BloodHound path selection, relay target confirmation, Metasploit CVE PoC, all decision points |
| **4 — Post-Exploit** | SAM dump sweep on confirmed hosts, Azure blast radius, blast radius report | Every lateral move hop (confirmed interactively), DCSync (hard gate), Azure VM commands |
| **5 — Reporting** | Evidence consolidation, report scaffold generation, finding count pre-fill | All writing — findings, impact, remediation, exec summary, debrief |

## Security Design

- **No secrets in any file** — config.env holds only non-sensitive variables
- **All credentials prompted at runtime** via Python's `getpass` or hidden `read -rs`
- **Business hours enforcement** — configurable gate that blocks testing outside agreed window
- **Every sensitive action has a `checkpoint()` gate** — operator must explicitly confirm
- **Background jobs tracked with PIDs** — `Ctrl+C` kills all background jobs cleanly
- **Full audit log** — every command and decision written to `engagement_log.md` with timestamp
- **Idempotent** — `skip_if_exists()` prevents re-running completed steps
- **Emergency kill** — `Ctrl+C` at any point triggers `cleanup_on_exit` and kills all background processes

## Directory Layout (auto-created by Phase 0)

```
~/vapt/
├── engagement_log.md          # Full audit trail
├── phase0/{network,ad,web,cloud,misc}/
│   └── scope.json             # Scope file for all phases
├── phase1/{network,ad,web,cloud}/
│   ├── network/live_hosts_all.txt
│   ├── network/fullscan.xml
│   ├── ad/bloodhound/*.zip
│   ├── ad/userlist.txt
│   ├── ad/relay_target_ips.txt
│   └── cloud/{roadrecon.db,azure_inventory.json,...}
├── phase2/{network,ad,web,cloud}/
│   ├── ad/ad_checks/
│   └── cloud/scoutsuite/report.html
├── phase3/{network,ad,web,cloud}/
│   ├── ad/{kerberoast_tickets,asrep_hashes,cracked_*}.txt
│   ├── ad/responder_session.log
│   └── cloud/public_blob_poc.txt
├── phase4/{network,ad,web,cloud}/
│   ├── ad/dcsync_poc.txt
│   └── blast_radius/summary.md
├── report/
│   ├── evidence/
│   └── TECHNICAL_REPORT_SCAFFOLD.md
└── tools/corporate_patterns.txt
```

## Running Background Jobs Safely

Long-running jobs (Nmap, Hashcat, Responder, ScoutSuite) are kicked off as
background processes with `bg_run`. You can:

```bash
# Check status of all background jobs
python3 orchestrator.py --status

# Monitor a specific job
tail -f ~/vapt/phase3/ad/hashcat_ntlm.log

# Monitor Responder captures in real-time
watch -n 30 'ls /usr/share/responder/logs/SMB-NTLMv2-*.txt 2>/dev/null | wc -l'

# Kill all background jobs (emergency)
pkill -f "responder\|hashcat\|nmap\|bloodhound-python\|roadrecon\|scout"
```

## Recommended Daily Scheduling

| Time | Action |
|------|--------|
| **08:50** | Start attack machine, verify Azure login |
| **09:00** | `python3 orchestrator.py --phase <today's phase>` |
| **09:05** | Background jobs start automatically (Responder, Hashcat, scans) |
| **09:10–12:00** | Active work: BloodHound analysis, Burp testing, manual AD checks |
| **12:00** | Check background job status, review any cracked hashes |
| **13:00–16:30** | Active exploitation / lateral movement (with human gates) |
| **16:30** | Start any overnight background jobs (Nmap full scan, Nessus) |
| **16:55** | Log work in engagement_log.md, confirm background jobs running |
| **17:00** | Leave overnight jobs running — check logs tomorrow AM |
