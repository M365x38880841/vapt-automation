#!/usr/bin/env python3
"""
============================================================================
HA-SHEM VAPT ENGAGEMENT — MASTER ORCHESTRATOR
============================================================================
Single entry point for the entire engagement.
Handles: config loading, credential prompting, phase sequencing,
         background job tracking, human gates, and audit logging.

Usage:
    python3 orchestrator.py                        # interactive mode — runs all phases
    python3 orchestrator.py --phase 1              # run only phase 1
    python3 orchestrator.py --phase 1,2,3          # run specific phases
    python3 orchestrator.py --phase 3 --dry-run    # show what would run without executing
    python3 orchestrator.py --status               # show background job status
============================================================================
"""

import argparse
import datetime
import getpass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ─── ANSI COLOURS ─────────────────────────────────────────────────────────────
R = "\033[0;31m"; Y = "\033[1;33m"; G = "\033[0;32m"
B = "\033[0;34m"; C = "\033[0;36m"; M = "\033[0;35m"
BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = f"""
{BOLD}{B}
 ██╗  ██╗ █████╗       ███████╗██╗  ██╗███████╗███╗   ███╗
 ██║  ██║██╔══██╗      ██╔════╝██║  ██║██╔════╝████╗ ████║
 ███████║███████║█████╗███████╗███████║█████╗  ██╔████╔██║
 ██╔══██║██╔══██║╚════╝╚════██║██╔══██║██╔══╝  ██║╚██╔╝██║
 ██║  ██║██║  ██║      ███████║██║  ██║███████╗██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝      ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
{RESET}{BOLD}           VAPT ENGAGEMENT ORCHESTRATOR — Ha-Shem Limited{RESET}
{C}           Infrastructure Security Team | Confidential{RESET}
"""

# ─── PHASE REGISTRY ───────────────────────────────────────────────────────────
PHASES = {
    0: {
        "name": "Pre-Engagement Setup",
        "script": "phases/phase0_setup.sh",
        "days": "Days 1–2",
        "automatable": True,
        "requires_creds": False,
        "description": "Tool verification, directory scaffolding, config validation",
    },
    1: {
        "name": "Reconnaissance & Discovery",
        "script": "phases/phase1_discovery.sh",
        "days": "Days 3–4",
        "automatable": True,
        "requires_creds": True,
        "description": "Nmap, CrackMapExec, BloodHound, ROADrecon, Azure CLI enumeration",
        "secrets_needed": ["DOMAIN_USER", "DOMAIN_PASS"],
        "background_jobs": ["nmap_fullscan", "bloodhound_collect", "roadrecon_gather", "azure_inventory"],
    },
    2: {
        "name": "Vulnerability Assessment",
        "script": "phases/phase2_va.sh",
        "days": "Days 5–7",
        "automatable": True,
        "requires_creds": True,
        "description": "ScoutSuite, Azure CLI security checks, PingCastle (remote), Nessus API trigger",
        "secrets_needed": ["DOMAIN_USER", "DOMAIN_PASS"],
        "background_jobs": ["scoutsuite_scan", "azure_security_checks"],
        "manual_steps": [
            "Nessus/OpenVAS credentialed scan — must be configured and launched via UI",
            "Burp Suite web app testing — active scan + manual test cases",
            "Purple Knight — must run from Windows domain-joined machine",
        ],
    },
    3: {
        "name": "Exploitation",
        "script": "phases/phase3_exploit.sh",
        "days": "Days 8–11",
        "automatable": "partial",
        "requires_creds": True,
        "description": "Kerberoasting, AS-REP, Responder, Hashcat, PtH sweep, Azure PoC",
        "secrets_needed": ["DOMAIN_USER", "DOMAIN_PASS"],
        "background_jobs": ["responder_capture", "hashcat_ntlm", "hashcat_tgs", "hashcat_asrep"],
        "manual_steps": [
            "BloodHound attack path selection — human judgment required",
            "NTLM relay decision — operator must confirm target list",
            "Metasploit CVE exploitation — one finding at a time with human oversight",
            "DCSync PoC — explicit human gate, must specify a non-sensitive target account",
        ],
    },
    4: {
        "name": "Post-Exploitation",
        "script": "phases/phase4_postexploit.sh",
        "days": "Days 9–11",
        "automatable": "partial",
        "requires_creds": True,
        "description": "Lateral movement sweep, SAM dump, blast radius documentation",
        "secrets_needed": ["DOMAIN_USER", "DOMAIN_PASS", "OBTAINED_HASH"],
        "manual_steps": [
            "Lateral movement target selection — operator decides which machines to pivot to",
            "DCSync execution — strictly manual with one-account-at-a-time confirmation",
            "Azure VM run-command — operator confirms each target",
        ],
    },
    5: {
        "name": "Reporting & Debrief",
        "script": None,  # No automation — fully manual
        "days": "Days 12–14",
        "automatable": False,
        "requires_creds": False,
        "description": "Evidence consolidation scaffold only — writing is manual",
        "manual_steps": [
            "Executive summary report writing",
            "Per-finding technical write-ups",
            "MITRE ATT&CK coverage table",
            "Debrief slide preparation",
            "Debrief session with management sponsors",
        ],
    },
}

# ─── STEP REGISTRY ────────────────────────────────────────────────────────────
# Maps step keys (passed to --skip / --only) to human descriptions.
# These keys must match the values used in _step_is_skipped() calls in phase scripts.
STEP_REGISTRY = {
    1: {
        "host_sweep":      "Nmap host sweep across all subnets",
        "nmap_fullscan":   "Nmap full port scan -p- (background, overnight)",
        "smb_sweep":       "CrackMapExec SMB sweep + signing check",
        "ldap_banner":     "LDAP rootDSE banner grab from DC",
        "ldap_users":      "LDAP domain user enumeration",
        "null_session":    "SMB null session check",
        "bloodhound":      "BloodHound data collection",
        "roadrecon":       "ROADrecon Entra ID gather",
        "azure_inventory": "Azure resource inventory across subscriptions",
    },
    2: {
        "scoutsuite":      "ScoutSuite Azure audit (per subscription)",
        "azure_security":  "Azure targeted security checks (MFA, RBAC, storage, NSG, KeyVault)",
        "ad_checks":       "AD security checks: password policy, Kerberoastable accounts, certipy AD CS, SMB vulns",
        "zap":             "OWASP ZAP web DAST scan",
        "nessus":          "Nessus credentialed scan trigger via API",
    },
    3: {
        "responder":       "Responder LLMNR/NBT-NS poisoning (background)",
        "kerberoast":      "Kerberoasting — TGS ticket request for SPN accounts",
        "asrep":           "AS-REP Roasting — accounts with pre-auth disabled",
        "hashcat":         "Hashcat cracking jobs (NTLMv2, TGS, AS-REP)",
        "ntlm_relay":      "NTLM relay setup (Responder relay mode + ntlmrelayx)",
        "pth_sweep":       "Pass-the-Hash sweep with obtained hash",
        "azure_storage":   "Azure public storage container check",
    },
    4: {
        "sam_sweep":          "Automated SAM dump on confirmed PtH hosts",
        "lateral_move":       "Interactive PsExec / WMIexec lateral movement",
        "dcsync":             "DCSync PoC (maximum gate)",
        "azure_blast_radius": "Azure blast radius assessment from compromised identity",
        "blast_summary":      "Blast radius summary report generation",
    },
}

# ─── CREDENTIAL REGISTRY ──────────────────────────────────────────────────────
CREDENTIAL_PROMPTS = {
    "DOMAIN_USER":   "Domain username (e.g. testuser)",
    "DOMAIN_PASS":   "Domain password",
    "AZURE_USER":    "Azure login UPN (e.g. user@hashem.com) — leave blank if using CLI login",
    "AZURE_PASS":    "Azure password — leave blank if using device code flow",
    "OBTAINED_HASH": "NTLM hash obtained from Phase 3 (for PtH — leave blank to skip)",
    "NESSUS_USER":   "Nessus username",
    "NESSUS_PASS":   "Nessus password",
    "NESSUS_URL":    "Nessus URL (e.g. https://localhost:8834)",
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def info(msg):  print(f"{C}[{ts()}] [INFO]{RESET}  {msg}")
def ok(msg):    print(f"{G}[{ts()}] [OK]{RESET}    {msg}")
def warn(msg):  print(f"{Y}[{ts()}] [WARN]{RESET}  {msg}")
def error(msg): print(f"{R}[{ts()}] [ERROR]{RESET} {msg}")

def phase_banner(num, name, days):
    print(f"\n{BOLD}{M}{'═'*64}{RESET}")
    print(f"{BOLD}{M}  PHASE {num} — {name.upper()}{RESET}")
    print(f"{C}  Timeline: {days}{RESET}")
    print(f"{BOLD}{M}{'═'*64}{RESET}\n")

def manual_gate(steps: list[str], phase_num: int):
    """Display manual steps and require operator acknowledgement."""
    print(f"\n{BOLD}{Y}┌{'─'*60}┐{RESET}")
    print(f"{BOLD}{Y}│  👤  MANUAL STEPS — Phase {phase_num}{' '*max(0,50-len(str(phase_num)))}│{RESET}")
    print(f"{BOLD}{Y}├{'─'*60}┤{RESET}")
    for i, step in enumerate(steps, 1):
        wrapped = f"│  {i}. {step}"
        print(f"{Y}{wrapped[:62]}{RESET}")
        if len(step) > 56:
            remainder = step[56:]
            print(f"{Y}│     {remainder[:57]}{RESET}")
    print(f"{BOLD}{Y}└{'─'*60}┘{RESET}")
    print(f"\n{BOLD}  Complete the above manually, then press [ENTER] to continue.{RESET}")
    print(f"  Press [s] to skip remaining manual steps in this phase: ", end="")
    sys.stdout.flush()
    choice = input().strip().lower()
    return choice != "s"

def checkpoint(description: str, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"{C}  [DRY-RUN] Would checkpoint: {description}{RESET}")
        return True
    print(f"\n{BOLD}{Y}{'━'*64}{RESET}")
    print(f"{BOLD}{Y}  CHECKPOINT — Human Review Required{RESET}")
    print(f"{BOLD}  Action:{RESET} {description}")
    print(f"{BOLD}{Y}{'━'*64}{RESET}")
    print(f"  [ENTER]=proceed  [s]=skip  [q]=abort: ", end="")
    sys.stdout.flush()
    choice = input().strip().lower()
    if choice == "q":
        warn(f"Aborted at checkpoint: {description}")
        sys.exit(1)
    if choice == "s":
        warn(f"Skipped: {description}")
        return False
    return True

def check_testing_window(config: dict) -> bool:
    if config.get("ENFORCE_TESTING_WINDOW", "false").lower() != "true":
        return True
    now = datetime.datetime.now().strftime("%H:%M")
    start = config.get("TESTING_WINDOW_START", "09:00")
    end   = config.get("TESTING_WINDOW_END",   "17:00")
    if now < start or now > end:
        warn(f"Current time {now} is outside testing window ({start}–{end}).")
        print(f"  Override? This may violate the RoE. [y/N]: ", end="")
        choice = input().strip().lower()
        if choice != "y":
            return False
        warn(f"Testing window overridden by operator at {now}")
    return True

# ─── CONFIG LOADER ────────────────────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    """Load config.env into a dict. Does NOT load secrets."""
    config = {}
    path = Path(config_path)
    if not path.exists():
        error(f"Config file not found: {config_path}")
        error("Copy config.env.example → config.env and fill in values.")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                # Strip inline comments — only strip when # is preceded by whitespace,
                # so URLs containing # (e.g. Slack webhooks) are preserved.
                v = re.sub(r'\s+#.*$', '', v).strip().strip('"').strip("'")
                config[k.strip()] = v
    return config

def validate_config(config: dict):
    required = ["TARGET_SUBNETS", "DOMAIN_NAME", "DC_IP", "AZURE_TENANT_ID",
                "ATTACKER_IP", "ATTACKER_INTERFACE", "OUTPUT_BASE_DIR"]
    missing = [k for k in required if not config.get(k)]
    if missing:
        error(f"Missing required config variables: {', '.join(missing)}")
        sys.exit(1)

# ─── CREDENTIAL COLLECTION ────────────────────────────────────────────────────

def collect_credentials(secrets_needed: list[str]) -> dict:
    """Prompt for credentials at runtime. Never stored in config file."""
    creds = {}
    print(f"\n{BOLD}{C}  Credential Collection (input is hidden){RESET}")
    print(f"  These will be exported as environment variables for this session only.\n")
    for key in secrets_needed:
        prompt = CREDENTIAL_PROMPTS.get(key, key)
        if key.endswith("_PASS") or key == "OBTAINED_HASH":
            val = getpass.getpass(f"  {prompt}: ")
        else:
            val = input(f"  {prompt}: ").strip()
        if val:
            creds[key] = val
        else:
            warn(f"  Skipped: {key}")
    return creds

# ─── PHASE RUNNER ─────────────────────────────────────────────────────────────

def run_phase(phase_num: int, config: dict, creds: dict, dry_run: bool, log_file: Path,
              skip: str = "", only: str = ""):
    phase = PHASES[phase_num]
    phase_banner(phase_num, phase["name"], phase["days"])

    # Business hours gate
    if not check_testing_window(config):
        error("Testing blocked outside business hours. Exiting.")
        sys.exit(1)

    # Log phase start
    with open(log_file, "a") as lf:
        lf.write(f"\n## [{ts()}] PHASE {phase_num} START — {phase['name']}\n")

    # Show what is automated vs manual
    if phase.get("manual_steps"):
        warn(f"Phase {phase_num} has {len(phase['manual_steps'])} manual step(s).")

    # Phase 5 — fully manual
    if not phase.get("automatable"):
        print(f"\n{BOLD}{Y}Phase {phase_num} ({phase['name']}) is fully manual.{RESET}")
        if phase.get("manual_steps"):
            manual_gate(phase["manual_steps"], phase_num)
        return

    # Run automated script
    script_path = Path(__file__).parent / phase["script"]
    if not script_path.exists():
        error(f"Phase script not found: {script_path}")
        return

    if dry_run:
        info(f"[DRY-RUN] Would execute: {script_path}")
        info(f"[DRY-RUN] With env vars: {list(creds.keys())} + config vars")
        if phase.get("manual_steps"):
            print(f"\n{BOLD}  Manual steps that would follow:{RESET}")
            for s in phase["manual_steps"]:
                print(f"    • {s}")
        return

    # Build environment
    env = os.environ.copy()
    env.update(config)
    env.update(creds)
    env["PHASE_NUM"] = str(phase_num)
    env["LOG_FILE"] = str(log_file)
    env["DRY_RUN"] = "false"
    if skip:
        env["SKIP_STEPS"] = skip
        info(f"Steps excluded this run: {skip}")
    if only:
        env["ONLY_STEPS"] = only
        info(f"Running only steps: {only}")

    checkpoint(f"Execute Phase {phase_num}: {phase['name']}")

    result = subprocess.run(
        ["bash", str(script_path)],
        env=env,
        # Run interactively — scripts have their own prompts and background jobs
    )

    if result.returncode != 0:
        warn(f"Phase {phase_num} script exited with code {result.returncode}.")
    else:
        ok(f"Phase {phase_num} automated components complete.")

    # Manual steps follow automated
    if phase.get("manual_steps"):
        print(f"\n{BOLD}Phase {phase_num} automated steps complete. Now complete manual steps:{RESET}")
        manual_gate(phase["manual_steps"], phase_num)

    with open(log_file, "a") as lf:
        lf.write(f"## [{ts()}] PHASE {phase_num} END\n")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ha-Shem VAPT Engagement Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config",     default="config.env", help="Path to config file (default: config.env)")
    parser.add_argument("--phase",      default="all",        help="Phase(s) to run: 0,1,2,3,4,5 or 'all'")
    parser.add_argument("--dry-run",    action="store_true",  help="Show what would run without executing")
    parser.add_argument("--status",     action="store_true",  help="Show phase completion status from logs")
    parser.add_argument("--list",       action="store_true",  help="List all phases and their automation status")
    parser.add_argument("--list-steps", action="store_true",  help="List skippable step keys for each phase")
    parser.add_argument("--skip",       default="",           metavar="STEPS",
                        help="Comma-separated step keys to skip, e.g. --skip nmap_fullscan,scoutsuite")
    parser.add_argument("--only",       default="",           metavar="STEPS",
                        help="Run only these step keys (skip all others), e.g. --only bloodhound,roadrecon")
    args = parser.parse_args()

    if args.skip and args.only:
        error("--skip and --only are mutually exclusive. Use one or the other.")
        sys.exit(1)

    print(BANNER)

    # ── List mode
    if args.list:
        print(f"{BOLD}{'Phase':<8} {'Name':<30} {'Automatable':<15} {'Days'}{RESET}")
        print("─" * 70)
        for num, p in PHASES.items():
            auto = p["automatable"]
            label = f"{G}Full{RESET}" if auto is True else (f"{Y}Partial{RESET}" if auto == "partial" else f"{R}Manual{RESET}")
            print(f"  {num:<6} {p['name']:<30} {label:<25} {p['days']}")
        return

    # ── List steps mode
    if args.list_steps:
        filter_phases = []
        if args.phase != "all":
            try:
                filter_phases = [int(p.strip()) for p in args.phase.split(",")]
            except ValueError:
                pass
        print(f"\n{BOLD}Skippable step keys  (use with --skip or --only){RESET}")
        print(f"{C}Example: python3 orchestrator.py --phase 1 --skip nmap_fullscan,smb_sweep{RESET}\n")
        for phase_num, steps in STEP_REGISTRY.items():
            if filter_phases and phase_num not in filter_phases:
                continue
            p = PHASES.get(phase_num, {})
            print(f"{BOLD}{M}  Phase {phase_num} — {p.get('name', '')}{RESET}")
            for key, desc in steps.items():
                print(f"    {G}{key:<22}{RESET}  {desc}")
            print()
        return

    # ── Load and validate config
    config = load_config(args.config)
    validate_config(config)

    # ── Set up output directory
    output_base = Path(config["OUTPUT_BASE_DIR"])
    output_base.mkdir(parents=True, exist_ok=True)
    log_file = output_base / "engagement_log.md"

    if not log_file.exists():
        with open(log_file, "w") as lf:
            lf.write(f"# VAPT Engagement Log — {config.get('ENGAGEMENT_NAME', 'Ha-Shem')}\n")
            lf.write(f"Started: {ts()}\n\n")

    # ── Status mode — morning briefing
    if args.status:
        # Phase completion summary from engagement log
        print(f"\n{BOLD}{'═'*62}{RESET}")
        print(f"{BOLD}  Phase Completion Summary{RESET}")
        print(f"{BOLD}{'═'*62}{RESET}")
        if log_file.exists():
            content = log_file.read_text()
            for num, p in PHASES.items():
                started = f"PHASE {num} START" in content
                ended   = f"PHASE {num} END"   in content
                if ended:
                    symbol = f"{G}✔  Complete   {RESET}"
                elif started:
                    symbol = f"{Y}⏳ In Progress{RESET}"
                else:
                    symbol = f"{R}✘  Not Started{RESET}"
                print(f"  Phase {num}  {symbol}  {p['name']}")
        else:
            warn("engagement_log.md not found — has the orchestrator been run yet?")

        # Background job briefing from persistent .bg_jobs file
        bg_jobs_file = output_base / ".bg_jobs"
        print(f"\n{BOLD}{C}{'═'*62}{RESET}")
        print(f"{BOLD}{C}  Overnight Background Job Status{RESET}")
        print(f"{BOLD}{C}{'═'*62}{RESET}")

        if not bg_jobs_file.exists():
            print(f"  {Y}No persistent job records found (.bg_jobs does not exist).{RESET}")
        else:
            running: list = []
            completed: list = []
            seen_pids: set = set()

            with open(bg_jobs_file) as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    parts = raw.split("|", 3)
                    if len(parts) < 3:
                        continue
                    pid_str, name, logfile_path = parts[0], parts[1], parts[2]
                    started_at = parts[3] if len(parts) > 3 else "unknown"
                    try:
                        pid = int(pid_str)
                    except ValueError:
                        continue
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                    alive = False
                    try:
                        os.kill(pid, 0)
                        alive = True
                    except ProcessLookupError:
                        alive = False
                    except PermissionError:
                        alive = True  # process exists, we don't own it — still running
                    if alive:
                        running.append((pid, name, logfile_path, started_at))
                    else:
                        completed.append((pid, name, logfile_path, started_at))

            if not running and not completed:
                print(f"  {Y}No jobs recorded in .bg_jobs.{RESET}")
            else:
                for pid, name, logfile_path, started_at in running:
                    print(f"\n  {Y}⏳ RUNNING  {RESET} {BOLD}{name}{RESET} (PID: {pid})")
                    print(f"     Started: {started_at}")
                    print(f"     Log:     {logfile_path}")

                for pid, name, logfile_path, started_at in completed:
                    print(f"\n  {G}✔  COMPLETE {RESET} {BOLD}{name}{RESET} (PID: {pid})")
                    print(f"     Started: {started_at}")
                    lf = Path(logfile_path)
                    if lf.exists():
                        tail = [l for l in lf.read_text().splitlines()[-5:] if l.strip()]
                        for line in tail:
                            print(f"     {line}")

                print(f"\n  {G}Completed overnight: {len(completed)}{RESET}   "
                      f"{Y}Still running: {len(running)}{RESET}")

        print(f"{BOLD}{C}{'═'*62}{RESET}")
        print(f"\n  Idempotency: completed steps are skipped automatically.")
        print(f"  Resume any unfinished phase: {BOLD}python3 orchestrator.py --phase N{RESET}\n")
        return

    # ── Emergency contact display
    print(f"{BOLD}{R}  EMERGENCY STOP: {config.get('EMERGENCY_CONTACT', 'See RoE document')}{RESET}")
    print(f"{Y}  Rules of Engagement must be signed before proceeding.{RESET}")
    print(f"\n  Is the signed RoE document in place? [y/N]: ", end="")
    if input().strip().lower() != "y":
        error("Aborting — RoE not confirmed.")
        sys.exit(1)

    # ── Determine phases to run
    if args.phase == "all":
        phases_to_run = list(PHASES.keys())
    else:
        try:
            phases_to_run = [int(p.strip()) for p in args.phase.split(",")]
        except ValueError:
            error(f"Invalid phase specification: {args.phase}")
            sys.exit(1)

    info(f"Phases to run: {phases_to_run}")

    # ── Collect all credentials needed upfront
    all_secrets_needed = set()
    for num in phases_to_run:
        if num in PHASES:
            all_secrets_needed.update(PHASES[num].get("secrets_needed", []))

    creds = {}
    if all_secrets_needed and not args.dry_run:
        print(f"\n{BOLD}Collecting credentials for phases {phases_to_run}:{RESET}")
        creds = collect_credentials(list(all_secrets_needed))

    # ── Run phases in order
    for phase_num in sorted(phases_to_run):
        if phase_num not in PHASES:
            warn(f"Unknown phase: {phase_num}. Skipping.")
            continue
        run_phase(phase_num, config, creds, args.dry_run, log_file,
                  skip=args.skip, only=args.only)
        if phase_num < max(phases_to_run):
            print(f"\n{BOLD}  Phase {phase_num} complete. Ready for Phase {phase_num + 1}? [ENTER/q]: {RESET}", end="")
            if input().strip().lower() == "q":
                warn("Engagement paused by operator.")
                break

    ok(f"Orchestrator finished. Log: {log_file}")

if __name__ == "__main__":
    main()
