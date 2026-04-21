# Architecture and Design Reference

**Classification:** INTERNAL — Infrastructure Security Team  
**Applies to:** Ha-Shem VAPT Automation Framework

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Component Overview](#2-component-overview)
3. [Execution Model](#3-execution-model)
4. [Credential Flow](#4-credential-flow)
5. [Background Job Model](#5-background-job-model)
6. [Tool Selection Rationale](#6-tool-selection-rationale)
7. [Output and Evidence Model](#7-output-and-evidence-model)
8. [Extending the Framework](#8-extending-the-framework)

---

## 1. Design Principles

The framework was designed around six constraints that define every architectural decision:

**1. Humans own decisions; scripts own mechanics.**
No lateral movement, relay confirmation, DCSync, or Metasploit execution runs without a human at the keyboard explicitly confirming. Automation handles scan invocation, background job management, output parsing, and evidence organisation. Judgment remains with the operator.

**2. No secrets at rest.**
`config.env` contains only non-sensitive configuration (IPs, subnets, tenant IDs). Credentials are prompted at runtime via Python's `getpass` module and passed only as environment variables to child processes. They are never written to any file, log, or config.

**3. Idempotent by default.**
Every step checks whether its output already exists (`skip_if_exists()`) before running. Re-running a phase after a partial failure will resume from where it stopped — it will not re-scan hosts that have already been scanned.

**4. Audit-first.**
Every command execution is logged to `engagement_log.md` with a timestamp before it runs. Every checkpoint decision (proceed / skip / abort) is logged. This log is the legal record of what was done and when.

**5. Fail loud, not silent.**
`set -euo pipefail` is set in every script. Commands that are expected to fail (e.g. checking null sessions) use explicit `|| true`. Unhandled errors stop the script immediately rather than silently continuing to the next step.

**6. Kali-portable.**
Every tool install path accounts for Kali-specific behaviours: Docker CE (not docker.io), pipx for Python tools (PEP 668 compliance on Kali 2023.1+), `nxc` as the default CME binary on Kali 2024+, and `find`-based config path discovery for tools like Responder whose config location varies across Kali versions.

---

## 2. Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OPERATOR                                    │
│  python3 orchestrator.py [--phase N] [--dry-run] [--status]        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │  config.env (non-sensitive)
                            │  getpass prompts (credentials)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    orchestrator.py                                  │
│                                                                     │
│  • Loads and validates config.env                                   │
│  • Collects credentials via getpass                                 │
│  • Enforces RoE confirmation gate                                   │
│  • Enforces business hours gate                                     │
│  • Sequences phase execution                                        │
│  • Writes phase start/end markers to engagement_log.md             │
│  • Renders manual steps after each automated phase                  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │  subprocess.run(["bash", "phases/phaseN.sh"])
                            │  env = config + credentials (process env only)
                            ▼
┌───────────────┐  ┌───────────────┐  ┌──────────────┐  ┌───────────┐
│ phase0_setup  │  │phase1_discov. │  │ phase2_va.sh │  │ phase3_   │
│     .sh       │  │     .sh       │  │              │  │ exploit.sh│
│               │  │               │  │              │  │           │
│ Tool install  │  │ Nmap sweeps   │  │ ScoutSuite   │  │ Responder │
│ Docker setup  │  │ CME SMB       │  │ Azure checks │  │ Kerberoast│
│ BloodHound CE │  │ LDAP enum     │  │ AD CS certipy│  │ AS-REP    │
│ Azure CLI     │  │ BloodHound    │  │ SMB vulns    │  │ Hashcat   │
│ Wordlists     │  │ ROADrecon     │  │ OWASP ZAP    │  │ NTLM relay│
│               │  │ Azure inv.    │  │ Nessus API   │  │ PtH sweep │
└───────────────┘  └───────────────┘  └──────────────┘  └───────────┘
        │                  │                  │                │
        └──────────────────┴──────────────────┴────────────────┘
                            │  source
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       lib/common.sh                                 │
│                                                                     │
│  pip_install()      detect_cme()       set_scout_cmd()             │
│  checkpoint()       bg_run()           wait_for_bg_jobs()          │
│  log()              skip_if_exists()   notify_complete()           │
│  require_tool()     require_var()      cleanup_on_exit()           │
│  check_testing_window()                phase_dir()                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Execution Model

### Orchestrator → Shell handoff

The orchestrator (`orchestrator.py`) is the single entry point. It does not run any security tools directly — it validates configuration, collects credentials, and then hands off to a Bash script via `subprocess.run()`.

Credentials and config variables are passed as process environment variables:
```python
env = os.environ.copy()
env.update(config)   # non-sensitive config variables
env.update(creds)    # credentials (in-process memory only)
subprocess.run(["bash", "phases/phaseN.sh"], env=env)
```

This means:
- No credential values appear in the script source
- The environment is scoped to the subprocess — it does not persist to the shell after the process exits
- Credentials are visible in `/proc/<pid>/environ` while the process runs (root or same UID can read this — accepted trade-off for interactive tooling; see [SECURITY.md](SECURITY.md))

### Checkpoint gates

Every phase script calls `checkpoint()` before sensitive actions. This function:
1. Displays what is about to happen
2. Prompts the operator for `[ENTER]` / `s` (skip) / `q` (abort)
3. Writes the decision to `engagement_log.md` with a timestamp
4. Returns 0 (proceed) or 1 (skip) — `q` calls `exit 1`

**Non-interactive bypass:** passing `--auto-approve` to the orchestrator sets `AUTO_APPROVE=true` in the environment. The `checkpoint()` function in `lib/common.sh` checks this variable and auto-proceeds, logging `Checkpoint auto-proceeded`. This is intended for demo runs, dry-runs, and CI/CD pipelines — it should never be used during live exploitation phases (3, 4). The Python `check_testing_window()` function also respects `--auto-approve` and `--dry-run`, bypassing the business hours prompt automatically in those modes.

All `input()` calls in the orchestrator have `EOFError` guards so that piping stdin (e.g. `echo y | python3 orchestrator.py`) does not cause a crash.

### `set -euo pipefail`

Every phase script uses `set -euo pipefail`. This means:
- Any unhandled non-zero exit code stops the script immediately (`-e`)
- Undefined variables cause an error (`-u`)
- Pipeline failures are propagated (`-o pipefail`)

Commands that are legitimately expected to fail use explicit `|| true` or `|| log WARN ...`. This is intentional — it forces each addition to the scripts to explicitly handle failure rather than silently continuing.

---

## 4. Credential Flow

```
Operator keyboard input
        │
        │  getpass.getpass() — hidden terminal input, never echoed
        ▼
orchestrator.py in-memory dict (creds{})
        │
        │  env.update(creds) — added to subprocess environment
        ▼
Phase script environment variables
  e.g. DOMAIN_PASS, OBTAINED_HASH
        │
        │  Used inline in commands (e.g. -p "${DOMAIN_PASS}")
        │
        ├─► Command line args: visible in /proc/<pid>/cmdline
        │   Risk: low in isolated engagement environment (root-only host)
        │
        └─► Log redirection: passwords masked in log_cmd() calls
            (log_cmd logs the command template, not the credential value)

After subprocess exits:
  • env dict goes out of scope
  • No file write ever occurs
  • Terminal scrollback may retain prompts (not values, which were hidden)
```

Credentials are prompted **once per orchestrator run** (not once per phase). All phases that need the same credential reuse the value collected at startup — the operator is not re-prompted.

---

## 5. Background Job Model

Long-running tools (Nmap, Hashcat, Responder, BloodHound, ROADrecon, ScoutSuite, ZAP) are launched with `bg_run()`:

```bash
bg_run "job_name" "log_file_path" command [args...]
```

`bg_run` appends the PID to `BG_JOB_PIDS[]` and the name to `BG_JOB_NAMES[]`. These arrays are used by:
- `wait_for_bg_jobs()` — blocks until all tracked jobs complete
- `status_bg_jobs()` — prints live/done status for each job
- `cleanup_on_exit()` — kills every tracked process group on Ctrl+C

Every background job PID is also written to `${OUTPUT_BASE_DIR}/.bg_jobs` (format: `PID|name|logfile|started_at`). This file survives terminal close and is read by `orchestrator.py --status` to report job completion across sessions.

**System-adaptive parallelism:** `detect_system_resources()` (called at phase startup) detects vCPU count and RAM at runtime and exports tuning constants:

| Export | Formula (4-vCPU example) | Used by |
|--------|--------------------------|---------|
| `NMAP_MIN_PARALLEL` | `vCPUs × 10` = 40 | nmap `--min-parallelism` |
| `NMAP_MAX_PARALLEL` | `vCPUs × 50`, cap 500 = 200 | nmap `--max-parallelism` |
| `HC_WORKLOAD` | `3` (high) if ≥4 vCPUs, else `2` | hashcat `-w` |
| `BH_WORKERS` | `vCPUs × 5`, cap 40 = 20 | bloodhound-python `-w` |

**Parallel Nmap full-port scan:** For host lists >50 entries, Phase 1 splits the host list into `SYS_VCPUS` chunks using `split -l` and launches one `nmap -p-` process per chunk as a background job. A separate merge-watcher background job polls every 30 seconds until all chunk `.xml` files appear (nmap writes `.xml` atomically at completion), then concatenates the `.gnmap` and `.nmap` files into `fullscan.gnmap` / `fullscan.nmap`. On a 4-vCPU system this yields approximately 4× wall-clock speedup over a single sequential scan.

**Hashcat concurrent output files:** The three NTLMv2 cracking jobs (rockyou, rules, corporate) each write to a separate output file (`cracked_ntlm_rockyou.txt`, etc.) to prevent concurrent-write corruption. A merge step combines them into `cracked_ntlm.txt` which downstream phases and Phase 5 reference.

**Limitation:** `BG_JOB_PIDS` is a shell array local to the running phase script. It does not persist across phase invocations. `orchestrator.py --status` addresses this by reading `.bg_jobs` on disk (process state) and `engagement_log.md` (phase start/end markers) rather than relying on in-memory arrays.

**Sudo-wrapped processes (Responder):** Responder runs under `sudo timeout`, which creates a process tree: shell → sudo → timeout → responder. `cleanup_on_exit()` kills the entire process group (`kill -- -<pgid>`) rather than just the top-level PID to ensure the responder process itself is killed.

---

## 6. Tool Selection Rationale

### Network discovery — Nmap
Nmap is the industry standard. SYN scan (`-sS`) with service detection (`-sV`) and default scripts (`-sC`) provides the best balance of coverage and reliability. Alternatives considered: masscan (faster but less reliable service detection), naabu (Go-based, good for large scopes but requires Go runtime).

**Host discovery — TCP SYN only, no ICMP/ARP:** The host sweep uses `nmap -sS --open -p <NMAP_DISCOVERY_PORTS>` rather than the `-sn` ping sweep. The `-sn` default sends ICMP echo + ICMP timestamp + TCP SYN/ACK to ports 80/443 — every router, switch, printer, UPS, and IPMI card on an enterprise network responds to ICMP, generating hundreds of false positives. TCP SYN probes to SMB (445), RDP (3389), and WinRM (5985) only produce responses from real Windows workstations and servers. `--max-retries 1` (vs. nmap's default 6) further reduces false positives from filtered ports being re-probed. `SCAN_EXCLUDE_RANGES` allows explicitly excluding known infrastructure.

**Full-port scan parallelism:** The full-port scan (`-p-`) is split across `SYS_VCPUS` parallel nmap processes to maximise CPU utilisation. A merge-watcher job auto-consolidates results when all chunks complete. Timing uses `T3` (normal) rather than `T4` (aggressive) for better accuracy on congested internal networks.

### SMB enumeration — NetExec (nxc) / CrackMapExec
CrackMapExec was the standard for Windows/SMB enumeration. It was renamed and re-maintained as NetExec (`nxc`) from 2023. The framework auto-detects whichever is installed via `detect_cme()`. The command interface is identical between the two.

### AD enumeration — Impacket suite
Impacket provides Python implementations of Windows network protocols including Kerberos, SMB, and MSRPC. The `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-secretsdump`, and `impacket-ntlmrelayx` tools are the gold standard for AD offensive operations. No credible alternative provides equivalent coverage in a Linux environment.

### AD graph analysis — BloodHound CE
BloodHound Community Edition (CE) provides graph-based attack path analysis of Active Directory. Running it via Docker Compose avoids the Java/Neo4j version complexity that plagued standalone BloodHound installations. The `bloodhound-python` collector (installed via pipx) handles collection from Linux without requiring a domain-joined machine.

### Entra ID enumeration — ROADrecon
ROADrecon (ROADtools) provides comprehensive Entra ID enumeration including users, groups, applications, service principals, role assignments, and Conditional Access policies. Its SQLite database output integrates with the ROADrecon GUI for visual analysis. Alternative: `az ad` CLI commands are used in parallel for raw data capture.

### Cloud security audit — ScoutSuite
ScoutSuite provides automated multi-service cloud security auditing against a defined ruleset. Its HTML report maps directly to findings. Alternative: Prowler provides similar coverage with JSON output and Compliance mapping — consider adding Prowler as a complementary tool for future engagements.

### AD Certificate Services — certipy-ad
Certipy automates the discovery and exploitation of Active Directory Certificate Services misconfigurations (ESC1–ESC8). It is the only tool that comprehensively covers the AD CS attack surface from Linux without requiring domain membership.

### Password cracking — Hashcat
Hashcat is the fastest CPU/GPU password cracker available. The framework runs three NTLMv2 cracking jobs in parallel: rockyou (coverage), rockyou + best64 rules (rule-based mutations), and corporate patterns (organisation-specific wordlist generated in Phase 0). Each job writes to its own output file to prevent concurrent-write corruption; results are merged into `cracked_ntlm.txt`. Workload profile (`-w`) and kernel selection (`--optimized-kernel-enable`) are tuned to the detected vCPU count via `detect_system_resources()`. Alternative: John the Ripper is slower and less GPU-optimised.

### LLMNR/NBT-NS poisoning — Responder
Responder is the standard tool for capturing NTLMv2 challenge-response hashes via LLMNR, NBT-NS, and MDNS poisoning. The `-rdwF` flags enable Responder, WPAD rogue proxy, and forced authentication. In relay mode (SMB/HTTP disabled), it works with `impacket-ntlmrelayx`.

### Web DAST — OWASP ZAP via Docker
ZAP (Zed Attack Proxy) was chosen over alternatives for the following reasons:
- Docker delivery: no Java version conflicts on Kali, consistent environment across engagements
- Passive baseline mode: safe for non-destructive initial pass
- Active scan mode: available when RoE explicitly covers active web testing
- JSON/HTML/XML report output: machine-parseable for scaffold pre-population
- `ghcr.io/zaproxy/zaproxy:stable` is the official maintained image
- Alternative considered: Nuclei (template-based, faster, but requires separate template management)

---

## 7. Output and Evidence Model

Evidence is written in three tiers:

**Tier 1 — Raw output:** Tool output written directly to phase directories during execution. These are the authoritative records. Format varies by tool (XML, JSON, plain text, SQLite).

**Tier 2 — Processed summaries:** Log entries in `engagement_log.md`, finding counts extracted by grep/wc, relay target IP lists, userlist.txt. These make raw data operationally useful.

**Tier 3 — Consolidated evidence:** Phase 5 copies relevant files from Tiers 1 and 2 into `report/evidence/`, structured by category. This is what the report references.

The `skip_if_exists()` function checks for Tier 1 outputs before re-running any step. This makes the output directory the canonical source of truth for what has already been done.

---

## 8. Extending the Framework

### Adding a new check to an existing phase

1. In the relevant `phases/phaseN.sh`, add a new section following the established pattern:
   ```bash
   # ─── STEP N.X — DESCRIPTION ──────────────────────────────────
   OUT_FILE="${OUT_DIR}/new_check.txt"
   if ! skip_if_exists "${OUT_FILE}" "Human-readable description"; then
       log INFO "Running new check..."
       log_cmd "tool arguments"
       tool arguments 2>&1 > "${OUT_FILE}" || true
       COUNT=$(grep -c 'pattern' "${OUT_FILE}" 2>/dev/null || echo 0)
       [[ "${COUNT}" -gt 0 ]] && log WARN "FINDING: ${COUNT} hits" || log OK "No issues found"
   fi
   ```

2. Add the finding count to Phase 5 consolidation and the report scaffold table.

3. Add any new required tools to `TOOLS_REQUIRED` or `TOOLS_OPTIONAL` in `phase0_setup.sh` with an install case.

### Adding a new tool

1. Add the binary name to `TOOLS_REQUIRED` or `TOOLS_OPTIONAL` in `phase0_setup.sh`.
2. Add an install case in the auto-install section using `pip_install` (Python tools) or `sudo apt-get install` (system tools).
3. Add the tool version to `requirements.txt` if it is a Python package.
4. Add a binary path override variable to `config.env.example` following the existing pattern.

### Adding a new phase

1. Create `phases/phaseN.sh` following the structure of existing phases:
   - `set -euo pipefail`
   - `source "${SCRIPT_DIR}/../lib/common.sh"`
   - `log PHASE "..."` and `check_testing_window`
   - `detect_system_resources` if the phase launches parallel or background work
   - `require_var` calls for all needed variables
   - `detect_cme` if the phase uses CME/nxc for network operations
2. Register the phase in `PHASES` dict in `orchestrator.py` with name, script path, days, automatable flag, secrets_needed, and background_jobs.
3. Update the README phase table.
