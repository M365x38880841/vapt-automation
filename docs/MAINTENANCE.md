# Maintenance Guide

**Classification:** INTERNAL — Infrastructure Security Team  
**Applies to:** Ha-Shem VAPT Automation Framework

This document is for the person responsible for keeping the framework current between engagements. It covers dependency updates, adding new checks, known Kali compatibility issues, and how to verify the framework is working correctly before an engagement begins.

---

## Table of Contents

1. [Maintenance Schedule](#1-maintenance-schedule)
2. [Updating Python Tool Versions](#2-updating-python-tool-versions)
3. [Updating System Tool Versions](#3-updating-system-tool-versions)
4. [Adding a New Automated Check](#4-adding-a-new-automated-check)
5. [Adding a New Tool](#5-adding-a-new-tool)
6. [Known Kali Compatibility Issues](#6-known-kali-compatibility-issues)
7. [Purging a Broken Installation](#7-purging-a-broken-installation)
8. [Pre-Engagement Verification Checklist](#8-pre-engagement-verification-checklist)
9. [Versioning and Change Management](#9-versioning-and-change-management)

---

## 1. Maintenance Schedule

Perform these tasks before each engagement and at minimum once per quarter:

| Task | Before each engagement | Quarterly |
|------|----------------------|-----------|
| Run pre-engagement verification checklist | ✓ | ✓ |
| Check for pipx tool updates | ✓ | ✓ |
| Check for `nxc` / `crackmapexec` updates | ✓ | ✓ |
| Verify `config.env` has no placeholder values; `SCAN_EXCLUDE_RANGES` reflects current infra | ✓ | |
| Validate `NMAP_DISCOVERY_PORTS` is still appropriate for the target environment | ✓ | |
| Check for `bloodhound-cli` updates; upgrade if new version available | ✓ | ✓ |
| Review new BloodHound CE release notes | | ✓ |
| Review new OWASP ZAP release notes | | ✓ |
| Check `requirements.txt` version pins still valid | | ✓ |
| Review new Kali release notes for breaking changes | | ✓ |
| Test on a lab environment | | ✓ |
| Update corporate patterns wordlist with new year (ORG_WORDS / YEARS in phase0_setup.sh) | Annually | |

---

## 2. Updating Python Tool Versions

Python tools are managed via pipx. To update all tools at once:

```bash
# Update all pipx-managed tools
pipx upgrade-all

# Update a specific tool
pipx upgrade bloodhound
pipx upgrade roadrecon
pipx upgrade scoutsuite
pipx upgrade impacket
pipx upgrade certipy-ad
```

After upgrading, update the version pins in `requirements.txt`:

```bash
# Check installed versions
pipx list

# Update requirements.txt with new versions
# Example — edit manually to match what pipx list shows:
# bloodhound>=1.8.0,<2.0.0
```

### Version pin strategy

The `requirements.txt` file uses `>=` lower bound with `<` major version upper bound. This allows patch updates (bug fixes, security patches) while preventing major version upgrades that may break the command-line interface.

Example: `scoutsuite>=5.14.0,<6.0.0` — accepts 5.14.x and 5.15.x but not 6.x.

When you upgrade a tool and it works correctly in testing, update the lower bound to the new version so that future installs get the tested version.

### Verifying tool functionality after upgrade

```bash
# bloodhound-python
bloodhound-python --help | head -5

# roadrecon
roadrecon --help | head -5

# ScoutSuite — must use "scout suite" (two words)
scout suite --help | head -5

# Impacket tools
impacket-GetUserSPNs --help 2>&1 | head -5
impacket-secretsdump --help 2>&1 | head -5

# certipy-ad
certipy-ad --help | head -5
```

---

## 3. Updating System Tool Versions

System tools (nmap, hashcat, responder, nxc, ldap-utils) are managed via apt:

```bash
sudo apt-get update
sudo apt-get upgrade nmap hashcat responder ldap-utils

# For nxc (NetExec) — check the Kali repo version
apt-cache policy nxc netexec
sudo apt-get upgrade nxc || sudo apt-get upgrade netexec
```

### Checking for nxc / crackmapexec naming changes

Kali's packaging of NetExec has changed between releases. Verify which binary is available:

```bash
command -v nxc && echo "nxc available"
command -v crackmapexec && echo "crackmapexec available"
command -v netexec && echo "netexec available"
```

The framework auto-detects the correct binary via `detect_cme()` in `lib/common.sh`. If a new binary name is introduced by Kali, update `detect_cme()`:

```bash
# lib/common.sh — detect_cme()
detect_cme() {
    CME_BIN="${CME_BIN:-}"
    if [[ -n "${CME_BIN}" ]] && command -v "${CME_BIN}" &>/dev/null; then
        return 0
    fi
    CME_BIN=$(command -v nxc 2>/dev/null \
        || command -v crackmapexec 2>/dev/null \
        || command -v netexec 2>/dev/null \   # add new names here
        || echo "nxc")
    export CME_BIN
}
```

### Docker CE updates

Docker CE updates are handled via apt:

```bash
sudo apt-get update
sudo apt-get upgrade docker-ce docker-ce-cli docker-compose-plugin

# Verify compose plugin version
docker compose version
```

After a Docker upgrade, restart BloodHound CE to ensure it runs against the updated daemon:

```bash
bloodhound-cli stop
bloodhound-cli start
```

### Updating BloodHound CE

BloodHound CE is now managed via `bloodhound-cli`. Updates are handled by upgrading `bloodhound-cli` itself and then letting it pull the new images:

```bash
# Check current version
bloodhound-cli version

# Download the latest bloodhound-cli binary
_arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli_linux_${_arch}.tar.gz" \
    | tar -xz -C ~/.local/bin
bloodhound-cli version   # confirm new version

# Restart to pick up any new BloodHound CE container images
bloodhound-cli stop
bloodhound-cli start
```

> **Note:** Major BloodHound CE versions may require database migrations. Read the release notes at https://github.com/SpecterOps/BloodHound/releases before upgrading. If collected data needs to be preserved, export it from the BloodHound UI first.

### Updating OWASP ZAP

ZAP is pulled automatically when Phase 2 runs if the image is not present. To manually update:

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
```

The `:stable` tag always points to the latest stable release. If a ZAP update breaks the command-line interface, pin to a specific version tag (e.g. `:2.15.0`) in `phases/phase2_va.sh`:

```bash
# phases/phase2_va.sh
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:2.15.0"  # pin if needed
```

---

## 4. Adding a New Automated Check

Follow this pattern to add a new check to any phase. Use Phase 2 as an example.

### Step 1 — Write the check in the phase script

Pass the step key as the third argument to `skip_if_exists`. This is what wires the check into the `--skip` / `--only` system.

```bash
# ─── STEP 2.X — CONSTRAINED DELEGATION CHECK ─────────────────────────────────
CONSTRAINED_OUT="${AD_CHECKS}/constrained_delegation.txt"
if ! skip_if_exists "${CONSTRAINED_OUT}" "Constrained delegation check" "constrained_delegation"; then
    log INFO "Checking for constrained delegation (msDS-AllowedToDelegateTo)..."
    log_cmd "ldapsearch -H ldap://${PRIMARY_DC} ... (constrained delegation filter)"
    ldapsearch -H "ldap://${PRIMARY_DC}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo \
        2>&1 > "${CONSTRAINED_OUT}" || true
    CON_COUNT=$(grep -c 'sAMAccountName:' "${CONSTRAINED_OUT}" 2>/dev/null || echo 0)
    [[ "${CON_COUNT}" -gt 0 ]] && \
        log WARN "FINDING: ${CON_COUNT} account(s) with constrained delegation → ${CONSTRAINED_OUT}" || \
        log OK "No constrained delegation accounts found"
fi
```

For steps that don't use `skip_if_exists` (e.g. steps with no single output file), use `_step_is_skipped` directly:

```bash
if ! _step_is_skipped "constrained_delegation"; then
    # ... step body ...
fi
```

### Step 2 — Register the step key in orchestrator.py

Add the key and description to `STEP_REGISTRY` in `orchestrator.py`. This makes it visible in `--list-steps` output.

```python
# In STEP_REGISTRY, under the relevant phase number:
2: {
    ...
    "constrained_delegation": "AD constrained delegation check (msDS-AllowedToDelegateTo)",
},
```

> **This is a breaking change if the key is referenced in documentation or operator runbooks.** Rename carefully — see Section 9.

### Step 3 — Add to the finding summary block

In the same phase script, add the count to the end-of-phase summary:

```bash
[[ -f "${AD_CHECKS}/constrained_delegation.txt" ]] && \
    echo -e "${YELLOW}  Constrained delegation accounts: ${CON_COUNT:-?}${RESET}"
```

### Step 4 — Add to Phase 5 consolidation

In `phases/phase5_consolidate.sh`:

```bash
# Add to count extraction section
CON_DELEG=$(grep -c 'sAMAccountName' "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/constrained_delegation.txt" 2>/dev/null || echo 0)

# Add to evidence copy section
cp -u "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/constrained_delegation.txt" "${EVIDENCE_DIR}/ad/" 2>/dev/null || true

# Add to scaffold table
| Constrained delegation accounts | ${CON_DELEG} | evidence/ad/constrained_delegation.txt |
```

### Step 5 — Update the docs

- Add the step key to the step table in `docs/RUNBOOK.md §9b`
- Add the check to the "What is automated" list in `README.md`
- If the new check produces a background job, add it to `docs/RUNBOOK.md §9` monitoring reference table

---

## 5. Adding a New Tool

### Python tool via pipx

1. Add an install case in `phases/phase0_setup.sh`:
   ```bash
   TOOLS_OPTIONAL=(... newtool)
   # In the install loop:
   newtool)
       pip_install newtool-package-name && log OK "newtool installed" || \
           log WARN "newtool install failed"
       ;;
   ```

2. Add a version pin to `requirements.txt`:
   ```
   newtool-package-name>=1.0.0,<2.0.0
   ```

3. Verify the binary name after install:
   ```bash
   pipx list | grep newtool
   ```

4. Add any required binary name to `TOOLS_OPTIONAL` using the exact installed binary name (which may differ from the package name — e.g. package `certipy-ad` installs binary `certipy-ad`).

### System tool via apt

1. Add to `TOOLS_REQUIRED` or `TOOLS_OPTIONAL` in phase0.
2. Add an install case:
   ```bash
   newtool)
       sudo apt-get install -y newtool-apt-package
       ;;
   ```

3. Add a binary path override variable to `config.env.example`:
   ```bash
   NEWTOOL_BIN="newtool"
   ```

---

## 6. Known Kali Compatibility Issues

### Docker CE vs docker.io

Kali's default Docker package (`docker.io`) is the Debian community build, which:
- Lags behind the upstream Docker CE version
- Does not include `docker-compose-plugin` by default
- May not support newer Docker Compose features

The framework installs Docker CE from the upstream repository at `download.docker.com/linux/debian`. If you encounter issues with the upstream repository on a new Kali release, check whether Kali has changed its Debian base codename:

```bash
# Check Kali's Debian base codename
cat /etc/debian_version
# or
lsb_release -cs

# The Docker CE repo entry in /etc/apt/sources.list.d/docker.list
# must match the Debian codename (currently "bookworm")
```

If Kali upgrades its base to a new Debian codename (e.g. `trixie`), update the repo line in `ensure_docker()` in `phases/phase0_setup.sh`:
```bash
"deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian trixie stable"
```

### pipx PATH on Kali

pipx installs binaries to `~/.local/bin`. This directory is added to `PATH` by `pipx ensurepath`, but only takes effect in new shell sessions (it modifies `~/.bashrc`). Phase 0 works around this by explicitly running `export PATH="${HOME}/.local/bin:${PATH}"` at the start of each session.

If pipx-installed tools are not found in a new terminal session, verify `~/.local/bin` is in `PATH`:
```bash
echo $PATH | tr ':' '\n' | grep local
# Should show: /home/<user>/.local/bin
```

If not, add to `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="${HOME}/.local/bin:${PATH}"
```

### nxc / crackmapexec command differences

`nxc` and `crackmapexec` share the same command-line interface for the commands used in this framework. However, some module names may differ between versions. If a module (e.g. `ms17-010`, `nopac`) fails with "Module not found", check the available modules:

```bash
nxc smb -L 2>/dev/null | grep -i 'ms17\|nopac\|petitpotam'
```

Update the module name in `phases/phase2_va.sh` if it has changed.

### ScoutSuite Azure API rate limits

ScoutSuite makes many parallel Azure API calls. On tenants with many resources, this can trigger Azure API throttling, causing some checks to return incomplete results. Signs: ScoutSuite log shows many `429 Too Many Requests` errors.

Workaround: ScoutSuite does not currently have a built-in rate-limit option. If throttling is a problem, run ScoutSuite for one subscription at a time (which the framework already does) and schedule runs outside peak hours.

### Responder config path

Responder's configuration file location has varied across Kali versions:
- Kali < 2022: `/etc/responder/Responder.conf`
- Kali 2022+: `/usr/share/responder/Responder.conf`

The framework uses `find` to locate the config:
```bash
RESP_CONF=$(find /usr/share/responder /etc/responder -name 'Responder.conf' 2>/dev/null | head -1)
```

If Responder is installed in a non-standard location (e.g. via pipx or a custom install), verify the config path:
```bash
find / -name 'Responder.conf' 2>/dev/null
```

### certipy-ad binary name

`certipy-ad` has been packaged under two binary names: `certipy` and `certipy-ad`. The framework checks for both:
```bash
CERTIPY_CMD=$(command -v certipy-ad 2>/dev/null || command -v certipy 2>/dev/null || echo "")
```

If neither is found despite a successful `pip_install certipy-ad`, check:
```bash
pipx list | grep certipy
~/.local/bin/certipy-ad --help
```

---

## 7. Purging a Broken Installation

Use `tools/purge_tools.sh` when tool installations have become inconsistent — for example when the same tool was installed via apt, pip, and pipx simultaneously, leaving conflicting binaries on PATH, or when an Azure CLI install from the Kali repo left behind a stale apt source that prevents the Microsoft version from installing cleanly.

### When to use it

- Azure CLI reports version mismatches or authentication errors that survive `az login`
- `which az` returns an unexpected path (e.g. `/usr/bin/az` instead of `/usr/bin/az` from the Microsoft repo)
- `pip3 show bloodhound` and `pipx list` both show bloodhound — two copies fighting for the same binary name
- Phase 0 installs a tool but the wrong version is invoked because an older apt-installed copy takes PATH precedence
- Any `command -v <tool>` returns a path you did not expect

### Usage

```bash
# Interactive — prompts before removing each group
bash tools/purge_tools.sh

# Dry run — shows exactly what would be removed without touching anything
bash tools/purge_tools.sh --dry-run

# Non-interactive — removes everything without prompting (CI / full reset)
bash tools/purge_tools.sh --yes
```

### What it removes

| Group | Scope |
|-------|-------|
| Azure CLI | apt package, Microsoft apt repo entry, GPG key(s), pip3 install, pipx install, optionally `~/.azure` |
| Python tools | bloodhound, roadrecon, impacket, certipy-ad, scoutsuite — from both pipx and system pip3 |
| Docker | All CE packages, legacy docker.io, apt repo entry, GPG key, optionally `/var/lib/docker` |
| nxc / crackmapexec | apt, pip3, and pipx installs of both binary names |
| apt cache | `apt-get clean` + `autoclean` |

Each group is independently confirmable in interactive mode — if only Azure CLI is broken, purge that group and skip the rest.

> **Warning:** Removing Docker also destroys the BloodHound CE database (Neo4j volume). If collected BloodHound data needs to be preserved, export it from the BloodHound UI before running the purge.

### After purging

Re-run Phase 0 to reinstall everything cleanly:

```bash
python3 orchestrator.py --phase 0
```

Or verify the current state first without making any changes:

```bash
bash tools/verify.sh
```

---

## 8. Pre-Engagement Verification Checklist

> The automated version of this checklist is `tools/verify.sh`. Run it instead of the manual steps below when possible.

Run this on the attack machine at least 48 hours before the engagement starts. This allows time to fix issues before Day 1.

```bash
#!/usr/bin/env bash
# Quick pre-engagement verification
echo "=== Tool availability ==="
for tool in nmap nxc crackmapexec responder hashcat bloodhound-python \
            roadrecon ldapsearch az docker certipy-ad impacket-GetUserSPNs; do
    command -v "$tool" && echo "  OK: $tool" || echo "  MISSING: $tool"
done

echo ""
echo "=== ScoutSuite invocation ==="
scout suite --help &>/dev/null && echo "  OK: scout suite" || echo "  FAIL: scout suite"

echo ""
echo "=== Docker ==="
docker info &>/dev/null && echo "  OK: Docker daemon" || echo "  FAIL: Docker daemon not running"
docker compose version && echo "  OK: docker compose plugin" || echo "  FAIL: compose plugin missing"

echo ""
echo "=== bloodhound-cli ==="
command -v bloodhound-cli && bloodhound-cli version || echo "  MISSING — Phase 0 will auto-download from GitHub releases"

echo ""
echo "=== BloodHound CE stack ==="
bloodhound-cli status 2>/dev/null | grep -qiE 'running|healthy|started' \
    && echo "  OK: BloodHound CE running" || echo "  NOT RUNNING — start with: bloodhound-cli start"

echo ""
echo "=== Azure CLI ==="
az account show --query 'user.name' -o tsv 2>/dev/null && echo "  OK: Azure CLI authenticated" || echo "  NOT LOGGED IN — run: az login"

echo ""
echo "=== Wordlists ==="
[[ -f /usr/share/wordlists/rockyou.txt ]] && echo "  OK: rockyou.txt" || echo "  MISSING: rockyou.txt"
[[ -f /usr/share/hashcat/rules/best64.rule ]] && echo "  OK: best64.rule" || echo "  MISSING: best64.rule"

echo ""
echo "=== config.env ==="
[[ -f config.env ]] && echo "  OK: config.env exists" || echo "  MISSING: copy from config.env.example"
grep -c 'xxxxxxxx\|COMPLETE\|TODO' config.env 2>/dev/null \
    && echo "  WARN: unfilled placeholder values in config.env" || echo "  OK: no obvious placeholders"
```

Save this as `tools/verify.sh` and run it before each engagement.

---

## 9. Versioning and Change Management

### Version tagging

Tag the framework repository before and after each engagement:

```bash
# Before engagement
git tag -a v2026.04-pre "Pre-engagement: HaShem VAPT April 2026"

# After engagement (any changes made during)
git tag -a v2026.04-post "Post-engagement: tool updates and fixes from April 2026 run"
```

This provides a clean reference point for what version was used during each engagement, which may be needed for audit purposes.

### Change log discipline

Any change to the framework — even a minor tool update — should be documented in a commit message that answers: what changed, why, and whether any phase behaviour changed as a result.

Good commit message:
```
fix(phase3): merge all Responder NTLMv2 capture files before hashcat

Previously only the first SMB-NTLMv2-*.txt file was passed to hashcat.
Responder creates one file per victim — multiple users' hashes were
being silently skipped. Now all capture files are merged into
ntlmv2_all.txt with deduplication before cracking.
```

Poor commit message:
```
update hashcat stuff
```

### Breaking changes

A change is a **breaking change** if it:
- Renames or removes a `config.env` variable
- Changes the output path or format of a file that downstream phases or Phase 5 depends on
- Changes the interface of a `lib/common.sh` function
- **Renames or removes a step key** in `STEP_REGISTRY` (operators may have these in scripts, cron jobs, or runbook notes)

Breaking changes must be documented in the commit, and `config.env.example` must be updated to reflect them. For step key renames, update `STEP_REGISTRY` in `orchestrator.py`, all `skip_if_exists` / `_step_is_skipped` calls in the phase scripts, and the step table in `docs/RUNBOOK.md §9b`. Notify anyone else who maintains operator runbooks or automation that calls the orchestrator with `--skip` or `--only`.
