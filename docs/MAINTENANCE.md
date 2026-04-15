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
7. [Pre-Engagement Verification Checklist](#7-pre-engagement-verification-checklist)
8. [Versioning and Change Management](#8-versioning-and-change-management)

---

## 1. Maintenance Schedule

Perform these tasks before each engagement and at minimum once per quarter:

| Task | Before each engagement | Quarterly |
|------|----------------------|-----------|
| Run pre-engagement verification checklist | ✓ | ✓ |
| Check for pipx tool updates | ✓ | ✓ |
| Check for `nxc` / `crackmapexec` updates | ✓ | ✓ |
| Review new BloodHound CE release notes | | ✓ |
| Review new OWASP ZAP release notes | | ✓ |
| Check `requirements.txt` version pins still valid | | ✓ |
| Review new Kali release notes for breaking changes | | ✓ |
| Test on a lab environment | | ✓ |
| Update corporate patterns wordlist with new year | Annually | |

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

After a Docker upgrade, restart the BloodHound CE stack to ensure it runs against the new version:

```bash
docker compose -f tools/bloodhound-ce/docker-compose.yml down
docker compose -f tools/bloodhound-ce/docker-compose.yml pull
docker compose -f tools/bloodhound-ce/docker-compose.yml up -d
```

### Updating BloodHound CE

BloodHound CE updates are handled by updating the Docker image:

```bash
# Pull the latest image
docker pull specterops/bloodhound:latest

# Restart the stack
docker compose -f tools/bloodhound-ce/docker-compose.yml down
docker compose -f tools/bloodhound-ce/docker-compose.yml up -d
```

> **Note:** Major BloodHound CE versions may require database migrations. Read the release notes at https://github.com/SpecterOps/BloodHound/releases before pulling a new major version. The `-v` flag on `docker compose down` removes volumes (including the database) — do not use it unless you intend to wipe all collected data.

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

```bash
# ─── STEP 2.X — CONSTRAINED DELEGATION CHECK ─────────────────────────────────
CONSTRAINED_OUT="${AD_CHECKS}/constrained_delegation.txt"
if ! skip_if_exists "${CONSTRAINED_OUT}" "Constrained delegation check"; then
    log INFO "Checking for constrained delegation (msDS-AllowedToDelegateTo)..."
    log_cmd "ldapsearch -H ldap://${DC_IP} ... (constrained delegation filter)"
    ldapsearch -H "ldap://${DC_IP}" \
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

### Step 2 — Add to the finding summary block

In the same phase script, add the count to the end-of-phase summary:

```bash
[[ -f "${AD_CHECKS}/constrained_delegation.txt" ]] && \
    echo -e "${YELLOW}  Constrained delegation accounts: ${CON_COUNT:-?}${RESET}"
```

### Step 3 — Add to Phase 5 consolidation

In `phases/phase5_consolidate.sh`:

```bash
# Add to count extraction section
CON_DELEG=$(grep -c 'sAMAccountName' "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/constrained_delegation.txt" 2>/dev/null || echo 0)

# Add to evidence copy section
cp -u "${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/constrained_delegation.txt" "${EVIDENCE_DIR}/ad/" 2>/dev/null || true

# Add to scaffold table
| Constrained delegation accounts | ${CON_DELEG} | evidence/ad/constrained_delegation.txt |
```

### Step 4 — Update the README

Add the new check to the "What is automated" list in `README.md`.

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

## 7. Pre-Engagement Verification Checklist

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
echo "=== BloodHound CE stack ==="
docker compose -f tools/bloodhound-ce/docker-compose.yml ps 2>/dev/null | grep -qE 'running|Up' \
    && echo "  OK: BloodHound CE running" || echo "  NOT RUNNING — start with: docker compose -f tools/bloodhound-ce/docker-compose.yml up -d"

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

## 8. Versioning and Change Management

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

Breaking changes must be documented in the commit, and `config.env.example` must be updated to reflect them. Notify anyone else who maintains a `config.env` file based on the old template.
