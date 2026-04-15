#!/usr/bin/env bash
# ============================================================================
# tools/purge_tools.sh — Clean-slate tool removal before a fresh Phase 0 run
#
# Use this when tool installations have become inconsistent — e.g. the same
# tool was installed via apt, pip, AND pipx, causing PATH conflicts or the
# wrong binary being resolved.
#
# After running this script, run Phase 0 to reinstall cleanly:
#   python3 orchestrator.py --phase 0
#
# Usage:
#   bash tools/purge_tools.sh              # interactive — prompts before each group
#   bash tools/purge_tools.sh --yes        # non-interactive — purge everything
#   bash tools/purge_tools.sh --dry-run    # show what would be removed without doing it
# ============================================================================
set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BOLD='\033[1m'; CYAN='\033[0;36m'; RESET='\033[0m'

DRY_RUN=false
AUTO_YES=false
for arg in "$@"; do
    [[ "$arg" == "--dry-run" ]] && DRY_RUN=true
    [[ "$arg" == "--yes" ]]     && AUTO_YES=true
done

REMOVED=0; SKIPPED=0; WARNINGS=0

info()  { echo -e "${CYAN}  [INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}  [OK]${RESET}    $*"; (( REMOVED++ )) || true; }
warn()  { echo -e "${YELLOW}  [WARN]${RESET}  $*"; (( WARNINGS++ )) || true; }
skip()  { echo -e "  [SKIP]  $*"; (( SKIPPED++ )) || true; }
header(){ echo -e "\n${BOLD}$*${RESET}"; }

run() {
    # run "description" command [args...]
    local desc="$1"; shift
    if $DRY_RUN; then
        echo -e "  ${CYAN}[DRY-RUN]${RESET}  $*"
        return 0
    fi
    "$@" && ok "${desc}" || warn "${desc} — command returned non-zero (may already be removed)"
}

confirm() {
    # confirm "prompt" — returns 0 (proceed) or 1 (skip group)
    local prompt="$1"
    $AUTO_YES && return 0
    echo -e "${YELLOW}  Purge: ${prompt}? [y/N]:${RESET} \c"
    read -r answer
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

echo -e "${BOLD}${RED}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       VAPT Framework — Tool Purge Utility           ║"
echo "  ║  Removes all framework-managed tool installations   ║"
echo "  ║  so Phase 0 can reinstall from a clean slate.       ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

$DRY_RUN  && echo -e "${CYAN}  DRY-RUN mode — nothing will be removed.${RESET}\n"
$AUTO_YES && echo -e "${YELLOW}  --yes mode — all groups will be purged without prompting.${RESET}\n"

# ─── AZURE CLI ────────────────────────────────────────────────────────────────
header "1. Azure CLI"
# Messy Kali scenarios:
#   a) Microsoft apt repo installed it correctly                → remove via apt + repo cleanup
#   b) Kali's own azure-cli package installed it               → remove via apt
#   c) pip/pip3 installed it into the system Python            → remove via pip
#   d) pipx installed it                                       → remove via pipx
#   e) Manual tarball / compiled — handled by apt remove fallback

if confirm "Azure CLI (all install sources)"; then
    # 1a/1b: apt — covers both Microsoft repo and Kali repo versions
    if dpkg -l azure-cli &>/dev/null 2>&1; then
        run "Remove azure-cli apt package" sudo apt-get remove -y --purge azure-cli
    else
        skip "azure-cli not installed via apt"
    fi

    # Remove Microsoft apt repository entry (prevents stale/conflicting repo)
    if [[ -f /etc/apt/sources.list.d/azure-cli.list ]]; then
        run "Remove Microsoft azure-cli apt repo" sudo rm -f /etc/apt/sources.list.d/azure-cli.list
    fi
    if [[ -f /etc/apt/keyrings/microsoft.gpg ]]; then
        run "Remove Microsoft GPG key (azure-cli)" sudo rm -f /etc/apt/keyrings/microsoft.gpg
    fi
    # The Microsoft install script may also write to trusted.gpg.d
    if [[ -f /etc/apt/trusted.gpg.d/microsoft.gpg ]]; then
        run "Remove Microsoft GPG key (trusted.gpg.d)" sudo rm -f /etc/apt/trusted.gpg.d/microsoft.gpg
    fi

    # 1c: pip-installed azure-cli in system Python
    if pip3 show azure-cli &>/dev/null 2>&1; then
        run "Remove azure-cli from system pip3" \
            sudo pip3 uninstall -y azure-cli 2>/dev/null || \
            pip3 uninstall -y azure-cli --break-system-packages 2>/dev/null || true
    else
        skip "azure-cli not in system pip3"
    fi

    # 1d: pipx-installed azure-cli
    if pipx list 2>/dev/null | grep -q 'azure-cli'; then
        run "Remove azure-cli from pipx" pipx uninstall azure-cli
    else
        skip "azure-cli not in pipx"
    fi

    # Remove leftover config / cache
    if [[ -d "${HOME}/.azure" ]]; then
        warn "~/.azure exists — this contains Azure login tokens and subscription state."
        if confirm "Remove ~/.azure (you will need to re-login after reinstall)"; then
            run "Remove ~/.azure" rm -rf "${HOME}/.azure"
        fi
    fi

    sudo apt-get autoremove -y --purge &>/dev/null || true
    sudo apt-get update -qq 2>/dev/null || true
    info "Azure CLI purge complete. Reinstall with: python3 orchestrator.py --phase 0"
else
    skip "Azure CLI — skipped by operator"
fi

# ─── PYTHON PENTEST TOOLS (pipx + pip) ────────────────────────────────────────
header "2. Python pentest tools (bloodhound-python, roadrecon, impacket, certipy-ad, scoutsuite)"

PIPX_TOOLS=(bloodhound roadrecon impacket certipy-ad scoutsuite)
PIP_PACKAGES=(bloodhound roadrecon impacket certipy-ad scoutsuite)

if confirm "Python pentest tools (pipx + system pip)"; then
    # pipx — clean uninstall for each tool
    if command -v pipx &>/dev/null; then
        for tool in "${PIPX_TOOLS[@]}"; do
            if pipx list 2>/dev/null | grep -q "${tool}"; then
                run "Remove ${tool} from pipx" pipx uninstall "${tool}"
            else
                skip "${tool} not in pipx"
            fi
        done
    else
        skip "pipx not installed"
    fi

    # System pip3 — removes anything installed with pip3 install / --break-system-packages
    for pkg in "${PIP_PACKAGES[@]}"; do
        if pip3 show "${pkg}" &>/dev/null 2>&1; then
            run "Remove ${pkg} from system pip3" \
                sudo pip3 uninstall -y "${pkg}" 2>/dev/null || \
                pip3 uninstall -y "${pkg}" 2>/dev/null || true
        else
            skip "${pkg} not in system pip3"
        fi
    done

    # Stale pipx venv directory (catches renamed/leftover venvs)
    PIPX_HOME="${PIPX_HOME:-${HOME}/.local/pipx}"
    if [[ -d "${PIPX_HOME}/venvs" ]]; then
        info "pipx venvs directory: ${PIPX_HOME}/venvs"
        info "Remaining venvs after uninstall: $(ls "${PIPX_HOME}/venvs" 2>/dev/null | tr '\n' ' ' || echo 'none')"
    fi

    info "Python tools purge complete."
else
    skip "Python pentest tools — skipped by operator"
fi

# ─── DOCKER ──────────────────────────────────────────────────────────────────
header "3. Docker"
warn "Removing Docker will destroy the BloodHound CE stack including its database."
warn "All collected BloodHound data will be lost."

if confirm "Docker CE + compose plugin (DESTRUCTIVE — loses BloodHound data)"; then
    # Stop BloodHound CE stack first so containers exit cleanly
    BHCE_COMPOSE="$(dirname "$0")/bloodhound-ce/docker-compose.yml"
    if [[ -f "${BHCE_COMPOSE}" ]] && command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        run "Stop BloodHound CE stack" docker compose -f "${BHCE_COMPOSE}" down 2>/dev/null || true
    fi

    # Remove all Docker CE packages
    run "Remove Docker CE packages" \
        sudo apt-get remove -y --purge \
            docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin \
            docker-ce-rootless-extras 2>/dev/null || true

    # Also remove legacy docker.io if present
    if dpkg -l docker.io &>/dev/null 2>&1; then
        run "Remove docker.io (legacy)" sudo apt-get remove -y --purge docker.io
    fi

    # Remove Docker apt repository entry
    if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
        run "Remove Docker apt repo" sudo rm -f /etc/apt/sources.list.d/docker.list
    fi
    if [[ -f /etc/apt/keyrings/docker.gpg ]]; then
        run "Remove Docker GPG key" sudo rm -f /etc/apt/keyrings/docker.gpg
    fi

    # Remove Docker data (images, volumes, networks)
    if confirm "Remove /var/lib/docker (all images, volumes, and container data)"; then
        run "Remove /var/lib/docker" sudo rm -rf /var/lib/docker
        run "Remove /var/lib/containerd" sudo rm -rf /var/lib/containerd
    else
        skip "Docker data directory — keeping /var/lib/docker"
    fi

    sudo apt-get autoremove -y --purge &>/dev/null || true
    sudo apt-get update -qq 2>/dev/null || true
    info "Docker purge complete. Reinstall with: python3 orchestrator.py --phase 0"
else
    skip "Docker — skipped by operator"
fi

# ─── NXC / CRACKMAPEXEC ───────────────────────────────────────────────────────
header "4. NetExec / CrackMapExec"

if confirm "nxc / crackmapexec (apt + pip)"; then
    for pkg in netexec nxc crackmapexec; do
        if dpkg -l "${pkg}" &>/dev/null 2>&1; then
            run "Remove ${pkg} via apt" sudo apt-get remove -y --purge "${pkg}"
        else
            skip "${pkg} not installed via apt"
        fi
    done
    for pkg in netexec crackmapexec; do
        if pip3 show "${pkg}" &>/dev/null 2>&1; then
            run "Remove ${pkg} from pip3" \
                sudo pip3 uninstall -y "${pkg}" 2>/dev/null || \
                pip3 uninstall -y "${pkg}" 2>/dev/null || true
        fi
        if pipx list 2>/dev/null | grep -q "${pkg}"; then
            run "Remove ${pkg} from pipx" pipx uninstall "${pkg}"
        fi
    done
    sudo apt-get autoremove -y --purge &>/dev/null || true
else
    skip "NetExec/CrackMapExec — skipped by operator"
fi

# ─── APT CACHE ───────────────────────────────────────────────────────────────
header "5. apt cache cleanup"
if confirm "Clean apt cache (frees disk space)"; then
    run "apt-get clean" sudo apt-get clean
    run "apt-get autoclean" sudo apt-get autoclean
else
    skip "apt cache — skipped"
fi

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Purge Summary${RESET}"
echo -e "${GREEN}  Removed / cleaned:  ${REMOVED}${RESET}"
echo -e "${YELLOW}  Warnings:           ${WARNINGS}${RESET}"
echo -e "  Skipped by choice:  ${SKIPPED}"
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Reinstall all tools from scratch:"
echo -e "    ${BOLD}python3 orchestrator.py --phase 0${RESET}"
echo ""
echo -e "  Or verify the current state first:"
echo -e "    ${BOLD}bash tools/verify.sh${RESET}"
echo ""
