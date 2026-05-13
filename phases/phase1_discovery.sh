#!/usr/bin/env bash
# ============================================================================
# phases/phase1_discovery.sh — Reconnaissance & Discovery
# ============================================================================
# AUTOMATED (background): Nmap host sweep, full port scan, CrackMapExec SMB
#                         sweep, LDAP enumeration, BloodHound collection,
#                         ROADrecon Entra ID gather, Azure resource inventory.
# MANUAL (after script):  BloodHound GUI analysis, ROADrecon GUI review.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

log PHASE "Phase 1 — Reconnaissance & Discovery"
check_testing_window
detect_system_resources

# ─── RUNTIME REQUIREMENTS ────────────────────────────────────────────────────
require_var "DOMAIN_NAME"; require_var "DC_IP"; require_var "TARGET_SUBNETS"
require_var "ATTACKER_INTERFACE"
set_primary_dc   # sets PRIMARY_DC = first IP in DC_IP

# Domain credentials only required by steps that authenticate to AD.
# Skipped when --only selects network-only steps (host_sweep, nmap_fullscan).
# Pass "quiet" so this pre-flight probe does not log a SKIP line for every
# inspected step — those lines would appear before the real step is reached.
# ldap_banner itself does not need creds (nmap script is anonymous) but is
# kept in the list for backwards-compat with earlier cred-gating logic.
_needs_domain_creds=false
for _cred_step in smb_sweep ldap_users null_session bloodhound roadrecon password_spray; do
    # roadrecon device-code auth is fully interactive — it does not consume
    # DOMAIN_USER or DOMAIN_PASS, so skip it from the cred-requirement probe.
    [[ "${_cred_step}" == "roadrecon" && "${ROADRECON_AUTH_METHOD:-password}" == "devicecode" ]] && continue
    if ! _step_is_skipped "${_cred_step}" quiet; then
        _needs_domain_creds=true; break
    fi
done
if [[ "${_needs_domain_creds}" == "true" ]]; then
    require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
    normalise_domain_user
fi
unset _cred_step _needs_domain_creds

detect_cme

OUT_NET="$(phase_dir phase1 network)"
OUT_AD="$(phase_dir phase1 ad)"
OUT_CLOUD="$(phase_dir phase1 cloud)"

# ─── BUILD NMAP EXCLUSION ARG ─────────────────────────────────────────────────
# Converts SCAN_EXCLUDE_RANGES (space-separated) to nmap's comma-separated --exclude.
# Empty string → no exclusion flag (nmap errors on --exclude with empty value).
NMAP_EXCL_ARG=""
if [[ -n "${SCAN_EXCLUDE_RANGES:-}" ]]; then
    _excl="${SCAN_EXCLUDE_RANGES// /,}"
    _excl="${_excl%%,}"  # strip any trailing comma
    NMAP_EXCL_ARG="--exclude ${_excl}"
    unset _excl
    log INFO "Exclusion list: ${SCAN_EXCLUDE_RANGES}"
fi

# ─── HELPER: extract IPs from gnmap (works for both -sn and -sS --open output) ──
_gnmap_live_ips() {
    local gnmap="$1"
    # "Ports:" lines appear for hosts with at least one open port in -sS --open output.
    # "Status: Up" lines appear in -sn output.  Handle both so skip-branch works
    # against previously collected gnmap files regardless of which mode produced them.
    grep -E 'Ports:.*\/open\/|Status: Up' "${gnmap}" 2>/dev/null \
        | awk '{print $2}' | sort -u
}

# ─── HELPER: extract ALL attempted IPs from a gnmap (fullscan context) ───────
# The fullscan (Phase B — service/version) runs WITHOUT --open, so the gnmap
# contains hosts where every targeted port is filtered/closed.  Those hosts
# still appear with a "Host: <ip> ... Status: Up" line (no Ports: line) or
# with a Ports: line showing only filtered/closed states.  _gnmap_live_ips()
# only keeps hosts with at least one open port, which would silently drop
# firewalled-but-reachable Windows boxes from downstream phase inputs.
# Use _gnmap_all_ips() whenever you need the complete set of hosts nmap
# actually reached during the full scan.
_gnmap_all_ips() {
    local gnmap="$1"
    grep -E '^Host:' "${gnmap}" 2>/dev/null | awk '{print $2}' | sort -u
}

# ─── STEP 1.1 — HOST SWEEP (TCP SYN — no ICMP, no ARP false positives) ───────
# WHY TCP instead of -sn (ping sweep):
#   -sn uses ICMP echo + ICMP timestamp + TCP SYN/ACK to ports 80 and 443.
#   Every router, switch, printer, UPS, and IPMI card on the network responds
#   to ICMP → massive false positives.  TCP SYN to SMB/RDP/WinRM ports only
#   respond on real Windows workstations and servers, eliminating infrastructure
#   noise at the sweep stage rather than having to filter it later.
log INFO "Starting TCP host sweep across all subnets (parallel, no ICMP)..."
log INFO "Discovery ports: ${NMAP_DISCOVERY_PORTS:-88,135,139,443,3389,5985,8080,8443}"
LIVE_HOSTS_MERGED="${OUT_NET}/live_hosts_all.txt"
> "${LIVE_HOSTS_MERGED}"

# Initialise LIVE_COUNT so the post-gate digit-strip (and any arithmetic
# compare that follows) never sees an unbound variable under `set -u`, even
# in the unlikely case that both branches of the skip gate fail to assign it.
LIVE_COUNT=0

if _step_is_skipped "host_sweep"; then
    for subnet in ${TARGET_SUBNETS}; do
        safe_name="${subnet//\//_}"
        gnmap="${OUT_NET}/hostsweep_${safe_name}.gnmap"
        [[ -f "${gnmap}" ]] && _gnmap_live_ips "${gnmap}" >> "${LIVE_HOSTS_MERGED}" || true
    done
    sort -u "${LIVE_HOSTS_MERGED}" -o "${LIVE_HOSTS_MERGED}" 2>/dev/null || true
    LIVE_COUNT=$(wc -l < "${LIVE_HOSTS_MERGED}" 2>/dev/null || echo 0)
    # Sanitise any leading whitespace from `wc -l` output so arithmetic compares work.
    LIVE_COUNT="${LIVE_COUNT//[^0-9]/}"
    LIVE_COUNT="${LIVE_COUNT:-0}"
    log INFO "host_sweep skipped — using cached live hosts (${LIVE_COUNT} hosts)"
else

for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    sweep_out="${OUT_NET}/hostsweep_${safe_name}"
    if skip_if_exists "${sweep_out}.gnmap" "Host sweep ${subnet}" "host_sweep"; then
        _gnmap_live_ips "${sweep_out}.gnmap" >> "${LIVE_HOSTS_MERGED}" || true
        continue
    fi
    log INFO "TCP sweep: ${subnet}"
    # RTT bounds trim infrastructure false positives: Windows hosts with open
    # SMB/RDP/WinRM respond in <100ms on a LAN.  Slow-responding devices
    # (managed switches, printers, UPS, IPMI) get dropped by the 300ms cap,
    # so we finish the sweep with a cleaner live-host list and less noise in
    # the downstream full-port scan.
    bg_run "hostsweep_${safe_name}" \
        "${OUT_NET}/hostsweep_${safe_name}.log" \
        "${NMAP_BIN:-nmap}" \
            -sS --open \
            -p "${NMAP_DISCOVERY_PORTS:-88,135,139,443,3389,5985,8080,8443}" \
            -T"${NMAP_TIMING:-3}" \
            --max-rate "${NMAP_MAX_RATE:-500}" \
            --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
            --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
            --max-retries 1 \
            --initial-rtt-timeout 100ms \
            --max-rtt-timeout 300ms \
            --host-timeout 10s \
            ${NMAP_EXCL_ARG} \
            -oA "${sweep_out}" \
            "${subnet}"
done

wait_for_bg_jobs "TCP host sweeps"

for subnet in ${TARGET_SUBNETS}; do
    safe_name="${subnet//\//_}"
    gnmap="${OUT_NET}/hostsweep_${safe_name}.gnmap"
    [[ -f "${gnmap}" ]] && _gnmap_live_ips "${gnmap}" >> "${LIVE_HOSTS_MERGED}" || true
done
sort -u "${LIVE_HOSTS_MERGED}" -o "${LIVE_HOSTS_MERGED}" 2>/dev/null || true
LIVE_COUNT=$(wc -l < "${LIVE_HOSTS_MERGED}" 2>/dev/null || echo 0)
log OK "TCP host sweep complete — validated live hosts: ${LIVE_COUNT} → ${LIVE_HOSTS_MERGED}"

fi  # end host_sweep skip gate

# Strip any whitespace that `wc -l` may have emitted (BSD wc pads with spaces).
LIVE_COUNT="${LIVE_COUNT//[^0-9]/}"
LIVE_COUNT="${LIVE_COUNT:-0}"

if [[ "${LIVE_COUNT}" -eq 0 ]]; then
    # Skip-aware behaviour:
    #   • If the user is running ONLY host_sweep (no downstream scans), a 0-host
    #     result is informational, not fatal — they can re-target and retry.
    #   • If nmap_fullscan is queued to run, we need live hosts, so warn hard
    #     but still give the user a chance to exit cleanly without set -e tripping.
    #   • If nmap_fullscan is skipped via --skip or not in --only, carry on so
    #     any downstream AD / cloud steps still execute.
    if ! _step_is_skipped "nmap_fullscan" quiet; then
        log WARN "No live hosts found for full-port scan. Verify TARGET_SUBNETS and NMAP_DISCOVERY_PORTS."
        log WARN "Full port scan will be skipped automatically — re-run Phase 1 after fixing discovery."
    else
        log WARN "No cached live hosts — downstream steps requiring the host list will skip automatically."
    fi
fi

# ─── STEP 1.2 — FULL PORT SCAN (two-phase: port confirm → service/version) ───
# Redesigned to fix the "empty fullscan.gnmap" failure mode.  Root causes of
# the previous design:
#   1. --host-timeout 30s was too short for -sV (multi-probe service detection)
#      and -sC (NSE scripts that can take 10–60s per host per port).  Most
#      hosts were aborted mid-scan and produced no output.
#   2. --open on the targeted-port scan silently dropped hosts whose ports
#      were all filtered (workstations that DROP rather than REJECT), so the
#      full scan lost hosts even though they were live.
#   3. -sC scripts in bulk were noisy, slow, and inconsistent — they belong
#      in targeted follow-up scans, not the phase-1 sweep.
#   4. The async merge-watcher pattern meant the gnmap file might not exist
#      when downstream phases ran.  Replaced with foreground wait.
#
# New flow:
#   Phase A — port confirmation (-sS --open, fast) → fullscan_portsonly.gnmap
#   Phase B — service/version on same hosts (-sS -sV, no -sC, no --open) → fullscan.gnmap
#   A foreground `wait_for_bg_jobs` between/after each phase ensures outputs
#   exist before phase 2 consumes them.  Parallel chunking is preserved ONLY
#   for LIVE_COUNT > 200; below that, a single scan is faster end-to-end
#   because chunking overhead + per-chunk scan ramp-up exceeds serial gain.
FULLSCAN_OUT="${OUT_NET}/fullscan"
FULLSCAN_PORTS_OUT="${OUT_NET}/fullscan_portsonly"
OPEN_PORTS_CONFIRMED="${OUT_NET}/open_ports_confirmed.txt"
CHUNK_DIR="${OUT_NET}/scan_chunks"

# Empty-file-aware skip gate: the original `skip_if_exists` returns true even
# if a zero-byte .gnmap was left behind by a prior failed run, which is how
# the fullscan step was silently no-op'ing.  Only treat the output as valid
# when it exists AND has non-zero content.
_fullscan_is_valid() {
    [[ -s "${FULLSCAN_OUT}.gnmap" ]]
}

# Clean up any empty-output artefact from a prior failed run so skip_if_exists
# in common.sh won't short-circuit the rebuild.
if [[ -f "${FULLSCAN_OUT}.gnmap" ]] && ! _fullscan_is_valid; then
    log WARN "Removing empty fullscan.gnmap from prior run (zero-byte file)."
    rm -f "${FULLSCAN_OUT}".{gnmap,nmap,xml} 2>/dev/null || true
fi

if _step_is_skipped "nmap_fullscan"; then
    :  # step explicitly skipped
elif _fullscan_is_valid; then
    log INFO "Skipping (already exists): Full port scan → ${FULLSCAN_OUT}.gnmap"
    echo -e "${GREEN}  [SKIP] Full port scan — non-empty output already exists.${RESET}"
elif [[ "${LIVE_COUNT}" -eq 0 ]]; then
    log WARN "Full port scan requires a non-empty live hosts list. Skipping nmap_fullscan."
    log INFO "Resolve TARGET_SUBNETS / NMAP_DISCOVERY_PORTS, then re-run: python3 orchestrator.py --phase 1 --only host_sweep,nmap_fullscan"
elif checkpoint "Start full port scan (ports: ${NMAP_FULLSCAN_PORTS:-88,135,139,443,3389,5985,8080,8443}) against ${LIVE_COUNT} validated hosts? (two-phase: port-confirm then service-detect)"; then

    mkdir -p "${CHUNK_DIR}"
    SCAN_RATE=$(( ${NMAP_MAX_RATE:-500} * 2 ))  # aggressive on confirmed live hosts
    FS_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT_FULLSCAN:-300}"
    FS_VER_INTENSITY="${NMAP_VERSION_INTENSITY:-5}"

    # ── PHASE A — port confirmation (fast, --open, no version detection) ────
    # Quickly re-confirms which ports are actually reachable on the live
    # host list so Phase B can focus its service-detection budget on hosts
    # with at least one open port.  60s host-timeout is safe here because
    # -sS without -sV/-sC completes in single-digit seconds per host.
    log INFO "Phase A: port confirmation scan (${LIVE_COUNT} hosts, --open, -sS only)..."
    bg_run "nmap_fullscan_portsonly" \
        "${OUT_NET}/fullscan_portsonly.log" \
        "${NMAP_BIN:-nmap}" \
            -sS --open \
            -p "${NMAP_FULLSCAN_PORTS:-88,135,139,443,3389,5985,8080,8443}" \
            -T"${NMAP_TIMING:-4}" \
            --max-rate 1000 \
            --max-retries 2 \
            --host-timeout 60s \
            ${NMAP_EXCL_ARG} \
            -iL "${LIVE_HOSTS_MERGED}" \
            -oA "${FULLSCAN_PORTS_OUT}"
    wait_for_bg_jobs "Phase A — port confirmation"

    # OPEN_PORTS_CONFIRMED is for operator visibility only — Phase B uses LIVE_HOSTS_MERGED
    # (not this file) so filtered-port hosts are not silently dropped from service detection.
    if [[ -s "${FULLSCAN_PORTS_OUT}.gnmap" ]]; then
        _gnmap_live_ips "${FULLSCAN_PORTS_OUT}.gnmap" > "${OPEN_PORTS_CONFIRMED}" || true
    else
        : > "${OPEN_PORTS_CONFIRMED}"
    fi
    CONFIRMED_COUNT=$(wc -l < "${OPEN_PORTS_CONFIRMED}" 2>/dev/null || echo 0)
    CONFIRMED_COUNT="${CONFIRMED_COUNT//[^0-9]/}"
    CONFIRMED_COUNT="${CONFIRMED_COUNT:-0}"
    log OK "Phase A complete — ${CONFIRMED_COUNT} host(s) with confirmed-open ports → ${OPEN_PORTS_CONFIRMED}"

    if [[ "${CONFIRMED_COUNT}" -eq 0 ]]; then
        log WARN "No open ports confirmed on any live host. Skipping Phase B service detection."
        # Seed fullscan.gnmap with the portsonly output so downstream skip-gates
        # see a non-empty file and the operator can inspect filtered states.
        cp "${FULLSCAN_PORTS_OUT}.gnmap" "${FULLSCAN_OUT}.gnmap" 2>/dev/null || true
        cp "${FULLSCAN_PORTS_OUT}.nmap"  "${FULLSCAN_OUT}.nmap"  2>/dev/null || true
    else
        # ── PHASE B — service/version detection (no --open, no -sC) ─────────
        # Run against the ORIGINAL live-hosts list (not just confirmed-open)
        # so the gnmap captures filtered/closed states too — operator needs
        # to see what was filtered vs closed vs open on every live host.
        # --host-timeout 300s gives -sV enough probe budget; --version-intensity 5
        # is the sweet spot between signal quality and scan duration.
        if [[ "${LIVE_COUNT}" -gt 200 && "${SYS_VCPUS:-1}" -gt 1 ]]; then
            # ── Parallel chunked path (only for large engagements) ─────────
            N_JOBS="${SYS_VCPUS}"
            LINES_PER_CHUNK=$(( LIVE_COUNT / N_JOBS + 1 ))
            # Wipe any stale chunk splits from a prior run so split(1) doesn't
            # interleave with old files and confuse the merge.
            rm -f "${CHUNK_DIR}"/chunk_* "${CHUNK_DIR}"/fullscan_chunk_*.{gnmap,nmap,xml} 2>/dev/null || true
            split -l "${LINES_PER_CHUNK}" "${LIVE_HOSTS_MERGED}" "${CHUNK_DIR}/chunk_"
            CHUNK_LIST=( "${CHUNK_DIR}"/chunk_* )
            log INFO "Phase B: splitting ${LIVE_COUNT} hosts into ${#CHUNK_LIST[@]} chunks (${LINES_PER_CHUNK} hosts/chunk)..."

            for chunk in "${CHUNK_LIST[@]}"; do
                suffix=$(basename "${chunk}")
                bg_run "nmap_fullscan_${suffix}" \
                    "${CHUNK_DIR}/fullscan_${suffix}.log" \
                    "${NMAP_BIN:-nmap}" \
                        -sS -sV \
                        --version-intensity "${FS_VER_INTENSITY}" \
                        -p "${NMAP_FULLSCAN_PORTS:-88,135,139,443,3389,5985,8080,8443}" \
                        -T"${NMAP_TIMING:-3}" \
                        --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
                        --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
                        --max-rate "${SCAN_RATE}" \
                        --max-retries 2 \
                        --host-timeout "${FS_HOST_TIMEOUT}s" \
                        ${NMAP_EXCL_ARG} \
                        -iL "${chunk}" \
                        -oA "${CHUNK_DIR}/fullscan_${suffix}"
            done

            log INFO "Phase B: ${#CHUNK_LIST[@]} parallel nmap jobs started. Blocking until all complete..."
            # FOREGROUND wait — the script must block here so that the merged
            # gnmap is guaranteed to exist before phase 2 begins.  The async
            # merge-watcher approach silently failed when the orchestrator
            # moved on to phase 2 before the watcher finished.
            wait_for_bg_jobs "Phase B — service/version scan"

            # Synchronous merge now that every chunk is done.
            # Guard with a file-existence check so the merge doesn't collapse to
            # the literal glob pattern (with nullglob off) or error out (with
            # nullglob/failglob on) when a chunk batch produced zero files.
            _chunk_gnmaps=( "${CHUNK_DIR}"/fullscan_chunk_*.gnmap )
            if [[ -f "${_chunk_gnmaps[0]}" ]]; then
                cat "${_chunk_gnmaps[@]}" 2>/dev/null | sort -u > "${FULLSCAN_OUT}.gnmap" || true
                cat "${CHUNK_DIR}"/fullscan_chunk_*.nmap 2>/dev/null > "${FULLSCAN_OUT}.nmap" || true
            fi
            unset _chunk_gnmaps
            MERGED_LINES=$(wc -l < "${FULLSCAN_OUT}.gnmap" 2>/dev/null || echo 0)
            MERGED_LINES="${MERGED_LINES//[^0-9]/}"; MERGED_LINES="${MERGED_LINES:-0}"
            log OK "Phase B merge complete — ${MERGED_LINES} gnmap lines → ${FULLSCAN_OUT}.gnmap"
        else
            # ── Single job path (LIVE_COUNT <= 200) ─────────────────────────
            log INFO "Phase B: service/version scan (${LIVE_COUNT} hosts, -sV intensity=${FS_VER_INTENSITY}, host-timeout=${FS_HOST_TIMEOUT}s)..."
            bg_run "nmap_fullscan" \
                "${OUT_NET}/fullscan.log" \
                "${NMAP_BIN:-nmap}" \
                    -sS -sV \
                    --version-intensity "${FS_VER_INTENSITY}" \
                    -p "${NMAP_FULLSCAN_PORTS:-88,135,139,443,3389,5985,8080,8443}" \
                    -T"${NMAP_TIMING:-3}" \
                    --min-parallelism "${NMAP_MIN_PARALLEL:-40}" \
                    --max-parallelism "${NMAP_MAX_PARALLEL:-200}" \
                    --max-rate "${SCAN_RATE}" \
                    --max-retries 2 \
                    --host-timeout "${FS_HOST_TIMEOUT}s" \
                    ${NMAP_EXCL_ARG} \
                    -iL "${LIVE_HOSTS_MERGED}" \
                    -oA "${FULLSCAN_OUT}"
            # FOREGROUND wait — block until the scan finishes so the gnmap
            # is guaranteed to exist when this phase returns to the orchestrator.
            wait_for_bg_jobs "Phase B — service/version scan"
        fi

        # Final sanity check — if Phase B produced nothing, fall back to
        # the Phase A output so the downstream skip gate doesn't re-trigger
        # an infinite-retry loop.
        if ! _fullscan_is_valid; then
            log WARN "Phase B produced empty gnmap — falling back to Phase A port-only output."
            cp "${FULLSCAN_PORTS_OUT}.gnmap" "${FULLSCAN_OUT}.gnmap" 2>/dev/null || true
            cp "${FULLSCAN_PORTS_OUT}.nmap"  "${FULLSCAN_OUT}.nmap"  2>/dev/null || true
        fi
    fi
else
    log INFO "Full port scan skipped — re-run: python3 orchestrator.py --phase 1 --only nmap_fullscan"
fi

# ─── STEP 1.3 — SMB SWEEP + SIGNING CHECK (background → foreground wait) ────
SMB_OUT="${OUT_AD}/smb_sweep.txt"
_smb_sweep_ran=false
if ! skip_if_exists "${SMB_OUT}" "CrackMapExec SMB sweep" "smb_sweep"; then
    log INFO "Starting CrackMapExec SMB sweep (signing + host enumeration)..."
    # Use single-quoted bash -c body so DOMAIN_PASS (and other vars) are resolved
    # from the inherited environment at execution time, not expanded here.  Inline
    # double-quoted expansion would break if the password contains ' or \.
    # `set -euo pipefail` inside the subshell promotes any failing subnet scan or
    # unset required variable (CME_BIN/TARGET_SUBNETS/...) to a clean non-zero
    # exit instead of silently producing an empty smb_sweep.txt.
    bg_run "cmexec_smb_sweep" \
        "${OUT_AD}/smb_sweep.log" \
        bash -c 'set -euo pipefail
for subnet in $TARGET_SUBNETS; do
    $CME_BIN smb "$subnet" \
        -u "$DOMAIN_USER" -p "$DOMAIN_PASS" -d "$DOMAIN_NAME" \
        2>&1
done > "$OUTPUT_BASE_DIR/phase1/ad/smb_sweep.txt"'
    log INFO "CME SMB sweep running in background."
    _smb_sweep_ran=true

    # Block until the SMB sweep completes before the signing-check below reads
    # ${SMB_OUT}. Without this wait the signing-check is a race: the file may
    # not exist or may be partially written when grep runs.
    wait_for_bg_jobs "SMB sweep"
    # common.sh's wait_for_bg_jobs already clears these, but set them
    # defensively so subsequent wait_for_bg_jobs (e.g. for nmap) never re-waits
    # on the CME PID by accident.
    BG_JOB_PIDS=()
    BG_JOB_NAMES=()
fi

# ─── SMB SIGNING CHECK — runs inline immediately after the wait above ───────
# Moved up from its previous position so the grep always reads a complete file.
if [[ -f "${SMB_OUT}" ]]; then
    SIGNING_NOT_REQ=$(grep -c 'signing:False\|SMB signing: disabled\|signing: False' "${SMB_OUT}" 2>/dev/null || true)
    SIGNING_NOT_REQ="${SIGNING_NOT_REQ//[^0-9]/}"
    SIGNING_NOT_REQ="${SIGNING_NOT_REQ:-0}"
    if [[ "${SIGNING_NOT_REQ}" -gt 0 ]]; then
        log WARN "FINDING: ${SIGNING_NOT_REQ} host(s) with SMB Signing NOT REQUIRED — relay targets for Phase 3"
        grep 'signing:False\|signing: False' "${SMB_OUT}" > "${OUT_AD}/relay_targets.txt" 2>/dev/null || true
        # Extract just IPs for ntlmrelayx
        awk '{print $2}' "${OUT_AD}/relay_targets.txt" 2>/dev/null | grep -E '^[0-9]+\.' \
            > "${OUT_AD}/relay_target_ips.txt" || true
        log WARN "Relay target IPs written to: ${OUT_AD}/relay_target_ips.txt"
    else
        log OK "All enumerated hosts appear to have SMB signing enabled"
    fi
fi
unset _smb_sweep_ran

# ─── STEP 1.4 — LDAP DC BANNER GRAB (active — all DCs) ──────────────────────
LDAP_OUT="${OUT_AD}/ldap_rootdse.txt"
if ! skip_if_exists "${LDAP_OUT}" "LDAP rootdse" "ldap_banner"; then
    log INFO "Grabbing LDAP rootdse from all DCs: ${DC_IP}"
    if checkpoint "Run LDAP rootDSE banner grab against all DCs (${DC_IP}) — generates one LDAP probe per DC?"; then
        : > "${LDAP_OUT}"
        for _dc in ${DC_IP}; do
            log_cmd "${NMAP_BIN} -p 389 --script ldap-rootdse ${_dc}"
            echo "### DC: ${_dc}" >> "${LDAP_OUT}"
            "${NMAP_BIN:-nmap}" -p 389 --script ldap-rootdse "${_dc}" \
                -oN - 2>&1 | tee -a "${OUT_AD}/ldap.log" >> "${LDAP_OUT}" || true
        done
        unset _dc
        log OK "LDAP rootdse collected (all DCs) → ${LDAP_OUT}"
    else
        log INFO "LDAP rootdse skipped — run manually per DC: nmap -p 389 --script ldap-rootdse <DC_IP>"
    fi
fi

# ─── STEP 1.5 — LDAP USER ENUMERATION (active — primary DC) ─────────────────
# Uses PRIMARY_DC only — all DCs share the same AD partition; querying one is enough.
LDAP_USERS_OUT="${OUT_AD}/ldap_users.txt"
if ! skip_if_exists "${LDAP_USERS_OUT}" "LDAP user enumeration" "ldap_users"; then
    log INFO "Enumerating domain users via LDAP (primary DC: ${PRIMARY_DC})..."
    log_cmd "ldapsearch -H ldap://${PRIMARY_DC} -D ${DOMAIN_USER}@${DOMAIN_NAME} -w *** -b DC=..."
    ldapsearch -H "ldap://${PRIMARY_DC}" \
        -D "${DOMAIN_USER}@${DOMAIN_NAME}" \
        -w "${DOMAIN_PASS}" \
        -b "$(echo "DC=${DOMAIN_NAME}" | sed 's/\./,DC=/g')" \
        '(objectClass=user)' sAMAccountName mail memberOf userAccountControl \
        2>&1 > "${LDAP_USERS_OUT}" || log WARN "LDAP query failed — check credentials and DC reachability"

    grep 'sAMAccountName:' "${LDAP_USERS_OUT}" | awk '{print $2}' \
        | grep -v -E '^\$' \
        > "${OUT_AD}/userlist.txt" || true
    UCOUNT=$(wc -l < "${OUT_AD}/userlist.txt" 2>/dev/null || echo 0)
    log OK "LDAP users collected: ${UCOUNT} accounts → ${OUT_AD}/userlist.txt"
fi

# ─── STEP 1.6 — SMB NULL SESSION CHECK (active — all DCs) ───────────────────
if ! _step_is_skipped "null_session"; then
    log INFO "Checking for SMB null session on all DCs (${DC_IP})..."
    : > "${OUT_AD}/nullsession_check.txt"
    _null_vulnerable=false
    for _dc in ${DC_IP}; do
        log_cmd "${CME_BIN} smb ${_dc} -u '' -p ''"
        _dc_out=$("${CME_BIN}" smb "${_dc}" -u '' -p '' 2>&1 || true)
        echo "### DC: ${_dc}" >> "${OUT_AD}/nullsession_check.txt"
        echo "${_dc_out}"    >> "${OUT_AD}/nullsession_check.txt"

        # A blocked null session produces STATUS_ACCESS_DENIED or STATUS_LOGON_FAILURE.
        # A successful null session produces a [+] line with host info and NO error code.
        # Check per-DC so one blocked DC cannot hide a vulnerable one.
        if echo "${_dc_out}" | grep -qE 'STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE'; then
            log OK "Null session blocked on ${_dc}"
        elif echo "${_dc_out}" | grep -qE '^\s*(\[|\*|SMB).*\+'; then
            log WARN "FINDING: Null session ALLOWED on ${_dc} — unauthenticated SMB access possible"
            _null_vulnerable=true
        else
            log WARN "Null session result inconclusive on ${_dc} (connection issue?) — review: ${OUT_AD}/nullsession_check.txt"
        fi
    done
    unset _dc _dc_out
    if [[ "${_null_vulnerable}" == "true" ]]; then
        log WARN "One or more DCs allow null sessions — add to findings, check legacy auth settings"
    fi
    unset _null_vulnerable
fi

# ─── STEP 1.7 — BLOODHOUND DATA COLLECTION (background) ──────────────────────
BH_OUT_DIR="${OUT_AD}/bloodhound"
mkdir -p "${BH_OUT_DIR}"
# `ls *.zip | head -1` fails under set -eo pipefail when no zip files exist
# (ls exits 1 → pipefail promotes the pipeline exit → set -e kills the script).
# Use a safe glob expansion instead: the for-loop body never runs on no-match.
BH_ZIP=""
for _bh_f in "${BH_OUT_DIR}"/*.zip; do
    if [[ -f "${_bh_f}" ]]; then BH_ZIP="${_bh_f}"; break; fi
done
unset _bh_f
if _step_is_skipped "bloodhound"; then
    : # skip
elif [[ -n "${BH_ZIP}" ]]; then
    log INFO "BloodHound ZIP already exists: ${BH_ZIP} — skipping collection"
else
    log INFO "Starting BloodHound data collection (-c All)..."
    # Run from BH_OUT_DIR so bloodhound-python writes the ZIP there regardless
    # of which version is installed — older versions create the zip in CWD,
    # newer versions honour -o; running from the target dir covers both.
    bg_run "bloodhound_collect" \
        "${OUT_AD}/bloodhound_collect.log" \
        bash -c "cd '${BH_OUT_DIR}' && \
            '${BLOODHOUND_BIN:-bloodhound-python}' \
            -u '${DOMAIN_USER}' \
            -p '${DOMAIN_PASS}' \
            -d '${DOMAIN_NAME}' \
            -ns '${PRIMARY_DC}' \
            -c All \
            --zip \
            -w '${BH_WORKERS:-20}' \
            -o '${BH_OUT_DIR}'"
    log INFO "BloodHound collection running in background."
fi

# ─── STEP 1.8 — ROADRECON ENTRA ID GATHER ────────────────────────────────────
ROAD_DB="${OUT_CLOUD}/roadrecon.db"
if ! skip_if_exists "${ROAD_DB}" "ROADrecon gather" "roadrecon"; then
    log INFO "Starting ROADrecon Entra ID gather..."
    if [[ "${ROADRECON_AUTH_METHOD:-password}" == "devicecode" ]]; then
        # Device code flow: no pipes — the URL and one-time code must reach the
        # terminal directly. Any redirect or tee buffers stdout and the code is
        # never displayed, making interactive auth impossible.
        log INFO "ROADrecon device code auth: a URL and code will appear below."
        log INFO "Open the URL in any browser, enter the code, then wait here."
        "${ROADRECON_BIN:-roadrecon}" auth --device-code
        "${ROADRECON_BIN:-roadrecon}" gather \
            --database "${ROAD_DB}" \
            2>&1 | tee "${OUT_CLOUD}/roadrecon.log"
        log OK "ROADrecon gather complete → ${ROAD_DB}"
    else
        # Modern roadrecon requires a separate auth step before gather.
        # Run auth in the foreground (it's a quick MSAL token request) so
        # credentials are never inline-interpolated into a bash -c string —
        # that breaks silently when the password contains single-quotes or
        # other shell-special characters.  Gather is then safe to background.
        log INFO "ROADrecon: authenticating (username/password)..."
        "${ROADRECON_BIN:-roadrecon}" auth \
            -u "${DOMAIN_USER}@${DOMAIN_NAME}" \
            -p "${DOMAIN_PASS}"
        bg_run "roadrecon_gather" \
            "${OUT_CLOUD}/roadrecon.log" \
            "${ROADRECON_BIN:-roadrecon}" gather \
                --database "${ROAD_DB}"
        log INFO "ROADrecon running in background. If DB is empty after completion, set ROADRECON_AUTH_METHOD=devicecode."
    fi
fi

# ─── STEP 1.9 — AZURE RESOURCE INVENTORY (background) ────────────────────────
AZURE_INV="${OUT_CLOUD}/azure_inventory.json"
if ! skip_if_exists "${AZURE_INV}" "Azure resource inventory" "azure_inventory"; then
    if ! require_az_login; then
        log WARN "Skipping Azure resource inventory — authenticate with az login first"
    else
    log INFO "Starting Azure resource inventory across all subscriptions..."
    bg_run "azure_inventory" \
        "${OUT_CLOUD}/azure_inventory.log" \
        bash -c "
            set -euo pipefail
            # Collect resources per subscription into separate files, then merge.
            # Using >> inside the loop would concatenate raw JSON arrays (invalid JSON).
            for sub in ${AZURE_SUBSCRIPTION_IDS}; do
                az account set --subscription \"\${sub}\" 2>/dev/null || continue
                az resource list --output json 2>/dev/null \
                    > '${OUT_CLOUD}/inventory_'\"\${sub}\".json || true
            done
            # Merge per-subscription JSON arrays into one (requires jq)
            if command -v jq &>/dev/null; then
                jq -s 'add // []' '${OUT_CLOUD}'/inventory_*.json > '${AZURE_INV}' 2>/dev/null || true
            else
                cat '${OUT_CLOUD}'/inventory_*.json > '${AZURE_INV}' 2>/dev/null || true
            fi
            # Always enumerate against the last active subscription context for tenant-wide resources
            az vm list --output table                    > '${OUT_CLOUD}/vms.txt'              2>&1 || true
            az storage account list --output table       > '${OUT_CLOUD}/storage.txt'          2>&1 || true
            az network nsg list --output table           > '${OUT_CLOUD}/nsgs.txt'             2>&1 || true
            az keyvault list --output table              > '${OUT_CLOUD}/keyvaults.txt'        2>&1 || true
            az sql server list --output table            > '${OUT_CLOUD}/sql_servers.txt'      2>&1 || true
            az network public-ip list --output table     > '${OUT_CLOUD}/public_ips.txt'       2>&1 || true
            az ad user list --output table               > '${OUT_CLOUD}/entra_users.txt'      2>&1 || true
            az ad group list --output table              > '${OUT_CLOUD}/entra_groups.txt'     2>&1 || true
            az ad app list --output table                > '${OUT_CLOUD}/entra_apps.txt'       2>&1 || true
            az ad sp list --output table                 > '${OUT_CLOUD}/entra_sps.txt'        2>&1 || true
            az role assignment list --all --output table > '${OUT_CLOUD}/role_assignments.txt' 2>&1 || true
        "
    log INFO "Azure inventory running in background (one JSON file per subscription → merged into azure_inventory.json)."
    fi  # end require_az_login gate
fi

# NOTE: SMB signing check previously lived here — moved up to run inline
# immediately after the SMB sweep's `wait_for_bg_jobs` call (see STEP 1.3)
# so it is not racing the background job.

# ─── STEP 1.10 — CONTROLLED PASSWORD SPRAY (optional) ───────────────────────
# Only runs when SPRAY_ENABLED=true in config.env.
# SPRAY_MAX_ATTEMPTS MUST be below the domain lockout threshold (verify via Phase 2
# password policy check first; default guard is 2 attempts, well below typical 5).
if [[ "${SPRAY_ENABLED:-false}" != "true" ]]; then
    log INFO "Password spray disabled (SPRAY_ENABLED=false). Set SPRAY_ENABLED=true in config.env to enable."
else
    SPRAY_OUT="${OUT_AD}/spray_results.txt"
    # Previously this gate was keyed to "host_sweep" which was incorrect — it meant
    # that with --only host_sweep, the spray would run as if it had been selected.
    # Password spraying needs its own explicit key so it can be targeted with --only
    # or suppressed with --skip independently of the rest of the phase.
    if skip_if_exists "${SPRAY_OUT}" "Password spray results" "password_spray"; then
        :
    else
        # Spray needs DOMAIN_USER/PASS to authenticate AND a user list from LDAP.
        # Both are enforced inline so running --only password_spray tells the operator
        # exactly what they still need to collect first.
        require_var "DOMAIN_USER"; require_var "DOMAIN_PASS"
        require_file "${OUT_AD}/userlist.txt"

        MAX_ATTEMPTS="${SPRAY_MAX_ATTEMPTS:-2}"
        DELAY_SECS="${SPRAY_DELAY_SECONDS:-1800}"

        # Safety: refuse to spray if lockout threshold is unknown
        POLFILE="${OUTPUT_BASE_DIR}/phase2/ad/ad_checks/password_policy.txt"
        if [[ -f "${POLFILE}" ]]; then
            LOCKOUT_THRESH=$(grep -i 'Account lockout threshold' "${POLFILE}" | grep -oE '[0-9]+' | head -1 || echo 0)
            if [[ "${LOCKOUT_THRESH:-0}" -gt 0 && "${MAX_ATTEMPTS}" -ge "${LOCKOUT_THRESH}" ]]; then
                log ERROR "SPRAY BLOCKED: SPRAY_MAX_ATTEMPTS (${MAX_ATTEMPTS}) >= lockout threshold (${LOCKOUT_THRESH}). Reduce SPRAY_MAX_ATTEMPTS in config.env."
                log ERROR "This would lock out accounts. Aborting spray."
            else
                log WARN "SPRAY: lockout threshold=${LOCKOUT_THRESH}, max_attempts=${MAX_ATTEMPTS} — safe margin confirmed."
                _do_spray=true
            fi
        else
            log WARN "Password policy not yet collected (run Phase 2 first, or accept risk). Proceeding with SPRAY_MAX_ATTEMPTS=${MAX_ATTEMPTS}."
            _do_spray=true
        fi

        if [[ "${_do_spray:-false}" == "true" ]]; then
            # Commonly used corporate patterns to try
            SPRAY_PASSWORDS=("${DOMAIN_NAME%%.*}2024!" "${DOMAIN_NAME%%.*}2025!" "Welcome1!" "Password1!" "Summer2024!" "Summer2025!")

            attempt=0
            for pwd in "${SPRAY_PASSWORDS[@]}"; do
                [[ ${attempt} -ge ${MAX_ATTEMPTS} ]] && break
                if ! checkpoint "Spray attempt $((attempt+1))/${MAX_ATTEMPTS}: try password '${pwd}' against all domain users (${DELAY_SECS}s delay between attempts)"; then
                    log INFO "Spray attempt skipped by operator."
                    continue
                fi
                log INFO "Spray attempt $((attempt+1)): password = [REDACTED FROM LOG]"
                log_cmd "${CME_BIN} smb ${PRIMARY_DC} -u ${OUT_AD}/userlist.txt -p *** -d ${DOMAIN_NAME} --continue-on-success"
                "${CME_BIN}" smb "${PRIMARY_DC}" \
                    -u "${OUT_AD}/userlist.txt" \
                    -p "${pwd}" \
                    -d "${DOMAIN_NAME}" \
                    --continue-on-success \
                    2>&1 >> "${SPRAY_OUT}" || true

                # `grep -c` exits 1 on no-match AFTER printing "0", so `|| echo 0`
                # double-counts into "0\n0".  `|| true` + digit-strip gives a
                # single-scalar safe for log display and downstream arithmetic.
                HITS=$(grep -c '(Pwn3d)\|[+] ' "${SPRAY_OUT}" 2>/dev/null || true)
                HITS="${HITS//[^0-9]/}"
                HITS="${HITS:-0}"
                log OK "Spray attempt $((attempt+1)) complete. Hits so far: ${HITS}"
                # (( attempt++ )) returns exit 1 when the pre-increment value was 0,
                # which trips `set -e`.  Use the assignment form to avoid that footgun.
                attempt=$(( attempt + 1 ))

                if [[ ${attempt} -lt ${MAX_ATTEMPTS} && ${#SPRAY_PASSWORDS[@]} -gt ${attempt} ]]; then
                    log INFO "Waiting ${DELAY_SECS}s before next spray attempt (anti-lockout delay)..."
                    sleep "${DELAY_SECS}"
                fi
            done
            SPRAY_HITS=$(grep -c '(Pwn3d)\|[+] ' "${SPRAY_OUT}" 2>/dev/null || true)
            SPRAY_HITS="${SPRAY_HITS//[^0-9]/}"
            SPRAY_HITS="${SPRAY_HITS:-0}"
            if [[ "${SPRAY_HITS}" -gt 0 ]]; then
                log WARN "FINDING: ${SPRAY_HITS} account(s) found via password spray → ${SPRAY_OUT}"
            else
                log OK "Password spray: no hits with tested passwords"
            fi
        fi
    fi
fi

# ─── STATUS SUMMARY ──────────────────────────────────────────────────────────
echo ""
status_bg_jobs
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Phase 1 — Active Steps Complete${RESET}"
echo -e "${BOLD}${CYAN}  Background jobs running — track with: python3 orchestrator.py --status${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${RESET}"
echo -e "${YELLOW}  Background jobs to monitor:${RESET}"
echo -e "    • Nmap full port scan    → ${FULLSCAN_OUT}.gnmap (merged automatically when done)"
echo -e "    • BloodHound collection  → ${BH_OUT_DIR}/*.zip"
echo -e "    • ROADrecon gather       → ${ROAD_DB}"
echo -e "    • Azure inventory        → ${AZURE_INV}"
echo ""
echo -e "${YELLOW}  Manual steps now required:${RESET}"
echo -e "    • Ensure BloodHound CE is running:  bloodhound-cli status"
echo -e "    • Import BloodHound ZIP:             http://localhost:8080  (Administration → File Ingest)"
echo -e "      ZIP location: ${BH_OUT_DIR}/*.zip"
echo -e "    • Run BloodHound key queries (see playbook Phase 1)"
echo -e "    • Review ROADrecon GUI: roadrecon analyze && roadrecon gui"
echo -e "    • Review Nmap full scan results when complete"
echo ""
log OK "Phase 1 automated steps complete. Background jobs running."
