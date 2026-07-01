#!/bin/bash
# ==============================================================================
# LINUX WORKLOAD OPTIMIZER & SANDBOX LAUNCHER — T560 EDITION (12 GB RAM)
# ==============================================================================
# Usage:
#   ./gamemode.sh              → Optimize system & launch Lutris
#   ./gamemode.sh trainer.exe  → Securely launch a Wine trainer
#
# Hardware target: Lenovo ThinkPad T560
#   CPU : Intel Skylake i5-6200U / i7-6600U  (Intel P-state driver)
#   GPU : Intel HD Graphics 520 (iris) ±  NVIDIA GeForce 940MX (Optimus)
#   RAM : 12 GB
# ==============================================================================

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
PREFERRED_VERSION="flatpak"   # native | flatpak | auto
GAMING_SWAPPINESS=100         # used only when ZRAM is active (auto-detected below)
DEFAULT_SWAPPINESS=60

STATE_DIR="$HOME/.config/gamemode"
mkdir -p "$STATE_DIR"

# ── HELPERS ───────────────────────────────────────────────────────────────────
log()     { printf '[*] %s\n'     "$*"; }
ok()      { printf '    -> %s\n'  "$*"; }
warn()    { printf '    [!] %s\n' "$*"; }
die()     { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
section() { printf '\n--- [ %s ] ---\n' "$*"; }

# ── CAPTURE ORIGINALS (before any tuning) ─────────────────────────────────────
ORIG_SWAPPINESS=$(cat /proc/sys/vm/swappiness)
ORIG_PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 1)
ORIG_DIRTY_RATIO=$(cat /proc/sys/vm/dirty_ratio)
ORIG_DIRTY_BG=$(cat /proc/sys/vm/dirty_background_ratio)
ORIG_VFS_PRESSURE=$(cat /proc/sys/vm/vfs_cache_pressure)
ORIG_THP=$(grep -oP '\[\K[^\]]+' /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo always)
ORIG_EPP=$(cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference 2>/dev/null || echo normal)
ORIG_GOVERNOR=""   # populated below if cpufreq is available
NVIDIA_GPU=false
ZRAM_ACTIVE=false

# ── CONSOLIDATED RESTORE (handles EXIT trap + manual path — no double-restore) ─
_RESTORED=0
restore_system() {
    [[ $_RESTORED -eq 1 ]] && return
    _RESTORED=1
    echo ""
    log "Restoring system to desktop defaults..."

    # Security
    echo "$ORIG_PTRACE" | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null 2>&1 || true

    # Memory
    sudo sysctl -q vm.swappiness="$ORIG_SWAPPINESS"             2>/dev/null || true
    sudo sysctl -q vm.dirty_ratio="$ORIG_DIRTY_RATIO"           2>/dev/null || true
    sudo sysctl -q vm.dirty_background_ratio="$ORIG_DIRTY_BG"   2>/dev/null || true
    sudo sysctl -q vm.vfs_cache_pressure="$ORIG_VFS_PRESSURE"   2>/dev/null || true

    # THP
    echo "$ORIG_THP" | sudo tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null 2>/dev/null || true

    # CPU governor
    if [[ -n "$ORIG_GOVERNOR" ]]; then
        for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo "$ORIG_GOVERNOR" | sudo tee "$f" > /dev/null 2>/dev/null || true
        done
        ok "CPU governor → $ORIG_GOVERNOR"
    fi

    # Intel EPP (restore captured original, not a hardcoded guess)
    for epp in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do
        [[ -f "$epp" ]] && { echo "$ORIG_EPP" | sudo tee "$epp" > /dev/null 2>/dev/null || true; }
    done
    ok "Intel EPP → $ORIG_EPP"

    # WiFi power save (re-enable)
    command -v nmcli &>/dev/null && nmcli device wifi powersave on > /dev/null 2>&1 || true

    # TLP (re-engage auto profile so it can manage thermals again)
    command -v tlp &>/dev/null && sudo tlp auto > /dev/null 2>&1 || true

    ok "All defaults restored. Goodbye."
}

trap restore_system EXIT SIGINT SIGTERM

# ==============================================================================
# MODE 1 — TRAINER LAUNCHER
# ==============================================================================
run_trainer_mode() {
    local trainer="$1"; shift
    log "TRAINER MODE: $trainer"

    # Guard: make sure Wine is present before doing anything
    command -v wine &>/dev/null || die "wine not found in PATH. Install Wine first."

    # Detect WINEPREFIX
    local prefix=""
    if   [[ -n "${WINEPREFIX:-}" && -d "${WINEPREFIX}" ]];        then prefix="$WINEPREFIX"
    elif [[ -d "$HOME/.wine" ]];                                    then prefix="$HOME/.wine"
    elif [[ -d "$HOME/.var/app/net.lutris.Lutris/data/wine" ]];    then prefix="$HOME/.var/app/net.lutris.Lutris/data/wine"
    else die "No valid WINEPREFIX found. Aborting."; fi

    ok "WINEPREFIX: $prefix"
    export WINEPREFIX="$prefix"

    local cur_ptrace
    cur_ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 1)

    if [[ "$cur_ptrace" -ne 0 ]]; then
        log "Shields UP — lowering ptrace_scope for injection..."
        sudo -v
        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
    else
        ok "ptrace_scope already 0 (Game Mode active) — proceeding."
    fi

    log "Launching trainer via Wine..."
    setsid wine "$trainer" "$@" > /dev/null 2>&1 &
    local pid=$!
    ok "Trainer PID: $pid"
    wait "$pid" 2>/dev/null || true

    ok "Trainer exited. Restoring ptrace_scope → $cur_ptrace"
    echo "$cur_ptrace" | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
    exit 0
}

[[ -n "${1:-}" ]] && run_trainer_mode "$@"

# ==============================================================================
# MODE 2 — GAME MODE ORCHESTRATOR
# ==============================================================================

echo "════════════════════════════════════════"
echo "  ENTERING HIGH-PERFORMANCE MODE"
echo "  ThinkPad T560  |  12 GB RAM"
echo "════════════════════════════════════════"

[[ "$EUID" -eq 0 ]] && die "Do NOT run as root. sudo is requested per-step when needed."

log "Caching sudo credentials..."
sudo -v

# ── 1. CPU ────────────────────────────────────────────────────────────────────
section "CPU"

# Intel P-state Energy Performance Preference (EPP):
# This is what actually controls turbo frequency on Skylake+ — the governor alone isn't enough.
EPP_CORES=0
for epp in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do
    [[ -f "$epp" ]] || continue
    echo performance | sudo tee "$epp" > /dev/null 2>/dev/null && ((EPP_CORES++)) || true
done
[[ $EPP_CORES -gt 0 ]] && ok "Intel P-state EPP → performance on ${EPP_CORES} thread(s) (turbo unrestricted)"

# Scaling governor (belt-and-suspenders for non-P-state kernels / future-proofing)
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    ORIG_GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
    APPLIED=0
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance | sudo tee "$f" > /dev/null 2>/dev/null && ((APPLIED++)) || true
    done
    ok "Scaling governor → performance on ${APPLIED} core(s)  (was: ${ORIG_GOVERNOR:-unknown})"
else
    warn "cpufreq sysfs not found — governor unchanged."
fi

# ── 2. MEMORY ─────────────────────────────────────────────────────────────────
section "MEMORY (12 GB)"

# CRITICAL: swappiness=100 only makes sense when ZRAM is the swap device.
# Without ZRAM, it means "hammer the disk aggressively" — terrible for gaming.
if swapon --show=NAME --noheadings 2>/dev/null | grep -q '/dev/zram'; then
    ZRAM_ACTIVE=true
    log "ZRAM swap detected → swappiness=$GAMING_SWAPPINESS (prefer compressed RAM over disk)"
    sudo sysctl -q vm.swappiness=$GAMING_SWAPPINESS
    # ZRAM decompresses in the CPU, so prefetching swap pages from "disk" is pure waste
    sudo sysctl -q vm.page-cluster=0 2>/dev/null || true
    ok "page-cluster=0 (no swap read-ahead — ZRAM is in-RAM)"
else
    warn "No ZRAM swap detected — clamping swappiness to 10 to avoid disk thrashing."
    warn "Tip: install & enable zram-generator for a real performance boost on 12 GB."
    GAMING_SWAPPINESS=10
    sudo sysctl -q vm.swappiness=$GAMING_SWAPPINESS
fi

# Dirty page ratios tuned for 12 GB:
#   dirty_ratio=15       → ~1.8 GB cap before foreground writeback forces a stall
#   dirty_background_ratio=8 → ~960 MB before background flush kicks in silently
# Both reduce mid-game I/O stutter without risking OOM at this RAM size.
log "Tuning dirty page thresholds (12 GB profile)..."
sudo sysctl -q vm.dirty_ratio=15
sudo sysctl -q vm.dirty_background_ratio=8
ok "dirty_ratio=15  /  dirty_background_ratio=8"

# Retain inode/dentry cache longer → fewer redundant SSD reads during level loads
log "Setting vfs_cache_pressure=50..."
sudo sysctl -q vm.vfs_cache_pressure=50
ok "vfs_cache_pressure=50"

# THP 'madvise': apps explicitly opt-in (better than 'always' for Wine/Proton;
# avoids page-fault storms on workloads that don't benefit from 2 MB pages)
log "Transparent Hugepages → madvise..."
echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null 2>/dev/null || \
    warn "Could not set THP — not critical."

# Drop page & slab caches so games start with the most free RAM possible
log "Syncing and dropping file caches..."
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
ok "File caches cleared — RAM freed for games."

# ── 3. STORAGE ────────────────────────────────────────────────────────────────
section "STORAGE (I/O Scheduler)"

# mq-deadline: gives bounded latency on SSDs/NVMe without sacrificing throughput.
# Better than cfq/bfq for gaming (deterministic, low-latency reads).
shopt -s nullglob
for sched_file in /sys/block/*/queue/scheduler; do
    blk=$(basename "$(dirname "$(dirname "$sched_file")")")
    rot=$(cat "/sys/block/${blk}/queue/rotational" 2>/dev/null || echo 1)
    if [[ "$rot" == "0" ]]; then
        if   echo mq-deadline | sudo tee "$sched_file" > /dev/null 2>/dev/null; then
            ok "${blk} → mq-deadline"
        elif echo deadline    | sudo tee "$sched_file" > /dev/null 2>/dev/null; then
            ok "${blk} → deadline (mq-deadline unavailable)"
        else
            warn "${blk}: could not change scheduler."
        fi
    else
        ok "${blk}: rotational drive — leaving scheduler unchanged."
    fi
done
shopt -u nullglob

# ── 4. SECURITY ───────────────────────────────────────────────────────────────
section "SECURITY"
log "Lowering ptrace_scope → 0 (Wine trainer injection enabled)..."
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
ok "ptrace_scope = 0  (auto-restored on exit)"

# ── 5. NETWORK ────────────────────────────────────────────────────────────────
section "NETWORK"
if command -v nmcli &>/dev/null; then
    WIFI_DEV=$(nmcli -t -f DEVICE,TYPE device 2>/dev/null | awk -F: '$2=="wifi"{print $1; exit}')
    if [[ -n "${WIFI_DEV:-}" ]]; then
        nmcli device wifi powersave off > /dev/null 2>&1 && \
            ok "WiFi power-save disabled on $WIFI_DEV (reduces ping variance)" || \
            warn "Could not disable WiFi power-save."
    else
        warn "No WiFi interface found via nmcli."
    fi
else
    warn "nmcli not found — skipping WiFi power-save tuning."
fi

# ── 6. POWER MANAGER (TLP) ───────────────────────────────────────────────────
section "POWER MANAGER"
# TLP actively fights the performance governor on ThinkPads.
# Switch it to AC mode so it stops throttling us mid-game.
if command -v tlp &>/dev/null && systemctl is-active --quiet tlp 2>/dev/null; then
    log "TLP running — switching to AC/performance profile..."
    sudo tlp ac > /dev/null 2>&1 && ok "TLP → AC mode." || warn "Could not switch TLP profile."
else
    ok "TLP not active — no action needed."
fi

# ── 7. THERMALS ───────────────────────────────────────────────────────────────
section "THERMALS"
OVERHEAT=false
shopt -s nullglob
for zone_temp in /sys/class/thermal/thermal_zone*/temp; do
    zone_dir=$(dirname "$zone_temp")
    zone_type=$(cat "$zone_dir/type" 2>/dev/null || basename "$zone_dir")
    temp_raw=$(cat "$zone_temp" 2>/dev/null || echo 0)
    temp_c=$((temp_raw / 1000))
    [[ $temp_c -le 0 ]] && continue  # skip invalid/unpopulated zones

    if   [[ $temp_c -gt 85 ]]; then
        warn "${zone_type}: ${temp_c}°C  ← VERY HOT — cool down before gaming!"
        OVERHEAT=true
    elif [[ $temp_c -gt 70 ]]; then
        printf '    [~] %s: %d°C (warm — keep an eye on it)\n' "$zone_type" "$temp_c"
    else
        ok "${zone_type}: ${temp_c}°C"
    fi
done
shopt -u nullglob

if $OVERHEAT; then
    echo ""
    read -rp "    [!] Temperature is dangerously high. Continue anyway? [y/N]: " CONFIRM
    [[ "${CONFIRM,,}" == y ]] || { log "Aborted by user."; exit 1; }
fi

# ── 8. GPU ────────────────────────────────────────────────────────────────────
section "GPU"

# T560 optionally ships with NVIDIA GeForce 940MX via Optimus.
# Detect it first — do NOT assume Intel-only.
if command -v nvidia-smi &>/dev/null && nvidia-smi -L 2>/dev/null | grep -q NVIDIA; then
    NVIDIA_GPU=true
    log "NVIDIA GeForce 940MX detected (Optimus)."
    # PRIME render offload: route game frames to the dGPU transparently
    export __NV_PRIME_RENDER_OFFLOAD=1
    export __GLX_VENDOR_LIBRARY_NAME=nvidia
    export __VK_LAYER_NV_optimus=NVIDIA_only
    ok "PRIME offload env vars set — Lutris games will render on 940MX."
    ok "For manual apps:  prime-run /path/to/game"
else
    log "No discrete GPU detected — using Intel HD Graphics 520 (iris)."
    # vblank_mode=0          : disable vsync at driver level → prevents frame-pacing stutter
    # MESA_LOADER_DRIVER_OVERRIDE=iris : force modern iris (not legacy i965/crocus)
    # GL 4.5 matches what HD 520 actually supports; 4.6 causes game compatibility breaks
    # NOTE: INTEL_DEBUG=norbc has been intentionally removed — it DISABLES render buffer
    #       compression on HD 520, making it slower, not faster.
    export vblank_mode=0
    export MESA_LOADER_DRIVER_OVERRIDE=iris
    export MESA_GL_VERSION_OVERRIDE=4.5
    export MESA_GLSL_VERSION_OVERRIDE=450
    ok "iris driver | GL 4.5 | vblank disabled"
fi

# ── 9. LAUNCH LUTRIS ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
printf  "  Launching Lutris [%s]\n" "$PREFERRED_VERSION"
echo "════════════════════════════════════════"

_launch() {
    # Launches a command in background, then raises its priority
    "$@" &
    local pid=$!
    # I/O priority: best-effort class, highest level (no root required)
    ionice -c 2 -n 0 -p "$pid" 2>/dev/null || true
    # CPU priority: nice -5 (requires cached sudo — already done above)
    sudo renice -n -5 -p "$pid" > /dev/null 2>/dev/null && \
        ok "CPU nice=-5 applied (PID $pid)" || true
    # Reduce chance of OOM-killer targeting Lutris under 12 GB memory pressure
    echo -200 | sudo tee "/proc/${pid}/oom_score_adj" > /dev/null 2>/dev/null || true
    ok "Lutris PID: $pid  (ionice best-effort/0  |  oom_adj=-200)"
}

run_native() {
    command -v lutris &>/dev/null || { warn "Native Lutris not found."; return 1; }
    ok "Launching native Lutris..."
    _launch lutris
}

run_flatpak() {
    flatpak info net.lutris.Lutris &>/dev/null || { warn "Flatpak Lutris not found."; return 1; }
    ok "Launching Flatpak Lutris..."
    _launch flatpak run net.lutris.Lutris
}

case "$PREFERRED_VERSION" in
    native)
        run_native  || die "Native Lutris not installed."
        ;;
    flatpak)
        run_flatpak || die "Flatpak Lutris not installed."
        ;;
    *)
        ok "Auto mode — trying native first..."
        run_native || {
            ok "Native unavailable. Trying Flatpak..."
            run_flatpak || die "No Lutris installation found (tried native + flatpak)."
        }
        ;;
esac

# ── STATUS SUMMARY ────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  ★  GAME MODE IS ACTIVE  ★"
echo "════════════════════════════════════════"
printf "  CPU governor  :  performance\n"
printf "  Intel EPP     :  performance (turbo unrestricted)\n"
if $ZRAM_ACTIVE; then
    printf "  Swappiness    :  %d (ZRAM active — compressed RAM preferred)\n" "$GAMING_SWAPPINESS"
else
    printf "  Swappiness    :  %d (no ZRAM — disk-safe mode)\n" "$GAMING_SWAPPINESS"
fi
printf "  Dirty ratio   :  15 / 8  (12 GB profile)\n"
printf "  vfs pressure  :  50\n"
printf "  THP           :  madvise\n"
printf "  I/O scheduler :  mq-deadline (SSDs)\n"
if $NVIDIA_GPU; then
    printf "  GPU           :  NVIDIA 940MX  (PRIME offload)\n"
else
    printf "  GPU           :  Intel HD 520  (iris, GL 4.5)\n"
fi
printf "  ptrace_scope  :  0  (auto-restores on exit)\n"
printf "  WiFi power    :  disabled\n"
echo "════════════════════════════════════════"
echo ""
echo "  ↳ Keep this window open while playing."
echo "  ↳ Press [ENTER] to restore Desktop Mode."
echo ""
read -rp "  > "

# ── CLEANUP PHASE ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  RESTORING DESKTOP MODE..."
echo "════════════════════════════════════════"
log "Cleanup in progress — please wait..."
sleep 1
# Script exits → EXIT trap fires → restore_system() handles everything
