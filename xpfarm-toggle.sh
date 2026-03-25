#!/bin/bash
# XPFarm on/off toggle — works with both Docker stack and native binary.
# Updates the desktop icon to reflect current state (green=ON, red=OFF).

WORKDIR="/mnt/workspace/xpfarm"
DESKTOP_FILE="$HOME/Desktop/XPFarm.desktop"
ICON_ON="$WORKDIR/img/xpfarm-on.svg"
ICON_OFF="$WORKDIR/img/xpfarm-off.svg"
URL="http://localhost:8888"

cd "$WORKDIR"

# ── helpers ────────────────────────────────────────────────────────────────────

is_running() {
    # Docker container running?
    docker compose ps -q xpfarm 2>/dev/null | grep -q . && return 0
    # Native binary on port 8888?
    ss -tlnp 2>/dev/null | grep -q ':8888' && return 0
    return 1
}

set_icon() {
    local icon="$1"
    if [ -f "$DESKTOP_FILE" ]; then
        sed -i "s|^Icon=.*|Icon=$icon|" "$DESKTOP_FILE"
        gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
        chmod +x "$DESKTOP_FILE"
    fi
}

notify() {
    notify-send "$1" "$2" -i "$3" -t 4000 2>/dev/null || true
}

# ── main toggle ────────────────────────────────────────────────────────────────

if is_running; then
    # ── STOP ──────────────────────────────────────────────────────────────────
    notify "XPFarm" "Stopping..." "$ICON_ON"

    # Stop Docker stack if it's the one running
    docker compose ps -q xpfarm 2>/dev/null | grep -q . && ./xpfarm.sh down

    # Kill any stray native process on 8888
    NATIVE_PID=$(ss -tlnp 2>/dev/null | grep ':8888' | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$NATIVE_PID" ]; then
        kill "$NATIVE_PID" 2>/dev/null || sudo kill "$NATIVE_PID" 2>/dev/null || true
        sleep 1
    fi

    set_icon "$ICON_OFF"
    notify "XPFarm" "Stopped." "$ICON_OFF"

else
    # ── START ─────────────────────────────────────────────────────────────────
    notify "XPFarm" "Starting stack..." "$ICON_OFF"

    ./xpfarm.sh up

    # Wait up to 30s for port 8888 to respond
    for i in $(seq 1 30); do
        sleep 1
        ss -tlnp 2>/dev/null | grep -q ':8888' && break
    done

    if is_running; then
        set_icon "$ICON_ON"
        notify "XPFarm" "Running at $URL" "$ICON_ON"
        xdg-open "$URL" 2>/dev/null || true
    else
        notify "XPFarm" "Failed to start — check logs." "$ICON_OFF"
    fi
fi
