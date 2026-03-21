#!/bin/bash

cd /mnt/workspace/xpfarm

STATUS=$(docker compose ps -q 2>/dev/null)

if [ -n "$STATUS" ]; then
    notify-send "XPFarm" "Stopping..." -i /mnt/workspace/xpfarm/img/dashboard.png 2>/dev/null || true
    ./xpfarm.sh down
    notify-send "XPFarm" "Stopped." -i /mnt/workspace/xpfarm/img/dashboard.png 2>/dev/null || true
else
    notify-send "XPFarm" "Starting..." -i /mnt/workspace/xpfarm/img/dashboard.png 2>/dev/null || true
    docker compose up -d
    notify-send "XPFarm" "Running at http://localhost:8888" -i /mnt/workspace/xpfarm/img/dashboard.png 2>/dev/null || true
    xdg-open http://localhost:8888 2>/dev/null || true
fi
