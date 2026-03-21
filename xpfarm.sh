#!/bin/bash

# XPFarm - Unified CLI
# Usage: ./xpfarm.sh [build|up|onlyGo|down|help]

set -e

banner() {
    echo -e "\033[38;2;139;92;246m ____  ________________________                     \033[0m"
    echo -e "\033[38;2;122;98;230m \u2572   \u2572\u2571  \u2571\u2572______   \u2572_   _____\u2571____ _______  _____  \033[0m"
    echo -e "\033[38;2;105;110;214m  \u2572     \u2571  \u2502     ___\u2571\u2502    __) \u2572__  \u2572\u2572_  __ \u2572\u2571     \u2572 \033[0m"
    echo -e "\033[38;2;80;130;190m  \u2571     \u2572  \u2502    \u2502    \u2502     \u2572   \u2571 __ \u2572\u2502  \u2502 \u2572\u2571  y y  \u2572\033[0m"
    echo -e "\033[38;2;48;158;163m \u2571___\u2571\u2572  \u2572 \u2502____\u2502    \u2572___  \u2571  (____  \u2571__\u2502  \u2502__\u2502_\u2502  \u2571\033[0m"
    echo -e "\033[38;2;16;185;129m       \u2572_\u2571               \u2572\u2571        \u2572\u2571            \u2572\u2571 \033[0m"
    echo -e "\033[38;2;16;185;129m                                    github.com/A3-N\033[0m"
    echo ""
}

require_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "\033[1;31mError: Docker is not installed\033[0m"
        exit 1
    fi
}


cmd_build() {
    require_docker
    banner
    echo -e "\033[1mBuilding XPFarm + Overlord containers...\033[0m"
    docker compose build
    echo ""
    echo -e "\033[1;32mBuild complete!\033[0m Run \033[1m./xpfarm.sh up\033[0m to start."
}

cmd_up() {
    require_docker
    banner

    # Ensure data directory exists
    mkdir -p data

    echo -e "\033[1mStarting XPFarm + Overlord...\033[0m"
    docker compose up -d

    echo -e "\033[1mWaiting for XPFarm web UI...\033[0m"
    while ! curl -s http://localhost:8888/ > /dev/null; do
        sleep 2
    done

    echo ""
    echo -e "\033[1;32mEnvironment is running and web UI is ready!\033[0m"
    echo -e "  XPFarm:   \033[1mhttp://localhost:8888\033[0m"
    echo -e "  Overlord: \033[1mRunning (internal)\033[0m"
    echo ""
    docker compose ps
}

cmd_onlygo() {
    banner
    echo -e "\033[1mBuilding XPFarm (Go native, no Docker)...\033[0m"
    echo -e "\033[1mNote: Overlord features require Docker.\033[0m"
    echo ""

    go build -o xpfarm main.go
    echo -e "\033[1;32mBuild complete. Starting...\033[0m"
    ./xpfarm "$@"
}

cmd_down() {
    require_docker
    echo -e "\033[1mStopping all containers...\033[0m"
    docker compose down
    echo -e "\033[1;32mEnvironment stopped.\033[0m"
}

cmd_help() {
    banner
    echo -e "Usage: \033[1m./xpfarm.sh\033[0m <command>"
    echo ""
    echo "Commands:"
    echo -e "  \033[1mbuild\033[0m       Build the Docker containers (XPFarm + Overlord)"
    echo -e "  \033[1mup\033[0m          Start the environment (docker compose up)"
    echo -e "  \033[1monlyGo\033[0m      Compile and run Go binary directly (no Docker, no Overlord)"
    echo -e "  \033[1mdown\033[0m        Stop all Docker containers"
    echo -e "  \033[1mhelp\033[0m        Show this help message"
    echo ""
    echo "Examples:"
    echo -e "  ./xpfarm.sh build        # Build containers"
    echo -e "  ./xpfarm.sh up           # Start full stack"
    echo -e "  ./xpfarm.sh onlyGo       # Dev mode, Go only"
}

case "${1:-help}" in
    build)    cmd_build ;;
    up)       cmd_up ;;
    onlyGo)   shift; cmd_onlygo "$@" ;;
    down)     cmd_down ;;
    help|*)   cmd_help ;;
esac
