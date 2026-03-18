#!/bin/bash
# Frida MCP wrapper — handles device availability gracefully.
# Used by OpenCode's MCP config. Waits for an ADB device before starting frida-mcp.

MAX_WAIT=10  # seconds to wait for device on startup
RETRY_DELAY=3

# Check if frida-mcp is installed
if ! command -v frida-mcp &> /dev/null; then
    echo "frida-mcp not installed, attempting pip install..." >&2
    pip3 install -q frida-mcp 2>/dev/null || {
        echo "Failed to install frida-mcp" >&2
        exit 1
    }
fi

# Wait briefly for a device to appear (non-blocking startup)
elapsed=0
while [ $elapsed -lt $MAX_WAIT ]; do
    if adb devices 2>/dev/null | grep -q "device$"; then
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

# Launch frida-mcp (it speaks MCP over stdio)
# If no device is connected, frida-mcp will still start but individual
# tool calls will report device errors through the MCP protocol.
exec frida-mcp "$@"
