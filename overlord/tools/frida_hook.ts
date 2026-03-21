import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { existsSync, writeFileSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Hook Android app functions at runtime using Frida. Connects to a physical Android device or emulator via ADB (host passthrough). Requires Frida server running on target device.",
    args: {
        package_name: tool.schema.string().describe("Target app package name (e.g., 'com.example.app')"),
        script: tool.schema.string().describe("Frida JS hook script (inline code or path to .js file)"),
        spawn: tool.schema.boolean().default(true).describe("If true, spawn the app fresh. If false, attach to running process."),
        timeout: tool.schema.number().default(30).describe("Capture timeout in seconds (default 30)"),
        device: tool.schema.string().optional().describe("Device serial number (from 'adb devices'). Auto-detected if only one device is connected."),
    },
    async execute(args, context) {
        return instrumentedCall({ toolName: "frida_hook", args }, async () => {
            const startTime = Date.now()

            try {
                // Check frida is available
                try {
                    await $`which frida`.quiet()
                } catch {
                    return JSON.stringify({ success: false, error: "frida-tools not installed. Run: pip3 install frida-tools" }, null, 2)
                }

                // ADB_SERVER_SOCKET is set in docker-compose.yml to use the host's ADB server.
                // This means `adb devices` automatically sees devices connected to the host (USB phones, emulators).
                // No manual `adb connect` is needed.

                // Verify ADB connection and detect devices
                const devices = await $`adb devices`.nothrow()
                const deviceList = devices.stdout?.toString() || ""
                const deviceLines = deviceList.split("\n")
                    .filter((l: string) => l.trim() && !l.startsWith("List of") && l.includes("\tdevice"))
                    .map((l: string) => l.split("\t")[0].trim())

                if (deviceLines.length === 0) {
                    return JSON.stringify({
                        success: false,
                        error: "No Android device found via ADB. Ensure your phone is connected via USB with USB debugging enabled, and ADB is running on the host.",
                        adbOutput: deviceList.trim(),
                        troubleshooting: [
                            "1. On the host, run 'adb devices' to confirm the phone is visible",
                            "2. Ensure USB debugging is enabled on the phone (Settings > Developer Options)",
                            "3. Ensure ADB server is running on the host (run 'adb start-server')",
                            "4. The container uses ADB_SERVER_SOCKET to connect to the host's ADB on port 5037",
                        ],
                    }, null, 2)
                }

                // Select device
                let targetDevice = args.device
                if (!targetDevice) {
                    targetDevice = deviceLines[0]
                    if (deviceLines.length > 1) {
                        // Multiple devices — use first but warn
                        console.log(`[*] Multiple devices detected: ${deviceLines.join(", ")}. Using ${targetDevice}. Pass 'device' arg to select a specific one.`)
                    }
                } else if (!deviceLines.includes(targetDevice)) {
                    return JSON.stringify({
                        success: false,
                        error: `Device '${targetDevice}' not found. Available devices: ${deviceLines.join(", ")}`,
                    }, null, 2)
                }

                console.log(`[*] Target device: ${targetDevice}`)

                // Check frida-server is running on the device
                const fridaCheck = await $`frida-ps -s ${targetDevice}`.nothrow().timeout(10000)
                if (fridaCheck.exitCode !== 0) {
                    const stderr = fridaCheck.stderr?.toString() || ""
                    return JSON.stringify({
                        success: false,
                        error: `Cannot connect to frida-server on device ${targetDevice}. Ensure frida-server is running on the device.`,
                        details: stderr.trim(),
                        troubleshooting: [
                            "1. Download frida-server for your device's architecture from https://github.com/frida/frida/releases",
                            "2. Push it to the device: adb push frida-server /data/local/tmp/",
                            "3. Make it executable: adb shell chmod +x /data/local/tmp/frida-server",
                            "4. Start it (requires root): adb shell su -c '/data/local/tmp/frida-server -D &'",
                            "5. Frida version on host and frida-server on device MUST match exactly",
                        ],
                    }, null, 2)
                }

                // Write script to temp file if inline
                let scriptPath: string
                if (existsSync(args.script)) {
                    scriptPath = args.script
                } else {
                    scriptPath = "/tmp/frida_hook.js"
                    writeFileSync(scriptPath, args.script)
                }

                // Build frida command
                const cmdArgs: string[] = ["-s", targetDevice]
                if (args.spawn) {
                    cmdArgs.push("-f", args.package_name)
                } else {
                    cmdArgs.push("-n", args.package_name)
                }
                cmdArgs.push("-l", scriptPath)
                cmdArgs.push("--no-pause")

                // Run frida with timeout
                const result = await $`timeout ${args.timeout} frida ${cmdArgs}`.nothrow().timeout((args.timeout + 10) * 1000)
                const stdout = result.stdout?.toString() || ""
                const stderr = result.stderr?.toString() || ""

                // Parse output for structured results
                const lines = stdout.split("\n").filter((l: string) => l.trim().length > 0)

                return JSON.stringify({
                    success: true,
                    package: args.package_name,
                    device: targetDevice,
                    mode: args.spawn ? "spawn" : "attach",
                    output: stdout.length > 10000 ? stdout.substring(0, 10000) + "\n... truncated" : stdout,
                    errors: stderr ? stderr.split("\n").filter((l: string) => l.trim()).slice(0, 20) : [],
                    lineCount: lines.length,
                    duration: Date.now() - startTime,
                }, null, 2)

            } catch (error: any) {
                return JSON.stringify({
                    success: false,
                    error: error.message || String(error),
                    duration: Date.now() - startTime,
                    hint: "Common issues: Frida server not running on device, version mismatch between frida and frida-server, app not installed, device not visible via ADB.",
                }, null, 2)
            }
        })
    }
})
