import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { existsSync, writeFileSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Hook Android app functions at runtime using Frida. Connects to Android device/emulator on host via ADB. Requires Frida server running on target device.",
    args: {
        package_name: tool.schema.string().describe("Target app package name (e.g., 'com.example.app')"),
        script: tool.schema.string().describe("Frida JS hook script (inline code or path to .js file)"),
        spawn: tool.schema.boolean().default(true).describe("If true, spawn the app fresh. If false, attach to running process."),
        timeout: tool.schema.number().default(30).describe("Capture timeout in seconds (default 30)"),
        device: tool.schema.string().optional().describe("Device ID or 'host.docker.internal:5555' for host emulator. Auto-detected if not specified."),
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

                // Connect to host emulator if no device specified
                if (args.device) {
                    await $`adb connect ${args.device}`.nothrow().timeout(10000)
                } else {
                    // Try connecting to host emulator
                    await $`adb connect host.docker.internal:5555`.nothrow().timeout(10000)
                }

                // Verify ADB connection
                const devices = await $`adb devices`.nothrow()
                const deviceList = devices.stdout?.toString() || ""
                if (!deviceList.includes("device") || deviceList.trim().endsWith("List of devices attached")) {
                    return JSON.stringify({
                        success: false,
                        error: "No Android device/emulator found. Ensure Android Studio emulator is running on host and ADB is accessible.",
                        adbOutput: deviceList,
                        hint: "CRITICAL: ADB version inside Docker must match the host ADB exactly, or they will kill each other's daemons. If they mismatch, use Frida over TCP directly (e.g. passing 'device: host.docker.internal:27042') instead of relying on ADB.",
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
                const cmdArgs: string[] = []
                if (args.spawn) {
                    cmdArgs.push("-f", args.package_name)
                } else {
                    cmdArgs.push("-n", args.package_name)
                }
                cmdArgs.push("-l", scriptPath)
                cmdArgs.push("--no-pause")

                if (args.device) {
                    cmdArgs.push("-D", args.device.split(":")[0])
                }

                // Run frida with timeout
                const result = await $`timeout ${args.timeout} frida ${cmdArgs}`.nothrow().timeout((args.timeout + 10) * 1000)
                const stdout = result.stdout?.toString() || ""
                const stderr = result.stderr?.toString() || ""

                // Parse output for structured results
                const lines = stdout.split("\n").filter((l: string) => l.trim().length > 0)

                return JSON.stringify({
                    success: true,
                    package: args.package_name,
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
                    hint: "Common issues: Frida server not running on device, version mismatch between frida and frida-server, app not installed.",
                }, null, 2)
            }
        })
    }
})
