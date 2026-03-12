import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Crack password hashes using hashcat in CPU mode. Agent should generate a targeted wordlist first via web research.",
    args: {
        hash: tool.schema.string().describe("Hash string to crack, or path to a file containing hashes"),
        hash_type: tool.schema.number().describe("Hashcat mode number (e.g., 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt). Use 'hashcat --help' via bash if unsure."),
        wordlist_path: tool.schema.string().describe("Path to the agent-generated wordlist file (e.g., /workspace/output/wordlist.txt)"),
        rules: tool.schema.string().optional().describe("Optional hashcat rules file or built-in rule name (e.g., 'best64.rule')"),
        runtime: tool.schema.number().default(300).describe("Maximum runtime in seconds (default 300 = 5 minutes)"),
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "hashcat_crack", args }, async () => {
            const startTime = Date.now()

            try {
                // Determine if hash is a file or inline string
                let hashArg: string
                const possiblePath = args.hash.startsWith("/") ? args.hash : path.join(context.directory, args.hash)
                if (fs.existsSync(possiblePath)) {
                    hashArg = possiblePath
                } else {
                    // Write inline hash to temp file
                    const tmpFile = "/tmp/hashcat_input.txt"
                    fs.writeFileSync(tmpFile, args.hash + "\n")
                    hashArg = tmpFile
                }

                // Verify wordlist exists
                if (!fs.existsSync(args.wordlist_path)) {
                    return JSON.stringify({
                        success: false,
                        error: `Wordlist not found at ${args.wordlist_path}. Generate a wordlist first by researching common passwords for this service.`,
                    }, null, 2)
                }

                // Build hashcat command (try GPU first if available)
                const baseCmdArgs = [
                    "-m", String(args.hash_type),
                    "-a", "0",           // dictionary attack
                    "--runtime", String(args.runtime),
                    "--potfile-disable",
                    "-o", "/tmp/hashcat_output.txt",
                    "--outfile-format", "2",  // plain passwords only
                    hashArg,
                    args.wordlist_path,
                ]

                if (args.rules) {
                    const rulePath = args.rules.includes("/") ? args.rules : `/usr/share/hashcat/rules/${args.rules}`
                    if (existsSync(rulePath)) {
                        baseCmdArgs.push("-r", rulePath)
                    }
                }

                // Run hashcat initially without --force (allows GPU usage if NVIDIA toolkit is mapped)
                let result = await $`hashcat ${baseCmdArgs}`.nothrow().timeout(args.runtime * 1000 + 30000)
                let stdout = result.stdout?.toString() || ""
                let stderr = result.stderr?.toString() || ""

                // Fallback to CPU mode (--force) if OpenCL/CUDA failed
                if (result.exitCode !== 0 && (stderr.includes("clGetPlatformIDs") || stderr.includes("No devices found") || stdout.includes("No devices found"))) {
                    const fallbackArgs = ["--force", ...baseCmdArgs]
                    result = await $`hashcat ${fallbackArgs}`.nothrow().timeout(args.runtime * 1000 + 30000)
                    stdout = result.stdout?.toString() || ""
                    stderr += "\n[GPU Failed - Fell back to CPU]: " + (result.stderr?.toString() || "")
                }

                // Read cracked results
                let cracked: string[] = []
                if (existsSync("/tmp/hashcat_output.txt")) {
                    const output = await Bun.file("/tmp/hashcat_output.txt").text()
                    cracked = output.trim().split("\n").filter(l => l.length > 0)
                    // Clean up
                    await $`rm -f /tmp/hashcat_output.txt`.nothrow()
                }

                // Parse status from stdout
                const statusMatch = stdout.match(/Status\.*:\s*(.+)/i)
                const speedMatch = stdout.match(/Speed\.*:\s*(.+)/i)

                return JSON.stringify({
                    success: true,
                    cracked: cracked.length > 0,
                    passwords: cracked,
                    count: cracked.length,
                    hashType: args.hash_type,
                    status: statusMatch?.[1]?.trim() || (cracked.length > 0 ? "Cracked" : "Exhausted"),
                    speed: speedMatch?.[1]?.trim() || "unknown",
                    duration: Date.now() - startTime,
                    note: stdout.includes("--force") ? "Fell back to CPU mode. For stronger hashes, enable GPU passthrough." : "Running with available hardware acceleration.",
                }, null, 2)

            } catch (error: any) {
                return JSON.stringify({
                    success: false,
                    error: error.message || String(error),
                    duration: Date.now() - startTime,
                    hint: "Common issues: invalid hash_type mode number, empty wordlist, or hash format mismatch.",
                }, null, 2)
            }
        })
    }
})
