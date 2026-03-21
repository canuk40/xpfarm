import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Crack password hashes using John the Ripper with wordlist or incremental mode",
  args: {
    hash: tool.schema.string().describe("Hash string to crack, or path to a file containing hashes in John format"),
    wordlist: tool.schema.string().optional().describe("Path to wordlist file. Omit to use incremental mode."),
    format: tool.schema.string().optional().describe("Hash format (e.g., 'md5', 'sha256', 'bcrypt', 'nt', 'raw-sha1'). Auto-detected if omitted."),
    rules: tool.schema.boolean().default(false).describe("Apply word mangling rules to wordlist"),
    runtime: tool.schema.number().default(180).describe("Maximum runtime in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "john_crack", args }, async () => {
      const startTime = Date.now()
      try {
        // Write inline hash to temp file if not a file path
        let hashFile: string
        const possiblePath = args.hash.startsWith("/") ? args.hash : `/workspace/${args.hash}`
        if (fs.existsSync(possiblePath)) {
          hashFile = possiblePath
        } else if (fs.existsSync(args.hash)) {
          hashFile = args.hash
        } else {
          hashFile = "/tmp/john_input.txt"
          fs.writeFileSync(hashFile, args.hash + "\n")
        }

        // John 1.8.0 (system pkg) doesn't support --format or --max-run-time
        // Use timeout(1) command as runtime limiter instead
        let cmdArr: string[] = [String(args.runtime), "john", hashFile]
        if (args.wordlist) {
          cmdArr.push(`--wordlist=${args.wordlist}`)
          if (args.rules) cmdArr.push("--rules")
        } else {
          cmdArr.push("--incremental")
        }

        const result = await $`timeout ${cmdArr}`.nothrow().timeout(args.runtime * 1000 + 15000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Show cracked passwords
        const showResult = await $`john --show ${hashFile}`.nothrow().timeout(10000)
        const showOutput = showResult.stdout?.toString() || ""

        const cracked: string[] = []
        for (const line of showOutput.split("\n")) {
          if (line.includes(":") && !line.includes("password hash") && line.trim()) {
            cracked.push(line.trim())
          }
        }

        return JSON.stringify({
          success: true,
          cracked: cracked.length > 0,
          passwords: cracked,
          count: cracked.length,
          mode: args.wordlist ? "wordlist" : "incremental",
          stdout: (stdout + stderr).slice(0, 1000),
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
