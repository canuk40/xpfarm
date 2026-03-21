import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Execute a pwntools Python exploit script against a binary or remote service. Write the script inline or point to an existing file.",
  args: {
    script: tool.schema.string().describe("Python exploit script using pwntools (inline code string). Use context.binary, context.log_level='debug', process(), remote(), etc."),
    binary: tool.schema.string().optional().describe("Path to the target binary (available as /workspace/binaries/<name> inside the script)"),
    host: tool.schema.string().optional().describe("Remote host for remote() connections"),
    port: tool.schema.number().optional().describe("Remote port for remote() connections"),
    timeout: tool.schema.number().default(60).describe("Execution timeout in seconds"),
    stdin_data: tool.schema.string().optional().describe("Data to pipe into stdin if the script reads from stdin"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "pwntools_run", args }, async () => {
      const startTime = Date.now()
      try {
        // Write script to temp file
        const scriptPath = "/tmp/pwn_exploit.py"
        let script = args.script

        // Inject binary/host/port context if provided
        const preamble: string[] = ["from pwn import *", "context.log_level = 'warning'"]
        if (args.binary) {
          const binPath = args.binary.startsWith("/") ? args.binary : path.join("/workspace/binaries", args.binary)
          preamble.push(`context.binary = ELF('${binPath}', checksec=False)`)
        }
        if (args.host && args.port) {
          preamble.push(`TARGET_HOST = '${args.host}'`)
          preamble.push(`TARGET_PORT = ${args.port}`)
        }

        // Only inject preamble if script doesn't already import pwn
        if (!script.includes("from pwn import") && !script.includes("import pwn")) {
          script = preamble.join("\n") + "\n\n" + script
        }

        fs.writeFileSync(scriptPath, script)

        let result: any
        if (args.stdin_data) {
          const stdinPath = "/tmp/pwn_stdin.txt"
          fs.writeFileSync(stdinPath, args.stdin_data)
          result = await $`python3 ${scriptPath} < ${stdinPath}`.nothrow().timeout(args.timeout * 1000 + 5000)
        } else {
          result = await $`python3 ${scriptPath}`.nothrow().timeout(args.timeout * 1000 + 5000)
        }

        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Check for common exploit indicators
        const gotShell = stdout.includes("$") || stdout.includes("#") || stdout.includes("sh-") || stdout.includes("/bin/sh") || stdout.includes("/bin/bash")
        const hasFlag = stdout.match(/(?:flag|CTF|picoCTF|HTB|THM)\{[^}]+\}/i)

        return JSON.stringify({
          success: result.exitCode === 0,
          exit_code: result.exitCode,
          stdout: stdout.slice(0, 5000),
          stderr: stderr.slice(0, 2000),
          got_shell: gotShell,
          flag: hasFlag?.[0] || null,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
