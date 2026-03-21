import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Craft and send custom network packets using Scapy. Useful for raw protocol fuzzing, fingerprinting, and exploit testing.",
  args: {
    script: tool.schema.string().describe("Python Scapy script (inline). Use send(), sr1(), sniff(), etc. Results printed to stdout are captured."),
    timeout: tool.schema.number().default(30).describe("Execution timeout in seconds"),
    iface: tool.schema.string().optional().describe("Network interface to use (e.g., 'eth0'). Uses default if omitted."),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "scapy_craft", args }, async () => {
      const startTime = Date.now()
      try {
        const scriptPath = "/tmp/scapy_script.py"

        let script = args.script
        // Inject scapy import and interface config if not present
        if (!script.includes("from scapy") && !script.includes("import scapy")) {
          const preamble = ["from scapy.all import *", "conf.verb = 0"]
          if (args.iface) preamble.push(`conf.iface = '${args.iface}'`)
          script = preamble.join("\n") + "\n\n" + script
        }

        fs.writeFileSync(scriptPath, script)

        const result = await $`python3 ${scriptPath}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        return JSON.stringify({
          success: result.exitCode === 0,
          exit_code: result.exitCode,
          output: stdout.slice(0, 5000),
          stderr: stderr.slice(0, 1000) || undefined,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
