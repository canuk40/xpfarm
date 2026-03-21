import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test API keys and credentials for validity and permissions using CobraAudit — supports Stripe, AWS, GitHub, SendGrid, Twilio, Slack, and 30+ services",
  args: {
    key: tool.schema.string().describe("API key or credential to test (e.g., 'sk_live_abc123', 'AKIA...')"),
    service: tool.schema.string().optional().describe("Force service type (e.g., 'stripe', 'aws', 'github', 'sendgrid'). Auto-detected if omitted."),
    file: tool.schema.string().optional().describe("Path to file with one key per line to bulk test"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "cobra_audit", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = []

        if (args.file) {
          cmdArgs.push("-f", args.file)
        } else {
          cmdArgs.push("-k", args.key)
        }

        if (args.service) cmdArgs.push("-s", args.service)

        const result = await $`python3 /opt/CobraAudit/cobraaudit.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse results
        const valid = stdout.includes("VALID") || stdout.includes("[+]") || stdout.includes("valid")
        const permissions = stdout.split("\n")
          .filter(l => l.match(/permission|scope|read|write|admin|access/i))
          .map(l => l.trim())

        const findings = stdout.split("\n")
          .filter(l => l.includes("[+]") || l.includes("VALID") || l.includes("Found"))
          .map(l => l.trim())

        return JSON.stringify({
          success: true,
          key: args.key ? args.key.slice(0, 8) + "..." : undefined,
          service_detected: stdout.match(/Service:\s*(\w+)/i)?.[1] || args.service || "auto",
          valid,
          permissions,
          findings,
          raw: stdout.slice(0, 3000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
