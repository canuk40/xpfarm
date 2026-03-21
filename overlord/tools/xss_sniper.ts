import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "XSS vulnerability scanner using XSSniper — 120+ payloads, WAF bypass techniques, DOM-based XSS detection, and blind XSS support",
  args: {
    url: tool.schema.string().describe("Target URL with parameter(s) to test (e.g., 'https://example.com/search?q=test')"),
    mode: tool.schema.enum(["reflected", "dom", "blind", "all"]).default("reflected").describe("reflected=standard XSS, dom=DOM-based, blind=OOB callback, all=all modes"),
    waf_bypass: tool.schema.boolean().default(true).describe("Enable WAF bypass encoding techniques"),
    blind_callback: tool.schema.string().optional().describe("Callback URL for blind XSS (e.g., interactsh URL)"),
    headers: tool.schema.string().optional().describe("Extra headers as 'Key:Value|Key2:Value2'"),
    threads: tool.schema.number().default(10).describe("Concurrent threads"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "xss_sniper", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "--threads", String(args.threads)]

        if (args.mode === "dom" || args.mode === "all") cmdArgs.push("--dom")
        if (args.waf_bypass) cmdArgs.push("--bypass")
        if (args.blind_callback) cmdArgs.push("--blind", args.blind_callback)

        if (args.headers) {
          for (const h of args.headers.split("|")) {
            cmdArgs.push("-H", h.trim())
          }
        }

        const result = await $`python3 /opt/XSSniper/XSSniper.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        const findings = stdout.split("\n")
          .filter(l => l.includes("[VULN]") || l.includes("[+]") || l.includes("XSS") || l.includes("Payload"))
          .map(l => l.trim())

        const payloads = stdout.split("\n")
          .filter(l => l.includes("Payload:") || l.match(/<script|onerror|onload|javascript:/i))
          .map(l => l.trim())

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable: findings.length > 0,
          mode: args.mode,
          findings,
          working_payloads: payloads.slice(0, 10),
          raw: stdout.slice(0, 4000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
