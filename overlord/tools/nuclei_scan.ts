import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Run Nuclei vulnerability scanner against a target URL or list of URLs using templates",
  args: {
    target: tool.schema.string().describe("Target URL or path to a file containing URLs (one per line)"),
    templates: tool.schema.string().optional().describe("Template tags or paths (e.g., 'cve', 'exposed', 'misconfig', or /path/to/template.yaml). Defaults to all templates."),
    severity: tool.schema.enum(["info", "low", "medium", "high", "critical", "all"]).default("all").describe("Minimum severity to report"),
    rate_limit: tool.schema.number().default(100).describe("Max requests per second"),
    concurrency: tool.schema.number().default(25).describe("Max concurrent templates"),
    timeout: tool.schema.number().default(300).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "nuclei_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.target, "-rl", String(args.rate_limit), "-c", String(args.concurrency), "-timeout", "10", "-silent", "-j"]

        if (args.templates) {
          cmdArgs.push("-t", args.templates)
        }
        if (args.severity !== "all") {
          cmdArgs.push("-severity", args.severity)
        }

        const result = await $`nuclei ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse JSONL output lines
        const findings: any[] = []
        for (const line of stdout.split("\n")) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            findings.push(JSON.parse(trimmed))
          } catch {
            // skip non-JSON lines
          }
        }

        return JSON.stringify({
          success: result.exitCode === 0 || findings.length > 0,
          target: args.target,
          findings,
          count: findings.length,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 500) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
