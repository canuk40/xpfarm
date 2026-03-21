import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Detect CORS misconfigurations on web targets using CORScanner",
  args: {
    url: tool.schema.string().describe("Target URL or domain (e.g., 'https://example.com' or path to file with one URL per line)"),
    threads: tool.schema.number().default(10).describe("Concurrent threads"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "corscanner_check", args }, async () => {
      const startTime = Date.now()
      try {
        const result = await $`python3 /usr/local/lib/python3.10/dist-packages/CORScanner/cors_scan.py -u ${args.url} -t ${args.threads} -o json`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        let findings: any[] = []
        try {
          // Try to parse JSON output
          const jsonMatch = stdout.match(/\[[\s\S]+\]/)
          if (jsonMatch) findings = JSON.parse(jsonMatch[0])
        } catch { /* fall through */ }

        const vulnerable = findings.length > 0 || stdout.toLowerCase().includes("vulnerable") || stdout.includes("CORS misconfiguration")

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable,
          findings,
          raw: findings.length === 0 ? stdout.slice(0, 3000) : undefined,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
