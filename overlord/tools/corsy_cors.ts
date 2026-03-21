import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Scan for CORS misconfigurations using Corsy — detects wildcard origins, null origin trust, pre-domain bypass, and other CORS weaknesses",
  args: {
    url: tool.schema.string().describe("Target URL or path to a file with one URL per line"),
    threads: tool.schema.number().default(20).describe("Concurrent threads"),
    headers: tool.schema.string().optional().describe("Extra headers as JSON object (e.g., '{\"Authorization\":\"Bearer token\"}')"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "corsy_cors", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-t", String(args.threads), "-q"]

        const isFile = args.url.startsWith("/") || args.url.endsWith(".txt")
        if (isFile) {
          cmdArgs.push("-i", args.url)
        } else {
          cmdArgs.push("-u", args.url)
        }

        if (args.headers) {
          try {
            const hdrs = JSON.parse(args.headers)
            const hdrStr = Object.entries(hdrs).map(([k, v]) => `${k}: ${v}`).join(", ")
            cmdArgs.push("--headers", hdrStr)
          } catch { /* ignore invalid JSON */ }
        }

        const result = await $`python3 /opt/Corsy/corsy.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Corsy outputs JSON-like results per vulnerable URL
        let findings: any[] = []
        try {
          // Try to extract JSON blocks from output
          const jsonMatches = stdout.match(/\{[\s\S]*?\}/g) || []
          for (const m of jsonMatches) {
            try { findings.push(JSON.parse(m)) } catch { /* skip */ }
          }
        } catch { /* fallback */ }

        if (findings.length === 0) {
          // Parse text output
          findings = stdout.split("\n")
            .filter(l => l.includes("Vulnerable") || l.includes("vulnerable") || l.includes("[+]"))
            .map(l => ({ raw: l.trim() }))
        }

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable: findings.length > 0,
          findings,
          count: findings.length,
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
