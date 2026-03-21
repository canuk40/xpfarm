import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Detect subdomain takeover via CNAME chain analysis using autoSubTakeover — checks for dangling CNAME records pointing to unclaimed third-party services",
  args: {
    domain: tool.schema.string().describe("Root domain to check (e.g., 'example.com'), or path to a file with one subdomain per line"),
    threads: tool.schema.number().default(20).describe("Concurrent resolution threads"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "autosub_takeover", args }, async () => {
      const startTime = Date.now()
      try {
        const outFile = "/tmp/autosub_out.txt"
        // Write domain list to temp file if inline
        const isFile = args.domain.startsWith("/") || args.domain.endsWith(".txt")
        let domainFile = args.domain
        if (!isFile) {
          domainFile = "/tmp/autosub_targets.txt"
          await Bun.write(domainFile, args.domain.split(",").map(d => d.trim()).join("\n"))
        }

        const cmdArgs: string[] = ["-f", domainFile, "-t", String(args.threads), "-o", outFile]
        const result = await $`python3 /opt/autoSubTakeover/takeover.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""

        let findings: string[] = []
        try {
          const f = Bun.file(outFile)
          if (await f.exists()) {
            findings = (await f.text()).trim().split("\n").filter(l => l.trim())
            await $`rm -f ${outFile}`.nothrow()
          }
        } catch { /* use stdout */ }

        if (findings.length === 0) {
          findings = stdout.split("\n")
            .filter(l => l.includes("[VULN]") || l.includes("takeover") || l.includes("[+]"))
            .map(l => l.trim())
        }

        return JSON.stringify({
          success: true,
          target: args.domain,
          vulnerable_count: findings.length,
          findings,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
