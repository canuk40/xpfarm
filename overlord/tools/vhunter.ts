import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Async multi-vulnerability scanner using vhunter — tests for XSS, SQL injection, SSRF, RCE, open redirects with SARIF output",
  args: {
    url: tool.schema.string().describe("Target URL or domain to scan"),
    vuln_types: tool.schema.string().default("xss,sqli,ssrf,rce,redirect").describe("Comma-separated vulnerability types to test: xss, sqli, ssrf, rce, redirect"),
    output_dir: tool.schema.string().default("/workspace/output/vhunter").describe("Output directory for SARIF reports"),
    timeout: tool.schema.number().default(90).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "vhunter", args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_dir}`.nothrow()

        const sarifOut = `${args.output_dir}/results.sarif`
        const types = args.vuln_types.split(",").map(t => t.trim())

        const cmdArgs: string[] = ["-u", args.url, "-o", sarifOut]
        for (const t of types) cmdArgs.push("--" + t)

        const result = await $`python3 /opt/vhunter/vhunter_v6.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse SARIF output
        let sarif: any = null
        let findings: any[] = []
        try {
          const f = Bun.file(sarifOut)
          if (await f.exists()) {
            sarif = JSON.parse(await f.text())
            findings = sarif?.runs?.[0]?.results || []
          }
        } catch { /* use stdout */ }

        if (findings.length === 0) {
          findings = stdout.split("\n")
            .filter(l => l.includes("[+]") || l.includes("VULNERABLE") || l.includes("found"))
            .map(l => ({ message: { text: l.trim() } }))
        }

        const simplified = findings.map((r: any) => ({
          rule: r.ruleId || r.rule_id,
          message: r.message?.text || r.message,
          location: r.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
          severity: r.level,
        }))

        return JSON.stringify({
          success: true,
          target: args.url,
          vuln_types_tested: types,
          total_findings: findings.length,
          findings: simplified,
          sarif_path: sarif ? sarifOut : undefined,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
