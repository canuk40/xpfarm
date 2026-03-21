import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Detect subdomain takeover vulnerabilities using Subzy — checks S3, GitHub Pages, Heroku, Netlify, and 60+ services for dangling CNAME records",
  args: {
    targets: tool.schema.string().describe("Comma-separated subdomains, single subdomain, or path to file with one subdomain per line"),
    concurrency: tool.schema.number().default(20).describe("Concurrent checks"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
    hide_fails: tool.schema.boolean().default(true).describe("Hide non-vulnerable results"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "subzy_takeover", args }, async () => {
      const startTime = Date.now()
      try {
        const outFile = "/tmp/subzy_out.json"
        const cmdArgs: string[] = ["check", "--output", outFile, "--concurrency", String(args.concurrency)]
        if (args.hide_fails) cmdArgs.push("--hide_fails")

        // Determine if targets is a file path or inline list
        const isFile = args.targets.startsWith("/") || args.targets.endsWith(".txt")
        if (isFile) {
          cmdArgs.push("--targets", args.targets)
        } else {
          // Write inline list to temp file
          const tmpTargets = "/tmp/subzy_targets.txt"
          await Bun.write(tmpTargets, args.targets.split(",").map(t => t.trim()).join("\n"))
          cmdArgs.push("--targets", tmpTargets)
        }

        const result = await $`subzy ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        let findings: any[] = []
        try {
          const f = Bun.file(outFile)
          if (await f.exists()) {
            const raw = await f.text()
            findings = JSON.parse(raw) || []
            await $`rm -f ${outFile}`.nothrow()
          }
        } catch { /* parse from stdout */ }

        // Fallback: parse vulnerable lines from stdout
        if (findings.length === 0 && stdout.includes("VULNERABLE")) {
          findings = stdout.split("\n")
            .filter(l => l.includes("VULNERABLE"))
            .map(l => ({ raw: l.trim() }))
        }

        return JSON.stringify({
          success: true,
          targets: args.targets,
          vulnerable_count: findings.length,
          findings,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
