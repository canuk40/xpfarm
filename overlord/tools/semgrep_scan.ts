import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Run Semgrep static analysis on source code to find security vulnerabilities and code patterns",
  args: {
    target: tool.schema.string().describe("Path to file or directory to scan"),
    ruleset: tool.schema.string().default("p/security-audit").describe("Semgrep ruleset (e.g., 'p/security-audit', 'p/owasp-top-ten', 'p/jwt', 'p/xss', 'p/sql-injection', or path to custom .yaml rule)"),
    language: tool.schema.string().optional().describe("Force language (e.g., 'python', 'javascript', 'java', 'go')"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const targetPath = args.target.startsWith("/") ? args.target : path.join(context.directory, args.target)
    return instrumentedCall({ toolName: "semgrep_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["--config", args.ruleset, "--json", "--no-git-ignore", targetPath]
        if (args.language) cmdArgs.push("--lang", args.language)

        const result = await $`semgrep ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        let findings: any[] = []
        let errors: any[] = []
        try {
          const parsed = JSON.parse(stdout)
          findings = (parsed.results || []).map((r: any) => ({
            rule: r.check_id,
            severity: r.extra?.severity,
            message: r.extra?.message,
            file: r.path,
            line: r.start?.line,
            code: r.extra?.lines,
          }))
          errors = parsed.errors || []
        } catch { /* semgrep may not return valid JSON on error */ }

        return JSON.stringify({
          success: result.exitCode === 0 || result.exitCode === 1, // exit 1 = findings found
          target: targetPath,
          ruleset: args.ruleset,
          findings,
          count: findings.length,
          errors: errors.length > 0 ? errors : undefined,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 500) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
