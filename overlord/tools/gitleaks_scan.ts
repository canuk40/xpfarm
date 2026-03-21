import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Scan git repositories or directories for leaked secrets and API keys using Gitleaks",
  args: {
    target: tool.schema.string().describe("Path to a git repo directory, or URL of a remote git repo to clone and scan"),
    source: tool.schema.enum(["dir", "git", "repo"]).default("dir").describe("dir=local directory, git=git history of local repo, repo=clone remote URL"),
    depth: tool.schema.number().optional().describe("Limit git log depth (commits to scan). Unlimited if omitted."),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "gitleaks_scan", args }, async () => {
      const startTime = Date.now()
      try {
        let targetPath = args.target

        if (args.source === "repo") {
          // Clone remote repo first
          const cloneDir = "/tmp/gitleaks_clone"
          await $`rm -rf ${cloneDir}`.nothrow()
          const cloneArgs = ["--depth", "50", args.target, cloneDir]
          await $`git clone ${cloneArgs}`.nothrow().timeout(60000)
          targetPath = cloneDir
        } else if (!args.target.startsWith("/")) {
          targetPath = path.join(context.directory, args.target)
        }

        const cmdArgs: string[] = [args.source === "dir" ? "detect" : "detect", "--source", targetPath, "--report-format", "json", "--report-path", "/tmp/gitleaks_out.json", "--no-banner", "-q"]
        if (args.source === "dir") cmdArgs.push("--no-git")
        if (args.depth) cmdArgs.push("--log-opts", `--max-count=${args.depth}`)

        const result = await $`gitleaks ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)

        let leaks: any[] = []
        try {
          const f = Bun.file("/tmp/gitleaks_out.json")
          if (await f.exists()) {
            const raw = await f.text()
            leaks = JSON.parse(raw) || []
            await $`rm -f /tmp/gitleaks_out.json`.nothrow()
          }
        } catch { /* no leaks */ }

        const summary = leaks.map(l => ({
          rule: l.RuleID || l.Description,
          file: l.File,
          line: l.StartLine,
          secret: l.Secret?.slice(0, 20) + "...",
          match: l.Match?.slice(0, 60),
        }))

        return JSON.stringify({
          success: true,
          target: args.target,
          leaks_found: leaks.length > 0,
          count: leaks.length,
          leaks: summary,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
