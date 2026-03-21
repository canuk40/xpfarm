import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Dump exposed .git directories from web servers using git-dumper, then scan for secrets with gitleaks",
  args: {
    url: tool.schema.string().describe("Target URL with exposed .git (e.g., 'https://example.com/.git/')"),
    output_dir: tool.schema.string().default("/workspace/output/git_dumps").describe("Directory to dump the repository into"),
    scan_secrets: tool.schema.boolean().default(true).describe("Run gitleaks on the dumped repo after download"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "git_dumper", args }, async () => {
      const startTime = Date.now()
      try {
        const dumpDir = `${args.output_dir}/${new URL(args.url).hostname}`
        await $`mkdir -p ${dumpDir}`.nothrow()

        const result = await $`git-dumper ${args.url} ${dumpDir}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Count dumped files
        const lsResult = await $`find ${dumpDir} -type f`.nothrow()
        const files = lsResult.stdout?.toString().trim().split("\n").filter(l => l.trim()) || []

        let leaks: any[] = []
        if (args.scan_secrets && files.length > 0) {
          const leakResult = await $`gitleaks detect --source ${dumpDir} --no-git --report-format json --report-path /tmp/gitdump_leaks.json --no-banner -q`.nothrow().timeout(30000)
          try {
            const f = Bun.file("/tmp/gitdump_leaks.json")
            if (await f.exists()) {
              leaks = JSON.parse(await f.text()) || []
              await $`rm -f /tmp/gitdump_leaks.json`.nothrow()
            }
          } catch { /* no leaks */ }
        }

        return JSON.stringify({
          success: files.length > 0,
          url: args.url,
          dump_dir: dumpDir,
          files_dumped: files.length,
          sample_files: files.slice(0, 20),
          leaks_found: leaks.length,
          leaks: leaks.map((l: any) => ({ rule: l.RuleID, file: l.File, secret: l.Secret?.slice(0, 20) + "..." })),
          stdout: stdout.slice(0, 1000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
