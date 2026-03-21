import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Brute-force directories and files on a web server using Feroxbuster",
  args: {
    url: tool.schema.string().describe("Target base URL (e.g., https://example.com)"),
    wordlist: tool.schema.string().default("/workspace/wordlists/common.txt").describe("Path to wordlist file"),
    extensions: tool.schema.string().optional().describe("Comma-separated file extensions to add (e.g., 'php,html,js')"),
    depth: tool.schema.number().default(2).describe("Maximum recursion depth"),
    threads: tool.schema.number().default(50).describe("Number of concurrent threads"),
    filter_status: tool.schema.string().optional().describe("Status codes to filter out (e.g., '404,403')"),
    timeout: tool.schema.number().default(180).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "feroxbuster_fuzz", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "-w", args.wordlist, "-d", String(args.depth), "-t", String(args.threads), "--no-recursion", "--silent", "--json"]

        if (args.extensions) {
          cmdArgs.push("-x", args.extensions)
        }
        if (args.filter_status) {
          cmdArgs.push("--filter-status", args.filter_status)
        }

        const result = await $`feroxbuster ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        const findings: any[] = []
        for (const line of stdout.split("\n")) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const obj = JSON.parse(trimmed)
            if (obj.url) findings.push({ url: obj.url, status: obj.status, length: obj.content_length, words: obj.word_count })
          } catch {
            // skip
          }
        }

        return JSON.stringify({
          success: result.exitCode === 0 || findings.length > 0,
          target: args.url,
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
