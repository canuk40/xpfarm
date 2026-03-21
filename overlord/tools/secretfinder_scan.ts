import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Extract API keys, tokens, and secrets from JavaScript files using SecretFinder",
  args: {
    input: tool.schema.string().describe("URL of a JS file or local path to a JS file (e.g., 'https://example.com/app.js' or '/workspace/output/app.js')"),
    output_file: tool.schema.string().default("/workspace/output/secretfinder_results.html").describe("Output HTML report path"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "secretfinder_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-i", args.input, "-o", "cli"]

        const result = await $`python3 /opt/SecretFinder/SecretFinder.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse findings from output
        const findings: any[] = []
        for (const line of stdout.split("\n")) {
          const trimmed = line.trim()
          if (!trimmed || trimmed.startsWith("[")) {
            // Try to parse key-value findings
            const match = trimmed.match(/\[(\w+)\]\s+(.+)/)
            if (match) findings.push({ type: match[1], value: match[2] })
          }
        }

        return JSON.stringify({
          success: result.exitCode === 0 || findings.length > 0,
          input: args.input,
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
