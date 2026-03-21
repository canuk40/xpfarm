import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Generate targeted wordlists using Crunch based on character sets, patterns, and length ranges",
  args: {
    min_length: tool.schema.number().describe("Minimum word length"),
    max_length: tool.schema.number().describe("Maximum word length"),
    charset: tool.schema.string().optional().describe("Character set to use (e.g., 'abc123', 'abcdefghijklmnopqrstuvwxyz0123456789'). Defaults to lowercase alpha."),
    pattern: tool.schema.string().optional().describe("Pattern template using @ (lowercase), , (uppercase), % (digit), ^ (symbol). E.g., '@@%%' generates 2-letter 2-digit combos."),
    output_file: tool.schema.string().default("/workspace/wordlists/crunch_out.txt").describe("Output file path"),
    max_lines: tool.schema.number().default(100000).describe("Max lines to generate (safety limit)"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "crunch_wordlist", args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_file.split("/").slice(0, -1).join("/")}`.nothrow()

        const cmdArgs: string[] = [String(args.min_length), String(args.max_length)]

        if (args.charset) {
          cmdArgs.push(args.charset)
        }

        cmdArgs.push("-o", args.output_file)

        if (args.pattern) {
          cmdArgs.push("-t", args.pattern)
        }

        // Add line count limit
        cmdArgs.push("-c", String(args.max_lines))

        const result = await $`crunch ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Count generated lines
        let lineCount = 0
        try {
          const countResult = await $`wc -l ${args.output_file}`.nothrow()
          lineCount = parseInt(countResult.stdout?.toString().trim().split(" ")[0] || "0")
        } catch { /* ignore */ }

        return JSON.stringify({
          success: result.exitCode === 0,
          output_file: args.output_file,
          lines_generated: lineCount,
          min_length: args.min_length,
          max_length: args.max_length,
          charset: args.charset || "lowercase alpha",
          pattern: args.pattern,
          stdout: stdout.slice(0, 500),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
