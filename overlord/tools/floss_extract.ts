import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import { existsSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Extracts heavily obfuscated strings (XOR, Base64, Stack strings) from a binary using FireEye's FLARE-FLOSS. Use this when standard strings_extract misses crucial data or when you suspect the binary is obfuscating its strings at runtime.",
    args: {
        binary_path: tool.schema.string().describe("Absolute path to the binary to analyze"),
        min_length: tool.schema.number().optional().default(4).describe("Minimum string length to extract (default 4)")
    },
    async execute(args, context) {
        return instrumentedCall({ toolName: "floss_extract", args }, async () => {
            if (!existsSync(args.binary_path)) {
                return JSON.stringify({ success: false, error: "Binary not found" })
            }

            console.log(`[*] Running FLARE-FLOSS on ${args.binary_path}... (This can take a minute)`)
            const result = await $`floss -q -n ${args.min_length} ${args.binary_path}`.nothrow()

            const stdout = result.stdout?.toString() || ""
            const stderr = result.stderr?.toString() || ""

            if (result.exitCode !== 0 && !stdout) {
                return JSON.stringify({
                    success: false,
                    error: `FLOSS execution failed.`,
                    details: stderr
                }, null, 2)
            }

            return JSON.stringify({
                success: true,
                output: stdout.trim(),
                stderr: stderr ? stderr.trim() : undefined
            }, null, 2)
        })
    }
})
