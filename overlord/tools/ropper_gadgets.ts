import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Find ROP/JOP gadgets in a binary using Ropper for exploit chain construction",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    search: tool.schema.string().optional().describe("Search for specific gadgets (e.g., 'pop rdi', 'ret', 'syscall')"),
    type: tool.schema.enum(["rop", "jop", "all"]).default("rop").describe("Gadget type to find"),
    arch: tool.schema.string().optional().describe("Architecture override (e.g., 'x86', 'x86_64', 'arm', 'arm64')"),
    limit: tool.schema.number().default(50).describe("Max gadgets to return"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)
    return instrumentedCall({ toolName: "ropper_gadgets", binary: binaryPath, args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["--file", binaryPath, "--nocolor"]

        if (args.type !== "all") cmdArgs.push("--type", args.type)
        if (args.arch) cmdArgs.push("--arch", args.arch)
        if (args.search) {
          cmdArgs.push("--search", args.search)
        }

        const result = await $`ropper ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse gadget lines: "0x000000000040101a: pop rdi; ret;"
        const gadgets: Array<{ address: string; gadget: string }> = []
        for (const line of stdout.split("\n")) {
          const match = line.match(/^(0x[0-9a-f]+):\s+(.+)$/i)
          if (match) {
            gadgets.push({ address: match[1], gadget: match[2].trim() })
          }
        }

        const limited = gadgets.slice(0, args.limit)

        return JSON.stringify({
          success: result.exitCode === 0 || gadgets.length > 0,
          binary: binaryPath,
          type: args.type,
          search: args.search,
          gadgets: limited,
          total: gadgets.length,
          omitted: Math.max(0, gadgets.length - args.limit),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
