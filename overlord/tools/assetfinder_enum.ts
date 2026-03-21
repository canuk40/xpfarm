import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Fast subdomain and asset discovery using assetfinder — finds subdomains and related domains",
  args: {
    domain: tool.schema.string().describe("Target domain (e.g., 'example.com')"),
    subs_only: tool.schema.boolean().default(true).describe("Only return subdomains of the given domain (filter out related domains)"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "assetfinder_enum", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = [args.subs_only ? "--subs-only" : "", args.domain].filter(Boolean)
        const result = await $`assetfinder ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""

        const subdomains = stdout.trim().split("\n").filter(l => l.trim() && !l.startsWith("*"))

        return JSON.stringify({
          success: subdomains.length > 0,
          domain: args.domain,
          subdomains,
          count: subdomains.length,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
