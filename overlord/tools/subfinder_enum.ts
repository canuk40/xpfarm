import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Fast passive subdomain enumeration from 60+ sources using Subfinder",
  args: {
    domain: tool.schema.string().describe("Target domain (e.g., 'example.com')"),
    all_sources: tool.schema.boolean().default(false).describe("Use all sources including slow ones"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "subfinder_enum", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-d", args.domain, "-silent", "-o", "/tmp/subfinder_out.txt"]
        if (args.all_sources) cmdArgs.push("-all")

        const result = await $`subfinder ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)

        let subdomains: string[] = []
        try {
          const outFile = Bun.file("/tmp/subfinder_out.txt")
          if (await outFile.exists()) {
            subdomains = (await outFile.text()).trim().split("\n").filter(l => l.trim())
            await $`rm -f /tmp/subfinder_out.txt`.nothrow()
          }
        } catch { subdomains = result.stdout?.toString().trim().split("\n").filter(l => l.trim()) || [] }

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
