import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Discover hidden GET/POST parameters on web endpoints using Arjun",
  args: {
    url: tool.schema.string().describe("Target URL (e.g., 'https://example.com/api/user')"),
    method: tool.schema.enum(["GET", "POST", "JSON", "XML"]).default("GET").describe("HTTP method to use for testing"),
    wordlist: tool.schema.string().optional().describe("Custom wordlist path. Uses built-in list if omitted."),
    rate: tool.schema.number().default(9999).describe("Requests per second"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "arjun_params", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "-m", args.method, "--rate-limit", String(args.rate), "-oJ", "/tmp/arjun_out.json", "-q"]
        if (args.wordlist) cmdArgs.push("-w", args.wordlist)

        const result = await $`arjun ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""

        let parameters: string[] = []
        try {
          const f = Bun.file("/tmp/arjun_out.json")
          if (await f.exists()) {
            const parsed = JSON.parse(await f.text())
            // arjun JSON: { "url": { "params": [...] } }
            for (const data of Object.values(parsed) as any[]) {
              if (data.params) parameters.push(...data.params)
            }
            await $`rm -f /tmp/arjun_out.json`.nothrow()
          }
        } catch { /* parse from stdout */ }

        if (parameters.length === 0) {
          const matches = [...stdout.matchAll(/\[(\w+)\]/g)].map(m => m[1])
          parameters = matches
        }

        return JSON.stringify({
          success: true,
          url: args.url,
          method: args.method,
          parameters,
          count: parameters.length,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
