import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Mine URL parameters from Wayback Machine and web crawls using ParamSpider",
  args: {
    domain: tool.schema.string().describe("Target domain (e.g., 'example.com')"),
    exclude: tool.schema.string().default("jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt,js").describe("Extensions to exclude"),
    quiet: tool.schema.boolean().default(true).describe("Suppress banner and noise"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "paramspider_mine", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["--domain", args.domain, "--exclude", args.exclude, "--output", "/tmp/paramspider_out.txt"]
        if (args.quiet) cmdArgs.push("--quiet")

        const result = await $`paramspider ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)

        let urls: string[] = []
        try {
          // ParamSpider writes to results/<domain>.txt
          const outPaths = [`/tmp/paramspider_out.txt`, `results/${args.domain}.txt`]
          for (const p of outPaths) {
            const f = Bun.file(p)
            if (await f.exists()) {
              urls = (await f.text()).trim().split("\n").filter(l => l.trim() && l.includes("="))
              break
            }
          }
        } catch { /* use stdout */ }

        if (urls.length === 0) {
          urls = result.stdout?.toString().trim().split("\n").filter(l => l.includes("=")) || []
        }

        // Extract unique parameter names
        const params = new Set<string>()
        for (const url of urls) {
          try {
            const u = new URL(url.includes("://") ? url : "http://" + url)
            u.searchParams.forEach((_, k) => params.add(k))
          } catch { /* skip */ }
        }

        return JSON.stringify({
          success: urls.length > 0,
          domain: args.domain,
          total_urls: urls.length,
          urls: urls.slice(0, 200),
          unique_params: [...params],
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
