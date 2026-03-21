import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Mine archived URLs from Wayback Machine, Common Crawl, and other sources using gau and waybackurls to find hidden endpoints and parameters",
  args: {
    domain: tool.schema.string().describe("Target domain or URL (e.g., 'example.com')"),
    providers: tool.schema.enum(["gau", "waybackurls", "both"]).default("both").describe("Which tools to use"),
    include_subs: tool.schema.boolean().default(false).describe("Include subdomains in results"),
    filter_extensions: tool.schema.string().default("png,jpg,gif,css,woff,woff2,ttf,svg,ico").describe("Comma-separated extensions to filter out"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "gau_urls", args }, async () => {
      const startTime = Date.now()
      const allUrls = new Set<string>()

      try {
        if (args.providers === "gau" || args.providers === "both") {
          const gauArgs: string[] = [args.domain, "--o", "/tmp/gau_out.txt"]
          if (args.include_subs) gauArgs.push("--subs")
          if (args.filter_extensions) gauArgs.push("--blacklist", args.filter_extensions)
          await $`gau ${gauArgs}`.nothrow().timeout(args.timeout * 1000)
          try {
            const f = Bun.file("/tmp/gau_out.txt")
            if (await f.exists()) {
              const lines = (await f.text()).trim().split("\n").filter(l => l.trim())
              lines.forEach(l => allUrls.add(l))
              await $`rm -f /tmp/gau_out.txt`.nothrow()
            }
          } catch { /* ignore */ }
        }

        if (args.providers === "waybackurls" || args.providers === "both") {
          const result = await $`waybackurls ${args.domain}`.nothrow().timeout(args.timeout * 1000)
          const lines = result.stdout?.toString().trim().split("\n").filter(l => l.trim()) || []
          lines.forEach(l => allUrls.add(l))
        }

        const urls = [...allUrls]

        // Categorize interesting URLs
        const withParams = urls.filter(u => u.includes("?") && u.includes("="))
        const jsFiles = urls.filter(u => u.endsWith(".js") || u.includes(".js?"))
        const apiEndpoints = urls.filter(u => u.includes("/api/") || u.match(/\/v\d+\//))
        const extensions = new Set(urls.map(u => u.split("?")[0].split(".").pop()?.toLowerCase()).filter(Boolean))

        return JSON.stringify({
          success: urls.length > 0,
          domain: args.domain,
          total: urls.length,
          urls: urls.slice(0, 500),
          with_params: withParams.slice(0, 100),
          js_files: jsFiles.slice(0, 50),
          api_endpoints: apiEndpoints.slice(0, 50),
          extensions: [...extensions],
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
