import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Crawl a web application with Katana to discover endpoints, forms, JavaScript sources, and API paths",
  args: {
    url: tool.schema.string().describe("Target URL to crawl"),
    depth: tool.schema.number().default(3).describe("Crawl depth"),
    concurrency: tool.schema.number().default(10).describe("Concurrent crawlers"),
    js_crawl: tool.schema.boolean().default(true).describe("Parse JavaScript files for additional endpoints"),
    form_extract: tool.schema.boolean().default(true).describe("Extract form fields and actions"),
    scope: tool.schema.string().optional().describe("Limit crawl to this domain scope (regex, e.g., 'example\\.com')"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "katana_crawl", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "-d", String(args.depth), "-c", String(args.concurrency), "-silent", "-jsonl", "-o", "/tmp/katana_out.jsonl"]

        if (args.js_crawl) cmdArgs.push("-jc")
        if (args.form_extract) cmdArgs.push("-kf", "all")
        if (args.scope) cmdArgs.push("-fs", `rdn:${args.scope}`)

        const result = await $`katana ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stderr = result.stderr?.toString() || ""

        const endpoints: any[] = []
        try {
          const outFile = Bun.file("/tmp/katana_out.jsonl")
          if (await outFile.exists()) {
            const lines = (await outFile.text()).trim().split("\n")
            for (const line of lines) {
              if (!line.trim()) continue
              try {
                const obj = JSON.parse(line)
                endpoints.push({
                  url: obj.request?.endpoint || obj.endpoint,
                  method: obj.request?.method,
                  source: obj.request?.source,
                })
              } catch { /* skip */ }
            }
            await $`rm -f /tmp/katana_out.jsonl`.nothrow()
          }
        } catch { /* use raw */ }

        // Categorize findings
        const apiEndpoints = endpoints.filter(e => e.url?.includes("/api/") || e.url?.match(/\/v\d+\//))
        const jsFiles = endpoints.filter(e => e.url?.endsWith(".js"))
        const forms = endpoints.filter(e => e.source === "form")

        return JSON.stringify({
          success: result.exitCode === 0 || endpoints.length > 0,
          target: args.url,
          total: endpoints.length,
          endpoints: endpoints.slice(0, 200),
          api_endpoints: apiEndpoints.slice(0, 50),
          js_files: jsFiles.map(e => e.url).slice(0, 50),
          forms: forms.slice(0, 30),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
