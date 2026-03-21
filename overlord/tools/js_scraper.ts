import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Extract secrets, API endpoints, GraphQL queries, WebSocket URLs, and hardcoded credentials from JavaScript files using JSScalper",
  args: {
    target: tool.schema.string().describe("URL of a JS file, webpage (auto-discovers JS files), or domain to scrape all JS from"),
    mode: tool.schema.enum(["url", "domain"]).default("url").describe("url=single JS file or page, domain=crawl all JS on the domain"),
    output_dir: tool.schema.string().default("/workspace/output/js_scraper").describe("Directory to save extracted data"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "js_scraper", args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_dir}`.nothrow()

        const cmdArgs: string[] = ["-u", args.target, "-o", args.output_dir]
        if (args.mode === "domain") cmdArgs.push("--crawl")

        const result = await $`python3 /opt/JSScalper/main.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Collect output files
        const lsResult = await $`find ${args.output_dir} -type f -newer /tmp`.nothrow()
        const outFiles = lsResult.stdout?.toString().trim().split("\n").filter(l => l.trim()) || []

        // Parse categories from stdout
        const endpoints = stdout.split("\n").filter(l => l.match(/https?:\/\/|\/api\/|\/v[0-9]/i)).map(l => l.trim())
        const secrets = stdout.split("\n").filter(l => l.match(/key|token|secret|password|api_key|bearer/i)).map(l => l.trim())
        const graphql = stdout.split("\n").filter(l => l.match(/query|mutation|graphql|gql/i)).map(l => l.trim())
        const websockets = stdout.split("\n").filter(l => l.match(/wss?:\/\//i)).map(l => l.trim())

        return JSON.stringify({
          success: true,
          target: args.target,
          endpoints: [...new Set(endpoints)].slice(0, 100),
          potential_secrets: [...new Set(secrets)].slice(0, 50),
          graphql_queries: [...new Set(graphql)].slice(0, 20),
          websocket_urls: [...new Set(websockets)],
          output_files: outFiles,
          raw_output: stdout.slice(0, 3000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
