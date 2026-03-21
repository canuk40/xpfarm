import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test endpoints for Server-Side Request Forgery (SSRF) vulnerabilities using SSRFmap",
  args: {
    url: tool.schema.string().describe("Target URL to test (e.g., 'https://example.com/fetch?url=')"),
    data: tool.schema.string().optional().describe("POST data (use 'url=SSRF_HERE' format for parameter injection)"),
    param: tool.schema.string().optional().describe("Parameter name to inject into (e.g., 'url', 'path', 'redirect')"),
    module: tool.schema.enum(["all", "axfr", "portscan", "networkscan", "readfiles", "alibaba", "aws", "gcp", "azure"]).default("all").describe("SSRF module to run"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "ssrfmap_test", args }, async () => {
      const startTime = Date.now()
      try {
        // Write request file for SSRFmap
        const reqFile = "/tmp/ssrfmap_request.txt"
        const method = args.data ? "POST" : "GET"
        const parsedUrl = new URL(args.url)
        const reqContent = `${method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\nHost: ${parsedUrl.host}\n\n${args.data || ""}`
        fs.writeFileSync(reqFile, reqContent)

        const cmdArgs: string[] = ["-r", reqFile]
        if (args.param) cmdArgs.push("-p", args.param)
        if (args.module !== "all") cmdArgs.push("-m", args.module)

        const result = await $`python3 /opt/SSRFmap/ssrfmap.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        const vulnerable = stdout.toLowerCase().includes("vulnerable") || stdout.includes("[+]") || stdout.includes("ssrf")
        const findings = [...stdout.matchAll(/\[\+\]\s+(.+)/g)].map(m => m[1].trim())

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable,
          findings,
          output: stdout.slice(0, 3000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
