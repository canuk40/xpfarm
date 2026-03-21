import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test web applications for command injection vulnerabilities using Commix",
  args: {
    url: tool.schema.string().describe("Target URL with parameter (e.g., 'https://example.com/ping?host=127.0.0.1')"),
    data: tool.schema.string().optional().describe("POST data (e.g., 'ip=127.0.0.1&submit=ping')"),
    param: tool.schema.string().optional().describe("Specific parameter to test. Tests all if omitted."),
    technique: tool.schema.enum(["classic", "time", "file", "all"]).default("all").describe("Injection technique to use"),
    os: tool.schema.enum(["unix", "windows", "auto"]).default("auto").describe("Target OS"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "commix_inject", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["--url", args.url, "--batch", "--output-dir", "/tmp/commix_out", "--quiet"]

        if (args.data) cmdArgs.push("--data", args.data)
        if (args.param) cmdArgs.push("--param", args.param)
        if (args.technique !== "all") cmdArgs.push("--technique", args.technique.toUpperCase()[0])
        if (args.os !== "auto") cmdArgs.push("--os", args.os)

        const result = await $`commix ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        const vulnerable = stdout.toLowerCase().includes("vulnerable") || stdout.includes("[+]") || stdout.includes("command injection")
        const payloads = [...stdout.matchAll(/\[\+\]\s+(.+)/g)].map(m => m[1].trim())

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable,
          payloads,
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
