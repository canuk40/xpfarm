import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Automated XSS detection using Dalfox — tests reflected, stored, and DOM-based XSS",
  args: {
    url: tool.schema.string().describe("Target URL (with parameters for reflected XSS, e.g., 'https://example.com/search?q=test')"),
    mode: tool.schema.enum(["url", "pipe", "file"]).default("url").describe("url=single URL, pipe=stdin list of URLs, file=file of URLs"),
    blind_xss_host: tool.schema.string().optional().describe("Blind XSS callback URL (e.g., your interactsh host)"),
    headers: tool.schema.string().optional().describe("Extra headers as 'Key:Value' (use | to separate multiple)"),
    worker: tool.schema.number().default(100).describe("Number of concurrent workers"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "dalfox_xss", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = [args.mode, args.url, "--silence", "--format", "json", "-o", "/tmp/dalfox_out.json"]
        if (args.blind_xss_host) cmdArgs.push("-b", args.blind_xss_host)
        if (args.worker) cmdArgs.push("--worker", String(args.worker))
        if (args.headers) {
          for (const h of args.headers.split("|")) {
            cmdArgs.push("-H", h.trim())
          }
        }

        const result = await $`dalfox ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""

        let findings: any[] = []
        try {
          const f = Bun.file("/tmp/dalfox_out.json")
          if (await f.exists()) {
            const raw = await f.text()
            // Dalfox outputs JSONL
            for (const line of raw.split("\n")) {
              if (line.trim()) {
                try { findings.push(JSON.parse(line)) } catch { /* skip */ }
              }
            }
            await $`rm -f /tmp/dalfox_out.json`.nothrow()
          }
        } catch { /* use stdout */ }

        // Parse from stdout if no JSON output
        if (findings.length === 0) {
          const vulnLines = stdout.split("\n").filter(l => l.includes("[V]") || l.includes("POC") || l.toLowerCase().includes("xss"))
          if (vulnLines.length) findings = vulnLines.map(l => ({ raw: l.trim() }))
        }

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable: findings.length > 0,
          findings,
          count: findings.length,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
