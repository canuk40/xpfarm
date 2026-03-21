import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Probe HTTP/HTTPS targets with httpx — detect live hosts, fingerprint technologies, grab titles, status codes, and response data",
  args: {
    targets: tool.schema.string().describe("Single URL, comma-separated URLs, or path to a file containing URLs (one per line)"),
    tech_detect: tool.schema.boolean().default(true).describe("Detect web technologies"),
    follow_redirects: tool.schema.boolean().default(true).describe("Follow HTTP redirects"),
    status_code: tool.schema.boolean().default(true).describe("Include HTTP status codes"),
    title: tool.schema.boolean().default(true).describe("Extract page titles"),
    content_length: tool.schema.boolean().default(true).describe("Include content length"),
    screenshot: tool.schema.boolean().default(false).describe("Take screenshots (requires headless browser)"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "httpx_probe", args }, async () => {
      const startTime = Date.now()
      try {
        // Determine if targets is a file or inline list
        let targetArg: string[]
        if (fs.existsSync(args.targets)) {
          targetArg = ["-l", args.targets]
        } else if (args.targets.includes(",")) {
          const tmpFile = "/tmp/httpx_targets.txt"
          fs.writeFileSync(tmpFile, args.targets.split(",").map(t => t.trim()).join("\n"))
          targetArg = ["-l", tmpFile]
        } else {
          targetArg = ["-u", args.targets]
        }

        const cmdArgs: string[] = [...targetArg, "-silent", "-json", "-o", "/tmp/httpx_out.jsonl", "-timeout", "10"]

        if (args.tech_detect) cmdArgs.push("-tech-detect")
        if (args.follow_redirects) cmdArgs.push("-follow-redirects")
        if (args.status_code) cmdArgs.push("-status-code")
        if (args.title) cmdArgs.push("-title")
        if (args.content_length) cmdArgs.push("-content-length")
        if (args.screenshot) cmdArgs.push("-screenshot")

        const result = await $`httpx ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stderr = result.stderr?.toString() || ""

        const results: any[] = []
        try {
          const outFile = Bun.file("/tmp/httpx_out.jsonl")
          if (await outFile.exists()) {
            const lines = (await outFile.text()).trim().split("\n")
            for (const line of lines) {
              if (!line.trim()) continue
              try {
                const obj = JSON.parse(line)
                results.push({
                  url: obj.url,
                  status: obj.status_code,
                  title: obj.title,
                  tech: obj.tech,
                  length: obj.content_length,
                  redirect: obj.final_url !== obj.url ? obj.final_url : undefined,
                })
              } catch { /* skip */ }
            }
            await $`rm -f /tmp/httpx_out.jsonl`.nothrow()
          }
        } catch { /* fall back to raw */ }

        return JSON.stringify({
          success: result.exitCode === 0 || results.length > 0,
          targets: args.targets,
          results,
          live: results.filter(r => r.status >= 200 && r.status < 400).length,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
