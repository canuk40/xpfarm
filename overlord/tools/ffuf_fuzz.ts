import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Fuzz web endpoints with ffuf — use FUZZ keyword in URL, headers, or POST body",
  args: {
    url: tool.schema.string().describe("Target URL with FUZZ keyword (e.g., https://example.com/FUZZ or https://example.com/api?id=FUZZ)"),
    wordlist: tool.schema.string().default("/workspace/wordlists/common.txt").describe("Path to wordlist file"),
    method: tool.schema.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).default("GET").describe("HTTP method"),
    data: tool.schema.string().optional().describe("POST body data (use FUZZ keyword for fuzzing, e.g., 'username=admin&password=FUZZ')"),
    headers: tool.schema.string().optional().describe("Extra headers as JSON object string (e.g., '{\"Authorization\":\"Bearer token\"}')"),
    filter_status: tool.schema.string().optional().describe("Filter response codes (e.g., '404,403')"),
    match_status: tool.schema.string().optional().describe("Match only these response codes (e.g., '200,301')"),
    threads: tool.schema.number().default(40).describe("Number of concurrent threads"),
    timeout: tool.schema.number().default(180).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "ffuf_fuzz", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "-w", args.wordlist, "-t", String(args.threads), "-o", "/tmp/ffuf_out.json", "-of", "json", "-s"]

        if (args.method !== "GET") {
          cmdArgs.push("-X", args.method)
        }
        if (args.data) {
          cmdArgs.push("-d", args.data)
        }
        if (args.filter_status) {
          cmdArgs.push("-fc", args.filter_status)
        }
        if (args.match_status) {
          cmdArgs.push("-mc", args.match_status)
        }
        if (args.headers) {
          try {
            const hdrs = JSON.parse(args.headers)
            for (const [k, v] of Object.entries(hdrs)) {
              cmdArgs.push("-H", `${k}: ${v}`)
            }
          } catch { /* ignore malformed headers */ }
        }

        const result = await $`ffuf ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)

        let findings: any[] = []
        try {
          const outFile = Bun.file("/tmp/ffuf_out.json")
          if (await outFile.exists()) {
            const data = JSON.parse(await outFile.text())
            findings = (data.results || []).map((r: any) => ({
              input: r.input?.FUZZ,
              url: r.url,
              status: r.status,
              length: r.length,
              words: r.words,
              lines: r.lines,
            }))
            await $`rm -f /tmp/ffuf_out.json`.nothrow()
          }
        } catch { /* ignore */ }

        return JSON.stringify({
          success: result.exitCode === 0 || findings.length > 0,
          target: args.url,
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
