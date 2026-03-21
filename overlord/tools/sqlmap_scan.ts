import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test a URL or request for SQL injection vulnerabilities using sqlmap",
  args: {
    url: tool.schema.string().describe("Target URL (e.g., https://example.com/item?id=1)"),
    data: tool.schema.string().optional().describe("POST data body (e.g., 'user=admin&pass=test')"),
    param: tool.schema.string().optional().describe("Specific parameter to test (e.g., 'id'). Tests all by default."),
    level: tool.schema.number().default(1).describe("Test level 1-5 (higher = more tests, slower)"),
    risk: tool.schema.number().default(1).describe("Risk level 1-3 (higher = more aggressive payloads)"),
    dbms: tool.schema.string().optional().describe("Force backend DBMS (e.g., 'mysql', 'postgres', 'mssql')"),
    dump: tool.schema.boolean().default(false).describe("Attempt to dump database tables if vulnerable"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "sqlmap_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-u", args.url, "--level", String(args.level), "--risk", String(args.risk), "--batch", "--output-dir", "/tmp/sqlmap_out", "--forms"]

        if (args.data) cmdArgs.push("--data", args.data)
        if (args.param) cmdArgs.push("-p", args.param)
        if (args.dbms) cmdArgs.push("--dbms", args.dbms)
        if (args.dump) cmdArgs.push("--dump")

        const result = await $`sqlmap ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""

        const vulnerable = stdout.includes("is vulnerable") || stdout.includes("sqlmap identified")
        const injectionTypes: string[] = []
        for (const line of stdout.split("\n")) {
          if (line.includes("Type:")) injectionTypes.push(line.trim())
        }

        // Parse identified injections
        const paramMatches = [...stdout.matchAll(/Parameter: (\S+) \((\w+)\)/g)]
        const params = paramMatches.map(m => ({ parameter: m[1], type: m[2] }))

        return JSON.stringify({
          success: true,
          target: args.url,
          vulnerable,
          params,
          injection_types: injectionTypes,
          summary: stdout.slice(0, 3000),
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
