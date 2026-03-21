import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test GraphQL endpoints for introspection, authorization flaws, and injection using InQL",
  args: {
    url: tool.schema.string().describe("GraphQL endpoint URL (e.g., 'https://example.com/graphql')"),
    action: tool.schema.enum(["introspect", "scan", "dump"]).default("introspect").describe("introspect=fetch schema, scan=security checks, dump=generate all queries"),
    headers: tool.schema.string().optional().describe("Extra headers as JSON object string (e.g., '{\"Authorization\":\"Bearer token\"}')"),
    output_dir: tool.schema.string().default("/workspace/output/graphql").describe("Output directory for schema/queries"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "inql_graphql", args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_dir}`.nothrow()

        const cmdArgs: string[] = ["-t", args.url, "-o", args.output_dir]

        if (args.headers) {
          try {
            const hdrs = JSON.parse(args.headers)
            for (const [k, v] of Object.entries(hdrs)) {
              cmdArgs.push("--header", `${k}:${v}`)
            }
          } catch { /* ignore */ }
        }

        const result = await $`inql ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // List generated files
        const lsResult = await $`find ${args.output_dir} -type f`.nothrow()
        const generatedFiles = lsResult.stdout?.toString().trim().split("\n").filter(l => l.trim()) || []

        // Read schema if dumped
        let schema = ""
        const schemaFile = generatedFiles.find(f => f.endsWith(".graphql") || f.endsWith("schema.json"))
        if (schemaFile) {
          try {
            const f = Bun.file(schemaFile)
            schema = (await f.text()).slice(0, 5000)
          } catch { /* ignore */ }
        }

        return JSON.stringify({
          success: result.exitCode === 0 || generatedFiles.length > 0,
          target: args.url,
          action: args.action,
          output_dir: args.output_dir,
          generated_files: generatedFiles,
          schema_preview: schema || undefined,
          stdout: stdout.slice(0, 2000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
