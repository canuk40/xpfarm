import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Fingerprint a web application's technology stack using WhatWeb",
  args: {
    url: tool.schema.string().describe("Target URL or IP"),
    aggression: tool.schema.number().default(1).describe("Aggression level 1-4 (1=passive, 3=aggressive, 4=heavy). Use 1 for stealthy recon."),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "whatweb_fingerprint", args }, async () => {
      const startTime = Date.now()
      try {
        const result = await $`whatweb --aggression ${args.aggression} --log-json=/tmp/whatweb_out.json ${args.url}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        let findings: any[] = []
        try {
          const outFile = Bun.file("/tmp/whatweb_out.json")
          if (await outFile.exists()) {
            const lines = (await outFile.text()).trim().split("\n")
            for (const line of lines) {
              if (line.trim()) {
                try { findings.push(JSON.parse(line)) } catch { /* skip */ }
              }
            }
            await $`rm -f /tmp/whatweb_out.json`.nothrow()
          }
        } catch { /* use raw output */ }

        const technologies: string[] = []
        for (const f of findings) {
          if (f.plugins) {
            for (const [name, data] of Object.entries(f.plugins as Record<string, any>)) {
              const version = data.version?.[0] || ""
              technologies.push(version ? `${name} ${version}` : name)
            }
          }
        }

        return JSON.stringify({
          success: result.exitCode === 0,
          target: args.url,
          technologies,
          raw: findings.length > 0 ? findings : stdout.slice(0, 3000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
