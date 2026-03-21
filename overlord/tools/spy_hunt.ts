import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Multi-vulnerability scanner using SpyHunt — tests for XXE, SSRF, SSTI, NoSQL injection, CRLF injection, open redirects, and runs Nuclei on discovered endpoints",
  args: {
    target: tool.schema.string().describe("Target URL or domain (e.g., 'https://example.com')"),
    scan_type: tool.schema.enum(["xxe", "ssrf", "ssti", "nosqli", "crlf", "redirect", "full"]).default("full").describe("Vulnerability type to test, or 'full' for all"),
    output_dir: tool.schema.string().default("/workspace/output/spyhunt").describe("Output directory"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "spy_hunt", args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_dir}`.nothrow()

        const cmdArgs: string[] = ["-u", args.target, "-o", args.output_dir]

        if (args.scan_type !== "full") {
          cmdArgs.push(`--${args.scan_type}`)
        } else {
          cmdArgs.push("--all")
        }

        const result = await $`spyhunt ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse by vulnerability type
        const findings: Record<string, string[]> = {
          xxe: [], ssrf: [], ssti: [], nosqli: [], crlf: [], redirect: [], other: [],
        }

        for (const line of stdout.split("\n")) {
          const l = line.trim()
          if (!l) continue
          if (l.match(/xxe/i)) findings.xxe.push(l)
          else if (l.match(/ssrf/i)) findings.ssrf.push(l)
          else if (l.match(/ssti|template/i)) findings.ssti.push(l)
          else if (l.match(/nosql|mongo/i)) findings.nosqli.push(l)
          else if (l.match(/crlf|header injection/i)) findings.crlf.push(l)
          else if (l.match(/redirect|open redirect/i)) findings.redirect.push(l)
          else if (l.includes("[+]") || l.includes("VULN") || l.includes("found")) findings.other.push(l)
        }

        const totalFindings = Object.values(findings).flat().length

        return JSON.stringify({
          success: true,
          target: args.target,
          scan_type: args.scan_type,
          total_findings: totalFindings,
          findings,
          output_dir: args.output_dir,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
