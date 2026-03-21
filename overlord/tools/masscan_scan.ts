import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Ultra-fast port scanning using Masscan — 100x faster than nmap, ideal for full 65535 port sweeps across large ranges",
  args: {
    target: tool.schema.string().describe("Target IP, range, or CIDR (e.g., '10.0.0.1', '10.0.0.0/24', '192.168.1.1-192.168.1.254')"),
    ports: tool.schema.string().default("0-65535").describe("Port range to scan (e.g., '80,443,8080', '1-1000', '0-65535')"),
    rate: tool.schema.number().default(1000).describe("Packets per second (1000=safe, 10000=fast, 100000=very fast/noisy)"),
    timeout: tool.schema.number().default(180).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "masscan_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const outFile = "/tmp/masscan_out.json"
        const result = await $`masscan ${args.target} -p ${args.ports} --rate ${args.rate} -oJ ${outFile} --wait 3`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stderr = result.stderr?.toString() || ""

        let findings: any[] = []
        try {
          const f = Bun.file(outFile)
          if (await f.exists()) {
            const raw = await f.text()
            // masscan JSON is a list of objects
            const parsed = JSON.parse("[" + raw.replace(/,\s*$/, "") + "]").filter((o: any) => o.ip)
            findings = parsed.map((o: any) => ({
              ip: o.ip,
              port: o.ports?.[0]?.port,
              proto: o.ports?.[0]?.proto,
              status: o.ports?.[0]?.status,
            }))
            await $`rm -f ${outFile}`.nothrow()
          }
        } catch { /* fall through */ }

        // Group by IP
        const byIp: Record<string, number[]> = {}
        for (const f of findings) {
          if (!byIp[f.ip]) byIp[f.ip] = []
          if (f.port) byIp[f.ip].push(f.port)
        }

        return JSON.stringify({
          success: findings.length > 0 || result.exitCode === 0,
          target: args.target,
          open_ports: findings,
          by_ip: byIp,
          total_open: findings.length,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), hint: "masscan requires root/cap_net_raw. Run inside Docker with SYS_PTRACE or as root.", duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
