import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Network reconnaissance using nmap — port scanning, service/version detection, OS fingerprinting, and script scanning",
  args: {
    target: tool.schema.string().describe("Target IP, hostname, CIDR range, or file of targets (e.g., '192.168.1.0/24', 'example.com', '/tmp/targets.txt')"),
    scan_type: tool.schema.enum(["quick", "full", "service", "os", "vuln", "stealth", "udp", "custom"]).default("service").describe("quick=top 1000 ports, full=all 65535, service=version detection, os=OS detect, vuln=vuln scripts, stealth=SYN scan, udp=UDP scan"),
    ports: tool.schema.string().optional().describe("Port specification (e.g., '80,443,8080', '1-1000', '-'). Overrides scan_type port selection."),
    scripts: tool.schema.string().optional().describe("NSE scripts to run (e.g., 'http-headers,ssl-cert', 'vuln', 'default'). Used with scan_type=custom."),
    timing: tool.schema.number().default(4).describe("Timing template 0-5 (0=paranoid, 3=normal, 4=aggressive, 5=insane)"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "nmap_scan", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-oX", "/tmp/nmap_out.xml", `-T${args.timing}`]

        switch (args.scan_type) {
          case "quick":    cmdArgs.push("-F"); break
          case "full":     cmdArgs.push("-p-"); break
          case "service":  cmdArgs.push("-sV", "-sC"); break
          case "os":       cmdArgs.push("-O", "-sV"); break
          case "vuln":     cmdArgs.push("-sV", "--script", "vuln"); break
          case "stealth":  cmdArgs.push("-sS"); break
          case "udp":      cmdArgs.push("-sU", "--top-ports", "200"); break
          case "custom":
            if (args.scripts) cmdArgs.push("--script", args.scripts)
            break
        }

        if (args.ports) cmdArgs.push("-p", args.ports)
        cmdArgs.push(args.target)

        const result = await $`nmap ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse XML output for structured results
        let hosts: any[] = []
        try {
          const xmlFile = Bun.file("/tmp/nmap_out.xml")
          if (await xmlFile.exists()) {
            const xml = await xmlFile.text()
            // Simple regex-based XML parse for key fields
            const hostBlocks = [...xml.matchAll(/<host[\s>]([\s\S]*?)<\/host>/g)]
            for (const block of hostBlocks) {
              const content = block[1]
              const addrMatch = content.match(/addr="([^"]+)"/)
              const stateMatch = content.match(/state="([^"]+)"/)
              const hostnameMatch = content.match(/hostname name="([^"]+)"/)

              const ports: any[] = []
              for (const portMatch of content.matchAll(/<port protocol="([^"]+)" portid="(\d+)"[\s\S]*?<state state="([^"]+)"[\s\S]*?(?:<service name="([^"]*)"[^/]*(?:product="([^"]*)")?[^/]*(?:version="([^"]*)")?)?/g)) {
                if (portMatch[3] === "open") {
                  ports.push({
                    port: `${portMatch[2]}/${portMatch[1]}`,
                    state: portMatch[3],
                    service: portMatch[4] || "unknown",
                    version: [portMatch[5], portMatch[6]].filter(Boolean).join(" ") || undefined,
                  })
                }
              }

              if (addrMatch) {
                hosts.push({
                  ip: addrMatch[1],
                  hostname: hostnameMatch?.[1],
                  state: stateMatch?.[1] || "up",
                  open_ports: ports,
                })
              }
            }
            await $`rm -f /tmp/nmap_out.xml`.nothrow()
          }
        } catch { /* fall back to raw */ }

        return JSON.stringify({
          success: result.exitCode === 0,
          target: args.target,
          scan_type: args.scan_type,
          hosts,
          hosts_up: hosts.filter(h => h.state === "up").length,
          raw: hosts.length === 0 ? stdout.slice(0, 5000) : undefined,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
