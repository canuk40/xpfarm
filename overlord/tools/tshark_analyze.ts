import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Analyze packet captures (PCAP/PCAPNG) or capture live traffic using tshark",
  args: {
    source: tool.schema.string().describe("Path to PCAP file, or interface name for live capture (e.g., 'eth0'). Use 'live:<iface>' for live capture."),
    filter: tool.schema.string().optional().describe("Wireshark display filter (e.g., 'http', 'tcp.port==80', 'dns', 'tcp contains password')"),
    fields: tool.schema.string().optional().describe("Comma-separated fields to extract (e.g., 'ip.src,ip.dst,tcp.dstport,http.request.uri'). Summary view if omitted."),
    follow: tool.schema.string().optional().describe("Follow a stream: 'tcp,0' or 'http,0' (stream index). Extracts full conversation."),
    limit: tool.schema.number().default(500).describe("Max packets to analyze"),
    duration: tool.schema.number().default(10).describe("Live capture duration in seconds (only for live capture)"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "tshark_analyze", args }, async () => {
      const startTime = Date.now()
      try {
        const isLive = args.source.startsWith("live:")
        const iface = isLive ? args.source.replace("live:", "") : null
        const pcapPath = isLive ? null : (args.source.startsWith("/") ? args.source : path.join(context.directory, args.source))

        const cmdArgs: string[] = []

        if (isLive && iface) {
          cmdArgs.push("-i", iface, "-a", `duration:${args.duration}`)
        } else if (pcapPath) {
          cmdArgs.push("-r", pcapPath)
        }

        if (args.filter) cmdArgs.push("-Y", args.filter)
        cmdArgs.push("-c", String(args.limit))

        let output = ""

        if (args.follow) {
          // Follow stream mode
          const [protocol, index] = args.follow.split(",")
          const followArgs = [...cmdArgs, "-z", `follow,${protocol},ascii,${index || "0"}`, "-q"]
          const result = await $`tshark ${followArgs}`.nothrow().timeout(args.timeout * 1000)
          output = result.stdout?.toString() || ""
        } else if (args.fields) {
          // Field extraction mode
          const fieldList = args.fields.split(",").map(f => f.trim())
          const fieldArgs = [...cmdArgs, "-T", "fields", "-E", "header=y", "-E", "separator=,"]
          for (const f of fieldList) fieldArgs.push("-e", f)
          const result = await $`tshark ${fieldArgs}`.nothrow().timeout(args.timeout * 1000)
          output = result.stdout?.toString() || ""
        } else {
          // Summary mode
          const result = await $`tshark ${cmdArgs}`.nothrow().timeout(args.timeout * 1000)
          output = result.stdout?.toString() || ""
        }

        // Quick stats
        const packets = output.trim().split("\n").filter(l => l.trim()).length
        const httpLines = output.split("\n").filter(l => l.includes("HTTP") || l.includes("GET ") || l.includes("POST "))
        const credPatterns = [...output.matchAll(/(?:password|passwd|pwd|token|secret|key|auth)[=:]["']?([^\s"'&]+)/gi)].map(m => m[0])

        return JSON.stringify({
          success: true,
          source: args.source,
          filter: args.filter,
          packets_shown: packets,
          output: output.slice(0, 10000),
          truncated: output.length > 10000,
          interesting: {
            http_requests: httpLines.slice(0, 20),
            credentials_found: credPatterns.slice(0, 10),
          },
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
