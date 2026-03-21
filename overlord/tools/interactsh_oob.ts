import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Generate out-of-band interaction URLs for SSRF, blind XSS, XXE, and RCE detection using interactsh-client",
  args: {
    action: tool.schema.enum(["generate", "poll", "listen"]).default("generate").describe("generate=get a unique OOB URL, poll=check for interactions, listen=wait for interactions in real-time"),
    server: tool.schema.string().default("oast.pro").describe("Interactsh server to use"),
    duration: tool.schema.number().default(30).describe("Duration to listen/poll in seconds"),
    token: tool.schema.string().optional().describe("Auth token for private interactsh server"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "interactsh_oob", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["-s", args.server, "-json"]
        if (args.token) cmdArgs.push("-t", args.token)

        if (args.action === "generate") {
          // Run briefly just to get a URL
          cmdArgs.push("-v")
          const result = await $`interactsh-client ${cmdArgs}`.nothrow().timeout(10000)
          const stdout = result.stdout?.toString() || ""
          const stderr = result.stderr?.toString() || ""

          const urlMatch = stdout.match(/([a-z0-9]+\.[a-z0-9.]+\.[a-z]+)/i) || stderr.match(/([a-z0-9]+\.[a-z0-9.]+\.[a-z]+)/i)
          const interactUrl = urlMatch ? urlMatch[1] : null

          return JSON.stringify({
            success: !!interactUrl,
            action: "generate",
            interaction_url: interactUrl,
            usage: interactUrl ? `Use ${interactUrl} as your OOB callback in SSRF/XSS/XXE payloads. Then poll with action=poll.` : "Failed to generate URL",
            duration: Date.now() - startTime,
          }, null, 2)
        }

        // Listen/poll mode
        const result = await $`interactsh-client ${cmdArgs}`.nothrow().timeout(args.duration * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""

        const interactions: any[] = []
        for (const line of stdout.split("\n")) {
          if (line.trim()) {
            try { interactions.push(JSON.parse(line)) } catch { /* non-JSON line */ }
          }
        }

        return JSON.stringify({
          success: true,
          action: args.action,
          interactions,
          count: interactions.length,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
