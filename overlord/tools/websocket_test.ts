import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test WebSocket endpoints for security vulnerabilities — authentication bypass, message injection (XSS/SQLi/SSTI), origin validation, DoS, and unauthenticated access using WSHawk",
  args: {
    url: tool.schema.string().describe("WebSocket URL (e.g., 'ws://example.com/socket' or 'wss://example.com/chat')"),
    action: tool.schema.enum(["recon", "fuzz", "inject", "auth", "full"]).default("recon").describe("recon=connect and observe, fuzz=send fuzzing payloads, inject=test XSS/SQLi/SSTI, auth=test auth bypass, full=all tests"),
    message: tool.schema.string().optional().describe("Initial message to send on connect (JSON or plain text)"),
    headers: tool.schema.string().optional().describe("Extra headers as JSON (e.g., '{\"Cookie\":\"session=abc\"}')"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds per test"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "websocket_test", args }, async () => {
      const startTime = Date.now()
      try {
        // Build WSHawk command
        const cmdArgs: string[] = [args.url]

        if (args.action === "fuzz" || args.action === "full") cmdArgs.push("--fuzz")
        if (args.action === "inject" || args.action === "full") cmdArgs.push("--inject")
        if (args.action === "auth" || args.action === "full") cmdArgs.push("--auth-bypass")
        if (args.message) cmdArgs.push("--message", args.message)

        if (args.headers) {
          try {
            const hdrs = JSON.parse(args.headers)
            for (const [k, v] of Object.entries(hdrs)) {
              cmdArgs.push("--header", `${k}:${v}`)
            }
          } catch { /* ignore */ }
        }

        const result = await $`wshawk ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Parse findings
        const vulnerabilities = stdout.split("\n")
          .filter(l => l.includes("[VULN]") || l.includes("[!]") || l.includes("VULNERABLE") || l.includes("bypass"))
          .map(l => l.trim())

        const messages = stdout.split("\n")
          .filter(l => l.includes("[RECV]") || l.includes("<<"))
          .map(l => l.trim())

        return JSON.stringify({
          success: true,
          url: args.url,
          action: args.action,
          vulnerable: vulnerabilities.length > 0,
          vulnerabilities,
          messages_received: messages.slice(0, 20),
          raw: stdout.slice(0, 4000),
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
