import { tool } from "@opencode-ai/plugin"
import { runCommand, getOrCreateSession, markAsAnalyzed, isAnalyzed } from "./lib/r2session"
import { extractJSON } from "./lib/json_utils"
import { instrumentedCall } from "./lib/tool_instrument"
import { toolLogger } from "./lib/logger"
import path from "path"

export default tool({
  description: "Find cross-references to/from addresses in binary",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    address: tool.schema.string().describe("Address to query (e.g., '0x14000203c', 'main', 'str.Hello_World')"),
    direction: tool.schema.enum(["to", "from", "both"]).default("both").describe("Find refs to, from, or both"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "r2xref", binary: binaryPath, args }, async () => {
    const startTime = Date.now()
    const timeoutMs = args.timeout * 1000

    try {
      // Ensure session exists and is analyzed
      const session = await getOrCreateSession(binaryPath)
      if (!isAnalyzed(binaryPath)) {
        // Only run basic analysis for xrefs, not full deep analysis
        await runCommand(binaryPath, "aa", timeoutMs)
        markAsAnalyzed(binaryPath)
      }
      
      const results: {
        to: any[]
        from: any[]
      } = { to: [], from: [] }
      
      if (args.direction === "to" || args.direction === "both") {
        // xrefs TO this address (who references it)
        try {
          const output = await runCommand(binaryPath, `axtj @ ${args.address}`, timeoutMs / 2)
          results.to = JSON.parse(extractJSON(output))
        } catch (e) {
          results.to = []
        }
      }
      
      if (args.direction === "from" || args.direction === "both") {
        // xrefs FROM this address (what it references)
        try {
          const output = await runCommand(binaryPath, `axfj @ ${args.address}`, timeoutMs / 2)
          results.from = JSON.parse(extractJSON(output))
        } catch (e) {
          results.from = []
        }
      }
      
      const duration = Date.now() - startTime

      if (results.to.length === 0 && results.from.length === 0) {
        toolLogger.warn(`r2xref: No cross-references found for "${args.address}" (direction: ${args.direction})`, {
          tool: "r2xref", binary: binaryPath,
        })
      }

      // Limit results to prevent context window overflow
      const maxResults = 50
      
      return JSON.stringify({
        success: true,
        binary: binaryPath,
        query: {
          address: args.address,
          direction: args.direction
        },
        duration: duration,
        results: {
          to: results.to.slice(0, maxResults),
          from: results.from.slice(0, maxResults),
          _totalTo: results.to.length,
          _totalFrom: results.from.length
        },
        summary: {
          totalRefsTo: results.to.length,
          totalRefsFrom: results.from.length,
          displayedTo: Math.min(results.to.length, maxResults),
          displayedFrom: Math.min(results.from.length, maxResults),
          topCallers: results.to.slice(0, 5).map((x: any) => x.from || x.name),
          topCallees: results.from.slice(0, 5).map((x: any) => x.to || x.name)
        }
      }, null, 2)
      
    } catch (error: any) {
      return JSON.stringify({
        success: false,
        binary: binaryPath,
        query: { address: args.address, direction: args.direction },
        error: error.message || String(error),
        duration: Date.now() - startTime
      }, null, 2)
    }
    }) // instrumentedCall
  }
})

