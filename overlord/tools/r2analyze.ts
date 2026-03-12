import { tool } from "@opencode-ai/plugin"
import { runCommand, getOrCreateSession, markAsAnalyzed, isAnalyzed, unmarkAnalyzed } from "./lib/r2session"
import { extractJSON } from "./lib/json_utils"
import { instrumentedCall } from "./lib/tool_instrument"
import { toolLogger } from "./lib/logger"
import path from "path"

export default tool({
  description: "Analyze a binary using radare2 with persistent sessions and structured output",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    analysis: tool.schema.enum(["basic", "deep", "functions", "strings", "imports", "exports", "sections", "entry", "info"]).default("basic").describe("Type of analysis to perform"),
    command: tool.schema.string().optional().describe("Custom radare2 command (optional)"),
    arch: tool.schema.string().optional().describe("Architecture (e.g., x86, arm, mips)"),
    bits: tool.schema.number().optional().describe("Bits (32 or 64)"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds (default: 60, use 0 for no timeout)"),
    limit: tool.schema.number().default(50).describe("Max results to return for array outputs"),
    sortBy: tool.schema.enum(["size", "name", "address"]).default("size").describe("Sort order for array results"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "r2analyze", binary: binaryPath, args }, async () => {
    const startTime = Date.now()

    try {
      // Get or create session
      const session = await getOrCreateSession(binaryPath)
      
      // Set arch/bits if specified — invalidates previous analysis
      if (args.arch || args.bits) {
        if (args.arch) {
          await runCommand(binaryPath, `e asm.arch=${args.arch}`, 5000)
        }
        if (args.bits) {
          await runCommand(binaryPath, `e asm.bits=${args.bits}`, 5000)
        }
        // Arch change invalidates previous analysis — force re-analysis
        if (isAnalyzed(binaryPath)) {
          unmarkAnalyzed(binaryPath)
          toolLogger.info(`Arch/bits changed for ${binaryPath}, forcing re-analysis`)
          await runCommand(binaryPath, "aaa", 120000)
          markAsAnalyzed(binaryPath)
        }
      }

      // Address validation: check if target address is within a valid section
      if (args.command && /@ 0x[0-9a-f]+/i.test(args.command)) {
        const addrMatch = args.command.match(/@ (0x[0-9a-f]+)/i)
        if (addrMatch) {
          try {
            const sectionsOutput = await runCommand(binaryPath, "iSj", 5000)
            const sections = JSON.parse(extractJSON(sectionsOutput))
            const addr = parseInt(addrMatch[1], 16)
            const inSection = sections.some((s: any) =>
              addr >= (s.vaddr || 0) && addr < (s.vaddr || 0) + (s.vsize || s.size || 0)
            )
            if (!inSection) {
              return JSON.stringify({
                success: false,
                error: `Address ${addrMatch[1]} (decimal: ${addr}) is outside all known sections. Valid sections: ${sections.map((s: any) => `${s.name}: 0x${(s.vaddr || 0).toString(16)}-0x${((s.vaddr || 0) + (s.vsize || s.size || 0)).toString(16)}`).join(", ")}`,
                hint: "Addresses in r2 JSON output are DECIMAL. For example, 1512 decimal = 0x5e8 hex. Did you convert correctly?",
                binary: binaryPath,
              }, null, 2)
            }
          } catch (e: any) {
            toolLogger.warn(`Address validation failed (non-fatal): ${e.message}`)
            // Non-fatal: proceed with the command even if validation fails
          }
        }
      }

      let r2Cmd: string
      let analysisType = args.analysis
      const timeoutMs = args.timeout > 0 ? args.timeout * 1000 : 300000 // Max 5 min if 0
      
      if (args.command) {
        r2Cmd = args.command
      } else {
        switch (args.analysis) {
          case "deep":
            r2Cmd = "aaaa;aflj;iij;iEj;izzj"
            break
          case "functions":
            r2Cmd = "aflj"
            break
          case "strings":
            r2Cmd = "izzj"
            break
          case "imports":
            r2Cmd = "iij"
            break
          case "exports":
            r2Cmd = "iEj"
            break
          case "sections":
            r2Cmd = "iSj"
            break
          case "entry":
            r2Cmd = "iej"
            break
          case "info":
            r2Cmd = "ij"
            break
          case "basic":
          default:
            r2Cmd = "aaa;aflj;iij;iEj"
            analysisType = "basic"
        }
      }
      
      // Run analysis command with timeout
      const output = await runCommand(binaryPath, r2Cmd, timeoutMs)

      if (output.trim().length === 0 && args.command) {
        toolLogger.warn(`r2analyze: Command returned empty output: ${r2Cmd}`, {
          tool: "r2analyze", binary: binaryPath, command: r2Cmd,
        })
      }
      
      // Mark as analyzed if we ran analysis
      if (analysisType === "basic" || analysisType === "deep") {
        markAsAnalyzed(binaryPath)
      }
      
      const duration = Date.now() - startTime
      
      // Parse JSON output
      let data: any
      try {
        data = JSON.parse(extractJSON(output))
      } catch (e) {
        // Fallback to raw output if not valid JSON
        data = { raw: output }
      }
      
      // Sort and limit array results
      let total: number | undefined
      if (Array.isArray(data)) {
        total = data.length
        if (data.length > 0) {
          // Sort based on sortBy param
          switch (args.sortBy) {
            case "size":
              data.sort((a: any, b: any) => (b.size || 0) - (a.size || 0))
              break
            case "name":
              data.sort((a: any, b: any) => (a.name || "").localeCompare(b.name || ""))
              break
            case "address":
              data.sort((a: any, b: any) => (a.offset || a.vaddr || 0) - (b.offset || b.vaddr || 0))
              break
          }
        }
        if (data.length > args.limit) {
          data = data.slice(0, args.limit)
        }
      }
      
      // Generate summary
      const summary = generateSummary(analysisType, data)
      
      return JSON.stringify({
        success: true,
        binary: binaryPath,
        analysis: analysisType,
        duration: duration,
        timestamp: Date.now(),
        data: data,
        total: total,
        omitted: total !== undefined ? Math.max(0, total - (Array.isArray(data) ? data.length : 0)) : undefined,
        summary: summary
      }, null, 2)
      
    } catch (error: any) {
      return JSON.stringify({
        success: false,
        binary: binaryPath,
        analysis: args.analysis,
        error: error.message || String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now()
      }, null, 2)
    }
    }) // instrumentedCall
  }
})

function generateSummary(analysis: string, data: any): any {
  const summary: any = { type: analysis }
  
  switch (analysis) {
    case "functions":
    case "basic":
    case "deep":
      if (Array.isArray(data)) {
        summary.totalFunctions = data.length
        summary.totalSize = data.reduce((acc: number, f: any) => acc + (f.size || 0), 0)
        summary.largestFunction = data.reduce((max: any, f: any) => 
          (f.size || 0) > (max.size || 0) ? f : max, data[0] || {})
      }
      break
    case "strings":
      if (Array.isArray(data)) {
        summary.totalStrings = data.length
        summary.longestString = data.reduce((max: any, s: any) => 
          (s.length || 0) > (max.length || 0) ? s : max, data[0] || {})
      }
      break
    case "imports":
      if (Array.isArray(data)) {
        summary.totalImports = data.length
        summary.libraries = [...new Set(data.map((i: any) => i.libname).filter(Boolean))]
      }
      break
    case "sections":
      if (Array.isArray(data)) {
        summary.totalSections = data.length
        summary.executableSections = data.filter((s: any) => s.perms?.includes("x")).length
        summary.writableSections = data.filter((s: any) => s.perms?.includes("w")).length
      }
      break
    case "info":
      summary.format = data.core?.format
      summary.arch = data.core?.arch
      summary.bits = data.core?.bits
      summary.os = data.core?.os
      summary.language = data.core?.lang
      break
  }
  
  return summary
}

