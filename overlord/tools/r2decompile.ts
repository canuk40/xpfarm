import { tool } from "@opencode-ai/plugin"
import { runCommand, getOrCreateSession, markAsAnalyzed, isAnalyzed } from "./lib/r2session"
import { extractJSON } from "./lib/json_utils"
import { instrumentedCall } from "./lib/tool_instrument"
import { toolLogger } from "./lib/logger"
import path from "path"

export default tool({
  description: "Decompile functions to pseudocode using radare2",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    function: tool.schema.string().default("main").describe("Function to decompile (name or address)"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "r2decompile", binary: binaryPath, args }, async () => {
    const startTime = Date.now()

    try {
      const session = await getOrCreateSession(binaryPath)
      if (!isAnalyzed(binaryPath)) {
        await runCommand(binaryPath, "aaa", args.timeout * 1000)
        markAsAnalyzed(binaryPath)
      }
      
      // Get function metadata
      let funcData: any = {}
      try {
        const funcInfoOutput = await runCommand(binaryPath, `afij @ ${args.function}`, 5000)
        const funcArray = JSON.parse(extractJSON(funcInfoOutput))
        funcData = funcArray[0] || {}
      } catch (e) {
        // Function info not available, continue without it
      }
      
      // Try r2ghidra first, fallback to built-in pdc
      // Note: r2 HTTP always returns 200, so missing plugins return error text
      // as successful response. We must check content, not just catch exceptions.
      let decompOutput = ""
      let decompiler = "pdc"

      // Only match actual error messages, NOT words that appear in valid output.
      // r2ghidra's valid pseudocode may contain "Ghidra" or "r2ghidra" in comments.
      const ghidraErrorPatterns = [
        "Cannot find function",
        "Unknown command",
        "Invalid command",
        "command not found",
        "unrecognized",
        "plugin not found",
        "not loaded",
      ]

      try {
        const pdgOutput = await runCommand(binaryPath, `pdg @ ${args.function}`, args.timeout * 1000)
        const trimmed = pdgOutput.trim()
        // Only flag as error if output is empty, very short (< 20 chars = likely just an error line),
        // or contains a known error pattern
        const isGhidraError = trimmed.length === 0 ||
          (trimmed.length < 20 && ghidraErrorPatterns.some(p => trimmed.toLowerCase().includes(p.toLowerCase())))

        if (!isGhidraError) {
          decompOutput = pdgOutput
          decompiler = "r2ghidra"
        } else {
          toolLogger.info(`r2ghidra unavailable or failed (output: "${pdgOutput.trim().substring(0, 100)}"), falling back to pdc`)
          decompOutput = await runCommand(binaryPath, `pdc @ ${args.function}`, args.timeout * 1000)
          decompiler = "r2-pdc"
        }
      } catch (e) {
        // Network/timeout error — fallback to pdc
        toolLogger.info(`r2ghidra threw exception, falling back to pdc: ${e}`)
        decompOutput = await runCommand(binaryPath, `pdc @ ${args.function}`, args.timeout * 1000)
        decompiler = "r2-pdc"
      }

      if (decompOutput.trim().length === 0) {
        toolLogger.warn(`r2decompile: Empty output for function "${args.function}" using ${decompiler}`, {
          tool: "r2decompile", binary: binaryPath, command: `pdg/pdc @ ${args.function}`,
        })
        return JSON.stringify({
          success: false,
          error: `Decompiler (${decompiler}) returned empty output for "${args.function}". This usually means the architecture is not supported by the decompiler (e.g., AVR, MIPS). Use r2analyze with disassembly commands (pd, pdf) instead.`,
          binary: binaryPath,
          function: args.function,
          decompiler,
          suggestion: "Try: r2analyze with command='pd 200 @ <address>' for raw disassembly",
          duration: Date.now() - startTime,
        }, null, 2)
      }

      // Limit output size
      const maxOutputLength = 10000
      const truncatedOutput = decompOutput.length > maxOutputLength 
        ? decompOutput.substring(0, maxOutputLength) + "\n... [truncated]"
        : decompOutput
      
      const duration = Date.now() - startTime
      
      return JSON.stringify({
        success: true,
        binary: binaryPath,
        function: args.function,
        decompiler: decompiler,
        duration: duration,
        metadata: {
          address: funcData?.offset,
          size: funcData?.size,
          complexity: funcData?.cc,
          locals: funcData?.locals?.length || 0,
          args: funcData?.bpvars?.length || 0
        },
        pseudocode: truncatedOutput,
        summary: summarizeFunction(decompOutput)
      }, null, 2)
      
    } catch (error: any) {
      return JSON.stringify({
        success: false,
        binary: binaryPath,
        function: args.function,
        error: error.message || String(error),
        duration: Date.now() - startTime
      }, null, 2)
    }
    }) // instrumentedCall
  }
})

function summarizeFunction(pseudocode: string): {
  signature: string;
  overview: string;
  operations: { calls: number; loops: number; conditionals: number; returns: number };
  totalLines: number;
} {
  const lines = pseudocode.split("\n").filter(line => line.trim())
  
  // Extract function signature (first line usually)
  const signature = lines[0] || ""
  
  // Get first 10 non-empty lines for overview
  const overview = lines.slice(0, 10).join("\n")
  
  // Count key operations
  const operations = {
    calls: (pseudocode.match(/\b(call|invoke)\b/gi) || []).length,
    loops: (pseudocode.match(/\b(for|while|do)\b/gi) || []).length,
    conditionals: (pseudocode.match(/\b(if|switch)\b/gi) || []).length,
    returns: (pseudocode.match(/\breturn\b/gi) || []).length
  }
  
  return {
    signature,
    overview,
    operations,
    totalLines: lines.length
  }
}

