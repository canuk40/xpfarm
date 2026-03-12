import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"
import { toolLogger } from "./lib/logger"

export default tool({
  description: "Extract strings from a binary file",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    minLength: tool.schema.number().default(4).describe("Minimum string length"),
    encoding: tool.schema.enum(["ascii", "unicode", "all"]).default("all").describe("String encoding to search for"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "strings_extract", binary: binaryPath, args }, async () => {
    const result: { success: boolean; stdout: string; stderr: string; encoding: string; count: number } = {
      success: false,
      stdout: "",
      stderr: "",
      encoding: args.encoding,
      count: 0
    }
    
    try {
      let output = ""
      
      switch (args.encoding) {
        case "ascii":
          output = await $`strings -n ${args.minLength} ${binaryPath}`.text()
          break
        case "unicode":
          // -e l = 16-bit little endian, -e b = 16-bit big endian
          output = await $`strings -n ${args.minLength} -e l ${binaryPath}`.text()
          break
        case "all":
        default:
          // Run multiple passes for different encodings since strings only accepts one -e flag
          const asciiStrings = await $`strings -n ${args.minLength} ${binaryPath}`.text()
          const unicodeLE = await $`strings -n ${args.minLength} -e l ${binaryPath}`.text()
          const unicodeBE = await $`strings -n ${args.minLength} -e b ${binaryPath}`.text()
          
          // Combine and deduplicate
          const allStrings = new Set([
            ...asciiStrings.split("\n"),
            ...unicodeLE.split("\n"),
            ...unicodeBE.split("\n")
          ])
          output = Array.from(allStrings).filter(s => s.length > 0).join("\n")
          break
      }
      
      result.success = true
      result.stdout = output
      result.count = output.split("\n").filter(s => s.length > 0).length

      if (result.count === 0) {
        toolLogger.warn(`strings_extract: Zero strings extracted from ${binaryPath}`, {
          tool: "strings_extract", binary: binaryPath,
        })
      }

      return JSON.stringify(result, null, 2)
    } catch (error: any) {
      result.success = false
      result.stderr = error.message || String(error)
      return JSON.stringify(result, null, 2)
    }
    }) // instrumentedCall
  },
})
