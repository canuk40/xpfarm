import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Analyze binary file using binwalk",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    extract: tool.schema.boolean().default(false).describe("Extract embedded files"),
    entropy: tool.schema.boolean().default(false).describe("Perform entropy analysis"),
    outputDir: tool.schema.string().optional().describe("Output directory for extracted files"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)
    const outDir = args.outputDir || "/workspace/output/binwalk"

    return instrumentedCall({ toolName: "binwalk_analyze", binary: binaryPath, args }, async () => {
    const result: {
      success: boolean; 
      stdout: string; 
      stderr: string; 
      exitCode: number;
      analysis: string[];
      extractedTo?: string;
    } = {
      success: false,
      stdout: "",
      stderr: "",
      exitCode: 0,
      analysis: []
    }
    
    try {
      let output = ""
      
      if (args.entropy) {
        // Entropy analysis using proper Bun shell syntax
        const entropyProc = await $`binwalk -E ${binaryPath}`
        output += "=== ENTROPY ANALYSIS ===\n"
        output += entropyProc.stdout.toString()
        if (entropyProc.stderr) {
          output += "\n" + entropyProc.stderr.toString()
        }
        output += "\n\n"
        result.analysis.push("entropy")
      }
      
      if (args.extract) {
        await $`mkdir -p ${outDir}`
        const extractProc = await $`binwalk -e -C ${outDir} ${binaryPath}`
        output += "=== EXTRACTION RESULTS ===\n"
        output += extractProc.stdout.toString()
        if (extractProc.stderr) {
          output += "\n" + extractProc.stderr.toString()
        }
        result.extractedTo = outDir
        result.analysis.push("extraction")
      } else if (!args.entropy) {
        // Standard analysis
        const standardProc = await $`binwalk ${binaryPath}`
        output += "=== SIGNATURE ANALYSIS ===\n"
        output += standardProc.stdout.toString()
        if (standardProc.stderr) {
          output += "\n" + standardProc.stderr.toString()
        }
        result.analysis.push("signatures")
      }
      
      // Limit output size
      const maxOutput = 10000
      if (output.length > maxOutput) {
        output = output.substring(0, maxOutput) + "\n... [truncated]"
      }
      
      result.success = true
      result.stdout = output
      result.exitCode = 0
      
      return JSON.stringify(result, null, 2)
    } catch (error: any) {
      result.success = false
      result.stderr = error.message || String(error)
      result.exitCode = error.exitCode || 1
      return JSON.stringify(result, null, 2)
    }
    }) // instrumentedCall
  }
})
