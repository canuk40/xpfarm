import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { toolLogger } from "./lib/logger"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Raw disassembly with objdump. Use when precise instruction-level analysis is needed and r2 annotations may be misleading. Returns unmodified Intel syntax disassembly.",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    startAddr: tool.schema.string().optional().describe("Start address (hex, e.g. '0x2250')"),
    stopAddr: tool.schema.string().optional().describe("Stop address (hex, e.g. '0x2720')"),
    function: tool.schema.string().optional().describe("Disassemble specific function by name (e.g. 'main')"),
    fullDump: tool.schema.boolean().default(false).describe("Dump entire .text section (warning: large output)"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "objdump_disasm", binary: binaryPath, args }, async () => {
      const startTime = Date.now()
      let objdumpCmd = "objdump"
      let extraFlags: string[] = ["-M", "intel"]
      let detectedArch = "x86"

      try {
        // Detect architecture to select correct objdump variant/flags
        const fileOut = (await $`file ${binaryPath}`.text()).trim()

        if (fileOut.includes("Atmel AVR") || fileOut.includes("AVR")) {
          detectedArch = "avr"
          // Try avr-objdump first
          try {
            await $`which avr-objdump`.text()
            objdumpCmd = "avr-objdump"
            extraFlags = [] // AVR objdump doesn't need -M intel
          } catch {
            extraFlags = ["-m", "avr"]
          }
        } else if (fileOut.includes("aarch64") || fileOut.includes("ARM aarch64")) {
          detectedArch = "aarch64"
          extraFlags = ["-m", "aarch64"]
        } else if (fileOut.includes("ARM,") || fileOut.includes("ARM EABI")) {
          detectedArch = "arm"
          extraFlags = ["-m", "arm"]
        } else if (fileOut.includes("MIPS")) {
          detectedArch = "mips"
          extraFlags = ["-m", "mips"]
        } else if (fileOut.includes("PowerPC")) {
          detectedArch = "ppc"
          extraFlags = ["-m", "powerpc"]
        }

        toolLogger.info(`objdump: Detected arch=${detectedArch}, using ${objdumpCmd} ${extraFlags.join(" ")}`)

        // Helper to run objdump with correct flags
        const runObjdump = async (additionalFlags: string[] = []) => {
          const allFlags = ["-d", ...extraFlags, ...additionalFlags, binaryPath]
          const result = await $`${objdumpCmd} ${allFlags}`.text()
          return result
        }

        let output: string

        if (args.function) {
          // Disassemble specific function using objdump + extract
          const fullDump = await runObjdump()
          const lines = fullDump.split("\n")
          const funcStart = lines.findIndex(l => l.includes(`<${args.function}>:`))
          if (funcStart === -1) {
            return JSON.stringify({ success: false, error: `Function '${args.function}' not found`, arch: detectedArch })
          }
          // Extract until next function or end
          const funcLines = [lines[funcStart]]
          for (let i = funcStart + 1; i < lines.length; i++) {
            if (lines[i].match(/^[0-9a-f]+ </) && !lines[i].includes(`<${args.function}>`)) break
            funcLines.push(lines[i])
          }
          output = funcLines.join("\n")
        } else if (args.startAddr && args.stopAddr) {
          output = await runObjdump([`--start-address=${args.startAddr}`, `--stop-address=${args.stopAddr}`])
        } else if (args.fullDump) {
          output = await runObjdump()
        } else {
          output = await runObjdump()
        }

        const lineCount = output.split("\n").length
        toolLogger.info(`objdump: Disassembled ${binaryPath}: ${lineCount} lines`)

        // Truncate if very large
        const maxChars = 50000
        const truncated = output.length > maxChars
        if (truncated) {
          output = output.substring(0, maxChars) + "\n... [truncated]"
        }

        return JSON.stringify({
          success: true,
          binary: binaryPath,
          arch: detectedArch,
          lineCount,
          truncated,
          disassembly: output,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        const stderr = error.stderr?.toString?.() || ""
        const cmd = `${objdumpCmd} -d ${extraFlags.join(" ")} ${binaryPath}` + (args.function ? ` (function: ${args.function})` : "") + (args.startAddr ? ` (range: ${args.startAddr}-${args.stopAddr})` : "")
        toolLogger.error(`objdump: Failed on ${binaryPath}: ${error.message}`, {
          tool: "objdump_disasm", binary: binaryPath, command: cmd,
          exitCode: error.exitCode, stderr: stderr.substring(0, 500),
        })

        // Provide architecture-specific suggestions on failure
        const isArchError = stderr.includes("can't disassemble") || stderr.includes("UNKNOWN") || stderr.includes("not recognised")
        const suggestion = isArchError
          ? `objdump cannot disassemble this architecture (${detectedArch}). Use r2analyze with architecture flags instead: r2analyze(binary, command="pd 200 @ <addr>", arch="${detectedArch}")`
          : undefined

        return JSON.stringify({
          success: false,
          error: error.message || String(error),
          arch: detectedArch,
          command: cmd,
          stderr: stderr.substring(0, 500),
          suggestion,
          duration: Date.now() - startTime,
        }, null, 2)
      }
    })
  }
})
