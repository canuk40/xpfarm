import { tool } from "@opencode-ai/plugin"
import path from "path"
import { toolLogger } from "./lib/logger"
import { instrumentedCall } from "./lib/tool_instrument"
import { runPythonHelper } from "./lib/py_runner"

export default tool({
  description: "Emulate a specific address range using Unicorn Engine. Returns register state at breakpoints. Use for precise register tracing when LLM analysis of disassembly is unreliable (e.g., tracking constants across 100+ instructions).",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    start: tool.schema.string().describe("Start address (hex, e.g., '0x2250')"),
    end: tool.schema.string().describe("End address (hex, e.g., '0x2720')"),
    breakpoints: tool.schema.array(tool.schema.string()).optional().describe("Addresses to snapshot registers at (hex). If omitted, snapshots every instruction (warning: verbose)."),
    initRegs: tool.schema.string().optional().describe("Initial register values as JSON object, e.g. '{\"rax\":\"0x1\",\"rbx\":\"0x2\"}'"),
  },
  async execute(args: any, context: any) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "emulate", binary: binaryPath, args }, async () => {
      const startTime = Date.now()

      try {
        let initRegs: Record<string, string> = {}
        if (args.initRegs) {
          try { initRegs = JSON.parse(args.initRegs) } catch { /* ignore invalid JSON */ }
        }

        const payload = JSON.stringify({
          binary: binaryPath,
          start: args.start,
          end: args.end,
          breakpoints: args.breakpoints || [],
          init_regs: initRegs,
        })

        const helperPath = path.join(import.meta.dir, "lib", "emulate_helper.py")
        const { stdout, stderr, exitCode } = await runPythonHelper("emulate", helperPath, payload)
        const parsed = JSON.parse(stdout)

        toolLogger.info(`emulate: Emulated ${args.start}-${args.end}: ${parsed.snapshots?.length || 0} snapshots`)

        // Limit snapshots to prevent context overflow
        const maxSnapshots = 200
        let snapshots = parsed.snapshots || []
        const totalSnapshots = snapshots.length
        if (snapshots.length > maxSnapshots) {
          snapshots = snapshots.slice(0, maxSnapshots)
        }

        return JSON.stringify({
          success: parsed.success,
          error: parsed.error,
          binary: binaryPath,
          range: { start: args.start, end: args.end },
          totalSnapshots,
          omittedSnapshots: Math.max(0, totalSnapshots - maxSnapshots),
          snapshots,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        toolLogger.error(`emulate: Failed: ${error.message}`)
        return JSON.stringify({
          success: false,
          error: error.message || String(error),
          duration: Date.now() - startTime,
        }, null, 2)
      }
    })
  }
})
