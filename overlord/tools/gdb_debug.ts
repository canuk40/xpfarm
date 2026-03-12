import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"
import { toolLogger } from "./lib/logger"

export default tool({
  description: "Debug a binary using GDB",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    commands: tool.schema.array(tool.schema.string()).default(["info functions", "disas main"]).describe("GDB commands to execute"),
    args: tool.schema.array(tool.schema.string()).optional().describe("Arguments to pass to the binary"),
    breakpoints: tool.schema.array(tool.schema.string()).optional().describe("Breakpoint addresses or function names"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "gdb_debug", binary: binaryPath, args }, async () => {
    const result: { success: boolean; stdout: string; stderr: string; exitCode: number } = {
      success: false,
      stdout: "",
      stderr: "",
      exitCode: 0
    }
    
    try {
      // Build GDB commands
      const gdbCommands: string[] = ["set pagination off", "set confirm off"]
      
      if (args.breakpoints) {
        for (const bp of args.breakpoints) {
          gdbCommands.push(`break ${bp}`)
        }
      }
      
      gdbCommands.push(...args.commands)
      gdbCommands.push("quit")

      toolLogger.debug(`gdb_debug: Command list: ${JSON.stringify(gdbCommands)}`, {
        tool: "gdb_debug", binary: binaryPath,
      })
      
      // Build GDB args array with multiple -ex flags
      const gdbArgs: string[] = ["-batch"]
      for (const cmd of gdbCommands) {
        gdbArgs.push("-ex", cmd)
      }
      gdbArgs.push("--args", binaryPath)
      if (args.args) {
        gdbArgs.push(...args.args)
      }
      
      // Run GDB with timeout
      const proc = Bun.spawn(["gdb", ...gdbArgs], {
        timeout: args.timeout * 1000,
        stdout: "pipe",
        stderr: "pipe",
      })
      
      // Collect stdout
      const stdoutChunks: Uint8Array[] = []
      const stderrChunks: Uint8Array[] = []
      
      // Read stdout
      const stdoutReader = proc.stdout.getReader()
      while (true) {
        const { done, value } = await stdoutReader.read()
        if (done) break
        stdoutChunks.push(value)
      }
      
      // Read stderr
      const stderrReader = proc.stderr.getReader()
      while (true) {
        const { done, value } = await stderrReader.read()
        if (done) break
        stderrChunks.push(value)
      }
      
      // Wait for process to fully exit
      await proc.exited
      
      // Now get exit code after process has exited
      const exitCode = proc.exitCode ?? 1
      
      // Decode output
      const decoder = new TextDecoder()
      result.stdout = stdoutChunks.map(chunk => decoder.decode(chunk)).join("")
      result.stderr = stderrChunks.map(chunk => decoder.decode(chunk)).join("")
      result.exitCode = exitCode
      result.success = exitCode === 0 || result.stdout.length > 0
      
      // Limit output size
      const maxOutput = 5000
      if (result.stdout.length > maxOutput) {
        result.stdout = result.stdout.substring(0, maxOutput) + "\n... [truncated]"
      }
      if (result.stderr.length > maxOutput) {
        result.stderr = result.stderr.substring(0, maxOutput) + "\n... [truncated]"
      }
      
      return JSON.stringify(result, null, 2)
    } catch (error: any) {
      result.success = false
      result.stderr = error.message || String(error)
      result.exitCode = error.exitCode || 1
      return JSON.stringify(result, null, 2)
    }
    }) // instrumentedCall
  },
})
