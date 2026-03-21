import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Trace system calls and library calls of a binary using strace/ltrace for dynamic analysis",
  args: {
    binary: tool.schema.string().describe("Path to the binary to trace"),
    args: tool.schema.string().optional().describe("Arguments to pass to the binary (space-separated)"),
    mode: tool.schema.enum(["strace", "ltrace", "both"]).default("strace").describe("strace=system calls, ltrace=library calls, both=run each"),
    filter: tool.schema.string().optional().describe("Filter to specific syscalls/functions (strace -e, e.g., 'read,write,open,execve')"),
    follow_forks: tool.schema.boolean().default(false).describe("Follow child processes"),
    stdin_input: tool.schema.string().optional().describe("Data to feed to stdin during tracing"),
    timeout: tool.schema.number().default(30).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)
    return instrumentedCall({ toolName: "strace_trace", binary: binaryPath, args }, async () => {
      const startTime = Date.now()
      const outputs: Record<string, string> = {}

      try {
        const binArgs = args.args ? args.args.split(" ") : []

        if (args.mode === "strace" || args.mode === "both") {
          const straceArgs: string[] = ["-o", "/tmp/strace_out.txt"]
          if (args.filter) straceArgs.push("-e", `trace=${args.filter}`)
          if (args.follow_forks) straceArgs.push("-f")
          straceArgs.push(binaryPath, ...binArgs)

          let result: any
          if (args.stdin_input) {
            const echo = await $`echo ${args.stdin_input} | strace ${straceArgs}`.nothrow().timeout(args.timeout * 1000)
            result = echo
          } else {
            result = await $`strace ${straceArgs}`.nothrow().timeout(args.timeout * 1000)
          }

          try {
            const outFile = Bun.file("/tmp/strace_out.txt")
            if (await outFile.exists()) {
              const raw = await outFile.text()
              outputs.strace = raw.slice(0, 8000)
              await $`rm -f /tmp/strace_out.txt`.nothrow()
            }
          } catch {
            outputs.strace = result.stderr?.toString().slice(0, 5000) || ""
          }
        }

        if (args.mode === "ltrace" || args.mode === "both") {
          const ltraceArgs: string[] = ["-o", "/tmp/ltrace_out.txt"]
          if (args.follow_forks) ltraceArgs.push("-f")
          ltraceArgs.push(binaryPath, ...binArgs)

          let result: any
          if (args.stdin_input) {
            result = await $`echo ${args.stdin_input} | ltrace ${ltraceArgs}`.nothrow().timeout(args.timeout * 1000)
          } else {
            result = await $`ltrace ${ltraceArgs}`.nothrow().timeout(args.timeout * 1000)
          }

          try {
            const outFile = Bun.file("/tmp/ltrace_out.txt")
            if (await outFile.exists()) {
              const raw = await outFile.text()
              outputs.ltrace = raw.slice(0, 8000)
              await $`rm -f /tmp/ltrace_out.txt`.nothrow()
            }
          } catch {
            outputs.ltrace = result.stderr?.toString().slice(0, 5000) || ""
          }
        }

        // Extract interesting patterns from strace output
        const straceOut = outputs.strace || ""
        const openedFiles = [...straceOut.matchAll(/open(?:at)?\([^,]+,"([^"]+)"/g)].map(m => m[1]).filter(f => !f.startsWith("/proc") && !f.startsWith("/dev"))
        const execveCalls = [...straceOut.matchAll(/execve\("([^"]+)"/g)].map(m => m[1])
        const networkCalls = straceOut.includes("connect(") || straceOut.includes("socket(")

        return JSON.stringify({
          success: Object.keys(outputs).length > 0,
          binary: binaryPath,
          mode: args.mode,
          outputs,
          interesting: {
            opened_files: [...new Set(openedFiles)].slice(0, 20),
            exec_calls: execveCalls.slice(0, 10),
            network_activity: networkCalls,
          },
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
