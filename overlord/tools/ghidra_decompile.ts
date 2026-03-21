import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Decompile a binary or specific function using Ghidra headless analyzer",
  args: {
    binary: tool.schema.string().describe("Path to the binary file"),
    function_name: tool.schema.string().optional().describe("Specific function name to decompile (e.g., 'main', 'encrypt'). Decompiles all if omitted."),
    output_dir: tool.schema.string().default("/workspace/output/ghidra").describe("Directory to write Ghidra project and output"),
    timeout: tool.schema.number().default(300).describe("Timeout in seconds (Ghidra is slow on first run)"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)
    return instrumentedCall({ toolName: "ghidra_decompile", binary: binaryPath, args }, async () => {
      const startTime = Date.now()
      try {
        await $`mkdir -p ${args.output_dir}`.nothrow()

        const projectName = path.basename(binaryPath).replace(/[^a-zA-Z0-9_]/g, "_")
        const ghidraHome = "/opt/ghidra_11.0.3_PUBLIC"
        const analyzeHeadless = `${ghidraHome}/support/analyzeHeadless`

        // Build script for decompilation
        const scriptContent = args.function_name
          ? `import ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.*;\n\nDecompInterface decomp = new DecompInterface();\ndecomp.openProgram(currentProgram);\nfor (Function func : currentProgram.getFunctionManager().getFunctions(true)) {\n  if (func.getName().equals("${args.function_name}")) {\n    DecompileResults res = decomp.decompileFunction(func, 60, monitor);\n    println("=== " + func.getName() + " ===");\n    if (res.decompileCompleted()) println(res.getDecompiledFunction().getC());\n  }\n}`
          : `import ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.*;\n\nDecompInterface decomp = new DecompInterface();\ndecomp.openProgram(currentProgram);\nfor (Function func : currentProgram.getFunctionManager().getFunctions(true)) {\n  DecompileResults res = decomp.decompileFunction(func, 60, monitor);\n  println("=== " + func.getName() + " @ " + func.getEntryPoint() + " ===");\n  if (res.decompileCompleted()) println(res.getDecompiledFunction().getC());\n}`

        const scriptPath = "/tmp/ghidra_decompile.java"
        await Bun.write(scriptPath, scriptContent)

        const result = await $`${analyzeHeadless} ${args.output_dir} ${projectName} -import ${binaryPath} -postScript ${scriptPath} -scriptlog /tmp/ghidra_script.log -deleteProject`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        // Extract decompiled output from script log
        let decompiled = ""
        try {
          const logFile = Bun.file("/tmp/ghidra_script.log")
          if (await logFile.exists()) {
            decompiled = await logFile.text()
            await $`rm -f /tmp/ghidra_script.log`.nothrow()
          }
        } catch { /* use stdout */ }

        const output = decompiled || stdout
        const maxOutput = 20000
        const truncated = output.length > maxOutput

        return JSON.stringify({
          success: result.exitCode === 0 || output.length > 100,
          binary: binaryPath,
          function: args.function_name || "all",
          decompiled: truncated ? output.slice(0, maxOutput) + "\n... [truncated]" : output,
          truncated,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 500) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({
          success: false,
          error: error.message || String(error),
          hint: "Ghidra requires Java. If this fails, radare2 r2decompile is a lighter alternative.",
          duration: Date.now() - startTime,
        }, null, 2)
      }
    })
  }
})
