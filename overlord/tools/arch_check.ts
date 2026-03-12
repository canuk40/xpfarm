import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Check if a binary's architecture matches the container. Returns compatibility info and recommended analysis approach.",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "arch_check", binary: binaryPath, args }, async () => {
    try {
      const containerArch = (await $`uname -m`.text()).trim()
      const fileOutput = (await $`file ${binaryPath}`.text()).trim()

      // Detect binary arch from file output
      let binaryArch = "unknown"
      if (fileOutput.includes("x86-64") || fileOutput.includes("x86_64")) binaryArch = "x86_64"
      else if (fileOutput.includes("aarch64") || fileOutput.includes("ARM aarch64")) binaryArch = "aarch64"
      else if (fileOutput.includes("ARM,") || fileOutput.includes("ARM EABI")) binaryArch = "arm"
      else if (fileOutput.includes("MIPS")) binaryArch = "mips"
      else if (fileOutput.includes("Intel 80386") || fileOutput.includes("i386")) binaryArch = "i386"
      else if (fileOutput.includes("Atmel AVR") || fileOutput.includes("AVR")) binaryArch = "avr"
      else if (fileOutput.includes("PowerPC")) binaryArch = "ppc"

      // Map to r2 arch/bits settings for non-x86 architectures
      const r2ArchMap: Record<string, { arch: string; bits: number }> = {
        "avr": { arch: "avr", bits: 16 },
        "arm": { arch: "arm", bits: 32 },
        "aarch64": { arch: "arm", bits: 64 },
        "mips": { arch: "mips", bits: 32 },
        "ppc": { arch: "ppc", bits: 32 },
      }
      const r2Hints = r2ArchMap[binaryArch] || null

      // Detect binary format
      let format = "unknown"
      if (fileOutput.includes("ELF")) format = "ELF"
      else if (fileOutput.includes("PE32")) format = "PE"
      else if (fileOutput.includes("Mach-O")) format = "Mach-O"

      const nativeExec = containerArch === binaryArch ||
        (containerArch === "x86_64" && binaryArch === "i386")

      // Check for QEMU
      let qemuAvailable = false
      try {
        await $`which qemu-x86_64 2>/dev/null || which qemu-user-static 2>/dev/null`.nothrow()
        qemuAvailable = true
      } catch (e) {}

      const canDebug = format === "ELF" && (nativeExec || qemuAvailable)
      const canExecute = format === "ELF" && (nativeExec || qemuAvailable)

      // Architecture-specific analysis notes
      const archNotes: string[] = []
      if (binaryArch === "avr") {
        archNotes.push("AVR/Arduino binary: look for tone(), delay(), setup(), loop() patterns.")
        archNotes.push("Decompilers (Ghidra/r2ghidra) may not support AVR — prefer raw disassembly with r2analyze (pd/pdf commands).")
        archNotes.push("AVR uses 16-bit instruction words in r2 (asm.bits=16).")
      }
      if (r2Hints) {
        archNotes.push(`r2 settings: e asm.arch=${r2Hints.arch}; e asm.bits=${r2Hints.bits} (auto-applied by r2session).`)
      }

      return JSON.stringify({
        success: true,
        binary: binaryPath,
        fileInfo: fileOutput,
        containerArch,
        binaryArch,
        format,
        r2Hints,
        compatibility: {
          nativeExecution: nativeExec,
          qemuAvailable,
          canExecute,
          canDebug,
          staticAnalysisOnly: !canDebug,
        },
        archNotes: archNotes.length > 0 ? archNotes : undefined,
        recommendation: canDebug
          ? "Full analysis available: static + dynamic (GDB)."
          : format !== "ELF"
            ? `${format} binary: static analysis only. GDB cannot debug ${format} binaries in this container.`
            : `Architecture mismatch (container: ${containerArch}, binary: ${binaryArch}). Static analysis only unless QEMU is installed.`,
      }, null, 2)
    } catch (error: any) {
      return JSON.stringify({ success: false, error: error.message || String(error) }, null, 2)
    }
    }) // instrumentedCall
  }
})
