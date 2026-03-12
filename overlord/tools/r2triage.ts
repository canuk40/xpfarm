import { tool } from "@opencode-ai/plugin"
import { runCommand, getOrCreateSession, markAsAnalyzed } from "./lib/r2session"
import { toolLogger } from "./lib/logger"
import { extractJSON } from "./lib/json_utils"
import { instrumentedCall } from "./lib/tool_instrument"
import path from "path"

export default tool({
  description: "Complete first-pass analysis of binary - returns comprehensive triage report",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    depth: tool.schema.enum(["quick", "standard", "deep"]).default("standard").describe("Analysis depth"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds for analysis phase"),
    verbose: tool.schema.boolean().default(false).describe("Return full arrays instead of capped results"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "r2triage", binary: binaryPath, args }, async () => {
    const startTime = Date.now()
    toolLogger.info(`Starting triage of ${binaryPath} with depth ${args.depth}`)

    const report: any = {
      timestamp: Date.now(),
      binary: binaryPath,
      depth: args.depth,
      errors: []
    }
    
    try {
      const session = await getOrCreateSession(binaryPath)
      toolLogger.debug(`Session established for ${binaryPath}`)
      
      // Phase 1: Metadata (always quick)
      try {
        const metadataOutput = await runCommand(binaryPath, "ij", 5000)
        report.metadata = JSON.parse(extractJSON(metadataOutput))
      } catch (e: any) {
        report.errors.push(`Metadata extraction failed: ${e.message}`)
        report.metadata = {}
      }
      
      // Phase 2: Analysis based on depth
      const analysisCmd = args.depth === "quick" ? "aa" : args.depth === "deep" ? "aaaa" : "aaa"
      const analysisTimeout = Math.min(args.timeout, 300) * 1000 // Max 5 minutes
      
      try {
        await runCommand(binaryPath, analysisCmd, analysisTimeout)
        markAsAnalyzed(binaryPath)
      } catch (e: any) {
        report.errors.push(`Analysis failed: ${e.message}`)
        // Continue with partial results
      }
      
      // Phase 3: Extract findings (each wrapped independently)
      
      // Sections
      try {
        const sectionsOutput = await runCommand(binaryPath, "iSj", 5000)
        report.sections = JSON.parse(extractJSON(sectionsOutput))
      } catch (e: any) {
        report.errors.push(`Sections extraction failed: ${e.message}`)
        report.sections = []
      }
      
      // Imports
      try {
        const importsOutput = await runCommand(binaryPath, "iij", 5000)
        report.imports = JSON.parse(extractJSON(importsOutput))
      } catch (e: any) {
        report.errors.push(`Imports extraction failed: ${e.message}`)
        report.imports = []
      }
      
      // Exports
      try {
        const exportsOutput = await runCommand(binaryPath, "iEj", 5000)
        report.exports = JSON.parse(extractJSON(exportsOutput))
      } catch (e: any) {
        report.errors.push(`Exports extraction failed: ${e.message}`)
        report.exports = []
      }
      
      // Strings
      let allStrings: any[] = []
      try {
        const stringsOutput = await runCommand(binaryPath, "izzj", 10000)
        allStrings = JSON.parse(extractJSON(stringsOutput))
        report.totalStrings = allStrings.length
      } catch (e: any) {
        report.errors.push(`Strings extraction failed: ${e.message}`)
        report.totalStrings = 0
      }

      // Functions
      let allFunctions: any[] = []
      try {
        const functionsOutput = await runCommand(binaryPath, "aflj", 10000)
        allFunctions = JSON.parse(extractJSON(functionsOutput))
        report.totalFunctions = allFunctions.length
      } catch (e: any) {
        report.errors.push(`Functions extraction failed: ${e.message}`)
        report.totalFunctions = 0
      }

      // Sort functions by size descending
      const sortedFunctions = [...allFunctions].sort((a: any, b: any) => (b.size || 0) - (a.size || 0))
      // Categorize and prioritize strings
      const categorizedStrings = categorizeStrings(allStrings)

      // Normalize address fields to include hex companions
      report.sections = normalizeAddresses(report.sections)
      report.imports = normalizeAddresses(report.imports)
      report.exports = normalizeAddresses(report.exports)

      // Cap arrays unless verbose
      const maxStrings = args.verbose ? allStrings.length : 30
      const maxFunctions = args.verbose ? allFunctions.length : 25
      report.strings = normalizeAddresses(categorizedStrings.slice(0, maxStrings))
      report.functions = normalizeAddresses(sortedFunctions.slice(0, maxFunctions))
      
      // Phase 4: Risk indicators
      try {
        report.indicators = analyzeRisk(report)
      } catch (e: any) {
        report.errors.push(`Risk analysis failed: ${e.message}`)
        report.indicators = []
      }
      
      // Phase 5: Build output with summary FIRST for truncation safety
      const duration = Date.now() - startTime
      const success = report.errors.length === 0

      const summary = {
        totalFunctions: report.totalFunctions || 0,
        totalImports: report.imports?.length || 0,
        totalExports: report.exports?.length || 0,
        totalStrings: report.totalStrings || 0,
        totalSections: report.sections?.length || 0,
        suspicious: report.indicators?.filter((i: any) => i.severity === "high").length || 0,
        warnings: report.indicators?.filter((i: any) => i.severity === "medium").length || 0,
        partialData: report.errors.length > 0,
        recommendedNextSteps: generateRecommendations(report),
        topFunctionsBySize: sortedFunctions.slice(0, 10).map((f: any) => ({ name: f.name, size: f.size, addr: f.offset, addr_hex: `0x${(f.offset || 0).toString(16)}` })),
        importLibraries: [...new Set((report.imports || []).map((i: any) => i.libname).filter(Boolean))],
      }

      toolLogger.info(`Triage completed in ${duration}ms. Success: ${success}, Errors: ${report.errors.length}`)

      // Decision-making fields FIRST, large arrays LAST (truncated first if output too big)
      return JSON.stringify({
        success,
        binary: binaryPath,
        depth: args.depth,
        duration,
        timestamp: report.timestamp,
        summary,
        indicators: report.indicators,
        metadata: report.metadata,
        errors: report.errors.length > 0 ? report.errors : undefined,
        sections: report.sections,
        imports: report.imports,
        exports: report.exports,
        strings: report.strings,
        functions: report.functions,
        omitted: {
          functions: Math.max(0, (report.totalFunctions || 0) - maxFunctions),
          strings: Math.max(0, (report.totalStrings || 0) - maxStrings),
        }
      }, null, 2)
      
    } catch (error: any) {
      report.success = false
      report.error = error.message || String(error)
      report.duration = Date.now() - startTime
      
      toolLogger.error(`Triage failed for ${binaryPath}: ${error.message}`)
      
      return JSON.stringify(report, null, 2)
    }
    }) // instrumentedCall
  }
})

/**
 * Recursively normalize address fields in r2 JSON output.
 * For fields like addr, offset, vaddr, paddr that are decimal numbers,
 * add a companion _hex field with the hex string representation.
 * This prevents agents from misinterpreting decimal 1512 as hex 0x1512.
 */
function normalizeAddresses(obj: any): any {
  if (Array.isArray(obj)) return obj.map(normalizeAddresses)
  if (obj && typeof obj === "object") {
    const result: any = {}
    for (const [k, v] of Object.entries(obj)) {
      if ((k === "addr" || k === "offset" || k === "vaddr" || k === "paddr") && typeof v === "number") {
        result[k] = v
        result[`${k}_hex`] = `0x${v.toString(16)}`
      } else {
        result[k] = normalizeAddresses(v)
      }
    }
    return result
  }
  return obj
}

function categorizeStrings(strings: any[]): any[] {
  const urlPattern = /https?:\/\//
  const pathPattern = /[A-Z]:\\|\/usr\/|\/etc\/|\/tmp\//i
  const suspiciousPattern = /password|passwd|secret|token|key|admin|root/i
  const errorPattern = /error|fail|denied|invalid|exception/i

  return strings
    .map(s => ({
      ...s,
      category: urlPattern.test(s.string) ? "url"
        : pathPattern.test(s.string) ? "path"
        : suspiciousPattern.test(s.string) ? "suspicious"
        : errorPattern.test(s.string) ? "error"
        : "general"
    }))
    .sort((a, b) => {
      const priority: Record<string, number> = { suspicious: 0, url: 1, path: 2, error: 3, general: 4 }
      return (priority[a.category] ?? 4) - (priority[b.category] ?? 4)
    })
}

function analyzeRisk(report: any): any[] {
  const indicators = []
  
  // Check for suspicious imports
  const suspiciousApis = ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "NtUnmapViewOfSection"]
  for (const imp of report.imports || []) {
    if (suspiciousApis.some(api => imp.name?.includes(api))) {
      indicators.push({type: "api", severity: "high", detail: `Suspicious API: ${imp.name}`})
    }
  }
  
  // Check for network APIs
  const networkApis = ["InternetOpen", "HttpSendRequest", "socket", "connect", "WSAStartup"]
  const hasNetwork = (report.imports || []).some((imp: any) => 
    networkApis.some(api => imp.name?.includes(api))
  )
  if (hasNetwork) {
    indicators.push({type: "network", severity: "medium", detail: "Network-related APIs detected"})
  }
  
  // Check for crypto APIs
  const cryptoApis = ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "Crypto"]
  const hasCrypto = (report.imports || []).some((imp: any) =>
    cryptoApis.some(api => imp.name?.includes(api))
  )
  if (hasCrypto) {
    indicators.push({type: "crypto", severity: "medium", detail: "Cryptographic APIs detected"})
  }
  
  // Check for suspicious strings
  const suspiciousStrings = ["password", "passwd", "pwd", "key", "secret", "token"]
  const suspiciousStringCount = (report.strings || []).filter((s: any) => 
    suspiciousStrings.some(ss => s.string?.toLowerCase().includes(ss))
  ).length
  if (suspiciousStringCount > 0) {
    indicators.push({type: "strings", severity: "low", detail: `${suspiciousStringCount} suspicious string patterns`})
  }
  
  // Check for URLs/domains
  const urlPattern = /https?:\/\//
  const domainPattern = /[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/
  const networkStrings = (report.strings || []).filter((s: any) => 
    urlPattern.test(s.string) || domainPattern.test(s.string)
  )
  if (networkStrings.length > 0) {
    indicators.push({type: "network", severity: "medium", detail: `${networkStrings.length} potential URLs/domains`})
  }
  
  return indicators
}

function generateRecommendations(report: any): string[] {
  const steps = []
  
  if (report.summary?.suspicious > 0) {
    steps.push("Decompile suspicious functions with r2decompile")
    steps.push("Trace cross-references with r2xref")
  }
  
  if (report.summary?.warnings > 0) {
    steps.push("Analyze flagged indicators in detail")
  }
  
  if ((report.strings || []).some((s: any) => s.string?.includes("password") || s.string?.includes("key"))) {
    steps.push("Scan for cryptographic patterns")
  }
  
  if ((report.totalFunctions || 0) > 100) {
    steps.push("Focus analysis on entry point and main function")
    steps.push("Use targeted analysis for suspicious functions only")
  } else {
    steps.push("Decompile key functions to understand logic")
  }
  
  if ((report.imports || []).length === 0) {
    steps.push("Binary may be statically linked - check for packed/obfuscated code")
  }
  
  steps.push("Check entry point disassembly")
  
  return steps
}
