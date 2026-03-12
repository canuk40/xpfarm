import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import { existsSync } from "fs"
import path from "path"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Scan binary with YARA rules for patterns, packers, and signatures",
  args: {
    binary: tool.schema.string().describe("Path to binary"),
    ruleset: tool.schema.enum(["all", "languages", "packers", "crypto"]).default("all").describe("Which rule categories to run"),
  },
  async execute(args: any, context: any) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)

    return instrumentedCall({ toolName: "yarascan", binary: binaryPath, args }, async () => {
      const startTime = Date.now()

      try {
        // Check if YARA is installed
        let yaraAvailable = false
        let yaraPath = ""
        try {
          const whichResult = await $`which yara`
          yaraPath = whichResult.stdout.toString().trim()
          yaraAvailable = true
        } catch (e) {
          // YARA not available
        }

        // If YARA not available, skip straight to heuristics (no early return)

        const rulesDir = "/opt/yara-rules"
        const results: any[] = []
        let scanMethod = "heuristic"

        // Try to run YARA with actual rules if available and rules exist
        const rulesFile = `${rulesDir}/${args.ruleset}.yar`
        if (yaraAvailable && existsSync(rulesFile)) {
          try {
            const yaraOutput = await $`yara -r ${rulesFile} ${binaryPath}`.nothrow()

            if (yaraOutput.stdout) {
              const lines = yaraOutput.stdout.toString().trim().split("\n").filter((line: string) => line)
              for (const line of lines) {
                const [rule] = line.split(" ")
                results.push({
                  rule,
                  category: inferCategory(rule),
                  confidence: "high",
                  method: "yara"
                })
              }
              scanMethod = "yara"
            }
          } catch (e) {
            // YARA execution failed, fall through to heuristics
          }
        }

        // If no YARA results, use heuristics as fallback
        if (results.length === 0) {
          const heuristicResults = await heuristicScan(binaryPath, args.ruleset)
          results.push(...heuristicResults.matches)
          scanMethod = "heuristic"
        }

        return JSON.stringify({
          success: true,
          binary: binaryPath,
          scanMethod,
          ruleset: args.ruleset,
          duration: Date.now() - startTime,
          matches: results,
          summary: {
            totalMatches: results.length,
            categories: [...new Set(results.map(r => r.category))],
            confidence: calculateConfidence(results),
            note: scanMethod === "yara"
              ? "YARA signature-based detection"
              : !yaraAvailable
                ? "Heuristic-based detection (YARA not installed)"
                : !existsSync(rulesFile)
                  ? `Heuristic-based detection (YARA rules not found at ${rulesFile})`
                  : "Heuristic-based detection (YARA returned no matches)"
          }
        }, null, 2)

      } catch (error: any) {
        return JSON.stringify({
          success: false,
          binary: binaryPath,
          error: error.message || String(error),
          duration: Date.now() - startTime
        }, null, 2)
      }
    }) // instrumentedCall
  }
})

async function heuristicScan(binaryPath: string, ruleset: string): Promise<{ matches: any[], confidence: string }> {
  const matches: any[] = []

  // Read first 1MB of binary for analysis
  const file = Bun.file(binaryPath)
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer.slice(0, 1024 * 1024))

  // Convert to string for pattern matching (be careful with binary data)
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  const textLower = text.toLowerCase()

  // Language detection - require multiple markers for confidence
  if (ruleset === "all" || ruleset === "languages") {
    // Rust detection
    const rustMarkers = ["rust_panic", "core::fmt", "std::io", "rust_begin_unwind"]
    const rustMatches = rustMarkers.filter(m => textLower.includes(m.toLowerCase()))
    if (rustMatches.length >= 2) {
      matches.push({ rule: "rust_binary", category: "languages", confidence: "high", method: "heuristic", markers: rustMatches })
    } else if (rustMatches.length === 1) {
      matches.push({ rule: "rust_binary", category: "languages", confidence: "low", method: "heuristic", markers: rustMatches })
    }

    // Zig detection - check for absence of C runtime + Zig markers
    const zigMarkers = ["std.io", "std.fmt", "std.heap"]
    const zigMatches = zigMarkers.filter(m => textLower.includes(m.toLowerCase()))
    const cMarkers = ["printf", "malloc", "free", "stderr", "stdout"]
    const cMatches = cMarkers.filter(m => textLower.includes(m.toLowerCase()))

    if (zigMatches.length >= 1 && cMatches.length < 3) {
      matches.push({ rule: "zig_binary", category: "languages", confidence: zigMatches.length >= 2 ? "high" : "medium", method: "heuristic", markers: zigMatches, antiMarkers: cMatches })
    }

    // Go detection
    const goMarkers = ["go.buildid", "runtime.go", "fmt.print", "main.main"]
    const goMatches = goMarkers.filter(m => textLower.includes(m.toLowerCase()))
    if (goMatches.length >= 2) {
      matches.push({ rule: "go_binary", category: "languages", confidence: "high", method: "heuristic", markers: goMatches })
    }
  }

  // Packer detection
  if (ruleset === "all" || ruleset === "packers") {
    if (textLower.includes("upx")) {
      matches.push({ rule: "upx_packed", category: "packers", confidence: "high", method: "heuristic" })
    }

    // Check entropy of sections via binwalk if available
    try {
      const entropyCheck = await $`binwalk -E ${binaryPath} 2>/dev/null | grep -E "(High|Very High)"`.nothrow()
      if (entropyCheck.stdout && entropyCheck.stdout.toString().trim()) {
        matches.push({ rule: "high_entropy", category: "packers", confidence: "medium", method: "heuristic", detail: "High entropy sections detected" })
      }
    } catch (e) {
      // binwalk not available or failed
    }
  }

  // Crypto detection
  if (ruleset === "all" || ruleset === "crypto") {
    const cryptoPatterns = [
      { name: "aes", pattern: /aes|rijndael/i },
      { name: "rsa", pattern: /rsa|mod_exp/i },
      { name: "des", pattern: /des_|3des|triple.des/i },
      { name: "rc4", pattern: /rc4|arc4/i },
      { name: "chacha", pattern: /chacha|salsa/i },
    ]

    for (const crypto of cryptoPatterns) {
      if (crypto.pattern.test(text)) {
        matches.push({ rule: `${crypto.name}_crypto`, category: "crypto", confidence: "low", method: "heuristic" })
      }
    }
  }

  // Determine overall confidence
  const highConf = matches.filter(m => m.confidence === "high").length
  const medConf = matches.filter(m => m.confidence === "medium").length

  let confidence = "low"
  if (highConf >= 2 || (highConf >= 1 && medConf >= 2)) confidence = "high"
  else if (highConf >= 1 || medConf >= 2) confidence = "medium"

  return { matches, confidence }
}

function inferCategory(ruleName: string): string {
  if (ruleName.match(/zig|rust|go|nim|swift|c\+\+|gcc|clang|msvc/i)) return "languages"
  if (ruleName.match(/upx|vmprotect|themida|aspack|packed|packer/i)) return "packers"
  if (ruleName.match(/aes|rsa|des|rc4|chacha|blowfish|crypto/i)) return "crypto"
  return "other"
}

function calculateConfidence(matches: any[]): string {
  const highConf = matches.filter(m => m.confidence === "high").length
  const medConf = matches.filter(m => m.confidence === "medium").length

  if (highConf >= 2 || (highConf >= 1 && medConf >= 2)) return "high"
  if (highConf >= 1 || medConf >= 2) return "medium"
  return "low"
}
