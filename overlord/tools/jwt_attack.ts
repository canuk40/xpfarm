import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Test JWT tokens for vulnerabilities using jwt_tool — alg:none, RS256→HS256 confusion, weak secret brute-force, JWK injection, kid injection, blank password, and more",
  args: {
    token: tool.schema.string().describe("JWT token to analyze/attack (e.g., 'eyJ0...')"),
    action: tool.schema.enum(["decode", "verify", "bruteforce", "tamper", "all_attacks"]).default("decode").describe("decode=show claims, verify=check signature, bruteforce=crack secret, tamper=try common bypasses, all_attacks=run all tests"),
    target_url: tool.schema.string().optional().describe("Target URL to send forged tokens to (required for tamper/all_attacks)"),
    wordlist: tool.schema.string().optional().describe("Wordlist for brute-force attack (default: /workspace/wordlists/passwords.txt)"),
    header_name: tool.schema.string().default("Authorization").describe("HTTP header name to inject forged token into"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "jwt_attack", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = [args.token]

        if (args.action === "decode") {
          // Just decode/display
          const result = await $`python3 /opt/jwt_tool/jwt_tool.py ${cmdArgs}`.nothrow().timeout(15000)
          const stdout = result.stdout?.toString() || ""
          return JSON.stringify({
            success: true,
            action: "decode",
            token: args.token,
            output: stdout.slice(0, 5000),
            duration: Date.now() - startTime,
          }, null, 2)
        }

        if (args.action === "bruteforce") {
          const wl = args.wordlist || "/workspace/wordlists/passwords.txt"
          cmdArgs.push("-C", "-d", wl)
          const result = await $`python3 /opt/jwt_tool/jwt_tool.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
          const stdout = result.stdout?.toString() || ""
          const cracked = stdout.includes("SECRET KEY") || stdout.includes("Found key")
          const keyMatch = stdout.match(/key:\s*(.+)/i) || stdout.match(/SECRET KEY:\s*(.+)/i)
          return JSON.stringify({
            success: true,
            action: "bruteforce",
            cracked,
            secret: keyMatch?.[1]?.trim() || null,
            output: stdout.slice(0, 3000),
            duration: Date.now() - startTime,
          }, null, 2)
        }

        if (args.action === "tamper" || args.action === "all_attacks") {
          if (!args.target_url) {
            return JSON.stringify({ success: false, error: "target_url required for tamper/all_attacks" }, null, 2)
          }
          // -M at = run all tamper tests, -u = target URL, -np = no proxy
          const attackArgs = [args.token, "-M", "at", "-u", args.target_url, "-np"]
          const result = await $`python3 /opt/jwt_tool/jwt_tool.py ${attackArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
          const stdout = result.stdout?.toString() || ""
          const stderr = result.stderr?.toString() || ""

          // Parse results — jwt_tool marks successes with [+]
          const successes = stdout.split("\n").filter(l => l.includes("[+]") || l.includes("VULNERABLE"))
          const tested = stdout.split("\n").filter(l => l.includes("Sending") || l.includes("Testing")).length

          return JSON.stringify({
            success: true,
            action: args.action,
            target: args.target_url,
            tests_run: tested,
            vulnerabilities_found: successes.length,
            findings: successes.map(l => l.trim()),
            output: stdout.slice(0, 5000),
            stderr: stderr.slice(0, 300) || undefined,
            duration: Date.now() - startTime,
          }, null, 2)
        }

        // verify
        cmdArgs.push("-V")
        if (args.target_url) cmdArgs.push("-u", args.target_url)
        const result = await $`python3 /opt/jwt_tool/jwt_tool.py ${cmdArgs}`.nothrow().timeout(30000)
        const stdout = result.stdout?.toString() || ""
        return JSON.stringify({
          success: true,
          action: "verify",
          valid: stdout.includes("VALID") || stdout.includes("[+]"),
          output: stdout.slice(0, 3000),
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
