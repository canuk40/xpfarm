import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Enumerate subdomains using OWASP Amass — best-in-class active and passive subdomain discovery",
  args: {
    domain: tool.schema.string().describe("Target domain (e.g., 'example.com')"),
    mode: tool.schema.enum(["passive", "active", "brute"]).default("passive").describe("passive=API sources only, active=DNS resolution+scraping, brute=dictionary brute-force"),
    wordlist: tool.schema.string().optional().describe("Wordlist for brute mode (e.g., '/workspace/wordlists/subdomains.txt')"),
    timeout: tool.schema.number().default(300).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "amass_enum", args }, async () => {
      const startTime = Date.now()
      try {
        const cmdArgs: string[] = ["enum", "-d", args.domain, "-o", "/tmp/amass_out.txt", "-silent"]
        if (args.mode === "passive") cmdArgs.push("-passive")
        if (args.mode === "brute" && args.wordlist) cmdArgs.push("-brute", "-w", args.wordlist)

        const result = await $`amass ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stderr = result.stderr?.toString() || ""

        let subdomains: string[] = []
        try {
          const outFile = Bun.file("/tmp/amass_out.txt")
          if (await outFile.exists()) {
            subdomains = (await outFile.text()).trim().split("\n").filter(l => l.trim())
            await $`rm -f /tmp/amass_out.txt`.nothrow()
          }
        } catch { subdomains = result.stdout?.toString().trim().split("\n").filter(l => l.trim()) || [] }

        return JSON.stringify({
          success: subdomains.length > 0,
          domain: args.domain,
          mode: args.mode,
          subdomains,
          count: subdomains.length,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 300) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
