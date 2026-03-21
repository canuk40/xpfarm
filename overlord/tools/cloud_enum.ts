import { tool } from "@opencode-ai/plugin"
import { $ } from "./lib/exec"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Enumerate open/public cloud resources for a company keyword across AWS (S3, CloudFront), GCP (Storage, AppEngine, Firebase), and Azure (Blobs, Websites) using cloud_enum",
  args: {
    keyword: tool.schema.string().describe("Company/brand keyword to search (e.g., 'acmecorp'). Multiple: comma-separated."),
    providers: tool.schema.enum(["all", "aws", "gcp", "azure"]).default("all").describe("Which cloud providers to enumerate"),
    mutations: tool.schema.string().optional().describe("Path to custom mutations wordlist file"),
    timeout: tool.schema.number().default(120).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    return instrumentedCall({ toolName: "cloud_enum", args }, async () => {
      const startTime = Date.now()
      try {
        const outFile = "/tmp/cloud_enum_out.txt"
        const keywords = args.keyword.split(",").map(k => k.trim())

        const cmdArgs: string[] = ["--output", outFile]
        for (const kw of keywords) cmdArgs.push("-k", kw)

        if (args.providers === "aws") cmdArgs.push("--disable-gcp", "--disable-azure")
        else if (args.providers === "gcp") cmdArgs.push("--disable-aws", "--disable-azure")
        else if (args.providers === "azure") cmdArgs.push("--disable-aws", "--disable-gcp")

        if (args.mutations) cmdArgs.push("-m", args.mutations)

        const result = await $`python3 /opt/cloud_enum/cloud_enum.py ${cmdArgs}`.nothrow().timeout(args.timeout * 1000 + 10000)
        const stdout = result.stdout?.toString() || ""

        let findings: string[] = []
        try {
          const f = Bun.file(outFile)
          if (await f.exists()) {
            findings = (await f.text()).trim().split("\n").filter(l => l.trim())
            await $`rm -f ${outFile}`.nothrow()
          }
        } catch { /* use stdout */ }

        if (findings.length === 0) {
          findings = stdout.split("\n").filter(l =>
            l.includes("OPEN") || l.includes("open") || l.includes("[+]") || l.includes("http")
          )
        }

        // Categorize by provider
        const aws = findings.filter(l => l.includes("s3") || l.includes("amazonaws") || l.includes("cloudfront"))
        const gcp = findings.filter(l => l.includes("storage.googleapis") || l.includes("appspot") || l.includes("firebaseapp"))
        const azure = findings.filter(l => l.includes("blob.core") || l.includes("azurewebsites") || l.includes("windows.net"))

        return JSON.stringify({
          success: true,
          keywords,
          total_found: findings.length,
          aws_resources: aws,
          gcp_resources: gcp,
          azure_resources: azure,
          all_findings: findings,
          duration: Date.now() - startTime,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
