import { tool } from "@opencode-ai/plugin"
import { instrumentedCall } from "./lib/tool_instrument"
import { readFileSync, existsSync } from "fs"

export default tool({
    description: "Uploads an APK to the local MobSF (Mobile Security Framework) REST API for deep static analysis. Returns a JSON string containing the findings (hardcoded secrets, exported activities, weak crypto). Use this as the very first step in APK analysis before manual decompilation.",
    args: {
        apk_path: tool.schema.string().describe("Absolute path to the APK file to scan")
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "mobsf_scan", args }, async () => {
            if (!existsSync(args.apk_path)) {
                return JSON.stringify({ success: false, error: "APK not found at path" })
            }

            try {
                // MobSF runs on a separate container exposed to the host network
                const MOBSF_API = "http://mobsf:8000/api/v1"
                const API_KEY = "dummy_api_key_for_local_mobsf" // Assuming local dev setup without auth enforcement, or default config

                console.log(`[*] Uploading ${args.apk_path} to MobSF... (This takes a moment)`)

                // 1. Upload APK
                const fileBuf = readFileSync(args.apk_path)
                const formData = new FormData()
                const blob = new Blob([fileBuf], { type: 'application/octet-stream' })
                formData.append('file', blob, args.apk_path.split('/').pop() || 'app.apk')

                const uploadRes = await fetch(`${MOBSF_API}/upload`, {
                    method: 'POST',
                    headers: { 'Authorization': API_KEY },
                    body: formData
                })

                if (!uploadRes.ok) {
                    throw new Error(`MobSF Upload Failed: ${uploadRes.statusText}`)
                }

                const uploadData = await uploadRes.json()
                const { hash, file_name } = uploadData

                console.log(`[*] Scan started for Hash: ${hash}...`)

                // 2. Scan APK
                const scanRes = await fetch(`${MOBSF_API}/scan`, {
                    method: 'POST',
                    headers: {
                        'Authorization': API_KEY,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({ hash: hash, file_name: file_name })
                })

                if (!scanRes.ok) {
                    throw new Error(`MobSF Scan Failed: ${scanRes.statusText}`)
                }

                // Instead of hitting /report_json which returns a massive file, 
                // we parse the direct scan output for the most actionable LLM items
                const scanData: any = await scanRes.json()

                const findings = {
                    package_name: scanData.package_name,
                    main_activity: scanData.main_activity,
                    exported_activities: scanData.exported_activities,
                    browsable_activities: scanData.browsable_activities,
                    permissions_dangerous: Object.keys(scanData.permissions || {}).filter(k => scanData.permissions[k].status === 'dangerous'),
                    hardcoded_secrets: scanData.secrets,
                    trackers_detected: scanData.trackers,
                    vulnerable_components: scanData.manifest_analysis?.filter((item: any) => item.stat === 'high')
                }

                return JSON.stringify({
                    success: true,
                    mobsf_findings: findings
                }, null, 2)

            } catch (e: any) {
                return JSON.stringify({ success: false, error: e.message })
            }
        })
    }
})
