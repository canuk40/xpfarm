import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { existsSync, readFileSync, readdirSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Analyze Android APK structure using apktool. Extracts manifest, permissions, components, and smali code listing.",
    args: {
        apk: tool.schema.string().describe("Path to APK file"),
        full_manifest: tool.schema.boolean().default(true).describe("Return full AndroidManifest.xml content"),
    },
    async execute(args: any, context: any) {
        const apkPath = args.apk.startsWith("/") ? args.apk : path.join(context.directory, args.apk)

        return instrumentedCall({ toolName: "apk_analyze", binary: apkPath, args }, async () => {
            const startTime = Date.now()

            try {
                if (!existsSync(apkPath)) {
                    return JSON.stringify({ success: false, error: `File not found: ${apkPath}` }, null, 2)
                }

                // Check apktool is available
                try {
                    await $`which apktool`.quiet()
                } catch {
                    return JSON.stringify({ success: false, error: "apktool not installed. Run: apt-get install -y apktool" }, null, 2)
                }

                const baseName = path.basename(apkPath, ".apk")
                const outputDir = `/workspace/output/apktool_${baseName}`

                // Run apktool decode
                await $`rm -rf ${outputDir}`.nothrow()
                const result = await $`apktool d -f -o ${outputDir} ${apkPath}`.nothrow().timeout(120000)
                const stderr = result.stderr?.toString() || ""

                // Read AndroidManifest.xml
                const manifestPath = path.join(outputDir, "AndroidManifest.xml")
                let manifest = ""
                if (existsSync(manifestPath)) {
                    manifest = readFileSync(manifestPath, "utf-8")
                }

                // Parse permissions
                const permissions: string[] = []
                const permRegex = /android:name="(android\.permission\.[^"]+)"/g
                let match
                while ((match = permRegex.exec(manifest)) !== null) {
                    permissions.push(match[1])
                }

                // Parse components
                const components: { type: string; name: string; exported: boolean }[] = []
                const componentTypes = ["activity", "service", "receiver", "provider"]
                for (const type of componentTypes) {
                    const regex = new RegExp(`<${type}[^>]*android:name="([^"]+)"[^>]*`, "gi")
                    let m
                    while ((m = regex.exec(manifest)) !== null) {
                        const exported = m[0].includes('android:exported="true"')
                        components.push({ type, name: m[1], exported })
                    }
                }

                // Parse intent filters (simplified)
                const intentFilters: string[] = []
                const actionRegex = /android:name="([^"]+)"/g
                const filterBlocks = manifest.match(/<intent-filter[\s\S]*?<\/intent-filter>/gi) || []
                for (const block of filterBlocks) {
                    let am
                    while ((am = actionRegex.exec(block)) !== null) {
                        if (am[1].startsWith("android.intent.")) {
                            intentFilters.push(am[1])
                        }
                    }
                }

                // List smali directories
                const smaliDirs: string[] = []
                const smaliFiles: string[] = []
                if (existsSync(outputDir)) {
                    const topLevel = readdirSync(outputDir)
                    for (const entry of topLevel) {
                        if (entry.startsWith("smali")) {
                            smaliDirs.push(entry)
                            // Count smali files
                            try {
                                const countResult = await $`find ${path.join(outputDir, entry)} -name "*.smali" | wc -l`.nothrow()
                                const count = parseInt(countResult.stdout?.toString().trim() || "0")
                                smaliFiles.push(`${entry}: ${count} files`)
                            } catch { /* skip */ }
                        }
                    }
                }

                // Check for native libraries
                const libDir = path.join(outputDir, "lib")
                const nativeLibs: string[] = []
                if (existsSync(libDir)) {
                    try {
                        const arches = readdirSync(libDir)
                        for (const arch of arches) {
                            const archDir = path.join(libDir, arch)
                            const libs = readdirSync(archDir).filter((f: string) => f.endsWith(".so"))
                            nativeLibs.push(...libs.map((l: string) => `${arch}/${l}`))
                        }
                    } catch { /* skip */ }
                }

                const exportedComponents = components.filter(c => c.exported)

                return JSON.stringify({
                    success: true,
                    apk: apkPath,
                    outputDir,
                    packageName: (manifest.match(/package="([^"]+)"/) || [])[1] || "unknown",
                    permissions: {
                        total: permissions.length,
                        list: permissions,
                        dangerous: permissions.filter(p =>
                            ["CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
                                "READ_SMS", "SEND_SMS", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE",
                                "READ_EXTERNAL_STORAGE", "READ_CALL_LOG"].some(d => p.includes(d))
                        ),
                    },
                    components: {
                        total: components.length,
                        exported: exportedComponents,
                        all: components,
                    },
                    intentFilters: [...new Set(intentFilters)],
                    smali: smaliFiles,
                    nativeLibs,
                    manifest: args.full_manifest
                        ? (manifest.length > 10000 ? manifest.substring(0, 10000) + "\n<!-- truncated -->" : manifest)
                        : "Use full_manifest=true to see full manifest",
                    attackSurface: {
                        exportedActivities: exportedComponents.filter(c => c.type === "activity").length,
                        exportedServices: exportedComponents.filter(c => c.type === "service").length,
                        exportedReceivers: exportedComponents.filter(c => c.type === "receiver").length,
                        exportedProviders: exportedComponents.filter(c => c.type === "provider").length,
                        dangerousPermissions: permissions.filter(p =>
                            ["CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
                                "READ_SMS", "SEND_SMS", "READ_PHONE_STATE"].some(d => p.includes(d))
                        ).length,
                        hasNativeCode: nativeLibs.length > 0,
                    },
                    duration: Date.now() - startTime,
                }, null, 2)

            } catch (error: any) {
                return JSON.stringify({
                    success: false,
                    error: error.message || String(error),
                    duration: Date.now() - startTime,
                }, null, 2)
            }
        })
    }
})
