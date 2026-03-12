import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import { existsSync, readdirSync, readFileSync, statSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Decompile Android APK/DEX files to Java source code using JADX. Returns manifest, class listing, and optionally source of a specific class.",
    args: {
        apk: tool.schema.string().describe("Path to APK or DEX file"),
        class_name: tool.schema.string().optional().describe("Full class name to return source for (e.g., 'com.example.MainActivity'). If omitted, returns class listing only."),
        decompile_all: tool.schema.boolean().default(false).describe("If true, decompile all classes (slower). Default: decompile on demand."),
        timeout: tool.schema.number().optional().default(60000).describe("Timeout in milliseconds (default 60s)")
    },
    async execute(args: any, context: any) {
        const apkPath = args.apk.startsWith("/") ? args.apk : path.join(context.directory, args.apk)

        return instrumentedCall({ toolName: "jadx_decompile", args }, async () => {
            const startTime = Date.now()

            try {
                if (!existsSync(apkPath)) {
                    return JSON.stringify({ success: false, error: `File not found: ${apkPath}` }, null, 2)
                }

                // Check JADX is available
                try {
                    await $`which jadx`.quiet()
                } catch {
                    return JSON.stringify({ success: false, error: "JADX not installed. Run: apt-get install -y jadx or install from GitHub releases." }, null, 2)
                }

                const baseName = path.basename(apkPath, path.extname(apkPath))
                const outputDir = `/workspace/output/jadx_${baseName}`

                // Run JADX decompilation
                const jadxArgs = [
                    "-d", outputDir,
                    "--no-res",  // skip resources for speed unless needed
                    "--show-bad-code",  // show decompilation issues rather than hiding them
                    apkPath,
                ]

                if (!args.decompile_all) {
                    jadxArgs.push("--no-imports")  // faster
                }

                // Run JADX with increased heap size to prevent OOM on large APKs
                const result = await $`jadx ${jadxArgs}`.env({ ...process.env, JAVA_OPTS: "-Xmx8G" }).nothrow().timeout(120000)
                const stderr = result.stderr?.toString() || ""

                // Read AndroidManifest.xml if it exists
                let manifest = ""
                // JADX puts resources in resources/ subdir; try the original APK for manifest
                const manifestPath = path.join(outputDir, "resources", "AndroidManifest.xml")
                if (existsSync(manifestPath)) {
                    manifest = readFileSync(manifestPath, "utf-8")
                } else {
                    // Try extracting manifest via apktool as fallback
                    try {
                        const aapt = await $`aapt2 dump xmltree ${apkPath} --file AndroidManifest.xml`.nothrow()
                        manifest = aapt.stdout?.toString() || "Manifest extraction failed"
                    } catch {
                        manifest = "Manifest not available (run apk_analyze for full manifest)"
                    }
                }

                // List decompiled classes
                const sourcesDir = path.join(outputDir, "sources")
                const classes: string[] = []
                if (existsSync(sourcesDir)) {
                    const walkDir = (dir: string, prefix: string = "") => {
                        try {
                            const entries = readdirSync(dir)
                            for (const entry of entries) {
                                const fullPath = path.join(dir, entry)
                                const stat = statSync(fullPath)
                                if (stat.isDirectory()) {
                                    walkDir(fullPath, prefix ? `${prefix}.${entry}` : entry)
                                } else if (entry.endsWith(".java")) {
                                    const className = prefix ? `${prefix}.${entry.replace(".java", "")}` : entry.replace(".java", "")
                                    classes.push(className)
                                }
                            }
                        } catch { /* skip unreadable dirs */ }
                    }
                    walkDir(sourcesDir)
                }

                // If specific class requested, return its source
                let classSource = ""
                if (args.class_name) {
                    const classPath = path.join(sourcesDir, ...args.class_name.split(".")) + ".java"
                    if (existsSync(classPath)) {
                        const content = readFileSync(classPath, "utf-8")
                        // Truncate if too large
                        classSource = content.length > 15000 ? content.substring(0, 15000) + "\n\n// ... truncated (use bash to read full file)" : content
                    } else {
                        classSource = `Class not found at ${classPath}. Check class listing for available classes.`
                    }
                }

                // Extract package name from manifest
                const pkgMatch = manifest.match(/package="([^"]+)"/) || manifest.match(/package\s*=\s*"([^"]+)"/)
                const packageName = pkgMatch?.[1] || "unknown"

                return JSON.stringify({
                    success: true,
                    apk: apkPath,
                    outputDir,
                    packageName,
                    totalClasses: classes.length,
                    classes: classes.slice(0, 100),  // cap listing at 100
                    classesNote: classes.length > 100 ? `Showing 100 of ${classes.length} classes. Use bash to explore ${sourcesDir}` : undefined,
                    manifest: manifest.length > 5000 ? manifest.substring(0, 5000) + "\n<!-- truncated -->" : manifest,
                    requestedClass: args.class_name ? {
                        name: args.class_name,
                        source: classSource,
                    } : undefined,
                    warnings: stderr ? stderr.split("\n").filter((l: string) => l.includes("WARN") || l.includes("ERROR")).slice(0, 10) : [],
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
