import { tool } from "@opencode-ai/plugin"
import { instrumentedCall } from "./lib/tool_instrument"
import { exec } from "child_process"
import { promisify } from "util"
import path from "path"
import fs from "fs"

const execAsync = promisify(exec)

export default tool({
    description: "Extracts native C/C++ libraries (.so files) from an Android APK and dumps them to the workspace so they can be analyzed by @re-decompiler and radare2. Use this when you find JNI 'native' declarations in Java source code to cross the Native Boundary.",
    args: {
        apk_path: tool.schema.string().describe("Absolute path to the target .apk file (e.g. /workspace/binaries/target.apk)"),
        architecture: tool.schema.enum(["arm64-v8a", "armeabi-v7a", "x86", "x86_64", "all"]).default("arm64-v8a").describe("Which architecture's libraries to extract. Usually arm64-v8a is best for modern analysis.")
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "apk_extract_native", args }, async () => {
            if (!fs.existsSync(args.apk_path)) {
                return JSON.stringify({ success: false, error: `APK not found at ${args.apk_path}` }, null, 2)
            }

            const outputBaseDir = "/workspace/output/native_libs"
            const apkName = path.basename(args.apk_path, '.apk')
            const targetOutDir = path.join(outputBaseDir, apkName)

            // Ensure output directory exists before writing
            fs.mkdirSync(targetOutDir, { recursive: true })

            // Create a temporary extraction directory inside the target out dir
            const tempExtractDir = path.join(targetOutDir, 'temp_unzip')
            fs.mkdirSync(tempExtractDir, { recursive: true })

            try {
                // We use apktool instead of unzip because it's already installed and handles APK resources better
                // However, for just grabbing .so files, unzip is much faster. Since we installed unzip earlier, let's use it.
                // We will specifically only extract the lib/ folder to save massive amounts of time on large APKs.

                let archFilter = "lib/*"
                if (args.architecture !== "all") {
                    archFilter = `lib/${args.architecture}/*`
                }

                console.log(`[*] Extracting native libraries(${archFilter}) from ${apkName}.apk...`)

                // Using standard unzip to grab just the libraries
                const { stdout, stderr } = await execAsync(`unzip -o -q "${args.apk_path}" "${archFilter}" -d "${tempExtractDir}"`)

                // Move them to a cleaner flat structure
                const extractedLibs: string[] = []

                // Read what was extracted
                const libDir = path.join(tempExtractDir, 'lib')
                if (!fs.existsSync(libDir)) {
                    // Clean up
                    fs.rmSync(tempExtractDir, { recursive: true, force: true })
                    return JSON.stringify({
                        success: false,
                        error: "No native libraries (lib/ directory) found in this APK."
                    }, null, 2)
                }

                // Recursively find all .so files
                const findSoFiles = (dir: string) => {
                    const files = fs.readdirSync(dir)
                    for (const file of files) {
                        const fullPath = path.join(dir, file)
                        if (fs.statSync(fullPath).isDirectory()) {
                            findSoFiles(fullPath)
                        } else if (file.endsWith('.so')) {
                            // Move it to the main output dir with arch prefixed to prevent collisions
                            const relativePath = path.relative(libDir, fullPath)
                            // e.g., arm64-v8a/libnative.so -> arm64-v8a_libnative.so
                            const flatName = relativePath.replace(/\\/g, '/').replace('/', '_')
                            const finalDest = path.join(targetOutDir, flatName)

                            fs.copyFileSync(fullPath, finalDest)
                            extractedLibs.push(finalDest)
                        }
                    }
                }

                findSoFiles(libDir)

                // Clean up the temp unzip directory
                fs.rmSync(tempExtractDir, { recursive: true, force: true })

                if (extractedLibs.length === 0) {
                    return JSON.stringify({
                        success: false,
                        error: `No .so files found for architecture ${args.architecture} in this APK.`
                    }, null, 2)
                }

                return JSON.stringify({
                    success: true,
                    apk: apkName,
                    architecture_requested: args.architecture,
                    total_libraries_extracted: extractedLibs.length,
                    output_directory: targetOutDir,
                    extracted_files: extractedLibs,
                    next_steps: `Pass these absolute file paths to the Orchestrator, or instruct @re - decompiler to run r2triage against them.`
                }, null, 2)

            } catch (err: any) {
                // Ensure cleanup even on error
                if (fs.existsSync(tempExtractDir)) {
                    fs.rmSync(tempExtractDir, { recursive: true, force: true })
                }

                if (err.message.includes("cannot find or open")) {
                    return JSON.stringify({ success: false, error: "Failed to unzip APK. File may be corrupted." }, null, 2)
                }
                if (err.message.includes("filename not matched")) {
                    return JSON.stringify({ success: false, error: `Architecture ${args.architecture} not found in this APK.` }, null, 2)
                }

                return JSON.stringify({ success: false, error: err.message }, null, 2)
            }
        })
    }
})
