import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import { writeFileSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Generates an AFL++ / libFuzzer C++ fuzzing harness for a specific target function in a binary.",
    args: {
        target_function: tool.schema.string().describe("Name of the C/C++ function to fuzz (e.g., 'parse_input', 'decrypt_buffer')"),
        argument_types: tool.schema.string().describe("Comma-separated list of expected C types for the function arguments (e.g., 'char*, size_t')"),
        is_cpp: tool.schema.boolean().optional().default(false).describe("Set to true if targeting a C++ binary/class method")
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "fuzz_harness_gen", args }, async () => {
            const outputPath = `/workspace/output/fuzz_${args.target_function}_${Date.now()}.cc`

            // Build argument extraction logic inside the fuzzer
            let argPrep = ""
            let callArgs = []

            const argTypesArray = args.argument_types.split(",").map((s: string) => s.trim())
            for (let i = 0; i < argTypesArray.length; i++) {
                const type = argTypesArray[i]
                if (type.includes("char *") || type.includes("char*") || type === "string") {
                    argPrep += `    // Ensure null-termination for string argument ${i}\n`
                    argPrep += `    std::string arg${i}(reinterpret_cast<const char*>(data), size);\n`
                    callArgs.push(`arg${i}.c_str()`)
                } else if (type.includes("size_t") || type.includes("int") || type.includes("long")) {
                    argPrep += `    // Use fuzz data size for numeric argument ${i}\n`
                    argPrep += `    ${type} arg${i} = static_cast<${type}>(size);\n`
                    callArgs.push(`arg${i}`)
                } else if (type.includes("void *") || type.includes("void*") || type.includes("uint8_t*")) {
                    argPrep += `    // Raw buffer pointer for argument ${i}\n`
                    argPrep += `    ${type} arg${i} = const_cast<${type}>(reinterpret_cast<const void*>(data));\n`
                    callArgs.push(`arg${i}`)
                } else {
                    argPrep += `    // Unrecognized type: ${type}. Defaulting to casting fuzz buffer.\n`
                    argPrep += `    ${type} arg${i} = (${type})(data);\n`
                    callArgs.push(`arg${i}`)
                }
            }

            const cppScript = `
#include <stdint.h>
#include <stddef.h>
#include <string>

${args.is_cpp ? 'extern "C" {' : ''}
// Declare the target function prototype
extern int ${args.target_function}(${args.argument_types});
${args.is_cpp ? '}' : ''}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0; // Skip empty inputs

${argPrep}

    // Call the target function
    ${args.target_function}(${callArgs.join(", ")});

    return 0; // Return 0 to indicate successful execution
}
`
            writeFileSync(outputPath, cppScript.trim())

            return JSON.stringify({
                success: true,
                message: `libFuzzer harness successfully generated at ${outputPath}`,
                hint: `To compile and run: clang++ -g -O1 -fsanitize=fuzzer,address ${outputPath} target_binary.o -o fuzzer_bin && ./fuzzer_bin`
            }, null, 2)
        })
    }
})
