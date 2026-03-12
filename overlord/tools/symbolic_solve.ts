import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import { writeFileSync, existsSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Perform Symbolic Execution on a binary using angr. Finds the input required to reach a 'target' address while avoiding 'avoid' addresses. Great for cracking software keys, bypassing checks, or solving complex branch math.",
    args: {
        binary_path: tool.schema.string().describe("Absolute path to the binary"),
        target_address: tool.schema.string().describe("Hex address of the 'win' instruction to reach (e.g., 0x401234)"),
        avoid_addresses: tool.schema.string().optional().describe("Comma-separated hex addresses to aggressively avoid (e.g., '0x401235, 0x401290')"),
        start_address: tool.schema.string().optional().describe("Optional hex address to start execution from (defaults to entry state)"),
        input_length: tool.schema.number().optional().default(32).describe("Length of the symbolic stdin input to inject (default 32 bytes)"),
        timeout: tool.schema.number().optional().default(120).describe("Timeout in seconds (default 120)")
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "symbolic_solve", args }, async () => {
            if (!existsSync(args.binary_path)) {
                return JSON.stringify({ success: false, error: "Binary not found" })
            }

            const scriptPath = `/tmp/symbolic_${Date.now()}.py`
            const avoidStr = args.avoid_addresses ? `[${args.avoid_addresses.split(",").map((a: string) => `int('${a.trim()}', 16)`).join(", ")}]` : "[]"
            const startStr = args.start_address ? `int('${args.start_address}', 16)` : "None"

            // Build the python angr script
            const pyScript = `
import angr
import sys
import logging

# Quiet down angr logs
logging.getLogger('angr').setLevel(logging.ERROR)

def main():
    try:
        binary_path = "${args.binary_path}"
        project = angr.Project(binary_path, auto_load_libs=False)
        
        target_addr = int('${args.target_address}', 16)
        avoid_addrs = ${avoidStr}
        start_addr = ${startStr}
        input_len = ${args.input_length}
        
        # Setup symbolic stdin
        sym_arg = angr.claripy.BVS('sym_input', 8 * input_len)
        
        if start_addr is not None:
            state = project.factory.blank_state(addr=start_addr, stdin=sym_arg)
        else:
            state = project.factory.entry_state(stdin=sym_arg)
            
        simulation = project.factory.simgr(state)
        
        print(f"Starting symbolic execution... Target: {hex(target_addr)}", flush=True)
        simulation.explore(find=target_addr, avoid=avoid_addrs)
        
        if simulation.found:
            solution_state = simulation.found[0]
            solution_bytes = solution_state.posix.dumps(0)
            print(f"\\n--- SUCCESS ---")
            print(f"Input required to reach target:")
            print(f"Raw Bytes: {solution_bytes}")
            try:
                print(f"ASCII String: {solution_bytes.decode('utf-8', errors='ignore')}")
            except:
                pass
            print(f"Constraints satisfied.")
        else:
            print(f"\\n--- FAILED ---")
            print("Could not find a path to the target address.")
            if simulation.deadended:
                print(f"Reached {len(simulation.deadended)} dead-ends.")
            
    except Exception as e:
        print(f"\\n--- ERROR ---")
        print(str(e))

if __name__ == "__main__":
    main()
`
            writeFileSync(scriptPath, pyScript)

            const result = await $`timeout ${args.timeout} python3 ${scriptPath}`.nothrow()
            const stdout = result.stdout?.toString() || ""
            const stderr = result.stderr?.toString() || ""

            if (result.exitCode === 124) { // timeout code
                return JSON.stringify({
                    success: false,
                    error: `Symbolic execution timed out after ${args.timeout} seconds. State explosion likely. Try providing a specific start_address closer to the target, or avoiding more branches.`,
                    partial_output: stdout
                }, null, 2)
            }

            return JSON.stringify({
                success: result.exitCode === 0 && stdout.includes("SUCCESS"),
                output: stdout.trim(),
                stderr: stderr.trim()
            }, null, 2)
        })
    }
})
