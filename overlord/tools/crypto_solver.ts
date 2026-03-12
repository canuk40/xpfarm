import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import { writeFileSync } from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Chains cryptographic operations to decrypt or decode data blobs. Think of this as an automated scriptable CyberChef. Supported operations (must strictly follow this exact formatting inside the operations array payload): 'xor:key_hex=4141', 'aes_cbc:key_hex=...,iv_hex=...', 'aes_ecb:key_hex=...', 'rc4:key_hex=...', 'rc4:key_text=secret', 'base64_decode', 'base64_encode'.",
    args: {
        input_hex: tool.schema.string().describe("The raw hex string of the data to decrypt/decode (e.g., '414243')"),
        operations_json: tool.schema.string().describe("A JSON string representing an array of operations. Examples: [\"base64_decode\", \"xor:key_hex=4141\"] or [\"rc4:key_text=secret\"] or [\"aes_cbc:key_hex=0011..,iv_hex=aabb..\"]")
    },
    async execute(args, context) {
        return instrumentedCall({ toolName: "crypto_solver", args }, async () => {
            try {
                const pyScriptPath = `/tmp/crypto_solve_${Date.now()}.py`

                const pyScript = `
import sys
import json
import base64
from Crypto.Cipher import AES, ARC4

def perform_ops(input_hex, ops_json):
    try:
        data = bytes.fromhex(input_hex)
        ops = json.loads(ops_json)
        
        for op in ops:
            if op == "base64_decode":
                data = base64.b64decode(data)
            elif op == "base64_encode":
                data = base64.b64encode(data)
            elif op.startswith("xor:"):
                key_hex = op.split("key_hex=")[1].split(",")[0]
                key = bytes.fromhex(key_hex)
                data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            elif op.startswith("rc4:"):
                if "key_hex=" in op:
                    key = bytes.fromhex(op.split("key_hex=")[1].split(",")[0])
                else:
                    key = op.split("key_text=")[1].split(",")[0].encode()
                cipher = ARC4.new(key)
                data = cipher.decrypt(data)
            elif op.startswith("aes_cbc:"):
                key = bytes.fromhex(op.split("key_hex=")[1].split(",")[0])
                iv = bytes.fromhex(op.split("iv_hex=")[1].split(",")[0])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data = cipher.decrypt(data)
            elif op.startswith("aes_ecb:"):
                key = bytes.fromhex(op.split("key_hex=")[1].split(",")[0])
                cipher = AES.new(key, AES.MODE_ECB)
                data = cipher.decrypt(data)
            else:
                return {"success": False, "error": f"Unknown operation: {op}"}
                
        decoded_ascii = data.decode('utf-8', errors='ignore')
        return {"success": True, "output_hex": data.hex(), "output_ascii": decoded_ascii}
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    res = perform_ops('${args.input_hex.replace(/'/g, "\\'")}', '${args.operations_json.replace(/'/g, "\\'")}')
    print(json.dumps(res))
`
                writeFileSync(pyScriptPath, pyScript)

                const result = await $`python3 ${pyScriptPath}`.nothrow()
                if (result.exitCode !== 0) {
                    return JSON.stringify({ success: false, error: "Python script failed", stderr: result.stderr.toString() })
                }

                return result.stdout.toString().trim()
            } catch (e: any) {
                return JSON.stringify({ success: false, error: e.message })
            }
        })
    }
})
