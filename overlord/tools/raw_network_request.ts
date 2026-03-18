import { tool } from "@opencode-ai/plugin"
import { instrumentedCall } from "./lib/tool_instrument"
import net from "net"
import dgram from "dgram"

export default tool({
    description: "Recreates and fires a raw TCP or UDP network request. Use this to understand custom proprietary protocols, reconstruct binary network interactions, or validate hardcoded binary protocol structures. This does NOT perform automated scanning or hacking; it just sends exactly what you tell it to.",
    args: {
        host: tool.schema.string().describe("The target IP address or hostname (e.g., '127.0.0.1' or 'c2-server.com')"),
        port: tool.schema.number().describe("The target port number (e.g., 4444)"),
        protocol: tool.schema.enum(["tcp", "udp"]).default("tcp").describe("Network protocol to use, either 'tcp' or 'udp'"),
        payload_hex: tool.schema.string().optional().describe("Raw hex string payload to send (e.g., 'deadbeef00000001'). Used for binary protocols."),
        payload_text: tool.schema.string().optional().describe("Raw text/string payload to send (e.g., 'HELO server\\n'). Used for text protocols."),
        timeout: tool.schema.number().optional().default(10000).describe("Timeout in milliseconds (default 10s)")
    },
    async execute(args, context) {
        return instrumentedCall({ toolName: "raw_network_request", args }, async () => {
            if (!args.payload_hex && !args.payload_text) {
                return JSON.stringify({ success: false, error: "Must provide either payload_hex or payload_text" }, null, 2)
            }

            let dataBuffer: Buffer
            if (args.payload_hex) {
                dataBuffer = Buffer.from(args.payload_hex.replace(/\s+/g, ''), 'hex')
            } else {
                dataBuffer = Buffer.from(args.payload_text || '', 'utf-8')
            }

            console.log(`[*] Sending ${dataBuffer.length} bytes via ${args.protocol.toUpperCase()} to ${args.host}:${args.port}...`)

            return new Promise((resolve) => {
                let responseData = Buffer.alloc(0)
                let isResolved = false

                const finalize = (success: boolean, errorMsg?: string) => {
                    if (isResolved) return
                    isResolved = true

                    const responseHex = responseData.toString('hex')
                    let responseAscii = responseData.toString('utf-8')
                    // Simple check if it looks like binary garbage
                    if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(responseAscii)) {
                        responseAscii = "[Binary Data - representation hidden. Use response_hex instead]"
                    }

                    resolve(JSON.stringify({
                        success,
                        protocol: args.protocol,
                        target: `${args.host}:${args.port}`,
                        bytes_sent: dataBuffer.length,
                        bytes_received: responseData.length,
                        response_hex: responseHex,
                        response_text: responseAscii,
                        ...(errorMsg ? { error: errorMsg } : {})
                    }, null, 2))
                }

                if (args.protocol === 'tcp') {
                    const client = new net.Socket()

                    client.setTimeout(args.timeout)

                    client.connect(args.port, args.host, () => {
                        client.write(dataBuffer)
                    })

                    client.on('data', (data) => {
                        responseData = Buffer.concat([responseData, data])
                        // Assuming request-reply architecture. We close after 1 chunk.
                        // For complex multi-packet responses, we rely on the timeout to gather all chunks before closing.
                    })

                    client.on('timeout', () => {
                        client.destroy()
                        finalize(true) // Timeout after gathering data is fine
                    })

                    client.on('error', (err) => {
                        finalize(false, `TCP Connection Error: ${err.message}`)
                    })

                    client.on('close', () => {
                        finalize(true)
                    })
                } else {
                    // UDP
                    const client = dgram.createSocket('udp4')

                    client.send(dataBuffer, args.port, args.host, (err) => {
                        if (err) {
                            client.close()
                            finalize(false, `UDP Send Error: ${err.message}`)
                        }
                    })

                    client.on('message', (msg, rinfo) => {
                        responseData = msg
                        client.close()
                    })

                    client.on('error', (err) => {
                        client.close()
                        finalize(false, `UDP Socket Error: ${err.message}`)
                    })

                    // Handle timeout manually for UDP since it's connectionless
                    setTimeout(() => {
                        client.close()
                        finalize(true)
                    }, args.timeout)
                }
            })
        })
    }
})
