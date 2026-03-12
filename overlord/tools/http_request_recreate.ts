import { tool } from "@opencode-ai/plugin"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
    description: "Recreates and safely fires an HTTP request to observe the server response. Use this to understand backend API schemas, C2 registration flows, or to validate hardcoded endpoints found in a binary. This does NOT perform automated scanning or hacking; it just sends exactly what you tell it to.",
    args: {
        url: tool.schema.string().describe("The full URL (e.g., 'http://127.0.0.1/api/login' or 'https://suspicious-domain.com/reg')"),
        method: tool.schema.string().optional().default("GET").describe("HTTP Method ('GET', 'POST', 'PUT', etc.)"),
        headers: tool.schema.string().optional().describe("JSON string of Key-Value map for HTTP headers (e.g., '{\"User-Agent\": \"CustomClient\"}')"),
        body: tool.schema.string().optional().describe("Raw string payload or JSON for POST/PUT requests"),
        timeout: tool.schema.number().optional().default(10000).describe("Timeout in milliseconds (default 10s)")
    },
    async execute(args: any, context: any) {
        return instrumentedCall({ toolName: "http_request_recreate", args }, async () => {
            try {
                const controller = new AbortController()
                const timeoutId = setTimeout(() => controller.abort(), args.timeout)

                const fetchOptions: RequestInit = {
                    method: args.method.toUpperCase(),
                    headers: args.headers || {},
                    signal: controller.signal
                }

                if (args.body && ["POST", "PUT", "PATCH"].includes(fetchOptions.method as string)) {
                    fetchOptions.body = args.body
                }

                console.log(`[*] Sending ${fetchOptions.method} request to ${args.url}...`)

                const response = await fetch(args.url, fetchOptions)
                clearTimeout(timeoutId)

                // Try to parse as JSON, otherwise fall back to text
                const textOutput = await response.text()
                let parsedOutput = textOutput
                try {
                    parsedOutput = JSON.parse(textOutput)
                } catch (e) {
                    // It's just a text/html response
                }

                return JSON.stringify({
                    success: true,
                    status: response.status,
                    statusText: response.statusText,
                    headers: Object.fromEntries(response.headers.entries()),
                    response: parsedOutput
                }, null, 2)

            } catch (error: any) {
                return JSON.stringify({
                    success: false,
                    error: `Failed to execute HTTP request: ${error.message}`,
                    details: "The server might be down, the IP might be dead, or the connection timed out."
                }, null, 2)
            }
        })
    }
})
