import { toolLogger, errorLogger, setCorrelationContext, getCorrelationId, type LogMeta } from "./logger"

interface InstrumentContext {
  toolName: string
  binary?: string
  args: Record<string, unknown>
}

/**
 * Wraps a tool's execute body with automatic entry/exit/error logging.
 * Generates a correlation ID, logs START with args, logs END with duration and output length,
 * and on error logs full context to both toolLogger and errorLogger.
 * Also detects suspicious results (empty output, success:false, very short output).
 */
export async function instrumentedCall<T>(
  ctx: InstrumentContext,
  fn: () => Promise<T>
): Promise<T> {
  setCorrelationContext()
  const correlationId = getCorrelationId()
  const startTime = Date.now()
  const meta: LogMeta = { tool: ctx.toolName, binary: ctx.binary }

  // Sanitize args for logging (truncate large values)
  const sanitizedArgs: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(ctx.args)) {
    if (typeof v === "string" && v.length > 200) {
      sanitizedArgs[k] = v.substring(0, 200) + "...[truncated]"
    } else {
      sanitizedArgs[k] = v
    }
  }

  toolLogger.info(`START ${ctx.toolName}`, { ...meta, args: sanitizedArgs })

  try {
    const result = await fn()
    const durationMs = Date.now() - startTime

    // Detect suspicious results
    let outputLen = 0
    let suspicious = false
    if (typeof result === "string") {
      outputLen = result.length
      try {
        const parsed = JSON.parse(result)
        if (parsed.success === false) {
          suspicious = true
          toolLogger.warn(`${ctx.toolName} returned success:false — ${parsed.error || "no error message"}`, {
            ...meta, durationMs,
          })
        }
      } catch {
        // Not JSON, that's fine
      }
      if (outputLen === 0) {
        suspicious = true
        toolLogger.warn(`${ctx.toolName} returned empty output`, { ...meta, durationMs })
      } else if (outputLen < 10 && !suspicious) {
        toolLogger.warn(`${ctx.toolName} returned suspiciously short output (${outputLen} chars)`, {
          ...meta, durationMs,
        })
      }
    }

    toolLogger.info(`END ${ctx.toolName} (${durationMs}ms, ${outputLen} chars)`, {
      ...meta, durationMs, outputLength: outputLen,
    })

    return result
  } catch (err: any) {
    const durationMs = Date.now() - startTime
    const errMsg = err.message || String(err)
    const stderr = err.stderr?.toString?.() || ""

    toolLogger.error(`ERROR ${ctx.toolName}: ${errMsg}`, {
      ...meta, durationMs, stderr: stderr.substring(0, 1000),
      args: sanitizedArgs, stack: err.stack?.substring(0, 500),
    })
    errorLogger.error(`${ctx.toolName}: ${errMsg}`, {
      ...meta, durationMs, stderr: stderr.substring(0, 1000),
      args: sanitizedArgs, exitCode: err.exitCode,
    })

    throw err
  }
}
