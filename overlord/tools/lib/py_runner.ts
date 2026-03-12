import { spawn } from "bun"
import { toolLogger, errorLogger, type LogMeta } from "./logger"

interface PythonResult {
  stdout: string
  stderr: string
  exitCode: number
}

/**
 * Runs a Python helper script with separate stdout/stderr capture.
 * Previously, `$\`python3 ${helper} ${payload}\`.text()` lost stderr entirely.
 * This captures both streams, logs stderr at WARN, and logs non-zero exit codes at ERROR.
 */
export async function runPythonHelper(
  toolName: string,
  helperPath: string,
  payload: string,
  timeoutMs: number = 60000
): Promise<PythonResult> {
  const meta: LogMeta = { tool: toolName, command: `python3 ${helperPath}` }

  toolLogger.debug(`Running Python helper: ${helperPath}`, meta)

  const proc = spawn(["python3", helperPath, payload], {
    stdout: "pipe",
    stderr: "pipe",
    timeout: timeoutMs,
  })

  // Read stdout and stderr in parallel
  const stdoutChunks: Uint8Array[] = []
  const stderrChunks: Uint8Array[] = []

  const stdoutReader = proc.stdout.getReader()
  const stderrReader = proc.stderr.getReader()

  const readStream = async (reader: ReadableStreamDefaultReader<Uint8Array>, chunks: Uint8Array[]) => {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
    }
  }

  await Promise.all([
    readStream(stdoutReader, stdoutChunks),
    readStream(stderrReader, stderrChunks),
  ])

  await proc.exited

  const decoder = new TextDecoder()
  const stdout = stdoutChunks.map(c => decoder.decode(c)).join("")
  const stderr = stderrChunks.map(c => decoder.decode(c)).join("")
  const exitCode = proc.exitCode ?? 1

  // Log stderr if present (Python helper diagnostics)
  if (stderr.trim()) {
    toolLogger.warn(`${toolName} Python stderr: ${stderr.trim().substring(0, 500)}`, {
      ...meta, stderr: stderr.trim().substring(0, 1000),
    })
  }

  // Log non-zero exit codes
  if (exitCode !== 0) {
    errorLogger.error(`${toolName} Python helper exited with code ${exitCode}`, {
      ...meta,
      exitCode,
      stderr: stderr.trim().substring(0, 1000),
    })
  }

  return { stdout, stderr, exitCode }
}
