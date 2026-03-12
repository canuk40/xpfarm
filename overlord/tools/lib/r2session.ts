import { spawn, type Subprocess } from "bun"
import { $ } from "bun"
import path from "path"
import { sessionLogger } from "./logger"

interface ArchHints {
  arch: string
  bits: number
}

interface R2Session {
  binary: string
  process: Subprocess
  httpPort: number
  isAnalyzed: boolean
  lastAccessed: number
  arch?: string
  bits?: number
}

/**
 * Detect architecture from `file` output and return r2-compatible arch/bits.
 * Returns null for x86/x86_64 (r2 defaults).
 */
async function detectArch(binaryPath: string): Promise<ArchHints | null> {
  try {
    const fileOutput = (await $`file ${binaryPath}`.text()).trim()

    if (fileOutput.includes("Atmel AVR") || fileOutput.includes("AVR")) {
      return { arch: "avr", bits: 16 }
    }
    if (fileOutput.includes("aarch64") || fileOutput.includes("ARM aarch64")) {
      return { arch: "arm", bits: 64 }
    }
    if (fileOutput.includes("ARM,") || fileOutput.includes("ARM EABI")) {
      return { arch: "arm", bits: 32 }
    }
    if (fileOutput.includes("MIPS64")) {
      return { arch: "mips", bits: 64 }
    }
    if (fileOutput.includes("MIPS")) {
      return { arch: "mips", bits: 32 }
    }
    if (fileOutput.includes("PowerPC")) {
      return { arch: "ppc", bits: 32 }
    }
    // x86-64 and Intel 80386 are r2 defaults — skip
    if (fileOutput.includes("x86-64") || fileOutput.includes("x86_64") ||
        fileOutput.includes("Intel 80386") || fileOutput.includes("i386")) {
      return null
    }

    return null
  } catch (e) {
    sessionLogger.warn(`Failed to detect architecture for ${binaryPath}: ${e}`)
    return null
  }
}

const sessions = new Map<string, R2Session>()
const MAX_SESSIONS = 5
const SESSION_TIMEOUT_MS = 60 * 60 * 1000
let nextPort = 9090

// Simple mutex lock for session operations
let sessionLockPromise: Promise<void> = Promise.resolve()

async function withSessionLock<T>(fn: () => Promise<T>): Promise<T> {
  // Wait for current lock to release
  await sessionLockPromise
  
  // Create a new deferred promise for this operation
  let release: () => void
  const newLock = new Promise<void>(resolve => { release = resolve })
  
  // Replace global lock with our new lock
  sessionLockPromise = sessionLockPromise.then(() => newLock)
  
  try {
    // Execute the function
    const result = await fn()
    return result
  } finally {
    // Always release the lock
    release!()
  }
}

export async function getOrCreateSession(binaryPath: string): Promise<R2Session> {
  return withSessionLock(async () => {
    const normalizedPath = path.resolve(binaryPath)

    // Return existing session if alive
    if (sessions.has(normalizedPath)) {
      const session = sessions.get(normalizedPath)!

      // Check if HTTP server is still responding
      try {
        const response = await fetch(`http://localhost:${session.httpPort}/cmd/?V`, {
          signal: AbortSignal.timeout(1000)
        })
        if (response.ok) {
          session.lastAccessed = Date.now()
          sessionLogger.debug(`Reusing existing session for ${normalizedPath} on port ${session.httpPort}`)
          return session
        }
      } catch (e) {
        // Session died, clean it up
        sessionLogger.warn(`Session for ${normalizedPath} not responding, recreating...`)
        session.process.kill()
        sessions.delete(normalizedPath)
      }
    }

    // Cleanup old sessions if at limit
    if (sessions.size >= MAX_SESSIONS) {
      cleanupOldestSession()
    }

    const port = nextPort++
    sessionLogger.info(`Creating new HTTP session on port ${port} for ${normalizedPath}`)

    // Spawn r2 with HTTP server mode
    const proc = spawn([
      "r2",
      "-q",
      "-c", `=h ${port}`,
      normalizedPath
    ], {
      stdout: "pipe",
      stderr: "pipe",
    })

    // Wait for HTTP server to be ready
    let attempts = 0
    const maxAttempts = 50 // 5 seconds max

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 100))

      try {
        const response = await fetch(`http://localhost:${port}/cmd/?V`, {
          signal: AbortSignal.timeout(500)
        })
        if (response.ok) {
          sessionLogger.info(`HTTP server ready on port ${port}`)
          break
        }
      } catch (e) {
        // Server not ready yet
      }

      attempts++
    }

    if (attempts >= maxAttempts) {
      proc.kill()
      throw new Error(`r2 HTTP server failed to start on port ${port} after 5 seconds`)
    }

    // Auto-detect architecture and set r2 config before any analysis
    const archHints = await detectArch(normalizedPath)
    if (archHints) {
      sessionLogger.info(`Detected architecture: ${archHints.arch} ${archHints.bits}-bit for ${normalizedPath}`)
      try {
        await fetch(`http://localhost:${port}/cmd/${encodeURIComponent(`e asm.arch=${archHints.arch}`)}`, { signal: AbortSignal.timeout(2000) })
        await fetch(`http://localhost:${port}/cmd/${encodeURIComponent(`e asm.bits=${archHints.bits}`)}`, { signal: AbortSignal.timeout(2000) })
      } catch (e) {
        sessionLogger.warn(`Failed to set arch hints for ${normalizedPath}: ${e}`)
      }
    }

    const session: R2Session = {
      binary: normalizedPath,
      process: proc,
      httpPort: port,
      isAnalyzed: false,
      lastAccessed: Date.now(),
      arch: archHints?.arch,
      bits: archHints?.bits,
    }

    sessions.set(normalizedPath, session)
    return session
  })
}

export async function runCommand(binaryPath: string, cmd: string, timeoutMs: number = 30000): Promise<string> {
  const session = await getOrCreateSession(binaryPath)

  // URL encode the command
  const encodedCmd = encodeURIComponent(cmd)
  const url = `http://localhost:${session.httpPort}/cmd/${encodedCmd}`

  sessionLogger.debug(`Running command: ${cmd}`)

  let response: Response
  try {
    response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs)
    })
  } catch (e) {
    // Connection error — session likely died. Delete and retry once.
    sessionLogger.warn(`Command fetch failed for ${binaryPath}, retrying: ${e}`)
    const normalizedPath = path.resolve(binaryPath)
    const deadSession = sessions.get(normalizedPath)
    if (deadSession) {
      try { deadSession.process.kill() } catch {}
      sessions.delete(normalizedPath)
    }

    // Recreate session and retry
    const newSession = await getOrCreateSession(binaryPath)
    const retryUrl = `http://localhost:${newSession.httpPort}/cmd/${encodedCmd}`
    response = await fetch(retryUrl, {
      signal: AbortSignal.timeout(timeoutMs)
    })
  }

  if (!response.ok) {
    throw new Error(`r2 HTTP error: ${response.status} ${response.statusText}`)
  }

  const result = await response.text()
  sessionLogger.debug(`Command completed, output length: ${result.length}`)

  // Warn when data-producing commands return empty output
  // Analysis commands (aa, aaa, aaaa, af, aF) normally produce no output
  if (result.trim().length === 0 && !cmd.match(/^(aa|aaa|aaaa|af|aF)\b/)) {
    sessionLogger.warn(`Command returned empty output: ${cmd}`, { binary: binaryPath, command: cmd })
  }

  return result
}

function cleanupOldestSession() {
  let oldest: R2Session | null = null
  let oldestPath = ""

  for (const [path, session] of sessions.entries()) {
    if (!oldest || session.lastAccessed < oldest.lastAccessed) {
      oldest = session
      oldestPath = path
    }
  }

  if (oldest) {
    sessionLogger.info(`Cleaning up oldest session: ${oldestPath}`)
    oldest.process.kill()
    sessions.delete(oldestPath)
  }
}

export function cleanupSessions(maxAgeMs: number = SESSION_TIMEOUT_MS) {
  const now = Date.now()
  for (const [path, session] of sessions.entries()) {
    if (now - session.lastAccessed > maxAgeMs) {
      sessionLogger.info(`Cleaning up idle session: ${path}`)
      session.process.kill()
      sessions.delete(path)
    }
  }
}

// Periodic cleanup of idle sessions (every 10 minutes)
setInterval(() => cleanupSessions(), 10 * 60 * 1000)

export function markAsAnalyzed(binaryPath: string) {
  const normalizedPath = path.resolve(binaryPath)
  const session = sessions.get(normalizedPath)
  if (session) {
    session.isAnalyzed = true
    sessionLogger.info(`Marked ${normalizedPath} as analyzed`)
  }
}

export function isAnalyzed(binaryPath: string): boolean {
  const normalizedPath = path.resolve(binaryPath)
  return sessions.get(normalizedPath)?.isAnalyzed || false
}

export function unmarkAnalyzed(binaryPath: string) {
  const normalizedPath = path.resolve(binaryPath)
  const session = sessions.get(normalizedPath)
  if (session) {
    session.isAnalyzed = false
    sessionLogger.info(`Unmarked ${normalizedPath} as analyzed (arch change requires re-analysis)`)
  }
}

export function getSessionArch(binaryPath: string): { arch?: string; bits?: number } {
  const normalizedPath = path.resolve(binaryPath)
  const session = sessions.get(normalizedPath)
  return { arch: session?.arch, bits: session?.bits }
}
