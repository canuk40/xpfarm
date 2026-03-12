import { appendFileSync, existsSync, mkdirSync } from "fs"
import path from "path"
import { randomBytes } from "crypto"

const LOG_DIR = "/workspace/logs"
const MAX_LOG_SIZE = 10 * 1024 * 1024 // 10MB

// Ensure log directory exists
if (!existsSync(LOG_DIR)) {
  mkdirSync(LOG_DIR, { recursive: true })
}

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3
}

export interface LogMeta {
  tool?: string
  binary?: string
  command?: string
  exitCode?: number
  stderr?: string
  durationMs?: number
  [key: string]: unknown
}

interface StructuredLogEntry {
  timestamp: string
  level: string
  correlationId: string
  message: string
  tool?: string
  binary?: string
  command?: string
  exitCode?: number
  stderr?: string
  durationMs?: number
  meta?: Record<string, unknown>
}

// Correlation ID context — set per agent/tool-chain invocation
let _correlationId = ""

export function setCorrelationContext(id?: string) {
  _correlationId = id || randomBytes(2).toString("hex") // 4 hex chars
}

export function getCorrelationId(): string {
  if (!_correlationId) {
    setCorrelationContext()
  }
  return _correlationId
}

class Logger {
  private logFile: string
  private jsonlFile: string
  private level: LogLevel

  constructor(name: string, level: LogLevel = LogLevel.INFO) {
    this.logFile = path.join(LOG_DIR, `${name}.log`)
    this.jsonlFile = path.join(LOG_DIR, `${name}.jsonl`)
    this.level = level

    // Rotate logs if too large
    this.rotateIfNeeded(this.logFile)
    this.rotateIfNeeded(this.jsonlFile)
  }

  private rotateIfNeeded(filePath: string) {
    try {
      const stats = Bun.file(filePath)
      if (stats.size && stats.size > MAX_LOG_SIZE) {
        const backupFile = `${filePath}.old`
        Bun.write(backupFile, Bun.file(filePath))
        Bun.write(filePath, "") // Clear current
      }
    } catch (e) {
      // File doesn't exist yet, that's fine
    }
  }

  private log(level: LogLevel, message: string, meta?: LogMeta) {
    if (level < this.level) return

    const timestamp = new Date().toISOString()
    const levelStr = LogLevel[level]
    const correlationId = getCorrelationId()
    const toolTag = meta?.tool ? ` [${meta.tool}]` : ""

    // Human-readable log line
    const logLine = `[${timestamp}] [${levelStr}] [${correlationId}]${toolTag} ${message}\n`

    // Structured JSONL entry
    const entry: StructuredLogEntry = {
      timestamp,
      level: levelStr,
      correlationId,
      message,
    }
    if (meta) {
      if (meta.tool) entry.tool = meta.tool
      if (meta.binary) entry.binary = meta.binary
      if (meta.command) entry.command = meta.command
      if (meta.exitCode !== undefined) entry.exitCode = meta.exitCode
      if (meta.stderr) entry.stderr = meta.stderr
      if (meta.durationMs !== undefined) entry.durationMs = meta.durationMs
      // Collect remaining meta keys
      const knownKeys = new Set(["tool", "binary", "command", "exitCode", "stderr", "durationMs"])
      const extra: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(meta)) {
        if (!knownKeys.has(k) && v !== undefined) extra[k] = v
      }
      if (Object.keys(extra).length > 0) entry.meta = extra
    }

    try {
      appendFileSync(this.logFile, logLine)
      appendFileSync(this.jsonlFile, JSON.stringify(entry) + "\n")
    } catch (e) {
      // Fallback to stderr if file logging fails
      console.error(`Failed to write to log file ${this.logFile}:`, e)
    }
  }

  debug(message: string, meta?: LogMeta) {
    this.log(LogLevel.DEBUG, message, meta)
  }

  info(message: string, meta?: LogMeta) {
    this.log(LogLevel.INFO, message, meta)
  }

  warn(message: string, meta?: LogMeta) {
    this.log(LogLevel.WARN, message, meta)
  }

  error(message: string, meta?: LogMeta) {
    this.log(LogLevel.ERROR, message, meta)
  }
}

// Create loggers for different components
export const sessionLogger = new Logger("r2session", LogLevel.DEBUG)
export const toolLogger = new Logger("tools", LogLevel.INFO)
export const errorLogger = new Logger("errors", LogLevel.ERROR)

export default Logger
