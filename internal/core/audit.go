package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditMaxBytes is the rotation threshold (5 MB).
const auditMaxBytes = 5 * 1024 * 1024

// AuditEvent represents a single structured log entry.
type AuditEvent struct {
	Timestamp  string `json:"ts"`
	Event      string `json:"event"`             // scan_start, scan_done, stage_start, stage_done, stage_error, stage_quarantined, stage_retry, target_skip
	Target     string `json:"target,omitempty"`
	Asset      string `json:"asset,omitempty"`
	Stage      string `json:"stage,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type auditLogger struct {
	mu       sync.Mutex
	f        *os.File
	written  int64
	rotation int
	dir      string
}

var globalAudit = &auditLogger{dir: "data"}

func init() {
	_ = os.MkdirAll("data", 0755)
	globalAudit.open()
}

func (a *auditLogger) open() {
	path := filepath.Join(a.dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	info, _ := f.Stat()
	if info != nil {
		a.written = info.Size()
	}
	a.f = f
}

func (a *auditLogger) rotate() {
	if a.f != nil {
		_ = a.f.Close()
	}
	a.rotation++
	old := filepath.Join(a.dir, "audit.jsonl")
	rotated := filepath.Join(a.dir, fmt.Sprintf("audit_%04d.jsonl", a.rotation))
	_ = os.Rename(old, rotated)
	a.written = 0
	a.open()
}

func (a *auditLogger) write(evt AuditEvent) {
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(evt)
	if err != nil {
		return
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	// Lazy-reopen: if open() failed at startup (e.g. stale root-owned file),
	// attempt to remove the blocking file and retry.
	if a.f == nil {
		path := filepath.Join(a.dir, "audit.jsonl")
		_ = os.Remove(path) // no-op if we lack permission; open() will try a new name
		a.open()
		if a.f == nil {
			return // still can't open — give up silently
		}
	}
	if a.written >= auditMaxBytes {
		a.rotate()
		if a.f == nil {
			return
		}
	}

	n, _ := a.f.Write(line)
	a.written += int64(n)
}

// Audit writes a structured audit event to the rotating JSONL log.
func Audit(event, target, asset, stage string, durationMs int64, errStr, detail string) {
	globalAudit.write(AuditEvent{
		Event:      event,
		Target:     target,
		Asset:      asset,
		Stage:      stage,
		DurationMs: durationMs,
		Error:      errStr,
		Detail:     detail,
	})
}
