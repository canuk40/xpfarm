package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// checkpointDir is relative to CWD (the project root).
const checkpointDir = "data/checkpoints"

// Stage constants for scan pipeline checkpoints.
const (
	CheckpointStageNone    = 0  // not started
	CheckpointStageWorkers = 8  // all per-target stages done (Naabu→Nuclei)
	CheckpointStageAll     = 10 // full pipeline complete (incl. subfinder/filter)
)

// checkpoint is the JSON payload stored on disk.
type checkpoint struct {
	AssetID   uint      `json:"asset_id"`
	Target    string    `json:"target"`
	LastStage int       `json:"last_stage"`
	UpdatedAt time.Time `json:"updated_at"`
}

var nonAlphanumRe = regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`)

// checkpointKey returns a filesystem-safe filename for (assetID, target).
func checkpointKey(assetID uint, target string) string {
	safe := nonAlphanumRe.ReplaceAllString(target, "_")
	return fmt.Sprintf("%d_%s.json", assetID, safe)
}

func checkpointPath(assetID uint, target string) string {
	return filepath.Join(checkpointDir, checkpointKey(assetID, target))
}

func ensureCheckpointDir() {
	_ = os.MkdirAll(checkpointDir, 0755)
}

// SaveCheckpoint atomically persists the last completed stage for a target.
// Uses tempfile → fsync → rename for durability (Entity pattern).
func SaveCheckpoint(assetID uint, target string, stage int) {
	ensureCheckpointDir()

	cp := checkpoint{
		AssetID:   assetID,
		Target:    target,
		LastStage: stage,
		UpdatedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return
	}
	data = append(data, '\n')

	final := checkpointPath(assetID, target)

	// Write to a temp file in the same directory, then rename atomically.
	tmp, err := os.CreateTemp(checkpointDir, ".tmp_checkpoint_*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return
	}
	tmp.Close()

	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
	}
}

// LoadCheckpoint returns the last completed stage for a target, or -1 if none.
func LoadCheckpoint(assetID uint, target string) int {
	path := checkpointPath(assetID, target)
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return -1
	}
	return cp.LastStage
}

// ClearCheckpoint removes the checkpoint file for a target (called on clean completion).
func ClearCheckpoint(assetID uint, target string) {
	_ = os.Remove(checkpointPath(assetID, target))
}
