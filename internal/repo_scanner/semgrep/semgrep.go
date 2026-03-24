// Package semgrep runs the Semgrep CLI against a local repository path and
// returns normalized security findings.
//
// Semgrep exit codes:
//
//	0  = success, no findings
//	1  = success, findings found (not an error)
//	2  = command-line usage error
//	3  = unexpected internal error
//	4  = target parsing error
package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

// CheckInstalled returns an error if semgrep is not found in PATH.
func CheckInstalled() error {
	if _, err := exec.LookPath("semgrep"); err != nil {
		return fmt.Errorf("semgrep: not installed or not in PATH — install with: pip install semgrep")
	}
	return nil
}

// Run executes `semgrep --config auto --json` against repoPath and returns
// normalized findings. target is the repository URL or identifier used to
// populate Finding.Target.
//
// The output is written to a temp file to handle large result sets without
// streaming-parse complexity.
func Run(repoPath, target string) ([]model.Finding, error) {
	if err := CheckInstalled(); err != nil {
		return nil, err
	}

	outFile, err := os.CreateTemp("", "semgrep-*.json")
	if err != nil {
		return nil, fmt.Errorf("semgrep: create temp file: %w", err)
	}
	outFile.Close()
	defer os.Remove(outFile.Name())

	var stderr bytes.Buffer
	cmd := exec.Command("semgrep",
		"--json",
		"--output", outFile.Name(),
		"--config", "auto",
		"--quiet",
		repoPath,
	)
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 = findings found — perfectly normal
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("semgrep: exit %d: %s",
					exitErr.ExitCode(), stderr.String())
			}
		} else {
			return nil, fmt.Errorf("semgrep: %w", err)
		}
	}

	data, err := os.ReadFile(outFile.Name())
	if err != nil {
		return nil, fmt.Errorf("semgrep: read output: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("semgrep: parse JSON: %w", err)
	}

	// Inject the target URL into each result so the adapter populates Finding.Target.
	if results, ok := raw["results"].([]any); ok {
		for _, r := range results {
			if m, ok := r.(map[string]any); ok {
				m["target"] = target
			}
		}
	}

	findings, _, err := normalization.Run("semgrep", raw)
	return findings, err
}
