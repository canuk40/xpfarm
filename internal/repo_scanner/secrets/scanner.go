// Package secrets provides secret-scanning implementations for repository paths.
// All scanners implement the SecretScanner interface and return findings
// normalised into the canonical model.Finding type.
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

// SecretScanner scans a local directory for exposed secrets and credentials.
type SecretScanner interface {
	// Scan walks path and returns one Finding per detected secret.
	Scan(path string) ([]model.Finding, error)
}

// CheckGitleaksInstalled returns an error if gitleaks is not found in PATH.
func CheckGitleaksInstalled() error {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		return fmt.Errorf("gitleaks: not installed — install from https://github.com/gitleaks/gitleaks/releases")
	}
	return nil
}

// GitleaksScanner wraps the gitleaks CLI.
// It scans the repository using gitleaks and normalises results through the
// existing gitleaks normalization adapter.
//
// Gitleaks exit codes:
//
//	0  = no leaks found
//	1  = leaks found (not an error)
//	2+ = gitleaks internal error
type GitleaksScanner struct {
	// RepoURL is injected into the gitleaks findings as the target identifier.
	RepoURL string
}

func (s *GitleaksScanner) Scan(path string) ([]model.Finding, error) {
	if err := CheckGitleaksInstalled(); err != nil {
		return nil, err
	}

	outFile, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("gitleaks: create temp file: %w", err)
	}
	outFile.Close()
	defer os.Remove(outFile.Name())

	var stderr bytes.Buffer
	cmd := exec.Command("gitleaks",
		"detect",
		"--source", path,
		"--report-format", "json",
		"--report-path", outFile.Name(),
		"--exit-code", "0", // always exit 0 so we control flow
	)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Check if it's a real error (not just "leaks found")
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("gitleaks: exit %d: %s",
					exitErr.ExitCode(), stderr.String())
			}
		} else {
			return nil, fmt.Errorf("gitleaks: %w", err)
		}
	}

	data, err := os.ReadFile(outFile.Name())
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	// Gitleaks outputs a top-level JSON array []{...}
	var leaks []any
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: parse JSON: %w", err)
	}
	if len(leaks) == 0 {
		return nil, nil
	}

	// Wrap in the map shape that the gitleaks adapter accepts:
	// {"findings": [...], "target": "..."}
	target := s.RepoURL
	if target == "" {
		target = path
	}
	raw := map[string]any{
		"findings": leaks,
		"target":   target,
	}

	findings, _, err := normalization.Run("gitleaks", raw)
	return findings, err
}
