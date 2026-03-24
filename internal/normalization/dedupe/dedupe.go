// Package dedupe provides fingerprinting and deduplication for normalized findings.
package dedupe

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"xpfarm/internal/normalization/model"
)

// GenerateFingerprint returns a SHA-256 hex digest of the fields that uniquely
// identify a finding regardless of when it was discovered.
//
// The fingerprint is intentionally stable: running the same scanner against the
// same target twice must produce identical fingerprints for the same issue so
// that callers can deduplicate across runs.
func GenerateFingerprint(f model.Finding) string {
	h := sha256.New()

	// Truncate evidence to the first 200 bytes to prevent noisy deduplication
	// from rotating tokens, timestamps, or session IDs in HTTP responses.
	evidence := f.Evidence
	if len(evidence) > 200 {
		evidence = evidence[:200]
	}

	// Canonical separator unlikely to appear in any of the field values.
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Source)),
		strings.ToLower(strings.TrimSpace(f.Target)),
		strings.ToLower(strings.TrimSpace(f.Location)),
		strings.ToUpper(strings.TrimSpace(f.CWE)),
		strings.ToUpper(strings.TrimSpace(f.CVE)),
		strings.ToLower(strings.TrimSpace(evidence)),
	}
	fmt.Fprint(h, strings.Join(parts, "\x00"))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Deduplicate removes findings with identical fingerprints, keeping the first
// occurrence. Findings with an empty fingerprint are kept as-is (the pipeline
// always sets fingerprints before calling Deduplicate, so this is a safety net).
func Deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Fingerprint == "" {
			out = append(out, f)
			continue
		}
		if _, exists := seen[f.Fingerprint]; exists {
			continue
		}
		seen[f.Fingerprint] = struct{}{}
		out = append(out, f)
	}
	return out
}
