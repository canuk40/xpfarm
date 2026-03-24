// Package gitleaks implements the normalization Adapter for Gitleaks JSON output.
//
// Expected raw map — one decoded element from gitleaks' JSON array output
// (`gitleaks detect --report-format json`):
//
//	{
//	  "Description": "AWS Access Key ID",
//	  "StartLine":   5,
//	  "EndLine":     5,
//	  "Match":       "AKIAIOSFODNN7EXAMPLE",
//	  "Secret":      "AKIAIOSFODNN7EXAMPLE",
//	  "File":        "config/settings.yml",
//	  "Commit":      "abc123def456",
//	  "Entropy":     3.58,
//	  "Author":      "Dev User",
//	  "Email":       "dev@example.com",
//	  "Date":        "2024-01-15T10:30:00Z",
//	  "Message":     "Add production config",
//	  "Tags":        ["aws", "cloud"],
//	  "RuleID":      "aws-access-key-id",
//	  "Fingerprint": "abc123:config/settings.yml:aws-access-key-id:5"
//	}
//
// The adapter also accepts the full gitleaks report (with a top-level array)
// when the raw map has a "findings" key holding the array.
package gitleaks

import (
	"fmt"
	"strings"
	"time"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

func init() {
	normalization.RegisterAdapter(&Adapter{})
}

// ruleIDToCWE maps known gitleaks rule IDs to the most appropriate CWE.
// All secret exposures are either CWE-798 (hard-coded credentials) or
// CWE-312 (cleartext storage of sensitive information).
var ruleIDToCWE = map[string]string{
	"private-key":               "CWE-312",
	"generic-api-key":           "CWE-798",
	"aws-access-key-id":         "CWE-798",
	"aws-secret-access-key":     "CWE-312",
	"github-pat":                "CWE-798",
	"github-oauth":              "CWE-798",
	"github-app-token":          "CWE-798",
	"github-refresh-token":      "CWE-798",
	"gitlab-pat":                "CWE-798",
	"slack-access-token":        "CWE-798",
	"slack-web-hook":            "CWE-798",
	"stripe-access-token":       "CWE-798",
	"pypi-upload-token":         "CWE-798",
	"google-api-key":            "CWE-798",
	"google-service-account":    "CWE-312",
	"heroku-api-key":            "CWE-798",
	"mailchimp-api-key":         "CWE-798",
	"mailgun-api-key":           "CWE-798",
	"sendgrid-api-token":        "CWE-798",
	"twitter-access-token":      "CWE-798",
	"twitter-api-key":           "CWE-798",
	"twilio-api-key":            "CWE-798",
	"hashicorp-vault-token":     "CWE-798",
	"jwt":                       "CWE-312",
	"password-in-url":           "CWE-256",
	"databricks-api-token":      "CWE-798",
	"digitalocean-access-token": "CWE-798",
	"doppler-api-token":         "CWE-798",
	"dropbox-api-secret":        "CWE-798",
	"npm-access-token":          "CWE-798",
	"shopify-access-token":      "CWE-798",
	"square-access-token":       "CWE-798",
}

// Adapter normalizes Gitleaks JSON output into model.Finding values.
type Adapter struct{}

func (a *Adapter) Source() string { return "gitleaks" }

func (a *Adapter) Normalize(raw map[string]any) ([]model.Finding, error) {
	// Support full report format: {"findings": [...], "target": "repo-url"}
	if rawList, ok := raw["findings"]; ok {
		arr, ok := rawList.([]any)
		if !ok {
			return nil, fmt.Errorf("gitleaks adapter: 'findings' is not an array")
		}
		target, _ := raw["target"].(string)
		var findings []model.Finding
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if target != "" {
				m["_target"] = target
			}
			f, err := normalizeLeak(m)
			if err != nil {
				continue
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
	// Single leak object
	f, err := normalizeLeak(raw)
	if err != nil {
		return nil, err
	}
	return []model.Finding{f}, nil
}

func normalizeLeak(r map[string]any) (model.Finding, error) {
	ruleID, _ := r["RuleID"].(string)
	description, _ := r["Description"].(string)
	file, _ := r["File"].(string)
	match, _ := r["Match"].(string)
	commit, _ := r["Commit"].(string)
	author, _ := r["Author"].(string)

	if ruleID == "" && description == "" {
		return model.Finding{}, fmt.Errorf("gitleaks adapter: empty ruleID and description")
	}

	// Line
	startLine := intVal(r, "StartLine")

	// Target: injected by the array normalizer, or fall back to file
	target, _ := r["_target"].(string)
	if target == "" {
		target = file
	}

	location := file
	if startLine > 0 {
		location = fmt.Sprintf("%s:%d", file, startLine)
	}

	// CWE
	cwe := lookupCWE(ruleID)

	// Severity: credentials are always high-severity; token entropy >4 → high
	severity := model.SeverityHigh
	if entropy, ok := r["Entropy"].(float64); ok && entropy < 3.0 {
		severity = model.SeverityMedium
	}

	title := buildTitle(ruleID, description)

	// Evidence: redact the actual secret but keep the match line context
	evidence := redactSecret(match, r["Secret"])
	if commit != "" {
		evidence += fmt.Sprintf("\nCommit: %s", commit)
		if author != "" {
			evidence += fmt.Sprintf(" by %s", author)
		}
	}

	// Tags
	tags := []string{"gitleaks", "secret", "credential"}
	if ruleID != "" {
		tags = append(tags, strings.ToLower(ruleID))
	}
	if rawTags, ok := r["Tags"].([]any); ok {
		for _, t := range rawTags {
			if s, ok := t.(string); ok && s != "" {
				tags = append(tags, strings.ToLower(s))
			}
		}
	}

	// Timestamp from gitleaks Date field
	ts := time.Now().UTC()
	if dateStr, _ := r["Date"].(string); dateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
			ts = parsed
		}
	}

	return model.Finding{
		ID:          model.NewID(),
		Source:      "gitleaks",
		Target:      target,
		Location:    location,
		Title:       title,
		Description: fmt.Sprintf("Secret exposure: %s detected in %s.", description, file),
		Severity:    severity,
		CWE:         cwe,
		Evidence:    trimEvidence(evidence),
		Tags:        tags,
		Raw:         r,
		Timestamp:   ts,
	}, nil
}

// lookupCWE returns the CWE for a rule ID, defaulting to CWE-798.
func lookupCWE(ruleID string) string {
	if cwe, ok := ruleIDToCWE[strings.ToLower(ruleID)]; ok {
		return cwe
	}
	// Any unrecognised rule that contains "key" or "token" → CWE-798
	lower := strings.ToLower(ruleID)
	if strings.Contains(lower, "key") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
		return "CWE-798"
	}
	return "CWE-312" // cleartext storage as a safe default for secrets
}

// redactSecret replaces the actual secret value with asterisks in the match line.
func redactSecret(match string, secret any) string {
	s, _ := secret.(string)
	if s == "" || match == "" {
		return match
	}
	if len(s) > 4 {
		// Keep first 4 chars for forensic reference, redact the rest
		redacted := s[:4] + strings.Repeat("*", len(s)-4)
		return strings.ReplaceAll(match, s, redacted)
	}
	return strings.ReplaceAll(match, s, "****")
}

// buildTitle creates a human-readable title from rule ID or description.
func buildTitle(ruleID, description string) string {
	if description != "" {
		return fmt.Sprintf("Exposed Secret: %s", description)
	}
	pretty := strings.ReplaceAll(ruleID, "-", " ")
	return fmt.Sprintf("Exposed Secret: %s", strings.Title(pretty)) //nolint:staticcheck
}

func intVal(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func trimEvidence(s string) string {
	const maxLen = 2048
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
