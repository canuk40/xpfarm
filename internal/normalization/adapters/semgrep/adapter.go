// Package semgrep implements the normalization Adapter for Semgrep JSON output.
//
// Expected raw map — the decoded output of `semgrep --json`:
//
//	{
//	  "results": [
//	    {
//	      "check_id": "python.django.security.audit.raw-query.raw-query",
//	      "path":     "app/views.py",
//	      "start":    {"line": 42, "col": 1},
//	      "extra": {
//	        "message":  "Found raw SQL query...",
//	        "severity": "ERROR",
//	        "lines":    "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
//	        "metadata": {
//	          "cwe":    ["CWE-89: SQL Injection"],
//	          "owasp":  ["A01:2017 - Injection"],
//	          "source-rule-url": "https://..."
//	        }
//	      }
//	    }
//	  ],
//	  "errors": []
//	}
//
// The adapter also accepts a single result object (without the top-level
// "results" wrapper) for callers that pre-split the array.
package semgrep

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

// Adapter normalizes Semgrep JSON output into model.Finding values.
type Adapter struct{}

func (a *Adapter) Source() string { return "semgrep" }

func (a *Adapter) Normalize(raw map[string]any) ([]model.Finding, error) {
	// Accept full semgrep output (has "results" array) or a single result object.
	if rawResults, ok := raw["results"]; ok {
		results, ok := rawResults.([]any)
		if !ok {
			return nil, fmt.Errorf("semgrep adapter: 'results' is not an array")
		}
		var findings []model.Finding
		for _, r := range results {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			f, err := normalizeResult(rm)
			if err != nil {
				continue
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
	// Single result object
	f, err := normalizeResult(raw)
	if err != nil {
		return nil, err
	}
	return []model.Finding{f}, nil
}

func normalizeResult(r map[string]any) (model.Finding, error) {
	checkID, _ := r["check_id"].(string)
	path, _ := r["path"].(string)
	if checkID == "" && path == "" {
		return model.Finding{}, fmt.Errorf("semgrep adapter: missing check_id and path")
	}

	extra, _ := r["extra"].(map[string]any)
	if extra == nil {
		extra = map[string]any{}
	}

	message, _ := extra["message"].(string)
	lines, _ := extra["lines"].(string)
	rawSeverity, _ := extra["severity"].(string)

	// Start line
	startLine := 0
	if startMap, ok := r["start"].(map[string]any); ok {
		switch v := startMap["line"].(type) {
		case float64:
			startLine = int(v)
		case int:
			startLine = v
		}
	}

	location := path
	if startLine > 0 {
		location = fmt.Sprintf("%s:%d", path, startLine)
	}

	// Parse metadata block
	meta, _ := extra["metadata"].(map[string]any)
	cwe := extractSemgrepCWE(meta)
	tags := extractSemgrepTags(checkID, meta)

	// Build a title from the rule ID
	title := ruleIDToTitle(checkID)

	// Target is the repository or a synthesized label; callers should inject
	// "target" into the raw map if available (e.g. the repo URL).
	target, _ := r["target"].(string)
	if target == "" {
		target = path // fallback: just the file path as target
	}

	return model.Finding{
		ID:          model.NewID(),
		Source:      "semgrep",
		Target:      target,
		Location:    location,
		Title:       title,
		Description: message,
		Severity:    model.NormalizeSeverity(rawSeverity),
		CWE:         cwe,
		Evidence:    trimEvidence(lines),
		Tags:        tags,
		Raw:         r,
		Timestamp:   time.Now().UTC(),
	}, nil
}

// extractSemgrepCWE extracts the first CWE from the metadata array.
// Semgrep encodes CWEs as "CWE-89: SQL Injection" strings.
func extractSemgrepCWE(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	cweList, _ := meta["cwe"].([]any)
	for _, c := range cweList {
		s, _ := c.(string)
		if s == "" {
			continue
		}
		// "CWE-89: SQL Injection" → "CWE-89"
		if idx := strings.Index(s, ":"); idx >= 0 {
			return strings.ToUpper(strings.TrimSpace(s[:idx]))
		}
		return strings.ToUpper(strings.TrimSpace(s))
	}
	return ""
}

// extractSemgrepTags builds a tag list from the rule ID components and OWASP refs.
func extractSemgrepTags(checkID string, meta map[string]any) []string {
	seen := make(map[string]struct{})
	var tags []string

	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			return
		}
		if _, exists := seen[t]; exists {
			return
		}
		seen[t] = struct{}{}
		tags = append(tags, t)
	}

	add("semgrep")
	// Rule ID segments, e.g. "python.django.security.audit.raw-query" → [python, django, security]
	for _, part := range strings.Split(checkID, ".") {
		add(part)
	}

	if meta != nil {
		if owasp, ok := meta["owasp"].([]any); ok {
			for _, o := range owasp {
				if s, ok := o.(string); ok {
					add(s)
				}
			}
		}
	}
	return tags
}

// ruleIDToTitle converts a dotted rule ID to a readable title.
// "python.django.security.audit.raw-query.raw-query" → "Raw Query (Django)"
func ruleIDToTitle(checkID string) string {
	parts := strings.Split(checkID, ".")
	if len(parts) == 0 {
		return checkID
	}
	// Last segment is usually the most descriptive
	name := strings.ReplaceAll(parts[len(parts)-1], "-", " ")
	name = strings.Title(name) //nolint:staticcheck
	if len(parts) >= 2 {
		framework := strings.Title(parts[len(parts)-2]) //nolint:staticcheck
		// avoid "Raw Query (Raw Query)"
		if !strings.EqualFold(framework, name) {
			return fmt.Sprintf("%s (%s)", name, framework)
		}
	}
	return name
}

func trimEvidence(s string) string {
	const maxLen = 2048
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
