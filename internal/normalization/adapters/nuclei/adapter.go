// Package nuclei implements the normalization Adapter for Nuclei v3 JSONL output.
//
// Expected raw map shape (one decoded JSONL line from nuclei -jsonl):
//
//	{
//	  "template-id": "CVE-2021-44228",
//	  "info": {
//	    "name": "...",
//	    "severity": "critical",
//	    "description": "...",
//	    "tags": ["cve","rce"],
//	    "classification": {
//	      "cve-id":    ["CVE-2021-44228"],
//	      "cwe-id":    ["CWE-502"],
//	      "cvss-score": 10.0
//	    }
//	  },
//	  "host":       "https://example.com",
//	  "matched-at": "https://example.com/path",
//	  "request":    "GET /path HTTP/1.1\r\n...",
//	  "timestamp":  "2024-01-01T00:00:00.000Z"
//	}
package nuclei

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

// Adapter normalizes a single Nuclei JSONL finding into a model.Finding.
type Adapter struct{}

func (a *Adapter) Source() string { return "nuclei" }

func (a *Adapter) Normalize(raw map[string]any) ([]model.Finding, error) {
	info, _ := raw["info"].(map[string]any)
	if info == nil {
		return nil, fmt.Errorf("nuclei adapter: missing 'info' key")
	}

	title, _ := info["name"].(string)
	if title == "" {
		title, _ = raw["template-id"].(string)
	}
	description, _ := info["description"].(string)
	severity := model.NormalizeSeverity(stringVal(info, "severity"))
	host := stringVal(raw, "host")
	matchedAt := stringVal(raw, "matched-at")
	if matchedAt == "" {
		matchedAt = host
	}
	request := stringVal(raw, "request")

	// Tags
	var tags []string
	if rawTags, ok := info["tags"].([]any); ok {
		for _, t := range rawTags {
			if s, ok := t.(string); ok {
				tags = append(tags, s)
			}
		}
	}
	// Nuclei also encodes tags as a comma-separated string in some versions
	if len(tags) == 0 {
		if tagStr, ok := info["tags"].(string); ok {
			for _, t := range strings.Split(tagStr, ",") {
				if t = strings.TrimSpace(t); t != "" {
					tags = append(tags, t)
				}
			}
		}
	}

	// Classification block
	cve, cwe, cvss := extractClassification(info)

	// Timestamp
	ts := time.Now().UTC()
	if tsStr := stringVal(raw, "timestamp"); tsStr != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			ts = parsed
		}
	}

	f := model.Finding{
		ID:          model.NewID(),
		Source:      "nuclei",
		Target:      host,
		Location:    matchedAt,
		Title:       title,
		Description: description,
		Severity:    severity,
		CWE:         cwe,
		CVE:         cve,
		Evidence:    trimEvidence(request),
		Raw:         raw,
		Tags:        tags,
		Timestamp:   ts,
	}
	if cvss > 0 {
		v := cvss
		f.CVSS = &v
	}

	return []model.Finding{f}, nil
}

// extractClassification pulls CVE, CWE, and CVSS from info.classification.
func extractClassification(info map[string]any) (cve, cwe string, cvss float64) {
	cls, _ := info["classification"].(map[string]any)
	if cls == nil {
		return
	}
	// CVE — array of strings
	if ids, ok := cls["cve-id"].([]any); ok && len(ids) > 0 {
		cve, _ = ids[0].(string)
		cve = strings.ToUpper(strings.TrimSpace(cve))
	}
	// CWE — array of strings, format "CWE-502"
	if ids, ok := cls["cwe-id"].([]any); ok && len(ids) > 0 {
		cwe, _ = ids[0].(string)
		cwe = strings.ToUpper(strings.TrimSpace(cwe))
	}
	// CVSS score
	switch v := cls["cvss-score"].(type) {
	case float64:
		cvss = v
	case int:
		cvss = float64(v)
	}
	return
}

// stringVal safely extracts a string from a map.
func stringVal(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

// trimEvidence caps evidence at 2 KB to keep DB rows manageable.
func trimEvidence(s string) string {
	const maxLen = 2048
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
