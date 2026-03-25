package reports

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"time"

	"xpfarm/internal/database"
	"xpfarm/internal/graph"
	graphstore "xpfarm/internal/storage/graph"
	"gorm.io/gorm"
)

// overlordAvailable is set by the caller; lazily checked per generation request.
// We re-check each time so a late-start overlord becomes available without restart.
func overlordAvailable() bool {
	// Import at call-site to avoid init-order coupling
	// We use a direct HTTP check instead of importing overlord package
	// to keep this package dependency-light; the server layer calls overlord.
	return false // overridden by GenerateWithOverlord
}

// newID generates a random 16-byte hex ID.
func newID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// collect builds a ReportData from the database given the request.
func collect(db *gorm.DB, req ReportRequest) (ReportData, error) {
	var assetNames []string
	targetIDs := map[uint]bool{}
	findings := []FindingSummary{}

	for _, assetID := range req.AssetIDs {
		var asset database.Asset
		if err := db.Preload("Targets").First(&asset, assetID).Error; err != nil {
			continue
		}
		assetNames = append(assetNames, asset.Name)

		for _, t := range asset.Targets {
			targetIDs[t.ID] = true

			// Vulnerabilities
			var vulns []database.Vulnerability
			db.Where("target_id = ?", t.ID).Find(&vulns)
			for _, v := range vulns {
				findings = append(findings, FindingSummary{
					ID:          v.ID,
					TargetValue: t.Value,
					TargetID:    t.ID,
					AssetName:   asset.Name,
					AssetID:     asset.ID,
					Type:        "vuln",
					Name:        v.Name,
					Severity:    strings.ToLower(v.Severity),
					Description: v.Description,
					TemplateID:  v.TemplateID,
					MatcherName: v.MatcherName,
					Extracted:   v.Extracted,
				})
			}

			// CVEs
			var cves []database.CVE
			db.Where("target_id = ?", t.ID).Find(&cves)
			for _, c := range cves {
				findings = append(findings, FindingSummary{
					ID:          c.ID,
					TargetValue: t.Value,
					TargetID:    t.ID,
					AssetName:   asset.Name,
					AssetID:     asset.ID,
					Type:        "cve",
					Name:        fmt.Sprintf("%s — %s", c.CveID, c.Product),
					Severity:    strings.ToLower(c.Severity),
					CVSS:        c.CvssScore,
					EPSS:        c.EpssScore,
					IsKEV:       c.IsKEV,
					HasPOC:      c.HasPOC,
					CveID:       c.CveID,
					Product:     c.Product,
				})
			}
		}
	}

	data := ReportData{
		Title:        req.Title,
		AssetNames:   assetNames,
		GeneratedAt:  time.Now().UTC(),
		Findings:     findings,
		TotalTargets: len(targetIDs),
	}

	if data.Title == "" {
		data.Title = "Security Assessment Report — " + strings.Join(assetNames, ", ")
	}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			data.ByCritical++
		case "high":
			data.ByHigh++
		case "medium":
			data.ByMedium++
		case "low":
			data.ByLow++
		default:
			data.ByInfo++
		}
		if f.IsKEV {
			data.KEVCount++
		}
		if f.HasPOC {
			data.POCCount++
		}
	}

	if req.IncludeGraph {
		sg, gErr := graphstore.LoadLatestGraph(db)
		if gErr == nil && sg != nil {
			data.GraphSummary = buildGraphSummary(sg)
		}
	}

	return data, nil
}

// buildGraphSummary produces a human-readable Markdown summary from a ScanGraph.
func buildGraphSummary(sg *graph.ScanGraph) string {
	if sg == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Graph snapshot contains **%d nodes** and **%d edges**.\n\n", len(sg.Nodes), len(sg.Edges)))

	typeCounts := map[string]int{}
	for _, n := range sg.Nodes {
		typeCounts[string(n.Type)]++
	}
	sb.WriteString("| Node Type | Count |\n|-----------|-------|\n")
	for _, t := range []string{"asset", "target", "service", "tech", "vuln", "exploit"} {
		if c := typeCounts[t]; c > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", t, c))
		}
	}

	// Exploit nodes indicate KEV+PoC — surface them
	for _, n := range sg.Nodes {
		if n.Type == graph.NodeExploit {
			sb.WriteString(fmt.Sprintf("\n⚠️ **Exploit path detected:** %s\n", n.Label))
		}
	}

	return sb.String()
}

// funcMap provides template helper functions.
var funcMap = template.FuncMap{
	"toUpper": strings.ToUpper,
	"toLower": strings.ToLower,
	"mul": func(a, b float64) float64 {
		return a * b
	},
}

// renderTemplate renders one of the built-in Markdown templates.
func renderTemplate(tmplStr string, data ReportData) (string, error) {
	t, err := template.New("report").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execute error: %w", err)
	}
	return buf.String(), nil
}

// GenerateReport builds a report from findings in the database.
// overlordGen is an optional function that calls Overlord to produce AI content;
// pass nil to use the built-in template renderer only.
func GenerateReport(
	ctx context.Context,
	db *gorm.DB,
	req ReportRequest,
	overlordGen func(data ReportData, format ReportFormat) (string, error),
) (*Report, error) {
	data, err := collect(db, req)
	if err != nil {
		return nil, fmt.Errorf("data collection failed: %w", err)
	}

	var content string

	// Try Overlord AI generation first
	if overlordGen != nil {
		content, err = overlordGen(data, req.Format)
		if err != nil {
			// Fall back to template
			err = nil
		}
	}

	// Template fallback (or primary when overlord unavailable)
	if content == "" {
		content, err = renderWithBuiltinTemplate(data, req.Format)
		if err != nil {
			return nil, err
		}
	}

	// Prepend mandatory validation disclaimer — enforced server-side regardless
	// of which AI provider or generation path was used.
	content = responsibleDisclosureDisclaimer(data.Title) + "\n\n" + content

	return &Report{
		ID:        newID(),
		Format:    req.Format,
		Title:     data.Title,
		Content:   content,
		Status:    StatusReady,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// responsibleDisclosureDisclaimer returns a hard-coded validation block that is
// prepended to every generated report regardless of AI provider or template used.
// This cannot be removed or overridden by prompt engineering or model output.
func responsibleDisclosureDisclaimer(title string) string {
	return fmt.Sprintf(`> ⚠️ **OPERATOR VALIDATION REQUIRED — DO NOT SUBMIT WITHOUT COMPLETING THIS CHECKLIST**
>
> This report was generated with AI assistance and automated scanning tools. Under bug bounty platform
> Codes of Conduct (Bugcrowd, HackerOne, Intigriti, and others), AI-assisted findings **must be manually
> reviewed and verified** prior to submission. Unvalidated reports are subject to rejection and may
> result in account suspension.
>
> **Before submitting "%s" to any platform, confirm each item below:**
>
> - [ ] Every finding has been **manually reproduced** from a clean session
> - [ ] Reproduction steps work as written and produce the stated outcome
> - [ ] Each target is **confirmed in-scope** on the current program policy page
> - [ ] Impact is accurately stated — not extrapolated beyond what was observed
> - [ ] No unintended third-party infrastructure was affected during testing
> - [ ] Severity ratings reflect actual exploitability, not theoretical worst-case
> - [ ] All evidence (requests, responses, screenshots) is current and unaltered
>
> *Submitting this report to a platform constitutes the operator's confirmation that all items above
> are satisfied. XPFarm and its contributors bear no responsibility for rejected or disputed reports.*`, title)
}

// renderWithBuiltinTemplate renders the appropriate built-in Markdown template.
func renderWithBuiltinTemplate(data ReportData, format ReportFormat) (string, error) {
	var tmplStr string
	switch format {
	case FormatHackerOne:
		tmplStr = hackerOneTemplate
	case FormatBugcrowd:
		tmplStr = bugcrowdTemplate
	default:
		tmplStr = baseMarkdownTemplate
	}
	return renderTemplate(tmplStr, data)
}

// BuildOverlordPrompt renders the Overlord prompt template with report data.
func BuildOverlordPrompt(data ReportData, format ReportFormat) (string, error) {
	type promptData struct {
		ReportData
		Format string
	}
	t, err := template.New("prompt").Funcs(funcMap).Parse(overlordPromptTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, promptData{ReportData: data, Format: string(format)}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ExtractAssistantText extracts text from the last assistant message in an Overlord session.
func ExtractAssistantText(messages []map[string]interface{}) string {
	// Walk backwards to find the last assistant message
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		role, _ := msg["role"].(string)
		if role != "assistant" {
			continue
		}
		parts, ok := msg["parts"].([]interface{})
		if !ok {
			continue
		}
		var sb strings.Builder
		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if t, _ := part["type"].(string); t == "text" {
				if text, _ := part["text"].(string); text != "" {
					sb.WriteString(text)
				}
			}
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	return ""
}

// ---- Embedded template strings ----
// These mirror the .md files in templates/ but are embedded in the binary
// to avoid runtime file I/O.

const overlordPromptTemplate = `You are a professional bug bounty researcher writing a security disclosure report.
Analyze the findings below and produce a complete, professional {{.Format}} report.

## Target Information
Assets: {{range $i, $a := .AssetNames}}{{if $i}}, {{end}}{{$a}}{{end}}
Report Title: {{.Title}}
Generated: {{.GeneratedAt.Format "2006-01-02"}}
Total Targets Scanned: {{.TotalTargets}}

## Finding Statistics
- Critical: {{.ByCritical}}
- High: {{.ByHigh}}
- Medium: {{.ByMedium}}
- Low: {{.ByLow}}
- Informational: {{.ByInfo}}
- Known Exploited (KEV): {{.KEVCount}}
- Has Public PoC: {{.POCCount}}

## Findings
{{range .Findings}}
### [{{.Severity | toUpper}}] {{.Name}}
- Target: {{.TargetValue}} (Asset: {{.AssetName}})
- Type: {{.Type}}
{{if .CveID}}- CVE: {{.CveID}}{{end}}
{{if .CVSS}}- CVSS Score: {{printf "%.1f" .CVSS}}{{end}}
{{if .EPSS}}- EPSS Score: {{printf "%.4f" .EPSS}}{{end}}
{{if .IsKEV}}- KNOWN EXPLOITED (CISA KEV){{end}}
{{if .HasPOC}}- Public PoC Available{{end}}
{{if .Description}}- Description: {{.Description}}{{end}}
{{if .Extracted}}- Extracted: {{.Extracted}}{{end}}
{{if .Product}}- Affected Product: {{.Product}}{{end}}
{{end}}
{{if .GraphSummary}}
## Attack Graph Context
{{.GraphSummary}}
{{end}}

## Instructions
Write a complete professional security report in {{.Format}} format with:
1. Executive Summary (non-technical overview, business impact, risk rating)
2. Technical Findings (one section per finding with: description, impact, reproduction steps, remediation)
3. Risk Assessment (prioritized remediation roadmap)
4. Appendix (raw finding data)

Use clear headings, bullet points, and professional language.
For hackerone format: follow their structured disclosure template with CVSS scores, impact, steps to reproduce, and supporting material.
For bugcrowd format: follow their VRT taxonomy and structured submission template.
Output ONLY the report content, no preamble or meta-commentary.`

const baseMarkdownTemplate = `# {{.Title}}

**Generated:** {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}
**Assets:** {{range $i, $a := .AssetNames}}{{if $i}}, {{end}}{{$a}}{{end}}
**Targets Scanned:** {{.TotalTargets}}

---

## Executive Summary

This report summarizes the security assessment findings for {{range $i, $a := .AssetNames}}{{if $i}}, {{end}}**{{$a}}**{{end}}.

| Severity    | Count |
|-------------|-------|
| Critical    | {{.ByCritical}} |
| High        | {{.ByHigh}} |
| Medium      | {{.ByMedium}} |
| Low         | {{.ByLow}} |
| Info        | {{.ByInfo}} |
| CISA KEV    | {{.KEVCount}} |
| Has PoC     | {{.POCCount}} |
{{$crit := .ByCritical}}{{if gt $crit 0}}
> **CRITICAL RISK:** {{$crit}} critical severity finding(s) require immediate attention.
{{end}}{{$kev := .KEVCount}}{{if gt $kev 0}}
> **ACTIVELY EXPLOITED:** {{$kev}} finding(s) are in the CISA Known Exploited Vulnerabilities catalog.
{{end}}
---

## Findings
{{range .Findings}}
### [{{.Severity | toUpper}}] {{.Name}}

| Field | Value |
|-------|-------|
| Target | {{.TargetValue}} |
| Asset | {{.AssetName}} |
| Type | {{.Type}} |
{{if .CveID}}| CVE | {{.CveID}} |
{{end}}{{if .CVSS}}| CVSS | {{printf "%.1f" .CVSS}} |
{{end}}{{if .EPSS}}| EPSS | {{printf "%.4f" .EPSS}} |
{{end}}{{if .IsKEV}}| KEV | CISA Known Exploited |
{{end}}{{if .HasPOC}}| PoC | Public exploit available |
{{end}}{{if .Product}}| Product | {{.Product}} |
{{end}}
{{if .Description}}**Description:** {{.Description}}{{end}}

{{if .Extracted}}**Extracted Data:**
` + "```" + `
{{.Extracted}}
` + "```" + `
{{end}}

**Remediation:** Apply vendor patches, review configuration, and verify remediation with a follow-up scan.

---
{{end}}
{{if .GraphSummary}}
## Attack Graph Context

{{.GraphSummary}}

---
{{end}}

## Disclaimer

This report was generated by XPFarm automated security scanner. All findings should be verified manually before disclosure.`

const hackerOneTemplate = `# HackerOne Vulnerability Report

**Title:** {{.Title}}
**Date:** {{.GeneratedAt.Format "2006-01-02"}}
**Assets:** {{range $i, $a := .AssetNames}}{{if $i}}, {{end}}{{$a}}{{end}}

---
{{range .Findings}}
## Report: [{{.Severity | toUpper}}] {{.Name}}

### Vulnerability Information

| Field | Value |
|-------|-------|
| Severity | **{{.Severity | toUpper}}** |
| Asset | {{.AssetName}} |
| Target | {{.TargetValue}} |
{{if .CveID}}| CVE | {{.CveID}} |
{{end}}{{if .CVSS}}| CVSS Score | {{printf "%.1f" .CVSS}} |
{{end}}{{if .EPSS}}| EPSS Score | {{printf "%.4f" .EPSS}} |
{{end}}{{if .IsKEV}}| Status | CISA Known Exploited Vulnerability |
{{end}}{{if .HasPOC}}| PoC | Public proof-of-concept available |
{{end}}

### Description

{{if .Description}}{{.Description}}{{else}}A {{.Severity}} severity vulnerability was detected on {{.TargetValue}}.{{end}}

{{if .Product}}**Affected Component:** {{.Product}}{{end}}

### Impact

This vulnerability could allow an attacker to compromise the confidentiality, integrity, or availability of the affected system.{{if .IsKEV}} This vulnerability is actively exploited in the wild according to CISA KEV.{{end}}

### Steps to Reproduce

1. Navigate to or connect to {{.TargetValue}}
2. The vulnerability {{.Name}} was identified by automated scanning
{{if .Extracted}}3. Extracted evidence:
` + "```" + `
{{.Extracted}}
` + "```" + `
{{end}}

### Supporting Material / References

{{if .CveID}}- NVD: {{.CveID}}
{{end}}- Detection via XPFarm / Nuclei{{if .TemplateID}} template {{.TemplateID}}{{end}}

### Remediation

Apply the latest security patches for {{if .Product}}{{.Product}}{{else}}the affected component{{end}}.

---
{{end}}

## Summary Statistics

| Severity | Count |
|----------|-------|
| Critical | {{.ByCritical}} |
| High | {{.ByHigh}} |
| Medium | {{.ByMedium}} |
| Low | {{.ByLow}} |
| Info | {{.ByInfo}} |`

const bugcrowdTemplate = `# Bugcrowd Vulnerability Submission

**Program:** {{range $i, $a := .AssetNames}}{{if $i}}, {{end}}{{$a}}{{end}}
**Date:** {{.GeneratedAt.Format "2006-01-02"}}
**Report Title:** {{.Title}}

---
{{range .Findings}}
## Submission: {{.Name}}

### VRT Classification

- **Severity:** {{.Severity | toUpper}}
- **Target:** {{.TargetValue}}
- **Asset:** {{.AssetName}}
{{if .CveID}}- **CVE:** {{.CveID}}{{end}}
{{if .CVSS}}- **CVSS:** {{printf "%.1f" .CVSS}}{{end}}
{{if .IsKEV}}- **CISA KEV:** This vulnerability is known to be exploited in the wild{{end}}
{{if .HasPOC}}- **PoC Available:** Yes, public proof-of-concept exists{{end}}

### Summary

{{if .Description}}{{.Description}}{{else}}Detected {{.Severity}}-severity issue {{.Name}} on {{.TargetValue}}.{{end}}

{{if .Product}}**Affected Software:** {{.Product}}{{end}}

### Reproduction Steps

1. **Target:** {{.TargetValue}}
2. **Vulnerability:** {{.Name}}{{if .TemplateID}} (Template: {{.TemplateID}}){{end}}
{{if .Extracted}}3. **Evidence:**
` + "```" + `
{{.Extracted}}
` + "```" + `
{{end}}

### Impact

{{if eq .Severity "critical"}}CRITICAL: Remote code execution, full system compromise, or mass data breach possible.{{else if eq .Severity "high"}}HIGH: Significant impact on data confidentiality, integrity, or availability.{{else if eq .Severity "medium"}}MEDIUM: Moderate security impact requiring remediation.{{else}}{{.Severity | toUpper}}: Security weakness requiring review and remediation.{{end}}
{{if .IsKEV}}
This is a CISA Known Exploited Vulnerability — active exploitation in the wild has been confirmed.{{end}}

### Remediation Recommendation

Apply the latest security patches for {{if .Product}}{{.Product}}{{else}}the affected component{{end}}.{{if .CveID}} Consult the vendor advisory for {{.CveID}}.{{end}}

---
{{end}}

## Aggregate Statistics

| Severity | Findings |
|----------|---------|
| Critical | {{.ByCritical}} |
| High | {{.ByHigh}} |
| Medium | {{.ByMedium}} |
| Low | {{.ByLow}} |
| Info | {{.ByInfo}} |
| CISA KEV | {{.KEVCount}} |

*Report generated by XPFarm. Verify all findings before submission.*`
