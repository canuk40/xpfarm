package planner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"xpfarm/internal/database"
	"xpfarm/internal/graph"
	graphstore "xpfarm/internal/storage/graph"
	"xpfarm/internal/overlord"
	"xpfarm/internal/planner/capabilities"
	"xpfarm/pkg/utils"

	"gorm.io/gorm"
)

// newID returns a random 16-byte hex string.
func newID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// reStripJSON strips markdown code fences that LLMs sometimes wrap JSON in.
var reStripJSON = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// plannerPromptTmpl is the embedded planning prompt template.
const plannerPromptTmpl = `You are an expert offensive security AI planner embedded in XPFarm.
Your job is to analyze the provided context and return a prioritized, actionable scan plan.

## Mode: {{.Mode}}
{{if eq .Mode "recon"}}Use ONLY passive reconnaissance tools. No active probing, no exploitation.{{end}}
{{if eq .Mode "web"}}Focus exclusively on web application testing. Include crawling, probing, and vuln scanning.{{end}}
{{if eq .Mode "binary"}}Focus exclusively on binary/APK/firmware analysis. No network-active tools.{{end}}
{{if eq .Mode "safe"}}Use ONLY risk=safe tools. Absolutely no destructive or active scanning.{{end}}
{{if eq .Mode "full"}}Use any available tool. Prioritize highest-impact steps first.{{end}}

## Constraints
- Maximum steps: {{.MaxSteps}}
- Maximum depth: {{.MaxDepth}}
- Do NOT include tools not in the Available Capabilities list below.
- Do NOT choose destructive tools unless mode is "full".
- Prioritize: KEV findings > high CVSS > unexplored targets > surface expansion.

## Assets
{{range .Assets}}
- Asset: {{.Name}}
  Targets: {{range $i, $t := .Targets}}{{if $i}}, {{end}}{{$t}}{{end}}
{{end}}

## Existing Findings
{{if .Findings}}
{{range .Findings}}
- [{{.Severity | upper}}] {{.Name}} on {{.Target}}{{if .CveID}} ({{.CveID}}){{end}}{{if .IsKEV}} KEV{{end}}
{{end}}
{{else}}
No findings yet. This is an initial scan — prioritize surface expansion.
{{end}}

## Graph Context
{{if .Graph}}
- Nodes: {{.Graph.NodeCount}} ({{range $k,$v := .Graph.TypeCounts}}{{$k}}:{{$v}} {{end}})
- Edges: {{.Graph.EdgeCount}}
{{if .Graph.ExploitNodes}}- Exploit paths: {{range .Graph.ExploitNodes}}{{.}} {{end}}{{end}}
{{else}}
No graph snapshot available.
{{end}}

## Available Capabilities
{{range .Capabilities}}
- agent={{.Agent}} tool={{.Tool}} categories=[{{range $i,$c := .Categories}}{{if $i}},{{end}}{{$c}}{{end}}] cost={{.Cost}} risk={{.Risk}} — {{.Desc}}
{{end}}

## Instructions
1. Select up to {{.MaxSteps}} steps from the Available Capabilities above.
2. Choose steps that will yield the most actionable security findings given the current context.
3. For each step, specify a concrete target from the Assets section.
4. Explain in 1 sentence WHY you chose each step.
5. Order steps from most to least impactful.
6. Respect the mode constraints.

## Output Format
Respond with ONLY a valid JSON object. No markdown, no code blocks, no explanation:

{
  "steps": [
    {
      "agent": "<agent name or builtin>",
      "tool": "<tool name>",
      "target": "<specific target>",
      "params": {},
      "reason": "<one sentence explanation>"
    }
  ]
}`

// plannerTemplateData is the data passed to the planning prompt template.
type plannerTemplateData struct {
	Mode         string
	MaxSteps     int
	MaxDepth     int
	Assets       []assetSummary
	Findings     []findingSummary
	Graph        *graphSummary
	Capabilities []capabilities.Capability
}

// buildPrompt renders the planning prompt with the given context.
func buildPrompt(data plannerTemplateData) (string, error) {
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}
	t, err := template.New("planner").Funcs(funcMap).Parse(plannerPromptTmpl)
	if err != nil {
		return "", fmt.Errorf("planner: prompt parse: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("planner: prompt render: %w", err)
	}
	return buf.String(), nil
}

// gatherContext queries the database and graph store for all context
// needed to build the planning prompt.
func gatherContext(db *gorm.DB, req PlannerRequest) (plannerTemplateData, error) {
	data := plannerTemplateData{
		Mode:     string(req.Mode),
		MaxSteps: req.MaxSteps,
		MaxDepth: req.MaxDepth,
	}
	if data.MaxSteps <= 0 {
		data.MaxSteps = 10
	}
	if data.MaxDepth <= 0 {
		data.MaxDepth = 3
	}

	// Assets + targets
	for _, assetID := range req.AssetIDs {
		var asset database.Asset
		if err := db.Preload("Targets").First(&asset, assetID).Error; err != nil {
			continue
		}
		as := assetSummary{Name: asset.Name}
		for _, t := range asset.Targets {
			as.Targets = append(as.Targets, t.Value)
		}
		data.Assets = append(data.Assets, as)

		// Findings for these assets
		for _, t := range asset.Targets {
			var vulns []database.Vulnerability
			db.Where("target_id = ?", t.ID).Find(&vulns)
			for _, v := range vulns {
				data.Findings = append(data.Findings, findingSummary{
					Target:   t.Value,
					Type:     "vuln",
					Name:     v.Name,
					Severity: v.Severity,
				})
			}
			var cves []database.CVE
			db.Where("target_id = ?", t.ID).Find(&cves)
			for _, c := range cves {
				data.Findings = append(data.Findings, findingSummary{
					Target:   t.Value,
					Type:     "cve",
					Name:     c.CveID + " — " + c.Product,
					Severity: c.Severity,
					CveID:    c.CveID,
					Product:  c.Product,
					IsKEV:    c.IsKEV,
				})
			}
		}
	}

	// Graph snapshot
	sg, err := graphstore.LoadLatestGraph(db)
	if err == nil && sg != nil {
		gs := &graphSummary{
			NodeCount:  len(sg.Nodes),
			EdgeCount:  len(sg.Edges),
			TypeCounts: map[string]int{},
		}
		for _, n := range sg.Nodes {
			gs.TypeCounts[string(n.Type)]++
			if n.Type == graph.NodeExploit {
				gs.ExploitNodes = append(gs.ExploitNodes, n.Label)
			}
		}
		data.Graph = gs
	}

	// Capabilities filtered by mode
	data.Capabilities = capabilities.GetByMode(string(req.Mode))

	return data, nil
}

// pollOverlordForJSON creates an Overlord session, sends the prompt, and
// polls until the assistant produces a stable JSON response or timeout fires.
func pollOverlordForJSON(ctx context.Context, prompt string) (string, error) {
	sess, err := overlord.CreateSession("Scan Plan — AI Optimizer")
	if err != nil {
		return "", fmt.Errorf("overlord session: %w", err)
	}
	if err := overlord.SendPromptAsync(sess.ID, prompt, ""); err != nil {
		return "", fmt.Errorf("overlord prompt: %w", err)
	}

	deadline := time.Now().Add(3 * time.Minute)
	var lastText string
	var stableCount int

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		time.Sleep(3 * time.Second)

		messages, err := overlord.GetSessionMessages(sess.ID)
		if err != nil {
			continue
		}
		text := extractAssistantText(messages)
		if text != "" && text == lastText {
			stableCount++
			if stableCount >= 2 {
				return text, nil
			}
		} else {
			lastText = text
			stableCount = 0
		}
	}
	if lastText != "" {
		return lastText, nil
	}
	return "", fmt.Errorf("overlord timed out waiting for plan response")
}

// extractAssistantText pulls the last assistant message text from Overlord messages.
func extractAssistantText(messages []map[string]interface{}) string {
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		if role, _ := msg["role"].(string); role != "assistant" {
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

// parseStepsJSON parses Overlord's response into plan steps.
// It handles raw JSON and markdown-fenced JSON blocks.
func parseStepsJSON(raw string) ([]PlanStep, error) {
	// Strip markdown code fences if present
	if m := reStripJSON.FindStringSubmatch(raw); m != nil {
		raw = m[1]
	}
	// Find the JSON object in the text if there's surrounding prose
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		raw = raw[start : end+1]
	}

	var result struct {
		Steps []struct {
			Agent  string         `json:"agent"`
			Tool   string         `json:"tool"`
			Target string         `json:"target"`
			Params map[string]any `json:"params"`
			Reason string         `json:"reason"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("planner: JSON parse failed: %w — raw: %.200s", err, raw)
	}

	steps := make([]PlanStep, 0, len(result.Steps))
	for i, s := range result.Steps {
		params := s.Params
		if params == nil {
			params = map[string]any{}
		}
		steps = append(steps, PlanStep{
			StepID: fmt.Sprintf("step-%02d", i+1),
			Agent:  s.Agent,
			Tool:   s.Tool,
			Target: s.Target,
			Params: params,
			Reason: s.Reason,
			Status: "pending",
		})
	}
	return steps, nil
}

// fallbackPlan builds a sensible default plan when Overlord is unavailable.
func fallbackPlan(data plannerTemplateData) []PlanStep {
	caps := data.Capabilities
	maxSteps := data.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 8
	}

	// Pick first target from first asset for the fallback
	target := "unknown"
	if len(data.Assets) > 0 && len(data.Assets[0].Targets) > 0 {
		target = data.Assets[0].Targets[0]
	}

	var steps []PlanStep
	for i, cap := range caps {
		if i >= maxSteps {
			break
		}
		steps = append(steps, PlanStep{
			StepID: fmt.Sprintf("step-%02d", i+1),
			Agent:  cap.Agent,
			Tool:   cap.Tool,
			Target: target,
			Params: map[string]any{},
			Reason: cap.Desc,
			Status: "pending",
		})
	}
	return steps
}

// GenerateScanPlan is the primary entry point. It gathers context, builds
// a prompt, calls Overlord, and returns a ready-to-execute ScanPlan.
// If Overlord is unavailable it falls back to a capability-ordered default plan.
func GenerateScanPlan(ctx context.Context, db *gorm.DB, req PlannerRequest) (*ScanPlan, error) {
	if req.Mode == "" {
		req.Mode = ModeFull
	}

	data, err := gatherContext(db, req)
	if err != nil {
		return nil, fmt.Errorf("planner: context: %w", err)
	}

	var steps []PlanStep

	if status := overlord.CheckConnection(); status.Connected {
		prompt, err := buildPrompt(data)
		if err != nil {
			utils.LogError("planner: prompt build failed: %v — using fallback", err)
		} else {
			raw, err := pollOverlordForJSON(ctx, prompt)
			if err != nil {
				utils.LogError("planner: overlord failed: %v — using fallback", err)
			} else {
				parsed, err := parseStepsJSON(raw)
				if err != nil {
					utils.LogError("planner: parse failed: %v — using fallback", err)
				} else {
					steps = parsed
				}
			}
		}
	} else {
		utils.LogWarning("planner: Overlord offline — using capability-ordered fallback plan")
	}

	if len(steps) == 0 {
		steps = fallbackPlan(data)
	}

	// Cap to MaxSteps
	if req.MaxSteps > 0 && len(steps) > req.MaxSteps {
		steps = steps[:req.MaxSteps]
	}

	now := time.Now().UTC()
	return &ScanPlan{
		ID:        newID(),
		AssetIDs:  req.AssetIDs,
		Mode:      req.Mode,
		Steps:     steps,
		Status:    StatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}
