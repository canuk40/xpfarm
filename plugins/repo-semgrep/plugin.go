// Package reposemgrepplugin is the repo-semgrep XPFarm plugin.
//
// It registers:
//   - SemgrepScannerTool — runs Semgrep --config auto against a local repo path
//   - SemgrepAgent       — wraps the tool and surfaces findings in a Task result
//   - semgrep-pipeline   — single-step pipeline backed by SemgrepAgent
package reposemgrepplugin

import (
	"context"
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
	"xpfarm/internal/plugin"
	reposemgrep "xpfarm/internal/repo_scanner/semgrep"
)

//go:embed plugin.yaml
var rawManifest []byte

func init() {
	var m plugin.Manifest
	if err := yaml.Unmarshal(rawManifest, &m); err != nil {
		panic(fmt.Sprintf("repo-semgrep: malformed plugin.yaml: %v", err))
	}
	plugin.RegisterManifest(m)

	tool := &SemgrepScannerTool{}
	plugin.RegisterTool(tool)
	plugin.RegisterAgent(&SemgrepAgent{tool: tool})
	plugin.RegisterPipeline("semgrep-pipeline", []plugin.PipelineStep{
		{
			Name:   "sast-scan",
			Agent:  "semgrep-agent",
			Params: map[string]any{"config": "auto"},
		},
	})
}

// ---------------------------------------------------------------------------
// SemgrepScannerTool
// ---------------------------------------------------------------------------

// SemgrepScannerTool runs Semgrep against a local repository path.
//
// Required input key:
//   - "path"   string — absolute or relative path to the repository root
//
// Optional input key:
//   - "target" string — repository URL or identifier used in findings (defaults to path)
type SemgrepScannerTool struct{}

func (t *SemgrepScannerTool) Name() string { return "semgrep-scanner" }
func (t *SemgrepScannerTool) Description() string {
	return "Runs Semgrep SAST with the auto ruleset on a local repository. " +
		"Input: {\"path\": \"/repo/path\", \"target\": \"https://github.com/…\"}. " +
		"Returns {\"finding_count\": N, \"findings\": [{...}, …]}."
}

func (t *SemgrepScannerTool) Run(_ context.Context, input map[string]any) (map[string]any, error) {
	path, ok := input["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("semgrep-scanner: missing required input key \"path\"")
	}
	target, _ := input["target"].(string)
	if target == "" {
		target = path
	}

	findings, err := reposemgrep.Run(path, target)
	if err != nil {
		return nil, fmt.Errorf("semgrep-scanner: %w", err)
	}

	// Convert findings to []map[string]any for JSON serialization
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"id":          f.ID,
			"source":      f.Source,
			"target":      f.Target,
			"location":    f.Location,
			"title":       f.Title,
			"description": f.Description,
			"severity":    string(f.Severity),
			"cwe":         f.CWE,
			"cve":         f.CVE,
			"evidence":    f.Evidence,
			"tags":        f.Tags,
		})
	}

	return map[string]any{
		"finding_count": len(findings),
		"findings":      out,
	}, nil
}

// ---------------------------------------------------------------------------
// SemgrepAgent
// ---------------------------------------------------------------------------

// SemgrepAgent wraps SemgrepScannerTool and adds a severity breakdown summary.
type SemgrepAgent struct {
	tool *SemgrepScannerTool
}

func (a *SemgrepAgent) Name() string         { return "semgrep-agent" }
func (a *SemgrepAgent) Tools() []plugin.Tool { return []plugin.Tool{a.tool} }

func (a *SemgrepAgent) Handle(ctx context.Context, task plugin.Task) (plugin.Result, error) {
	input := make(map[string]any, len(task.Payload)+1)
	for k, v := range task.Payload {
		input[k] = v
	}
	// task.Target is the repo path/URL; plugins receive it separately.
	if _, hasPath := input["path"]; !hasPath {
		input["path"] = task.Target
	}
	if _, hasTarget := input["target"]; !hasTarget {
		input["target"] = task.Target
	}

	out, err := a.tool.Run(ctx, input)
	if err != nil {
		return plugin.Result{Error: err.Error()}, err
	}

	// Build severity summary
	summary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	if findings, ok := out["findings"].([]map[string]any); ok {
		for _, f := range findings {
			if sev, ok := f["severity"].(string); ok {
				summary[sev]++
			}
		}
	}
	out["severity_summary"] = summary

	return plugin.Result{Output: out}, nil
}
