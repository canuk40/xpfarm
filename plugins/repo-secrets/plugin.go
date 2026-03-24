// Package reposecretsplugin is the repo-secrets XPFarm plugin.
//
// It registers:
//   - SecretsScannerTool — runs Gitleaks (if installed) + Go SecretFinder
//   - SecretsAgent       — wraps the tool and summarises findings by type
//   - secrets-pipeline   — single-step pipeline backed by SecretsAgent
package reposecretsplugin

import (
	"context"
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
	"xpfarm/internal/plugin"
	"xpfarm/internal/repo_scanner/secrets"
)

//go:embed plugin.yaml
var rawManifest []byte

func init() {
	var m plugin.Manifest
	if err := yaml.Unmarshal(rawManifest, &m); err != nil {
		panic(fmt.Sprintf("repo-secrets: malformed plugin.yaml: %v", err))
	}
	plugin.RegisterManifest(m)

	tool := &SecretsScannerTool{}
	plugin.RegisterTool(tool)
	plugin.RegisterAgent(&SecretsAgent{tool: tool})
	plugin.RegisterPipeline("secrets-pipeline", []plugin.PipelineStep{
		{
			Name:   "secret-scan",
			Agent:  "secrets-agent",
			Params: map[string]any{},
		},
	})
}

// ---------------------------------------------------------------------------
// SecretsScannerTool
// ---------------------------------------------------------------------------

// SecretsScannerTool runs secret scanning (Gitleaks + SecretFinder) on a
// local repository path.
//
// Required input key:
//   - "path"   string — absolute or relative path to the repository root
//
// Optional input key:
//   - "target" string — repository URL or identifier embedded in findings
type SecretsScannerTool struct{}

func (t *SecretsScannerTool) Name() string { return "secrets-scanner" }
func (t *SecretsScannerTool) Description() string {
	return "Runs Gitleaks (if installed) and the built-in SecretFinder on a local repository. " +
		"Input: {\"path\": \"/repo/path\", \"target\": \"https://github.com/…\"}. " +
		"Returns {\"finding_count\": N, \"gitleaks_count\": N, \"secretfinder_count\": N, \"findings\": [{...}, …]}."
}

func (t *SecretsScannerTool) Run(_ context.Context, input map[string]any) (map[string]any, error) {
	path, ok := input["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("secrets-scanner: missing required input key \"path\"")
	}
	target, _ := input["target"].(string)
	if target == "" {
		target = path
	}

	var glCount, sfCount int
	var allFindings []map[string]any

	// ── Gitleaks ──────────────────────────────────────────────────────────────
	if err := secrets.CheckGitleaksInstalled(); err == nil {
		gl := &secrets.GitleaksScanner{RepoURL: target}
		glFindings, err := gl.Scan(path)
		if err != nil {
			// Non-fatal: log in output rather than failing
			allFindings = append(allFindings, map[string]any{
				"source": "gitleaks",
				"error":  err.Error(),
			})
		} else {
			glCount = len(glFindings)
			for _, f := range glFindings {
				allFindings = append(allFindings, map[string]any{
					"id":          f.ID,
					"source":      f.Source,
					"target":      f.Target,
					"location":    f.Location,
					"title":       f.Title,
					"description": f.Description,
					"severity":    string(f.Severity),
					"cwe":         f.CWE,
					"evidence":    f.Evidence,
					"tags":        f.Tags,
				})
			}
		}
	}

	// ── SecretFinder ──────────────────────────────────────────────────────────
	sf := &secrets.SecretFinderScanner{RepoURL: target}
	sfFindings, err := sf.Scan(path)
	if err != nil {
		allFindings = append(allFindings, map[string]any{
			"source": "secretfinder",
			"error":  err.Error(),
		})
	} else {
		sfCount = len(sfFindings)
		for _, f := range sfFindings {
			allFindings = append(allFindings, map[string]any{
				"id":          f.ID,
				"source":      f.Source,
				"target":      f.Target,
				"location":    f.Location,
				"title":       f.Title,
				"description": f.Description,
				"severity":    string(f.Severity),
				"cwe":         f.CWE,
				"evidence":    f.Evidence,
				"tags":        f.Tags,
			})
		}
	}

	if allFindings == nil {
		allFindings = []map[string]any{}
	}

	return map[string]any{
		"finding_count":      glCount + sfCount,
		"gitleaks_count":     glCount,
		"secretfinder_count": sfCount,
		"findings":           allFindings,
	}, nil
}

// ---------------------------------------------------------------------------
// SecretsAgent
// ---------------------------------------------------------------------------

// SecretsAgent wraps SecretsScannerTool and adds a pattern-type breakdown.
type SecretsAgent struct {
	tool *SecretsScannerTool
}

func (a *SecretsAgent) Name() string         { return "secrets-agent" }
func (a *SecretsAgent) Tools() []plugin.Tool { return []plugin.Tool{a.tool} }

func (a *SecretsAgent) Handle(ctx context.Context, task plugin.Task) (plugin.Result, error) {
	input := make(map[string]any, len(task.Payload)+1)
	for k, v := range task.Payload {
		input[k] = v
	}
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

	// Summarise by CWE category (secret type)
	cweCount := map[string]int{}
	if findings, ok := out["findings"].([]map[string]any); ok {
		for _, f := range findings {
			cwe, _ := f["cwe"].(string)
			if cwe == "" {
				cwe = "unknown"
			}
			cweCount[cwe]++
		}
	}
	out["cwe_summary"] = cweCount

	return plugin.Result{Output: out}, nil
}
