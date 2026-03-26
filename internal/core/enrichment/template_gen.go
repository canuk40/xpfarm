// AI-powered Nuclei template generation (#6).
// When a CVE has no existing Nuclei template (has_template=false), calls an LLM
// to generate a basic detection template. Saves to a local custom-templates/ directory
// and indexes it in the NucleiTemplate table for immediate use.
// Requires OPENAI_API_KEY or ANTHROPIC_API_KEY. No-ops gracefully if absent.
package enrichment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var templateGenClient = &http.Client{Timeout: 45 * time.Second}

const customTemplatesDir = "/opt/nuclei-templates/custom-generated"

// GenerateMissingNucleiTemplates finds CVEs for targetID with no Nuclei template
// and attempts to generate one per CVE using an LLM. Saves generated templates
// to disk and indexes them for immediate use by the Nuclei stage.
func GenerateMissingNucleiTemplates(db *gorm.DB, targetID uint) {
	openaiKey := os.Getenv("OPENAI_API_KEY")
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")
	if openaiKey == "" && anthropicKey == "" {
		return
	}

	// Find CVEs that have no template and are high severity
	var cves []database.CVE
	db.Where(`target_id = ? AND has_template = false AND severity IN ('critical','high') AND cve_id != '' AND cve_id != 'unknown'`,
		targetID).Limit(5).Find(&cves) // Limit to 5 per run to control costs
	if len(cves) == 0 {
		return
	}

	if err := os.MkdirAll(customTemplatesDir, 0755); err != nil {
		utils.LogDebug("[TemplateGen] Cannot create templates dir: %v", err)
		return
	}

	generated := 0
	for _, cve := range cves {
		outPath := filepath.Join(customTemplatesDir, strings.ToLower(cve.CveID)+".yaml")
		if _, err := os.Stat(outPath); err == nil {
			// Already exists — just index it
			indexGeneratedTemplate(db, cve.CveID, outPath)
			continue
		}

		tmpl, err := generateTemplateForCVE(cve, openaiKey, anthropicKey)
		if err != nil {
			utils.LogDebug("[TemplateGen] Failed for %s: %v", cve.CveID, err)
			continue
		}
		if tmpl == "" {
			continue
		}

		if err := os.WriteFile(outPath, []byte(tmpl), 0644); err != nil {
			utils.LogDebug("[TemplateGen] Write failed for %s: %v", cve.CveID, err)
			continue
		}

		// Index the new template
		indexGeneratedTemplate(db, cve.CveID, outPath)
		// Mark CVE as having a template now
		db.Model(&cve).Update("has_template", true)
		generated++
		utils.LogSuccess("[TemplateGen] Generated template for %s → %s", cve.CveID, outPath)
	}

	if generated > 0 {
		utils.LogSuccess("[TemplateGen] Generated %d Nuclei templates for target %d", generated, targetID)
	}
}

func indexGeneratedTemplate(db *gorm.DB, cveID, filePath string) {
	templateID := "custom/" + strings.ToLower(cveID)
	db.Where(database.NucleiTemplate{TemplateID: templateID}).FirstOrCreate(&database.NucleiTemplate{
		TemplateID: templateID,
		FilePath:   filePath,
		Tags:       cveID + ",ai-generated",
		Severity:   "high",
		Name:       "AI-generated: " + cveID,
	})
}

const templateGenPrompt = `You are a Nuclei template author. Generate a valid Nuclei YAML template for detecting %s.

Requirements:
- Use id: %s
- Set info.name, info.severity (critical/high/medium), info.tags including the CVE ID
- Include at least one HTTP request with a matcher
- Keep it simple: detect vulnerability presence, not exploit it
- Use status matchers or word matchers on known vulnerable response patterns
- If you don't know the exact detection, create a version/banner check template

Only output the raw YAML, no explanation, no markdown code fences.`

func generateTemplateForCVE(cve database.CVE, openaiKey, anthropicKey string) (string, error) {
	prompt := fmt.Sprintf(templateGenPrompt, cve.CveID, strings.ToLower(cve.CveID))

	var content string
	var err error
	if openaiKey != "" {
		content, err = callOpenAIForTemplate(prompt, openaiKey)
	} else {
		content, err = callAnthropicForTemplate(prompt, anthropicKey)
	}
	if err != nil {
		return "", err
	}

	// Validate it looks like YAML with nuclei structure
	if !strings.Contains(content, "id:") || !strings.Contains(content, "requests:") {
		return "", fmt.Errorf("generated content doesn't look like a valid template")
	}

	// Strip any markdown fences if the LLM added them
	if idx := strings.Index(content, "id:"); idx > 0 {
		content = content[idx:]
	}
	if idx := strings.LastIndex(content, "\n---"); idx > 0 {
		content = content[:idx]
	}

	return strings.TrimSpace(content) + "\n", nil
}

func callOpenAIForTemplate(prompt, apiKey string) (string, error) {
	payload := map[string]interface{}{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":  800,
		"temperature": 0.1,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := templateGenClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Choices []struct {
			Message struct{ Content string `json:"content"` } `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Choices) == 0 {
		return "", fmt.Errorf("empty openai response")
	}
	return result.Choices[0].Message.Content, nil
}

func callAnthropicForTemplate(prompt, apiKey string) (string, error) {
	payload := map[string]interface{}{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 800,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	resp, err := templateGenClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Content) == 0 {
		return "", fmt.Errorf("empty anthropic response")
	}
	return result.Content[0].Text, nil
}
