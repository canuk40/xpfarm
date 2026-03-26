// Natural language chat interface for XPFarm (#12).
// Parses user messages to detect scan intents and answer questions.
// Uses LLM when API key is available, falls back to keyword matching.
package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/core"
	"xpfarm/internal/database"
)

var chatHTTPClient = &http.Client{Timeout: 20 * time.Second}

// ChatAction describes an action the UI should perform after a chat response.
type ChatAction struct {
	Type   string `json:"type"`   // "start_scan", "navigate", "none"
	Target string `json:"target,omitempty"`
	Asset  string `json:"asset,omitempty"`
	URL    string `json:"url,omitempty"`
}

func handleChatMessage(db *gorm.DB, message string) (string, ChatAction) {
	lower := strings.ToLower(strings.TrimSpace(message))

	// Try LLM parsing if key available
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return handleChatWithLLM(db, message, key, "openai")
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return handleChatWithLLM(db, message, key, "anthropic")
	}

	// Keyword fallback
	return handleChatKeywords(db, lower, message)
}

func handleChatKeywords(db *gorm.DB, lower, original string) (string, ChatAction) {
	// Detect scan intent: "scan example.com", "start scan for 10.0.0.1", "run a scan on ..."
	scanKeywords := []string{"scan ", "recon ", "enumerate ", "check "}
	for _, kw := range scanKeywords {
		if idx := strings.Index(lower, kw); idx != -1 {
			rest := strings.Fields(original[idx+len(kw):])
			if len(rest) > 0 {
				target := rest[0]
				// Strip trailing punctuation
				target = strings.TrimRight(target, ".,!?;:")
				mgr := core.GetManager()
				mgr.StartScan(target, "Default")
				return fmt.Sprintf("Scan started for **%s**. Check the dashboard for progress.", target),
					ChatAction{Type: "start_scan", Target: target, Asset: "Default"}
			}
		}
	}

	// Status/stats query
	if strings.Contains(lower, "finding") || strings.Contains(lower, "vulnerabilit") || strings.Contains(lower, "cve") {
		var vulnCount, cveCount int64
		db.Model(&database.Vulnerability{}).Where("fp_status != 'false_positive'").Count(&vulnCount)
		db.Model(&database.CVE{}).Count(&cveCount)
		return fmt.Sprintf("Currently tracking **%d vulnerabilities** and **%d CVEs** across all assets.", vulnCount, cveCount),
			ChatAction{Type: "navigate", URL: "/findings"}
	}

	if strings.Contains(lower, "asset") || strings.Contains(lower, "target") {
		var assetCount, targetCount int64
		db.Model(&database.Asset{}).Count(&assetCount)
		db.Model(&database.Target{}).Count(&targetCount)
		return fmt.Sprintf("You have **%d assets** with **%d targets** discovered.", assetCount, targetCount),
			ChatAction{Type: "navigate", URL: "/"}
	}

	if strings.Contains(lower, "report") {
		return "You can generate a report from the **Reports** page or enable auto-report in Scan Settings.",
			ChatAction{Type: "navigate", URL: "/reports"}
	}

	if strings.Contains(lower, "help") || lower == "?" {
		return `Here's what I can do:
- **Start a scan**: "scan example.com" or "recon 10.0.0.1"
- **Check findings**: "show vulnerabilities" or "how many CVEs"
- **Check assets**: "list assets" or "show targets"
- **Reports**: "generate a report"`, ChatAction{Type: "none"}
	}

	return "I'm not sure what you mean. Try saying **\"scan example.com\"** or **\"show findings\"**. Type **help** for more options.",
		ChatAction{Type: "none"}
}

type llmChatIntent struct {
	Intent  string `json:"intent"` // "start_scan", "query_findings", "query_assets", "query_status", "help", "unknown"
	Target  string `json:"target,omitempty"`
	Asset   string `json:"asset,omitempty"`
	Reply   string `json:"reply"`
}

func handleChatWithLLM(db *gorm.DB, message, apiKey, provider string) (string, ChatAction) {
	// Gather context for the LLM
	var vulnCount, cveCount, targetCount int64
	db.Model(&database.Vulnerability{}).Where("fp_status != 'false_positive'").Count(&vulnCount)
	db.Model(&database.CVE{}).Count(&cveCount)
	db.Model(&database.Target{}).Count(&targetCount)

	systemPrompt := fmt.Sprintf(`You are XPFarm's AI assistant. XPFarm is a vulnerability scanner.
Current state: %d targets, %d vulnerabilities, %d CVEs.

Parse the user message and respond with JSON:
{
  "intent": "start_scan" | "query_findings" | "query_assets" | "query_status" | "help" | "unknown",
  "target": "<target if intent=start_scan>",
  "asset": "<asset name, default 'Default'>",
  "reply": "<friendly markdown reply to show the user>"
}
Only respond with valid JSON.`, targetCount, vulnCount, cveCount)

	var content string
	var err error
	if provider == "openai" {
		content, err = chatOpenAI(message, systemPrompt, apiKey)
	} else {
		content, err = chatAnthropic(message, systemPrompt, apiKey)
	}

	if err != nil || content == "" {
		return handleChatKeywords(db, strings.ToLower(message), message)
	}

	// Parse LLM response
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start == -1 || end == -1 {
		return handleChatKeywords(db, strings.ToLower(message), message)
	}

	var intent llmChatIntent
	if err := json.Unmarshal([]byte(content[start:end+1]), &intent); err != nil {
		return handleChatKeywords(db, strings.ToLower(message), message)
	}

	action := ChatAction{Type: "none"}
	switch intent.Intent {
	case "start_scan":
		if intent.Target != "" {
			if intent.Asset == "" {
				intent.Asset = "Default"
			}
			mgr := core.GetManager()
			mgr.StartScan(intent.Target, intent.Asset)
			action = ChatAction{Type: "start_scan", Target: intent.Target, Asset: intent.Asset}
		}
	case "query_findings":
		action = ChatAction{Type: "navigate", URL: "/findings"}
	case "query_assets":
		action = ChatAction{Type: "navigate", URL: "/"}
	}

	reply := intent.Reply
	if reply == "" {
		reply = "Done."
	}
	return reply, action
}

func chatOpenAI(userMsg, systemMsg, apiKey string) (string, error) {
	payload := map[string]interface{}{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": systemMsg},
			{"role": "user", "content": userMsg},
		},
		"max_tokens":  200,
		"temperature": 0,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := chatHTTPClient.Do(req)
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
		return "", err
	}
	return result.Choices[0].Message.Content, nil
}

func chatAnthropic(userMsg, systemMsg, apiKey string) (string, error) {
	payload := map[string]interface{}{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 200,
		"system":     systemMsg,
		"messages":   []map[string]string{{"role": "user", "content": userMsg}},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	resp, err := chatHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Content) == 0 {
		return "", err
	}
	return result.Content[0].Text, nil
}
