package overlord

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OverlordURL is the base URL of the OpenCode serve API.
var OverlordURL = "http://overlord:3000"

// basePath caches the resolved project root for file operations
var (
	basePath     string
	basePathOnce sync.Once
)

func getBasePath() string {
	basePathOnce.Do(func() {
		if _, err := os.Stat("overlord"); err == nil {
			basePath, _ = filepath.Abs(".")
			return
		}
		exe, err := os.Executable()
		if err == nil {
			basePath = filepath.Dir(exe)
			return
		}
		basePath = "."
	})
	return basePath
}

func init() {
	if u := os.Getenv("OVERLORD_URL"); u != "" {
		OverlordURL = u
	}
}

// --- Status Types ---

type ConnectionStatus struct {
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
	URL       string `json:"url"`
	Version   string `json:"version,omitempty"`
}

type AgentInfo struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Description string `json:"description"`
	Color       string `json:"color,omitempty"`
	Steps       int    `json:"steps,omitempty"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type OverlordStatus struct {
	Connection ConnectionStatus `json:"connection"`
	Agents     []AgentInfo      `json:"agents"`
	Tools      []ToolInfo       `json:"tools"`
}

// --- Provider Definitions ---

type ProviderDef struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	EnvKeys     []string `json:"env_keys"`
	Description string   `json:"description"`
	HasFree     bool     `json:"has_free"`
}

func GetProviders() []ProviderDef {
	return []ProviderDef{
		{ID: "opencode-zen", Name: "OpenCode Zen", EnvKeys: []string{"OPENCODE_API_KEY"}, Description: "Curated models from the OpenCode team", HasFree: true},
		{ID: "opencode-go", Name: "OpenCode Go", EnvKeys: []string{"OPENCODE_API_KEY"}, Description: "$5-10/mo subscription for open coding models", HasFree: false},
		{ID: "anthropic", Name: "Anthropic", EnvKeys: []string{"ANTHROPIC_API_KEY"}, Description: "Claude Opus, Sonnet, Haiku models", HasFree: false},
		{ID: "openai", Name: "OpenAI", EnvKeys: []string{"OPENAI_API_KEY"}, Description: "GPT models", HasFree: false},
		{ID: "azure-openai", Name: "Azure OpenAI", EnvKeys: []string{"AZURE_API_KEY", "AZURE_RESOURCE_NAME"}, Description: "Azure-hosted OpenAI models", HasFree: false},
		{ID: "google-vertex", Name: "Google Vertex AI", EnvKeys: []string{"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"}, Description: "Google Cloud AI models", HasFree: false},
		{ID: "groq", Name: "Groq", EnvKeys: []string{"GROQ_API_KEY"}, Description: "Fast inference engine", HasFree: false},
		{ID: "deepseek", Name: "DeepSeek", EnvKeys: []string{"DEEPSEEK_API_KEY"}, Description: "DeepSeek Reasoner and others", HasFree: false},
		{ID: "openrouter", Name: "OpenRouter", EnvKeys: []string{"OPENROUTER_API_KEY"}, Description: "100+ model aggregator", HasFree: false},
		{ID: "xai", Name: "xAI", EnvKeys: []string{"XAI_API_KEY"}, Description: "Grok models", HasFree: false},
		{ID: "fireworks", Name: "Fireworks AI", EnvKeys: []string{"FIREWORKS_API_KEY"}, Description: "Fast open model hosting", HasFree: false},
		{ID: "together", Name: "Together AI", EnvKeys: []string{"TOGETHER_API_KEY"}, Description: "Open model hosting", HasFree: false},
		{ID: "deepinfra", Name: "Deep Infra", EnvKeys: []string{"DEEPINFRA_API_KEY"}, Description: "Open model hosting", HasFree: false},
		{ID: "minimax", Name: "MiniMax", EnvKeys: []string{"MINIMAX_API_KEY"}, Description: "M2.1 and free tier models", HasFree: true},
		{ID: "cerebras", Name: "Cerebras", EnvKeys: []string{"CEREBRAS_API_KEY"}, Description: "Fast inference", HasFree: false},
		{ID: "moonshot", Name: "Moonshot AI", EnvKeys: []string{"MOONSHOT_API_KEY"}, Description: "Kimi K2", HasFree: false},
		{ID: "nebius", Name: "Nebius", EnvKeys: []string{"NEBIUS_API_KEY"}, Description: "Token Factory", HasFree: false},
		{ID: "zai", Name: "Z.AI", EnvKeys: []string{"ZAI_API_KEY"}, Description: "GLM models", HasFree: false},
		{ID: "ollama", Name: "Ollama (Local)", EnvKeys: []string{}, Description: "Free local models, no API key needed", HasFree: true},
		{ID: "cloudflare", Name: "Cloudflare AI", EnvKeys: []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_GATEWAY_ID"}, Description: "Unified billing gateway", HasFree: false},
		{ID: "vercel", Name: "Vercel AI", EnvKeys: []string{"VERCEL_API_KEY"}, Description: "AI gateway at list price", HasFree: false},
	}
}

// --- Connection Check: GET /session (reliable JSON endpoint) ---

func CheckConnection() ConnectionStatus {
	client := &http.Client{Timeout: 3 * time.Second}

	// Use /session endpoint — always returns JSON (array of sessions)
	resp, err := client.Get(OverlordURL + "/session")
	if err != nil {
		return ConnectionStatus{Connected: false, Error: err.Error(), URL: OverlordURL}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return ConnectionStatus{Connected: false, Error: fmt.Sprintf("HTTP %d", resp.StatusCode), URL: OverlordURL}
	}

	return ConnectionStatus{Connected: true, URL: OverlordURL}
}

// --- Config Parsing (from local file) ---

func GetStatus() OverlordStatus {
	status := OverlordStatus{
		Connection: CheckConnection(),
	}

	configPath := findConfigPath()
	if configPath == "" {
		return status
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return status
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return status
	}

	if agentMap, ok := config["agent"].(map[string]interface{}); ok {
		for name, v := range agentMap {
			agentData, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			info := AgentInfo{Name: name}
			if m, ok := agentData["mode"].(string); ok {
				info.Mode = m
			}
			if d, ok := agentData["description"].(string); ok {
				info.Description = d
			}
			if c, ok := agentData["color"].(string); ok {
				info.Color = c
			}
			if s, ok := agentData["steps"].(float64); ok {
				info.Steps = int(s)
			}
			status.Agents = append(status.Agents, info)
		}
	}

	if toolMap, ok := config["tools"].(map[string]interface{}); ok {
		for name, v := range toolMap {
			enabled, _ := v.(bool)
			status.Tools = append(status.Tools, ToolInfo{Name: name, Enabled: enabled})
		}
	}

	return status
}

func findConfigPath() string {
	candidates := []string{
		filepath.Join(getBasePath(), "overlord", "config", "opencode.json"),
		"/root/.config/opencode/opencode.json",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// --- Session Management ---

type Session struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	ProjectID string `json:"projectID,omitempty"`
	Version   string `json:"version,omitempty"`
	Time      struct {
		Created int64 `json:"created"`
		Updated int64 `json:"updated"`
	} `json:"time"`
}

// GetSessions lists all sessions via GET /session
func GetSessions() ([]Session, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(OverlordURL + "/session")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var sessions []Session
	if err := json.Unmarshal(body, &sessions); err != nil {
		return nil, fmt.Errorf("invalid response: %s", string(body))
	}
	return sessions, nil
}

// GetSessionMessages fetches messages for a session via GET /session/{id}/message
func GetSessionMessages(sessionID string) ([]map[string]interface{}, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/session/%s/message", OverlordURL, sessionID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var messages []map[string]interface{}
	json.Unmarshal(body, &messages)
	return messages, nil
}

// CreateSession creates a new session via POST /session
func CreateSession(title string) (*Session, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	payload, _ := json.Marshal(map[string]string{"title": title})
	resp, err := client.Post(OverlordURL+"/session", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("invalid response: %s", string(body))
	}
	return &session, nil
}

// SendPromptAsync sends a user message asynchronously via POST /session/{id}/prompt_async
// Returns immediately — content streams via SSE events
func SendPromptAsync(sessionID, message string) error {
	client := &http.Client{Timeout: 15 * time.Second}

	payload := map[string]interface{}{
		"parts": []map[string]string{
			{"type": "text", "text": message},
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := client.Post(
		fmt.Sprintf("%s/session/%s/prompt_async", OverlordURL, sessionID),
		"application/json",
		strings.NewReader(string(payloadBytes)),
	)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// AbortSession aborts the current processing via POST /session/{id}/abort
func AbortSession(sessionID string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("%s/session/%s/abort", OverlordURL, sessionID),
		"application/json",
		strings.NewReader("{}"),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ProxySSE streams the global /event SSE endpoint to the client.
// The frontend filters events by sessionID.
func ProxySSE(w http.ResponseWriter) error {
	client := &http.Client{Timeout: 0}
	resp, err := client.Get(OverlordURL + "/event")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	return nil
}

// SetAuth sets an API key on the OpenCode server via PUT /auth/{providerID}
func SetAuth(providerID, apiKey string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	payload, _ := json.Marshal(map[string]string{
		"type": "api",
		"key":  apiKey,
	})

	req, err := http.NewRequest("PUT",
		fmt.Sprintf("%s/auth/%s", OverlordURL, providerID),
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// --- Binary Management ---

func ListBinaries() ([]string, error) {
	dir := filepath.Join(getBasePath(), "overlord", "binaries")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{}, nil
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	return files, nil
}

func SaveBinary(filename string, data io.Reader) error {
	dir := filepath.Join(getBasePath(), "overlord", "binaries")
	os.MkdirAll(dir, 0755)

	path := filepath.Join(dir, filepath.Base(filename))
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, data)
	return err
}

func ListOutputs() ([]string, error) {
	dir := filepath.Join(getBasePath(), "overlord", "output")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{}, nil
	}

	var files []string
	for _, e := range entries {
		files = append(files, e.Name())
	}
	return files, nil
}

// --- Auth File Management (fallback for non-API auth) ---

func WriteAuthFile(keys map[string]string) error {
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(getBasePath(), "overlord", "auth.json")
	return os.WriteFile(path, data, 0600)
}
