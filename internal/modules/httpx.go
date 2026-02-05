package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"xpfarm/pkg/utils"
)

type Httpx struct{}

func (h *Httpx) Name() string {
	return "httpx"
}

func (h *Httpx) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("httpx")
	_, err := exec.LookPath(path)
	return err == nil
}

func (h *Httpx) Install() error {
	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install httpx: %v", err)
	}
	return nil
}

type HttpxResult struct {
	Timestamp   string   `json:"timestamp"`
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	WebServer   string   `json:"webserver"`
	Tech        []string `json:"tech"`
	StatusCode  int      `json:"status_code"`
	ContentLen  int      `json:"content_length"`
	WordCount   int      `json:"word_count"`
	LineCount   int      `json:"lines"`
	ContentType string   `json:"content_type"`
	Location    string   `json:"location"`
	Host        string   `json:"host"`
	A           []string `json:"a"` // Actual IPs
	CNAMEs      []string `json:"cname"`
	CDN         bool     `json:"cdn"`
	CDNName     string   `json:"cdn_name"`
	Response    string   `json:"response"` // Need to check if this is raw body or requires separate flag logic
}

func (h *HttpxResult) GetTech() string {
	return strings.Join(h.Tech, ", ")
}

func (h *HttpxResult) GetCNAME() string {
	return strings.Join(h.CNAMEs, ", ")
}

// RunRich takes a list of URLs and runs rich analysis
func (h *Httpx) RunRich(ctx context.Context, urls []string) ([]HttpxResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	utils.LogInfo("Running httpx rich scan on %d urls...", len(urls))
	path := utils.ResolveBinaryPath("httpx")

	// Flags requested: -status-code -content-type -content-length -location -title -web-server -tech-detect -ip -cname -word-count -line-count -cdn -include-response -follow-host-redirects -max-redirects 2 -json
	args := []string{
		"-status-code", "-content-type", "-content-length", "-location", "-title",
		"-web-server", "-tech-detect", "-ip", "-cname", "-word-count", "-line-count",
		"-cdn", "-include-response", "-follow-host-redirects", "-max-redirects", "2",
		"-json", "-silent",
	}

	cmd := exec.CommandContext(ctx, path, args...)

	// Stdin Pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		for _, u := range urls {
			if _, err := io.WriteString(stdin, u+"\n"); err != nil {
				utils.LogDebug("Failed to write to httpx stdin: %v", err)
			}
		}
	}()

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Httpx checks might fail for some but still return data.
		// If output is present, try to parse it.
		utils.LogDebug("httpx finished with error: %v (output length: %d)", err, len(output))
	}

	var results []HttpxResult
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var res HttpxResult
		if err := json.Unmarshal([]byte(line), &res); err == nil {
			results = append(results, res)
		}
	}

	return results, nil
}

// Keep legacy Run for compatibility if needed, or update it.
func (h *Httpx) Run(ctx context.Context, target string) (string, error) {
	// Simple wrapper around RunRich for single target?
	// Or kept for other modules utilizing simple check.
	// Let's leave as is for now, but implemented RunRich.
	return "", nil
}
