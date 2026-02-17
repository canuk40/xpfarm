package modules

import (
	"bytes"
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
	A           []string `json:"a"`
	CNAMEs      []string `json:"cname"`
	CDN         bool     `json:"cdn"`
	CDNName     string   `json:"cdn_name"`
	Response    string   `json:"response"`
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

	args := []string{
		"-status-code", "-content-type", "-content-length", "-location", "-title",
		"-web-server", "-tech-detect", "-ip", "-cname", "-word-count", "-line-count",
		"-cdn", "-include-response", "-follow-host-redirects", "-max-redirects", "2",
		"-threads", "50", "-json", "-silent",
	}

	cmd := exec.CommandContext(ctx, path, args...)

	// Stdin Pipe for URLs
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

	// Separate stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmdErr := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Httpx] stderr: %s", stderr.String())
	}

	var results []HttpxResult
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var res HttpxResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			utils.LogDebug("[Httpx] Failed to parse JSON line: %v (line: %.100s)", err, line)
		} else {
			results = append(results, res)
		}
	}

	// If command failed AND we got no results, propagate the error
	if cmdErr != nil && len(results) == 0 {
		return nil, fmt.Errorf("httpx failed: %v", cmdErr)
	}

	return results, nil
}

// Run is a simple wrapper for the Module interface
func (h *Httpx) Run(ctx context.Context, target string) (string, error) {
	return "", nil
}
