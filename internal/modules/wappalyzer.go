package modules

import (
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

type Wappalyzer struct {
	client *wappalyzergo.Wappalyze
}

func (w *Wappalyzer) Name() string {
	return "wappalyzer"
}

func (w *Wappalyzer) Description() string {
	return "Wappalyzer uncovers the technology stack of web applications. It inspects server responses, HTML content, and headers to identify CMS platforms, frameworks, programming languages, and embedded scripts."
}

// CheckInstalled checks for the update-fingerprints binary as requested
func (w *Wappalyzer) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("update-fingerprints")
	_, err := exec.LookPath(path)
	return err == nil
}

// Install runs the specific command requested by the user
func (w *Wappalyzer) Install() error {
	utils.LogInfo("Installing wappalyzergo fingerprints updater...")
	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install wappalyzergo updater: %v", err)
	}
	return nil
}

// ensureClient lazily initializes the wappalyzer client once
func (w *Wappalyzer) ensureClient() error {
	if w.client != nil {
		return nil
	}
	c, err := wappalyzergo.New()
	if err != nil {
		return err
	}
	w.client = c
	return nil
}

// Analyze performs technology detection on response headers and body
func (w *Wappalyzer) Analyze(headers map[string][]string, body []byte) []string {
	if err := w.ensureClient(); err != nil {
		utils.LogError("Failed to initialize wappalyzer: %v", err)
		return nil
	}

	fingerprints := w.client.Fingerprint(headers, body)

	results := make([]string, 0, len(fingerprints))
	for name := range fingerprints {
		results = append(results, name)
	}
	return results
}

// Run is a placeholder to satisfy the interface, though we primarily use Analyze directly
func (w *Wappalyzer) Run(ctx context.Context, target string) (string, error) {
	return "", nil
}
