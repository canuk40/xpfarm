package modules

import (
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

type Wappalyzer struct{}

func (w *Wappalyzer) Name() string {
	return "wappalyzer"
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

// Analyze performs technology detection on response headers and body
func (w *Wappalyzer) Analyze(headers map[string][]string, body []byte) []string {
	wappalyzerClient, err := wappalyzergo.New()
	if err != nil {
		utils.LogError("Failed to initialize wappalyzer: %v", err)
		return nil
	}

	fingerprints := wappalyzerClient.Fingerprint(headers, body)

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
