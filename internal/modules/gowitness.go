package modules

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"xpfarm/pkg/utils"
)

type Gowitness struct{}

func (g *Gowitness) Name() string {
	return "gowitness"
}

func (g *Gowitness) Description() string {
	return "Gowitness is a web screenshot utility. It connects to discovered web applications and captures high-resolution screenshots of the landing pages to assist in rapid visual reconnaissance."
}

func (g *Gowitness) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("gowitness")
	_, err := exec.LookPath(path)
	return err == nil
}

func (g *Gowitness) Install() error {
	cmd := exec.Command("go", "install", "github.com/sensepost/gowitness@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install gowitness: %v", err)
	}
	return nil
}

// RunSingle captures a screenshot for a single URL and returns (path, cliOutput, error)
func (g *Gowitness) RunSingle(ctx context.Context, url string) (string, string, error) {
	utils.LogInfo("Running gowitness on %s...", url)
	path := utils.ResolveBinaryPath("gowitness")

	// Generate a safe filename prefix for verification
	prefix := strings.ReplaceAll(url, ":", "-")
	prefix = strings.ReplaceAll(prefix, "/", "-")

	// gowitness scan single -u <url> --screenshot-fullpage
	cmd := exec.CommandContext(ctx, path, "scan", "single", "-u", url, "--screenshot-fullpage")
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	if err != nil {
		return "", output, fmt.Errorf("gowitness failed: %v", err)
	}

	// Verify file exists
	extensions := []string{".jpeg", ".jpg", ".png"}
	var finalPath string

	for _, ext := range extensions {
		candidate := fmt.Sprintf("screenshots/%s%s", prefix, ext)
		if _, err := os.Stat(candidate); err == nil {
			finalPath = candidate
			break
		}
	}

	if finalPath == "" {
		return "", output, fmt.Errorf("screenshot file not found for %s", url)
	}

	return finalPath, output, nil
}

func (g *Gowitness) Run(ctx context.Context, target string) (string, error) {
	_, out, err := g.RunSingle(ctx, target)
	return out, err
}
