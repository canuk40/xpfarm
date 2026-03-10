package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"
)

type Subfinder struct{}

func (s *Subfinder) Name() string {
	return "subfinder"
}

func (s *Subfinder) Description() string {
	return "Subfinder is a fast passive subdomain discovery tool. It aggregates and processes OSINT sources to expand the targeted organization's external attack surface before any active exploitation begins."
}

func (s *Subfinder) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("subfinder")
	_, err := exec.LookPath(path)
	return err == nil
}

func (s *Subfinder) Install() error {
	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install subfinder: %v", err)
	}
	return nil
}

func (s *Subfinder) Run(ctx context.Context, target string) (string, error) {
	utils.LogInfo("Running subfinder on %s...", target)
	path := utils.ResolveBinaryPath("subfinder")
	cmd := exec.CommandContext(ctx, path, "-d", target, "-silent")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Subfinder] stderr: %s", stderr.String())
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("subfinder failed: %v", err)
	}
	return stdout.String(), nil
}
