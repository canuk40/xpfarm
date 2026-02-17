package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"
)

type Naabu struct{}

func (n *Naabu) Name() string {
	return "naabu"
}

func (n *Naabu) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("naabu")
	_, err := exec.LookPath(path)
	return err == nil
}

func (n *Naabu) Install() error {
	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install naabu: %v", err)
	}
	return nil
}

func (n *Naabu) Run(ctx context.Context, target string) (string, error) {
	utils.LogInfo("Running naabu on %s...", target)
	path := utils.ResolveBinaryPath("naabu")
	cmd := exec.CommandContext(ctx, path, "-host", target, "-json", "-silent", "-top-ports", "100", "-c", "50", "-rate", "1000")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Naabu] stderr: %s", stderr.String())
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("naabu failed: %v", err)
	}
	return stdout.String(), nil
}
