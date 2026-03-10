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

func (n *Naabu) Description() string {
	return "Naabu is a fast, specialized port scanner. It rapidly iterates over target architectures to map out structurally exposed TCP/UDP ports before passing them to secondary tools for deep state inspection."
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
	return n.CustomRun(ctx, target, "top100", "fast")
}

func (n *Naabu) CustomRun(ctx context.Context, target string, scope string, speed string) (string, error) {
	utils.LogInfo("Running naabu on %s (Scope: %s, Speed: %s)...", target, scope, speed)
	path := utils.ResolveBinaryPath("naabu")

	args := []string{"-host", target, "-json", "-silent"}

	switch scope {
	case "top100":
		args = append(args, "-top-ports", "100")
	case "top1000":
		args = append(args, "-top-ports", "1000")
	case "all":
		args = append(args, "-p", "-")
	default:
		args = append(args, "-top-ports", "100")
	}

	switch speed {
	case "slow":
		args = append(args, "-c", "10", "-rate", "100")
	case "standard":
		args = append(args, "-c", "25", "-rate", "500")
	case "fast":
		args = append(args, "-c", "50", "-rate", "1000")
	default:
		args = append(args, "-c", "50", "-rate", "1000")
	}

	cmd := exec.CommandContext(ctx, path, args...)

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
