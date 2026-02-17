package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"
)

type Uncover struct{}

func (u *Uncover) Name() string {
	return "uncover"
}

func (u *Uncover) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("uncover")
	_, err := exec.LookPath(path)
	return err == nil
}

func (u *Uncover) Install() error {
	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/uncover/cmd/uncover@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install uncover: %v", err)
	}
	return nil
}

func (u *Uncover) Run(ctx context.Context, target string) (string, error) {
	utils.LogInfo("Running uncover on %s...", target)
	path := utils.ResolveBinaryPath("uncover")
	cmd := exec.CommandContext(ctx, path, "-q", target, "-silent")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Uncover] stderr: %s", stderr.String())
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("uncover failed: %v", err)
	}
	return stdout.String(), nil
}
