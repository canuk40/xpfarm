package modules

import (
	"context"
	"os/exec"
	"xpfarm/pkg/utils"
)

// Module defines the interface that all tool wrappers must implement.
type Module interface {
	// Name returns the name of the tool (e.g., "nuclei")
	Name() string

	// Description returns a UI-friendly overview of the tool and its methodology within xpfarm.
	Description() string

	// CheckInstalled returns true if the tool is available in PATH
	CheckInstalled() bool

	// Install attempts to install the tool (e.g., via go install)
	Install() error

	// Run executes the tool against a specific target.
	// target can be a domain, URL, or IP.
	// It returns the raw output or a path to the output file, and an error.
	Run(ctx context.Context, target string) (string, error)
}

// RunUpdates checks for updates for all ProjectDiscovery tools.
func RunUpdates() {
	utils.LogInfo("Checking for updates...")

	pdTools := []string{
		"subfinder", "naabu", "httpx", "katana",
		"urlfinder", "nuclei", "vulnx", // cvemap is vulnx
	}

	// Maybe run in parallel? But sequential is safer for output order.
	for _, tool := range pdTools {
		checkToolUpdate(tool)
	}

	utils.LogSuccess("Running latest versions.")
}

// checkToolUpdate runs the tool with -up flag to check/perform updates.
func checkToolUpdate(toolName string) {
	path := utils.ResolveBinaryPath(toolName)
	// Check if exists first
	if _, err := exec.LookPath(path); err != nil {
		return
	}

	// We run with -up.
	cmd := exec.Command(path, "-up")
	// We don't care about output unless debugging, as user wants silence.
	_, _ = cmd.CombinedOutput()

	// Special Case for Nuclei: Update Templates
	if toolName == "nuclei" {
		cmdTmpl := exec.Command(path, "-ut")
		_, _ = cmdTmpl.CombinedOutput()
	}
}
