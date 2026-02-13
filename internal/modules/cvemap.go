package modules

import (
	"context"
	"fmt"
	"os/exec"
	"xpfarm/pkg/utils"
)

type Cvemap struct{}

func (c *Cvemap) Name() string {
	return "cvemap"
}

func (c *Cvemap) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("vulnx")
	_, err := exec.LookPath(path)
	return err == nil
}

func (c *Cvemap) Install() error {
	cmd := exec.Command("go", "install", "github.com/projectdiscovery/cvemap/cmd/vulnx@latest")
	cmd.Stdout = utils.GetInfoWriter()
	cmd.Stderr = utils.GetInfoWriter()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install cvemap (vulnx): %v", err)
	}
	return nil
}

func (c *Cvemap) Run(ctx context.Context, target string) (string, error) {
	return c.Search(ctx, target)
}

// CvemapResponse is the top-level JSON response from vulnx search
type CvemapResponse struct {
	Count   int            `json:"count"`
	Total   int            `json:"total"`
	Results []CvemapResult `json:"results"`
}

// CvemapResult represents a single CVE from vulnx JSON output
type CvemapResult struct {
	CveID       string  `json:"cve_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CvssScore   float64 `json:"cvss_score"`
	EpssScore   float64 `json:"epss_score"`
	IsKEV       bool    `json:"is_kev"`
	HasPOC      bool    `json:"is_poc"`
	HasTemplate bool    `json:"is_template"`
}

// Search runs vulnx search with a raw query string and returns JSON output
func (c *Cvemap) Search(ctx context.Context, query string) (string, error) {
	path := utils.ResolveBinaryPath("vulnx")
	utils.LogInfo("Querying cvemap (vulnx): %s", query)

	cmd := exec.CommandContext(ctx, path, "search", "--json", "--silent", query)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("cvemap query failed: %v", err)
	}
	return string(output), nil
}

// SearchProduct queries vulnx for CVEs matching a specific product name
// Uses --product, --severity, and --template flags for targeted results
func (c *Cvemap) SearchProduct(ctx context.Context, product string) (string, error) {
	path := utils.ResolveBinaryPath("vulnx")
	utils.LogInfo("Querying cvemap (vulnx) for product: %s", product)

	args := []string{
		"search",
		"--product", product,
		"--severity", "critical,high,medium",
		"--template",
		"--json",
		"--silent",
		"--limit", "25",
	}

	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("cvemap product query failed for %s: %v", product, err)
	}
	return string(output), nil
}
