package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"xpfarm/pkg/utils"
)

type Cvemap struct{}

func (c *Cvemap) Name() string {
	return "cvemap"
}

func (c *Cvemap) Description() string {
	return "Cvemap is a vulnerability mapping tool. It searches localized databases for known CVEs matching the precise product software and versions identified during the port scanning phase by Nmap."
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

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Cvemap] stderr: %s", stderr.String())
	}

	output := strings.TrimSpace(stdout.String())
	if err != nil {
		return output, fmt.Errorf("cvemap query failed: %v", err)
	}
	return output, nil
}

// SearchProduct queries vulnx for CVEs matching a specific product name.
// Versions are stripped since vulnx only accepts bare product names.
func (c *Cvemap) SearchProduct(ctx context.Context, product string) (string, error) {
	// Strip versions: "drupal:10" → "drupal", "apache/2.4.1" → "apache",
	// "microsoft asp.net 4.0" → "microsoft asp.net"
	cleaned := product

	// Handle colon-separated versions (drupal:10, wordpress:6.4)
	if idx := strings.Index(cleaned, ":"); idx > 0 {
		cleaned = cleaned[:idx]
	}

	// Handle slash-separated versions (apache/2.4.1)
	if idx := strings.Index(cleaned, "/"); idx > 0 {
		cleaned = cleaned[:idx]
	}

	// Handle trailing version numbers (e.g. "nginx 1.25.3" → "nginx")
	// Split by space, drop trailing parts that look like version numbers
	parts := strings.Fields(cleaned)
	for len(parts) > 1 {
		last := parts[len(parts)-1]
		// Check if the last part starts with a digit (likely a version)
		if len(last) > 0 && last[0] >= '0' && last[0] <= '9' {
			parts = parts[:len(parts)-1]
		} else {
			break
		}
	}
	cleaned = strings.Join(parts, " ")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" || len(cleaned) < 2 {
		return "", fmt.Errorf("product name too short after cleanup: %q → %q", product, cleaned)
	}

	path := utils.ResolveBinaryPath("vulnx")
	if product != cleaned {
		utils.LogInfo("Querying cvemap (vulnx) for product: %s (cleaned from %s)", cleaned, product)
	} else {
		utils.LogInfo("Querying cvemap (vulnx) for product: %s", cleaned)
	}

	args := []string{
		"search",
		"--product", cleaned,
		"--severity", "critical,high,medium",
		"--template",
		"--json",
		"--silent",
		"--limit", "25",
	}

	cmd := exec.CommandContext(ctx, path, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stderr.Len() > 0 {
		utils.LogDebug("[Cvemap] stderr: %s", strings.TrimSpace(stderr.String()))
	}

	output := strings.TrimSpace(stdout.String())
	if err != nil {
		return output, fmt.Errorf("cvemap product query failed for %s: %v", cleaned, err)
	}
	return output, nil
}
