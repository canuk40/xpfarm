package secrets

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"xpfarm/internal/normalization/model"
)

// SecretFinderScanner is a Go-native implementation of JavaScript and
// source-file secret scanning. It applies the same regex patterns used by
// the original Python SecretFinder tool plus many additional patterns drawn
// from gitleaks and truffleHog rule sets.
//
// Unlike the Python SecretFinder, this implementation:
//   - Requires no external dependencies
//   - Scans all source and configuration files (not only .js)
//   - Skips vendor/node_modules directories automatically
//   - Redacts matched secrets in findings
type SecretFinderScanner struct {
	// RepoURL is embedded in generated findings as the target identifier.
	RepoURL string
}

// jsPattern describes a single secret pattern.
type jsPattern struct {
	Name string
	CWE  string
	Re   *regexp.Regexp
}

// patterns is the full list of secret patterns applied to every source file.
var patterns = []jsPattern{
	// Cloud provider keys
	{"Google API Key", "CWE-798", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Google OAuth Client ID", "CWE-798", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{"Google OAuth Client Secret", "CWE-312", regexp.MustCompile(`GOCSPX-[a-zA-Z0-9_-]{28}`)},
	{"AWS Access Key ID", "CWE-798", regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)},
	{"AWS Secret Access Key", "CWE-312", regexp.MustCompile(`(?i)aws.{0,25}?['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Azure Client Secret", "CWE-798", regexp.MustCompile(`(?i)azure.{0,25}?['"][0-9a-zA-Z/+~._-]{34}['"]`)},
	{"GCP Service Account", "CWE-312", regexp.MustCompile(`\"type\":\s*\"service_account\"`)},

	// Source control tokens
	{"GitHub Personal Access Token", "CWE-798", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{"GitHub OAuth Token", "CWE-798", regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
	{"GitHub App Token", "CWE-798", regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`)},
	{"GitHub Refresh Token", "CWE-798", regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`)},
	{"GitLab Personal Token", "CWE-798", regexp.MustCompile(`glpat-[a-zA-Z0-9\-_]{20}`)},
	{"GitLab Runner Token", "CWE-798", regexp.MustCompile(`GR1348941[a-zA-Z0-9\-_]{20}`)},

	// Payment
	{"Stripe Live Secret Key", "CWE-798", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
	{"Stripe Live Restricted Key", "CWE-798", regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`)},
	{"Square Access Token", "CWE-798", regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`)},
	{"Square OAuth Secret", "CWE-798", regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`)},
	{"Braintree Access Token", "CWE-798", regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},

	// Messaging & comms
	{"Slack Bot Token", "CWE-798", regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{"Slack User Token", "CWE-798", regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-fA-F0-9]{32}`)},
	{"Slack Webhook", "CWE-798", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`)},
	{"Twilio Account SID", "CWE-798", regexp.MustCompile(`AC[a-fA-F0-9]{32}`)},
	{"Twilio Auth Token", "CWE-798", regexp.MustCompile(`(?i)twilio.{0,25}?['"][a-fA-F0-9]{32}['"]`)},
	{"SendGrid API Key", "CWE-798", regexp.MustCompile(`SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}`)},
	{"Mailgun API Key", "CWE-798", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"Mailchimp API Key", "CWE-798", regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`)},

	// Infrastructure & DevOps
	{"NPM Access Token", "CWE-798", regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)},
	{"PyPI Upload Token", "CWE-798", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{70,}`)},
	{"Heroku API Key", "CWE-798", regexp.MustCompile(`(?i)heroku.{0,25}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
	{"Shopify Access Token", "CWE-798", regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`)},
	{"Shopify Custom Token", "CWE-798", regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`)},
	{"Dropbox Long-Lived Token", "CWE-798", regexp.MustCompile(`sl\.[a-zA-Z0-9\-_]{130,150}`)},
	{"Databricks API Token", "CWE-798", regexp.MustCompile(`dapi[a-h0-9]{32}`)},
	{"HashiCorp Vault Token", "CWE-798", regexp.MustCompile(`hvs\.[a-zA-Z0-9]{24,}`)},
	{"Doppler Service Token", "CWE-798", regexp.MustCompile(`dp\.st\.[a-zA-Z0-9._]{40,}`)},
	{"Firebase URL", "CWE-200", regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`)},

	// Auth & crypto material
	{"Private Key (PEM)", "CWE-312", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?:\s+BLOCK)?-----`)},
	{"JWT Token", "CWE-312", regexp.MustCompile(`eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}`)},
	{"Basic Auth in URL", "CWE-522", regexp.MustCompile(`https?://[a-zA-Z0-9._%+\-]+:[a-zA-Z0-9._%+\-!@#$]{3,}@[a-zA-Z0-9.\-]+`)},

	// Generic high-confidence patterns — must be last to avoid shadowing specifics
	{"Generic Secret Assignment", "CWE-798", regexp.MustCompile(`(?i)(?:secret|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*['"][^'"]{12,}['"]`)},
	{"Generic Password Assignment", "CWE-256", regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]`)},
}

// scannableExtensions is the set of file extensions SecretFinderScanner will read.
var scannableExtensions = map[string]bool{
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".vue": true, ".mjs": true, ".cjs": true,
	".py": true, ".rb": true, ".php": true, ".java": true,
	".go": true, ".cs": true, ".cpp": true, ".c": true,
	".env": true, ".yaml": true, ".yml": true, ".toml": true,
	".json": true, ".xml": true, ".conf": true, ".config": true,
	".properties": true, ".ini": true, ".sh": true, ".bash": true,
}

// skipDirs is a set of directory names that should never be scanned.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".idea": true, ".vscode": true, "target": true,
}

func (s *SecretFinderScanner) Scan(repoPath string) ([]model.Finding, error) {
	target := s.RepoURL
	if target == "" {
		target = repoPath
	}

	var findings []model.Finding

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannableExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}

		fileFindings, err := scanFile(path, repoPath, target)
		if err != nil {
			return nil // skip files we can't read
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("secretfinder: walk %s: %w", repoPath, err)
	}

	return findings, nil
}

// scanFile applies all secret patterns to a single file and returns findings.
func scanFile(path, repoRoot, target string) ([]model.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	relPath, _ := filepath.Rel(repoRoot, path)

	var findings []model.Finding
	lineNum := 0
	scanner := bufio.NewScanner(f)
	// Increase scanner buffer for long minified JS lines
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range patterns {
			match := p.Re.FindString(line)
			if match == "" {
				continue
			}
			evidence := redact(line, match)

			findings = append(findings, model.Finding{
				ID:          model.NewID(),
				Source:      "secretfinder",
				Target:      target,
				Location:    fmt.Sprintf("%s:%d", relPath, lineNum),
				Title:       fmt.Sprintf("Exposed Secret: %s", p.Name),
				Description: fmt.Sprintf("%s detected in %s at line %d.", p.Name, relPath, lineNum),
				Severity:    model.SeverityHigh,
				CWE:         p.CWE,
				Evidence:    evidence,
				Tags:        []string{"secretfinder", "secret", "credential"},
				Raw: map[string]any{
					"file":    relPath,
					"line":    lineNum,
					"pattern": p.Name,
				},
				Timestamp: time.Now().UTC(),
			})
			// One match per pattern per line — don't create duplicate findings for
			// multiple occurrences on the same line.
			break
		}
	}
	return findings, scanner.Err()
}

// redact replaces the matched secret with asterisks, keeping the first 4 chars
// for forensic identification.
func redact(line, match string) string {
	if len(match) <= 4 {
		return strings.ReplaceAll(line, match, "****")
	}
	visible := match[:4]
	masked := visible + strings.Repeat("*", len(match)-4)
	result := strings.ReplaceAll(line, match, masked)
	// Truncate very long lines
	if len(result) > 300 {
		return result[:300] + "…"
	}
	return result
}
