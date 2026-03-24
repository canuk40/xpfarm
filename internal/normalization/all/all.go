// Package all registers all normalization adapters and enrichers by importing
// their packages for side effects (each package calls Register* in init()).
//
// Import order determines enricher execution order:
//   cwe → cvss → epss → kev
//
// This package must be blank-imported in main.go (or any other entry point
// that uses the normalization pipeline) before the first call to Run().
package all

import (
	// Adapters — one per scanner
	_ "xpfarm/internal/normalization/adapters/gitleaks"
	_ "xpfarm/internal/normalization/adapters/nmap"
	_ "xpfarm/internal/normalization/adapters/nuclei"
	_ "xpfarm/internal/normalization/adapters/semgrep"

	// Enrichers — ordered: local first, then network calls
	_ "xpfarm/internal/normalization/enrichers/cwe"  // 1. keyword/tag CWE mapping (local)
	_ "xpfarm/internal/normalization/enrichers/cvss" // 2. NVD CVSS score (needs CVE)
	_ "xpfarm/internal/normalization/enrichers/epss" // 3. FIRST.org EPSS (needs CVE)
	_ "xpfarm/internal/normalization/enrichers/kev"  // 4. CISA KEV flag (needs CVE)
)
