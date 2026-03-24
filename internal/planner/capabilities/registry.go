// Package capabilities maintains a registry of all tool and agent capabilities
// available to the scan planner. Each entry describes what category of work
// a tool does, its relative compute cost, and its risk level.
package capabilities

import "sync"

// RiskLevel describes how potentially disruptive a tool is.
const (
	RiskSafe        = 0 // passive, read-only
	RiskActive      = 1 // sends traffic but non-destructive
	RiskDestructive = 2 // may crash services, trigger WAF bans, etc.
)

// Capability describes one tool or agent entry in the registry.
type Capability struct {
	Agent      string   `json:"agent"`      // "builtin" or Overlord agent name
	Tool       string   `json:"tool"`       // module name or Overlord tool name
	Categories []string `json:"categories"` // recon, web, binary, secrets, fuzzing
	Cost       int      `json:"cost"`       // relative compute cost (1=fast, 10=slow)
	Risk       int      `json:"risk"`       // RiskSafe | RiskActive | RiskDestructive
	Desc       string   `json:"desc"`
}

var (
	mu       sync.RWMutex
	registry []Capability
)

// RegisterCapability adds a capability to the registry.
func RegisterCapability(c Capability) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, c)
}

// GetCapabilities returns a snapshot of all registered capabilities.
func GetCapabilities() []Capability {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Capability, len(registry))
	copy(out, registry)
	return out
}

// GetByMode filters capabilities appropriate for the given mode string.
// Modes: "recon", "web", "binary", "full", "safe".
func GetByMode(mode string) []Capability {
	all := GetCapabilities()
	var out []Capability
	for _, c := range all {
		switch mode {
		case "safe":
			if c.Risk > RiskSafe {
				continue
			}
		case "recon":
			if !hasCategory(c.Categories, "recon") {
				continue
			}
		case "web":
			if !hasCategory(c.Categories, "web") {
				continue
			}
		case "binary":
			if !hasCategory(c.Categories, "binary") {
				continue
			}
		case "full":
			// all tools allowed
		}
		out = append(out, c)
	}
	return out
}

func hasCategory(cats []string, target string) bool {
	for _, c := range cats {
		if c == target {
			return true
		}
	}
	return false
}

func init() {
	// ---- Built-in Go modules ----
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "subfinder",
		Categories: []string{"recon"},
		Cost: 2, Risk: RiskSafe,
		Desc: "Passive subdomain enumeration from OSINT sources",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "httpx",
		Categories: []string{"recon", "web"},
		Cost: 2, Risk: RiskActive,
		Desc: "HTTP probing — status, title, tech stack fingerprinting",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "naabu",
		Categories: []string{"recon"},
		Cost: 3, Risk: RiskActive,
		Desc: "Fast port scanning across discovered targets",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "nmap",
		Categories: []string{"recon"},
		Cost: 5, Risk: RiskActive,
		Desc: "Service and version detection on open ports",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "nuclei",
		Categories: []string{"web"},
		Cost: 6, Risk: RiskActive,
		Desc: "Template-based vulnerability scanner (CVEs, misconfigs, exposures)",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "katana",
		Categories: []string{"web", "recon"},
		Cost: 4, Risk: RiskActive,
		Desc: "Web crawler for endpoint and parameter discovery",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "urlfinder",
		Categories: []string{"web", "recon"},
		Cost: 3, Risk: RiskSafe,
		Desc: "Passive URL discovery from JavaScript and source",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "gowitness",
		Categories: []string{"web"},
		Cost: 3, Risk: RiskSafe,
		Desc: "Web screenshot capture for visual recon",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "wappalyzer",
		Categories: []string{"web", "recon"},
		Cost: 1, Risk: RiskSafe,
		Desc: "Technology fingerprinting (frameworks, CMS, languages)",
	})
	RegisterCapability(Capability{
		Agent: "builtin", Tool: "cvemap",
		Categories: []string{"recon"},
		Cost: 2, Risk: RiskSafe,
		Desc: "CVE lookup by detected product/version — EPSS and KEV enrichment",
	})

	// ---- Overlord agents ----
	RegisterCapability(Capability{
		Agent: "recon", Tool: "subfinder_enum",
		Categories: []string{"recon"},
		Cost: 2, Risk: RiskSafe,
		Desc: "AI-guided subdomain expansion and OSINT correlation",
	})
	RegisterCapability(Capability{
		Agent: "re-explorer", Tool: "surface_map",
		Categories: []string{"recon"},
		Cost: 3, Risk: RiskSafe,
		Desc: "Attack surface mapping — correlate subdomains, IPs, ASNs",
	})
	RegisterCapability(Capability{
		Agent: "re-web-analyzer", Tool: "web_analyze",
		Categories: []string{"web"},
		Cost: 4, Risk: RiskActive,
		Desc: "Deep web application analysis — auth flows, APIs, inputs",
	})
	RegisterCapability(Capability{
		Agent: "web-tester", Tool: "web_test",
		Categories: []string{"web", "fuzzing"},
		Cost: 7, Risk: RiskActive,
		Desc: "Active web testing — injection, XSS, auth bypass",
	})
	RegisterCapability(Capability{
		Agent: "re-net-exploiter", Tool: "exploit_web",
		Categories: []string{"web", "fuzzing"},
		Cost: 9, Risk: RiskDestructive,
		Desc: "Automated web exploitation — SQLi, RCE, SSRF",
	})
	RegisterCapability(Capability{
		Agent: "re-session-analyzer", Tool: "session_analysis",
		Categories: []string{"web"},
		Cost: 4, Risk: RiskActive,
		Desc: "Cookie, JWT, and session token analysis for weaknesses",
	})
	RegisterCapability(Capability{
		Agent: "re-logic-analyzer", Tool: "logic_audit",
		Categories: []string{"web", "binary"},
		Cost: 5, Risk: RiskSafe,
		Desc: "Business logic flaw analysis on observed flows",
	})
	RegisterCapability(Capability{
		Agent: "apk-recon", Tool: "apk_recon",
		Categories: []string{"binary", "recon"},
		Cost: 3, Risk: RiskSafe,
		Desc: "Android APK static analysis — permissions, endpoints, secrets",
	})
	RegisterCapability(Capability{
		Agent: "apk-dynamic", Tool: "apk_dynamic",
		Categories: []string{"binary"},
		Cost: 6, Risk: RiskActive,
		Desc: "Dynamic APK analysis with Frida instrumentation",
	})
	RegisterCapability(Capability{
		Agent: "apk-decompiler", Tool: "apk_decompile",
		Categories: []string{"binary"},
		Cost: 4, Risk: RiskSafe,
		Desc: "APK decompilation and source code review",
	})
	RegisterCapability(Capability{
		Agent: "re-ghidra", Tool: "r2triage",
		Categories: []string{"binary"},
		Cost: 5, Risk: RiskSafe,
		Desc: "Binary triage with radare2 — strings, imports, entropy",
	})
	RegisterCapability(Capability{
		Agent: "re-ghidra", Tool: "ghidra_decompile",
		Categories: []string{"binary"},
		Cost: 8, Risk: RiskSafe,
		Desc: "Deep binary decompilation via Ghidra/r2 — function analysis",
	})
	RegisterCapability(Capability{
		Agent: "re-decompiler", Tool: "decompile",
		Categories: []string{"binary"},
		Cost: 6, Risk: RiskSafe,
		Desc: "Multi-format decompilation pipeline",
	})
	RegisterCapability(Capability{
		Agent: "re-crypto-analyzer", Tool: "crypto_audit",
		Categories: []string{"binary"},
		Cost: 5, Risk: RiskSafe,
		Desc: "Cryptographic weakness analysis — weak keys, hardcoded secrets",
	})
	RegisterCapability(Capability{
		Agent: "re-static-audit", Tool: "static_audit",
		Categories: []string{"binary"},
		Cost: 5, Risk: RiskSafe,
		Desc: "Static code audit for vulnerabilities via Semgrep",
	})
	RegisterCapability(Capability{
		Agent: "secrets-hunter", Tool: "secret_scan",
		Categories: []string{"recon", "binary", "secrets"},
		Cost: 3, Risk: RiskSafe,
		Desc: "Secret and credential detection across source and binaries",
	})
}
