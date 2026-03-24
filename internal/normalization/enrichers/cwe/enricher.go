// Package cwe enriches findings with a CWE identifier using local keyword and
// tag mappings. No network calls — all lookups run from embedded data.
//
// Priority order:
//  1. If f.CWE is already set (by the adapter), skip.
//  2. Search title for known vulnerability keyword phrases.
//  3. Search f.Tags for known short-form tag labels.
//  4. Leave f.CWE empty if nothing matches.
package cwe

import (
	"strings"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

func init() {
	normalization.RegisterEnricher(&Enricher{})
}

// Enricher maps finding titles and tags to CWE identifiers.
type Enricher struct{}

func (e *Enricher) Name() string { return "cwe" }

func (e *Enricher) Enrich(f *model.Finding) error {
	if f.CWE != "" {
		return nil // adapter already set it
	}
	titleLower := strings.ToLower(f.Title + " " + f.Description)
	for _, rule := range keywordRules {
		for _, kw := range rule.keywords {
			if strings.Contains(titleLower, kw) {
				f.CWE = rule.cwe
				return nil
			}
		}
	}
	// Fall through to tag matching
	for _, tag := range f.Tags {
		if cwe, ok := tagCWE[strings.ToLower(tag)]; ok {
			f.CWE = cwe
			return nil
		}
	}
	return nil
}

// keywordRule maps a set of title/description keywords to a CWE.
// Keywords are lowercase; the first matching rule wins.
type keywordRule struct {
	cwe      string
	keywords []string
}

// keywordRules are ordered from most-specific to least-specific.
var keywordRules = []keywordRule{
	{"CWE-89", []string{"sql injection", " sqli ", "raw sql", "sql query", "union select", "sqlmap"}},
	{"CWE-79", []string{"cross-site scripting", " xss ", "reflected xss", "stored xss", "dom xss"}},
	{"CWE-22", []string{"path traversal", "directory traversal", " lfi ", "local file inclusion", "zip slip", "../"}},
	{"CWE-78", []string{"command injection", "os command", "shell injection", "arbitrary command"}},
	{"CWE-77", []string{"remote code execution", " rce ", "code execution", "arbitrary code"}},
	{"CWE-94", []string{"code injection", "template injection", " ssti ", "server-side template"}},
	{"CWE-918", []string{"server-side request forgery", " ssrf ", "internal request"}},
	{"CWE-611", []string{"xml external entity", " xxe ", "external entity"}},
	{"CWE-601", []string{"open redirect", "unvalidated redirect", "url redirect"}},
	{"CWE-352", []string{"cross-site request forgery", " csrf "}},
	{"CWE-502", []string{"deserialization", "unsafe deserialization", "object injection", "pickle", "java deserialization"}},
	{"CWE-798", []string{"hardcoded credential", "hardcoded password", "hardcoded secret", "hardcoded api key", "default credential", "default password"}},
	{"CWE-312", []string{"cleartext storage", "plaintext secret", "unencrypted secret", "secret exposure", "exposed secret", "leaked secret"}},
	{"CWE-256", []string{"plaintext password", "password in plaintext", "password stored in clear"}},
	{"CWE-287", []string{"authentication bypass", "auth bypass", "broken auth", "missing authentication"}},
	{"CWE-269", []string{"privilege escalation", "improper privilege", "permission escalation"}},
	{"CWE-434", []string{"unrestricted upload", "arbitrary file upload", "insecure file upload"}},
	{"CWE-326", []string{"weak crypto", "weak cipher", "weak encryption", "md5 hash", "sha1 hash", "des cipher", "rc4"}},
	{"CWE-330", []string{"insecure random", "weak random", "predictable random", "math/rand", "rand.random"}},
	{"CWE-200", []string{"information disclosure", "info disclosure", "sensitive data exposure", "stack trace", "debug information"}},
	{"CWE-942", []string{"cors misconfiguration", "cors wildcard", "access-control-allow-origin: *"}},
	{"CWE-1021", []string{"clickjacking", "x-frame-options", "frame injection"}},
	{"CWE-614", []string{"secure flag", "missing secure flag"}},
	{"CWE-1004", []string{"httponly", "missing httponly", "cookie without httponly"}},
	{"CWE-113", []string{"header injection", "http header injection", "crlf injection"}},
	{"CWE-90", []string{"ldap injection", "ldap query injection"}},
	{"CWE-643", []string{"xpath injection", "xpath query injection"}},
	{"CWE-776", []string{"billion laughs", "xml bomb", "entity expansion"}},
	{"CWE-1321", []string{"prototype pollution", "__proto__", "constructor pollution"}},
	{"CWE-16", []string{"security misconfiguration", "misconfiguration", "exposed admin", "debug mode enabled", "default configuration"}},
	{"CWE-1188", []string{"default login", "default credentials", "factory credentials"}},
	{"CWE-116", []string{"improper encoding", "encoding injection", "missing output encoding"}},
	{"CWE-117", []string{"log injection", "log forging", "log poisoning"}},
	{"CWE-362", []string{"race condition", "time-of-check", "toctou"}},
	{"CWE-416", []string{"use after free", "use-after-free", "uaf "}},
	{"CWE-476", []string{"null pointer", "null dereference", "nil pointer"}},
	{"CWE-120", []string{"buffer overflow", "stack overflow", "heap overflow", "out-of-bounds write"}},
	{"CWE-134", []string{"format string", "printf injection", "format specifier"}},
}

// tagCWE maps short tag labels (as used by nuclei, semgrep, etc.) to CWEs.
var tagCWE = map[string]string{
	"sqli":           "CWE-89",
	"sql-injection":  "CWE-89",
	"xss":            "CWE-79",
	"lfi":            "CWE-22",
	"rfi":            "CWE-98",
	"traversal":      "CWE-22",
	"rce":            "CWE-77",
	"injection":      "CWE-74",
	"ssrf":           "CWE-918",
	"xxe":            "CWE-611",
	"redirect":       "CWE-601",
	"csrf":           "CWE-352",
	"deserialization": "CWE-502",
	"default-login":  "CWE-1188",
	"misconfig":      "CWE-16",
	"exposure":       "CWE-200",
	"disclosure":     "CWE-200",
	"auth-bypass":    "CWE-287",
	"privesc":        "CWE-269",
	"ssti":           "CWE-94",
	"cors":           "CWE-942",
	"secret":         "CWE-312",
	"credential":     "CWE-798",
	"token":          "CWE-798",
	"api-key":        "CWE-798",
	"clickjacking":   "CWE-1021",
	"log4j":          "CWE-502",
	"prototype-pollution": "CWE-1321",
	"race-condition": "CWE-362",
	"buffer-overflow": "CWE-120",
	"format-string":  "CWE-134",
}
