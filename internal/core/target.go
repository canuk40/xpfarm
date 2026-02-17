package core

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"xpfarm/pkg/utils"
)

type TargetType string

const (
	TargetTypeIP     TargetType = "ip"
	TargetTypeCIDR   TargetType = "cidr"
	TargetTypeDomain TargetType = "domain"
	TargetTypeURL    TargetType = "url"
)

type ParsedTarget struct {
	Value string
	Type  TargetType
}

// ParseTarget determines the type of the target string.
// It does NOT perform DNS resolution; that's for a separate step or the tools themselves.
func ParseTarget(input string) ParsedTarget {
	input = strings.TrimSpace(input)

	// Check if CIDR
	if _, _, err := net.ParseCIDR(input); err == nil {
		return ParsedTarget{Value: input, Type: TargetTypeCIDR}
	}

	// Check if IP
	if net.ParseIP(input) != nil {
		return ParsedTarget{Value: input, Type: TargetTypeIP}
	}

	// Check if URL (has scheme)
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err == nil && u.Scheme != "" && u.Host != "" {
			return ParsedTarget{Value: input, Type: TargetTypeURL}
		}
	}

	// Default to Domain
	return ParsedTarget{Value: input, Type: TargetTypeDomain}
}

// NormalizeToHostname strips scheme, port, paths, trailing slashes,
// and query strings from the input, returning just the bare hostname/domain.
// Examples:
//
//	"https://example.com/path?q=1" -> "example.com"
//	"example.com/"                 -> "example.com"
//	"http://sub.example.com:8080/" -> "sub.example.com"
//	"192.168.1.1"                  -> "192.168.1.1"
func NormalizeToHostname(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return input
	}

	// If it looks like a URL with a scheme, parse it properly
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err == nil && u.Host != "" {
			input = u.Host
		}
	}

	// Remove trailing slashes and paths (for bare domain/path inputs like "example.com/foo")
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	// Remove port if present (handles both IPv4:port and [IPv6]:port)
	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}

	// Remove trailing dots
	input = strings.TrimRight(input, ".")

	return input
}

// TargetCheckResult holds intelligence data
type TargetCheckResult struct {
	IsCloudflare bool
	IsAlive      bool
	IsLocalhost  bool
	Status       string
	ResolvedIPs  []string
}

// cachedDNSEntry wraps a result with a timestamp for TTL
type cachedDNSEntry struct {
	result   TargetCheckResult
	cachedAt time.Time
}

const dnsCacheTTL = 5 * time.Minute

// dnsCache stores DNS resolution results with TTL to avoid redundant lookups
var dnsCache sync.Map

// isLocalhost returns true if the IP is a loopback or unspecified address
func isLocalhost(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsUnspecified()
}

// ResolveAndCheck performs DNS resolution and checks Cloudflare status, liveness,
// and localhost resolution. Results are cached with a TTL.
func ResolveAndCheck(input string) TargetCheckResult {
	// Check cache first (with TTL)
	if cached, ok := dnsCache.Load(input); ok {
		entry := cached.(cachedDNSEntry)
		if time.Since(entry.cachedAt) < dnsCacheTTL {
			return entry.result
		}
		// Expired — remove and re-resolve
		dnsCache.Delete(input)
	}

	parsed := ParseTarget(input)
	res := TargetCheckResult{
		Status:  "down",
		IsAlive: false,
	}

	ips := []string{}

	// 1. Resolve IP
	switch parsed.Type {
	case TargetTypeIP:
		ips = append(ips, parsed.Value)
		res.IsAlive = true // Assume IP provided is "alive" in terms of resolution
	case TargetTypeDomain, TargetTypeURL:
		host := parsed.Value
		if parsed.Type == TargetTypeURL {
			u, err := url.Parse(parsed.Value)
			if err != nil || u.Host == "" {
				res.Status = "unreachable"
				return res
			}
			host = u.Host
		}
		// Strip port
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		resolved, err := net.LookupHost(host)
		if err == nil && len(resolved) > 0 {
			ips = append(ips, resolved...)
			res.IsAlive = true
			res.Status = "up"
		} else {
			res.Status = "unreachable"
			return res
		}
	case TargetTypeCIDR:
		_, ipNet, err := net.ParseCIDR(parsed.Value)
		if err == nil && ipNet != nil {
			res.IsAlive = true
			res.Status = "up"
			// Don't try to resolve the network address as an IP
		}
	}

	// 2. Check Localhost (keep IsAlive=true so excludeLocalhost toggle can decide)
	for _, ip := range ips {
		if isLocalhost(ip) {
			res.IsLocalhost = true
			res.Status = "localhost"
			break
		}
	}

	// 3. Check Cloudflare (only if alive and not localhost)
	if res.IsAlive {
		for _, ip := range ips {
			if utils.IsCloudflareIP(ip) {
				res.IsCloudflare = true
				break
			}
		}
	}

	res.ResolvedIPs = ips
	if res.IsAlive {
		res.Status = "up"
	}
	if len(ips) == 0 && parsed.Type != TargetTypeCIDR {
		res.IsAlive = false
		res.Status = "unreachable"
	}

	// Cache the result with timestamp
	dnsCache.Store(input, cachedDNSEntry{
		result:   res,
		cachedAt: time.Now(),
	})

	return res
}
