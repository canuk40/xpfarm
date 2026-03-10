package core

import (
	"fmt"
	"strings"

	"xpfarm/internal/database"
)

// serviceTagMap maps common Nmap service names to Nuclei template tags.
// These tags correspond to the tags used in the nuclei-templates "network/" directory.
var serviceTagMap = map[string][]string{
	"ssh":           {"ssh"},
	"ftp":           {"ftp"},
	"smtp":          {"smtp"},
	"pop3":          {"pop3"},
	"imap":          {"imap"},
	"rdp":           {"rdp"},
	"smb":           {"smb"},
	"mysql":         {"mysql"},
	"postgresql":    {"postgresql", "postgres"},
	"postgres":      {"postgresql", "postgres"},
	"redis":         {"redis"},
	"mongodb":       {"mongodb"},
	"mongod":        {"mongodb"},
	"mssql":         {"mssql"},
	"ms-sql-s":      {"mssql"},
	"vnc":           {"vnc"},
	"telnet":        {"telnet"},
	"ldap":          {"ldap"},
	"dns":           {"dns"},
	"domain":        {"dns"},
	"snmp":          {"snmp"},
	"nfs":           {"nfs"},
	"mqtt":          {"mqtt"},
	"amqp":          {"rabbitmq"},
	"cassandra":     {"cassandra"},
	"memcached":     {"memcached"},
	"docker":        {"docker"},
	"elasticsearch": {"elasticsearch"},
	"kafka":         {"kafka"},
	"zookeeper":     {"zookeeper"},
	"rtsp":          {"rtsp"},
	"sip":           {"voip"},
	"ajp13":         {"ajp"},
	"pptp":          {"vpn"},
	"openvpn":       {"vpn"},
	"rmiregistry":   {"rmi"},
	"java-rmi":      {"rmi"},
	"epmd":          {"epmd", "erlang"},
	"couchdb":       {"couchdb"},
	"consul":        {"consul"},
}

// webServices are Nmap service names that indicate a web server — these
// should be handled by the "-as" (automatic/wappalyzer) scan, not network templates.
var webServices = map[string]bool{
	"http":       true,
	"https":      true,
	"http-proxy": true,
	"http-alt":   true,
}

// portServiceMap provides a fallback service name when Nmap fails to detect one.
// Used when service is empty, "unknown", or "tcpwrapped".
var portServiceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "smb",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "smtp",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	1883:  "mqtt",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5672:  "amqp",
	5900:  "vnc",
	5901:  "vnc",
	6379:  "redis",
	6443:  "https",
	8080:  "http",
	8443:  "https",
	8888:  "http",
	9042:  "cassandra",
	9092:  "kafka",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
	2181:  "zookeeper",
}

// NucleiPortScan represents a single per-port Nuclei scan to execute.
type NucleiPortScan struct {
	Target string   // host:port
	Tags   []string // nuclei tags to use
	Port   int
}

// NucleiPlan describes all Nuclei scans to execute for a target.
type NucleiPlan struct {
	// NetworkScans are per-port scans with service-specific tags using -pt network
	NetworkScans []NucleiPortScan

	// WebURLs are HTTP/HTTPS URLs to scan with -as (automatic/wappalyzer)
	WebURLs []string

	// FallbackURLs are host:port targets with no known tags — scanned with -as
	FallbackURLs []string
}

// BuildNucleiPlan analyzes detected ports and web assets to build a targeted scan plan.
func BuildNucleiPlan(targetValue string, ports []database.Port, webAssets []database.WebAsset) NucleiPlan {
	plan := NucleiPlan{}

	for _, p := range ports {
		service := strings.ToLower(strings.TrimSpace(p.Service))
		product := strings.ToLower(strings.TrimSpace(p.Product))
		hostPort := fmt.Sprintf("%s:%d", targetValue, p.Port)

		// Fallback: if Nmap didn't identify the service, infer from port number
		if service == "" || service == "unknown" || service == "tcpwrapped" {
			if fallback, ok := portServiceMap[p.Port]; ok {
				service = fallback
			}
		}

		// Skip web services — they'll be handled by the -as scan via WebAssets
		if webServices[service] {
			continue
		}

		// If the product is entirely unknown, skip sending raw tags and immediately
		// push to fallback for wappalyzer (-as) guessing
		if product == "" || product == "unknown" {
			plan.FallbackURLs = append(plan.FallbackURLs, hostPort)
			continue
		}

		// Build tags for this port's distinct service
		tags := buildTagsForService(service, product)
		if len(tags) > 0 {
			plan.NetworkScans = append(plan.NetworkScans, NucleiPortScan{
				Target: hostPort,
				Tags:   tags,
				Port:   p.Port,
			})
		} else {
			// No known tags — fall back to -as automatic scan
			plan.FallbackURLs = append(plan.FallbackURLs, hostPort)
		}
	}

	// Collect web URLs for -as scan
	urlSeen := make(map[string]bool)
	for _, wa := range webAssets {
		u := strings.TrimSpace(wa.URL)
		if u != "" && !urlSeen[u] {
			plan.WebURLs = append(plan.WebURLs, u)
			urlSeen[u] = true
		}
	}

	return plan
}

// buildTagsForService returns nuclei tags for a given Nmap service and product.
func buildTagsForService(service, product string) []string {
	seen := make(map[string]bool)
	var tags []string

	// Add service-mapped tags
	if mapped, ok := serviceTagMap[service]; ok {
		for _, t := range mapped {
			if !seen[t] {
				tags = append(tags, t)
				seen[t] = true
			}
		}
	}

	// Add the product name as an additional tag (e.g., "openssh", "proftpd", "vsftpd")
	if product != "" && product != "unknown" {
		// Clean product: remove version-like suffixes, lowercase
		cleanProduct := strings.Fields(product)[0] // Take first word
		cleanProduct = strings.ToLower(cleanProduct)
		if !seen[cleanProduct] {
			tags = append(tags, cleanProduct)
			seen[cleanProduct] = true
		}
	}

	return tags
}
