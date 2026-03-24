// Package nmap implements the normalization Adapter for Nmap scan results.
//
// Expected raw map shape — the top-level map represents one scanned host and
// is typically produced by parsing nmap's XML output (-oX) into JSON.
// XPFarm's nmap module produces text output; callers can convert via
// github.com/Ullaakut/nmap/v3 or by running nmap with -oX and parsing.
//
//	{
//	  "host": "192.168.1.1",
//	  "ports": [
//	    {
//	      "port":     22,
//	      "protocol": "tcp",
//	      "state":    "open",
//	      "service":  "ssh",
//	      "product":  "OpenSSH",
//	      "version":  "7.4",
//	      "scripts": [
//	        {"id": "ssh-vuln-cve2018-15473", "output": "VULNERABLE: CVE-2018-15473\n  ..."}
//	      ]
//	    }
//	  ]
//	}
//
// The adapter emits one Finding per vulnerable port/script combination.
// Open ports with no vulnerability scripts produce an info-severity Finding.
package nmap

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

func init() {
	normalization.RegisterAdapter(&Adapter{})
}

// cvePattern matches CVE identifiers in NSE script output.
var cvePattern = regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,7})`)

// Adapter normalizes nmap host+port data into model.Finding values.
type Adapter struct{}

func (a *Adapter) Source() string { return "nmap" }

func (a *Adapter) Normalize(raw map[string]any) ([]model.Finding, error) {
	host, _ := raw["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("nmap adapter: missing 'host' key")
	}

	rawPorts, _ := raw["ports"].([]any)
	if len(rawPorts) == 0 {
		return nil, nil
	}

	var findings []model.Finding
	ts := time.Now().UTC()

	for _, rp := range rawPorts {
		portMap, ok := rp.(map[string]any)
		if !ok {
			continue
		}
		if state, _ := portMap["state"].(string); state != "open" {
			continue
		}

		portNum := intVal(portMap, "port")
		protocol, _ := portMap["protocol"].(string)
		if protocol == "" {
			protocol = "tcp"
		}
		service, _ := portMap["service"].(string)
		product, _ := portMap["product"].(string)
		version, _ := portMap["version"].(string)

		location := fmt.Sprintf("%s:%d/%s", host, portNum, protocol)
		serviceLabel := service
		if product != "" {
			serviceLabel = product
			if version != "" {
				serviceLabel += " " + version
			}
		}

		// Process NSE scripts attached to this port.
		scripts, _ := portMap["scripts"].([]any)
		if len(scripts) == 0 {
			// No scripts — emit an info finding for the open port so it
			// appears in the findings inventory.
			findings = append(findings, model.Finding{
				ID:          model.NewID(),
				Source:      "nmap",
				Target:      host,
				Location:    location,
				Title:       fmt.Sprintf("Open Port: %d/%s (%s)", portNum, protocol, service),
				Description: fmt.Sprintf("Port %d/%s is open. Service identified as %s.", portNum, protocol, serviceLabel),
				Severity:    model.SeverityInfo,
				Tags:        []string{"port", "nmap", service},
				Raw:         raw,
				Timestamp:   ts,
			})
			continue
		}

		for _, rs := range scripts {
			scriptMap, ok := rs.(map[string]any)
			if !ok {
				continue
			}
			scriptID, _ := scriptMap["id"].(string)
			scriptOut, _ := scriptMap["output"].(string)

			severity, cve := classifyScript(scriptID, scriptOut)
			title := buildTitle(scriptID, portNum, protocol, service)

			findings = append(findings, model.Finding{
				ID:          model.NewID(),
				Source:      "nmap",
				Target:      host,
				Location:    location,
				Title:       title,
				Description: fmt.Sprintf("NSE script %q reported on %s (%s).", scriptID, location, serviceLabel),
				Severity:    severity,
				CVE:         cve,
				Evidence:    trimEvidence(scriptOut),
				Tags:        []string{"nmap", "nse", scriptID, service},
				Raw:         raw,
				Timestamp:   ts,
			})
		}
	}

	return findings, nil
}

// classifyScript infers severity and any embedded CVE from the script ID / output.
func classifyScript(id, output string) (severity, cve string) {
	idLower := strings.ToLower(id)
	outLower := strings.ToLower(output)

	// Extract the first CVE from the output
	if m := cvePattern.FindString(output); m != "" {
		cve = strings.ToUpper(m)
	}

	switch {
	case strings.Contains(outLower, "vulnerable") || strings.Contains(idLower, "vuln"):
		severity = model.SeverityHigh
	case strings.Contains(idLower, "brute") || strings.Contains(idLower, "default"):
		severity = model.SeverityMedium
	case cve != "":
		severity = model.SeverityHigh
	default:
		severity = model.SeverityInfo
	}
	return
}

// buildTitle generates a human-readable finding title from script and port info.
func buildTitle(scriptID string, port int, proto, service string) string {
	// Pretty-print the script ID: "ssh-vuln-cve2018-15473" → "SSH Vuln CVE-2018-15473"
	pretty := strings.ReplaceAll(scriptID, "-", " ")
	pretty = strings.Title(pretty) //nolint:staticcheck // acceptable for display-only use
	return fmt.Sprintf("%s on port %d/%s (%s)", pretty, port, proto, service)
}

// intVal extracts an int from a map key that may be float64 (JSON default) or int.
func intVal(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func trimEvidence(s string) string {
	const maxLen = 2048
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
