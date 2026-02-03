package modules

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"xpfarm/pkg/utils"
)

type Nmap struct{}

func (n *Nmap) Name() string {
	return "nmap"
}

func (n *Nmap) CheckInstalled() bool {
	path := utils.ResolveBinaryPath("nmap")
	_, err := exec.LookPath(path)
	return err == nil
}

func (n *Nmap) Install() error {
	return fmt.Errorf("nmap must be installed manually")
}

func (n *Nmap) Run(ctx context.Context, target string) (string, error) {
	// Standard full scan logic if needed, but we mostly use CustomScan
	return "", nil
}

// NmapRun XML Structures
type NmapRun struct {
	Vars  string `xml:"args,attr"`
	Hosts []Host `xml:"host"`
}
type Host struct {
	Ports []Port `xml:"ports>port"`
}
type Port struct {
	PortID   int      `xml:"portid,attr"`
	Protocol string   `xml:"protocol,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}
type State struct {
	State string `xml:"state,attr"`
}
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}
type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapResult struct {
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
	Scripts  string
}

// CustomScan runs the Aggressive Scan -> Fallback Scan logic
func (n *Nmap) CustomScan(ctx context.Context, target string, ports []int) ([]NmapResult, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	portList := strings.Join(portStrs, ",")

	utils.LogInfo("Running nmap service scan on %s (Ports: %s)...", target, portList)
	path := utils.ResolveBinaryPath("nmap")

	// 1. Aggressive Scan
	args := []string{"-Pn", "-sV", "-sC", "-p", portList, "-oX", "-", target}
	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %v", err)
	}

	results, fallbackPorts := n.parseNmapXML(output)

	// 2. Fallback Scan
	if len(fallbackPorts) > 0 {
		utils.LogInfo("Running nmap fallback scan on %v...", fallbackPorts)
		fbPortStrs := make([]string, len(fallbackPorts))
		for i, p := range fallbackPorts {
			fbPortStrs[i] = strconv.Itoa(p)
		}
		fbList := strings.Join(fbPortStrs, ",")

		// Simple scan (-Pn only)
		fbArgs := []string{"-Pn", "-p", fbList, "-oX", "-", target}
		fbCmd := exec.CommandContext(ctx, path, fbArgs...)
		fbOutput, fbErr := fbCmd.Output()
		if fbErr == nil {
			fbResults, _ := n.parseNmapXML(fbOutput)
			// Merge fallback results
			resultMap := make(map[int]*NmapResult)
			for i := range results {
				resultMap[results[i].Port] = &results[i]
			}

			for _, fb := range fbResults {
				if original, ok := resultMap[fb.Port]; ok {
					// Update service name, keep scripts/original data if needed?
					// User logic: "use the default service name"
					original.Service = fb.Service
					// Clear product/version if they were misleading? Probably yes.
					original.Product = ""
					original.Version = ""
					// Scripts? Tcpwrapped implies connection closed, so scripts likely failed or are useless.
					// But user said: "if ... tcpwrapped ... or fingerprints ... redo"
					// We might keep the fingerprint in the script output for debugging if interesting,
					// but usually we want to clean it up.
					// Let's keep original scripts if they exist (unless it's just the fingerprint one).
				}
			}
		} else {
			utils.LogError("Fallback scan failed: %v", fbErr)
		}
	}

	return results, nil
}

func (n *Nmap) parseNmapXML(xmlData []byte) ([]NmapResult, []int) {
	var run NmapRun
	if err := xml.Unmarshal(xmlData, &run); err != nil {
		utils.LogError("Failed to parse Nmap XML: %v", err)
		return nil, nil
	}

	var results []NmapResult
	var fallbackPorts []int

	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			// Clean up script output
			var scriptOutputs []string
			hasFingerprint := false
			for _, s := range port.Scripts {
				clean := strings.TrimSpace(s.Output)
				if clean != "" {
					scriptOutputs = append(scriptOutputs, fmt.Sprintf("[%s]\n%s", s.ID, clean))
					if s.ID == "fingerprint-strings" {
						hasFingerprint = true
					}
				}
			}

			res := NmapResult{
				Port:     port.PortID,
				Protocol: port.Protocol,
				Service:  port.Service.Name,
				Product:  port.Service.Product,
				Version:  port.Service.Version,
				Scripts:  strings.Join(scriptOutputs, "\n\n"),
			}
			results = append(results, res)

			// Fallback Criteria
			// 1. tcpwrapped
			// 2. Unrecognized service (usually "unknown") with fingerprints
			if port.Service.Name == "tcpwrapped" || (port.Service.Name == "unknown" && hasFingerprint) {
				fallbackPorts = append(fallbackPorts, port.PortID)
			} else if port.Service.Name == "unknown" {
				// Also fallback for just unknown?
				fallbackPorts = append(fallbackPorts, port.PortID)
			}
		}
	}
	return results, fallbackPorts
}
