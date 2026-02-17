package modules

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
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
func (n *Nmap) CustomScan(ctx context.Context, target string, ports []int) ([]NmapResult, string, error) {
	if len(ports) == 0 {
		return nil, "", nil
	}

	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	portList := strings.Join(portStrs, ",")

	utils.LogInfo("Running nmap service scan on %s (Ports: %s)...", target, portList)
	path := utils.ResolveBinaryPath("nmap")

	// Create Temp File for XML
	xmlFile, err := os.CreateTemp("", "nmap-*.xml")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp xml file: %v", err)
	}
	xmlPath := xmlFile.Name()
	xmlFile.Close()
	defer os.Remove(xmlPath)

	// 1. Aggressive Scan
	// Output XML to file, Normal output to stdout (captured)
	args := []string{"-Pn", "-sV", "-sC", "-p", portList, "-oX", xmlPath, target}

	cmd := exec.CommandContext(ctx, path, args...)
	outputBytes, err := cmd.CombinedOutput() // This captures normal output now
	rawOutput := string(outputBytes)

	if err != nil {
		return nil, rawOutput, fmt.Errorf("nmap scan failed: %v", err)
	}

	// Parse XML from file
	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, rawOutput, fmt.Errorf("failed to read nmap xml: %v", err)
	}

	results, fallbackPorts := n.parseNmapXML(xmlData)

	// 2. Fallback Scan
	if len(fallbackPorts) > 0 {
		utils.LogInfo("Running nmap fallback scan on %v...", fallbackPorts)
		fbPortStrs := make([]string, len(fallbackPorts))
		for i, p := range fallbackPorts {
			fbPortStrs[i] = strconv.Itoa(p)
		}
		fbList := strings.Join(fbPortStrs, ",")

		// Simple scan (-Pn only)
		// Again, separate XML to file? Or just reuse/overwrite? Overwrite is fine or new file.
		// For fallback, we might not need "Raw Log" as much, but let's append it to rawOutput.

		fbXmlFile, _ := os.CreateTemp("", "nmap-fb-*.xml")
		fbXmlPath := fbXmlFile.Name()
		fbXmlFile.Close()
		defer os.Remove(fbXmlPath)

		fbArgs := []string{"-Pn", "-p", fbList, "-oX", fbXmlPath, target}
		fbCmd := exec.CommandContext(ctx, path, fbArgs...)
		fbOutBytes, fbErr := fbCmd.CombinedOutput()

		rawOutput += "\n\n--- Fallback Scan ---\n" + string(fbOutBytes)

		if fbErr == nil {
			fbXmlData, _ := os.ReadFile(fbXmlPath)
			fbResults, _ := n.parseNmapXML(fbXmlData)

			// Merge fallback results
			resultMap := make(map[int]*NmapResult)
			for i := range results {
				resultMap[results[i].Port] = &results[i]
			}

			for _, fb := range fbResults {
				if original, ok := resultMap[fb.Port]; ok {
					// Only overwrite with fallback data if it's actually better
					if fb.Service != "" && fb.Service != "unknown" {
						original.Service = fb.Service
					}
					if fb.Product != "" {
						original.Product = fb.Product
					}
					if fb.Version != "" {
						original.Version = fb.Version
					}
				}
			}
		} else {
			utils.LogError("Fallback scan failed: %v", fbErr)
		}
	}

	return results, rawOutput, nil
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
