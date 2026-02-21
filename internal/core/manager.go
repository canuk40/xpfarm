package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"xpfarm/internal/database"
	"xpfarm/internal/modules"
	"xpfarm/pkg/utils"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ScanManager handles scan execution and cancellation
type ScanInfo struct {
	Cancel    context.CancelFunc
	AssetName string
}

type ScanManager struct {
	mu          sync.Mutex
	activeScans map[string]ScanInfo

	// Optional callbacks — must hold mu or copy under mu before calling
	onStart func(target string)
	onStop  func(target string, cancelled bool)
}

var currentManager *ScanManager
var managerOnce sync.Once

func GetManager() *ScanManager {
	managerOnce.Do(func() {
		currentManager = &ScanManager{
			activeScans: make(map[string]ScanInfo),
		}
	})
	return currentManager
}

type ActiveScanData struct {
	Target string `json:"target"`
	Asset  string `json:"asset"`
}

func (sm *ScanManager) GetActiveScans() []ActiveScanData {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	var list []ActiveScanData
	for t, info := range sm.activeScans {
		list = append(list, ActiveScanData{Target: t, Asset: info.AssetName})
	}
	return list
}

// SetOnStart sets the callback for when a scan starts (thread-safe).
func (sm *ScanManager) SetOnStart(fn func(target string)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onStart = fn
}

// SetOnStop sets the callback for when a scan stops (thread-safe).
func (sm *ScanManager) SetOnStop(fn func(target string, cancelled bool)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onStop = fn
}

func (sm *ScanManager) StartScan(targetInput string, assetName string, excludeCF bool, excludeLocalhost bool) {
	sm.mu.Lock()
	if _, exists := sm.activeScans[targetInput]; exists {
		sm.mu.Unlock()
		utils.LogWarning("[Manager] Scan already running for %s, ignoring start request.", targetInput)
		return
	}
	utils.LogInfo("[Manager] Starting scan for %s (Asset: %s)", targetInput, assetName)

	ctx, cancel := context.WithCancel(context.Background())
	sm.activeScans[targetInput] = ScanInfo{
		Cancel:    cancel,
		AssetName: assetName,
	}
	onStartFn := sm.onStart
	sm.mu.Unlock()

	if onStartFn != nil {
		onStartFn(targetInput)
	}

	// Run in background
	go func() {
		defer func() {
			sm.mu.Lock()
			delete(sm.activeScans, targetInput)
			onStopFn := sm.onStop
			sm.mu.Unlock()

			if onStopFn != nil {
				cancelled := ctx.Err() == context.Canceled
				onStopFn(targetInput, cancelled)
			}
		}()
		sm.runScanLogic(ctx, targetInput, assetName, excludeCF, excludeLocalhost)
	}()
}

func (sm *ScanManager) StopScan(target string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if target == "" {
		// Stop ALL — cancel contexts, goroutine defers handle cleanup & notification
		for t, info := range sm.activeScans {
			info.Cancel()
			utils.LogInfo("[Manager] Stopping scan for %s", t)
		}
	} else {
		// Stop Specific
		if info, ok := sm.activeScans[target]; ok {
			info.Cancel()
			utils.LogInfo("[Manager] Stopping scan for %s", target)
		}
	}
}

func (sm *ScanManager) StopAssetScan(assetName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	for _, info := range sm.activeScans {
		if info.AssetName == assetName {
			info.Cancel()
			count++
		}
	}
	utils.LogInfo("[Manager] Requested stop for %d scans for asset %s", count, assetName)
}

// runScanLogic executes the sequential pipeline
func (sm *ScanManager) runScanLogic(ctx context.Context, targetInput string, assetName string, excludeCF bool, excludeLocalhost bool) {
	// 1. Initialize & Context Check
	db := database.GetDB()
	if ctx.Err() != nil {
		return
	}

	// 2. Normalize & Resolve Target
	parsed := ParseTarget(targetInput)
	hostname := NormalizeToHostname(parsed.Value)
	if hostname == "" {
		hostname = parsed.Value
	}
	utils.LogInfo("[Scanner] Pipeline Start: %s (normalized: %s, type: %s)", parsed.Value, hostname, parsed.Type)

	if assetName == "" {
		assetName = "Default"
	}
	var asset database.Asset
	if err := db.Where(database.Asset{Name: assetName}).FirstOrCreate(&asset).Error; err != nil {
		utils.LogError("[Scanner] Error getting asset: %v", err)
	}

	// 3. Create Main Target Record (before IsAlive check — always stored in DB)
	targetObj := database.Target{
		AssetID: asset.ID,
		Value:   hostname,
		Type:    string(parsed.Type),
	}
	if err := db.Where(database.Target{Value: hostname, AssetID: asset.ID}).FirstOrCreate(&targetObj).Error; err != nil {
		utils.LogError("Error creating target: %v", err)
		return // Critical failure
	}
	db.Model(&targetObj).Update("updated_at", time.Now())

	// === STAGE 1: Subdomain Discovery (Subfinder — Synchronous) ===
	utils.LogInfo("[Scanner] Stage 1: Running Subfinder on %s", hostname)
	var subdomains []string

	subfinderMod := modules.Get("subfinder")
	if subfinderMod != nil && subfinderMod.CheckInstalled() {
		output, err := subfinderMod.Run(ctx, hostname)
		recordResult(db, targetObj.ID, "subfinder", output)

		if err == nil && output != "" {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				domain := strings.TrimSpace(line)
				if domain == "" || domain == hostname {
					continue
				}
				subdomains = append(subdomains, domain)
			}
			utils.LogSuccess("[Scanner] Subfinder found %d subdomains for %s", len(subdomains), hostname)
		} else if err != nil {
			utils.LogError("[Scanner] Subfinder failed: %v", err)
		}
	}

	if ctx.Err() != nil {
		return
	}

	// === STAGE 2: Create subdomain records, then check IsAlive on all ===
	utils.LogInfo("[Scanner] Stage 2: Creating %d subdomain records and running IsAlive checks", len(subdomains))

	// First, create all subdomain records in DB (no alive check yet)
	var allSubTargets []database.Target
	for _, domain := range subdomains {
		subTarget := database.Target{
			AssetID:  asset.ID,
			ParentID: &targetObj.ID,
			Value:    domain,
			Type:     "domain",
		}
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "value"}},
			DoNothing: true,
		}).Where(database.Target{Value: domain, AssetID: asset.ID}).FirstOrCreate(&subTarget).Error; err != nil {
			utils.LogDebug("[Scanner] Error creating subtarget %s: %v", domain, err)
			continue
		}
		allSubTargets = append(allSubTargets, subTarget)
	}

	// Now check IsAlive on the main target + all subdomains
	// Channel for alive targets to be scanned
	targetsChan := make(chan database.Target, 100)
	var producerWG sync.WaitGroup

	// Check main target alive status
	mainCheck := ResolveAndCheck(hostname)

	// Tag localhost in DB regardless of excludeLocalhost setting
	if mainCheck.IsLocalhost {
		db.Model(&targetObj).Update("is_localhost", true)
	}

	if !mainCheck.IsAlive {
		// Truly unreachable — soft-delete
		utils.LogWarning("[Scanner] Main target %s is unreachable (%s), removing", hostname, mainCheck.Status)
		db.Model(&targetObj).Updates(map[string]interface{}{"status": mainCheck.Status, "is_alive": false})
		db.Delete(&targetObj)
		// Subdomains can still be alive even if the apex domain is dead,
		// so we continue checking them individually below.
	} else if mainCheck.IsLocalhost && excludeLocalhost {
		// Alive but resolves to localhost and user chose to exclude
		utils.LogWarning("[Scanner] Main target %s resolves to localhost (excluded), removing", hostname)
		db.Model(&targetObj).Updates(map[string]interface{}{"status": "resolves to localhost", "is_alive": false})
		db.Delete(&targetObj)
	} else {
		// Main target is alive (and either not localhost, or localhost is allowed)
		db.Model(&targetObj).Updates(map[string]interface{}{
			"is_cloudflare": mainCheck.IsCloudflare,
			"is_localhost":  mainCheck.IsLocalhost,
			"is_alive":      true,
			"status":        "up",
		})
		targetObj.IsCloudflare = mainCheck.IsCloudflare
		targetObj.IsLocalhost = mainCheck.IsLocalhost
		targetObj.IsAlive = true
		targetObj.Status = "up"

		// Push main target if it passes filters
		skip := (excludeCF && mainCheck.IsCloudflare)
		if !skip {
			producerWG.Add(1)
			go func() {
				defer producerWG.Done()
				targetsChan <- targetObj
			}()
		} else {
			utils.LogWarning("[Scanner] Skipping main target %s (Cloudflare)", hostname)
		}
	}

	// Check all subdomains
	for _, subTarget := range allSubTargets {
		if ctx.Err() != nil {
			break
		}

		check := ResolveAndCheck(subTarget.Value)

		// Tag localhost in DB regardless of excludeLocalhost setting
		if check.IsLocalhost {
			db.Model(&subTarget).Update("is_localhost", true)
		}

		// Truly unreachable → soft-delete
		if !check.IsAlive {
			utils.LogDebug("[Scanner] Subdomain %s is unreachable (%s), removing", subTarget.Value, check.Status)
			db.Model(&subTarget).Updates(map[string]interface{}{"status": check.Status, "is_alive": false})
			db.Delete(&subTarget)
			continue
		}

		// Alive but localhost — only exclude if user opted in
		if check.IsLocalhost && excludeLocalhost {
			utils.LogDebug("[Scanner] Subdomain %s resolves to localhost (excluded), removing", subTarget.Value)
			db.Model(&subTarget).Updates(map[string]interface{}{"status": "resolves to localhost", "is_alive": false})
			db.Delete(&subTarget)
			continue
		}

		// Update alive status in DB
		db.Model(&subTarget).Updates(map[string]interface{}{
			"is_cloudflare": check.IsCloudflare,
			"is_localhost":  check.IsLocalhost,
			"is_alive":      true,
			"status":        "up",
		})

		// Skip if Cloudflare-excluded
		if excludeCF && check.IsCloudflare {
			utils.LogDebug("[Scanner] Subdomain %s is behind Cloudflare, skipping scan", subTarget.Value)
			continue
		}

		subTarget.IsAlive = true
		subTarget.IsCloudflare = check.IsCloudflare
		subTarget.IsLocalhost = check.IsLocalhost
		subTarget.Status = "up"

		producerWG.Add(1)
		go func(t database.Target) {
			defer producerWG.Done()
			targetsChan <- t
		}(subTarget)
	}

	// === Uncover Producer (Parallel — ports only) ===
	hasUncoverKeys := false
	uncoverKeys := []string{"SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET", "FOFA_KEY", "QUAKE_TOKEN", "HUNTER_API_KEY", "CRIMINALIP_API_KEY"}
	for _, k := range uncoverKeys {
		if os.Getenv(k) != "" {
			hasUncoverKeys = true
			break
		}
	}

	if hasUncoverKeys {
		uncoverMod := modules.Get("uncover")
		if uncoverMod != nil && uncoverMod.CheckInstalled() {
			producerWG.Add(1)
			go func() {
				defer producerWG.Done()
				output, err := uncoverMod.Run(ctx, hostname)
				recordResult(db, targetObj.ID, "uncover", output)

				if err == nil && output != "" {
					lines := strings.Split(output, "\n")
					count := 0
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}

						// Parse host:port safely (handles IPv6)
						host, portStr, splitErr := net.SplitHostPort(line)
						if splitErr != nil {
							// Might be just an IP/host without port
							utils.LogDebug("[Scanner] Uncover line not host:port format: %s", line)
							continue
						}

						portVal := utils.StringToInt(portStr)
						if portVal <= 0 || portVal > 65535 {
							utils.LogDebug("[Scanner] Uncover invalid port: %s", portStr)
							continue
						}

						// Find the correct target to attribute the port to
						portTargetID := targetObj.ID
						if host != "" && host != hostname {
							var matchTarget database.Target
							if err := db.Where("value = ? AND asset_id = ?", host, asset.ID).First(&matchTarget).Error; err == nil {
								portTargetID = matchTarget.ID
							}
						}

						db.Clauses(clause.OnConflict{
							Columns:   []clause.Column{{Name: "target_id"}, {Name: "port"}},
							DoNothing: true,
						}).Create(&database.Port{
							TargetID: portTargetID,
							Port:     portVal,
							Protocol: "tcp",
							Service:  "unknown",
						})
						count++
					}
					utils.LogSuccess("[Scanner] Uncover found %d results", count)
				}
			}()
		}
	}

	// Channel Closer
	go func() {
		producerWG.Wait()
		close(targetsChan)
	}()

	// === CONSUMER (Worker Pool — Naabu + downstream stages) ===
	const maxWorkers = 5
	naabuMod := modules.Get("naabu")

	if naabuMod != nil && naabuMod.CheckInstalled() {
		var scannedTargets sync.Map
		var workerWG sync.WaitGroup

		for i := 0; i < maxWorkers; i++ {
			workerWG.Add(1)
			go func() {
				defer workerWG.Done()
				for t := range targetsChan {
					if ctx.Err() != nil {
						return
					}
					if _, loaded := scannedTargets.LoadOrStore(t.ID, true); loaded {
						continue
					}

					output, err := naabuMod.Run(ctx, t.Value)
					recordResult(db, t.ID, "naabu", output)

					if err == nil && output != "" {
						lines := strings.Split(output, "\n")
						portsFound := 0
						var targetPorts []int
						seenNaabuPorts := make(map[int]bool)
						for _, line := range lines {
							if strings.TrimSpace(line) == "" {
								continue
							}
							var nResult struct {
								IP   string `json:"ip"`
								Port int    `json:"port"`
							}
							if jsonErr := json.Unmarshal([]byte(line), &nResult); jsonErr != nil {
								utils.LogDebug("[Scanner] [Naabu] Failed to parse JSON line: %v (line: %.100s)", jsonErr, line)
								continue
							}
							if nResult.Port <= 0 || nResult.Port > 65535 {
								utils.LogDebug("[Scanner] [Naabu] Invalid port value: %d", nResult.Port)
								continue
							}
							// Skip duplicate ports
							if seenNaabuPorts[nResult.Port] {
								continue
							}
							seenNaabuPorts[nResult.Port] = true

							// Use OnConflict to handle race condition between Uncover and Naabu
							db.Clauses(clause.OnConflict{
								Columns:   []clause.Column{{Name: "target_id"}, {Name: "port"}},
								DoNothing: true,
							}).Create(&database.Port{
								TargetID: t.ID,
								Port:     nResult.Port,
								Protocol: "tcp",
								Service:  "unknown",
							})
							portsFound++
							targetPorts = append(targetPorts, nResult.Port)
						}
						if portsFound > 0 {
							utils.LogSuccess("[Scanner] [Naabu] Found %d open ports on %s", portsFound, t.Value)
						}

						// --- STAGE 3: Nmap Service Enumeration ---
						var nResults []modules.NmapResult
						if len(targetPorts) > 0 {
							nm := modules.Get("nmap")
							if nmapMod, ok := nm.(*modules.Nmap); ok && nmapMod.CheckInstalled() {
								var nmapErr error
								var nmapRaw string
								nResults, nmapRaw, nmapErr = nmapMod.CustomScan(ctx, t.Value, targetPorts)

								if nmapRaw != "" {
									recordResult(db, t.ID, "nmap", nmapRaw)
								}

								if nmapErr != nil {
									utils.LogError("[Scanner] Nmap failed for %s: %v", t.Value, nmapErr)
								} else {
									utils.LogSuccess("[Scanner] [Nmap] Enriched %d services on %s", len(nResults), t.Value)
									for _, res := range nResults {
										db.Model(&database.Port{}).
											Where("target_id = ? AND port = ?", t.ID, res.Port).
											Updates(map[string]interface{}{
												"service": res.Service,
												"product": res.Product,
												"version": res.Version,
												"scripts": res.Scripts,
											})
									}
								}
							}

							// --- STAGE 4: Web Probing (Httpx) ---
							// Build a service map from Nmap results for protocol detection
							nmapServiceMap := make(map[int]string)
							for _, res := range nResults {
								nmapServiceMap[res.Port] = res.Service
							}

							var httpUrls []string
							seenPorts := make(map[int]bool)

							addPort := func(port int) {
								if seenPorts[port] {
									return
								}
								seenPorts[port] = true
								proto := "http"
								// Use Nmap service detection if available
								if svc, ok := nmapServiceMap[port]; ok {
									if strings.Contains(svc, "ssl") || strings.Contains(svc, "https") {
										proto = "https"
									}
								} else if port == 443 || port == 8443 || port == 9443 || port == 4443 {
									proto = "https"
								}
								httpUrls = append(httpUrls, fmt.Sprintf("%s://%s:%d", proto, t.Value, port))
							}

							for _, res := range nResults {
								addPort(res.Port)
							}
							for _, port := range targetPorts {
								addPort(port)
							}

							utils.LogDebug("[Scanner] Prepared %d URLs for Httpx probing on %s", len(httpUrls), t.Value)

							if len(httpUrls) > 0 {
								utils.LogInfo("[Scanner] Triggering Httpx Stage 4 for %d URLs on %s", len(httpUrls), t.Value)
								httpxMod := modules.Get("httpx")
								if hx, ok := httpxMod.(*modules.Httpx); ok && hx.CheckInstalled() {
									webResults, httpxErr := hx.RunRich(ctx, httpUrls)
									if httpxErr != nil {
										utils.LogError("[Scanner] Httpx Stage 4 failed: %v", httpxErr)
									} else {
										// Save WebAssets
										count := 0
										for _, w := range webResults {
											if w.URL == "" {
												continue
											}

											// Run Wappalyzer analysis with response headers
											wapp := modules.Get("wappalyzer")
											if wappalyzer, ok := wapp.(*modules.Wappalyzer); ok {
												// Parse response headers from httpx response
												headers := extractHeadersFromResponse(w.Response)
												bodyBytes := []byte(w.Response)

												extraTech := wappalyzer.Analyze(headers, bodyBytes)

												// Merge unique technologies
												existing := make(map[string]bool)
												for _, tech := range w.Tech {
													existing[tech] = true
												}
												for _, tech := range extraTech {
													if !existing[tech] {
														w.Tech = append(w.Tech, tech)
														existing[tech] = true
													}
												}

												if len(w.Tech) > 0 {
													wappLog := fmt.Sprintf("Target: %s\nDetected Technologies:\n%s", w.URL, strings.Join(w.Tech, ", "))
													recordResult(db, t.ID, "wappalyzer", wappLog)
												}
											}

											techStr := strings.Join(w.Tech, ", ")

											db.Clauses(clause.OnConflict{
												Columns: []clause.Column{{Name: "target_id"}, {Name: "url"}},
												DoUpdates: clause.AssignmentColumns([]string{
													"title", "tech_stack", "web_server", "status_code",
													"content_len", "word_count", "line_count", "content_type",
													"location", "ip", "cname", "cdn", "response", "updated_at",
												}),
											}).Create(&database.WebAsset{
												TargetID:    t.ID,
												URL:         w.URL,
												Title:       w.Title,
												TechStack:   techStr,
												WebServer:   w.WebServer,
												StatusCode:  w.StatusCode,
												ContentLen:  w.ContentLen,
												WordCount:   w.WordCount,
												LineCount:   w.LineCount,
												ContentType: w.ContentType,
												Location:    w.Location,
												IP:          strings.Join(w.A, ", "),
												CNAME:       strings.Join(w.CNAMEs, ", "),
												CDN:         w.CDNName,
												Response:    "",
											})
											count++
										}

										utils.LogSuccess("[Scanner] [Httpx] Enriched %d web assets on %s", count, t.Value)

										// --- STAGES 5-6: Parallel Web Asset Processing ---
										gw := modules.Get("gowitness")
										kat := modules.Get("katana")
										urlF := modules.Get("urlfinder")

										gowitnessMod, gwOk := gw.(*modules.Gowitness)
										katanaMod, katOk := kat.(*modules.Katana)
										urlMod, urlOk := urlF.(*modules.Urlfinder)

										gwInstalled := gwOk && gowitnessMod.CheckInstalled()
										katInstalled := katOk && katanaMod.CheckInstalled()
										urlInstalled := urlOk && urlMod.CheckInstalled()

										if gwInstalled || katInstalled {
											utils.LogInfo("[Scanner] Triggering parallel web asset processing for %d URLs on %s", count, t.Value)

											var webWG sync.WaitGroup
											sem := make(chan struct{}, 10)

											for _, w := range webResults {
												if w.URL == "" {
													continue
												}

												webWG.Add(1)
												go func(webResult modules.HttpxResult) {
													defer webWG.Done()
													sem <- struct{}{}
													defer func() { <-sem }()

													// --- Gowitness Screenshot ---
													if gwInstalled {
														shotPath, gwOut, gwErr := gowitnessMod.RunSingle(ctx, webResult.URL)
														if gwOut != "" {
															recordResult(db, t.ID, "gowitness", gwOut)
														}
														if gwErr != nil {
															utils.LogDebug("[Scanner] Gowitness failed for %s: %v", webResult.URL, gwErr)
														} else {
															if _, statErr := os.Stat(shotPath); statErr == nil {
																db.Model(&database.WebAsset{}).
																	Where("target_id = ? AND url = ?", t.ID, webResult.URL).
																	Update("screenshot", shotPath)
															}
														}
													}

													// --- Katana & URLFinder ---
													if katInstalled {
														uniquePaths := make(map[string]bool)
														var pathsList []string
														var pathsMu sync.Mutex

														processOutput := func(rawOutput string) {
															lines := strings.Split(rawOutput, "\n")
															pathsMu.Lock()
															defer pathsMu.Unlock()
															for _, line := range lines {
																line = strings.TrimSpace(line)
																if line == "" {
																	continue
																}
																if strings.HasPrefix(line, "http") {
																	u, parseErr := url.Parse(line)
																	if parseErr == nil && u.Path != "" {
																		pathVal := u.Path
																		if !uniquePaths[pathVal] {
																			uniquePaths[pathVal] = true
																			pathsList = append(pathsList, pathVal)
																		}
																	} else if parseErr == nil {
																		if !uniquePaths["/"] {
																			uniquePaths["/"] = true
																			pathsList = append(pathsList, "/")
																		}
																	}
																} else {
																	if !uniquePaths[line] {
																		uniquePaths[line] = true
																		pathsList = append(pathsList, line)
																	}
																}
															}
														}

														// Run Katana
														args := []string{"-jc", "-kf", "all", "-fx", "-d", "5", "-pc", "-c", "20"}
														katanaOutput, katErr := katanaMod.RunCustom(ctx, webResult.URL, args)
														recordResult(db, t.ID, "katana", katanaOutput)
														if katErr == nil {
															processOutput(katanaOutput)
														}

														// Run URLFinder
														if urlInstalled {
															u, parseErr := url.Parse(webResult.URL)
															if parseErr == nil && u.Host != "" {
																urlHostname := u.Hostname()
																if urlHostname != "" {
																	urlOutput, urlErr := urlMod.Run(ctx, urlHostname)
																	recordResult(db, t.ID, "urlfinder", urlOutput)
																	if urlErr == nil {
																		processOutput(urlOutput)
																	}
																}
															}
														}

														// Save combined paths
														sort.Strings(pathsList)
														jsonBytes, jsonErr := json.Marshal(pathsList)
														if jsonErr != nil {
															utils.LogError("[Scanner] Failed to marshal katana paths: %v", jsonErr)
														} else {
															db.Model(&database.WebAsset{}).
																Where("target_id = ? AND url = ?", t.ID, webResult.URL).
																Update("katana_output", string(jsonBytes))
														}
													}
												}(w)
											}
											webWG.Wait()
										}
									}
								}
							}
						}
					}

					// --- STAGE 7: CVE Lookup via Cvemap (Per-Worker/Per-Target) ---
					sm.runCvemapScan(ctx, db, t)

					// --- STAGE 8: Nuclei Vulnerability Scanning (Per-Port) ---
					sm.runNucleiScan(ctx, db, t)
				}
			}()
		}
		workerWG.Wait()
	} else {
		utils.LogWarning("[Scanner] Naabu missing, draining pipeline...")
		for range targetsChan {
		}
	}

	utils.LogSuccess("[Scanner] Pipeline Completed for %s", hostname)
}

// extractHeadersFromResponse parses HTTP response headers from raw httpx response string
func extractHeadersFromResponse(rawResponse string) map[string][]string {
	headers := make(map[string][]string)
	if rawResponse == "" {
		return headers
	}

	// Normalize line endings: handle both \r\n and \n
	normalized := strings.ReplaceAll(rawResponse, "\r\n", "\n")

	// Response format: HTTP status line, then headers, then blank line, then body
	parts := strings.SplitN(normalized, "\n\n", 2)
	if len(parts) == 0 {
		return headers
	}

	headerSection := parts[0]
	lines := strings.Split(headerSection, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip HTTP status line
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		headers[key] = append(headers[key], value)
	}

	return headers
}

// runCvemapScan looks up CVEs for each detected product using vulnx
func (sm *ScanManager) runCvemapScan(ctx context.Context, db *gorm.DB, targetObj database.Target) {
	if ctx.Err() != nil {
		return
	}

	cveMapMod := modules.Get("cvemap")
	cm, ok := cveMapMod.(*modules.Cvemap)
	if !ok || !cm.CheckInstalled() {
		utils.LogDebug("[Scanner] Cvemap (vulnx) not available, skipping CVE lookup")
		return
	}

	// Gather unique products from ports (Nmap service detection)
	var ports []database.Port
	db.Where("target_id = ? AND product != ''", targetObj.ID).Find(&ports)

	// Deduplicate products
	productSet := make(map[string]bool)
	for _, p := range ports {
		prod := strings.TrimSpace(p.Product)
		if prod != "" && prod != "unknown" {
			productSet[strings.ToLower(prod)] = true
		}
	}

	// Also gather technologies from web assets (httpx tech detection)
	var webAssets []database.WebAsset
	db.Where("target_id = ? AND tech_stack != ''", targetObj.ID).Find(&webAssets)

	for _, wa := range webAssets {
		techs := strings.Split(wa.TechStack, ",")
		for _, tech := range techs {
			tech = strings.TrimSpace(tech)
			if tech != "" && tech != "unknown" {
				productSet[strings.ToLower(tech)] = true
			}
		}
	}

	if len(productSet) == 0 {
		utils.LogDebug("[Scanner] No products/technologies detected for CVE lookup on %s", targetObj.Value)
		return
	}

	utils.LogInfo("[Scanner] Querying Cvemap for %d products on %s...", len(productSet), targetObj.Value)

	totalCVEs := 0
	for product := range productSet {
		if ctx.Err() != nil {
			return
		}

		jsonOut, err := cm.SearchProduct(ctx, product)

		if jsonOut != "" {
			recordResult(db, targetObj.ID, "cvemap", fmt.Sprintf("Product: %s\n%s", product, jsonOut))
		}

		if err != nil {
			utils.LogDebug("[Scanner] Cvemap query failed for %s: %v", product, err)
			continue
		}

		// Parse JSON response (skip if empty — vulnx returns nothing for some products)
		if jsonOut == "" {
			continue
		}
		var response modules.CvemapResponse
		if err := json.Unmarshal([]byte(jsonOut), &response); err != nil {
			utils.LogDebug("[Scanner] Failed to parse Cvemap JSON for %s: %v", product, err)
			continue
		}

		seen := make(map[string]bool)
		count := 0

		for _, result := range response.Results {
			if result.CveID == "" || seen[result.CveID] {
				continue
			}
			seen[result.CveID] = true

			db.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "target_id"}, {Name: "product"}, {Name: "cve_id"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"severity", "cvss_score", "epss_score", "is_kev", "has_poc", "has_template",
				}),
			}).Create(&database.CVE{
				TargetID:    targetObj.ID,
				Product:     product,
				CveID:       result.CveID,
				Severity:    strings.ToLower(result.Severity),
				CvssScore:   result.CvssScore,
				EpssScore:   result.EpssScore,
				IsKEV:       result.IsKEV,
				HasPOC:      result.HasPOC,
				HasTemplate: result.HasTemplate,
			})
			count++
		}

		if count > 0 {
			utils.LogSuccess("[Scanner] [Cvemap] Found %d CVEs for %s", count, product)
			totalCVEs += count
		}
	}

	if totalCVEs > 0 {
		utils.LogSuccess("[Scanner] [Cvemap] Total: %d CVEs across %d products for %s", totalCVEs, len(productSet), targetObj.Value)
	}
}

// runNucleiScan executes Nuclei per-port with service-aware template selection.
func (sm *ScanManager) runNucleiScan(ctx context.Context, db *gorm.DB, targetObj database.Target) {
	if ctx.Err() != nil {
		return
	}

	nucleiMod := modules.Get("nuclei")
	nm, ok := nucleiMod.(*modules.Nuclei)
	if !ok || !nm.CheckInstalled() {
		utils.LogDebug("[Scanner] Nuclei not available, skipping vulnerability scan")
		return
	}

	// Gather port and web asset data for this target
	var ports []database.Port
	db.Where("target_id = ?", targetObj.ID).Find(&ports)

	var webAssets []database.WebAsset
	db.Where("target_id = ?", targetObj.ID).Find(&webAssets)

	if len(ports) == 0 && len(webAssets) == 0 {
		utils.LogDebug("[Scanner] No ports or web assets for Nuclei scan on %s", targetObj.Value)
		return
	}

	// Build the scan plan
	plan := BuildNucleiPlan(targetObj.Value, ports, webAssets)
	totalFindings := 0

	// --- Per-Port Network Scans ---
	for _, scan := range plan.NetworkScans {
		if ctx.Err() != nil {
			return
		}

		utils.LogInfo("[Scanner] [Nuclei] Scanning %s with tags: %v", scan.Target, scan.Tags)
		output, err := nm.RunWithTags(ctx, scan.Target, scan.Tags, "tcp")
		if output != "" {
			recordResult(db, targetObj.ID, "nuclei", fmt.Sprintf("Network scan %s [tags: %s]\n%s", scan.Target, strings.Join(scan.Tags, ","), output))
		}

		if strings.Contains(output, "no templates provided for scan") {
			utils.LogInfo("[Scanner] [Nuclei] No templates found for tags %v on %s, falling back to auto-scan", scan.Tags, scan.Target)
			plan.FallbackURLs = append(plan.FallbackURLs, scan.Target)
			// Proceed to parse (though it will be empty) or just continue, but keeping the flow is fine.
		}

		if err != nil {
			utils.LogDebug("[Scanner] [Nuclei] Network scan error for %s: %v", scan.Target, err)
			// Don't skip — partial output may have findings
		}

		count := sm.parseAndStoreNucleiResults(db, targetObj.ID, output)
		totalFindings += count
	}

	// --- Fallback: Automatic Scan for unmapped services ---
	if len(plan.FallbackURLs) > 0 {
		if ctx.Err() != nil {
			return
		}

		tmpFile, err := os.CreateTemp("", "nuclei-fallback-*.txt")
		if err != nil {
			utils.LogError("[Scanner] [Nuclei] Failed to create temp file: %v", err)
		} else {
			for _, u := range plan.FallbackURLs {
				fmt.Fprintln(tmpFile, u)
			}
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			utils.LogInfo("[Scanner] [Nuclei] Running fallback auto-scan on %d unmapped ports for %s", len(plan.FallbackURLs), targetObj.Value)
			output, err := nm.RunAutoScan(ctx, tmpFile.Name())
			if output != "" {
				recordResult(db, targetObj.ID, "nuclei", fmt.Sprintf("Fallback auto-scan (%d ports)\n%s", len(plan.FallbackURLs), output))
			}
			if err != nil {
				utils.LogDebug("[Scanner] [Nuclei] Fallback scan error for %s: %v", targetObj.Value, err)
			}

			count := sm.parseAndStoreNucleiResults(db, targetObj.ID, output)
			totalFindings += count
		}
	}

	// --- Web Automatic Scan ---
	if len(plan.WebURLs) > 0 {
		if ctx.Err() != nil {
			return
		}

		// Write URLs to temp file
		tmpFile, err := os.CreateTemp("", "nuclei-web-urls-*.txt")
		if err != nil {
			utils.LogError("[Scanner] [Nuclei] Failed to create temp file: %v", err)
		} else {
			for _, u := range plan.WebURLs {
				fmt.Fprintln(tmpFile, u)
			}
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			utils.LogInfo("[Scanner] [Nuclei] Running default web scan on %d URLs for %s", len(plan.WebURLs), targetObj.Value)
			output, err := nm.RunDefaultScan(ctx, tmpFile.Name())
			if output != "" {
				recordResult(db, targetObj.ID, "nuclei", fmt.Sprintf("Web default scan (%d URLs)\n%s", len(plan.WebURLs), output))
			}
			if err != nil {
				utils.LogDebug("[Scanner] [Nuclei] Web scan error for %s: %v", targetObj.Value, err)
			}

			count := sm.parseAndStoreNucleiResults(db, targetObj.ID, output)
			totalFindings += count
		}
	}

	// --- SSL Scans ---
	for _, sslTarget := range plan.SSLTargets {
		if ctx.Err() != nil {
			return
		}

		utils.LogInfo("[Scanner] [Nuclei] Running SSL scan on %s", sslTarget)
		output, err := nm.RunSSLScan(ctx, sslTarget)
		if output != "" {
			recordResult(db, targetObj.ID, "nuclei", fmt.Sprintf("SSL scan %s\n%s", sslTarget, output))
		}
		if err != nil {
			utils.LogDebug("[Scanner] [Nuclei] SSL scan error for %s: %v", sslTarget, err)
		}

		count := sm.parseAndStoreNucleiResults(db, targetObj.ID, output)
		totalFindings += count
	}

	if totalFindings > 0 {
		utils.LogSuccess("[Scanner] [Nuclei] Found %d vulnerabilities for %s", totalFindings, targetObj.Value)
	}
}

// parseAndStoreNucleiResults parses JSONL output from nuclei and stores findings as Vulnerability records.
func (sm *ScanManager) parseAndStoreNucleiResults(db *gorm.DB, targetID uint, output string) int {
	if output == "" {
		return 0
	}

	count := 0
	seen := make(map[string]bool) // Deduplicate by template-id + matched-at

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var result modules.NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		if result.TemplateID == "" {
			continue
		}

		// Deduplicate
		dedupeKey := result.TemplateID + "|" + result.MatchedAt
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		// Build extracted results string
		extracted := ""
		if len(result.ExtractedResults) > 0 {
			extracted = strings.Join(result.ExtractedResults, "\n")
		}

		db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "target_id"}, {Name: "template_id"}, {Name: "matcher_name"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"name", "severity", "description", "extracted",
			}),
		}).Create(&database.Vulnerability{
			TargetID:    targetID,
			Name:        result.Info.Name,
			Severity:    strings.ToLower(result.Info.Severity),
			Description: result.Info.Description,
			MatcherName: result.MatcherName,
			Extracted:   extracted,
			TemplateID:  result.TemplateID,
		})
		count++
	}

	return count
}

// recordResult saves raw tool output to the database with retry on failure

func recordResult(db *gorm.DB, targetID uint, tool, output string) {
	if output == "" {
		return
	}
	result := db.Create(&database.ScanResult{
		TargetID: targetID,
		ToolName: tool,
		Output:   output,
	})
	if result.Error != nil {
		utils.LogError("[Scanner] Failed to record %s result for target %d: %v", tool, targetID, result.Error)
		// Retry once after a brief pause (handles transient SQLite locks)
		time.Sleep(500 * time.Millisecond)
		retryResult := db.Create(&database.ScanResult{
			TargetID: targetID,
			ToolName: tool,
			Output:   output,
		})
		if retryResult.Error != nil {
			utils.LogError("[Scanner] Retry failed for %s result: %v", tool, retryResult.Error)
		}
	}
}
