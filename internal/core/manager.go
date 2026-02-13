package core

import (
	"context"
	"encoding/json"
	"fmt"
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

	// Optional callbacks
	OnStart func(target string)
	OnStop  func(target string, cancelled bool)
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

func (sm *ScanManager) StartScan(targetInput string, assetName string, excludeCF bool) {
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
	sm.mu.Unlock()

	if sm.OnStart != nil {
		sm.OnStart(targetInput)
	}

	// Run in background
	go func() {
		defer func() {
			sm.mu.Lock()
			delete(sm.activeScans, targetInput)
			sm.mu.Unlock()

			if sm.OnStop != nil {
				cancelled := ctx.Err() == context.Canceled
				// Only notify here if NOT cancelled (Natural Finish).
				// If cancelled, StopScan handled the notification immediately.
				if !cancelled {
					sm.OnStop(targetInput, false)
				}
			}
		}()
		sm.runScanLogic(ctx, targetInput, assetName, excludeCF)
	}()
}

func (sm *ScanManager) StopScan(target string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if target == "" {
		// Stop ALL
		for t, info := range sm.activeScans {
			info.Cancel()
			delete(sm.activeScans, t) // Immediate removal
			if sm.OnStop != nil {
				sm.OnStop(t, true) // Immediate notification
			}
			utils.LogInfo("[Manager] Stopping scan for %s", t)
		}
	} else {
		// Stop Specific
		if info, ok := sm.activeScans[target]; ok {
			info.Cancel()
			delete(sm.activeScans, target) // Immediate removal
			if sm.OnStop != nil {
				sm.OnStop(target, true) // Immediate notification
			}
			utils.LogInfo("[Manager] Stopping scan for %s", target)
		}
	}
}

func (sm *ScanManager) StopAssetScan(assetName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	var toStop []string

	for t, info := range sm.activeScans {
		if info.AssetName == assetName {
			toStop = append(toStop, t)
		}
	}

	for _, t := range toStop {
		if info, ok := sm.activeScans[t]; ok {
			info.Cancel()
			delete(sm.activeScans, t)
			if sm.OnStop != nil {
				sm.OnStop(t, true) // Immediate notification
			}
			count++
		}
	}
	utils.LogInfo("[Manager] Stopped %d scans for asset %s", count, assetName)
}

// runScanLogic executes the sequential pipeline
func (sm *ScanManager) runScanLogic(ctx context.Context, targetInput string, assetName string, excludeCF bool) {
	// 1. Initialize & Context Check
	db := database.GetDB()
	if ctx.Err() != nil {
		return
	}

	// 2. Resolve Target & Asset
	parsed := ParseTarget(targetInput)
	utils.LogInfo("[Scanner] Pipeline Start: %s (%s)", parsed.Value, parsed.Type)

	if assetName == "" {
		assetName = "Default"
	}
	var asset database.Asset
	if err := db.Where(database.Asset{Name: assetName}).FirstOrCreate(&asset).Error; err != nil {
		utils.LogError("[Scanner] Error getting asset: %v", err)
	}

	// 3. Pre-Scan Checks (Resolution/CF)
	check := ResolveAndCheck(parsed.Value)
	if !check.IsAlive {
		utils.LogWarning("[Scanner] Target unreachable: %s", parsed.Value)
		// We might still want to scan it if it's a domain that resolves but doesn't ping?
		// For now, adhere to strict check to save resources.
		return
	}
	if check.IsCloudflare && excludeCF {
		utils.LogWarning("[Scanner] Skipping Cloudflare target: %s", parsed.Value)
		return
	}

	// 4. Create/Get Main Target Record
	targetObj := database.Target{
		AssetID:      asset.ID,
		Value:        parsed.Value,
		Type:         string(parsed.Type),
		IsCloudflare: check.IsCloudflare,
		IsAlive:      check.IsAlive,
		Status:       check.Status,
	}
	if err := db.Where(database.Target{Value: parsed.Value, AssetID: asset.ID}).FirstOrCreate(&targetObj).Error; err != nil {
		utils.LogError("Error creating target: %v", err)
		return // Critical failure
	} else {
		db.Model(&targetObj).Update("updated_at", time.Now())
	}

	// === PIPELINE START ===
	utils.LogInfo("[Scanner] Starting Pipeline for %s", parsed.Value)

	// Initialize Multi-line Progress
	// pm := utils.StartProgress() REMOVED
	// defer utils.StopProgress() REMOVED

	// Channel for targets to be scanned (Producer -> Consumer)
	// Buffer slightly to avoid blocking producers on immediate processing
	targetsChan := make(chan database.Target, 100)
	var producerWG sync.WaitGroup

	// Tracking for Progress Bars
	// Removed tracking variables

	// Push the main target to the channel first
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		targetsChan <- targetObj
	}()

	// --- PRODUCERS (Discovery) ---

	// A. Subfinder Producer
	subfinderMod := modules.Get("subfinder")
	if subfinderMod != nil && subfinderMod.CheckInstalled() {
		producerWG.Add(1)
		go func() {
			defer producerWG.Done()
			output, err := subfinderMod.Run(ctx, parsed.Value)
			recordResult(db, targetObj.ID, "subfinder", output)

			if err == nil && output != "" {
				lines := strings.Split(output, "\n")
				// count := 0 (Unused for now)
				for _, line := range lines {
					domain := strings.TrimSpace(line)
					if domain == "" || domain == parsed.Value {
						continue
					}
					// Check simple context cancellation
					if ctx.Err() != nil {
						return
					}

					// Validate & Check Cloudflare
					check := ResolveAndCheck(domain)
					if !check.IsAlive {
						// Skip unreachable subdomains
						continue
					}

					if excludeCF && check.IsCloudflare {
						// Skip Cloudflare subdomains if requested
						continue
					}

					subTarget := database.Target{
						AssetID:      asset.ID,
						ParentID:     &targetObj.ID,
						Value:        domain,
						Type:         "domain",
						Status:       check.Status,
						IsCloudflare: check.IsCloudflare,
						IsAlive:      check.IsAlive,
					}
					// DB FirstOrCreate
					if err := db.Clauses(clause.OnConflict{DoNothing: true}).Where(database.Target{Value: domain, AssetID: asset.ID}).FirstOrCreate(&subTarget).Error; err == nil {
						// Send to scanner
						targetsChan <- subTarget
						// found++ (Removed, user requested no count)
						// pm.UpdateStatus("Subfinder", fmt.Sprintf("Found %d", found)) (Removed)

						// Update Naabu Total (it might not be started yet, but variable is shared)
						// atomic add
						// Actually we can just update the bar if it exists
						// We'll update the variable, Naabu loop will pick it up or we push update?
						// Better: atomic add to total.
						// We need atomic because Subfinder and Uncover run parallel.
					}
				}
				// Atomic add to total targets for Naabu
				// Wait, we need to import sync/atomic or just use mutex.
				// Let's use a local lock for counters if needed, but for now simple addition.
				// Actually, to keep it simple without major race on the int:
				// We can just update the progress bar from here if Naabu is running.
				// Ideally, we add to a shared counter.

				// Simplify: We just update status text for Subfinder. Naabu's *total* updates when it *receives*?
				// No, Naabu consumes from channel. Channel length is unknown.
				// We must track total discovered.
				// Use atomic for thread safety.
				// atomic.AddInt32(&totalTargets, int32(found))

				// pm.Remove("Subfinder") REMOVED
			} else if err != nil {
				// pm.Remove("Subfinder") REMOVED
				utils.LogError("[Scanner] Subfinder failed: %v", err)
			}
		}()
	}

	// B. Uncover Producer
	// utils.LogInfo checks suppressed, just check keys silently or log once
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
				output, err := uncoverMod.Run(ctx, parsed.Value)
				recordResult(db, targetObj.ID, "uncover", output)

				if err == nil && output != "" {
					lines := strings.Split(output, "\n")
					count := 0
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}

						parts := strings.Split(line, ":")
						if len(parts) >= 2 {
							portVal := utils.StringToInt(parts[len(parts)-1])
							db.Clauses(clause.OnConflict{
								Columns:   []clause.Column{{Name: "target_id"}, {Name: "port"}},
								DoNothing: true,
							}).Create(&database.Port{
								TargetID: targetObj.ID,
								Port:     portVal,
								Protocol: "tcp",
								Service:  "unknown",
							})
							count++
						}
					}
					utils.LogSuccess("[Scanner] Uncover found %d results", count)
				}
				// pm.Remove("Uncover") REMOVED
			}()
		}
	}

	// Channel Closer
	go func() {
		producerWG.Wait()
		close(targetsChan)
	}()

	// --- CONSUMER (Worker Pool) ---
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
							if err := json.Unmarshal([]byte(line), &nResult); err == nil {
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
								// Collect for Stage 3
								targetPorts = append(targetPorts, nResult.Port)
							}
						}
						if portsFound > 0 {
							utils.LogSuccess("[Scanner] [Naabu] Found %d open ports on %s", portsFound, t.Value)
						}

						// --- STAGE 3: Nmap Service Enumeration ---
						var nResults []modules.NmapResult
						if len(targetPorts) > 0 {
							nm := modules.Get("nmap")
							// Type assertion to access CustomScan
							if nmapMod, ok := nm.(*modules.Nmap); ok && nmapMod.CheckInstalled() {
								var err error
								var nmapRaw string
								nResults, nmapRaw, err = nmapMod.CustomScan(ctx, t.Value, targetPorts)

								// Record Raw Nmap Output
								if nmapRaw != "" {
									recordResult(db, t.ID, "nmap", nmapRaw)
								}

								if err != nil {
									utils.LogError("[Scanner] Nmap failed for %s: %v", t.Value, err)
								} else {
									utils.LogSuccess("[Scanner] [Nmap] Enriched %d services on %s", len(nResults), t.Value)
									// Save results
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
							var httpUrls []string
							seenPorts := make(map[int]bool)

							addPort := func(port int) {
								if seenPorts[port] {
									return
								}
								seenPorts[port] = true
								proto := "http"
								if port == 443 || port == 8443 {
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
									webResults, err := hx.RunRich(ctx, httpUrls)
									if err != nil {
										utils.LogError("[Scanner] Httpx Stage 4 failed: %v", err)
									} else {
										// Save WebAssets
										count := 0
										for _, w := range webResults {
											// Skip completely empty results if any
											if w.URL == "" {
												continue
											}

											// Run Wappalyzer analysis
											wapp := modules.Get("wappalyzer")
											if wappalyzer, ok := wapp.(*modules.Wappalyzer); ok {

												headers := make(map[string][]string)

												bodyBytes := []byte(w.Response)

												extraTech := wappalyzer.Analyze(headers, bodyBytes)

												// Merge unique
												existing := make(map[string]bool)
												for _, t := range w.Tech {
													existing[t] = true
												}
												for _, t := range extraTech {
													if !existing[t] {
														w.Tech = append(w.Tech, t)
														existing[t] = true
													}
												}

												// Record Wappalyzer "Raw" Log (Synthesized)
												if len(w.Tech) > 0 {
													wappLog := fmt.Sprintf("Target: %s\nDetected Technologies:\n%s", w.URL, strings.Join(w.Tech, ", "))
													recordResult(db, t.ID, "wappalyzer", wappLog)
												}
											}

											// Convert tech stack slice to string
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
										// Run Gowitness, Katana, URLFinder concurrently per URL
										gw := modules.Get("gowitness")
										kat := modules.Get("katana")
										urlF := modules.Get("urlfinder")

										gowitnessMod, gwOk := gw.(*modules.Gowitness)
										katanaMod, katOk := kat.(*modules.Katana)
										urlMod, urlOk := urlF.(*modules.Urlfinder)

										// Cache installation checks to avoid repeated lookups
										gwInstalled := gwOk && gowitnessMod.CheckInstalled()
										katInstalled := katOk && katanaMod.CheckInstalled()
										urlInstalled := urlOk && urlMod.CheckInstalled()

										if gwInstalled || katInstalled {
											utils.LogInfo("[Scanner] Triggering parallel web asset processing for %d URLs on %s", count, t.Value)

											var webWG sync.WaitGroup
											sem := make(chan struct{}, 10) // Limit to 10 concurrent web asset operations

											for _, w := range webResults {
												if w.URL == "" {
													continue
												}

												webWG.Add(1)
												go func(webResult modules.HttpxResult) {
													defer webWG.Done()
													sem <- struct{}{}        // Acquire semaphore
													defer func() { <-sem }() // Release semaphore

													// --- Gowitness Screenshot ---
													if gwInstalled {
														shotPath, gwOut, err := gowitnessMod.RunSingle(ctx, webResult.URL)
														if gwOut != "" {
															recordResult(db, t.ID, "gowitness", gwOut)
														}
														if err != nil {
															utils.LogDebug("[Scanner] Gowitness failed for %s: %v", webResult.URL, err)
														} else {
															if _, err := os.Stat(shotPath); err == nil {
																db.Model(&database.WebAsset{}).
																	Where("target_id = ? AND url = ?", t.ID, webResult.URL).
																	Update("screenshot", shotPath)
															}
														}
													}

													// --- Katana & URLFinder ---
													if katOk && katanaMod.CheckInstalled() {
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
																	parts := strings.SplitN(line, "://", 2)
																	if len(parts) == 2 {
																		pathParts := strings.SplitN(parts[1], "/", 2)
																		if len(pathParts) == 2 {
																			pathVal := "/" + pathParts[1]
																			if !uniquePaths[pathVal] {
																				uniquePaths[pathVal] = true
																				pathsList = append(pathsList, pathVal)
																			}
																		} else {
																			if !uniquePaths["/"] {
																				uniquePaths["/"] = true
																				pathsList = append(pathsList, "/")
																			}
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
														katanaOutput, err := katanaMod.RunCustom(ctx, webResult.URL, args)
														recordResult(db, t.ID, "katana", katanaOutput)
														if err == nil {
															processOutput(katanaOutput)
														}

														// Run URLFinder
														if urlInstalled {
															var hostname string
															if strings.Contains(webResult.URL, "://") {
																parts := strings.Split(webResult.URL, "://")
																if len(parts) > 1 {
																	subParts := strings.Split(parts[1], "/")
																	hostname = subParts[0]
																	if strings.Contains(hostname, ":") {
																		hParts := strings.Split(hostname, ":")
																		hostname = hParts[0]
																	}
																}
															}
															if hostname != "" {
																urlOutput, err := urlMod.Run(ctx, hostname)
																recordResult(db, t.ID, "urlfinder", urlOutput)
																if err == nil {
																	processOutput(urlOutput)
																}
															}
														}

														// Save combined paths
														sort.Strings(pathsList)
														jsonBytes, _ := json.Marshal(pathsList)
														db.Model(&database.WebAsset{}).
															Where("target_id = ? AND url = ?", t.ID, webResult.URL).
															Update("katana_output", string(jsonBytes))
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
				}
			}()
		}
		workerWG.Wait()
	} else {
		utils.LogWarning("[Scanner] Naabu missing, draining pipeline...")
		for range targetsChan {
		}
	}

	utils.LogSuccess("[Scanner] Pipeline Completed for %s", parsed.Value)
}

// runCvemapScan looks up CVEs for each detected product (from Nmap) using vulnx
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
		// TechStack is comma-separated — split into individual technologies
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

		// Record raw output regardless of parse success (for Raw Logs tab)
		if jsonOut != "" {
			recordResult(db, targetObj.ID, "cvemap", fmt.Sprintf("Product: %s\n%s", product, jsonOut))
		}

		if err != nil {
			utils.LogDebug("[Scanner] Cvemap query failed for %s: %v", product, err)
			continue
		}

		// Parse JSON response (single object with results array)
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

func recordResult(db *gorm.DB, targetID uint, tool, output string) {
	db.Create(&database.ScanResult{
		TargetID: targetID,
		ToolName: tool,
		Output:   output,
	})
}
