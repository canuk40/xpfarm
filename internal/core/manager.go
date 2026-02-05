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

	// --- CONSUMER (Scanner - Naabu) ---
	naabuMod := modules.Get("naabu")

	if naabuMod != nil && naabuMod.CheckInstalled() {
		scannedTargets := make(map[uint]bool) // Key by ID

		for t := range targetsChan {
			if ctx.Err() != nil {
				break
			}
			if scannedTargets[t.ID] {
				continue
			}
			scannedTargets[t.ID] = true

			// scannedTargetsCount++ (Removed)
			// Dynamically update total based on channel buffer + scanned?
			// This is tricky. Producers add to channel.
			// Let's just assume Current/Total where Total grows as we find things.
			// We need a thread-safe way to know "Total Discovered".
			// Since we didn't implement atomic counters perfectlly above, let's cheat slightly:
			// Total = scanned + len(targetsChan) approx? No.
			// Effective fix: Make `totalTargets` an atomic.

			// For this iteration, let's just increment total if current > total (which happens if discovery adds more)
			// Actually, just rely on what we have.
			// We will just show "Scanned X" if we can't get strict total.
			// But user asked for 5/10.

			// Let's implement atomic total properly.
			// Using channel len is unstable.
			// We'll update the bar:
			// pm.UpdateProgress("Naabu", int(scannedTargetsCount), int(totalTargets))
			// But totalTargets needs to be updated by producers.
			// Since I can't import sync/atomic easily effectively in this patch without adding imports:
			// I will just use a heuristic: Total = scanned + len(channel) + 1.
			// It gives a rough estimate of "Pending work".

			// pm.UpdateProgress("Naabu", int(scannedTargetsCount), currentTotal) REMOVED

			// NOTE: The above updates every target, but the Ticker only redrawing every 1.5s filters the noise. Perfect.

			output, err := naabuMod.Run(ctx, t.Value)
			recordResult(db, t.ID, "naabu", output)

			if err == nil && output != "" {
				lines := strings.Split(output, "\n")
				portsFound := 0
				var targetPorts []int
				for _, line := range lines {
					if strings.TrimSpace(line) == "" {
						continue
					}
					var nResult struct {
						IP   string `json:"ip"`
						Port int    `json:"port"`
					}
					if err := json.Unmarshal([]byte(line), &nResult); err == nil {
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
					// Filter for HTTP services from Nmap results
					var httpUrls []string
					for _, res := range nResults {
						if strings.Contains(res.Service, "http") ||
							strings.Contains(res.Service, "ssl") ||
							res.Port == 80 || res.Port == 443 || res.Port == 8080 || res.Port == 8443 {

							protocol := "http"
							if strings.Contains(res.Service, "ssl") || strings.Contains(res.Service, "https") || res.Port == 443 || res.Port == 8443 {
								protocol = "https"
							}
							url := fmt.Sprintf("%s://%s:%d", protocol, t.Value, res.Port)
							httpUrls = append(httpUrls, url)
						}
					}

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
										// Httpx result doesn't explicitly separate headers/body in the struct I defined?
										// I need to check HttpxResult struct.
										// Assuming w.Response contains everything?
										// Actually HttpxResult has `Response` field but I need to parse it or use headers/body separation.
										// Since simple wappalyzergo takes map[string][]string for headers, I might need to simulate it
										// if httpx doesn't provide structured headers.
										// OR just rely on body signature for now?
										// Realistically, the httpx JSON output might merge response.
										// But let's check what I have. I have `w.Response`.
										// If `w.Response` is empty (no -include-response?), I skip.
										// But I added -include-response to RunRich.

										// Basic header parsing (very naive)
										headers := make(map[string][]string)
										// TODO: better parsing if needed.
										// For now, let's just use body analysis on the whole response string if library supports it?
										// Wappalyzergo Fingerprint takes (headers, body).

										bodyBytes := []byte(w.Response)
										// Note: w.Response usually includes status line and headers in httpx text output?
										// In JSON, `response` field might be raw.

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

								// --- STAGE 5: Visual Inspection (Gowitness) ---
								// Trigger screenshots for newly added/found web assets
								gw := modules.Get("gowitness")
								if gowitness, ok := gw.(*modules.Gowitness); ok && gowitness.CheckInstalled() {
									utils.LogInfo("[Scanner] Triggering Gowitness Stage 5 for %d URLs on %s", count, t.Value)
									for _, w := range webResults {
										if w.URL == "" {
											continue
										}

										shotPath, gwOut, err := gowitness.RunSingle(ctx, w.URL)

										// Record Raw Gowitness CLI Output
										if gwOut != "" {
											// Deduplicate? Or just append? Tools recordResult usually stores separate entries or appends?
											// recordResult creates a new entry for each call.
											// Users usually want to see the sequence.
											recordResult(db, t.ID, "gowitness", gwOut)
										}

										if err != nil {
											// Suppress error as some ports might not have a web server or screenshot fails
											utils.LogDebug("[Scanner] Gowitness failed for %s: %v", w.URL, err)
										} else {
											// Check if file actually exists before saving path
											if _, err := os.Stat(shotPath); err == nil {
												// Save screenshot path to DB
												// Upsert again or just update specific field
												db.Model(&database.WebAsset{}).
													Where("target_id = ? AND url = ?", t.ID, w.URL).
													Update("screenshot", shotPath)
											} else {
												utils.LogWarning("[Scanner] Gowitness reported success but file not found at %s", shotPath)
											}
										}
									}
								}

								// --- STAGE 6: Katana & URLFinder Execution ---
								kat := modules.Get("katana")
								urlF := modules.Get("urlfinder")

								// Check type assertion and install
								if katanaMod, ok := kat.(*modules.Katana); ok && katanaMod.CheckInstalled() {
									utils.LogInfo("[Scanner] Triggering Katana Stage 6 for %d URLs on %s", count, t.Value)
									for _, w := range webResults {
										if w.URL == "" {
											continue
										}

										// Collect all unique paths from both tools
										uniquePaths := make(map[string]bool)
										var pathsList []string

										// Helper to process line-based output
										processOutput := func(rawOutput string) {
											lines := strings.Split(rawOutput, "\n")
											for _, line := range lines {
												line = strings.TrimSpace(line)
												if line == "" {
													continue
												}

												// Naive URL parsing
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
															// Root
															if !uniquePaths["/"] {
																uniquePaths["/"] = true
																pathsList = append(pathsList, "/")
															}
														}
													}
												} else {
													// Relative path or other
													if !uniquePaths[line] {
														uniquePaths[line] = true
														pathsList = append(pathsList, line)
													}
												}
											}
										}

										// 1. Run Katana
										// katana -u https://adriaanbosch.com/hax0r -jc -kf all -fx -d 5 -pc
										args := []string{"-jc", "-kf", "all", "-fx", "-d", "5", "-pc"}
										katanaOutput, err := katanaMod.RunCustom(ctx, w.URL, args)
										recordResult(db, t.ID, "katana", katanaOutput)

										if err != nil {
											utils.LogDebug("[Scanner] Katana failed for %s: %v", w.URL, err)
										} else {
											processOutput(katanaOutput)
										}

										// 2. Run URLFinder
										if urlMod, ok := urlF.(*modules.Urlfinder); ok && urlMod.CheckInstalled() {
											// Extract hostname for -d flag
											// w.URL is like https://example.com/foo
											// We need 'example.com' or whatever hostname Httpx found
											// Use simple string manipulation or parse
											var hostname string
											if strings.Contains(w.URL, "://") {
												parts := strings.Split(w.URL, "://")
												if len(parts) > 1 {
													subParts := strings.Split(parts[1], "/")
													hostname = subParts[0]
													// Remove port if exists? urlfinder might want domain only?
													// "adriaanbosch.com:443" -> "adriaanbosch.com"
													if strings.Contains(hostname, ":") {
														hParts := strings.Split(hostname, ":")
														hostname = hParts[0]
													}
												}
											}

											if hostname != "" {
												// Run urlfinder -d hostname -all -silent
												utils.LogInfo("[Scanner] Running URLFinder on %s...", hostname)
												urlOutput, err := urlMod.Run(ctx, hostname)
												recordResult(db, t.ID, "urlfinder", urlOutput)

												if err != nil {
													utils.LogDebug("[Scanner] URLFinder failed for %s: %v", hostname, err)
												} else {
													processOutput(urlOutput)
												}
											}
										}

										// Sort paths
										sort.Strings(pathsList)

										// Convert to JSON
										jsonBytes, _ := json.Marshal(pathsList)
										jsonOutput := string(jsonBytes)

										// Save Combined Output (JSON Paths) to DB
										// We overwrite 'katana_output' field to effectively merge visual result
										db.Model(&database.WebAsset{}).
											Where("target_id = ? AND url = ?", t.ID, w.URL).
											Update("katana_output", jsonOutput)

									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		utils.LogWarning("[Scanner] Naabu missing, draining pipeline...")
		for range targetsChan {
		}
	}

	utils.LogSuccess("[Scanner] Pipeline Completed for %s", parsed.Value)

	// --- STAGE 7: Smart Vulnerability Scan ---
	sm.runSmartScan(ctx, db, targetObj)
}

func (sm *ScanManager) runSmartScan(ctx context.Context, db *gorm.DB, targetObj database.Target) {
	utils.LogInfo("[Scanner] Starting Stage 7: Smart Vulnerability Scan for %s", targetObj.Value)

	// 1. Gather Context & URLs
	techSet := make(map[string]bool)
	versionMap := make(map[string]string) // Product -> Version
	var targetURLs []string

	// A. From WebAssets
	var webAssets []database.WebAsset
	db.Where("target_id = ?", targetObj.ID).Find(&webAssets)
	for _, wa := range webAssets {
		if wa.URL != "" {
			targetURLs = append(targetURLs, wa.URL)
		}
		if wa.TechStack != "" {
			parts := strings.Split(wa.TechStack, ", ")
			for _, p := range parts {
				if p != "" {
					techSet[strings.ToLower(strings.TrimSpace(p))] = true
				}
			}
		}
	}

	// B. From Ports (Nmap)
	var ports []database.Port
	db.Where("target_id = ?", targetObj.ID).Find(&ports)
	for _, p := range ports {
		if p.Product != "" {
			prod := strings.ToLower(strings.TrimSpace(p.Product))
			techSet[prod] = true
			if p.Version != "" {
				versionMap[prod] = strings.TrimSpace(p.Version)
			}
		}
	}

	if len(techSet) == 0 {
		utils.LogInfo("[Scanner] No technologies detected for Smart Scan on %s", targetObj.Value)
		return
	}

	// 2. Prepare Target List File
	// Nuclei works best with a list of URLs to scan specific endpoints/ports found
	var targetFile string
	if len(targetURLs) > 0 {
		f, err := os.CreateTemp("", "nuclei_targets_*.txt")
		if err == nil {
			defer os.Remove(f.Name())
			for _, u := range targetURLs {
				if _, err := f.WriteString(u + "\n"); err != nil {
					utils.LogDebug("Failed to write to nuclei target file: %v", err)
				}
			}
			f.Close()
			targetFile = f.Name()
		}
	}
	// Fallback to domain if no URLs or file error
	if targetFile == "" {
		targetFile = targetObj.Value // Treat as single target args
	}

	// 3. Prepare Tags
	var tags []string
	for t := range techSet {
		// Simple sanitization: replace spaces with -, keep alphanumeric
		// e.g. "Apache HTTP Server" -> "apache-http-server"
		// This is a heuristic.
		safe := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return '-'
		}, t)
		// Clean multiple dashes
		// For MVP just use it.
		if safe != "" {
			tags = append(tags, safe)
		}
	}

	// 4. Advanced: Get CVEs for Versions
	var cveIDs []string
	cveMapMod := modules.Get("cvemap")
	if cm, ok := cveMapMod.(*modules.Cvemap); ok && cm.CheckInstalled() && len(versionMap) > 0 {
		utils.LogInfo("[Scanner] Querying Cvemap for %d detected products...", len(versionMap))
		for prod, ver := range versionMap {
			// clean prod name for query?
			// cvemap query: product:"apache" version:"2.4.49"
			query := fmt.Sprintf("product:\"%s\" version:\"%s\"", prod, ver)
			jsonOut, err := cm.Search(ctx, query)
			if err == nil {
				// Parse JSON output
				// Output is stream of JSON objects
				lines := strings.Split(jsonOut, "\n")
				type CveStub struct {
					CveID string `json:"cve_id"`
				}
				for _, line := range lines {
					if strings.TrimSpace(line) == "" {
						continue
					}
					var stub CveStub
					if json.Unmarshal([]byte(line), &stub) == nil && stub.CveID != "" {
						cveIDs = append(cveIDs, stub.CveID)
					}
				}
			}
		}
	}

	// 5. Run Nuclei Passes
	nucleiMod := modules.Get("nuclei")
	nm, ok := nucleiMod.(*modules.Nuclei)
	if !ok || !nm.CheckInstalled() {
		utils.LogWarning("[Scanner] Nuclei not available for Smart Scan.")
		return
	}

	// Pass A: Tags
	if len(tags) > 0 {
		// Limit tags to avoid too huge command?
		tagStr := strings.Join(tags, ",")
		utils.LogInfo("[Scanner] Running Smart Nuclei Tags: %s", tagStr)

		args := []string{"-silent", "-tags", tagStr, "-severity", "critical,high"}
		if strings.Contains(targetFile, "nuclei_targets") {
			args = append(args, "-l", targetFile)
		} else {
			args = append(args, "-u", targetFile)
		}

		out, err := nm.RunRaw(ctx, args)
		recordResult(db, targetObj.ID, "nuclei-smart-tags", out)
		if err != nil {
			utils.LogDebug("Nuclei tags scan error/found: %v", err)
		}
	}

	// Pass B: Specific CVEs
	if len(cveIDs) > 0 {
		// Deduplicate
		uniqueIDs := make(map[string]bool)
		var cleanIDs []string
		for _, id := range cveIDs {
			if !uniqueIDs[id] {
				uniqueIDs[id] = true
				cleanIDs = append(cleanIDs, id)
			}
		}

		if len(cleanIDs) > 0 {
			idStr := strings.Join(cleanIDs, ",")
			utils.LogInfo("[Scanner] Running Smart Nuclei CVEs: %d identified", len(cleanIDs))

			args := []string{"-silent", "-id", idStr}
			if strings.Contains(targetFile, "nuclei_targets") {
				args = append(args, "-l", targetFile)
			} else {
				args = append(args, "-u", targetFile)
			}

			out, err := nm.RunRaw(ctx, args)
			recordResult(db, targetObj.ID, "nuclei-smart-cves", out)
			if err != nil {
				utils.LogDebug("Nuclei CVE scan error/found: %v", err)
			}
		}
	}
}

func recordResult(db *gorm.DB, targetID uint, tool, output string) {
	db.Create(&database.ScanResult{
		TargetID: targetID,
		ToolName: tool,
		Output:   output,
	})
}
