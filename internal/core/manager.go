package core

import (
	"context"
	"encoding/json"
	"os"
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

					subTarget := database.Target{
						AssetID:  asset.ID,
						ParentID: &targetObj.ID,
						Value:    domain,
						Type:     "domain",
						Status:   "discovered",
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
							var portObj database.Port
							db.Where(database.Port{TargetID: targetObj.ID, Port: portVal}).FirstOrCreate(&portObj, database.Port{
								TargetID: targetObj.ID,
								Port:     portVal,
								Protocol: "tcp", // inference
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
	} else {
		// utils.LogInfo("[Scanner] No Uncover keys, skipping.")
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
						var portObj database.Port
						db.Where(database.Port{TargetID: t.ID, Port: nResult.Port}).FirstOrCreate(&portObj, database.Port{
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
				if len(targetPorts) > 0 {
					nm := modules.Get("nmap")
					// Type assertion to access CustomScan
					if nmapMod, ok := nm.(*modules.Nmap); ok && nmapMod.CheckInstalled() {
						nResults, err := nmapMod.CustomScan(ctx, t.Value, targetPorts)
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
				}
			}
		}
	} else {
		utils.LogWarning("[Scanner] Naabu missing, draining pipeline...")
		for range targetsChan {
		}
	}

	utils.LogSuccess("[Scanner] Pipeline Completed for %s", parsed.Value)
}

func recordResult(db *gorm.DB, targetID uint, tool, output string) {
	db.Create(&database.ScanResult{
		TargetID: targetID,
		ToolName: tool,
		Output:   output,
	})
}
