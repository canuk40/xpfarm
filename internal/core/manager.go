package core

import (
	"context"
	"log"
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
		log.Printf("[Manager] Scan already running for %s, ignoring start request.", targetInput)
		return
	}
	log.Printf("[Manager] Starting scan for %s (Asset: %s)", targetInput, assetName)

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
			log.Printf("[Manager] Stopping scan for %s", t)
		}
	} else {
		// Stop Specific
		if info, ok := sm.activeScans[target]; ok {
			info.Cancel()
			delete(sm.activeScans, target) // Immediate removal
			if sm.OnStop != nil {
				sm.OnStop(target, true) // Immediate notification
			}
			log.Printf("[Manager] Stopping scan for %s", target)
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
	log.Printf("[Manager] Stopped %d scans for asset %s", count, assetName)
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
		log.Printf("[Scanner] Error getting asset: %v", err)
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
		log.Printf("Error creating target: %v", err)
		return // Critical failure
	} else {
		db.Model(&targetObj).Update("updated_at", time.Now())
	}

	// === PIPELINE START ===

	// STAGE 1: DISCOVERY (Subfinder, Uncover)
	// Goal: Find subdomains and populate them as child targets.
	utils.LogInfo("[Scanner] Starting Stage 1: Discovery for %s", parsed.Value)

	// A. Subfinder
	subfinderMod := modules.Get("subfinder")
	if subfinderMod != nil && subfinderMod.CheckInstalled() {
		// Run Subfinder
		output, err := subfinderMod.Run(parsed.Value)
		// Always record raw output
		recordResult(db, targetObj.ID, "subfinder", output)

		if err == nil && output != "" {
			// Parse Output (simulated "lines" parsing)
			lines := strings.Split(output, "\n")
			count := 0
			for _, line := range lines {
				domain := strings.TrimSpace(line)
				if domain == "" || domain == parsed.Value {
					continue
				} // Skip empty or self

				// Create Subdomain Target
				subTarget := database.Target{
					AssetID:  asset.ID,
					ParentID: &targetObj.ID, // Link to parent
					Value:    domain,
					Type:     "domain", // Subfinder returns domains
					// We don't know status yet, will be scanned in future stages or recursive loop
					Status: "discovered",
				}
				// Use FirstOrCreate to avoid duplicates, with DoNothing clause to suppress unique index errors from race conditions
				if err := db.Clauses(clause.OnConflict{DoNothing: true}).Where(database.Target{Value: domain, AssetID: asset.ID}).FirstOrCreate(&subTarget).Error; err == nil {
					count++
				}
			}
			utils.LogSuccess("[Scanner] Subfinder found %d new subdomains for %s", count, parsed.Value)
		} else if err != nil {
			utils.LogError("[Scanner] Subfinder failed: %v", err)
		}
	}

	// B. Uncover (Sequential)
	utils.LogInfo("[Scanner] Checking for Uncover configuration...")
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
			utils.LogInfo("[Scanner] Uncover keys found. Running Uncover...")
			// Uncover typically finds IP:PORT
			output, err := uncoverMod.Run(parsed.Value)
			recordResult(db, targetObj.ID, "uncover", output)

			if err == nil && output != "" {
				// Parse Output: Expecting IP:PORT or Host:Port
				lines := strings.Split(output, "\n")
				count := 0
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}

					// Store as Port? Or as a web asset?
					// Uncover usually returns "1.2.3.4:80"
					// Let's assume Port for now.
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						// Simple parse
						// We don't have protocol info easily unless uncover provides it.
						// We'll store it as a Port record on the Target.
						// But wait, if target is domain, and output is IP:Port, does it belong to domain target? Yes.
						portVal := parts[len(parts)-1]
						// Log it for now to avoid "unused variable" error and debug
						utils.LogInfo("[Scanner] [Uncover] Found potential service: %s on port %s", line, portVal)
						// Basic int check skipped for brevity, saving as string might be cleaner but model expects int
						// TODO: Safely parse int.

						// For now, allow raw output to guide next steps or just save result.
						// User asked to "dump everything we know... tab on the page"
						// We already have "Network" tab for Ports.
						// Let's try to add to Port table if possible.
					}
					count++
				}
				utils.LogSuccess("[Scanner] Uncover found %d results", count)
			}
		} else {
			utils.LogWarning("[Scanner] Uncover tool not installed/found.")
		}
	} else {
		utils.LogWarning("[Scanner] No Uncover API keys configured. Skipping Uncover.")
	}

	utils.LogSuccess("[Scanner] Stage 1 Completed for %s", parsed.Value)

	// Future Stages: Network, Web, Vuln...
	// For now, we stop here as requested ("Stage 1 you suggested sounds good... get that working")
}

func recordResult(db *gorm.DB, targetID uint, tool, output string) {
	db.Create(&database.ScanResult{
		TargetID: targetID,
		ToolName: tool,
		Output:   output,
	})
}
