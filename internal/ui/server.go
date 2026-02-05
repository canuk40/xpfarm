package ui

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"xpfarm/internal/core"
	"xpfarm/internal/database"
	"xpfarm/internal/modules"
	"xpfarm/internal/notifications/discord"
	"xpfarm/internal/notifications/telegram"
	"xpfarm/pkg/utils"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

//go:embed templates/* static/*
var f embed.FS

func StartServer(port string) error {
	// Check for debug mode code
	isDebug := false
	for _, arg := range os.Args {
		if arg == "-debug" {
			isDebug = true
			break
		}
	}
	if os.Getenv("DEBUG") != "" {
		isDebug = true
	}

	if !isDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Use gin.New() to skip Default Logger output
	r := gin.New()
	r.Use(gin.Recovery())
	if isDebug {
		r.Use(gin.Logger())
	}

	// Serve embedded favicon
	r.GET("/favicon.ico", func(c *gin.Context) {
		data, err := f.ReadFile("static/favicon.ico")
		if err != nil {
			// Try serving from generic static mapping if exists, else 404
			c.Status(404)
			return
		}
		c.Data(200, "image/x-icon", data)
	})

	// Serve screenshots directory
	if err := os.MkdirAll("screenshots", 0755); err != nil {
		utils.LogError("Failed to create screenshots dir: %v", err)
	}
	r.Static("/screenshots", "./screenshots")

	// Custom template renderer to handle layout + page isolation
	render := MultiRender{templates: make(map[string]*template.Template)}

	// Load templates
	layoutContent, err := f.ReadFile("templates/layout.html")
	if err != nil {
		return err
	}

	pages := []string{"dashboard.html", "assets.html", "asset_details.html", "target_details.html", "modules.html", "settings.html", "target.html", "overlord.html"}

	for _, page := range pages {
		pageContent, err := f.ReadFile("templates/" + page)
		if err != nil {
			return err
		}

		// Create a new template for this page
		// We parse layout first, then the page content
		// The page content defines "content", which layout calls
		tmpl := template.New(page).Funcs(template.FuncMap{
			"sub": func(a, b int) int { return a - b },
			"json": func(v interface{}) template.JS {
				a, _ := json.Marshal(v)
				return template.JS(a)
			},
		})

		// Parse layout
		if _, err := tmpl.New("layout.html").Parse(string(layoutContent)); err != nil {
			return err
		}

		// Parse page
		if _, err := tmpl.Parse(string(pageContent)); err != nil {
			return err
		}

		render.templates[page] = tmpl
	}
	r.HTMLRender = render

	r.HTMLRender = render

	var discordToken, discordChannel string
	var telegramToken, telegramChatID string
	db := database.GetDB()
	var settings []database.Setting
	db.Find(&settings)
	for _, s := range settings {
		if s.Key == "DISCORD_TOKEN" {
			discordToken = s.Value
		}
		if s.Key == "DISCORD_CHANNEL_ID" {
			discordChannel = s.Value
		}
		if s.Key == "TELEGRAM_TOKEN" {
			telegramToken = s.Value
		}
		if s.Key == "TELEGRAM_CHAT_ID" {
			telegramChatID = s.Value
		}
	}

	// Notification Clients
	var discordClient *discord.Client
	var telegramClient *telegram.Client
	manager := core.GetManager()

	// Init Discord
	if discordToken != "" {
		dc, err := discord.NewClient(discordToken, discordChannel, manager)
		if err == nil {
			if err := dc.Start(); err == nil {
				discordClient = dc
			} else {
				os.Stderr.WriteString("Failed to start Discord bot: " + err.Error() + "\n")
			}
		} else {
			os.Stderr.WriteString("Failed to create Discord client: " + err.Error() + "\n")
		}
	}

	// Init Telegram
	if telegramToken != "" && telegramChatID != "" {
		telegramClient = telegram.NewClient(telegramToken, telegramChatID)
	}

	// Hook up callbacks (Broadcast)
	manager.OnStart = func(target string) {
		if discordClient != nil {
			discordClient.SendNotification("🚀 Scan Started", "Started scanning target: **"+target+"**", 0x34d399)
		}
		if telegramClient != nil {
			if err := telegramClient.SendNotification(fmt.Sprintf("*🚀 Scan Started*\nStarted scanning target: `%s`", target)); err != nil {
				utils.LogError("Telegram notification failed: %v", err)
			}
		}
	}
	manager.OnStop = func(target string, cancelled bool) {
		if discordClient != nil {
			discordClient.SendNotification("🏁 Scan Ended", "Scanning finished or stopped for: **"+target+"**", 0x8b5cf6)
		}
		if telegramClient != nil {
			if err := telegramClient.SendNotification(fmt.Sprintf("*🏁 Scan Ended*\nScanning finished or stopped for: `%s`", target)); err != nil {
				utils.LogError("Telegram notification failed: %v", err)
			}
		}
	}

	// --- Helper for Sidebar Data ---
	getGlobalContext := func(data gin.H) gin.H {
		var assets []database.Asset
		// Preload Targets for sidebar dropdowns
		database.GetDB().Preload("Targets").Find(&assets)

		data["SidebarAssets"] = assets
		return data
	}

	// --- Routes ---

	// Dashboard
	r.GET("/", func(c *gin.Context) {
		var assetsCount int64
		var targetsCount int64
		var resultsCount int64
		var recentResults []database.ScanResult

		db := database.GetDB()
		db.Model(&database.Asset{}).Count(&assetsCount)
		db.Model(&database.Target{}).Count(&targetsCount)
		db.Model(&database.ScanResult{}).Count(&resultsCount)

		var portsCount int64
		db.Model(&database.Port{}).Count(&portsCount)

		// Tech Stack Count (Unique technologies)
		var techStacks []string
		db.Model(&database.WebAsset{}).Pluck("tech_stack", &techStacks)
		uniqueTech := make(map[string]bool)
		for _, stack := range techStacks {
			if stack == "" {
				continue
			}
			techs := strings.Split(stack, ", ")
			for _, t := range techs {
				if t != "" {
					uniqueTech[t] = true
				}
			}
		}
		techCount := len(uniqueTech)

		// Tools Count (Installed/Available)
		toolsCount := len(modules.GetAll())

		// Chart Data: Results per Tool
		type ToolStat struct {
			ToolName string
			Count    int64
		}
		var toolStats []ToolStat
		db.Model(&database.ScanResult{}).Select("tool_name, count(*) as count").Group("tool_name").Scan(&toolStats)

		// Chart Data: Targets per Asset
		type AssetStat struct {
			ID    uint
			Name  string
			Count int
		}
		var assetStats []AssetStat
		var allAssets []database.Asset
		db.Preload("Targets").Find(&allAssets)
		for _, a := range allAssets {
			assetStats = append(assetStats, AssetStat{ID: a.ID, Name: a.Name, Count: len(a.Targets)})
		}

		// Chart: Tech Stack Distribution (Top 10)
		type LabelCount struct {
			Label string
			Count int
		}
		techMap := make(map[string]int)
		for _, stack := range techStacks {
			if stack == "" {
				continue
			}
			parts := strings.Split(stack, ", ")
			for _, p := range parts {
				if p != "" {
					techMap[p]++
				}
			}
		}
		var techChart []LabelCount
		for k, v := range techMap {
			techChart = append(techChart, LabelCount{Label: k, Count: v})
		}
		// Sort by count desc
		// Sort by count desc
		sort.Slice(techChart, func(i, j int) bool {
			return techChart[i].Count > techChart[j].Count
		})
		if len(techChart) > 10 {
			techChart = techChart[:10]
		}

		// Chart: Web Server Distribution
		var webServerStats []LabelCount
		db.Model(&database.WebAsset{}).
			Select("web_server as label, count(*) as count").
			Where("web_server != ''").
			Group("web_server").
			Order("count desc").
			Limit(10).
			Scan(&webServerStats)

		// Chart: Port Distribution (Top 10)
		var portStats []LabelCount
		db.Model(&database.Port{}).
			Select("port as label, count(*) as count").
			Group("port").
			Order("count desc").
			Limit(10).
			Scan(&portStats)

		// Chart: Top Services
		var serviceStats []LabelCount
		db.Model(&database.Port{}).
			Select("service as label, count(*) as count").
			Where("service != ''").
			Group("service").
			Order("count desc").
			Limit(10).
			Scan(&serviceStats)

		c.HTML(http.StatusOK, "dashboard.html", getGlobalContext(gin.H{
			"Page": "dashboard",
			"Stats": gin.H{
				"Assets":  assetsCount,
				"Targets": targetsCount,
				"Results": resultsCount,
				"Ports":   portsCount,
				"Tech":    techCount,
				"Tools":   toolsCount,
			},
			"RecentResults": recentResults,
			"ChartData": gin.H{
				"Tools":      toolStats,
				"Assets":     assetStats,
				"Tech":       techChart,
				"WebServers": webServerStats,
				"Ports":      portStats,
				"Services":   serviceStats,
			},
		}))
	})

	// Overlord
	r.GET("/overlord", func(c *gin.Context) {
		c.HTML(http.StatusOK, "overlord.html", getGlobalContext(gin.H{
			"Page": "overlord",
		}))
	})

	// Assets
	r.GET("/assets", func(c *gin.Context) {
		// We already fetch assets in getGlobalContext, but the page specific logic
		// might need it too. It's redundant but safe (gorm caches slightly or just lightweight sqlite).
		// actually, we can just reuse the one from global context if we structured it differently,
		// but standard pattern is clean separation.
		var assets []database.Asset
		database.GetDB().Preload("Targets").Find(&assets)

		c.HTML(http.StatusOK, "assets.html", getGlobalContext(gin.H{
			"Page":   "assets",
			"Assets": assets,
		}))
	})

	r.POST("/assets/create", func(c *gin.Context) {
		name := c.PostForm("name")
		if name != "" {
			database.GetDB().Create(&database.Asset{Name: name})
		}
		c.Redirect(http.StatusFound, "/assets")
	})

	r.POST("/assets/delete", func(c *gin.Context) {
		id := c.PostForm("id")
		if id != "" {
			db := database.GetDB()
			// Manually cascade delete targets
			// 1. Get Target IDs
			var targets []database.Target
			db.Select("id").Where("asset_id = ?", id).Find(&targets)
			var targetIDs []uint
			for _, t := range targets {
				targetIDs = append(targetIDs, t.ID)
			}

			if len(targetIDs) > 0 {
				// 2. Delete Related Data for these targets
				db.Unscoped().Where("target_id IN ?", targetIDs).Delete(&database.ScanResult{})
				db.Unscoped().Where("target_id IN ?", targetIDs).Delete(&database.Port{})
				db.Unscoped().Where("target_id IN ?", targetIDs).Delete(&database.WebAsset{})
				db.Unscoped().Where("target_id IN ?", targetIDs).Delete(&database.Vulnerability{})
				// 3. Delete Targets
				db.Unscoped().Delete(&database.Target{}, targetIDs)
			}
			// 4. Delete Asset
			db.Unscoped().Delete(&database.Asset{}, id)
		}
		c.Redirect(http.StatusFound, "/assets")
	})

	r.POST("/asset/:id/scan", func(c *gin.Context) {
		id := c.Param("id")
		excludeCF := c.PostForm("exclude_cf") == "on"

		var asset database.Asset
		if err := database.GetDB().Preload("Targets").First(&asset, id).Error; err == nil {
			// Trigger scans for all targets
			for _, t := range asset.Targets {
				val := t.Value
				// Run in goroutine to not block
				go core.RunScan(val, asset.Name, excludeCF)
			}
		}
		c.Redirect(http.StatusFound, "/asset/"+id)
	})

	r.POST("/asset/:id/import", func(c *gin.Context) {
		assetID := c.Param("id")
		rawText := c.PostForm("raw_text")

		targets := []string{}

		// 1. Process Raw Text (Newline separated)
		if rawText != "" {
			lines := strings.Split(rawText, "\n")
			for _, line := range lines {
				clean := strings.TrimSpace(line)
				if clean != "" {
					targets = append(targets, clean)
				}
			}
		}

		// 2. Process File Upload
		file, err := c.FormFile("file")
		if err == nil {
			f, err := file.Open()
			if err == nil {
				defer f.Close()
				content, _ := io.ReadAll(f)
				filename := strings.ToLower(file.Filename)
				strContent := string(content)

				if strings.HasSuffix(filename, ".csv") {
					r := csv.NewReader(strings.NewReader(strContent))
					records, _ := r.ReadAll()
					targetCol := -1
					if len(records) > 0 {
						header := records[0]
						for i, h := range header {
							h = strings.ToLower(strings.TrimSpace(h))
							if h == "target" || h == "targets" {
								targetCol = i
								break
							}
						}
					}
					if targetCol != -1 && len(records) > 1 {
						for _, row := range records[1:] {
							if len(row) > targetCol {
								targets = append(targets, strings.TrimSpace(row[targetCol]))
							}
						}
					} else {
						lines := strings.Split(strContent, "\n")
						for _, line := range lines {
							targets = append(targets, strings.TrimSpace(line))
						}
					}
				} else {
					lines := strings.Split(strContent, "\n")
					for _, line := range lines {
						targets = append(targets, strings.TrimSpace(line))
					}
				}
			}
		}

		db := database.GetDB()
		var asset database.Asset
		if err := db.Preload("Targets").First(&asset, assetID).Error; err != nil {
			c.Redirect(http.StatusFound, "/assets")
			return
		}

		// Report Structs
		type ImportStatus struct {
			Target string
			Status string
			Detail string
		}
		var report []ImportStatus

		for _, tVal := range targets {
			if tVal == "" {
				continue
			}

			// Basic Validation
			// Advanced Validation & Check
			check := core.ResolveAndCheck(tVal) // Performs DNS + CF Check

			if check.Status == "unreachable" && !strings.Contains(tVal, "/") { // specific check for domains failing DNS
				report = append(report, ImportStatus{Target: tVal, Status: "error", Detail: "Unreachable / DNS Fail"})
				continue
			}

			// Global Duplicate Check
			var existing database.Target
			// Use Find() to check existence
			if db.Where("value = ?", tVal).Limit(1).Find(&existing).RowsAffected > 0 {
				// Found existing target. Check if its Asset still exists.
				var existingAsset database.Asset
				if err := db.Find(&existingAsset, existing.AssetID).Error; err != nil || existingAsset.ID == 0 {
					// Async/Orphaned Target case (Asset was hard deleted but Target wasn't?)
					// Or just broken reference. Use Unscoped to be sure we find it if it exists.
					// Actually, if we are here, it means Target exists. If Asset lookup fails, it's an orphan.

					// We'll treat orphans as non-existent (delete them and allow import)
					db.Unscoped().Delete(&existing)
				} else {
					// Asset exists, so it is a true duplicate
					report = append(report, ImportStatus{Target: tVal, Status: "warning", Detail: "Duplicate found in group: " + existingAsset.Name})
					continue
				}
			}

			// Add New
			// Use the original value (tVal) but store intelligence
			newTarget := database.Target{
				AssetID:      asset.ID,
				Value:        tVal, // Keep input value (domain)
				Type:         string(core.ParseTarget(tVal).Type),
				IsCloudflare: check.IsCloudflare,
				IsAlive:      check.IsAlive,
				Status:       check.Status,
			}
			db.Create(&newTarget)
			status := "success"
			detail := "Added successfully"
			if check.IsCloudflare {
				detail += " (Cloudflare)"
			}
			report = append(report, ImportStatus{Target: tVal, Status: status, Detail: detail})
		}

		// Reload asset to show new targets
		db.Preload("Targets").First(&asset, assetID)

		// Render page with report
		c.HTML(http.StatusOK, "asset_details.html", getGlobalContext(gin.H{
			"Page":         "assets",
			"Asset":        asset,
			"ImportReport": report,
		}))
	})

	r.POST("/asset/:id/refresh", func(c *gin.Context) {
		id := c.Param("id")
		db := database.GetDB()
		var asset database.Asset
		if err := db.Preload("Targets").First(&asset, id).Error; err == nil {
			for _, t := range asset.Targets {
				// Re-check
				check := core.ResolveAndCheck(t.Value)
				db.Model(&t).Updates(map[string]interface{}{
					"is_cloudflare": check.IsCloudflare,
					"is_alive":      check.IsAlive,
					"status":        check.Status,
					"updated_at":    time.Now(),
				})
			}
		}
		c.Redirect(http.StatusFound, "/asset/"+id)
	})

	r.GET("/asset/:id", func(c *gin.Context) {
		id := c.Param("id")
		var asset database.Asset
		// Use Find to avoid GORM "record not found" error log
		database.GetDB().Preload("Targets").Find(&asset, id)
		if asset.ID == 0 {
			c.Redirect(http.StatusFound, "/assets")
			return
		}
		c.HTML(http.StatusOK, "asset_details.html", getGlobalContext(gin.H{
			"Page":  "assets",
			"Asset": asset,
		}))
	})

	// Modules
	r.GET("/modules", func(c *gin.Context) {
		allMods := modules.GetAll()
		type ModStatus struct {
			Name      string
			Installed bool
		}
		var statusList []ModStatus
		for _, m := range allMods {
			statusList = append(statusList, ModStatus{
				Name:      m.Name(),
				Installed: m.CheckInstalled(),
			})
		}
		c.HTML(http.StatusOK, "modules.html", getGlobalContext(gin.H{
			"Page":    "modules",
			"Modules": statusList,
		}))
	})

	// Settings
	r.GET("/settings", func(c *gin.Context) {
		var settings []database.Setting
		database.GetDB().Find(&settings)
		c.HTML(http.StatusOK, "settings.html", getGlobalContext(gin.H{
			"Page":     "settings",
			"Settings": settings,
		}))
	})

	r.POST("/settings", func(c *gin.Context) {
		key := c.PostForm("key")
		value := c.PostForm("value")
		desc := c.PostForm("description")

		if key != "" && value != "" {
			var setting database.Setting
			db := database.GetDB()
			// Robust Upsert using OnConflict to handle soft-deletes and updates atomically
			setting.Key = key
			setting.Value = value
			setting.Description = desc
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&setting)

			// Apply to current process env
			os.Setenv(key, value)
		}
		c.Redirect(http.StatusFound, "/settings")
	})

	r.POST("/settings/discord", func(c *gin.Context) {
		mode := c.PostForm("discord_mode")
		token := c.PostForm("discord_token")
		channel := c.PostForm("discord_channel_id")

		db := database.GetDB()
		settings := map[string]string{
			"DISCORD_MODE":       mode,
			"DISCORD_TOKEN":      token,
			"DISCORD_CHANNEL_ID": channel,
		}

		for k, v := range settings {
			var s database.Setting
			s.Key = k
			s.Value = v
			s.Description = "Discord Configuration"
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
			os.Setenv(k, v)
		}

		// Restart Bot Logic
		// Ideally we would stop the old one and start new, but for MVP we just try to start new one?
		// Current simple implementation in main doesn't support clean restart easily without global var.
		// For now, prompt user to restart app or we can try to hack it in.
		// Let's implement a simple re-init trigger if we moved the client var to package level.

		// Trigger re-init check (simple version: standard response)
		// User might need to restart app for full effect if we don't implement dynamic reload.
		// But let's try to utilize the existing init logic if possible.
		// Actually, we should extract the Discord Init logic to a function we can call here.

		if token != "" && mode == "custom" {
			manager := core.GetManager()
			// Close existing if we tracked it (we didn't yet track it globally)
			// TODO: Add global tracking for discord client to allow Stop()

			dc, err := discord.NewClient(token, channel, manager)
			if err == nil {
				// Stop previous if exists? (Not implemented yet)
				go func() {
					if err := dc.Start(); err != nil {
						utils.LogError("Failed to restart Discord bot: %v", err)
					}
				}()

				// Re-hook callbacks (idempotent assignment)
				manager.OnStart = func(target string) {
					dc.SendNotification("🚀 Scan Started", "Started scanning target: **"+target+"**", 0x34d399)
				}
				manager.OnStop = func(target string, cancelled bool) {
					dc.SendNotification("🏁 Scan Ended", "Scanning finished or stopped for: **"+target+"**", 0x8b5cf6)
				}
			}
		}

		c.Redirect(http.StatusFound, "/settings?tab=notifications")
	})

	r.POST("/settings/telegram", func(c *gin.Context) {
		token := c.PostForm("telegram_token")
		chatID := c.PostForm("telegram_chat_id")

		db := database.GetDB()
		settings := map[string]string{
			"TELEGRAM_TOKEN":   token,
			"TELEGRAM_CHAT_ID": chatID,
		}

		for k, v := range settings {
			var s database.Setting
			s.Key = k
			s.Value = v
			s.Description = "Telegram Configuration"
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
			os.Setenv(k, v)
		}

		// Simplified Reload: Note that we aren't stopping/starting listeners dynamically perfectly here
		// But Telegram is stateless REST, so just creating a client object next time or re-assigning var would work if we had global access.
		// For now, save requires restart for reliable effect, or we accept that it works on next boot.
		// We could try to inject it into the closure if we refactored, but preventing complexity.

		c.Redirect(http.StatusFound, "/settings?tab=notifications")
	})

	r.POST("/settings/uncover", func(c *gin.Context) {
		db := database.GetDB()
		settings := map[string]string{
			"SHODAN_API_KEY":     c.PostForm("shodan"),
			"CENSYS_API_ID":      c.PostForm("censys_id"),
			"CENSYS_API_SECRET":  c.PostForm("censys_secret"),
			"FOFA_EMAIL":         c.PostForm("fofa_email"),
			"FOFA_KEY":           c.PostForm("fofa_key"),
			"QUAKE_TOKEN":        c.PostForm("quake"),
			"HUNTER_API_KEY":     c.PostForm("hunter"),
			"CRIMINALIP_API_KEY": c.PostForm("criminalip"),
		}

		for k, v := range settings {
			var s database.Setting
			s.Key = k
			s.Value = v
			s.Description = "Uncover Provider Key"
			// Upsert to handle unique constraint + soft deletes
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
		c.Redirect(http.StatusFound, "/settings?tab=env")
	})

	r.POST("/settings/delete", func(c *gin.Context) {
		key := c.PostForm("key")
		if key != "" {
			database.GetDB().Where("key = ?", key).Delete(&database.Setting{})
			os.Unsetenv(key)
		}
		c.Redirect(http.StatusFound, "/settings?tab=env")
	})

	r.POST("/target/update", func(c *gin.Context) {
		id := c.PostForm("id")
		newValue := c.PostForm("value")
		if id != "" && newValue != "" {
			db := database.GetDB()
			// Update value and re-check Cloudflare status
			isCF := utils.IsCloudflareIP(newValue)
			db.Model(&database.Target{}).Where("id = ?", id).Updates(map[string]interface{}{
				"value":         newValue,
				"is_cloudflare": isCF,
			})
		}
		// Redirect back to referrer or asset page?
		// We don't have easy referrer tracking, but usually we come from asset details.
		// We can find the asset ID or just go back.
		// Let's rely on Referer header or just go to /assets if fail.
		ref := c.Request.Referer()
		if ref != "" {
			c.Redirect(http.StatusFound, ref)
		} else {
			c.Redirect(http.StatusFound, "/assets")
		}
	})

	r.POST("/target/delete", func(c *gin.Context) {
		id := c.PostForm("id")
		if id != "" {
			db := database.GetDB()
			// Cascade delete related data
			// 1. Unlink Subdomains (Set ParentID to nil)
			// Instead of deleting subdomains, we just unlink them so they become top-level targets (or just orphaned from this parent)
			db.Model(&database.Target{}).Where("parent_id = ?", id).Update("parent_id", nil)

			// 2. Delete this target's data
			db.Unscoped().Where("target_id = ?", id).Delete(&database.ScanResult{})
			db.Unscoped().Where("target_id = ?", id).Delete(&database.Port{})
			db.Unscoped().Where("target_id = ?", id).Delete(&database.WebAsset{})
			db.Unscoped().Where("target_id = ?", id).Delete(&database.Vulnerability{})

			// 3. Delete Target
			db.Unscoped().Delete(&database.Target{}, id)
		}
		ref := c.Request.Referer()
		if ref != "" {
			c.Redirect(http.StatusFound, ref)
		} else {
			c.Redirect(http.StatusFound, "/assets")
		}
	})

	// Target Details
	r.GET("/target/:id", func(c *gin.Context) {
		id := c.Param("id")
		var target database.Target
		// Preload everything for the details view
		if err := database.GetDB().
			Preload("Results").
			Preload("Subdomains").
			Preload("Ports", func(db *gorm.DB) *gorm.DB {
				return db.Order("port ASC")
			}).
			Preload("WebAssets").
			Preload("Vulns").
			Find(&target, id).Error; err != nil {
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
		if target.ID == 0 {
			c.String(http.StatusNotFound, "Target not found")
			return
		}
		c.HTML(http.StatusOK, "target_details.html", getGlobalContext(gin.H{
			"Page":   "assets", // Highlight Assets in sidebar
			"Target": target,
		}))
	})

	// Scan Trigger
	r.POST("/scan", func(c *gin.Context) {
		target := c.PostForm("target")
		asset := c.PostForm("asset")
		excludeCF := c.PostForm("exclude_cf") == "on"

		if target != "" {
			go core.RunScan(target, asset, excludeCF)
		}
		c.Redirect(http.StatusFound, "/assets")
	})

	r.POST("/api/scan", func(c *gin.Context) {
		var req struct {
			Target    string `json:"target"`
			Asset     string `json:"asset"`
			ExcludeCF bool   `json:"exclude_cf"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		go core.RunScan(req.Target, req.Asset, req.ExcludeCF)
		c.JSON(http.StatusOK, gin.H{"status": "started"})
	})

	r.GET("/api/scans", func(c *gin.Context) {
		manager := core.GetManager()
		active := manager.GetActiveScans()
		c.JSON(http.StatusOK, gin.H{"active_scans": active})
	})

	r.POST("/api/scan/stop", func(c *gin.Context) {
		target := c.PostForm("target")
		// If target is empty, it stops all?
		// Current manager StopScan logic: empty string = stop all.
		// Let's allow specific stop via JSON or Form.
		if target == "" {
			// Try JSON
			var req struct {
				Target string `json:"target"`
			}
			if err := c.ShouldBindJSON(&req); err == nil {
				target = req.Target
			}
		}

		core.GetManager().StopScan(target)
		c.JSON(http.StatusOK, gin.H{"status": "stopped", "target": target})
	})

	r.POST("/api/scan/stop_asset", func(c *gin.Context) {
		var req struct {
			Asset string `json:"asset"`
		}
		if err := c.ShouldBindJSON(&req); err == nil && req.Asset != "" {
			core.GetManager().StopAssetScan(req.Asset)
			c.JSON(http.StatusOK, gin.H{"status": "stopped", "asset": req.Asset})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "asset name required"})
		}
	})

	return r.Run(":" + port)
}

// MultiRender implements gin.HTMLRender
type MultiRender struct {
	templates map[string]*template.Template
}

func (r MultiRender) Instance(name string, data any) render.Render {
	return render.HTML{
		Template: r.templates[name],
		Name:     "layout.html", // Start execution at layout.html
		Data:     data,
	}
}
