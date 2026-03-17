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
	"xpfarm/internal/overlord"
	"xpfarm/pkg/utils"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

//go:embed templates/* static/*
var f embed.FS

func StartServer(port string) error {
	// Debug mode is already set in main.go via flag.Parse() and gin.SetMode().
	// Check if Gin is in debug mode to enable the logger middleware.
	isDebug := gin.Mode() == gin.DebugMode

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

	pages := []string{"dashboard.html", "assets.html", "asset_details.html", "target_details.html", "modules.html", "settings.html", "target.html", "overlord.html", "overlord_binary.html", "search.html", "advanced_scan.html", "scan_settings.html"}

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
	manager.SetOnStart(func(target string) {
		if discordClient != nil {
			discordClient.SendNotification("🚀 Scan Started", "Started scanning target: **"+target+"**", 0x34d399)
		}
		if telegramClient != nil {
			if err := telegramClient.SendNotification(fmt.Sprintf("*🚀 Scan Started*\nStarted scanning target: `%s`", target)); err != nil {
				utils.LogError("Telegram notification failed: %v", err)
			}
		}
	})
	manager.SetOnStop(func(target string, cancelled bool) {
		if discordClient != nil {
			discordClient.SendNotification("🏁 Scan Ended", "Scanning finished or stopped for: **"+target+"**", 0x8b5cf6)
		}
		if telegramClient != nil {
			if err := telegramClient.SendNotification(fmt.Sprintf("*🏁 Scan Ended*\nScanning finished or stopped for: `%s`", target)); err != nil {
				utils.LogError("Telegram notification failed: %v", err)
			}
		}
	})

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

		db := database.GetDB()
		db.Model(&database.Asset{}).Count(&assetsCount)
		db.Model(&database.Target{}).Count(&targetsCount)
		db.Model(&database.ScanResult{}).Count(&resultsCount)

		var recentResults []database.ScanResult
		db.Order("created_at desc").Limit(10).Preload("Target").Find(&recentResults)

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

		// Vulnerability Stats for Dashboard
		var vulnTotalCount int64
		db.Model(&database.Vulnerability{}).Count(&vulnTotalCount)

		type SevCount struct {
			Severity string
			Count    int64
		}
		var sevCounts []SevCount
		db.Model(&database.Vulnerability{}).
			Select("severity, count(*) as count").
			Group("severity").
			Scan(&sevCounts)

		vulnStats := gin.H{
			"Total":    vulnTotalCount,
			"Critical": int64(0),
			"High":     int64(0),
			"Medium":   int64(0),
			"Low":      int64(0),
			"Info":     int64(0),
		}
		for _, sc := range sevCounts {
			switch sc.Severity {
			case "critical":
				vulnStats["Critical"] = sc.Count
			case "high":
				vulnStats["High"] = sc.Count
			case "medium":
				vulnStats["Medium"] = sc.Count
			case "low":
				vulnStats["Low"] = sc.Count
			case "info":
				vulnStats["Info"] = sc.Count
			}
		}

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
			"VulnStats":     vulnStats,
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

	// Modules
	r.GET("/modules", func(c *gin.Context) {
		// Get all tools and their statuses
		allTools := modules.GetAll()
		
		type ModuleInfo struct {
			Name        string
			Description string
			Installed   bool
		}
		
		var modsInfo []ModuleInfo
		for _, m := range allTools {
			modsInfo = append(modsInfo, ModuleInfo{
				Name:        m.Name(),
				Description: m.Description(),
				Installed:   m.CheckInstalled(),
			})
		}

		c.HTML(http.StatusOK, "modules.html", getGlobalContext(gin.H{
			"Page":    "modules",
			"Modules": modsInfo,
		}))
	})

	// Overlord
	r.GET("/overlord", func(c *gin.Context) {
		status := overlord.GetStatus()
		c.HTML(http.StatusOK, "overlord.html", getGlobalContext(gin.H{
			"Page":   "overlord",
			"Status": status,
		}))
	})

	r.GET("/overlord/binary", func(c *gin.Context) {
		status := overlord.CheckConnection()
		binaries, _ := overlord.ListBinaries()
		outputs, _ := overlord.ListOutputs()

		// Get saved model selection
		activeModel := ""
		var modelSetting database.Setting
		if database.GetDB().Where("key = ?", "OVERLORD_MODEL").First(&modelSetting).Error == nil {
			activeModel = modelSetting.Value
		}

		c.HTML(http.StatusOK, "overlord_binary.html", getGlobalContext(gin.H{
			"Page":        "overlord",
			"Connection":  status,
			"Binaries":    binaries,
			"Outputs":     outputs,
			"ActiveModel": activeModel,
		}))
	})

	// Overlord API
	r.GET("/api/overlord/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, overlord.GetStatus())
	})

	r.GET("/api/overlord/sessions", func(c *gin.Context) {
		sessions, err := overlord.GetSessions()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, sessions)
	})

	r.GET("/api/overlord/sessions/:id/messages", func(c *gin.Context) {
		sessionID := c.Param("id")
		messages, err := overlord.GetSessionMessages(sessionID)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, messages)
	})

	r.POST("/api/overlord/sessions", func(c *gin.Context) {
		var body struct {
			Message string `json:"message"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		session, err := overlord.CreateSession(body.Message)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, session)
	})

	r.POST("/api/overlord/sessions/:id/prompt", func(c *gin.Context) {
		sessionID := c.Param("id")
		var body struct {
			Message string `json:"message"`
			Model   string `json:"model"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := overlord.SendPromptAsync(sessionID, body.Message, body.Model)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/api/overlord/sessions/:id/abort", func(c *gin.Context) {
		sessionID := c.Param("id")
		err := overlord.AbortSession(sessionID)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "aborted"})
	})

	r.GET("/api/overlord/events", func(c *gin.Context) {
		if err := overlord.ProxySSE(c.Writer); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		}
	})

	r.GET("/api/overlord/binaries", func(c *gin.Context) {
		files, _ := overlord.ListBinaries()
		c.JSON(http.StatusOK, files)
	})

	r.POST("/api/overlord/binaries/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
			return
		}
		f, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer f.Close()
		if err := overlord.SaveBinary(file.Filename, f); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "uploaded", "filename": file.Filename})
	})

	// Live Provider & Agent APIs
	r.GET("/api/overlord/providers", func(c *gin.Context) {
		providers, err := overlord.GetLiveProviders()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, providers)
	})

	r.GET("/api/overlord/agents", func(c *gin.Context) {
		agents, err := overlord.GetLiveAgents()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, agents)
	})

	r.POST("/api/overlord/model", func(c *gin.Context) {
		var body struct {
			Model string `json:"model"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var s database.Setting
		s.Key = "OVERLORD_MODEL"
		s.Value = body.Model
		s.Description = "Selected AI model for Overlord"
		database.GetDB().Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
		}).Create(&s)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// AI Provider Settings
	r.POST("/settings/ai", func(c *gin.Context) {
		providerID := c.PostForm("active_provider")
		db := database.GetDB()

		// Save active provider
		if providerID != "" {
			var s database.Setting
			s.Key = "OVERLORD_ACTIVE_PROVIDER"
			s.Value = providerID
			s.Description = "Active AI Provider for Overlord"
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
		}

		// Save all provider API keys (use fallback list for form field names)
		authKeys := make(map[string]string)
		for _, provider := range overlord.GetFallbackProviders() {
			for _, envKey := range provider.EnvKeys {
				val := c.PostForm(envKey)
				if val != "" {
					var s database.Setting
					s.Key = envKey
					s.Value = val
					s.Description = provider.Name + " API Key"
					db.Clauses(clause.OnConflict{
						Columns:   []clause.Column{{Name: "key"}},
						DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
					}).Create(&s)
					os.Setenv(envKey, val)
					authKeys[envKey] = val

					// Also set auth on OpenCode server directly
					overlord.SetAuth(provider.ID, val)
				}
			}
		}

		// Write auth file for overlord container (fallback)
		if len(authKeys) > 0 {
			var allSettings []database.Setting
			db.Find(&allSettings)
			allKeys := make(map[string]string)
			for _, s := range allSettings {
				allKeys[s.Key] = s.Value
			}
			overlord.WriteAuthFile(allKeys)
		}

		// Invalidate provider cache so new auth is picked up
		overlord.InvalidateProviderCache()

		c.Redirect(http.StatusFound, "/settings?tab=ai")
	})


	// Global Search
	r.GET("/search", func(c *gin.Context) {
		var savedSearches []database.SavedSearch
		database.GetDB().Find(&savedSearches)

		c.HTML(http.StatusOK, "search.html", getGlobalContext(gin.H{
			"Page":          "search",
			"SavedSearches": savedSearches,
		}))
	})

	r.POST("/api/search", func(c *gin.Context) {
		var req core.SearchPayload
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		results, err := core.GlobalSearch(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, results)
	})

	r.POST("/api/search/save", func(c *gin.Context) {
		var body struct {
			Name      string `json:"name"`
			QueryData string `json:"query_data"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		saved := database.SavedSearch{
			Name:      body.Name,
			QueryData: body.QueryData,
		}

		if err := database.GetDB().Create(&saved).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})

	r.POST("/api/search/delete", func(c *gin.Context) {
		id := c.PostForm("id")
		if id != "" {
			database.GetDB().Unscoped().Delete(&database.SavedSearch{}, id)
		}
		c.Status(http.StatusOK)
	})

	r.GET("/api/search/columns", func(c *gin.Context) {
		source := c.Query("source")
		if source == "" {
			source = "targets"
		}
		cols := core.SourceColumns(source)
		c.JSON(http.StatusOK, cols)
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
			db := database.GetDB()
			profile := database.ScanProfile{
				Name: "Default " + name,
			}
			if err := db.Create(&profile).Error; err == nil {
				db.Create(&database.Asset{Name: name, ScanProfileID: &profile.ID})
			} else {
				db.Create(&database.Asset{Name: name})
			}
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
				db.Unscoped().Where("target_id IN ?", targetIDs).Delete(&database.CVE{})
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

		var asset database.Asset
		if err := database.GetDB().Preload("Targets").First(&asset, id).Error; err == nil {
			// Trigger scans for all targets
			for _, t := range asset.Targets {
				val := t.Value
				// Run in goroutine to not block
				go core.RunScan(val, asset.Name)
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

			// Normalize: strip scheme, port, path from URLs
			normalized := core.NormalizeToHostname(tVal)
			if normalized == "" {
				normalized = tVal
			}

			// Determine target type
			parsed := core.ParseTarget(normalized)

			// Global Duplicate Check
			var existing database.Target
			if db.Where("value = ?", normalized).Limit(1).Find(&existing).RowsAffected > 0 {
				var existingAsset database.Asset
				if err := db.Find(&existingAsset, existing.AssetID).Error; err != nil || existingAsset.ID == 0 {
					// Orphaned target — delete and allow re-import
					db.Unscoped().Delete(&existing)
				} else {
					report = append(report, ImportStatus{Target: normalized, Status: "warning", Detail: "Duplicate found in group: " + existingAsset.Name})
					continue
				}
			}

			// Also check soft-deleted targets and restore if found
			var softDeleted database.Target
			if db.Unscoped().Where("value = ? AND deleted_at IS NOT NULL", normalized).Limit(1).Find(&softDeleted).RowsAffected > 0 {
				// Restore the soft-deleted target
				db.Unscoped().Model(&softDeleted).Updates(map[string]interface{}{
					"deleted_at": nil,
					"asset_id":   asset.ID,
					"status":     "",
					"is_alive":   true,
				})
				report = append(report, ImportStatus{Target: normalized, Status: "success", Detail: "Restored (was previously removed)"})
				continue
			}

			// Add New — no alive check, just store it
			newTarget := database.Target{
				AssetID: asset.ID,
				Value:   normalized,
				Type:    string(parsed.Type),
				IsAlive: true,
				Status:  "",
			}
			db.Create(&newTarget)

			detail := "Added successfully"
			if tVal != normalized {
				detail += fmt.Sprintf(" (normalized from %s)", tVal)
			}
			report = append(report, ImportStatus{Target: normalized, Status: "success", Detail: detail})
		}

		// Reload asset to show new targets
		db.Preload("Targets").First(&asset, assetID)

		// Query soft-deleted (removed) targets for this asset
		var removedTargets []database.Target
		db.Unscoped().Where("asset_id = ? AND deleted_at IS NOT NULL", asset.ID).Find(&removedTargets)

		// Render page with report
		c.HTML(http.StatusOK, "asset_details.html", getGlobalContext(gin.H{
			"Page":           "assets",
			"Asset":          asset,
			"ImportReport":   report,
			"RemovedTargets": removedTargets,
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
		db := database.GetDB()
		var asset database.Asset
		// Use Find to avoid GORM "record not found" error log
		db.Preload("Targets").Preload("ScanProfile").Find(&asset, id)
		if asset.ID == 0 {
			c.Redirect(http.StatusFound, "/assets")
			return
		}

		// Query soft-deleted (removed) targets for this asset
		var removedTargets []database.Target
		db.Unscoped().Where("asset_id = ? AND deleted_at IS NOT NULL", asset.ID).Find(&removedTargets)

		c.HTML(http.StatusOK, "asset_details.html", getGlobalContext(gin.H{
			"Page":           "assets",
			"Asset":          asset,
			"RemovedTargets": removedTargets,
		}))
	})

	r.GET("/asset/:id/advanced", func(c *gin.Context) {
		id := c.Param("id")
		db := database.GetDB()
		var asset database.Asset
		db.Preload("Targets").Find(&asset, id)
		if asset.ID == 0 {
			c.Redirect(http.StatusFound, "/assets")
			return
		}

		var allTemplates []database.NucleiTemplate
		db.Find(&allTemplates)

		// Create a lookup map for pre-selecting checkboxes
		selectedMap := make(map[string]bool)
		for _, tID := range strings.Split(asset.AdvancedTemplates, ",") {
			id := strings.TrimSpace(tID)
			if id != "" {
				selectedMap[id] = true
			}
		}

		// Structs for ordered rendering
		type SubFolderGroup struct {
			Name      string
			Templates []database.NucleiTemplate
		}
		type TabGroup struct {
			Name       string
			TotalCount int
			SubFolders []SubFolderGroup
		}

		// 1. Group by Tab -> Subfolder -> Templates using maps first
		tempMap := make(map[string]map[string][]database.NucleiTemplate)
		for _, t := range allTemplates {
			parts := strings.Split(t.FilePath, string(os.PathSeparator))
			if len(parts) == 0 {
				continue
			}

			folder := parts[0]
			subfolder := "Generic"

			if len(parts) > 2 {
				// e.g., ssl/c2/template.yaml -> parts = ["ssl", "c2", "template.yaml"]
				subfolder = parts[1]
			}

			if tempMap[folder] == nil {
				tempMap[folder] = make(map[string][]database.NucleiTemplate)
			}
			tempMap[folder][subfolder] = append(tempMap[folder][subfolder], t)
		}

		// 2. Convert to sorted slices
		var tabs []TabGroup
		for folderName, subMap := range tempMap {
			var subs []SubFolderGroup
			var genericIdx = -1
			totalCount := 0

			// Extract all subfolders into slice
			for subName, tmpls := range subMap {
				// Sort templates inside the subfolder alphabetically by TemplateID
				sort.Slice(tmpls, func(i, j int) bool {
					return tmpls[i].TemplateID < tmpls[j].TemplateID
				})

				subs = append(subs, SubFolderGroup{
					Name:      subName,
					Templates: tmpls,
				})
				totalCount += len(tmpls)
			}

			// Sort subfolders alphabetically
			sort.Slice(subs, func(i, j int) bool {
				return subs[i].Name < subs[j].Name
			})

			// Find Generic and move it to the front
			for i, s := range subs {
				if s.Name == "Generic" {
					genericIdx = i
					break
				}
			}

			if genericIdx > 0 {
				genericSub := subs[genericIdx]
				subs = append(subs[:genericIdx], subs[genericIdx+1:]...) // Remove
				subs = append([]SubFolderGroup{genericSub}, subs...)     // Prepend
			}

			tabs = append(tabs, TabGroup{
				Name:       folderName,
				TotalCount: totalCount,
				SubFolders: subs,
			})
		}

		// Sort tabs alphabetically
		sort.Slice(tabs, func(i, j int) bool {
			return tabs[i].Name < tabs[j].Name
		})

		c.HTML(http.StatusOK, "advanced_scan.html", getGlobalContext(gin.H{
			"Page":        "assets",
			"Asset":       asset,
			"Tabs":        tabs,
			"SelectedMap": selectedMap,
		}))
	})

	r.POST("/asset/:id/advanced/save", func(c *gin.Context) {
		id := c.Param("id")
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form: " + err.Error()})
			return
		}

		enableAdvanced := c.PostForm("enable_advanced") == "on"
		selectedTemplates := c.Request.Form["templates[]"]

		db := database.GetDB()
		db.Model(&database.Asset{}).Where("id = ?", id).Updates(map[string]interface{}{
			"advanced_mode":      enableAdvanced,
			"advanced_templates": strings.Join(selectedTemplates, ","),
		})

		c.Redirect(http.StatusFound, "/asset/"+id)
	})

	r.GET("/asset/:id/settings", func(c *gin.Context) {
		id := c.Param("id")
		db := database.GetDB()
		var asset database.Asset
		db.Preload("ScanProfile").Find(&asset, id)
		if asset.ID == 0 {
			c.Redirect(http.StatusFound, "/assets")
			return
		}

		if asset.ScanProfileID == nil || asset.ScanProfile == nil {
			// Create default
			profile := database.ScanProfile{Name: "Default " + asset.Name}
			db.Create(&profile)
			asset.ScanProfileID = &profile.ID
			asset.ScanProfile = &profile
			db.Save(&asset)
		}

		c.HTML(http.StatusOK, "scan_settings.html", getGlobalContext(gin.H{
			"Page":  "assets",
			"Asset": asset,
		}))
	})

	r.POST("/asset/:id/settings/save", func(c *gin.Context) {
		id := c.Param("id")
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form: " + err.Error()})
			return
		}

		db := database.GetDB()
		var asset database.Asset
		db.Preload("ScanProfile").Find(&asset, id)
		if asset.ID == 0 || asset.ScanProfile == nil {
			c.Redirect(http.StatusFound, "/asset/"+id)
			return
		}

		profile := asset.ScanProfile
		profile.ExcludeCloudflare = c.PostForm("exclude_cloudflare") == "on"
		profile.ExcludeLocalhost = c.PostForm("exclude_localhost") == "on"
		profile.EnableSubfinder = c.PostForm("enable_subfinder") == "on"
		profile.ScanDiscoveredSubdomains = c.PostForm("scan_discovered_subdomains") == "on"
		profile.EnablePortScan = c.PostForm("enable_port_scan") == "on"

		portScope := c.PostForm("port_scan_scope")
		if portScope != "" {
			profile.PortScanScope = portScope
		}
		portSpeed := c.PostForm("port_scan_speed")
		if portSpeed != "" {
			profile.PortScanSpeed = portSpeed
		}
		portMode := c.PostForm("port_scan_mode")
		if portMode != "" {
			profile.PortScanMode = portMode
		}

		profile.EnableWebProbe = c.PostForm("enable_web_probe") == "on"
		profile.EnableWebWappalyzer = c.PostForm("enable_web_wappalyzer") == "on"
		profile.EnableWebGowitness = c.PostForm("enable_web_gowitness") == "on"
		profile.EnableWebKatana = c.PostForm("enable_web_katana") == "on"
		profile.EnableWebUrlfinder = c.PostForm("enable_web_urlfinder") == "on"

		webScope := c.PostForm("web_scan_scope")
		if webScope != "" {
			profile.WebScanScope = webScope
		}

		webRate := c.PostForm("web_scan_rate_limit")
		if webRate != "" {
			// Basic generic int parse instead of complex deps
			var wr int
			if _, err := fmt.Sscanf(webRate, "%d", &wr); err == nil && wr > 0 {
				profile.WebScanRateLimit = wr
			}
		}

		profile.EnableVulnScan = c.PostForm("enable_vuln_scan") == "on"
		profile.EnableCvemap = c.PostForm("enable_cvemap") == "on"
		profile.EnableNuclei = c.PostForm("enable_nuclei") == "on"

		db.Save(profile)
		c.Redirect(http.StatusFound, "/asset/"+id+"/settings")
	})
	// Settings
	r.GET("/settings", func(c *gin.Context) {
		var settings []database.Setting
		database.GetDB().Find(&settings)

		// Get active provider for AI tab
		activeProvider := ""
		for _, s := range settings {
			if s.Key == "OVERLORD_ACTIVE_PROVIDER" {
				activeProvider = s.Value
				break
			}
		}

		c.HTML(http.StatusOK, "settings.html", getGlobalContext(gin.H{
			"Page":           "settings",
			"Settings":       settings,
			"Providers":      overlord.GetFallbackProviders(),
			"ActiveProvider": activeProvider,
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

				// Re-hook callbacks (thread-safe)
				manager.SetOnStart(func(target string) {
					dc.SendNotification("🚀 Scan Started", "Started scanning target: **"+target+"**", 0x34d399)
				})
				manager.SetOnStop(func(target string, cancelled bool) {
					dc.SendNotification("🏁 Scan Ended", "Scanning finished or stopped for: **"+target+"**", 0x8b5cf6)
				})
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
			db.Unscoped().Where("target_id = ?", id).Delete(&database.CVE{})

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
			Preload("CVEs").
			First(&target, "id = ?", id).Error; err != nil {
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
		if target.ID == 0 {
			c.String(http.StatusNotFound, "Target not found")
			return
		}

		// Group CVEs by product for the template
		cvesByProduct := make(map[string][]database.CVE)
		for _, cve := range target.CVEs {
			cvesByProduct[cve.Product] = append(cvesByProduct[cve.Product], cve)
		}

		// Sort CVEs within each product by severity
		sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		for prod := range cvesByProduct {
			cves := cvesByProduct[prod]
			sort.Slice(cves, func(i, j int) bool {
				oi, oj := sevOrder[cves[i].Severity], sevOrder[cves[j].Severity]
				if oi != oj {
					return oi < oj
				}
				return cves[i].CvssScore > cves[j].CvssScore
			})
			cvesByProduct[prod] = cves
		}

		// Count only Nuclei findings with severity low or above (not info)
		vulnCount := 0
		vulnsBySeverity := make(map[string][]database.Vulnerability)
		for _, v := range target.Vulns {
			sev := v.Severity
			vulnsBySeverity[sev] = append(vulnsBySeverity[sev], v)
			if sev == "low" || sev == "medium" || sev == "high" || sev == "critical" {
				vulnCount++
			}
		}

		// Sort vulns within each severity by name
		for sev := range vulnsBySeverity {
			vulns := vulnsBySeverity[sev]
			sort.Slice(vulns, func(i, j int) bool {
				return vulns[i].Name < vulns[j].Name
			})
			vulnsBySeverity[sev] = vulns
		}

		c.HTML(http.StatusOK, "target_details.html", getGlobalContext(gin.H{
			"Page":            "assets",
			"Target":          target,
			"CVEsByProduct":   cvesByProduct,
			"VulnCount":       vulnCount,
			"VulnsBySeverity": vulnsBySeverity,
			"SeverityOrder":   []string{"critical", "high", "medium", "low", "info"},
		}))

	})

	// Scan Trigger
	r.POST("/scan", func(c *gin.Context) {
		target := c.PostForm("target")
		asset := c.PostForm("asset")

		if target != "" {
			go core.RunScan(target, asset)
		}
		c.Redirect(http.StatusFound, "/assets")
	})

	r.POST("/api/scan", func(c *gin.Context) {
		var req struct {
			Target           string `json:"target"`
			Asset            string `json:"asset"`
			ExcludeCF        bool   `json:"exclude_cf"`
			ExcludeLocalhost bool   `json:"exclude_localhost"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		go core.RunScan(req.Target, req.Asset)
		c.JSON(http.StatusOK, gin.H{"status": "started"})
	})

	r.GET("/api/scans", func(c *gin.Context) {
		manager := core.GetManager()
		active := manager.GetActiveScans()
		c.JSON(http.StatusOK, gin.H{"active_scans": active})
	})

	r.POST("/api/scan/stop", func(c *gin.Context) {
		var target string
		// Determine content type to avoid consuming the body twice
		if c.ContentType() == "application/json" {
			var req struct {
				Target string `json:"target"`
			}
			if err := c.ShouldBindJSON(&req); err == nil {
				target = req.Target
			}
		} else {
			target = c.PostForm("target")
		}
		// Empty target = stop all scans
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

	// Nuclei Templates
	r.GET("/api/nuclei/templates", func(c *gin.Context) {
		var templates []database.NucleiTemplate
		// Optional search query parameter
		query := c.Query("q")
		db := database.GetDB()
		if query != "" {
			search := "%" + query + "%"
			db.Where("name LIKE ? OR template_id LIKE ? OR tags LIKE ?", search, search, search).Find(&templates)
		} else {
			db.Find(&templates)
		}
		c.JSON(http.StatusOK, gin.H{
			"count":     len(templates),
			"templates": templates,
		})
	})

	r.POST("/api/nuclei/templates/refresh", func(c *gin.Context) {
		err := core.IndexNucleiTemplates(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var count int64
		database.GetDB().Model(&database.NucleiTemplate{}).Count(&count)

		c.JSON(http.StatusOK, gin.H{
			"status": "indexed",
			"count":  count,
		})
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
