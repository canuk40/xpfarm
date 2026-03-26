package ui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xpfarm/internal/core"
	"xpfarm/internal/crypto"
	"xpfarm/internal/database"
	"xpfarm/internal/modules"
	"xpfarm/internal/normalization"
	"xpfarm/internal/notifications/discord"
	"xpfarm/internal/notifications/telegram"
	"xpfarm/internal/overlord"
	"xpfarm/internal/plugin"
	findingsrepo "xpfarm/internal/storage/findings"
	"xpfarm/internal/graph"
	graphstore "xpfarm/internal/storage/graph"
	repo_scanner "xpfarm/internal/repo_scanner"
	"xpfarm/internal/repos"
	"xpfarm/internal/reports"
	"xpfarm/internal/reports/exporter"
	reportstore "xpfarm/internal/storage/reports"
	repostore "xpfarm/internal/storage/repos"
	"xpfarm/internal/planner"
	planstore "xpfarm/internal/storage/plans"
	"xpfarm/internal/distributed/controller"
	"xpfarm/internal/distributed/localworker"
	jobstore "xpfarm/internal/storage/jobs"
	workerstore "xpfarm/internal/storage/workers"
	schedulestore "xpfarm/internal/storage/schedules"
	scanhistorystore "xpfarm/internal/storage/scanhistory"
	"xpfarm/pkg/utils"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

//go:embed templates/* static/*
var f embed.FS

// csrfGuard rejects state-mutating POST requests that originate from external origins.
// XPFarm is a local tool, so only localhost origins are legitimate callers.
func csrfGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}
		origin := c.Request.Header.Get("Origin")
		referer := c.Request.Header.Get("Referer")

		// Allow requests with no Origin/Referer (direct curl calls, same-origin form submits)
		if origin == "" && referer == "" {
			c.Next()
			return
		}

		allowed := func(u string) bool {
			return strings.HasPrefix(u, "http://localhost") ||
				strings.HasPrefix(u, "http://127.0.0.1") ||
				strings.HasPrefix(u, "http://0.0.0.0") ||
				strings.HasPrefix(u, "https://localhost") ||
				strings.HasPrefix(u, "https://127.0.0.1")
		}

		if (origin != "" && !allowed(origin)) || (referer != "" && !allowed(referer)) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin request rejected"})
			return
		}
		c.Next()
	}
}

// rateLimiter returns a simple per-IP token bucket middleware.
// Each IP gets burst capacity with refill at rate requests/second.
func rateLimiter(rate int, burst int) gin.HandlerFunc {
	type bucket struct {
		tokens    int64
		lastRefil int64 // unix nanos
	}
	var mu sync.Mutex
	buckets := map[string]*bucket{}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now().UnixNano()
		mu.Lock()
		b, ok := buckets[ip]
		if !ok {
			b = &bucket{tokens: int64(burst), lastRefil: now}
			buckets[ip] = b
		}
		// Refill tokens based on elapsed time
		elapsed := now - atomic.LoadInt64(&b.lastRefil)
		refill := int64(float64(elapsed) / float64(time.Second) * float64(rate))
		if refill > 0 {
			b.tokens += refill
			if b.tokens > int64(burst) {
				b.tokens = int64(burst)
			}
			atomic.StoreInt64(&b.lastRefil, now)
		}
		if b.tokens <= 0 {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		b.tokens--
		mu.Unlock()
		c.Next()
	}
}

const authCookieName = "xpf_session"
const authSettingKey = "ui_password_hash"

// hashPassword returns a SHA-256 hex hash of the password with a static salt.
func hashPassword(pw string) string {
	h := sha256.Sum256([]byte("xpfarm:" + pw))
	return hex.EncodeToString(h[:])
}

// generateSessionToken returns a 32-byte random hex token.
func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// sessionStore maps token → expiry (in-memory, resets on restart)
var (
	sessionMu    sync.RWMutex
	sessionStore = map[string]time.Time{}
)

func isValidSession(token string) bool {
	sessionMu.RLock()
	exp, ok := sessionStore[token]
	sessionMu.RUnlock()
	return ok && time.Now().Before(exp)
}

func createSession() string {
	tok := generateSessionToken()
	sessionMu.Lock()
	sessionStore[tok] = time.Now().Add(24 * time.Hour)
	sessionMu.Unlock()
	return tok
}

func destroySession(token string) {
	sessionMu.Lock()
	delete(sessionStore, token)
	sessionMu.Unlock()
}

// authRequired middleware — skips auth if no password is configured.
func authRequired(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if password is set
		var setting database.Setting
		if err := db.Where("key = ?", authSettingKey).First(&setting).Error; err != nil || setting.Value == "" {
			// No password configured — allow all access
			c.Next()
			return
		}
		// Skip auth for login page and static assets
		path := c.Request.URL.Path
		if path == "/login" || path == "/api/auth/login" || path == "/api/auth/logout" ||
			strings.HasPrefix(path, "/static/") || path == "/favicon.ico" {
			c.Next()
			return
		}
		// Check session cookie
		token, err := c.Cookie(authCookieName)
		if err != nil || !isValidSession(token) {
			if strings.HasPrefix(path, "/api/") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			} else {
				c.Redirect(http.StatusFound, "/login")
				c.Abort()
			}
			return
		}
		c.Next()
	}
}

func StartServer(port string) error {
	// Debug mode is already set in main.go via flag.Parse() and gin.SetMode().
	// Check if Gin is in debug mode to enable the logger middleware.
	isDebug := gin.Mode() == gin.DebugMode

	// Use gin.New() to skip Default Logger output
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(csrfGuard())
	r.Use(rateLimiter(60, 120)) // 60 req/s, burst 120
	r.Use(authRequired(database.GetDB()))
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

	pages := []string{"dashboard.html", "assets.html", "asset_details.html", "target_details.html", "modules.html", "settings.html", "target.html", "overlord.html", "overlord_binary.html", "search.html", "advanced_scan.html", "scan_settings.html", "reports.html", "planner.html", "workers.html", "graph.html", "asset.html", "index.html", "repos.html", "nuclei.html", "schedules.html", "history.html", "findings.html", "login.html", "chat.html"}

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
			"truncateString": func(s string, n int) string {
				if len(s) <= n {
					return s
				}
				return s[:n] + "…"
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
	startupAuthKeys := make(map[string]string)
	for _, s := range settings {
		val := crypto.Decrypt(s.Value)
		switch s.Key {
		case "DISCORD_TOKEN":
			discordToken = val
		case "DISCORD_CHANNEL_ID":
			discordChannel = val
		case "TELEGRAM_TOKEN":
			telegramToken = val
		case "TELEGRAM_CHAT_ID":
			telegramChatID = val
		default:
			// Restore env vars for all other settings (e.g. AI provider keys)
			os.Setenv(s.Key, val)
			startupAuthKeys[s.Key] = val
		}
	}
	// Re-write auth file so Overlord has up-to-date credentials after restart
	if len(startupAuthKeys) > 0 {
		overlord.WriteAuthFile(startupAuthKeys)
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

		// Chart Data: Targets per Asset (GROUP BY avoids loading all target records)
		type AssetStat struct {
			ID    uint
			Name  string
			Count int
		}
		type targetCount struct {
			AssetID uint
			Count   int
		}
		var assetStats []AssetStat
		var allAssets []database.Asset
		db.Find(&allAssets)
		var tCounts []targetCount
		db.Model(&database.Target{}).Select("asset_id, count(*) as count").Group("asset_id").Scan(&tCounts)
		tCountMap := make(map[uint]int, len(tCounts))
		for _, tc := range tCounts {
			tCountMap[tc.AssetID] = tc.Count
		}
		for _, a := range allAssets {
			assetStats = append(assetStats, AssetStat{ID: a.ID, Name: a.Name, Count: tCountMap[a.ID]})
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

		// Get enabled providers
		enabledProviders := ""
		var epSetting database.Setting
		if database.GetDB().Where("key = ?", "OVERLORD_ENABLED_PROVIDERS").First(&epSetting).Error == nil {
			enabledProviders = epSetting.Value
		}

		c.HTML(http.StatusOK, "overlord_binary.html", getGlobalContext(gin.H{
			"Page":             "overlord",
			"Connection":       status,
			"Binaries":         binaries,
			"Outputs":          outputs,
			"ActiveModel":      activeModel,
			"EnabledProviders": enabledProviders,
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
		// Enforce 500 MB upload limit
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 500<<20)

		file, err := c.FormFile("file")
		if err != nil {
			if err.Error() == "http: request body too large" {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds 500 MB limit"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
			}
			return
		}
		f, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer f.Close()

		// Detect MIME type from first 512 bytes
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		mimeType := http.DetectContentType(buf[:n])
		// Accept known binary/archive types; reject plain text disguised as binary
		allowed := strings.HasPrefix(mimeType, "application/") ||
			strings.HasPrefix(mimeType, "text/") || // scripts
			mimeType == "application/octet-stream"
		if !allowed {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported file type: " + mimeType})
			return
		}

		// Rewind to include the already-read bytes by creating a combined reader
		combined := io.MultiReader(strings.NewReader(string(buf[:n])), f)
		if err := overlord.SaveBinary(file.Filename, combined); err != nil {
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
		s.Value = crypto.Encrypt(body.Model)
		s.Description = "Selected AI model for Overlord"
		database.GetDB().Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
		}).Create(&s)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Save AI provider keys via JSON API
	r.POST("/api/overlord/providers/save", func(c *gin.Context) {
		var body struct {
			Keys []struct {
				ProviderID string `json:"providerID"`
				EnvKey     string `json:"envKey"`
				Value      string `json:"value"`
			} `json:"keys"`
			EnabledProviders []string `json:"enabledProviders"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		db := database.GetDB()
		authKeys := make(map[string]string)

		for _, k := range body.Keys {
			if k.EnvKey == "" || k.Value == "" {
				continue
			}
			// Save to DB (encrypted)
			var s database.Setting
			s.Key = k.EnvKey
			s.Value = crypto.Encrypt(k.Value)
			s.Description = k.ProviderID + " API Key"
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
			os.Setenv(k.EnvKey, k.Value)
			authKeys[k.EnvKey] = k.Value

			// Set auth on OpenCode server
			overlord.SetAuth(k.ProviderID, k.Value)
		}

		// Save enabled providers list
		if body.EnabledProviders != nil {
			var s database.Setting
			s.Key = "OVERLORD_ENABLED_PROVIDERS"
			s.Value = crypto.Encrypt(strings.Join(body.EnabledProviders, ","))
			s.Description = "Enabled AI providers"
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key"}},
				DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
			}).Create(&s)
		}

		// Write auth file (plaintext — overlord reads this directly)
		if len(authKeys) > 0 {
			var allSettings []database.Setting
			db.Find(&allSettings)
			allKeys := make(map[string]string)
			for _, s := range allSettings {
				allKeys[s.Key] = crypto.Decrypt(s.Value)
			}
			overlord.WriteAuthFile(allKeys)
		}

		overlord.InvalidateProviderCache()
		c.JSON(http.StatusOK, gin.H{"status": "ok", "saved": len(authKeys)})
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
					s.Value = crypto.Encrypt(val)
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

		// Write auth file for overlord container (plaintext — overlord reads this directly)
		if len(authKeys) > 0 {
			var allSettings []database.Setting
			db.Find(&allSettings)
			allKeys := make(map[string]string)
			for _, s := range allSettings {
				allKeys[s.Key] = crypto.Decrypt(s.Value)
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

		result, err := core.GlobalSearch(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, result)
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

		// Report Structs (declared early so file parsing can append errors)
		type ImportStatus struct {
			Target string
			Status string
			Detail string
		}
		var report []ImportStatus

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
					records, csvErr := r.ReadAll()
					if csvErr != nil {
						// Malformed CSV — surface error and fall back to line-by-line
						report = append(report, ImportStatus{Target: "(csv parse error)", Status: "error", Detail: csvErr.Error()})
						for _, line := range strings.Split(strContent, "\n") {
							if t := strings.TrimSpace(line); t != "" {
								targets = append(targets, t)
							}
						}
					} else {
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
							for _, line := range strings.Split(strContent, "\n") {
								targets = append(targets, strings.TrimSpace(line))
							}
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

		// Intelligence enrichment toggles
		profile.EnableEPSSEnrich = c.PostForm("enable_epss_enrich") == "on"
		profile.EnableVulnCheckKEV = c.PostForm("enable_vulncheck_kev") == "on"
		profile.EnableGreyNoise = c.PostForm("enable_greynoise") == "on"
		profile.EnableVisionAnalysis = c.PostForm("enable_vision_analysis") == "on"
		profile.EnableAutoReport = c.PostForm("enable_auto_report") == "on"

		db.Save(profile)
		c.Redirect(http.StatusFound, "/asset/"+id+"/settings")
	})
	// Settings
	r.GET("/settings", func(c *gin.Context) {
		var rawSettings []database.Setting
		database.GetDB().Find(&rawSettings)

		// Decrypt values before passing to template
		settings := make([]database.Setting, len(rawSettings))
		activeProvider := ""
		for i, s := range rawSettings {
			settings[i] = s
			settings[i].Value = crypto.Decrypt(s.Value)
			if s.Key == "OVERLORD_ACTIVE_PROVIDER" {
				activeProvider = settings[i].Value
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
			setting.Value = crypto.Encrypt(value)
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
			s.Value = crypto.Encrypt(v)
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
			s.Value = crypto.Encrypt(v)
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

	// Plugin SDK — list all registered tools, agents, pipelines, and manifests.
	r.GET("/api/plugins", func(c *gin.Context) {
		type toolInfo struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		type agentInfo struct {
			Name  string   `json:"name"`
			Tools []string `json:"tools"`
		}
		type pipelineInfo struct {
			Name  string               `json:"name"`
			Steps []plugin.PipelineStep `json:"steps"`
		}

		var ts []toolInfo
		for _, t := range plugin.AllTools() {
			ts = append(ts, toolInfo{Name: t.Name(), Description: t.Description()})
		}
		var as []agentInfo
		for _, a := range plugin.AllAgents() {
			names := make([]string, 0, len(a.Tools()))
			for _, t := range a.Tools() {
				names = append(names, t.Name())
			}
			as = append(as, agentInfo{Name: a.Name(), Tools: names})
		}
		var ps []pipelineInfo
		for name, steps := range plugin.AllPipelines() {
			ps = append(ps, pipelineInfo{Name: name, Steps: steps})
		}

		c.JSON(http.StatusOK, gin.H{
			"tools":     ts,
			"agents":    as,
			"pipelines": ps,
			"manifests": plugin.AllManifests(),
		})
	})

	// -------------------------------------------------------------------------
	// Finding Normalization Engine API
	// -------------------------------------------------------------------------

	// POST /api/normalize — normalize raw scanner output into canonical findings.
	// Body: {"source": "nuclei", "raw": { ... }}
	r.POST("/api/normalize", func(c *gin.Context) {
		var body struct {
			Source string         `json:"source" binding:"required"`
			Raw    map[string]any `json:"raw"    binding:"required"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		nFindings, groups, err := normalization.Run(body.Source, body.Raw)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		db := database.GetDB()
		var saveErrors []string
		for _, f := range nFindings {
			if err := findingsrepo.SaveFinding(db, f); err != nil {
				saveErrors = append(saveErrors, err.Error())
			}
		}
		for _, g := range groups {
			if err := findingsrepo.SaveGroup(db, g); err != nil {
				saveErrors = append(saveErrors, err.Error())
			}
		}
		resp := gin.H{"findings": nFindings, "groups": groups, "count": len(nFindings)}
		if len(saveErrors) > 0 {
			resp["save_errors"] = saveErrors
		}
		c.JSON(http.StatusOK, resp)
	})

	// GET /api/findings — list normalized findings.
	// Query params: source, severity, cwe, cve, target, kev
	r.GET("/api/findings", func(c *gin.Context) {
		filters := make(map[string]string)
		for _, key := range []string{"source", "severity", "cwe", "cve", "target", "kev"} {
			if v := c.Query(key); v != "" {
				filters[key] = v
			}
		}
		list, err := findingsrepo.ListFindings(database.GetDB(), filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"findings": list, "count": len(list)})
	})

	// GET /api/findings/:id — fetch a single finding by ID.
	r.GET("/api/findings/:id", func(c *gin.Context) {
		f, err := findingsrepo.GetFindingByID(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, f)
	})

	// GET /api/groups — list finding groups with their member findings.
	r.GET("/api/groups", func(c *gin.Context) {
		groups, err := findingsrepo.ListGroups(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"groups": groups, "count": len(groups)})
	})

	// -------------------------------------------------------------------------
	// Repo Scanner API
	// -------------------------------------------------------------------------

	// POST /api/repos/add — register a new Git repository target.
	// Body: {"url": "https://github.com/...", "branch": "main"}
	r.POST("/api/repos/add", func(c *gin.Context) {
		var req struct {
			URL    string `json:"url" binding:"required"`
			Branch string `json:"branch"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Branch == "" {
			req.Branch = "main"
		}
		target := repos.RepoTarget{
			ID:     repos.NewID(),
			URL:    req.URL,
			Branch: req.Branch,
		}
		if err := repostore.SaveRepoTarget(database.GetDB(), target); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, target)
	})

	// GET /api/repos — list all tracked repositories.
	r.GET("/api/repos", func(c *gin.Context) {
		targets, err := repostore.ListRepoTargets(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"repos": targets, "count": len(targets)})
	})

	// DELETE /api/repos/:id — remove a repository and all its scan data.
	r.DELETE("/api/repos/:id", func(c *gin.Context) {
		if err := repostore.DeleteRepoTarget(database.GetDB(), c.Param("id")); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// repoScanMu serializes concurrent scan-trigger calls to the same repo.
	var repoScanMu sync.Mutex

	// POST /api/repos/scan/:id — trigger an async repo scan.
	// Returns 202 immediately; client polls /api/repos/:id/findings.
	r.POST("/api/repos/scan/:id", func(c *gin.Context) {
		id := c.Param("id")
		target, err := repostore.GetRepoTarget(database.GetDB(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "repo not found"})
			return
		}
		go func() {
			repoScanMu.Lock()
			defer repoScanMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			if _, err := repo_scanner.ScanRepo(ctx, database.GetDB(), target); err != nil {
				utils.LogDebug("[repo_scanner] scan failed for %s: %v", target.URL, err)
			}
		}()
		c.JSON(http.StatusAccepted, gin.H{"status": "scan started", "repo_id": id})
	})

	// GET /api/repos/:id/findings — list findings for a specific repository.
	// Query params: source, severity, cwe, cve, kev
	r.GET("/api/repos/:id/findings", func(c *gin.Context) {
		filters := make(map[string]string)
		for _, key := range []string{"source", "severity", "cwe", "cve", "kev"} {
			if v := c.Query(key); v != "" {
				filters[key] = v
			}
		}
		findings, err := repostore.ListRepoFindings(database.GetDB(), c.Param("id"), filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"findings": findings, "count": len(findings)})
	})

	// GET /api/repos/:id/sbom — return the latest SBOM for a repository.
	r.GET("/api/repos/:id/sbom", func(c *gin.Context) {
		s, err := repostore.GetLatestSBOM(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no SBOM found for this repo"})
			return
		}
		c.JSON(http.StatusOK, s)
	})

	// SSE endpoint: real-time scan stage progress for the dashboard
	r.GET("/api/scan/events", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")

		mgr := core.GetManager()
		ch := mgr.Subscribe()
		defer mgr.Unsubscribe(ch)

		// Flush headers immediately
		c.Writer.WriteHeader(http.StatusOK)
		if f, ok := c.Writer.(http.Flusher); ok {
			f.Flush()
		}

		ctx := c.Request.Context()
		for {
			select {
			case evt, ok := <-ch:
				if !ok {
					return
				}
				data, err := json.Marshal(evt)
				if err != nil {
					continue
				}
				fmt.Fprintf(c.Writer, "data: %s\n\n", data)
				if f, ok := c.Writer.(http.Flusher); ok {
					f.Flush()
				}
			case <-ctx.Done():
				return
			}
		}
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

	// -------------------------------------------------------------------------
	// Scan Graph API
	// -------------------------------------------------------------------------

	// GET /graph — serve the interactive graph visualization page.
	r.GET("/graph", func(c *gin.Context) {
		c.HTML(http.StatusOK, "graph.html", getGlobalContext(gin.H{
			"Page": "graph",
		}))
	})

	// GET /api/graph — build and return the full ScanGraph as JSON.
	// The freshly-built graph is saved as a snapshot for query helpers.
	r.GET("/api/graph", func(c *gin.Context) {
		g, err := graph.BuildGraph(c.Request.Context(), database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Save snapshot asynchronously — don't block the response.
		go func() {
			if saveErr := graphstore.SaveGraph(database.GetDB(), g); saveErr != nil {
				utils.LogDebug("[graph] save snapshot: %v", saveErr)
			}
			_ = graphstore.PruneSnapshots(database.GetDB(), 5)
		}()
		c.JSON(http.StatusOK, g)
	})

	// GET /api/graph/nodes — return all nodes with optional ?type= filter.
	r.GET("/api/graph/nodes", func(c *gin.Context) {
		g, err := graph.BuildGraph(c.Request.Context(), database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		filter := c.Query("type")
		nodes := g.Nodes
		if filter != "" {
			filtered := make([]graph.GraphNode, 0)
			for _, n := range g.Nodes {
				if string(n.Type) == filter {
					filtered = append(filtered, n)
				}
			}
			nodes = filtered
		}
		c.JSON(http.StatusOK, gin.H{"nodes": nodes, "count": len(nodes)})
	})

	// GET /api/graph/edges — return all edges with optional ?kind= filter.
	r.GET("/api/graph/edges", func(c *gin.Context) {
		g, err := graph.BuildGraph(c.Request.Context(), database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		filter := c.Query("kind")
		edges := g.Edges
		if filter != "" {
			filtered := make([]graph.GraphEdge, 0)
			for _, e := range g.Edges {
				if e.Kind == filter {
					filtered = append(filtered, e)
				}
			}
			edges = filtered
		}
		c.JSON(http.StatusOK, gin.H{"edges": edges, "count": len(edges)})
	})

	// GET /api/graph/node/:id — return a single node from the latest snapshot.
	r.GET("/api/graph/node/:id", func(c *gin.Context) {
		node, err := graphstore.GetNodeByID(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
			return
		}
		// Also return connected edges from the latest snapshot.
		edgesFrom, _ := graphstore.GetEdgesFrom(database.GetDB(), node.ID)
		edgesTo, _ := graphstore.GetEdgesTo(database.GetDB(), node.ID)
		c.JSON(http.StatusOK, gin.H{
			"node":       node,
			"edges_from": edgesFrom,
			"edges_to":   edgesTo,
		})
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

	// -------------------------------------------------------------------------
	// Reports
	// -------------------------------------------------------------------------

	// GET /api/assets — return all assets as JSON (for report generator and other JS).
	r.GET("/api/assets", func(c *gin.Context) {
		var assets []database.Asset
		database.GetDB().Select("id, name").Find(&assets)
		c.JSON(http.StatusOK, gin.H{"assets": assets})
	})

	// GET /reports — serve the report generator UI page.
	r.GET("/reports", func(c *gin.Context) {
		c.HTML(http.StatusOK, "reports.html", getGlobalContext(gin.H{"Page": "reports"}))
	})

	// POST /api/reports/generate — generate a new report from findings.
	r.POST("/api/reports/generate", func(c *gin.Context) {
		var req reports.ReportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}
		if len(req.AssetIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "at least one asset_id is required"})
			return
		}
		if req.Format == "" {
			req.Format = reports.FormatMarkdown
		}

		// Build the Overlord generator function if Overlord is reachable.
		var overlordGen func(data reports.ReportData, format reports.ReportFormat) (string, error)
		if status := overlord.CheckConnection(); status.Connected {
			overlordGen = func(data reports.ReportData, format reports.ReportFormat) (string, error) {
				prompt, err := reports.BuildOverlordPrompt(data, format)
				if err != nil {
					return "", err
				}
				sess, err := overlord.CreateSession("Report: " + data.Title)
				if err != nil {
					return "", err
				}
				if err := overlord.SendPromptAsync(sess.ID, prompt, ""); err != nil {
					return "", err
				}
				// Poll for completion (max 3 minutes, every 3 seconds)
				deadline := time.Now().Add(3 * time.Minute)
				var lastText string
				var stableCount int
				for time.Now().Before(deadline) {
					time.Sleep(3 * time.Second)
					messages, err := overlord.GetSessionMessages(sess.ID)
					if err != nil {
						continue
					}
					text := reports.ExtractAssistantText(messages)
					if text != "" && text == lastText {
						stableCount++
						if stableCount >= 2 {
							return text, nil
						}
					} else {
						lastText = text
						stableCount = 0
					}
				}
				if lastText != "" {
					return lastText, nil
				}
				return "", fmt.Errorf("overlord: timed out waiting for response")
			}
		}

		report, err := reports.GenerateReport(c.Request.Context(), database.GetDB(), req, overlordGen)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Persist the report
		if saveErr := reportstore.SaveReport(database.GetDB(), reportstore.ReportRecord{
			ID:        report.ID,
			Format:    string(report.Format),
			Title:     report.Title,
			Content:   report.Content,
			Status:    string(report.Status),
			CreatedAt: report.CreatedAt,
		}); saveErr != nil {
			// Non-fatal — still return the report to the client
			utils.LogError("failed to save report: %v", saveErr)
		}

		c.JSON(http.StatusOK, report)
	})

	// GET /api/reports — list all saved reports.
	r.GET("/api/reports", func(c *gin.Context) {
		records, err := reportstore.ListReports(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Return summary (omit content for list view)
		type reportSummary struct {
			ID        string    `json:"id"`
			Format    string    `json:"format"`
			Title     string    `json:"title"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}
		summaries := make([]reportSummary, len(records))
		for i, r := range records {
			summaries[i] = reportSummary{
				ID:        r.ID,
				Format:    r.Format,
				Title:     r.Title,
				Status:    r.Status,
				CreatedAt: r.CreatedAt,
			}
		}
		c.JSON(http.StatusOK, gin.H{"reports": summaries})
	})

	// GET /api/reports/:id — fetch a single report with full content.
	r.GET("/api/reports/:id", func(c *gin.Context) {
		rec, err := reportstore.GetReport(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
			return
		}
		c.JSON(http.StatusOK, rec)
	})

	// GET /api/reports/:id/download — download a report as file.
	// ?format=pdf converts to PDF (requires wkhtmltopdf); default is raw Markdown.
	r.GET("/api/reports/:id/download", func(c *gin.Context) {
		rec, err := reportstore.GetReport(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
			return
		}
		dl := c.DefaultQuery("format", "md")
		filename := "report-" + rec.ID
		if dl == "pdf" {
			pdfBytes, err := exporter.MarkdownToPDF(rec.Content)
			if err != nil {
				// Fall back to HTML
				html := exporter.MarkdownToHTML(rec.Content)
				c.Header("Content-Disposition", `attachment; filename="`+filename+`.html"`)
				c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
				return
			}
			c.Header("Content-Disposition", `attachment; filename="`+filename+`.pdf"`)
			c.Data(http.StatusOK, "application/pdf", pdfBytes)
			return
		}
		if dl == "html" {
			html := exporter.MarkdownToHTML(rec.Content)
			c.Header("Content-Disposition", `attachment; filename="`+filename+`.html"`)
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
			return
		}
		c.Header("Content-Disposition", `attachment; filename="`+filename+`.md"`)
		c.Data(http.StatusOK, "text/markdown; charset=utf-8", []byte(rec.Content))
	})

	// DELETE /api/reports/:id — delete a report.
	r.DELETE("/api/reports/:id", func(c *gin.Context) {
		if err := reportstore.DeleteReport(database.GetDB(), c.Param("id")); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// -------------------------------------------------------------------------
	// Scan Plan Optimizer
	// -------------------------------------------------------------------------

	// activePlanLogs holds log channels for currently executing plans.
	// Key = plan ID, value = channel of StepLog. Channel is closed when done.
	type planLogEntry struct {
		ch   chan planner.StepLog
		plan *planner.ScanPlan
	}
	var (
		planLogsMu sync.Mutex
		planLogMap = map[string]*planLogEntry{}
	)

	// GET /planner — serve the scan plan optimizer UI page.
	r.GET("/planner", func(c *gin.Context) {
		c.HTML(http.StatusOK, "planner.html", getGlobalContext(gin.H{"Page": "planner"}))
	})

	// POST /api/planner/generate — generate a new AI scan plan.
	r.POST("/api/planner/generate", func(c *gin.Context) {
		var req planner.PlannerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}
		if len(req.AssetIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "at least one asset_id is required"})
			return
		}

		plan, err := planner.GenerateScanPlan(c.Request.Context(), database.GetDB(), req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Persist
		stepsJSON, _ := planstore.MarshalSteps(plan.Steps)
		if saveErr := planstore.SavePlan(database.GetDB(), planstore.PlanRecord{
			ID:        plan.ID,
			AssetIDs:  planstore.MarshalAssetIDs(plan.AssetIDs),
			Mode:      string(plan.Mode),
			StepsJSON: stepsJSON,
			Status:    string(plan.Status),
			CreatedAt: plan.CreatedAt,
			UpdatedAt: plan.UpdatedAt,
		}); saveErr != nil {
			utils.LogError("planstore: save failed: %v", saveErr)
		}

		c.JSON(http.StatusOK, plan)
	})

	// GET /api/planner/plans — list all saved plans.
	r.GET("/api/planner/plans", func(c *gin.Context) {
		recs, err := planstore.ListPlans(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		type planSummary struct {
			ID        string    `json:"id"`
			Mode      string    `json:"mode"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}
		out := make([]planSummary, len(recs))
		for i, r := range recs {
			out[i] = planSummary{ID: r.ID, Mode: r.Mode, Status: r.Status, CreatedAt: r.CreatedAt}
		}
		c.JSON(http.StatusOK, gin.H{"plans": out})
	})

	// GET /api/planner/plans/:id — fetch a single plan with full step detail.
	r.GET("/api/planner/plans/:id", func(c *gin.Context) {
		rec, err := planstore.GetPlan(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "plan not found"})
			return
		}
		c.JSON(http.StatusOK, rec)
	})

	// POST /api/planner/execute/:id — start executing a plan asynchronously.
	// Returns 202 immediately; client streams logs via SSE at /api/planner/execute/:id/logs.
	r.POST("/api/planner/execute/:id", func(c *gin.Context) {
		id := c.Param("id")

		planLogsMu.Lock()
		if _, running := planLogMap[id]; running {
			planLogsMu.Unlock()
			c.JSON(http.StatusConflict, gin.H{"error": "plan is already executing"})
			return
		}
		planLogsMu.Unlock()

		rec, err := planstore.GetPlan(database.GetDB(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "plan not found"})
			return
		}

		// Decode steps from JSON
		var steps []planner.PlanStep
		if err := json.Unmarshal([]byte(rec.StepsJSON), &steps); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not decode plan steps"})
			return
		}

		plan := &planner.ScanPlan{
			ID:       rec.ID,
			Mode:     planner.Mode(rec.Mode),
			Steps:    steps,
			Status:   planner.StatusExecuting,
		}

		logCh := make(chan planner.StepLog, 500)
		entry := &planLogEntry{ch: logCh, plan: plan}
		planLogsMu.Lock()
		planLogMap[id] = entry
		planLogsMu.Unlock()

		go func() {
			defer func() {
				close(logCh)
				planLogsMu.Lock()
				delete(planLogMap, id)
				planLogsMu.Unlock()
			}()

			execErr := planner.ExecutePlanWithLogs(context.Background(), database.GetDB(), plan, logCh)

			// Persist updated steps
			stepsJSON, _ := planstore.MarshalSteps(plan.Steps)
			status := string(planner.StatusDone)
			errStr := ""
			if execErr != nil {
				status = string(planner.StatusFailed)
				errStr = execErr.Error()
			}
			planstore.SavePlan(database.GetDB(), planstore.PlanRecord{
				ID:        rec.ID,
				AssetIDs:  rec.AssetIDs,
				Mode:      rec.Mode,
				StepsJSON: stepsJSON,
				Status:    status,
				Error:     errStr,
				CreatedAt: rec.CreatedAt,
				UpdatedAt: time.Now().UTC(),
			})
		}()

		c.JSON(http.StatusAccepted, gin.H{"status": "executing", "plan_id": id})
	})

	// GET /api/planner/execute/:id/logs — SSE stream of execution log lines.
	r.GET("/api/planner/execute/:id/logs", func(c *gin.Context) {
		id := c.Param("id")

		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")

		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
			return
		}

		// Wait briefly for the execution goroutine to register the channel
		var entry *planLogEntry
		for i := 0; i < 10; i++ {
			planLogsMu.Lock()
			entry = planLogMap[id]
			planLogsMu.Unlock()
			if entry != nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}

		if entry == nil {
			fmt.Fprintf(c.Writer, "data: {\"error\":\"plan %s is not executing\"}\n\n", id)
			flusher.Flush()
			return
		}

		ctx := c.Request.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case log, open := <-entry.ch:
				if !open {
					fmt.Fprintf(c.Writer, "data: {\"done\":true}\n\n")
					flusher.Flush()
					return
				}
				msg := strings.ReplaceAll(log.Message, "\n", " ")
				fmt.Fprintf(c.Writer, "data: {\"step_id\":%q,\"msg\":%q}\n\n", log.StepID, msg)
				flusher.Flush()
			}
		}
	})

	// DELETE /api/planner/plans/:id — delete a saved plan.
	r.DELETE("/api/planner/plans/:id", func(c *gin.Context) {
		if err := planstore.DeletePlan(database.GetDB(), c.Param("id")); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// -------------------------------------------------------------------------
	// Chat Interface (#12) — Natural language scan control
	// -------------------------------------------------------------------------

	r.GET("/chat", func(c *gin.Context) {
		c.HTML(http.StatusOK, "chat.html", getGlobalContext(gin.H{"Page": "chat"}))
	})

	r.POST("/api/chat", func(c *gin.Context) {
		var req struct {
			Message string `json:"message"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Message == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "message required"})
			return
		}
		reply, action := handleChatMessage(database.GetDB(), req.Message)
		c.JSON(http.StatusOK, gin.H{"reply": reply, "action": action})
	})

	// -------------------------------------------------------------------------
	// Distributed Workers & Jobs
	// -------------------------------------------------------------------------

	// Instantiate the controller (starts background heartbeat monitor)
	ctrl := controller.New(database.GetDB())
	_ = ctrl // used by handlers below via closure

	// Embedded local worker — can be started/stopped from the Workers UI.
	lw := localworker.New(database.GetDB(), ctrl)

	// POST /api/workers/local/start — launch the embedded local worker.
	r.POST("/api/workers/local/start", func(c *gin.Context) {
		if lw.IsRunning() {
			c.JSON(http.StatusOK, gin.H{"status": "already_running"})
			return
		}
		if err := lw.Start(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "started", "worker_id": localworker.LocalWorkerID})
	})

	// POST /api/workers/local/stop — stop the embedded local worker.
	r.POST("/api/workers/local/stop", func(c *gin.Context) {
		lw.Stop()
		c.JSON(http.StatusOK, gin.H{"status": "stopped"})
	})

	// GET /api/workers/local/status — check if embedded worker is running.
	r.GET("/api/workers/local/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"running": lw.IsRunning(), "worker_id": localworker.LocalWorkerID})
	})

	// workerAuth is a middleware that validates X-Worker-Token on worker-facing routes.
	workerAuth := func(c *gin.Context) {
		token := c.GetHeader("X-Worker-Token")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-Worker-Token"})
			return
		}
		workerID, err := ctrl.ValidateToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("workerID", workerID)
		c.Next()
	}

	// GET /workers — serve the workers & jobs dashboard.
	r.GET("/workers", func(c *gin.Context) {
		c.HTML(http.StatusOK, "workers.html", getGlobalContext(gin.H{"Page": "workers"}))
	})

	// ------------------------------------------------------------------
	// Worker registration & heartbeat (no auth required on register)
	// ------------------------------------------------------------------

	// POST /api/workers/register — worker registers on startup.
	// Body: { "id", "hostname", "address", "capabilities": [], "labels": [] }
	r.POST("/api/workers/register", func(c *gin.Context) {
		var req struct {
			ID           string   `json:"id" binding:"required"`
			Hostname     string   `json:"hostname"`
			Address      string   `json:"address"`
			Capabilities []string `json:"capabilities"`
			Labels       []string `json:"labels"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		token, err := ctrl.RegisterWorker(req.ID, req.Hostname, req.Address, req.Capabilities, req.Labels)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token, "worker_id": req.ID})
	})

	// POST /api/workers/heartbeat — worker pings every 10s.
	// Requires X-Worker-Token.
	r.POST("/api/workers/heartbeat", workerAuth, func(c *gin.Context) {
		workerID := c.GetString("workerID")
		if err := ctrl.Heartbeat(workerID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// GET /api/workers — list all registered workers (UI / admin use).
	r.GET("/api/workers", func(c *gin.Context) {
		workers, err := workerstore.ListWorkers(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Decode JSON columns for the response
		type workerView struct {
			ID           string    `json:"id"`
			Hostname     string    `json:"hostname"`
			Address      string    `json:"address"`
			Capabilities []string  `json:"capabilities"`
			Labels       []string  `json:"labels"`
			Status       string    `json:"status"`
			ActiveJobs   int       `json:"active_jobs"`
			LastSeen     time.Time `json:"last_seen"`
		}
		out := make([]workerView, len(workers))
		for i, w := range workers {
			out[i] = workerView{
				ID:           w.ID,
				Hostname:     w.Hostname,
				Address:      w.Address,
				Capabilities: workerstore.UnmarshalStringSlice(w.Capabilities),
				Labels:       workerstore.UnmarshalStringSlice(w.Labels),
				Status:       w.Status,
				ActiveJobs:   w.ActiveJobs,
				LastSeen:     w.LastSeen,
			}
		}
		c.JSON(http.StatusOK, gin.H{"workers": out})
	})

	// DELETE /api/workers/:id — deregister a worker.
	r.DELETE("/api/workers/:id", func(c *gin.Context) {
		if err := workerstore.DeleteWorker(database.GetDB(), c.Param("id")); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// ------------------------------------------------------------------
	// Job management (UI → controller)
	// ------------------------------------------------------------------

	// POST /api/jobs/create — enqueue a new job.
	// Body: { "tool": "subfinder", "payload": { "target": "example.com" } }
	r.POST("/api/jobs/create", func(c *gin.Context) {
		var req struct {
			Tool    string         `json:"tool" binding:"required"`
			Payload map[string]any `json:"payload"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Payload == nil {
			req.Payload = map[string]any{}
		}
		job, err := ctrl.CreateJob(req.Tool, req.Payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, job)
	})

	// GET /api/jobs — list all jobs, optional ?status= filter.
	r.GET("/api/jobs", func(c *gin.Context) {
		status := c.Query("status")
		jobs, err := jobstore.ListJobs(database.GetDB(), status)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Decode payload/result JSON columns
		type jobView struct {
			ID        string         `json:"id"`
			WorkerID  string         `json:"worker_id"`
			Tool      string         `json:"tool"`
			Payload   map[string]any `json:"payload"`
			Status    string         `json:"status"`
			Result    map[string]any `json:"result"`
			Error     string         `json:"error,omitempty"`
			CreatedAt time.Time      `json:"created_at"`
			UpdatedAt time.Time      `json:"updated_at"`
		}
		out := make([]jobView, len(jobs))
		for i, j := range jobs {
			out[i] = jobView{
				ID:        j.ID,
				WorkerID:  j.WorkerID,
				Tool:      j.Tool,
				Payload:   jobstore.UnmarshalPayload(j.Payload),
				Status:    j.Status,
				Result:    jobstore.UnmarshalPayload(j.Result),
				Error:     j.Error,
				CreatedAt: j.CreatedAt,
				UpdatedAt: j.UpdatedAt,
			}
		}
		c.JSON(http.StatusOK, gin.H{"jobs": out})
	})

	// GET /api/jobs/:id — fetch a single job with full result.
	r.GET("/api/jobs/:id", func(c *gin.Context) {
		job, err := jobstore.GetJob(database.GetDB(), c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"id":         job.ID,
			"worker_id":  job.WorkerID,
			"tool":       job.Tool,
			"payload":    jobstore.UnmarshalPayload(job.Payload),
			"status":     job.Status,
			"result":     jobstore.UnmarshalPayload(job.Result),
			"error":      job.Error,
			"created_at": job.CreatedAt,
			"updated_at": job.UpdatedAt,
		})
	})

	// DELETE /api/jobs/:id — remove a job.
	r.DELETE("/api/jobs/:id", func(c *gin.Context) {
		if err := jobstore.DeleteJob(database.GetDB(), c.Param("id")); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// ------------------------------------------------------------------
	// Worker ↔ Controller job handoff (authenticated)
	// ------------------------------------------------------------------

	// GET /api/workers/:id/jobs/next — worker polls for its next job.
	// Returns 200 + job JSON if a job was claimed, or 204 No Content if queue empty.
	r.GET("/api/workers/:id/jobs/next", workerAuth, func(c *gin.Context) {
		workerID := c.GetString("workerID")

		// Load capabilities from DB so the scheduler knows what this worker can run
		w, err := workerstore.GetWorker(database.GetDB(), workerID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "worker not registered"})
			return
		}
		tools := workerstore.UnmarshalStringSlice(w.Capabilities)

		job, err := ctrl.ClaimNextJob(workerID, tools)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if job == nil {
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"id":      job.ID,
			"tool":    job.Tool,
			"payload": jobstore.UnmarshalPayload(job.Payload),
		})
	})

	// POST /api/workers/:id/jobs/:jobid/result — worker submits result.
	r.POST("/api/workers/:id/jobs/:jobid/result", workerAuth, func(c *gin.Context) {
		workerID := c.GetString("workerID")
		jobID := c.Param("jobid")

		var body struct {
			Result map[string]any `json:"result"`
			Error  string         `json:"error"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := ctrl.RecordJobResult(workerID, jobID, body.Result, body.Error); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "recorded"})
	})

	// -------------------------------------------------------------------------
	// Authentication
	// -------------------------------------------------------------------------

	// GET /login — login page
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{"Page": "login"})
	})

	// POST /api/auth/login
	r.POST("/api/auth/login", func(c *gin.Context) {
		var body struct {
			Password string `json:"password" form:"password"`
		}
		c.ShouldBind(&body) //nolint:errcheck
		var setting database.Setting
		if err := database.GetDB().Where("key = ?", authSettingKey).First(&setting).Error; err != nil || setting.Value == "" {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		if hashPassword(body.Password) != setting.Value {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
			return
		}
		tok := createSession()
		c.SetCookie(authCookieName, tok, 86400, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// POST /api/auth/logout
	r.POST("/api/auth/logout", func(c *gin.Context) {
		if tok, err := c.Cookie(authCookieName); err == nil {
			destroySession(tok)
		}
		c.SetCookie(authCookieName, "", -1, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// POST /api/settings/password — set or change the UI password
	r.POST("/api/settings/password", func(c *gin.Context) {
		var body struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		value := ""
		if body.Password != "" {
			value = hashPassword(body.Password)
		}
		db := database.GetDB()
		var s database.Setting
		db.Where("key = ?", authSettingKey).First(&s)
		s.Key = authSettingKey
		s.Value = value
		s.Description = "UI access password (SHA-256 hashed)"
		db.Save(&s)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// -------------------------------------------------------------------------
	// Repo Scanner UI
	// -------------------------------------------------------------------------

	r.GET("/repos", func(c *gin.Context) {
		c.HTML(http.StatusOK, "repos.html", getGlobalContext(gin.H{"Page": "repos"}))
	})

	// -------------------------------------------------------------------------
	// Nuclei Template Browser
	// -------------------------------------------------------------------------

	r.GET("/nuclei", func(c *gin.Context) {
		c.HTML(http.StatusOK, "nuclei.html", getGlobalContext(gin.H{"Page": "nuclei"}))
	})

	// -------------------------------------------------------------------------
	// Scheduled Scans
	// -------------------------------------------------------------------------

	r.GET("/schedules", func(c *gin.Context) {
		c.HTML(http.StatusOK, "schedules.html", getGlobalContext(gin.H{"Page": "schedules"}))
	})

	r.GET("/api/schedules", func(c *gin.Context) {
		list, err := schedulestore.List(database.GetDB())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"schedules": list})
	})

	r.POST("/api/schedules", func(c *gin.Context) {
		var body struct {
			AssetID   uint   `json:"asset_id"`
			IntervalH int    `json:"interval_h"`
			Label     string `json:"label"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || body.AssetID == 0 || body.IntervalH < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "asset_id and interval_h (>=1) required"})
			return
		}
		var asset database.Asset
		if err := database.GetDB().First(&asset, body.AssetID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		label := body.Label
		if label == "" {
			label = fmt.Sprintf("Every %dh", body.IntervalH)
		}
		rec := &schedulestore.ScheduleRecord{
			AssetID:   body.AssetID,
			AssetName: asset.Name,
			Label:     label,
			IntervalH: body.IntervalH,
			Enabled:   true,
			NextRunAt: time.Now().Add(time.Duration(body.IntervalH) * time.Hour),
		}
		if err := schedulestore.Create(database.GetDB(), rec); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, rec)
	})

	r.POST("/api/schedules/:id/toggle", func(c *gin.Context) {
		var id uint
		fmt.Sscanf(c.Param("id"), "%d", &id)
		rec, err := schedulestore.GetByID(database.GetDB(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "schedule not found"})
			return
		}
		schedulestore.SetEnabled(database.GetDB(), id, !rec.Enabled) //nolint:errcheck
		c.JSON(http.StatusOK, gin.H{"enabled": !rec.Enabled})
	})

	r.DELETE("/api/schedules/:id", func(c *gin.Context) {
		var id uint
		fmt.Sscanf(c.Param("id"), "%d", &id)
		schedulestore.Delete(database.GetDB(), id) //nolint:errcheck
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// Background goroutine: check for due schedules every minute and fire scans.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			due, err := schedulestore.ListDue(database.GetDB())
			if err != nil {
				continue
			}
			for _, s := range due {
				schedulestore.MarkRan(database.GetDB(), s.ID)     //nolint:errcheck
				schedulestore.BumpNextRun(database.GetDB(), s.ID, s.IntervalH) //nolint:errcheck
				var asset database.Asset
				if database.GetDB().Preload("Targets").First(&asset, s.AssetID).Error != nil {
					continue
				}
				for _, t := range asset.Targets {
					go core.GetManager().StartScan(t.Value, asset.Name)
				}
			}
		}
	}()

	// -------------------------------------------------------------------------
	// Scan History & Diffing
	// -------------------------------------------------------------------------

	r.GET("/history", func(c *gin.Context) {
		c.HTML(http.StatusOK, "history.html", getGlobalContext(gin.H{"Page": "history"}))
	})

	r.GET("/api/history/:assetID", func(c *gin.Context) {
		var assetID uint
		fmt.Sscanf(c.Param("assetID"), "%d", &assetID)
		snaps, err := scanhistorystore.ListByAsset(database.GetDB(), assetID, 20)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"snapshots": snaps})
	})

	r.GET("/api/history/snapshot/:id", func(c *gin.Context) {
		var id uint
		fmt.Sscanf(c.Param("id"), "%d", &id)
		snap, findings, err := scanhistorystore.GetByID(database.GetDB(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "snapshot not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"snapshot": snap, "findings": findings})
	})

	r.GET("/api/history/diff/:idA/:idB", func(c *gin.Context) {
		var idA, idB uint
		fmt.Sscanf(c.Param("idA"), "%d", &idA)
		fmt.Sscanf(c.Param("idB"), "%d", &idB)
		_, findingsA, errA := scanhistorystore.GetByID(database.GetDB(), idA)
		_, findingsB, errB := scanhistorystore.GetByID(database.GetDB(), idB)
		if errA != nil || errB != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "one or both snapshots not found"})
			return
		}
		diff := scanhistorystore.Diff(findingsA, findingsB)
		c.JSON(http.StatusOK, diff)
	})

	// POST /api/history/snapshot — manually capture a snapshot of an asset now
	r.POST("/api/history/snapshot", func(c *gin.Context) {
		var body struct {
			AssetID uint `json:"asset_id"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || body.AssetID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "asset_id required"})
			return
		}
		snap, findings, err := captureSnapshot(database.GetDB(), body.AssetID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if saveErr := scanhistorystore.Save(database.GetDB(), snap, findings); saveErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": saveErr.Error()})
			return
		}
		scanhistorystore.PruneOld(database.GetDB(), body.AssetID, 50) //nolint:errcheck
		c.JSON(http.StatusCreated, gin.H{"snapshot": snap, "findings_count": len(findings)})
	})

	r.DELETE("/api/history/snapshot/:id", func(c *gin.Context) {
		var id uint
		fmt.Sscanf(c.Param("id"), "%d", &id)
		scanhistorystore.Delete(database.GetDB(), id) //nolint:errcheck
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	// -------------------------------------------------------------------------
	// Findings Dedup View
	// -------------------------------------------------------------------------

	r.GET("/findings", func(c *gin.Context) {
		c.HTML(http.StatusOK, "findings.html", getGlobalContext(gin.H{"Page": "findings"}))
	})

	// GET /api/findings/deduplicated — aggregate findings across all assets
	r.GET("/api/findings/deduplicated", func(c *gin.Context) {
		db := database.GetDB()
		type Row struct {
			Name           string  `json:"name"`
			Severity       string  `json:"severity"`
			TemplateID     string  `json:"template_id"`
			CveID          string  `json:"cve_id"`
			AffectedCount  int     `json:"affected_count"`
			MaxCVSS        float64 `json:"max_cvss"`
			IsKEV          bool    `json:"is_kev"`
			InVulnCheckKEV bool    `json:"in_vulncheck_kev"`
			EpssScore      float64 `json:"epss_score"`
			EpssPercentile float64 `json:"epss_percentile"`
			RiskScore      float64 `json:"risk_score"`
			FpStatus       string  `json:"fp_status"`
		}

		severity := c.Query("severity")

		var vulns []database.Vulnerability
		showFP := c.Query("show_fp") == "true"
		q := db.Select("name, severity, template_id, fp_status")
		if !showFP {
			q = q.Where("fp_status != 'false_positive'")
		}
		if severity != "" {
			q = q.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		q.Find(&vulns)

		// Deduplicate by name+templateID
		type key struct{ Name, TemplateID string }
		agg := map[key]*Row{}
		for _, v := range vulns {
			k := key{v.Name, v.TemplateID}
			if _, ok := agg[k]; !ok {
				agg[k] = &Row{Name: v.Name, Severity: v.Severity, TemplateID: v.TemplateID, FpStatus: v.FpStatus}
			}
			agg[k].AffectedCount++
		}

		// CVEs
		var cves []database.CVE
		cq := db.Select("cve_id, severity, cvss_score, is_kev, in_vulncheck_kev, epss_score, epss_percentile, risk_score, product")
		if severity != "" {
			cq = cq.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		cq.Find(&cves)
		for _, c := range cves {
			k := key{c.CveID, ""}
			if _, ok := agg[k]; !ok {
				agg[k] = &Row{Name: c.CveID, Severity: c.Severity, CveID: c.CveID, IsKEV: c.IsKEV, InVulnCheckKEV: c.InVulnCheckKEV, EpssScore: c.EpssScore, EpssPercentile: c.EpssPercentile, RiskScore: c.RiskScore}
			}
			agg[k].AffectedCount++
			if c.CvssScore > agg[k].MaxCVSS {
				agg[k].MaxCVSS = c.CvssScore
			}
			if c.IsKEV {
				agg[k].IsKEV = true
			}
			if c.InVulnCheckKEV {
				agg[k].InVulnCheckKEV = true
			}
			if c.EpssScore > agg[k].EpssScore {
				agg[k].EpssScore = c.EpssScore
				agg[k].EpssPercentile = c.EpssPercentile
			}
			if c.RiskScore > agg[k].RiskScore {
				agg[k].RiskScore = c.RiskScore
			}
		}

		rows := make([]Row, 0, len(agg))
		for _, v := range agg {
			rows = append(rows, *v)
		}
		sort.Slice(rows, func(i, j int) bool {
			// Primary sort: KEV status (confirmed exploited first)
			iKev := rows[i].IsKEV || rows[i].InVulnCheckKEV
			jKev := rows[j].IsKEV || rows[j].InVulnCheckKEV
			if iKev != jKev {
				return iKev
			}
			// Secondary sort: risk score when available
			if rows[i].RiskScore != rows[j].RiskScore {
				return rows[i].RiskScore > rows[j].RiskScore
			}
			// Tertiary: severity
			order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
			a := order[strings.ToLower(rows[i].Severity)]
			b := order[strings.ToLower(rows[j].Severity)]
			if a != b {
				return a < b
			}
			return rows[i].AffectedCount > rows[j].AffectedCount
		})
		c.JSON(http.StatusOK, gin.H{"findings": rows, "total": len(rows)})
	})

	// -------------------------------------------------------------------------
	// Export Findings
	// -------------------------------------------------------------------------

	// GET /api/export/findings?format=csv|json&severity=&asset_id=
	r.GET("/api/export/findings", func(c *gin.Context) {
		format := c.DefaultQuery("format", "json")
		severity := c.Query("severity")
		assetIDStr := c.Query("asset_id")

		db := database.GetDB()

		type ExportRow struct {
			AssetName   string  `json:"asset_name" csv:"Asset"`
			Target      string  `json:"target" csv:"Target"`
			Type        string  `json:"type" csv:"Type"`
			Name        string  `json:"name" csv:"Name"`
			Severity    string  `json:"severity" csv:"Severity"`
			TemplateID  string  `json:"template_id" csv:"Template ID"`
			CveID       string  `json:"cve_id" csv:"CVE ID"`
			CVSS        float64 `json:"cvss" csv:"CVSS"`
			IsKEV       bool    `json:"is_kev" csv:"KEV"`
			DiscoveredAt string `json:"discovered_at" csv:"Discovered"`
		}

		var rows []ExportRow

		// Build asset→name map
		var assets []database.Asset
		db.Find(&assets)
		assetNames := map[uint]string{}
		for _, a := range assets {
			assetNames[a.ID] = a.Name
		}

		// Targets filter
		targetFilter := []uint{}
		if assetIDStr != "" {
			var assetID uint
			fmt.Sscanf(assetIDStr, "%d", &assetID)
			var targets []database.Target
			db.Where("asset_id = ?", assetID).Find(&targets)
			for _, t := range targets {
				targetFilter = append(targetFilter, t.ID)
			}
		}

		// Vulnerabilities
		var vulns []database.Vulnerability
		vq := db
		if severity != "" {
			vq = vq.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		if len(targetFilter) > 0 {
			vq = vq.Where("target_id IN ?", targetFilter)
		}
		vq.Find(&vulns)

		for _, v := range vulns {
			var t database.Target
			db.First(&t, v.TargetID)
			rows = append(rows, ExportRow{
				AssetName:   assetNames[t.AssetID],
				Target:      t.Value,
				Type:        "vulnerability",
				Name:        v.Name,
				Severity:    v.Severity,
				TemplateID:  v.TemplateID,
				DiscoveredAt: v.CreatedAt.Format(time.RFC3339),
			})
		}

		// CVEs
		var cves []database.CVE
		cq := db
		if severity != "" {
			cq = cq.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		if len(targetFilter) > 0 {
			cq = cq.Where("target_id IN ?", targetFilter)
		}
		cq.Find(&cves)

		for _, cv := range cves {
			var t database.Target
			db.First(&t, cv.TargetID)
			rows = append(rows, ExportRow{
				AssetName:   assetNames[t.AssetID],
				Target:      t.Value,
				Type:        "cve",
				Name:        cv.CveID + " — " + cv.Product,
				Severity:    cv.Severity,
				CveID:       cv.CveID,
				CVSS:        cv.CvssScore,
				IsKEV:       cv.IsKEV,
				DiscoveredAt: cv.CreatedAt.Format(time.RFC3339),
			})
		}

		if format == "csv" {
			c.Header("Content-Disposition", "attachment; filename=findings.csv")
			c.Header("Content-Type", "text/csv")
			w := csv.NewWriter(c.Writer)
			w.Write([]string{"Asset", "Target", "Type", "Name", "Severity", "Template ID", "CVE ID", "CVSS", "KEV", "Discovered"}) //nolint:errcheck
			for _, r := range rows {
				kev := "false"
				if r.IsKEV {
					kev = "true"
				}
				w.Write([]string{r.AssetName, r.Target, r.Type, r.Name, r.Severity, r.TemplateID, r.CveID, fmt.Sprintf("%.1f", r.CVSS), kev, r.DiscoveredAt}) //nolint:errcheck
			}
			w.Flush()
			return
		}

		c.Header("Content-Disposition", "attachment; filename=findings.json")
		c.JSON(http.StatusOK, gin.H{"findings": rows, "total": len(rows)})
	})

	// -------------------------------------------------------------------------
	// Target Import
	// -------------------------------------------------------------------------

	// POST /api/assets/:id/import — bulk import targets from text (one per line)
	r.POST("/api/assets/:id/import", func(c *gin.Context) {
		var assetID uint
		fmt.Sscanf(c.Param("id"), "%d", &assetID)
		var asset database.Asset
		if err := database.GetDB().First(&asset, assetID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}

		var body struct {
			Targets string `json:"targets"` // newline-separated
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		type ImportResult struct {
			Target string `json:"target"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		}
		var results []ImportResult
		added := 0

		lines := strings.Split(strings.ReplaceAll(body.Targets, "\r\n", "\n"), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			normalized := core.NormalizeToHostname(line)
			if normalized == "" {
				normalized = line
			}
			parsed := core.ParseTarget(normalized)
			if parsed.Type == "" {
				results = append(results, ImportResult{Target: line, Status: "skip", Detail: "invalid target"})
				continue
			}
			var existing database.Target
			if database.GetDB().Where("value = ? AND asset_id = ?", normalized, assetID).First(&existing).Error == nil {
				results = append(results, ImportResult{Target: normalized, Status: "skip", Detail: "already exists"})
				continue
			}
			t := database.Target{
				Value:   normalized,
				AssetID: assetID,
				Type:    string(parsed.Type),
			}
			if err := database.GetDB().Create(&t).Error; err != nil {
				results = append(results, ImportResult{Target: normalized, Status: "error", Detail: err.Error()})
			} else {
				results = append(results, ImportResult{Target: normalized, Status: "added"})
				added++
			}
		}

		c.JSON(http.StatusOK, gin.H{"added": added, "results": results})
	})

	return r.Run(":" + port)
}

// captureSnapshot reads the current state of an asset from the DB and returns
// a ScanSnapshot + findings slice ready to be persisted.
func captureSnapshot(db *gorm.DB, assetID uint) (*scanhistorystore.ScanSnapshot, []scanhistorystore.SnapshotFinding, error) {
	var asset database.Asset
	if err := db.Preload("Targets").First(&asset, assetID).Error; err != nil {
		return nil, nil, err
	}

	var portCount int64
	var findings []scanhistorystore.SnapshotFinding

	for _, t := range asset.Targets {
		var ports []database.Port
		db.Where("target_id = ?", t.ID).Find(&ports)
		portCount += int64(len(ports))

		var vulns []database.Vulnerability
		db.Where("target_id = ?", t.ID).Find(&vulns)
		for _, v := range vulns {
			findings = append(findings, scanhistorystore.SnapshotFinding{
				TargetValue: t.Value,
				Name:        v.Name,
				Severity:    v.Severity,
				TemplateID:  v.TemplateID,
			})
		}

		var cves []database.CVE
		db.Where("target_id = ?", t.ID).Find(&cves)
		for _, cv := range cves {
			findings = append(findings, scanhistorystore.SnapshotFinding{
				TargetValue: t.Value,
				Name:        cv.CveID,
				Severity:    cv.Severity,
				CveID:       cv.CveID,
			})
		}
	}

	snap := &scanhistorystore.ScanSnapshot{
		AssetID:     assetID,
		AssetName:   asset.Name,
		ScannedAt:   time.Now().UTC(),
		TargetCount: len(asset.Targets),
		PortCount:   int(portCount),
	}
	return snap, findings, nil
}

// MultiRender implements gin.HTMLRender
type MultiRender struct {
	templates map[string]*template.Template
}

func (r MultiRender) Instance(name string, data any) render.Render {
	tmpl, ok := r.templates[name]
	if !ok || tmpl == nil {
		panic(fmt.Sprintf("template %q not registered — add it to the pages slice in StartServer", name))
	}
	return render.HTML{
		Template: tmpl,
		Name:     "layout.html", // Start execution at layout.html
		Data:     data,
	}
}
