package main

import (
	"flag"
	"log"
	"os"

	"xpfarm/internal/core"
	"xpfarm/internal/database"
	"xpfarm/internal/modules"
	"xpfarm/internal/ui"
	"xpfarm/pkg/utils"

	"github.com/gin-gonic/gin"
)

func main() {
	// Parse Flags
	debugMode := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	// Configure Logging
	utils.SetDebug(*debugMode)

	// Configure Gin Mode
	if *debugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	banner := `
____  ________________________                     
╲   ╲╱  ╱╲______   ╲_   _____╱____ _______  _____  
 ╲     ╱  │     ___╱│    __) ╲__  ╲╲_  __ ╲╱     ╲ 
 ╱     ╲  │    │    │     ╲   ╱ __ ╲│  │ ╲╱  y y  ╲
╱___╱╲  ╲ │____│    ╲___  ╱  (____  ╱__│  │__│_│  ╱
      ╲_╱               ╲╱        ╲╱            ╲╱ 
                                github.com/A3-N
                            ` + "\x1b[3m" + `bugs, bounties & b*tchz` + "\x1b[0m" + `
`
	utils.PrintGradient(banner)

	// 0. Environment Setup
	// utils.EnsureGoBinPath() - REMOVED per user request

	// 1. Initialize Database
	utils.LogInfo("Initializing Database...")
	database.InitDB(*debugMode)

	// 2. Register Modules
	modules.InitModules()

	// 3. Health Checks & Installation
	utils.LogInfo("Checking Dependencies...")
	allModules := modules.GetAll()
	missingCount := 0

	for _, mod := range allModules {
		if !mod.CheckInstalled() {
			// Specific bypass for Nmap as it is not a Go binary and cannot be auto-installed
			if mod.Name() == "nmap" {
				utils.LogWarning("Tool %s not found. Please install Nmap manually and ensure it is in your PATH.", utils.Bold("nmap"))
				continue
			}

			utils.LogWarning("Tool %s not found. Attempting install...", utils.Bold(mod.Name()))
			if err := mod.Install(); err != nil {
				utils.LogError("Failed to install %s: %v", utils.Bold(mod.Name()), err)
				missingCount++
			} else {
				utils.LogSuccess("Successfully installed %s", utils.Bold(mod.Name()))
			}
		}
	}

	if missingCount > 0 {
		utils.LogError("%d tools failed to install. The tool might not function correctly.", missingCount)
		// We can decide to exit here or continue.
		// User said "if it fails it will error out".
		utils.LogError("Exiting due to missing dependencies.")
		os.Exit(1)
	}

	utils.LogSuccess("%s", utils.Bold("All dependencies satisfied."))

	// 4. Check for Updates
	modules.RunUpdates()

	// 5. Check and Index Nuclei Templates
	utils.LogInfo("Checking Nuclei Templates version...")
	go core.CheckAndIndexTemplates(database.GetDB())

	// 6. Start Web Server
	port := "8888"
	utils.LogSuccess("Starting Web Interface on port %s...", utils.Bold(port))
	utils.LogSuccess("Access at %s", utils.Bold("http://localhost:"+port))

	// Enable Silent Mode (suppress further Info/Success logs to keep terminal clean for bars)
	if !*debugMode {
		utils.SetSilent(true)
	}

	// Open browser? Maybe later.

	if err := ui.StartServer(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
