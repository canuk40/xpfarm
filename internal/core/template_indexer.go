package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"xpfarm/internal/database"
	"xpfarm/pkg/utils"

	"xpfarm/internal/modules"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GetNucleiTemplatesDir attempts to find the nuclei-templates directory
func GetNucleiTemplatesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	possiblePaths := []string{
		// Windows specific default
		filepath.Join(home, "nuclei-templates"),
		// Standard config paths (Unix/Mac/Linux)
		filepath.Join(home, ".config", "nuclei", "nuclei-templates"),
		filepath.Join(home, ".config", "nuclei-templates"),
		filepath.Join(home, ".local", "nuclei-templates"),
		// Go install default / generic
		filepath.Join(home, "go", "bin", "nuclei-templates"),
		filepath.Join(home, ".nuclei-templates"),
	}

	for _, p := range possiblePaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("nuclei-templates directory not found in common locations")
}

// IndexNucleiTemplates walks the templates repo and updates the database
func IndexNucleiTemplates(db *gorm.DB) error {
	templatesDir, err := GetNucleiTemplatesDir()
	if err != nil {
		return err
	}

	utils.LogInfo("[Scanner] [Nuclei] Starting lightweight template indexing from %s", templatesDir)

	// Wipe the slate clean before indexing
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&database.NucleiTemplate{})

	var templates []database.NucleiTemplate
	var parseCount int

	err = filepath.WalkDir(templatesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "tests" || name == "profiles" || name == "workflows" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}

		// Fast metadata extraction: ID = filename, FilePath = relative path
		relPath, relErr := filepath.Rel(templatesDir, path)
		if relErr != nil {
			relPath = path
		}

		// Skip root files. If the relative path doesn't contain a directory separator, it's in the root
		if !strings.Contains(relPath, string(os.PathSeparator)) {
			return nil
		}

		ext := filepath.Ext(d.Name())
		templateID := strings.TrimSuffix(d.Name(), ext)

		tmpl := database.NucleiTemplate{
			TemplateID: templateID,
			FilePath:   relPath,
			// Name, Severity, Tags, etc. left empty for lazy loading
		}

		templates = append(templates, tmpl)
		parseCount++

		// Batch insert to avoid huge memory spikes and DB locks
		if len(templates) >= 1000 {
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "template_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"file_path", "updated_at"}),
			}).Create(&templates)
			templates = templates[:0]
		}

		return nil
	})

	// Insert remaining
	if len(templates) > 0 {
		db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "template_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"file_path", "updated_at"}),
		}).Create(&templates)
	}

	if err != nil {
		utils.LogError("[Scanner] [Nuclei] Error walking templates directory: %v", err)
		return err
	}

	utils.LogSuccess("[Scanner] [Nuclei] Successfully indexed %d templates in lightweight mode.", parseCount)
	return nil
}

// CheckAndIndexTemplates runs asynchronously on startup to keep templates synced
func CheckAndIndexTemplates(db *gorm.DB) {
	// 1. Get current installed version via CLI
	nucleiMod := modules.Get("nuclei")
	nm, ok := nucleiMod.(*modules.Nuclei)
	if !ok || !nm.CheckInstalled() {
		utils.LogDebug("[Scanner] [Nuclei] Nuclei not installed, skipping template index check.")
		return
	}

	currentVersion, err := nm.GetTemplateVersion()
	if err != nil {
		utils.LogError("[Scanner] [Nuclei] Failed to get template version: %v", err)
		return
	}

	if currentVersion == "" {
		utils.LogDebug("[Scanner] [Nuclei] Could not determine template version, skipping check.")
		return
	}

	// 2. Get saved version from DB
	var setting database.Setting
	db.Where("key = ?", "nuclei_template_version").First(&setting)
	savedVersion := setting.Value

	// 3. Compare
	if savedVersion == currentVersion {
		utils.LogDebug("[Scanner] [Nuclei] Templates are up to date (Version: %s), skipping index.", currentVersion)
		return
	}

	utils.LogInfo("[Scanner] [Nuclei] Template version changed (%s -> %s). Re-indexing templates...", savedVersion, currentVersion)

	// 4. Index
	if err := IndexNucleiTemplates(db); err != nil {
		utils.LogError("[Scanner] [Nuclei] Failed to index templates during update check: %v", err)
		return
	}

	// 5. Save the new version
	setting.Key = "nuclei_template_version"
	setting.Value = currentVersion
	setting.Description = "Currently indexed version of nuclei-templates"

	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "description", "updated_at", "deleted_at"}),
	}).Create(&setting)

	utils.LogSuccess("[Scanner] [Nuclei] Template index updated to version %s.", currentVersion)
}
