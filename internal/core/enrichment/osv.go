// OSV.dev integration: https://api.osv.dev/v1/query
// Free, no auth. Covers Go, Python, npm, Maven, Cargo, RubyGems, etc.
package enrichment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var osvClient = &http.Client{Timeout: 15 * time.Second}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// techToOSV maps a technology string like "jQuery 3.6.0" to (name, version, ecosystem).
func techToOSV(tech string) (name, version, ecosystem string) {
	parts := strings.Fields(strings.TrimSpace(tech))
	if len(parts) < 2 {
		return
	}
	rawName := strings.ToLower(parts[0])
	ver := parts[len(parts)-1]
	if !strings.Contains(ver, ".") {
		return
	}
	ecosystems := map[string]string{
		"jquery": "npm", "bootstrap": "npm", "react": "npm", "angular": "npm",
		"vue": "npm", "express": "npm", "lodash": "npm", "axios": "npm",
		"moment": "npm", "wordpress": "npm",
		"django": "PyPI", "flask": "PyPI", "fastapi": "PyPI", "requests": "PyPI",
		"spring": "Maven", "struts": "Maven", "log4j": "Maven",
		"drupal": "Packagist", "laravel": "Packagist", "symfony": "Packagist",
		"rails": "RubyGems", "sinatra": "RubyGems",
		"gin": "Go", "beego": "Go", "echo": "Go",
	}
	if eco, ok := ecosystems[rawName]; ok {
		return rawName, ver, eco
	}
	return
}

func queryOSV(pkgName, version, ecosystem string) ([]osvVuln, error) {
	payload := map[string]interface{}{
		"package": map[string]string{"name": pkgName, "ecosystem": ecosystem},
		"version": version,
	}
	body, _ := json.Marshal(payload)
	resp, err := osvClient.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Vulns, nil
}

// EnrichWithOSV queries OSV.dev for all tech stack entries detected on targetID's
// web assets and upserts any found vulnerabilities as CVE records.
func EnrichWithOSV(db *gorm.DB, targetID uint) {
	var webAssets []database.WebAsset
	db.Where("target_id = ? AND tech_stack != ''", targetID).Find(&webAssets)
	if len(webAssets) == 0 {
		return
	}

	seen := make(map[string]bool)
	type techEntry struct{ name, version, ecosystem string }
	var techList []techEntry

	for _, wa := range webAssets {
		for _, tech := range strings.Split(wa.TechStack, ",") {
			tech = strings.TrimSpace(tech)
			if tech == "" || seen[tech] {
				continue
			}
			seen[tech] = true
			n, v, eco := techToOSV(tech)
			if n != "" && eco != "" {
				techList = append(techList, techEntry{n, v, eco})
			}
		}
	}
	if len(techList) == 0 {
		return
	}

	added := 0
	for _, t := range techList {
		vulns, err := queryOSV(t.name, t.version, t.ecosystem)
		if err != nil {
			utils.LogDebug("[OSV] Query failed for %s %s: %v", t.name, t.version, err)
			continue
		}
		for _, v := range vulns {
			cveID := v.ID
			for _, alias := range v.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					cveID = alias
					break
				}
			}
			severity := "medium"
			if len(v.Severity) > 0 {
				s := v.Severity[0].Score
				switch {
				case strings.HasPrefix(s, "9") || strings.HasPrefix(s, "10"):
					severity = "critical"
				case strings.HasPrefix(s, "7") || strings.HasPrefix(s, "8"):
					severity = "high"
				case strings.HasPrefix(s, "4") || strings.HasPrefix(s, "5") || strings.HasPrefix(s, "6"):
					severity = "medium"
				default:
					severity = "low"
				}
			}
			db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "target_id"}, {Name: "product"}, {Name: "cve_id"}},
				DoNothing: true,
			}).Create(&database.CVE{
				TargetID: targetID,
				Product:  fmt.Sprintf("%s (osv)", t.name),
				CveID:    cveID,
				Severity: severity,
			})
			added++
		}
	}
	if added > 0 {
		utils.LogSuccess("[OSV] Added %d vulnerabilities for target %d", added, targetID)
	}
}
