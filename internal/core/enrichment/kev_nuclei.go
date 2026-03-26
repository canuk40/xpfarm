// KEV-priority Nuclei template selector.
// After CVEMap runs, finds Nuclei templates matching CVEs that are in KEV or
// have EPSS > 0.5 (actively exploited / high probability). These run first,
// before the general auto-scan plan, so the most dangerous findings appear fast.
package enrichment

import (
	"strings"

	"gorm.io/gorm"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

// BuildKEVPriorityTemplates returns file paths of Nuclei templates that match
// CVEs for this target which are in KEV or have high EPSS scores.
func BuildKEVPriorityTemplates(db *gorm.DB, targetID uint) []string {
	// Find CVEs with templates where exploitation is confirmed/likely
	var cves []database.CVE
	db.Where(`target_id = ? AND has_template = true AND (
		is_kev = true OR
		in_vulncheck_kev = true OR
		epss_score > 0.5
	)`, targetID).Find(&cves)

	if len(cves) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var paths []string

	for _, cve := range cves {
		if cve.CveID == "" {
			continue
		}
		// Search template index by CVE ID match in template_id or tags
		var templates []database.NucleiTemplate
		cveUpper := strings.ToUpper(cve.CveID)
		db.Where("template_id LIKE ? OR tags LIKE ?",
			"%"+strings.ToLower(cve.CveID)+"%",
			"%"+cveUpper+"%",
		).Find(&templates)

		for _, t := range templates {
			if t.FilePath != "" && !seen[t.FilePath] {
				seen[t.FilePath] = true
				paths = append(paths, t.FilePath)
			}
		}
	}

	if len(paths) > 0 {
		utils.LogInfo("[KEV] Found %d priority templates for target %d (KEV/EPSS>0.5 CVEs)", len(paths), targetID)
	}
	return paths
}
