package core

import (
	"strings"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/database"
)

// scoringWeights mirrors Entity/QueenCore's DEFAULT_SCORING_WEIGHTS, adapted to
// XPFarm's data model. Values represent attack-surface richness, not exploitability.
var scoringWeights = struct {
	PerPort       float64
	ServiceBanner float64
	HTTPPresent   float64
	ServerKnown   float64
	AuthPresent   float64
	TLSPresent    float64
	TechDetected  float64
	// Exploitability weights (Entity fitness: exploration + innovation)
	VulnLow      float64
	VulnMedium   float64
	VulnHigh     float64
	VulnCritical float64
	CVEBase      float64 // base points per CVE
	CVEKev       float64 // bonus for CISA KEV entries
	CVEPoc       float64 // bonus for CVEs with public PoC
	// Recency: decay per day since last scan
	RecencyDecayPerDay float64
}{
	PerPort:       2.0,
	ServiceBanner: 4.0,
	HTTPPresent:   5.0,
	ServerKnown:   3.0,
	AuthPresent:   5.0,
	TLSPresent:    6.0,
	TechDetected:  3.0,
	// Exploitability
	VulnLow:      2.0,
	VulnMedium:   5.0,
	VulnHigh:     8.0,
	VulnCritical: 15.0,
	CVEBase:      1.0,
	CVEKev:       10.0,
	CVEPoc:       5.0,
	// Recency decay
	RecencyDecayPerDay: 0.1,
}

// TargetSurfaceScore holds a breakdown of a target's attack surface score.
// Higher total = richer attack surface = more worthwhile deep scanning.
type TargetSurfaceScore struct {
	Total        float64 `json:"total"`
	PortScore    float64 `json:"port_score"`
	BannerScore  float64 `json:"banner_score"`
	WebScore     float64 `json:"web_score"`
	TLSScore     float64 `json:"tls_score"`
	TechScore    float64 `json:"tech_score"`
	VulnScore    float64 `json:"vuln_score"`    // weighted by severity
	CVEScore     float64 `json:"cve_score"`     // KEV/PoC bonuses
	RecencyDecay float64 `json:"recency_decay"` // subtracted for stale scans
}

// ComputeTargetScore calculates attack surface score from discovered ports and web assets.
func ComputeTargetScore(ports []database.Port, webAssets []database.WebAsset) TargetSurfaceScore {
	s := TargetSurfaceScore{}

	for _, p := range ports {
		s.PortScore += scoringWeights.PerPort
		product := strings.TrimSpace(strings.ToLower(p.Product))
		if product != "" && product != "unknown" {
			s.BannerScore += scoringWeights.ServiceBanner
		}
	}

	for _, wa := range webAssets {
		s.WebScore += scoringWeights.HTTPPresent

		if wa.WebServer != "" {
			s.WebScore += scoringWeights.ServerKnown
		}

		// 401/403 indicates an auth-protected surface — higher value target
		if wa.StatusCode == 401 || wa.StatusCode == 403 {
			s.WebScore += scoringWeights.AuthPresent
		}

		if strings.HasPrefix(strings.ToLower(wa.URL), "https://") {
			s.TLSScore += scoringWeights.TLSPresent
		}

		for _, tech := range strings.Split(wa.TechStack, ",") {
			if strings.TrimSpace(tech) != "" {
				s.TechScore += scoringWeights.TechDetected
			}
		}
	}

	s.Total = s.PortScore + s.BannerScore + s.WebScore + s.TLSScore + s.TechScore
	return s
}

// ComputeFullScore loads all findings for a target from the DB, computes the
// multi-dimensional score (Entity fitness model), persists it to Target.Score,
// and returns the breakdown.
//
// Dimensions: attack surface (ports/web/tech) + exploitability (vulns/CVEs) + recency decay.
func ComputeFullScore(db *gorm.DB, target *database.Target) TargetSurfaceScore {
	var ports []database.Port
	db.Where("target_id = ?", target.ID).Find(&ports)

	var webAssets []database.WebAsset
	db.Where("target_id = ?", target.ID).Find(&webAssets)

	// Start with the existing surface score.
	s := ComputeTargetScore(ports, webAssets)

	// --- Vuln scoring (Entity: exploration dimension) ---
	var vulns []database.Vulnerability
	db.Where("target_id = ?", target.ID).Find(&vulns)
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			s.VulnScore += scoringWeights.VulnCritical
		case "high":
			s.VulnScore += scoringWeights.VulnHigh
		case "medium":
			s.VulnScore += scoringWeights.VulnMedium
		default: // low, info
			s.VulnScore += scoringWeights.VulnLow
		}
	}

	// --- CVE scoring (Entity: innovation dimension — novel/high-value findings) ---
	var cves []database.CVE
	db.Where("target_id = ?", target.ID).Find(&cves)
	for _, c := range cves {
		s.CVEScore += scoringWeights.CVEBase
		if c.IsKEV {
			s.CVEScore += scoringWeights.CVEKev
		}
		if c.HasPOC {
			s.CVEScore += scoringWeights.CVEPoc
		}
	}

	// --- Recency decay (Entity: survival dimension — older = less urgent) ---
	daysSince := time.Since(target.UpdatedAt).Hours() / 24
	if daysSince > 0 {
		s.RecencyDecay = daysSince * scoringWeights.RecencyDecayPerDay
	}

	s.Total = s.PortScore + s.BannerScore + s.WebScore + s.TLSScore + s.TechScore +
		s.VulnScore + s.CVEScore - s.RecencyDecay
	if s.Total < 0 {
		s.Total = 0
	}

	// Persist the updated score to the DB.
	db.Model(target).Update("score", s.Total)
	target.Score = s.Total

	return s
}
