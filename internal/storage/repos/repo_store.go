package repostore

import (
	"fmt"
	"time"

	"xpfarm/internal/normalization/model"
	"xpfarm/internal/repo_scanner/sbom"
	"xpfarm/internal/repos"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SaveRepoTarget upserts a repository target record. If a record with the same
// URL already exists its Branch and LocalPath are updated; the ID is preserved.
func SaveRepoTarget(db *gorm.DB, target repos.RepoTarget) error {
	rec := FromRepoTarget(target)
	result := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "url"}},
		DoUpdates: clause.AssignmentColumns([]string{"branch", "local_path", "updated_at"}),
	}).Create(&rec)
	return result.Error
}

// GetRepoTarget retrieves a repository target by ID.
func GetRepoTarget(db *gorm.DB, id string) (repos.RepoTarget, error) {
	var rec RepoTargetRecord
	if err := db.First(&rec, "id = ?", id).Error; err != nil {
		return repos.RepoTarget{}, fmt.Errorf("repostore: get target %s: %w", id, err)
	}
	return rec.ToRepoTarget(), nil
}

// GetRepoTargetByURL retrieves a repository target by URL.
func GetRepoTargetByURL(db *gorm.DB, url string) (repos.RepoTarget, error) {
	var rec RepoTargetRecord
	if err := db.First(&rec, "url = ?", url).Error; err != nil {
		return repos.RepoTarget{}, fmt.Errorf("repostore: get target by url %s: %w", url, err)
	}
	return rec.ToRepoTarget(), nil
}

// ListRepoTargets returns all tracked repository targets ordered by creation time.
func ListRepoTargets(db *gorm.DB) ([]repos.RepoTarget, error) {
	var records []RepoTargetRecord
	if err := db.Order("created_at desc").Find(&records).Error; err != nil {
		return nil, fmt.Errorf("repostore: list targets: %w", err)
	}
	targets := make([]repos.RepoTarget, len(records))
	for i, r := range records {
		targets[i] = r.ToRepoTarget()
	}
	return targets, nil
}

// UpdateLastScan updates the last_scan timestamp for a repo target.
func UpdateLastScan(db *gorm.DB, repoID string, t time.Time) error {
	return db.Model(&RepoTargetRecord{}).
		Where("id = ?", repoID).
		Update("last_scan", t).Error
}

// DeleteRepoTarget removes a repo target and all associated findings and SBOMs.
func DeleteRepoTarget(db *gorm.DB, id string) error {
	// Cascade delete associated records first
	if err := db.Where("repo_id = ?", id).Delete(&RepoFindingRecord{}).Error; err != nil {
		return fmt.Errorf("repostore: delete findings for %s: %w", id, err)
	}
	if err := db.Where("repo_id = ?", id).Delete(&SBOMRecord{}).Error; err != nil {
		return fmt.Errorf("repostore: delete sboms for %s: %w", id, err)
	}
	if err := db.Delete(&RepoTargetRecord{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("repostore: delete target %s: %w", id, err)
	}
	return nil
}

// ---------------------------------------------------------------------------

// SaveRepoScanResults upserts a batch of findings for a given repo.
// Findings with duplicate fingerprints are silently skipped.
func SaveRepoScanResults(db *gorm.DB, repoID string, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	records := make([]RepoFindingRecord, 0, len(findings))
	for _, f := range findings {
		rec, err := FromFinding(repoID, f)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "fingerprint"}},
		DoNothing: true,
	}).CreateInBatches(records, 100).Error
}

// ListRepoFindings returns all findings for a given repository.
// Optional filters: source, severity, cwe, cve, kev.
func ListRepoFindings(db *gorm.DB, repoID string, filters map[string]string) ([]model.Finding, error) {
	q := db.Where("repo_id = ?", repoID)

	if v := filters["source"]; v != "" {
		q = q.Where("source = ?", v)
	}
	if v := filters["severity"]; v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := filters["cwe"]; v != "" {
		q = q.Where("cwe = ?", v)
	}
	if v := filters["cve"]; v != "" {
		q = q.Where("cve = ?", v)
	}
	if v := filters["kev"]; v == "true" {
		q = q.Where("kev = ?", true)
	}

	var records []RepoFindingRecord
	if err := q.Order("timestamp desc").Find(&records).Error; err != nil {
		return nil, fmt.Errorf("repostore: list findings for %s: %w", repoID, err)
	}
	findings := make([]model.Finding, len(records))
	for i, r := range records {
		findings[i] = r.ToFinding()
	}
	return findings, nil
}

// ---------------------------------------------------------------------------

// SaveSBOM persists a new SBOM snapshot for a repository.
// A new row is created each time a scan runs (audit trail).
func SaveSBOM(db *gorm.DB, s *sbom.SBOM) error {
	if s == nil {
		return nil
	}
	rec, err := FromSBOM(s)
	if err != nil {
		return fmt.Errorf("repostore: encode sbom: %w", err)
	}
	return db.Create(&rec).Error
}

// GetLatestSBOM returns the most recent SBOM snapshot for a repository.
func GetLatestSBOM(db *gorm.DB, repoID string) (*sbom.SBOM, error) {
	var rec SBOMRecord
	if err := db.Where("repo_id = ?", repoID).
		Order("scanned_at desc").
		First(&rec).Error; err != nil {
		return nil, fmt.Errorf("repostore: get sbom for %s: %w", repoID, err)
	}
	return rec.ToSBOM(), nil
}

// ListSBOMs returns all SBOM snapshots for a repository ordered newest-first.
func ListSBOMs(db *gorm.DB, repoID string) ([]*sbom.SBOM, error) {
	var records []SBOMRecord
	if err := db.Where("repo_id = ?", repoID).
		Order("scanned_at desc").
		Find(&records).Error; err != nil {
		return nil, fmt.Errorf("repostore: list sboms for %s: %w", repoID, err)
	}
	result := make([]*sbom.SBOM, len(records))
	for i, r := range records {
		result[i] = r.ToSBOM()
	}
	return result, nil
}
