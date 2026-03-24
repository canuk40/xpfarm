// Package repostore persists repository scan targets, scan results, and SBOMs.
package repostore

import (
	"encoding/json"
	"time"

	"xpfarm/internal/normalization/model"
	"xpfarm/internal/repo_scanner/sbom"
	"xpfarm/internal/repos"

	"gorm.io/gorm"
)

// RepoTargetRecord is the GORM model for a tracked Git repository.
type RepoTargetRecord struct {
	ID        string    `gorm:"primaryKey"`
	URL       string    `gorm:"uniqueIndex;not null"`
	Branch    string
	LocalPath string
	LastScan  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (RepoTargetRecord) TableName() string { return "repo_targets" }

// FromRepoTarget converts a domain model to a GORM record.
func FromRepoTarget(t repos.RepoTarget) RepoTargetRecord {
	return RepoTargetRecord{
		ID:        t.ID,
		URL:       t.URL,
		Branch:    t.Branch,
		LocalPath: t.LocalPath,
		LastScan:  t.LastScan,
	}
}

// ToRepoTarget converts a GORM record to the domain model.
func (r RepoTargetRecord) ToRepoTarget() repos.RepoTarget {
	return repos.RepoTarget{
		ID:        r.ID,
		URL:       r.URL,
		Branch:    r.Branch,
		LocalPath: r.LocalPath,
		LastScan:  r.LastScan,
	}
}

// ---------------------------------------------------------------------------

// RepoFindingRecord stores a single normalized finding linked to a repo target.
type RepoFindingRecord struct {
	ID          string `gorm:"primaryKey"`
	RepoID      string `gorm:"index;not null"`
	Fingerprint string `gorm:"uniqueIndex"`
	Source      string
	Target      string
	Location    string
	Title       string
	Description string
	Severity    string
	CWE         string
	CVE         string
	CVSS        *float64
	EPSS        *float64
	KEV         bool
	Evidence    string
	TagsJSON    string
	RawJSON     string
	Timestamp   time.Time
}

func (RepoFindingRecord) TableName() string { return "repo_findings" }

// FromFinding converts a model.Finding to a RepoFindingRecord for the given repo.
func FromFinding(repoID string, f model.Finding) (RepoFindingRecord, error) {
	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return RepoFindingRecord{}, err
	}
	rawJSON, err := json.Marshal(f.Raw)
	if err != nil {
		return RepoFindingRecord{}, err
	}
	return RepoFindingRecord{
		ID:          f.ID,
		RepoID:      repoID,
		Fingerprint: f.Fingerprint,
		Source:      f.Source,
		Target:      f.Target,
		Location:    f.Location,
		Title:       f.Title,
		Description: f.Description,
		Severity:    f.Severity,
		CWE:         f.CWE,
		CVE:         f.CVE,
		CVSS:        f.CVSS,
		EPSS:        f.EPSS,
		KEV:         f.KEV,
		Evidence:    f.Evidence,
		TagsJSON:    string(tagsJSON),
		RawJSON:     string(rawJSON),
		Timestamp:   f.Timestamp,
	}, nil
}

// ToFinding reconstructs a model.Finding from the record.
func (r RepoFindingRecord) ToFinding() model.Finding {
	var tags []string
	var raw map[string]any
	_ = json.Unmarshal([]byte(r.TagsJSON), &tags)
	_ = json.Unmarshal([]byte(r.RawJSON), &raw)
	return model.Finding{
		ID:          r.ID,
		Fingerprint: r.Fingerprint,
		Source:      r.Source,
		Target:      r.Target,
		Location:    r.Location,
		Title:       r.Title,
		Description: r.Description,
		Severity:    r.Severity,
		CWE:         r.CWE,
		CVE:         r.CVE,
		CVSS:        r.CVSS,
		EPSS:        r.EPSS,
		KEV:         r.KEV,
		Evidence:    r.Evidence,
		Tags:        tags,
		Raw:         raw,
		Timestamp:   r.Timestamp,
	}
}

// ---------------------------------------------------------------------------

// SBOMRecord stores the dependency list for a repo scan as a JSON blob.
type SBOMRecord struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"`
	RepoID       string    `gorm:"index;not null"`
	DepsJSON     string    `gorm:"not null"`
	DepCount     int
	ScannedAt    time.Time
}

func (SBOMRecord) TableName() string { return "repo_sboms" }

// FromSBOM converts an sbom.SBOM to a SBOMRecord.
func FromSBOM(s *sbom.SBOM) (SBOMRecord, error) {
	j, err := json.Marshal(s.Dependencies)
	if err != nil {
		return SBOMRecord{}, err
	}
	return SBOMRecord{
		RepoID:    s.TargetID,
		DepsJSON:  string(j),
		DepCount:  len(s.Dependencies),
		ScannedAt: time.Now().UTC(),
	}, nil
}

// ToSBOM reconstructs an sbom.SBOM from the record.
func (r SBOMRecord) ToSBOM() *sbom.SBOM {
	var deps []sbom.Dependency
	_ = json.Unmarshal([]byte(r.DepsJSON), &deps)
	return &sbom.SBOM{
		TargetID:     r.RepoID,
		Dependencies: deps,
	}
}

// ---------------------------------------------------------------------------

// Migrate creates or migrates all repo storage tables.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&RepoTargetRecord{},
		&RepoFindingRecord{},
		&SBOMRecord{},
	)
}
