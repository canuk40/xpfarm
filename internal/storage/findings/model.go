// Package findings provides SQLite-backed persistence for normalized security
// findings and their groups.
package findings

import (
	"encoding/json"
	"fmt"
	"time"

	"xpfarm/internal/normalization/model"
)

// FindingRecord is the GORM model for a single normalized Finding.
// Complex fields (Raw, Tags) are JSON-encoded into text columns.
type FindingRecord struct {
	ID          string    `gorm:"primaryKey"`
	Source      string    `gorm:"index"`
	Target      string    `gorm:"index"`
	Location    string
	Title       string
	Description string    `gorm:"type:text"`
	Severity    string    `gorm:"index"`
	CWE         string    `gorm:"index"`
	CVE         string    `gorm:"index"`
	CVSS        *float64
	EPSS        *float64
	KEV         bool
	Evidence    string    `gorm:"type:text"`
	RawJSON     string    `gorm:"type:text"`   // json.Marshal(Finding.Raw)
	Fingerprint string    `gorm:"uniqueIndex"` // SHA-256 dedup key
	TagsJSON    string    `gorm:"type:text"`   // json.Marshal(Finding.Tags)
	Timestamp   time.Time
	CreatedAt   time.Time
}

// GroupRecord is the GORM model for a NormalizedGroup.
// The member finding IDs are stored as a JSON array.
type GroupRecord struct {
	GroupID        string    `gorm:"primaryKey"`
	CWE            string    `gorm:"index"`
	CVE            string    `gorm:"index"`
	Severity       string    `gorm:"index"`
	Target         string    `gorm:"index"`
	FindingIDsJSON string    `gorm:"type:text"` // json.Marshal([]string of finding IDs)
	FindingCount   int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Migrate runs AutoMigrate for the findings tables on the provided DB.
// Call this from database.InitDB() after opening the connection.
func Migrate(db interface {
	AutoMigrate(dst ...any) error
}) error {
	return db.AutoMigrate(&FindingRecord{}, &GroupRecord{})
}

// FromFinding converts a model.Finding into a FindingRecord for storage.
func FromFinding(f model.Finding) (FindingRecord, error) {
	rawJSON, err := json.Marshal(f.Raw)
	if err != nil {
		return FindingRecord{}, fmt.Errorf("findings: marshal raw: %w", err)
	}
	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return FindingRecord{}, fmt.Errorf("findings: marshal tags: %w", err)
	}
	return FindingRecord{
		ID:          f.ID,
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
		RawJSON:     string(rawJSON),
		Fingerprint: f.Fingerprint,
		TagsJSON:    string(tagsJSON),
		Timestamp:   f.Timestamp,
	}, nil
}

// ToFinding converts a FindingRecord back into a model.Finding.
func (r FindingRecord) ToFinding() model.Finding {
	var raw map[string]any
	_ = json.Unmarshal([]byte(r.RawJSON), &raw)
	var tags []string
	_ = json.Unmarshal([]byte(r.TagsJSON), &tags)
	return model.Finding{
		ID:          r.ID,
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
		Raw:         raw,
		Fingerprint: r.Fingerprint,
		Tags:        tags,
		Timestamp:   r.Timestamp,
	}
}

// FromGroup converts a model.NormalizedGroup into a GroupRecord for storage.
func FromGroup(g model.NormalizedGroup) (GroupRecord, error) {
	ids := make([]string, len(g.Findings))
	for i, f := range g.Findings {
		ids[i] = f.ID
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return GroupRecord{}, fmt.Errorf("findings: marshal group ids: %w", err)
	}
	return GroupRecord{
		GroupID:        g.GroupID,
		CWE:            g.CWE,
		CVE:            g.CVE,
		Severity:       g.Severity,
		Target:         g.Target,
		FindingIDsJSON: string(idsJSON),
		FindingCount:   len(g.Findings),
	}, nil
}
