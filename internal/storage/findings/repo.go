package findings

import (
	"encoding/json"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"xpfarm/internal/normalization/model"
)

// SaveFinding upserts a Finding by its fingerprint.
// If a record with the same fingerprint already exists, the call is a no-op
// (we do not update existing findings — deduplication handles that upstream).
func SaveFinding(db *gorm.DB, f model.Finding) error {
	if f.Fingerprint == "" {
		return fmt.Errorf("findings: cannot save finding with empty fingerprint (ID=%s)", f.ID)
	}
	rec, err := FromFinding(f)
	if err != nil {
		return err
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "fingerprint"}},
		DoNothing: true,
	}).Create(&rec).Error
}

// SaveGroup upserts a NormalizedGroup by its GroupID.
// If the group already exists it is fully replaced (finding membership may change).
func SaveGroup(db *gorm.DB, g model.NormalizedGroup) error {
	rec, err := FromGroup(g)
	if err != nil {
		return err
	}
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "group_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"finding_ids_json", "finding_count", "updated_at",
		}),
	}).Create(&rec).Error
}

// ListFindings returns findings, optionally filtered by field=value pairs.
// Supported filter keys: source, severity, cwe, cve, target, kev ("true"/"false").
func ListFindings(db *gorm.DB, filters map[string]string) ([]model.Finding, error) {
	q := db.Model(&FindingRecord{})

	for key, val := range filters {
		switch strings.ToLower(key) {
		case "source":
			q = q.Where("source = ?", val)
		case "severity":
			q = q.Where("severity = ?", strings.ToLower(val))
		case "cwe":
			q = q.Where("cwe = ?", strings.ToUpper(val))
		case "cve":
			q = q.Where("cve = ?", strings.ToUpper(val))
		case "target":
			q = q.Where("target LIKE ?", "%"+val+"%")
		case "kev":
			q = q.Where("kev = ?", val == "true" || val == "1")
		}
	}

	var records []FindingRecord
	if err := q.Order("timestamp DESC").Find(&records).Error; err != nil {
		return nil, fmt.Errorf("findings: list: %w", err)
	}

	out := make([]model.Finding, len(records))
	for i, r := range records {
		out[i] = r.ToFinding()
	}
	return out, nil
}

// GetFindingByID returns the finding with the given ID.
func GetFindingByID(db *gorm.DB, id string) (model.Finding, error) {
	var rec FindingRecord
	if err := db.First(&rec, "id = ?", id).Error; err != nil {
		return model.Finding{}, fmt.Errorf("findings: get %s: %w", id, err)
	}
	return rec.ToFinding(), nil
}

// ListGroups returns all stored NormalizedGroups.
// It reconstructs the full Finding list for each group by fetching members
// from the findings table in a single batch query per group.
func ListGroups(db *gorm.DB) ([]model.NormalizedGroup, error) {
	var groupRecs []GroupRecord
	if err := db.Order("finding_count DESC").Find(&groupRecs).Error; err != nil {
		return nil, fmt.Errorf("findings: list groups: %w", err)
	}

	groups := make([]model.NormalizedGroup, 0, len(groupRecs))
	for _, gr := range groupRecs {
		var ids []string
		if err := json.Unmarshal([]byte(gr.FindingIDsJSON), &ids); err != nil || len(ids) == 0 {
			// Store the group without findings if the IDs are malformed
			groups = append(groups, model.NormalizedGroup{
				GroupID:  gr.GroupID,
				CWE:      gr.CWE,
				CVE:      gr.CVE,
				Severity: gr.Severity,
				Target:   gr.Target,
			})
			continue
		}

		var findingRecs []FindingRecord
		if err := db.Where("id IN ?", ids).Find(&findingRecs).Error; err != nil {
			return nil, fmt.Errorf("findings: fetch members of group %s: %w", gr.GroupID, err)
		}

		members := make([]model.Finding, len(findingRecs))
		for i, r := range findingRecs {
			members[i] = r.ToFinding()
		}
		groups = append(groups, model.NormalizedGroup{
			GroupID:  gr.GroupID,
			CWE:      gr.CWE,
			CVE:      gr.CVE,
			Severity: gr.Severity,
			Target:   gr.Target,
			Findings: members,
		})
	}
	return groups, nil
}
