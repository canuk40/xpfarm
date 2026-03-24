// Package planstore handles SQLite persistence of ScanPlan records.
package planstore

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PlanRecord is the GORM model for a persisted scan plan.
type PlanRecord struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	AssetIDs  string    `gorm:"type:text" json:"asset_ids"` // JSON-encoded []uint
	Mode      string    `json:"mode"`
	StepsJSON string    `gorm:"type:text" json:"steps_json"` // JSON-encoded []PlanStep
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Migrate creates or updates the plan_records table.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&PlanRecord{})
}

// SavePlan upserts a plan record. The caller is responsible for marshalling
// Steps and AssetIDs into JSON before calling.
func SavePlan(db *gorm.DB, rec PlanRecord) error {
	return db.Save(&rec).Error
}

// GetPlan returns a single plan by ID.
func GetPlan(db *gorm.DB, id string) (*PlanRecord, error) {
	var rec PlanRecord
	if err := db.First(&rec, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("planstore: get %s: %w", id, err)
	}
	return &rec, nil
}

// ListPlans returns all plans ordered by creation time descending.
func ListPlans(db *gorm.DB) ([]PlanRecord, error) {
	var recs []PlanRecord
	if err := db.Order("created_at desc").Find(&recs).Error; err != nil {
		return nil, fmt.Errorf("planstore: list: %w", err)
	}
	return recs, nil
}

// DeletePlan removes a plan by ID.
func DeletePlan(db *gorm.DB, id string) error {
	return db.Delete(&PlanRecord{}, "id = ?", id).Error
}

// MarshalAssetIDs encodes a []uint slice to JSON string for storage.
func MarshalAssetIDs(ids []uint) string {
	b, _ := json.Marshal(ids)
	return string(b)
}

// MarshalSteps encodes a steps slice to JSON string for storage.
// The caller passes the steps as an interface{} to avoid an import cycle.
func MarshalSteps(steps interface{}) (string, error) {
	b, err := json.Marshal(steps)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
