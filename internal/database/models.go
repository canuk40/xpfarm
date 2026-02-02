package database

import (
	"time"

	"gorm.io/gorm"
)

type Asset struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Name      string         `gorm:"uniqueIndex" json:"name"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	Targets   []Target       `gorm:"foreignKey:AssetID" json:"targets"`
}

type Target struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	AssetID      uint           `gorm:"index" json:"asset_id"`
	ParentID     *uint          `gorm:"index" json:"parent_id"` // Pointer allows null for root targets
	Parent       *Target        `gorm:"foreignKey:ParentID" json:"parent,omitempty"`
	Subdomains   []Target       `gorm:"foreignKey:ParentID" json:"subdomains,omitempty"`
	Value        string         `gorm:"uniqueIndex" json:"value"` // IP, Domain, or URL
	Type         string         `json:"type"`                     // "ip", "domain", "url", "cidr"
	IsCloudflare bool           `json:"is_cloudflare"`
	IsAlive      bool           `json:"is_alive" gorm:"default:true"`
	Status       string         `json:"status"` // "up", "down", "unreachable"
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	Results      []ScanResult   `gorm:"foreignKey:TargetID" json:"results"`
	Ports        []Port         `gorm:"foreignKey:TargetID" json:"ports"`
	WebAssets    []WebAsset     `gorm:"foreignKey:TargetID" json:"web_assets"`
	Vulns        []Vulnerability `gorm:"foreignKey:TargetID" json:"vulnerabilities"`
}

type Port struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	TargetID  uint           `gorm:"index" json:"target_id"`
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	Service   string         `json:"service"`
	Product   string         `json:"product"`
	Version   string         `json:"version"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type WebAsset struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	TargetID   uint           `gorm:"index" json:"target_id"`
	URL        string         `json:"url"`
	Title      string         `json:"title"`
	TechStack  string         `json:"tech_stack"`
	StatusCode int            `json:"status_code"`
	ContentLen int            `json:"content_length"`
	Screenshot string         `json:"screenshot_path"`
	CreatedAt  time.Time      `json:"created_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

type Vulnerability struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	TargetID    uint           `gorm:"index" json:"target_id"`
	Name        string         `json:"name"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	MatcherName string         `json:"matcher_name"`
	Extracted   string         `json:"extracted_results"`
	TemplateID  string         `json:"template_id"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type ScanResult struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	TargetID  uint           `gorm:"index" json:"target_id"`
	Target    Target         `gorm:"foreignKey:TargetID" json:"target,omitempty"`
	ToolName  string         `json:"tool_name"`
	Output    string         `json:"output"` // JSON or text output
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Setting struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Key         string         `gorm:"uniqueIndex" json:"key"`
	Value       string         `json:"value"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}
