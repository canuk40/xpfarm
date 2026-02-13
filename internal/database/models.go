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
	ID           uint            `gorm:"primaryKey" json:"id"`
	AssetID      uint            `gorm:"index" json:"asset_id"`
	ParentID     *uint           `gorm:"index" json:"parent_id"` // Pointer allows null for root targets
	Parent       *Target         `gorm:"foreignKey:ParentID" json:"parent,omitempty"`
	Subdomains   []Target        `gorm:"foreignKey:ParentID" json:"subdomains,omitempty"`
	Value        string          `gorm:"uniqueIndex" json:"value"`          // IP, Domain, or URL
	Type         string          `gorm:"index:idx_target_type" json:"type"` // "ip", "domain", "url", "cidr"
	IsCloudflare bool            `gorm:"index:idx_target_cf" json:"is_cloudflare"`
	IsAlive      bool            `gorm:"index:idx_target_alive;default:true" json:"is_alive"`
	Status       string          `json:"status"` // "up", "down", "unreachable"
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	DeletedAt    gorm.DeletedAt  `gorm:"index" json:"-"`
	Results      []ScanResult    `gorm:"foreignKey:TargetID" json:"results"`
	Ports        []Port          `gorm:"foreignKey:TargetID" json:"ports"`
	WebAssets    []WebAsset      `gorm:"foreignKey:TargetID" json:"web_assets"`
	Vulns        []Vulnerability `gorm:"foreignKey:TargetID" json:"vulnerabilities"`
	CVEs         []CVE           `gorm:"foreignKey:TargetID" json:"cves"`
}

type Port struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	TargetID  uint           `gorm:"index:idx_target_port,unique" json:"target_id"` // Composite unique index
	Port      int            `json:"port" gorm:"index:idx_target_port,unique"`
	Protocol  string         `json:"protocol"`
	Service   string         `gorm:"index:idx_port_service" json:"service"`
	Product   string         `gorm:"index:idx_port_product" json:"product"`
	Version   string         `json:"version"`
	Scripts   string         `json:"scripts"` // Stores raw script output (e.g. from nmap)
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type WebAsset struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	TargetID     uint           `gorm:"index:idx_web_id_url,unique" json:"target_id"`
	URL          string         `json:"url" gorm:"index:idx_web_id_url,unique"`
	Title        string         `json:"title"`
	TechStack    string         `gorm:"index:idx_web_tech" json:"tech_stack"`
	WebServer    string         `json:"web_server"`
	StatusCode   int            `gorm:"index:idx_web_status" json:"status_code"`
	ContentLen   int            `json:"content_length"`
	WordCount    int            `json:"word_count"`
	LineCount    int            `json:"line_count"`
	ContentType  string         `json:"content_type"`
	Location     string         `json:"location"` // Redirect target
	IP           string         `json:"ip"`
	CNAME        string         `json:"cname"`
	CDN          string         `json:"cdn"`
	Response     string         `json:"response"` // Raw response body/headers if needed
	Screenshot   string         `json:"screenshot_path"`
	KatanaOutput string         `json:"katana_output"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type Vulnerability struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	TargetID    uint           `gorm:"index" json:"target_id"`
	Name        string         `json:"name"`
	Severity    string         `gorm:"index:idx_vuln_severity" json:"severity"`
	Description string         `json:"description"`
	MatcherName string         `json:"matcher_name"`
	Extracted   string         `json:"extracted_results"`
	TemplateID  string         `gorm:"index:idx_vuln_template" json:"template_id"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type CVE struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	TargetID    uint           `gorm:"index;uniqueIndex:idx_cve_unique" json:"target_id"`
	Product     string         `gorm:"index:idx_cve_product;uniqueIndex:idx_cve_unique" json:"product"`
	CveID       string         `gorm:"index:idx_cve_id;uniqueIndex:idx_cve_unique" json:"cve_id"`
	Severity    string         `gorm:"index:idx_cve_severity" json:"severity"`
	CvssScore   float64        `json:"cvss_score"`
	EpssScore   float64        `json:"epss_score"`
	IsKEV       bool           `json:"is_kev"`
	HasPOC      bool           `json:"has_poc"`
	HasTemplate bool           `json:"has_template"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type ScanResult struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	TargetID  uint           `gorm:"index" json:"target_id"`
	Target    Target         `gorm:"foreignKey:TargetID" json:"target,omitempty"`
	ToolName  string         `gorm:"index:idx_result_tool" json:"tool_name"`
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
