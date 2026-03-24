package planner

import "time"

// Mode controls what categories of tools the planner may use.
type Mode string

const (
	ModeRecon      Mode = "recon"
	ModeWeb        Mode = "web"
	ModeBinary     Mode = "binary"
	ModeFull       Mode = "full"
	ModeSafe       Mode = "safe"
)

// PlanStatus tracks the lifecycle of a plan.
type PlanStatus string

const (
	StatusPending   PlanStatus = "pending"
	StatusExecuting PlanStatus = "executing"
	StatusDone      PlanStatus = "done"
	StatusFailed    PlanStatus = "failed"
)

// PlanStep is a single action the planner has decided to take.
type PlanStep struct {
	StepID  string         `json:"step_id"`
	Agent   string         `json:"agent"`  // Overlord agent name, or "builtin"
	Tool    string         `json:"tool"`   // module name or Overlord tool name
	Target  string         `json:"target"` // domain, IP, URL, or file path
	Params  map[string]any `json:"params"`
	Reason  string         `json:"reason"` // why Overlord chose this step
	Output  string         `json:"output,omitempty"`
	Status  string         `json:"status,omitempty"` // "pending"|"running"|"done"|"failed"
	Error   string         `json:"error,omitempty"`
}

// ScanPlan is the full AI-generated execution plan.
type ScanPlan struct {
	ID        string     `json:"id"`
	AssetIDs  []uint     `json:"asset_ids"`
	Mode      Mode       `json:"mode"`
	Steps     []PlanStep `json:"steps"`
	Status    PlanStatus `json:"status"`
	Error     string     `json:"error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// PlannerRequest is the API payload that triggers plan generation.
type PlannerRequest struct {
	AssetIDs []uint `json:"asset_ids"`
	Mode     Mode   `json:"mode"`
	MaxDepth int    `json:"max_depth"`
	MaxSteps int    `json:"max_steps"`
}

// assetSummary is a compact representation of an asset for the planning prompt.
type assetSummary struct {
	Name    string   `json:"name"`
	Targets []string `json:"targets"`
}

// findingSummary is a compact finding for the planning prompt.
type findingSummary struct {
	Target   string `json:"target"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Product  string `json:"product,omitempty"`
	CveID    string `json:"cve_id,omitempty"`
	IsKEV    bool   `json:"is_kev,omitempty"`
}

// graphSummary is a compact graph overview for the planning prompt.
type graphSummary struct {
	NodeCount int            `json:"node_count"`
	EdgeCount int            `json:"edge_count"`
	TypeCounts map[string]int `json:"type_counts"`
	ExploitNodes []string   `json:"exploit_nodes,omitempty"`
}
