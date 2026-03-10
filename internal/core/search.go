package core

import (
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
	"xpfarm/internal/database"
)

// SearchRule defines a single condition in the query builder
type SearchRule struct {
	Logical  string `json:"logical"` // AND / OR
	Field    string `json:"field"`
	Operator string `json:"operator"` // contains, equals, not_equals, regex, glob, gt, lt
	Value    string `json:"value"`
}

// SearchPayload is the JSON request from the UI
type SearchPayload struct {
	Rules []SearchRule `json:"rules"`
}

// SearchResult is the normalized structure returned to the UI table
type SearchResult struct {
	Type      string `json:"Type"`
	Value     string `json:"Value"`
	Details   string `json:"Details"`
	AssetName string `json:"AssetName"`
	Link      string `json:"Link"`
}

// GlobalSearch parses the dynamic payload and executes queries across models
func GlobalSearch(payload SearchPayload) ([]SearchResult, error) {
	db := database.GetDB()
	var finalResults []SearchResult

	if len(payload.Rules) == 0 {
		return finalResults, nil
	}

	// We will use standard Target as the base for many of these joins,
	// but because a user can search Port or WebAsset specifically, we map queries based on root table.
	// For simplicity in a dynamic generic search:
	// We build a query against Target, left joining WebAssets, Ports, and Vulns.

	query := db.Model(&database.Target{}).
		Select("targets.*, assets.name as asset_name").
		Joins("left join assets on assets.id = targets.asset_id").
		Joins("left join web_assets on web_assets.target_id = targets.id").
		Joins("left join ports on ports.target_id = targets.id").
		Joins("left join vulnerabilities on vulnerabilities.target_id = targets.id").
		Joins("left join cves on cves.target_id = targets.id").
		Group("targets.id") // Ensure we don't get massive duplication from joins

	var goRegexFilters []func(t *database.Target) bool

	// Conditionally group all rules to prevent OR clause bleed
	var ruleGroup *gorm.DB

	// Pre-check if any valid rules exist
	hasValidRules := false

	// Parse Rules into GORM scopes
	for _, rule := range payload.Rules {
		dbFieldStr := mapFieldToDB(rule.Field)
		if dbFieldStr == "" {
			continue
		}

		opStr, val, isRegex := mapOperator(rule.Operator, rule.Value)

		// If it's pure regex, SQLite doesn't natively support it in this driver easily.
		// So we construct a wildcard base search to narrow SQLite results if possible,
		// and push the real regex to a Go post-filter.
		if isRegex {
			// Create a compiled regex func for later
			compiled, err := regexp.Compile(rule.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for field %s: %v", rule.Field, err)
			}
			f := rule.Field // capture for closure
			goRegexFilters = append(goRegexFilters, func(t *database.Target) bool {
				return checkRegexMatch(t, f, compiled)
			})
			// Try to narrow SQL side with IS NOT NULL or LIKE '%' as dummy to keep it syntactically active
			if !hasValidRules {
				ruleGroup = db.Where(dbFieldStr + " IS NOT NULL AND " + dbFieldStr + " != ''")
			} else {
				if rule.Logical == "OR" {
					ruleGroup = ruleGroup.Or(dbFieldStr + " IS NOT NULL AND " + dbFieldStr + " != ''")
				} else {
					ruleGroup = ruleGroup.Where(dbFieldStr + " IS NOT NULL AND " + dbFieldStr + " != ''")
				}
			}
			hasValidRules = true
			continue
		}

		condition := fmt.Sprintf("%s %s ?", dbFieldStr, opStr)

		// For robust case-insensitive matching across database engines where LIKE may be case-sensitive
		if opStr == "LIKE" || opStr == "NOT LIKE" {
			condition = fmt.Sprintf("LOWER(%s) %s LOWER(?)", dbFieldStr, opStr)
		}

		if !hasValidRules {
			ruleGroup = db.Where(condition, val)
		} else {
			if rule.Logical == "OR" {
				ruleGroup = ruleGroup.Or(condition, val)
			} else {
				ruleGroup = ruleGroup.Where(condition, val)
			}
		}
		hasValidRules = true
	}

	if hasValidRules {
		query = query.Where(ruleGroup)
	}

	// Preload necessary relations to extract data for the results table
	query = query.Preload("Asset").Preload("WebAssets").Preload("Ports").Preload("Vulns").Preload("CVEs")

	var targets []database.Target
	if err := query.Find(&targets).Error; err != nil {
		return nil, err
	}

	// Post-process Regex Filters
	for _, t := range targets {
		matchedAllRegex := true
		for _, regFilter := range goRegexFilters {
			if !regFilter(&t) {
				matchedAllRegex = false
				break
			}
		}

		if matchedAllRegex {
			res := formatResult(t)
			finalResults = append(finalResults, res)
		}
	}

	return finalResults, nil
}

func mapFieldToDB(frontendField string) string {
	switch frontendField {
	case "target.type":
		return "targets.type"
	case "target.value":
		return "targets.value"
	case "target.status":
		return "targets.status"
	case "web.tech_stack":
		return "web_assets.tech_stack"
	case "web.status_code":
		return "web_assets.status_code"
	case "web.url":
		return "web_assets.url"
	case "web.title":
		return "web_assets.title"
	case "port.port":
		return "ports.port"
	case "port.service":
		return "ports.service"
	case "vuln.name":
		return "vulnerabilities.name"
	case "vuln.severity":
		return "vulnerabilities.severity"
	case "cve.id":
		return "cves.cve_id"
	case "cve.severity":
		return "cves.severity"
	}
	return ""
}

func mapOperator(op string, val string) (string, interface{}, bool) {
	switch op {
	case "contains":
		return "LIKE", "%" + val + "%", false
	case "equals":
		return "=", val, false
	case "not_equals":
		return "!=", val, false
	case "glob":
		// Replace * with % and ? with _ for SQL LIKE
		sqlGlob := strings.ReplaceAll(val, "*", "%")
		sqlGlob = strings.ReplaceAll(sqlGlob, "?", "_")
		return "LIKE", sqlGlob, false
	case "regex":
		return "", val, true // Flag true for post-filter
	case "gt":
		return ">", val, false
	case "lt":
		return "<", val, false
	}
	return "=", val, false
}

// checkRegexMatch checks if a specific target (with its preloaded relations) matches the regex for a field
func checkRegexMatch(t *database.Target, field string, r *regexp.Regexp) bool {
	switch field {
	case "target.type":
		return r.MatchString(t.Type)
	case "target.value":
		return r.MatchString(t.Value)
	case "target.status":
		return r.MatchString(t.Status)
	case "web.tech_stack":
		for _, w := range t.WebAssets {
			if r.MatchString(w.TechStack) {
				return true
			}
		}
	case "web.status_code":
		if len(t.WebAssets) == 0 {
			return false
		}
		for _, w := range t.WebAssets {
			if r.MatchString(fmt.Sprintf("%d", w.StatusCode)) {
				return true
			}
		}
	case "web.url":
		for _, w := range t.WebAssets {
			if r.MatchString(w.URL) {
				return true
			}
		}
	case "web.title":
		for _, w := range t.WebAssets {
			if r.MatchString(w.Title) {
				return true
			}
		}
	case "port.port":
		for _, p := range t.Ports {
			if r.MatchString(fmt.Sprintf("%d", p.Port)) {
				return true
			}
		}
	case "port.service":
		for _, p := range t.Ports {
			if r.MatchString(p.Service) {
				return true
			}
		}
	case "vuln.name":
		for _, v := range t.Vulns {
			if r.MatchString(v.Name) {
				return true
			}
		}
	case "vuln.severity":
		for _, v := range t.Vulns {
			if r.MatchString(v.Severity) {
				return true
			}
		}
	case "cve.id":
		for _, c := range t.CVEs {
			if r.MatchString(c.CveID) {
				return true
			}
		}
	case "cve.severity":
		for _, c := range t.CVEs {
			if r.MatchString(c.Severity) {
				return true
			}
		}
	}
	return false
}

func formatResult(t database.Target) SearchResult {
	res := SearchResult{
		Type:  t.Type,
		Value: t.Value,
		Link:  fmt.Sprintf("/target/%d", t.ID),
	}
	if t.AssetID != 0 && t.Asset != nil {
		res.AssetName = t.Asset.Name
	}

	// Create a summary for Details based on related data
	var details []string
	if len(t.WebAssets) > 0 {
		details = append(details, fmt.Sprintf("%d Web Assets", len(t.WebAssets)))
	}
	if len(t.Ports) > 0 {
		details = append(details, fmt.Sprintf("%d Ports", len(t.Ports)))
	}
	if len(t.Vulns) > 0 {
		details = append(details, fmt.Sprintf("%d Vulns", len(t.Vulns)))
	}

	res.Details = strings.Join(details, " | ")
	if res.Details == "" {
		res.Details = "Base Target"
	}
	return res
}
