// Package grouping clusters normalized findings by CWE, CVE, Severity, and Target.
package grouping

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"xpfarm/internal/normalization/model"
)

// groupKey is the composite key used to cluster findings.
type groupKey struct {
	CWE      string
	CVE      string
	Severity string
	Target   string
}

func (k groupKey) id() string {
	h := sha256.New()
	fmt.Fprint(h, strings.Join([]string{k.CWE, k.CVE, k.Severity, k.Target}, "\x00"))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// GroupFindings clusters the input slice into NormalizedGroups.
// Findings without a CWE or CVE are still grouped — they cluster by Severity+Target.
// The returned slice order is non-deterministic; callers should sort if needed.
func GroupFindings(findings []model.Finding) []model.NormalizedGroup {
	index := make(map[groupKey]*model.NormalizedGroup)

	for _, f := range findings {
		k := groupKey{
			CWE:      f.CWE,
			CVE:      f.CVE,
			Severity: f.Severity,
			Target:   f.Target,
		}
		g, ok := index[k]
		if !ok {
			g = &model.NormalizedGroup{
				GroupID:  k.id(),
				CWE:      k.CWE,
				CVE:      k.CVE,
				Severity: k.Severity,
				Target:   k.Target,
			}
			index[k] = g
		}
		g.Findings = append(g.Findings, f)
	}

	groups := make([]model.NormalizedGroup, 0, len(index))
	for _, g := range index {
		groups = append(groups, *g)
	}
	return groups
}
