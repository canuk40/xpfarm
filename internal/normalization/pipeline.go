// Package normalization is the entry point for the XPFarm Finding Normalization
// Engine. It orchestrates adapter dispatch, enrichment, fingerprinting,
// deduplication, and grouping.
//
// Typical call:
//
//	findings, groups, err := normalization.Run("nuclei", rawMap)
package normalization

import (
	"fmt"

	"xpfarm/internal/normalization/dedupe"
	"xpfarm/internal/normalization/grouping"
	"xpfarm/internal/normalization/model"
	"xpfarm/pkg/utils"
)

// EnrichAll applies every registered Enricher to a slice of findings that were
// created directly (not via an adapter). It also generates fingerprints and
// deduplicates. No grouping is performed — call normalization.Run when you have
// raw scanner output and want the full pipeline including grouping.
func EnrichAll(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	enrichers := GetEnrichers()
	for i := range findings {
		for _, e := range enrichers {
			if err := e.Enrich(&findings[i]); err != nil {
				utils.LogDebug("[normalization] enricher %q on finding %s: %v", e.Name(), findings[i].ID, err)
			}
		}
		findings[i].Fingerprint = dedupe.GenerateFingerprint(findings[i])
	}
	return dedupe.Deduplicate(findings)
}

// Run executes the full normalization pipeline for a single scanner output.
//
//  1. Dispatches raw to the registered Adapter for source.
//  2. Applies every registered Enricher to each finding (CWE → CVSS → EPSS → KEV).
//  3. Generates a deterministic fingerprint after enrichment.
//  4. Deduplicates findings by fingerprint.
//  5. Groups deduplicated findings by CWE / CVE / Severity / Target.
//
// Enrichment failures are logged and swallowed — they never abort the pipeline.
func Run(source string, raw map[string]any) ([]model.Finding, []model.NormalizedGroup, error) {
	adapter, ok := GetAdapter(source)
	if !ok {
		return nil, nil, fmt.Errorf("normalization: no adapter registered for source %q", source)
	}

	findings, err := adapter.Normalize(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("normalization: adapter %q: %w", source, err)
	}
	if len(findings) == 0 {
		return nil, nil, nil
	}

	enrichers := GetEnrichers()
	for i := range findings {
		for _, e := range enrichers {
			if err := e.Enrich(&findings[i]); err != nil {
				utils.LogDebug("[normalization] enricher %q on finding %s: %v", e.Name(), findings[i].ID, err)
			}
		}
		// Fingerprint after enrichment so CWE/CVE are included in the hash.
		findings[i].Fingerprint = dedupe.GenerateFingerprint(findings[i])
	}

	findings = dedupe.Deduplicate(findings)
	groups := grouping.GroupFindings(findings)

	return findings, groups, nil
}
