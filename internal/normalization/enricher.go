package normalization

import "xpfarm/internal/normalization/model"

// Enricher augments a Finding in-place with additional threat intelligence.
// Enrichers must never overwrite a field that is already set; they only fill gaps.
//
// Implementations live in normalization/enrichers/<name>/ and register via init().
// Failures are logged and swallowed — enrichment is always best-effort.
type Enricher interface {
	// Name identifies the enricher (e.g. "cwe", "cvss", "epss", "kev").
	Name() string

	// Enrich populates additional fields on f. It receives a pointer so it can
	// modify the Finding directly. Returning a non-nil error causes the pipeline
	// to log the failure and continue with the next enricher.
	Enrich(f *model.Finding) error
}
