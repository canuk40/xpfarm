package normalization

import "xpfarm/internal/normalization/model"

// Adapter converts raw scanner output (a map decoded from JSON/XML) into one
// or more canonical model.Finding values.
//
// Implementations live in normalization/adapters/<scanner>/ and self-register
// in init() by calling RegisterAdapter — no direct import from this package
// is needed outside of the adapters themselves.
type Adapter interface {
	// Source returns the scanner name this adapter handles (e.g. "nuclei").
	// It must match the "source" key callers pass to Run().
	Source() string

	// Normalize converts the raw map into canonical findings.
	// Returning (nil, nil) is valid when the raw data contains no findings
	// (e.g. a clean semgrep run). Returning an error aborts the pipeline for
	// that call but does not affect other in-flight normalizations.
	Normalize(raw map[string]any) ([]model.Finding, error)
}
