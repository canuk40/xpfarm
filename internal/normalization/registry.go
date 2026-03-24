package normalization

import (
	"fmt"
	"sync"
)

var (
	adapterMu  sync.RWMutex
	adapterReg = make(map[string]Adapter)

	enricherMu  sync.RWMutex
	enricherReg []Enricher
)

// RegisterAdapter adds an Adapter to the global registry.
// Panics on duplicate source names so mistakes are caught at startup.
func RegisterAdapter(a Adapter) {
	adapterMu.Lock()
	defer adapterMu.Unlock()
	if _, exists := adapterReg[a.Source()]; exists {
		panic(fmt.Sprintf("normalization: duplicate adapter for source %q", a.Source()))
	}
	adapterReg[a.Source()] = a
}

// GetAdapter returns the registered Adapter for the given source name.
func GetAdapter(source string) (Adapter, bool) {
	adapterMu.RLock()
	defer adapterMu.RUnlock()
	a, ok := adapterReg[source]
	return a, ok
}

// RegisterEnricher appends an Enricher to the global ordered enricher list.
// Enrichers are applied in registration order, so register CWE before CVSS/EPSS/KEV.
func RegisterEnricher(e Enricher) {
	enricherMu.Lock()
	defer enricherMu.Unlock()
	enricherReg = append(enricherReg, e)
}

// GetEnrichers returns a snapshot of the current enricher list.
func GetEnrichers() []Enricher {
	enricherMu.RLock()
	defer enricherMu.RUnlock()
	cp := make([]Enricher, len(enricherReg))
	copy(cp, enricherReg)
	return cp
}
