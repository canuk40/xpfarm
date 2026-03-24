// Package kev enriches findings with the CISA Known Exploited Vulnerabilities
// (KEV) flag. If a finding's CVE appears in CISA's KEV catalog, Finding.KEV
// is set to true.
//
// The KEV catalog is downloaded from CISA once per process start using
// sync.Once. If the download fails, the enricher degrades gracefully and logs
// the error — it will not block the normalization pipeline.
//
// CISA KEV catalog URL:
//
//	https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
	"xpfarm/pkg/utils"
)

func init() {
	normalization.RegisterEnricher(newEnricher())
}

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Enricher flags findings whose CVE appears in CISA's KEV catalog.
type Enricher struct {
	once   sync.Once
	kevSet map[string]struct{} // lowercased CVE IDs
	loadErr error
	client *http.Client
}

func newEnricher() *Enricher {
	return &Enricher{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (e *Enricher) Name() string { return "kev" }

func (e *Enricher) Enrich(f *model.Finding) error {
	if f.CVE == "" {
		return nil
	}
	// Load the catalog exactly once per process
	e.once.Do(func() {
		if err := e.loadCatalog(); err != nil {
			e.loadErr = err
			utils.LogDebug("[kev enricher] failed to load CISA KEV catalog: %v", err)
		} else {
			utils.LogDebug("[kev enricher] loaded %d KEV entries", len(e.kevSet))
		}
	})
	if e.loadErr != nil || e.kevSet == nil {
		return nil // degrade gracefully
	}

	cve := strings.ToLower(strings.TrimSpace(f.CVE))
	if _, ok := e.kevSet[cve]; ok {
		f.KEV = true
	}
	return nil
}

// loadCatalog downloads and parses the CISA KEV JSON catalog.
func (e *Enricher) loadCatalog() error {
	req, err := http.NewRequest(http.MethodGet, kevURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "XPFarm-KEV-Enricher/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA returned HTTP %d", resp.StatusCode)
	}

	// Catalog is ~1.5 MB; cap at 8 MB to be safe
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var catalog struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	set := make(map[string]struct{}, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		if v.CVEID != "" {
			set[strings.ToLower(v.CVEID)] = struct{}{}
		}
	}
	e.kevSet = set
	return nil
}
