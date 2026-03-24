// Package epss enriches findings with an EPSS (Exploit Prediction Scoring System)
// probability fetched from the FIRST.org API (https://api.first.org/data/v1/epss).
//
// EPSS scores range 0–1 and represent the probability that a CVE will be
// exploited in the wild within the next 30 days.
//
// Behaviour:
//   - Skips findings with no CVE or an already-set EPSS score.
//   - Caches scores in memory.
//   - 6-second HTTP timeout per request.
//   - Returns nil on any error — EPSS enrichment is always best-effort.
package epss

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
)

func init() {
	normalization.RegisterEnricher(&Enricher{
		client: &http.Client{Timeout: 6 * time.Second},
		cache:  make(map[string]float64),
	})
}

const epssBaseURL = "https://api.first.org/data/v1/epss"

// Enricher fetches EPSS scores from the FIRST.org API.
type Enricher struct {
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]float64 // CVE-ID → epss score (-1 = not found)
}

func (e *Enricher) Name() string { return "epss" }

func (e *Enricher) Enrich(f *model.Finding) error {
	if f.EPSS != nil || f.CVE == "" {
		return nil
	}
	cve := strings.ToUpper(strings.TrimSpace(f.CVE))

	score, err := e.fetchScore(cve)
	if err != nil {
		return err
	}
	if score >= 0 {
		f.EPSS = &score
	}
	return nil
}

func (e *Enricher) fetchScore(cve string) (float64, error) {
	e.mu.RLock()
	if score, ok := e.cache[cve]; ok {
		e.mu.RUnlock()
		if score < 0 {
			return -1, nil
		}
		return score, nil
	}
	e.mu.RUnlock()

	url := fmt.Sprintf("%s?cve=%s", epssBaseURL, cve)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1, fmt.Errorf("epss enricher: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("epss enricher: %s: %w", cve, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("epss enricher: FIRST API returned HTTP %d for %s", resp.StatusCode, cve)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64 KB cap
	if err != nil {
		return -1, fmt.Errorf("epss enricher: read body: %w", err)
	}

	score, err := parseEPSSScore(body)
	if err != nil {
		return -1, fmt.Errorf("epss enricher: parse %s: %w", cve, err)
	}

	e.mu.Lock()
	e.cache[cve] = score
	e.mu.Unlock()

	return score, nil
}

// epssResponse mirrors the FIRST.org EPSS API response shape.
type epssResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`       // encoded as a decimal string, e.g. "0.97520"
		Percentile string `json:"percentile"` // e.g. "0.99999"
	} `json:"data"`
}

// parseEPSSScore decodes the FIRST.org API response and returns the EPSS score.
// Returns -1 when the CVE is not in the EPSS dataset.
func parseEPSSScore(body []byte) (float64, error) {
	var r epssResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return -1, fmt.Errorf("json decode: %w", err)
	}
	if r.Status != "OK" && r.StatusCode != 200 {
		return -1, fmt.Errorf("API status: %s (%d)", r.Status, r.StatusCode)
	}
	if len(r.Data) == 0 {
		return -1, nil // CVE not in EPSS dataset
	}
	score, err := strconv.ParseFloat(strings.TrimSpace(r.Data[0].EPSS), 64)
	if err != nil {
		return -1, fmt.Errorf("parse score %q: %w", r.Data[0].EPSS, err)
	}
	return score, nil
}
