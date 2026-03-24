// Package cvss enriches findings with a CVSS base score fetched from the NVD
// REST API v2 (https://services.nvd.nist.gov/rest/json/cves/2.0).
//
// Behaviour:
//   - Skips findings with no CVE or an already-set CVSS score.
//   - Caches scores in memory to avoid redundant API calls within a process.
//   - Reads NVD_API_KEY from the environment; without a key NVD enforces a
//     rolling 5-requests/30-second limit. With a key the limit is 50/30s.
//   - Applies a 6-second HTTP timeout per request.
//   - On any error (network, rate limit, parse) the enricher returns nil so
//     the pipeline continues — CVSS is always best-effort.
package cvss

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Enricher fetches CVSS base scores from the NVD API.
type Enricher struct {
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]float64 // CVE-ID → base score (-1 = not found)
}

func (e *Enricher) Name() string { return "cvss" }

func (e *Enricher) Enrich(f *model.Finding) error {
	if f.CVSS != nil || f.CVE == "" {
		return nil
	}
	cve := strings.ToUpper(strings.TrimSpace(f.CVE))

	score, err := e.fetchScore(cve)
	if err != nil {
		return err // pipeline logs and continues
	}
	if score >= 0 {
		f.CVSS = &score
	}
	return nil
}

func (e *Enricher) fetchScore(cve string) (float64, error) {
	// Check cache first
	e.mu.RLock()
	if score, ok := e.cache[cve]; ok {
		e.mu.RUnlock()
		if score < 0 {
			return -1, nil // cached "not found"
		}
		return score, nil
	}
	e.mu.RUnlock()

	url := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, cve)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1, fmt.Errorf("cvss enricher: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("cvss enricher: %s: %w", cve, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return -1, fmt.Errorf("cvss enricher: NVD rate limit hit for %s (set NVD_API_KEY env var)", cve)
	}
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("cvss enricher: NVD returned HTTP %d for %s", resp.StatusCode, cve)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256 KB cap
	if err != nil {
		return -1, fmt.Errorf("cvss enricher: read body: %w", err)
	}

	score, err := parseNVDScore(body)
	if err != nil {
		return -1, fmt.Errorf("cvss enricher: parse %s: %w", cve, err)
	}

	e.mu.Lock()
	e.cache[cve] = score
	e.mu.Unlock()

	return score, nil
}

// nvdResponse is a minimal decode target for the NVD CVE 2.0 API.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics struct {
				V31 []struct {
					CVSSData struct{ BaseScore float64 } `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					CVSSData struct{ BaseScore float64 } `json:"cvssData"`
				} `json:"cvssMetricV30"`
				V2 []struct {
					CVSSData struct{ BaseScore float64 } `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// parseNVDScore extracts the CVSS base score from the NVD API response body.
// It tries CVSS 3.1 first, then 3.0, then 2.0.
// Returns -1 when no score is available (not the same as an error).
func parseNVDScore(body []byte) (float64, error) {
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return -1, fmt.Errorf("json decode: %w", err)
	}
	if len(r.Vulnerabilities) == 0 {
		return -1, nil // CVE not in NVD
	}
	m := r.Vulnerabilities[0].CVE.Metrics
	if len(m.V31) > 0 && m.V31[0].CVSSData.BaseScore > 0 {
		return m.V31[0].CVSSData.BaseScore, nil
	}
	if len(m.V30) > 0 && m.V30[0].CVSSData.BaseScore > 0 {
		return m.V30[0].CVSSData.BaseScore, nil
	}
	if len(m.V2) > 0 && m.V2[0].CVSSData.BaseScore > 0 {
		return m.V2[0].CVSSData.BaseScore, nil
	}
	return -1, nil
}
