// Shodan InternetDB: https://internetdb.shodan.io/{ip}
// Free, no API key, returns pre-scanned port/banner data for any public IP.
// Used for passive pre-enrichment before active Naabu scanning.
package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var (
	idbCache   = make(map[string]*idbEntry)
	idbCacheMu sync.RWMutex
	idbClient  = &http.Client{Timeout: 8 * time.Second}
)

type idbEntry struct {
	result    *InternetDBResult
	fetchedAt time.Time
}

// InternetDBResult is the response from internetdb.shodan.io/{ip}
type InternetDBResult struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"` // CVE IDs
	CPEs      []string `json:"cpes"`
}

func queryInternetDB(ip string) (*InternetDBResult, error) {
	idbCacheMu.RLock()
	if e, ok := idbCache[ip]; ok && time.Since(e.fetchedAt) < 24*time.Hour {
		idbCacheMu.RUnlock()
		return e.result, nil
	}
	idbCacheMu.RUnlock()

	resp, err := idbClient.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ip))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		// IP not in Shodan — cache as empty result
		empty := &InternetDBResult{IP: ip}
		idbCacheMu.Lock()
		idbCache[ip] = &idbEntry{result: empty, fetchedAt: time.Now()}
		idbCacheMu.Unlock()
		return empty, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("internetdb returned %d", resp.StatusCode)
	}
	var result InternetDBResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	idbCacheMu.Lock()
	idbCache[ip] = &idbEntry{result: &result, fetchedAt: time.Now()}
	idbCacheMu.Unlock()
	return &result, nil
}

// EnrichTargetWithInternetDB pre-populates ports and CVE stubs from Shodan
// InternetDB before active scanning begins. Only adds records that don't exist.
func EnrichTargetWithInternetDB(db *gorm.DB, targetID uint, ip string) {
	// Only run on IPs (not domains — InternetDB is IP-only)
	if strings.ContainsAny(ip, "/") || !looksLikeIP(ip) {
		return
	}

	result, err := queryInternetDB(ip)
	if err != nil {
		utils.LogDebug("[InternetDB] Query failed for %s: %v", ip, err)
		return
	}
	if len(result.Ports) == 0 && len(result.Vulns) == 0 {
		return
	}

	portsAdded := 0
	for _, port := range result.Ports {
		res := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_id"}, {Name: "port"}},
			DoNothing: true,
		}).Create(&database.Port{
			TargetID: targetID,
			Port:     port,
			Protocol: "tcp",
			Service:  "unknown",
		})
		if res.RowsAffected > 0 {
			portsAdded++
		}
	}

	cvesAdded := 0
	for _, cveID := range result.Vulns {
		if !strings.HasPrefix(cveID, "CVE-") {
			continue
		}
		res := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "target_id"}, {Name: "product"}, {Name: "cve_id"}},
			DoNothing: true,
		}).Create(&database.CVE{
			TargetID: targetID,
			Product:  "shodan",
			CveID:    cveID,
			Severity: "unknown",
		})
		if res.RowsAffected > 0 {
			cvesAdded++
		}
	}

	if portsAdded > 0 || cvesAdded > 0 {
		utils.LogSuccess("[InternetDB] %s: pre-populated %d ports, %d CVE stubs passively", ip, portsAdded, cvesAdded)
	}
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
