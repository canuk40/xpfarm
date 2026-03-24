// Package repo_scanner orchestrates all repository scanning stages:
//  1. Clone or update the repository
//  2. Run Semgrep (SAST)
//  3. Run Gitleaks secret scan
//  4. Run SecretFinder (Go-native secret scan)
//  5. Build SBOM
//  6. Normalize + enrich findings
//  7. Persist findings and SBOM
package repo_scanner

import (
	"context"
	"fmt"
	"log"
	"time"

	"xpfarm/internal/normalization"
	"xpfarm/internal/normalization/model"
	"xpfarm/internal/repo_scanner/sbom"
	"xpfarm/internal/repo_scanner/secrets"
	reposemgrep "xpfarm/internal/repo_scanner/semgrep"
	"xpfarm/internal/repos"
	repostore "xpfarm/internal/storage/repos"

	"gorm.io/gorm"
)

// ScanResult is the full output of a single repository scan.
type ScanResult struct {
	RepoTarget repos.RepoTarget
	Findings   []model.Finding
	SBOM       *sbom.SBOM
	Duration   time.Duration
	Errors     []string
}

// ScanRepo runs all scanning stages against target. It stores results in db and
// returns a ScanResult. ctx can be cancelled to abort in-progress stages.
//
// Individual stage failures are collected in ScanResult.Errors rather than
// halting the overall scan — best-effort output is more useful than silence.
func ScanRepo(ctx context.Context, db *gorm.DB, target repos.RepoTarget) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{RepoTarget: target}

	// ── 1. Clone / update ────────────────────────────────────────────────────
	log.Printf("[repo_scanner] cloning/updating %s", target.URL)
	repoPath, err := repos.CloneOrUpdate(target)
	if err != nil {
		return nil, fmt.Errorf("repo_scanner: clone %s: %w", target.URL, err)
	}

	// ── 2. Semgrep SAST ───────────────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("repo_scanner: cancelled before semgrep: %w", err)
	}
	log.Printf("[repo_scanner] running semgrep on %s", repoPath)
	semgrepFindings, err := reposemgrep.Run(repoPath, target.URL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("semgrep: %v", err))
		log.Printf("[repo_scanner] semgrep error (non-fatal): %v", err)
	} else {
		result.Findings = append(result.Findings, semgrepFindings...)
		log.Printf("[repo_scanner] semgrep: %d findings", len(semgrepFindings))
	}

	// ── 3. Gitleaks secret scan ───────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("repo_scanner: cancelled before gitleaks: %w", err)
	}
	if err := secrets.CheckGitleaksInstalled(); err == nil {
		log.Printf("[repo_scanner] running gitleaks on %s", repoPath)
		gl := &secrets.GitleaksScanner{RepoURL: target.URL}
		glFindings, err := gl.Scan(repoPath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("gitleaks: %v", err))
			log.Printf("[repo_scanner] gitleaks error (non-fatal): %v", err)
		} else {
			result.Findings = append(result.Findings, glFindings...)
			log.Printf("[repo_scanner] gitleaks: %d findings", len(glFindings))
		}
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("gitleaks skipped: %v", err))
		log.Printf("[repo_scanner] %v — skipping gitleaks", err)
	}

	// ── 4. SecretFinder (Go-native) ───────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("repo_scanner: cancelled before secretfinder: %w", err)
	}
	log.Printf("[repo_scanner] running secretfinder on %s", repoPath)
	sf := &secrets.SecretFinderScanner{RepoURL: target.URL}
	sfFindings, err := sf.Scan(repoPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("secretfinder: %v", err))
		log.Printf("[repo_scanner] secretfinder error (non-fatal): %v", err)
	} else {
		result.Findings = append(result.Findings, sfFindings...)
		log.Printf("[repo_scanner] secretfinder: %d findings", len(sfFindings))
	}

	// ── 5. SBOM ───────────────────────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("repo_scanner: cancelled before sbom: %w", err)
	}
	log.Printf("[repo_scanner] building SBOM for %s", repoPath)
	builtSBOM, err := sbom.BuildSBOM(repoPath, target.ID)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("sbom: %v", err))
		log.Printf("[repo_scanner] sbom error (non-fatal): %v", err)
	} else {
		result.SBOM = builtSBOM
		log.Printf("[repo_scanner] sbom: %d dependencies", len(builtSBOM.Dependencies))
	}

	// ── 6. Enrich directly-created findings (secretfinder produces model.Finding
	//        directly rather than going through an adapter).  ──────────────────
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("repo_scanner: cancelled before enrichment: %w", err)
	}
	result.Findings = normalization.EnrichAll(result.Findings)

	// ── 7. Persist ────────────────────────────────────────────────────────────
	if db != nil {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("repo_scanner: cancelled before persist: %w", err)
		}
		if err := repostore.SaveRepoScanResults(db, target.ID, result.Findings); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("persist findings: %v", err))
			log.Printf("[repo_scanner] persist findings error (non-fatal): %v", err)
		}
		if result.SBOM != nil {
			if err := repostore.SaveSBOM(db, result.SBOM); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("persist sbom: %v", err))
				log.Printf("[repo_scanner] persist sbom error (non-fatal): %v", err)
			}
		}
		// Update last-scan timestamp on the repo target record
		if err := repostore.UpdateLastScan(db, target.ID, time.Now().UTC()); err != nil {
			log.Printf("[repo_scanner] update last_scan error (non-fatal): %v", err)
		}
	}

	result.Duration = time.Since(start)
	log.Printf("[repo_scanner] scan of %s complete in %s — %d findings, %d errors",
		target.URL, result.Duration.Round(time.Millisecond), len(result.Findings), len(result.Errors))
	return result, nil
}
