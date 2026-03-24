// Package sbom detects and parses software bill-of-materials (dependency
// manifests) from a repository and returns a structured SBOM.
//
// Supported manifest formats:
//   - Node.js  — package.json  (top-level dependencies + devDependencies)
//   - Python   — requirements.txt  (PEP 440 specifiers)
//   - Go       — go.mod  (require directives)
//   - Java     — pom.xml  (dependencies block, regex-parsed to avoid xmlns issues)
package sbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dependency represents a single third-party package declared in a manifest.
type Dependency struct {
	// Name is the package name as it appears in the manifest.
	Name string `json:"name"`
	// Version is the declared version string (range specifiers preserved as-is).
	Version string `json:"version"`
	// File is the repo-relative path of the manifest file that declared this dep.
	File string `json:"file"`
	// Kind is "direct" for top-level deps and "dev" for dev/test-only deps.
	Kind string `json:"kind"`
}

// SBOM is the full software bill-of-materials for one repository scan.
type SBOM struct {
	// TargetID is the RepoTarget.ID this SBOM belongs to.
	TargetID string `json:"target_id"`
	// Dependencies is the deduplicated list of all discovered dependencies.
	Dependencies []Dependency `json:"dependencies"`
}

// BuildSBOM walks repoPath looking for known manifest files and returns a
// populated SBOM. targetID is stored verbatim in the returned struct.
// Walk errors and parse errors for individual files are silently skipped —
// best-effort SBOM generation is intentional.
func BuildSBOM(repoPath, targetID string) (*SBOM, error) {
	s := &SBOM{TargetID: targetID}

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, _ := filepath.Rel(repoPath, path)
		name := d.Name()

		switch name {
		case "package.json":
			deps, _ := parsePackageJSON(path, relPath)
			s.Dependencies = append(s.Dependencies, deps...)
		case "requirements.txt":
			deps, _ := parseRequirementsTxt(path, relPath)
			s.Dependencies = append(s.Dependencies, deps...)
		case "go.mod":
			deps, _ := parseGoMod(path, relPath)
			s.Dependencies = append(s.Dependencies, deps...)
		case "pom.xml":
			deps, _ := parsePomXML(path, relPath)
			s.Dependencies = append(s.Dependencies, deps...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sbom: walk %s: %w", repoPath, err)
	}

	s.Dependencies = dedup(s.Dependencies)
	return s, nil
}

// skipDirs mirrors the set used by SecretFinderScanner.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".idea": true, ".vscode": true, "target": true,
}

// ---------------------------------------------------------------------------
// package.json (Node.js)
// ---------------------------------------------------------------------------

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func parsePackageJSON(path, relPath string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	var deps []Dependency
	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: version, File: relPath, Kind: "direct"})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{Name: name, Version: version, File: relPath, Kind: "dev"})
	}
	return deps, nil
}

// ---------------------------------------------------------------------------
// requirements.txt (Python)
// ---------------------------------------------------------------------------

// reReqLine matches:  package==1.2.3  package>=1.0  package~=2.0  package
var reReqLine = regexp.MustCompile(`^([A-Za-z0-9_\-\.\[\]]+)\s*([><=!~^]{0,2}\s*[^\s#;]*)`)

func parseRequirementsTxt(path, relPath string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reReqLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		version := strings.TrimSpace(m[2])
		deps = append(deps, Dependency{Name: name, Version: version, File: relPath, Kind: "direct"})
	}
	return deps, scanner.Err()
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

// reGoRequire matches:  	github.com/foo/bar v1.2.3
var reGoRequire = regexp.MustCompile(`^\s+([\w\.\-/]+)\s+(v[\w\.\-+]+)`)

func parseGoMod(path, relPath string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	inRequire := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}
		// Single-line require: require github.com/foo/bar v1.2.3
		if strings.HasPrefix(trimmed, "require ") && !strings.Contains(trimmed, "(") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				name := parts[1]
				version := parts[2]
				kind := "direct"
				if strings.HasSuffix(line, "// indirect") {
					kind = "indirect"
				}
				deps = append(deps, Dependency{Name: name, Version: version, File: relPath, Kind: kind})
			}
			continue
		}
		if inRequire {
			m := reGoRequire.FindStringSubmatch(line)
			if m != nil {
				kind := "direct"
				if strings.Contains(line, "// indirect") {
					kind = "indirect"
				}
				deps = append(deps, Dependency{Name: m[1], Version: m[2], File: relPath, Kind: kind})
			}
		}
	}
	return deps, scanner.Err()
}

// ---------------------------------------------------------------------------
// pom.xml (Maven/Java) — regex-based to avoid encoding/xml namespace issues
// ---------------------------------------------------------------------------

// rePomDep captures a <dependency> block.
var rePomDep = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)

// rePomTag extracts a single XML tag value.
var rePomGroupID = regexp.MustCompile(`<groupId>\s*([^<]+)\s*</groupId>`)
var rePomArtifactID = regexp.MustCompile(`<artifactId>\s*([^<]+)\s*</artifactId>`)
var rePomVersion = regexp.MustCompile(`<version>\s*([^<]+)\s*</version>`)
var rePomScope = regexp.MustCompile(`<scope>\s*([^<]+)\s*</scope>`)

func parsePomXML(path, relPath string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var deps []Dependency
	for _, block := range rePomDep.FindAllString(content, -1) {
		gm := rePomGroupID.FindStringSubmatch(block)
		am := rePomArtifactID.FindStringSubmatch(block)
		if gm == nil || am == nil {
			continue
		}
		groupID := strings.TrimSpace(gm[1])
		artifactID := strings.TrimSpace(am[1])
		name := groupID + ":" + artifactID

		version := ""
		if vm := rePomVersion.FindStringSubmatch(block); vm != nil {
			version = strings.TrimSpace(vm[1])
		}

		kind := "direct"
		if sm := rePomScope.FindStringSubmatch(block); sm != nil {
			scope := strings.TrimSpace(strings.ToLower(sm[1]))
			if scope == "test" || scope == "provided" {
				kind = "dev"
			}
		}

		deps = append(deps, Dependency{Name: name, Version: version, File: relPath, Kind: kind})
	}
	return deps, nil
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

func dedup(deps []Dependency) []Dependency {
	seen := make(map[string]struct{}, len(deps))
	out := make([]Dependency, 0, len(deps))
	for _, d := range deps {
		key := d.File + "\x00" + d.Name + "\x00" + d.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}
