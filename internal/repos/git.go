// Package repos manages Git repository targets: their model, workspace paths,
// and the clone/refresh lifecycle.
package repos

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// NewID returns a random UUID v4 string for use as a RepoTarget ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RepoTarget describes a Git repository that XPFarm will scan.
type RepoTarget struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Branch    string    `json:"branch"`
	LocalPath string    `json:"local_path"`
	LastScan  time.Time `json:"last_scan"`
}

// WorkspacePath returns the local filesystem path where the repo is (or will be)
// checked out. If LocalPath is set explicitly it is used directly; otherwise a
// deterministic path under data/repos/<id> is returned.
func (r *RepoTarget) WorkspacePath() string {
	if r.LocalPath != "" {
		return r.LocalPath
	}
	return filepath.Join("data", "repos", r.ID)
}

// CloneOrUpdate ensures the repository is present on disk and up-to-date.
//
//   - If the workspace does not contain a .git directory, the repo is cloned
//     at --depth 1 for speed. If the requested branch does not exist the clone
//     is retried without --branch to fall back to the remote's default branch.
//   - If the workspace already contains a .git directory, a fetch + hard reset
//     is performed to bring it in sync with the remote.
//
// Returns the absolute local path on success.
func CloneOrUpdate(target RepoTarget) (string, error) {
	path := target.WorkspacePath()
	branch := target.Branch
	if branch == "" {
		branch = "main"
	}

	gitDir := filepath.Join(path, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return clone(target.URL, branch, path)
	}
	return refresh(path, branch)
}

// clone performs a shallow git clone, retrying without --branch if the named
// branch does not exist on the remote.
func clone(url, branch, path string) (string, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", fmt.Errorf("repos: create workspace %s: %w", path, err)
	}

	args := []string{"clone", "--depth", "1", "--branch", branch, url, path}
	if out, err := runGit(args...); err != nil {
		// Remove partial clone before retrying
		os.RemoveAll(path)
		if err2 := os.MkdirAll(path, 0o755); err2 != nil {
			return "", fmt.Errorf("repos: recreate workspace: %w", err2)
		}
		// Retry without --branch — uses remote's default branch
		args2 := []string{"clone", "--depth", "1", url, path}
		if out2, err2 := runGit(args2...); err2 != nil {
			return "", fmt.Errorf("repos: git clone %s: %s\n%s", url, err2, out2)
		}
		_ = out
	}
	return path, nil
}

// refresh fetches the latest commits and hard-resets the working tree.
func refresh(path, branch string) (string, error) {
	if out, err := runGit("-C", path, "fetch", "--depth", "1", "origin"); err != nil {
		return "", fmt.Errorf("repos: git fetch in %s: %s\n%w", path, out, err)
	}
	if out, err := runGit("-C", path, "reset", "--hard", "origin/"+branch); err != nil {
		return "", fmt.Errorf("repos: git reset in %s: %s\n%w", path, out, err)
	}
	return path, nil
}

// runGit executes git with the given arguments and returns combined output.
func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// CheckGitInstalled returns an error if git is not found in PATH.
func CheckGitInstalled() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("repos: git is not installed or not in PATH")
	}
	return nil
}
