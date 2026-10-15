// Package release knows how to talk to GitHub Releases for the wsl-vpn-router
// repo: looks up the latest tag, builds MSI download URLs, and answers "is the
// remote tag newer than the locally-embedded version?".
//
// The package is deliberately stdlib-only and has a short HTTP timeout — it's
// called from a tray-side goroutine that must not block the UI loop, and from
// the `vpn upgrade` CLI verb where a hang would be a worse UX than a fail-soft.
package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Repo points at the canonical GitHub repository. Hard-coded because the
// release pipeline writes asset names that depend on the repo path, and we
// want all updates to come from one place (no third-party mirroring).
const Repo = "Murhaf-Mo/split-vpn-router"

// localVersion is stamped by the release build via:
//   go build -ldflags "-X github.com/vpn/controller/internal/release.localVersion=v1.2.3" ...
// Dev builds leave it as "dev". Exposed via LocalVersion() so callers don't
// import the main package (which would cycle).
var localVersion = "dev"

// LocalVersion returns the version embedded at build time (or "dev").
func LocalVersion() string { return localVersion }

// HTTPTimeout caps the latest-release lookup. Callers handle errors silently.
var HTTPTimeout = 5 * time.Second

// LatestVersion fetches the most recent non-draft release tag from GitHub and
// returns it normalized (leading "v" stripped — "v1.2.3" -> "1.2.3"). Returns
// an error on network failure, GitHub rate limit, or missing tag_name; callers
// (tray daily-check, vpn upgrade) treat any error as "no update visible".
func LatestVersion(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", Repo)
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// Pin the API version so future GitHub changes don't quietly reshape the response.
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github releases: HTTP %d", resp.StatusCode)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	tag := strings.TrimSpace(body.TagName)
	if tag == "" {
		return "", fmt.Errorf("github releases: empty tag_name")
	}
	return strings.TrimPrefix(tag, "v"), nil
}

// MSIDownloadURL builds the URL for the MSI artifact attached to a given tag.
// The release pipeline (`.github/workflows/release.yml`) MUST upload the asset
// with this exact filename for `vpn upgrade` to find it.
func MSIDownloadURL(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("https://github.com/%s/releases/download/v%s/wsl-vpn-router-%s.msi", Repo, v, v)
}

// SHA256SidecarURL returns the URL of the `.sha256` sidecar uploaded next to
// the MSI. `vpn upgrade` verifies the downloaded MSI against this hash before
// invoking msiexec.
func SHA256SidecarURL(version string) string {
	return MSIDownloadURL(version) + ".sha256"
}

// IsNewer reports whether `remote` is strictly greater than `local` under
// semver-ish ordering: dot-separated numeric components, longer compared as
// having trailing zeros. Any non-numeric component (e.g. "dev", "v1.2-rc1")
// makes the local version sort as "older" so dev builds always see remote
// releases as upgrades. Pre-release suffixes after a numeric tail (e.g.
// "1.2.3-rc1") are ignored for the comparison.
//
// This avoids pulling in a full semver dependency for the handful of digits
// we actually care about. Edge cases (build metadata, alphabetic pre-releases)
// are not supported — if those become real, swap in golang.org/x/mod/semver.
func IsNewer(local, remote string) bool {
	if local == remote {
		return false
	}
	if local == "" || local == "dev" {
		return true
	}
	lp := splitVersion(local)
	rp := splitVersion(remote)
	n := len(lp)
	if len(rp) > n {
		n = len(rp)
	}
	for i := 0; i < n; i++ {
		var l, r int
		if i < len(lp) {
			l = lp[i]
		}
		if i < len(rp) {
			r = rp[i]
		}
		if l != r {
			return r > l
		}
	}
	return false
}

func splitVersion(s string) []int {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i] // drop pre-release / build metadata
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil // non-numeric — treat as "unknown / older"
		}
		out = append(out, n)
	}
	return out
}
