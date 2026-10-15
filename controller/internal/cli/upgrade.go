package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vpn/controller/internal/platform"
	"github.com/vpn/controller/internal/release"
)

// Upgrade implements `vpn upgrade`.
//
// Flow:
//  1. GET the latest release tag from the GitHub API.
//  2. If the local version is already >= remote, print and exit 0.
//  3. Download the MSI + its .sha256 sidecar into %TEMP%.
//  4. Verify SHA-256.
//  5. Spawn `msiexec /i <msi> /qb` (basic UI, UAC prompts).
//
// We deliberately DON'T self-terminate before launching msiexec — the running
// vpn.exe and the running vpn-tray.exe both keep their .exe files locked, but
// MSI's MajorUpgrade phase queues a file replace via MoveFileEx + reboot if
// needed. In practice MSI's ScheduleReboot logic + InstallValidate gracefully
// closes the tray (because the tray registers a SCM-like restart manager
// handle); a future improvement is to handle that explicitly here.
func Upgrade(args []string) error {
	local := release.LocalVersion()
	fmt.Printf("current: %s\n", local)
	if local == "dev" {
		return fmt.Errorf("this is an unreleased development build; rebuild the checkout instead of replacing it with a published release")
	}

	remote, err := release.LatestVersion(context.Background())
	if err != nil {
		return fmt.Errorf("checking GitHub for latest release: %w", err)
	}
	fmt.Printf("latest:  %s\n", remote)

	if !release.IsNewer(local, remote) {
		fmt.Println("already up to date.")
		return nil
	}

	msiURL := release.MSIDownloadURL(remote)
	shaURL := release.SHA256SidecarURL(remote)
	tmpDir, err := os.MkdirTemp("", "wsl-vpn-router-upgrade-*")
	if err != nil {
		return err
	}
	// Don't auto-clean tmpDir on success — msiexec runs async and reads the
	// MSI after this process exits. The OS evicts %TEMP% later.

	msiPath := filepath.Join(tmpDir, fmt.Sprintf("wsl-vpn-router-%s.msi", remote))
	fmt.Printf("downloading %s ...\n", msiURL)
	if err := downloadTo(msiURL, msiPath); err != nil {
		return fmt.Errorf("downloading MSI: %w", err)
	}

	fmt.Println("verifying SHA-256 ...")
	expected, err := fetchExpectedSHA(shaURL)
	if err != nil {
		return fmt.Errorf("fetching sha256 sidecar: %w", err)
	}
	actual, err := fileSHA256(msiPath)
	if err != nil {
		return fmt.Errorf("hashing MSI: %w", err)
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", actual, expected)
	}

	fmt.Println("launching installer (UAC will prompt) ...")
	// /qb = basic UI with progress bar; /norestart = never silently reboot.
	cmd := exec.Command(platform.SysExe("msiexec.exe"), "/i", msiPath, "/qb", "/norestart")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting msiexec: %w", err)
	}
	// Release msiexec from our wait group — it'll run to completion after we exit.
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	fmt.Println("upgrade launched; this process exits now.")
	return nil
}

// downloadTo streams an HTTP GET into the named file. Fails if status != 200.
func downloadTo(url, dst string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// fetchExpectedSHA pulls the .sha256 sidecar. Format is one of:
//
//	"<hex>"                       (bare hash)
//	"<hex>  <filename>"           (shasum / sha256sum format)
//
// Returns the hex digest.
func fetchExpectedSHA(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	first := strings.TrimSpace(strings.SplitN(string(body), "\n", 2)[0])
	if i := strings.IndexAny(first, " \t"); i >= 0 {
		first = first[:i]
	}
	if first == "" {
		return "", fmt.Errorf("empty sha256 sidecar")
	}
	return first, nil
}

// fileSHA256 returns hex-encoded SHA-256 of a file's contents.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
