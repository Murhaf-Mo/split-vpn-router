// Package platform locates Windows installation and per-user data files.
package platform

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"strings"
)

const (
	AppKey      = `Software\wsl-vpn-router`
	AppKeyValue = "InstallDir"
	AppDirName  = "wsl-vpn-router"
)

func SysExe(name string) string {
	if root := os.Getenv("SystemRoot"); root != "" {
		p := filepath.Join(root, "System32", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

// IsInstalled reports whether we're running as an installed product (vs a dev
// checkout). True when EITHER:
//   - the HKLM marker key the MSI writes is present, OR
//   - vpn.exe lives under a Program Files directory.
//
// The second check is a safety net: if the registry key is ever missing
// (failed write, manual file copy, AV stripping), an exe sitting in Program
// Files is still unmistakably "installed" — and we must route config.toml to
// %LOCALAPPDATA% rather than trying to write under read-only Program Files.
//
// In dev mode (running from a checkout under e.g. E:\...), both checks fail and
// the install + data layout collapses to a single directory, preserving the
// pre-1.0 single-directory project layout for hacking without an MSI build.
func IsInstalled() bool {
	if isCheckout() {
		return false
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, AppKey, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue(AppKeyValue); err == nil && v != "" {
			return true
		}
	}
	return runningFromProgramFiles()
}

// runningFromProgramFiles reports whether the current executable is under one
// of the Program Files roots (native or x86). Case-insensitive prefix match.
func runningFromProgramFiles() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	exeLower := strings.ToLower(filepath.Clean(exe))
	for _, env := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		if root := os.Getenv(env); root != "" {
			rootLower := strings.ToLower(filepath.Clean(root)) + string(filepath.Separator)
			if strings.HasPrefix(exeLower, rootLower) {
				return true
			}
		}
	}
	return false
}

// InstallDir returns the directory containing vpn.exe, vpnctl.py, static/, and
// other read-only assets shipped by the MSI.
//
//   - Installed:  HKLM\Software\wsl-vpn-router\InstallDir (e.g. "C:\Program Files\wsl-vpn-router")
//   - Dev:        the directory containing the running vpn.exe (a checkout)
func InstallDir() (string, error) {
	if isCheckout() {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.Dir(exe), nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, AppKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue(AppKeyValue); err == nil && v != "" {
			return v, nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func isCheckout() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	dir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(dir, "controller", "go.mod")); err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, "Dockerfile"))
	return err == nil
}

// DataDir returns the writable per-user directory holding config.toml,
// vpn.list, direct.list, and runtime/ (logs, pid files, generated configs).
//
//   - Installed:  %LOCALAPPDATA%\wsl-vpn-router  (created if missing)
//   - Dev:        same as InstallDir() — keeps the pre-1.0 single-dir layout
//     working from a checkout without any extra setup.
func DataDir() (string, error) {
	if !IsInstalled() {
		return InstallDir()
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", errors.New("LOCALAPPDATA not set")
	}
	dir := filepath.Join(base, AppDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
