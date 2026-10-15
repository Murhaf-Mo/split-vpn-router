package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn/controller/internal/backend"
	"github.com/vpn/controller/internal/config"
	"github.com/vpn/controller/internal/release"
	"github.com/vpn/controller/internal/router"
	"github.com/vpn/controller/internal/winproxy"
)

var startLock sync.Mutex

// Start prepares the dashboard and an idle routing service. It never authenticates
// or activates the adapter; the service waits for a connected VPN's metadata.
func Start(e *Env) error {
	startLock.Lock()
	defer startLock.Unlock()
	cfg, err := config.Load(e.Cfg.Path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(e.InstallDir, "sing-box.exe")); err != nil {
		return fmt.Errorf("sing-box.exe is missing; reinstall the app: %w", err)
	}
	if err := backend.Check(); err != nil {
		return err
	}
	if !router.Installed() || router.PreparedFor(e.InstallDir, e.DataDir) != nil {
		fmt.Println("[start] preparing Windows router service (UAC)...")
		if router.Admin() {
			err = router.Prepare(e.DataDir)
		} else {
			err = router.Elevate(e.DataDir)
		}
		if err != nil {
			return err
		}
	}
	if err := router.PreparedFor(e.InstallDir, e.DataDir); err != nil {
		return err
	}
	if err := winproxy.CleanupLegacy(); err != nil {
		return err
	}
	if err := config.Save(cfg.Path, cfg); err != nil {
		return err
	}
	if !IsDaemonReachable(e) || !backend.Current(e.InstallDir, e.DataDir) {
		if router.Running() {
			if err := router.Control(false); err != nil {
				return err
			}
		}
		fmt.Println("[start] preparing Docker runtime; no VPN login...")
		if err := backend.Start(e.InstallDir, e.DataDir, release.LocalVersion(), cfg); err != nil {
			return err
		}
		ready := false
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
			if IsDaemonReachable(e) {
				ready = true
				break
			}
		}
		if !ready {
			return fmt.Errorf("Docker API did not become ready; inspect docker logs %s", backend.Name(e.DataDir))
		}
	}
	if err := router.StartIdle(); err != nil {
		return err
	}
	fmt.Println("[start] dashboard ready; choose Connect to authenticate")
	return nil
}
