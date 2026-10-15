package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vpn/controller/internal/api"
	"github.com/vpn/controller/internal/backend"
	"github.com/vpn/controller/internal/config"
	"github.com/vpn/controller/internal/platform"
	"github.com/vpn/controller/internal/release"
	"github.com/vpn/controller/internal/router"
	"github.com/vpn/controller/internal/winproxy"
	"golang.org/x/sys/windows"
)

type Env struct {
	InstallDir, DataDir string
	Cfg                 *config.Config
}

func LoadEnv() (*Env, error) {
	install, err := platform.InstallDir()
	if err != nil {
		return nil, err
	}
	data, err := platform.DataDir()
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"vpn.list", "direct.list"} {
		target := filepath.Join(data, name)
		if _, err := os.Stat(target); os.IsNotExist(err) {
			b, _ := os.ReadFile(filepath.Join(install, name))
			if err := os.WriteFile(target, b, 0600); err != nil {
				return nil, err
			}
		}
	}
	cfg, err := config.Load(filepath.Join(data, "config.toml"))
	if err != nil {
		return nil, fmt.Errorf("load config (run vpn configure): %w", err)
	}
	return &Env{install, data, cfg}, nil
}

func Client(e *Env) *api.Client {
	cfg := e.Cfg
	if fresh, err := config.Load(e.Cfg.Path); err == nil {
		cfg = fresh
	}
	c := api.New("127.0.0.1", cfg.APIport)
	c.Token = backend.Token(e.DataDir)
	return c
}

func Up(e *Env) (result error) {
	name, _ := windows.UTF16PtrFromString(`Local\VPNRouterConnect-` + backend.Name(e.DataDir))
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return fmt.Errorf("another connection operation is in progress: %w", err)
	}
	defer windows.CloseHandle(mutex)
	cfg, err := config.Load(e.Cfg.Path)
	if err != nil {
		return err
	}
	for _, which := range []string{"vpn", "direct"} {
		body, err := os.ReadFile(filepath.Join(e.DataDir, which+".list"))
		if err != nil {
			return err
		}
		for _, entry := range router.ParseList(string(body)) {
			if _, err := router.Normalize(entry); err != nil {
				return err
			}
		}
	}
	// Validate everything that can fail locally before asking the VPN to authenticate.
	if err := router.CheckForwarding(cfg.ManageForwarding); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(e.InstallDir, "sing-box.exe")); err != nil {
		return fmt.Errorf("sing-box.exe is missing; run .\\prepare-runtime.ps1 or reinstall: %w", err)
	}
	if err := backend.Check(); err != nil {
		return err
	}
	if !router.Installed() || router.PreparedFor(e.InstallDir, e.DataDir) != nil {
		fmt.Println("[up] installing Windows router service (UAC)...")
		if router.Admin() {
			if err := router.Prepare(e.DataDir); err != nil {
				return err
			}
		} else {
			if err := router.Elevate(e.DataDir); err != nil {
				return err
			}
		}
	}
	if err := router.PreparedFor(e.InstallDir, e.DataDir); err != nil {
		return err
	}
	if status, err := Client(e).Quick().Status(); err == nil && status.ConnectionState == "connected" {
		if !router.ReadStatus().Active {
			if err := router.Control(true); err != nil {
				return err
			}
		}
		return Status(e)
	}
	// Save the canonical Docker-only schema. Old credentials/lists survive migration.
	if err := winproxy.CleanupLegacy(); err != nil {
		return err
	}
	if err := config.Save(cfg.Path, cfg); err != nil {
		return err
	}
	if err := backend.Start(e.InstallDir, e.DataDir, release.LocalVersion(), cfg); err != nil {
		return err
	}
	connected := false
	defer func() {
		if result != nil {
			_ = Client(e).Disconnect()
			if connected {
				_ = router.Control(false)
			}
		}
	}()
	client := Client(e)
	ready := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if _, err := client.Quick().Status(); err == nil {
			ready = true
			break
		}
	}
	if !ready {
		return fmt.Errorf("Docker daemon did not become ready; inspect docker logs %s", backend.Name(e.DataDir))
	}
	fmt.Println("[up] authenticating once; approve your VPN MFA request...")
	if _, err := client.Connect(); err != nil {
		return err
	}
	for deadline := time.Now().Add(130 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		s, err := client.Quick().Status()
		if err != nil {
			continue
		}
		if s.ConnectionState == "disconnected" {
			return fmt.Errorf("VPN disconnected: %s", s.Error)
		}
		if s.ConnectionState == "connected" {
			connected = true
			break
		}
	}
	if !connected {
		return fmt.Errorf("VPN connection timed out; reconnect manually")
	}
	if err := router.Control(true); err != nil {
		return err
	}
	fmt.Println("[up] Windows TUN routing is active; automatic login is disabled")
	return Status(e)
}

func Down(e *Env) error {
	// Remove interception first so direct networking remains usable even if Docker is stopped.
	var routerErr error
	if router.Installed() {
		routerErr = router.Control(false)
	}
	_ = Client(e).Disconnect()
	dockerErr := backend.Stop(e.DataDir)
	cleanupErr := winproxy.CleanupLegacy()
	if routerErr != nil {
		return routerErr
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	if dockerErr != nil {
		fmt.Println("[down] Docker cleanup:", dockerErr)
	}
	fmt.Println("[down] Windows routing stopped")
	return nil
}

// Down must remain available after a corrupt/deleted configuration or stopped Docker engine.
func EmergencyDown() error {
	data, err := platform.DataDir()
	if err != nil {
		return err
	}
	install, err := platform.InstallDir()
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(data, "config.toml"))
	if err != nil {
		cfg = &config.Config{APIport: 8889, Path: filepath.Join(data, "config.toml")}
	}
	return Down(&Env{InstallDir: install, DataDir: data, Cfg: cfg})
}

func Status(e *Env) error {
	native := router.ReadStatus()
	fmt.Printf("Windows router: active=%t", native.Active)
	if native.Error != "" {
		fmt.Print(" (", native.Error, ")")
	}
	fmt.Println()
	s, err := Client(e).Quick().Status()
	if err != nil {
		fmt.Println("Docker daemon: unavailable")
		return nil
	}
	fmt.Printf("VPN: %s\nMode: %s\nRelay: 127.0.0.1:%d (TCP/UDP)\n", s.ConnectionState, s.Mode, s.ProxyPort)
	if s.Error != "" {
		fmt.Println("VPN:", s.Error)
	}
	return nil
}

func Mode(e *Env, args []string) error {
	if len(args) == 0 {
		cfg, err := config.Load(e.Cfg.Path)
		if err != nil {
			return err
		}
		fmt.Println(cfg.Mode)
		return nil
	}
	mode := strings.ToLower(args[0])
	if IsDaemonReachable(e) {
		if err := Client(e).SetMode(mode); err != nil {
			return err
		}
		fmt.Println("Mode:", mode, "(applies to new connections within a few seconds)")
		return nil
	}
	if err := config.SetMode(e.Cfg.Path, mode); err != nil {
		return err
	}
	fmt.Println("Mode:", mode, "(applies to new connections within a few seconds)")
	return nil
}

func Add(e *Env, args []string) error    { return editList(e, args, true) }
func Remove(e *Env, args []string) error { return editList(e, args, false) }
func editList(e *Env, args []string, add bool) error {
	which := "vpn"
	var patterns []string
	for _, arg := range args {
		switch arg {
		case "-direct", "--direct", "direct":
			which = "direct"
		case "-vpn", "--vpn", "vpn":
			which = "vpn"
		default:
			entry, err := router.Normalize(arg)
			if err != nil {
				return err
			}
			patterns = append(patterns, entry)
		}
	}
	if len(patterns) == 0 {
		return fmt.Errorf("supply a domain, URL, IP or CIDR")
	}
	if IsDaemonReachable(e) {
		var err error
		if add {
			_, err = Client(e).ListAdd(which, patterns)
		} else {
			_, err = Client(e).ListRemove(which, patterns)
		}
		return err
	}
	// Offline edits still work. Canonicalize legacy URL inputs at the same time.
	path := filepath.Join(e.DataDir, which+".list")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	values := router.ParseList(string(b))
	var normalized []string
	for _, v := range values {
		n, err := router.Normalize(v)
		if err != nil {
			return err
		}
		normalized = append(normalized, n)
	}
	for _, p := range patterns {
		found := false
		var next []string
		for _, v := range normalized {
			if v == p {
				found = true
				if !add {
					continue
				}
			}
			next = append(next, v)
		}
		if add && !found {
			next = append(next, p)
		}
		normalized = next
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(normalized, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func List(e *Env) error {
	for _, which := range []string{"vpn", "direct"} {
		b, err := os.ReadFile(filepath.Join(e.DataDir, which+".list"))
		if err != nil {
			return err
		}
		fmt.Println("===", which, "===")
		fmt.Print(string(b))
	}
	return nil
}
func Reload(e *Env) error {
	fmt.Println("Routing lists are watched automatically; new connections use the updated rules.")
	return nil
}
func Restart(e *Env) error {
	if err := Down(e); err != nil {
		return err
	}
	return Up(e)
}
func SyncHosts(e *Env) error {
	fmt.Println("Windows hosts-file mappings are read by the routing service automatically.")
	return nil
}
func DashboardURL(e *Env) string {
	return fmt.Sprintf("http://127.0.0.1:%d/#token=%s", e.Cfg.APIport, backend.Token(e.DataDir))
}
func OpenDashboard(e *Env, hash string) error {
	if hash != "" {
		hash = "&" + strings.TrimPrefix(hash, "#")
	}
	verb, _ := windows.UTF16PtrFromString("open")
	url, _ := windows.UTF16PtrFromString(DashboardURL(e) + hash)
	return windows.ShellExecute(0, verb, url, nil, nil, 1)
}
func IsDaemonReachable(e *Env) bool { _, err := Client(e).Quick().Status(); return err == nil }

func Logs(e *Env, args []string) error {
	name := "pac"
	follow := false
	for _, arg := range args {
		switch arg {
		case "oc", "pac", "proxy":
			name = arg
		case "-f", "--follow":
			follow = true
		}
	}
	seen := ""
	for {
		out, err := Client(e).LogTail(name, 200)
		if err != nil {
			return err
		}
		if strings.HasPrefix(out, seen) {
			fmt.Print(out[len(seen):])
		} else {
			fmt.Print(out)
		}
		seen = out
		if !follow {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func Autostart(e *Env, args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "enable", "on":
		exe := filepath.Join(e.InstallDir, "vpn-tray.exe")
		if err := winproxy.EnableAutostart(exe); err != nil {
			return err
		}
		fmt.Println("Tray autostart enabled; this never connects the VPN")
		return nil
	case "disable", "off":
		return winproxy.DisableAutostart()
	case "status":
		path, active := winproxy.AutostartStatus()
		fmt.Println("Tray autostart:", active, path)
		return nil
	default:
		return fmt.Errorf("use autostart enable, disable or status")
	}
}

func Usage() {
	fmt.Println(`vpn — Docker VPN runtime with a Windows TUN router
  vpn configure                  VPN credentials; auto reconnect defaults off
  vpn up | down | restart         explicit connect/disconnect (Up installs the service with UAC)
  vpn status                      VPN and Windows router health
  vpn mode [direct-default|vpn-default]
  vpn add [-vpn|-direct] <URL|domain|IP|CIDR>...
  vpn remove [-vpn|-direct] <entry>...
  vpn list | reload | sync-hosts
  vpn logs [oc|pac|proxy] [-f]
  vpn dashboard | tray
  vpn autostart [enable|disable|status]
  vpn build-image                 build/update the contained VPN runtime
  vpn repair-proxy                remove recognized legacy router proxy settings
  vpn router-uninstall            remove the Windows service (administrator)
  vpn upgrade | version`)
}
