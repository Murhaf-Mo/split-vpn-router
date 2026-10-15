// Package winproxy only repairs proxy settings left by the legacy version.
// Native TUN routing does not install PAC, environment variables or Git proxies.
package winproxy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/BurntSushi/toml"
	"github.com/vpn/controller/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const environmentKey = `Environment`

func GetAutoConfigURL() string {
	k, e := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if e != nil {
		return ""
	}
	defer k.Close()
	s, _, _ := k.GetStringValue("AutoConfigURL")
	return s
}

func legacyProxy(value, host, port string) bool {
	u, err := url.Parse(value)
	if err != nil || host == "" || u.User != nil || u.Scheme != "http" || u.Port() != port || (u.Path != "" && u.Path != "/") {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.IsPrivate() && u.Hostname() == host
}

func CleanupLegacy() error {
	data, err := platform.DataDir()
	if err != nil {
		return err
	}
	// Checkout builds can migrate settings left by an installed old release.
	if _, err := os.Stat(filepath.Join(data, "runtime", "wsl-keepalive.pid")); err != nil {
		body, _ := os.ReadFile(filepath.Join(data, "config.toml"))
		if !strings.Contains(string(body), "[wsl]") {
			profile := filepath.Join(os.Getenv("LOCALAPPDATA"), platform.AppDirName)
			if _, err := os.Stat(filepath.Join(profile, "runtime", "wsl-keepalive.pid")); err == nil {
				data = profile
			} else {
				oldConfig, _ := os.ReadFile(filepath.Join(profile, "config.toml"))
				if strings.Contains(string(oldConfig), "[wsl]") {
					data = profile
				}
			}
		}
	}
	marker := false
	if _, err := os.Stat(filepath.Join(data, "runtime", "wsl-keepalive.pid")); err == nil {
		marker = true
	}
	var old struct {
		WSL   map[string]any `toml:"wsl"`
		Proxy struct {
			HTTP int `toml:"http_port"`
			PAC  int `toml:"pac_port"`
		} `toml:"proxy"`
	}
	_, _ = toml.DecodeFile(filepath.Join(data, "config.toml"), &old)
	if !marker && old.WSL == nil {
		return nil
	}
	httpPort, pacPort := "8888", "8889"
	if old.Proxy.HTTP != 0 {
		httpPort = strconv.Itoa(old.Proxy.HTTP)
	}
	if old.Proxy.PAC != 0 {
		pacPort = strconv.Itoa(old.Proxy.PAC)
	}
	pac := GetAutoConfigURL()
	host := ""
	ownPAC := false
	if u, err := url.Parse(pac); err == nil && u.Scheme == "http" && u.User == nil && u.Path == "/proxy.pac" && u.Port() == pacPort {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && ip.IsPrivate() {
			host = u.Hostname()
			ownPAC = true
		}
	}
	if host == "" {
		body, _ := os.ReadFile(filepath.Join(data, "runtime", "pac.log"))
		matches := regexp.MustCompile(`PAC will return PROXY ([0-9.]+):([0-9]+)`).FindAllStringSubmatch(string(body), -1)
		if len(matches) > 0 {
			last := matches[len(matches)-1]
			if ip, err := netip.ParseAddr(last[1]); err == nil && ip.IsPrivate() {
				host = last[1]
				httpPort = last[2]
			}
		}
	}
	if !ownPAC && !marker {
		return nil
	}
	backups := map[string]string{}
	if ownPAC {
		backups["AutoConfigURL"] = pac
	}
	environment, err := registry.OpenKey(registry.CURRENT_USER, environmentKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil && err != registry.ErrNotExist {
		return err
	}
	if err == nil {
		defer environment.Close()
		proxyOwned := false
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
			value, _, _ := environment.GetStringValue(name)
			if legacyProxy(value, host, httpPort) {
				backups[name] = value
				proxyOwned = true
			}
		}
		if proxyOwned {
			value, _, _ := environment.GetStringValue("NO_PROXY")
			list, _ := os.ReadFile(filepath.Join(data, "direct.list"))
			var expected []string
			for _, line := range strings.Split(string(list), "\n") {
				line, _, _ = strings.Cut(line, "#")
				line = strings.TrimSpace(line)
				if line == "" || strings.Contains(line, "://") {
					continue
				}
				line = strings.TrimPrefix(line, "*")
				expected = append(expected, line)
			}
			if value != "" && value == strings.Join(expected, ",") {
				backups["NO_PROXY"] = value
			}
		}
	}
	for _, key := range []string{"http.proxy", "https.proxy"} {
		out, err := exec.Command("git", "config", "--global", "--get", key).Output()
		value := strings.TrimSpace(string(out))
		if err == nil && legacyProxy(value, host, httpPort) {
			backups["git."+key] = value
		}
	}
	if len(backups) == 0 {
		return nil
	}
	// Preserve the actual values removed. Never overwrite an earlier migration backup.
	backup := filepath.Join(data, "legacy-proxy-backup.json")
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		b, _ := json.MarshalIndent(backups, "", "  ")
		if err := os.WriteFile(backup, b, 0600); err != nil {
			return err
		}
	}
	if ownPAC {
		k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
		if err != nil {
			return err
		}
		err = k.DeleteValue("AutoConfigURL")
		k.Close()
		if err != nil {
			return err
		}
	}
	for name := range backups {
		if name == "HTTP_PROXY" || name == "HTTPS_PROXY" || name == "NO_PROXY" {
			if err := environment.DeleteValue(name); err != nil {
				return err
			}
			if name != "NO_PROXY" {
				_ = os.Unsetenv(name)
			}
		}
		if strings.HasPrefix(name, "git.") {
			key := strings.TrimPrefix(name, "git.")
			pattern := "^" + regexp.QuoteMeta(backups[name]) + "$"
			if out, err := exec.Command("git", "config", "--global", "--unset-all", key, pattern).CombinedOutput(); err != nil {
				return fmt.Errorf("removing legacy Git proxy: %w: %s", err, out)
			}
		}
	}
	notifyWinINet()
	broadcastEnvChange()
	fmt.Println("Removed recognized legacy proxy settings; backup:", backup)
	fmt.Println("Apps already holding the old proxy in memory may need one restart during migration.")
	return nil
}

func notifyWinINet() {
	dll := syscall.NewLazyDLL("wininet.dll")
	p := dll.NewProc("InternetSetOptionW")
	p.Call(0, 39, 0, 0)
	p.Call(0, 37, 0, 0)
}
func broadcastEnvChange() {
	target, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	syscall.NewLazyDLL("user32.dll").NewProc("SendMessageTimeoutW").Call(0xffff, 0x1a, 0, uintptr(unsafe.Pointer(target)), 2, 5000, uintptr(unsafe.Pointer(&result)))
}
