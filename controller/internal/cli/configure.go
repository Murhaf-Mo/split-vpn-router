package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vpn/controller/internal/config"
	"github.com/vpn/controller/internal/platform"
	"golang.org/x/term"
)

func Configure(_ []string) error {
	dir, err := platform.DataDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "config.toml")
	c, err := config.Load(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		c = &config.Config{Mode: "direct-default", DirectDNS: "1.1.1.1", Image: "split-vpn-router:local", APIport: 8889, RelayPort: 1080}
	}
	in := bufio.NewReader(os.Stdin)
	prompt := func(label, previous string) string {
		fmt.Printf("%s [%s]: ", label, previous)
		s, _ := in.ReadString('\n')
		s = strings.TrimSpace(s)
		if s == "" {
			return previous
		}
		return s
	}
	fmt.Println("Docker VPN router configuration. Enter keeps the current value.")
	c.VPNHost = prompt("VPN host", c.VPNHost)
	c.VPNUser = prompt("VPN username", c.VPNUser)
	fmt.Print("VPN password (blank keeps current): ")
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, e := term.ReadPassword(int(os.Stdin.Fd()))
		if e != nil {
			return e
		}
		password = string(b)
		fmt.Println()
	} else {
		password, _ = in.ReadString('\n')
		password = strings.TrimRight(password, "\r\n")
	}
	if password != "" {
		c.VPNPassword = password
	}
	c.VPNGroup = prompt("Auth group (optional)", c.VPNGroup)
	c.DNS = prompt("Corporate DNS IP (blank uses VPN-provided DNS)", c.DNS)
	c.DirectDNS = prompt("Home/public DNS IP", c.DirectDNS)
	c.Mode = prompt("Mode: direct-default or vpn-default", c.Mode)
	// Reconfiguration never enables automatic reconnect implicitly.
	if c.VPNHost == "" || c.VPNUser == "" || c.VPNPassword == "" {
		return fmt.Errorf("VPN host, username and password are required")
	}
	if c.Mode != "vpn-default" && c.Mode != "direct-default" {
		return fmt.Errorf("invalid mode")
	}
	if err := config.Save(path, c); err != nil {
		return err
	}
	fmt.Println("Saved", path, "\nNext: vpn up (one explicit authentication attempt)")
	return nil
}
