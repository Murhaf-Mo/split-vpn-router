// Package config reads TOML with proper quoting, comments and type validation.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	VPNHost, VPNUser, VPNPassword, VPNGroup, DNS, DirectDNS, Mode, Image, Path string
	AutoReconnect, ManageForwarding                                            bool
	APIport, RelayPort                                                         int
}

type document struct {
	VPN struct {
		Host          string `toml:"host"`
		User          string `toml:"user"`
		Password      string `toml:"password"`
		Group         string `toml:"group"`
		DNS           string `toml:"dns_server"`
		AutoReconnect bool   `toml:"auto_reconnect"`
	} `toml:"vpn"`
	Docker struct {
		Image     string `toml:"image"`
		APIport   int    `toml:"api_port"`
		RelayPort int    `toml:"relay_port"`
	} `toml:"docker"`
	Routing struct {
		Mode             string `toml:"mode"`
		DirectDNS        string `toml:"direct_dns"`
		ManageForwarding bool   `toml:"manage_forwarding"`
	} `toml:"routing"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d document
	d.Docker.Image = "split-vpn-router:local"
	d.Docker.APIport = 8889
	d.Docker.RelayPort = 1080
	d.Routing.Mode = "direct-default"
	d.Routing.DirectDNS = "1.1.1.1"
	if _, err = toml.Decode(strings.TrimPrefix(string(data), "\ufeff"), &d); err != nil {
		return nil, err
	}
	c := &Config{Path: path, VPNHost: d.VPN.Host, VPNUser: d.VPN.User, VPNPassword: d.VPN.Password, VPNGroup: d.VPN.Group,
		DNS: d.VPN.DNS, AutoReconnect: d.VPN.AutoReconnect, Image: d.Docker.Image, APIport: d.Docker.APIport, RelayPort: d.Docker.RelayPort,
		Mode: d.Routing.Mode, DirectDNS: d.Routing.DirectDNS, ManageForwarding: d.Routing.ManageForwarding}
	if c.Mode != "vpn-default" && c.Mode != "direct-default" {
		return nil, fmt.Errorf("invalid routing.mode")
	}
	if c.APIport < 1024 || c.APIport > 65535 || c.RelayPort < 1024 || c.RelayPort > 65535 || c.APIport == c.RelayPort {
		return nil, fmt.Errorf("Docker ports must be distinct and between 1024 and 65535")
	}
	if _, err := netip.ParseAddr(c.DirectDNS); err != nil {
		return nil, fmt.Errorf("routing.direct_dns must be an IP address")
	}
	if c.DNS != "" {
		if _, err := netip.ParseAddr(c.DNS); err != nil {
			return nil, fmt.Errorf("vpn.dns_server must be an IP address")
		}
	}
	return c, nil
}

func (c *Config) Serialize() string {
	var d document
	d.VPN.Host = c.VPNHost
	d.VPN.User = c.VPNUser
	d.VPN.Password = c.VPNPassword
	d.VPN.Group = c.VPNGroup
	d.VPN.DNS = c.DNS
	d.VPN.AutoReconnect = c.AutoReconnect
	d.Docker.Image = c.Image
	d.Docker.APIport = c.APIport
	d.Docker.RelayPort = c.RelayPort
	d.Routing.Mode = c.Mode
	d.Routing.DirectDNS = c.DirectDNS
	d.Routing.ManageForwarding = c.ManageForwarding
	var out strings.Builder
	out.WriteString("# Docker VPN router; contains plaintext credentials.\n")
	_ = toml.NewEncoder(&out).Encode(d)
	return out.String()
}

func Save(path string, c *Config) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(c.Serialize()), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func SetMode(path, mode string) error {
	if mode != "vpn-default" && mode != "direct-default" {
		return fmt.Errorf("invalid routing mode")
	}
	c, err := Load(path)
	if err != nil {
		return err
	}
	c.Mode = mode
	return Save(path, c)
}
