package router

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeURLAndIPv6(t *testing.T) {
	for input, want := range map[string]string{"https://Example.com/a?x=1": "example.com", "10.77.1.7/16": "10.77.0.0/16", "::1": "::1/128", "*.example.com": "*.example.com"} {
		got, e := Normalize(input)
		if e != nil || got != want {
			t.Fatalf("%q: %q %v", input, got, e)
		}
	}
	for _, input := range []string{"example.com/path", "https://", "foo bar", "x\nmode = evil"} {
		if _, e := Normalize(input); e == nil {
			t.Fatalf("accepted invalid rule %q", input)
		}
	}
}

func TestHostsFileVPNWinsSharedIP(t *testing.T) {
	vpn, direct := HostsRules("10.1.1.1 home.example corp.example\n127.0.0.1 localhost\n", []string{"corp.example"}, []string{"home.example"})
	if len(vpn) != 1 || len(direct) != 0 {
		t.Fatalf("VPN must win shared-IP conflict: %v %v", vpn, direct)
	}
}

func TestPolicyHasDomainDNSAndUDPDataPlane(t *testing.T) {
	p := Policy{Mode: "direct-default", DirectDNS: "1.1.1.1", CorpDNS: "10.0.0.53", Gateway: "203.0.113.1", VPNHost: "https://vpn.example.net/group", RouterProcessPath: `C:\ProgramData\VPNRouter\bin\sing-box.exe`, Key: "test-key", RelayPort: 1080, VPN: []string{"corp.example", "10.77.0.0/16"}, Direct: []string{"*.example.com"}}
	b, e := Generate(p)
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	outs := cfg["outbounds"].([]any)
	relay := outs[1].(map[string]any)
	if relay["type"] != "shadowsocks" || relay["server"] != "127.0.0.1" {
		t.Fatalf("relay configuration: %v", relay)
	}
	if _, restricted := relay["network"]; restricted {
		t.Fatal("relay must carry TCP and UDP")
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["auto_route"] != true || in["strict_route"] != true {
		t.Fatal("TUN must route and protect DNS")
	}
	if cfg["route"].(map[string]any)["final"] != "direct" {
		t.Fatal("wrong direct-default behavior")
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["action"] != "reject" || first["process_path"].([]any)[0] != p.RouterProcessPath {
		t.Fatal("self-captured engine traffic must be rejected before DNS or routing")
	}
	if len(in["dns_address"].([]any)) != 2 {
		t.Fatal("explicit IPv4/IPv6 DNS endpoints are required")
	}
	// Optional fixture for the real sing-box check command, without activating networking.
	if path := os.Getenv("VPN_ROUTER_CONFIG_FIXTURE"); path != "" {
		if e = os.WriteFile(filepath.Clean(path), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
