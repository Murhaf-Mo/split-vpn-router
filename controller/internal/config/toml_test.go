package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoAutomaticReconnectAndLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	source := "[vpn]\nhost = \"vpn.example\"\npassword = \"p#ass\\\"word\"\n[wsl]\ndistro = \"Ubuntu\"\nsudo_password = \"secret\"\n[routing]\nmode = \"vpn-default\"\n"
	if e := os.WriteFile(path, []byte(source), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if c.AutoReconnect || c.ManageForwarding || c.VPNPassword != "p#ass\"word" {
		t.Fatalf("unsafe defaults or bad credential parsing: %#v", c)
	}
	if e = Save(path, c); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "[wsl]") || strings.Contains(string(b), "sudo_password") {
		t.Fatal("legacy runtime credentials survived migration")
	}
	migrated, e := Load(path)
	if e != nil || migrated.VPNPassword != c.VPNPassword || migrated.Mode != c.Mode {
		t.Fatalf("migration lost values: %v", e)
	}
}

func TestRejectMalformedReconnectAndPorts(t *testing.T) {
	for _, source := range []string{"[vpn]\nauto_reconnect = 1", "[routing]\nmanage_forwarding = \"true\"", "[docker]\napi_port = 1080\nrelay_port = 1080", "[docker]\napi_port = 99999"} {
		path := filepath.Join(t.TempDir(), "config.toml")
		os.WriteFile(path, []byte(source), 0600)
		if _, e := Load(path); e == nil {
			t.Fatalf("accepted invalid config: %s", source)
		}
	}
}

func TestForwardingOptInSurvivesConfigChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte("[routing]\nmanage_forwarding = true\n"), 0600)
	if err := SetMode(path, "vpn-default"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || !c.ManageForwarding {
		t.Fatalf("forwarding consent was lost: %v", err)
	}
}
