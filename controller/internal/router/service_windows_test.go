package router

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyWaitsForVPNMetadataOnFreshStartup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[routing]\nmode='direct-default'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lastNetwork := ""
	_, _, err := readPolicy(dir, &lastNetwork)
	if !errors.Is(err, errVPNNotReady) {
		t.Fatalf("idle startup must wait for VPN metadata: %v", err)
	}
	if lastNetwork != "" {
		t.Fatal("idle startup invented VPN network metadata")
	}
}
