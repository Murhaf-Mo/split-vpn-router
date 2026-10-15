package cli

import (
	"strings"
	"testing"

	"github.com/vpn/controller/internal/release"
)

func TestDevelopmentUpgradeCannotReplaceCheckoutWithPublishedRelease(t *testing.T) {
	if release.LocalVersion() != "dev" {
		t.Skip("this check is for unstamped development builds")
	}
	err := Upgrade(nil)
	if err == nil || !strings.Contains(err.Error(), "unreleased development build") {
		t.Fatalf("Upgrade() = %v; expected a development build guard", err)
	}
}
