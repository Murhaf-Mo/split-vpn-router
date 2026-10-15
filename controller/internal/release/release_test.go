package release

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		local, remote string
		want          bool
	}{
		// Equal -> not newer
		{"1.0.0", "1.0.0", false},
		{"v1.0.0", "v1.0.0", false},

		// Patch / minor / major bumps
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
		{"1.2.3", "1.3.0", true},
		{"1.2.3", "2.0.0", true},
		{"2.0.0", "1.99.99", false},

		// Leading "v" tolerated on either side
		{"v1.2.3", "1.2.4", true},
		{"1.2.3", "v1.2.4", true},

		// Differing component counts (treat missing as 0)
		{"1.0", "1.0.0", false},
		{"1.0.0", "1.0", false},
		{"1.0", "1.0.1", true},
		{"1", "1.0.0", false},

		// Pre-release suffix on remote is ignored; numeric tail compared
		{"1.2.3", "1.2.4-rc1", true},
		{"1.2.4", "1.2.4-rc1", false},

		// Build metadata stripped
		{"1.2.3", "1.2.4+build.5", true},

		// Dev / empty local -> any remote wins
		{"dev", "1.0.0", true},
		{"", "1.0.0", true},
		{"dev", "0.0.1", true},
	}
	for _, c := range cases {
		got := IsNewer(c.local, c.remote)
		if got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v; want %v", c.local, c.remote, got, c.want)
		}
	}
}

func TestMSIDownloadURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3", "https://github.com/Murhaf-Mo/split-vpn-router/releases/download/v1.2.3/wsl-vpn-router-1.2.3.msi"},
		{"v1.2.3", "https://github.com/Murhaf-Mo/split-vpn-router/releases/download/v1.2.3/wsl-vpn-router-1.2.3.msi"},
	}
	for _, c := range cases {
		got := MSIDownloadURL(c.in)
		if got != c.want {
			t.Errorf("MSIDownloadURL(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
