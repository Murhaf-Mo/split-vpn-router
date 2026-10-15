package winproxy

import "testing"

func TestRepairRecognizesOnlyKnownLegacyEndpoint(t *testing.T) {
	for _, test := range []struct {
		value, host, port string
		want              bool
	}{
		{"http://172.22.1.2:8888", "172.22.1.2", "8888", true},
		{"http://172.22.1.2:9999", "172.22.1.2", "9999", true},
		{"http://172.22.1.3:8888", "172.22.1.2", "8888", false},
		{"http://172.22.1.2:8888", "", "8888", false},
		{"http://user:password@172.22.1.2:8888", "172.22.1.2", "8888", false},
		{"http://127.0.0.1:8888", "127.0.0.1", "8888", false},
		{"https://172.22.1.2:8888", "172.22.1.2", "8888", false},
	} {
		if got := legacyProxy(test.value, test.host, test.port); got != test.want {
			t.Fatalf("%q: %t", test.value, got)
		}
	}
}
