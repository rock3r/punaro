package canopitransport

import "testing"

func TestValidateOriginRequiresHTTPSOutsideLiteralLoopback(t *testing.T) {
	for _, origin := range []string{
		"https://canopi.example.internal:8443",
		"http://127.0.0.1:8090",
		"http://[::1]:8090",
	} {
		if err := ValidateOrigin(origin); err != nil {
			t.Errorf("ValidateOrigin(%q) error = %v", origin, err)
		}
	}
	for _, origin := range []string{
		"http://192.168.2.10:8090",
		"http://localhost:8090",
		"https://user@example.test",
		"https://example.test/path",
	} {
		if err := ValidateOrigin(origin); err == nil {
			t.Errorf("ValidateOrigin(%q) unexpectedly succeeded", origin)
		}
	}
}
