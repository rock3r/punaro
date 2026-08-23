package postgres

import "testing"

func TestListenerAddressesPrivateRejectsAnyPublicBinding(t *testing.T) {
	for _, value := range []string{"", "localhost", "127.0.0.1", "::1", "127.0.0.1, ::1", "LOCALHOST"} {
		if !listenerAddressesPrivate(value) {
			t.Fatalf("private listener set rejected: %q", value)
		}
	}
	for _, value := range []string{"*", "0.0.0.0", "::", "192.168.2.10", "database.internal", "127.0.0.1,0.0.0.0", "localhost,public.example"} {
		if listenerAddressesPrivate(value) {
			t.Fatalf("public or unprovable listener set accepted: %q", value)
		}
	}
}
