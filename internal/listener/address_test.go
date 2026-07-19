package listener

import "testing"

func TestCanonicalListenerParsingAndEquality(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:http", "127.0.0.1:65536", "127.0.0.1:08080", ":8080", "[fe80::1%]:8080", "[fe80::1]:8080", "[127.0.0.1%en0]:8080", "[::ffff:127.0.0.1%en0]:8080", "[::1%lo0]:8080", "[2001:db8::1%en0]:8080"} {
		if _, err := Parse(address); err == nil {
			t.Errorf("Parse(%q) accepted an ambiguous listener", address)
		}
	}
	if _, err := Parse("[fe80::1%en0]:8080"); err != nil {
		t.Fatalf("valid scoped IPv6 listener was rejected: %v", err)
	}
	if !IsLoopback("127.0.0.1:8080") || !IsLoopback("[::1]:8080") {
		t.Fatal("canonical loopback listener was rejected")
	}
	if !Same("127.0.0.1:8080", "127.0.0.1:8080") || Same("127.0.0.1:8080", "127.0.0.1:8081") {
		t.Fatal("listener equality is incorrect")
	}
	if Same("[fe80::1%en0]:8080", "[fe80::1%en1]:8080") {
		t.Fatal("listener equality discarded the IPv6 scope zone")
	}
}
