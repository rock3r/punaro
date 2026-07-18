//go:build darwin

package main

import (
	"encoding/base64"
	"testing"
)

func TestSafeName(t *testing.T) {
	for _, value := range []string{"punaro.attachment-v3", "macbook-recipient", "a_b.9"} {
		if !safeName(value) {
			t.Fatalf("safeName(%q) = false", value)
		}
	}
	for _, value := range []string{"", "space here", "line\nbreak", "slash/name"} {
		if safeName(value) {
			t.Fatalf("safeName(%q) = true", value)
		}
	}
}

func TestNewWrappingKeyIsBase64Encoded32Bytes(t *testing.T) {
	encoded, err := newWrappingKey()
	if err != nil {
		t.Fatalf("newWrappingKey: %v", err)
	}
	defer zeroBytes(encoded)
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded key length = %d, want 32", len(decoded))
	}
}
