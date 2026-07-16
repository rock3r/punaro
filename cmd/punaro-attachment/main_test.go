package main

import (
	"encoding/base64"
	"testing"
)

func TestFixedIdentifierParsingRejectsNonCanonicalValues(t *testing.T) {
	var sixteen [16]byte
	for index := range sixteen {
		sixteen[index] = byte(index + 1)
	}
	raw := base64.RawURLEncoding.EncodeToString(sixteen[:])
	if got, err := id16(raw); err != nil || got != sixteen {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if _, err := id16(raw + "="); err == nil {
		t.Fatal("padded identifier accepted")
	}
	if _, err := id32(raw); err == nil {
		t.Fatal("wrong identifier length accepted")
	}
}

func TestReceiveConfigurationFailsClosedWithoutLocalCredentials(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_URL", "")
	if _, err := loadReceiveConfig(); err == nil {
		t.Fatal("receive accepted missing local credentials")
	}
}
