package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeviceCredentialJSONRepresentsOptionalExpiry(t *testing.T) {
	credential := DeviceCredential{PrincipalID: "principal", LookupID: "lookup", Encoded: "secret", Generation: 1}
	body, err := json.Marshal(credential)
	if err != nil || strings.Contains(string(body), "expires_at") || strings.Contains(string(body), "0001-01-01") {
		t.Fatalf("non-expiring JSON=%q err=%v", body, err)
	}
	credential.ExpiresAt = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	body, err = json.Marshal(credential)
	if err != nil || !strings.Contains(string(body), `"expires_at":"2030-01-02T03:04:05Z"`) {
		t.Fatalf("expiring JSON=%q err=%v", body, err)
	}
}

func TestDeviceCredentialMetadataJSONOmitsAbsentLifecycleTimes(t *testing.T) {
	metadata := DeviceCredentialMetadata{PrincipalID: "principal", LookupID: "lookup", Label: "laptop", Generation: 1, CreatedAt: time.Date(2029, time.January, 1, 0, 0, 0, 0, time.UTC)}
	body, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"last_used_at", "expires_at", "rotated_at", "revoked_at", "0001-01-01"} {
		if strings.Contains(string(body), field) {
			t.Fatalf("metadata JSON=%q contains absent value %q", body, field)
		}
	}
	metadata.LastUsedAt = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	metadata.ExpiresAt = metadata.LastUsedAt.Add(time.Hour)
	metadata.RotatedAt = metadata.LastUsedAt.Add(2 * time.Hour)
	metadata.RevokedAt = metadata.LastUsedAt.Add(3 * time.Hour)
	body, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"last_used_at", "expires_at", "rotated_at", "revoked_at"} {
		if !strings.Contains(string(body), field) {
			t.Fatalf("metadata JSON=%q omits present value %q", body, field)
		}
	}
}
