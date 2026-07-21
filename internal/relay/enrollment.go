package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type enrollmentValidationStore struct{}

func (enrollmentValidationStore) ConsumeRequestNonce(string, string, time.Time, time.Time) error {
	return nil
}

type enrollmentValidationTransition struct{}

func (enrollmentValidationTransition) AuthorizeTransition(context.Context, string, ed25519.PublicKey) (TransitionAuthorization, error) {
	return TransitionAuthorization{}, ErrForbidden
}

// ValidateMachineEnrollments proves that raw enrollment JSON is safe for the
// transition runtime, including non-overlapping authority and unique keys.
func ValidateMachineEnrollments(raw string) error {
	machines, err := ParseMachineEnrollments(raw)
	if err != nil {
		return err
	}
	_, err = newAuthenticator(enrollmentValidationStore{}, machines, enrollmentValidationTransition{})
	return err
}

// ParseMachineEnrollments parses the non-secret daemon enrollment setting. It
// deliberately accepts public keys only; an adapter's private key must never
// be supplied to or persisted by the relay.
func ParseMachineEnrollments(raw string) ([]Machine, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var records []struct {
		ID                 string   `json:"id"`
		PublicKey          string   `json:"public_key"`
		EndpointPrefixes   []string `json:"endpoint_prefixes"`
		Endpoints          []string `json:"endpoints"`
		AttachmentDeviceID string   `json:"attachment_device_id"`
	}
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("parse machine enrollment: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse machine enrollment: trailing JSON")
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("machine enrollment is empty")
	}
	machines := make([]Machine, 0, len(records))
	for _, record := range records {
		publicKey, err := base64.RawURLEncoding.DecodeString(record.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key for machine %q", record.ID)
		}
		var attachmentDeviceID [16]byte
		if record.AttachmentDeviceID != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(record.AttachmentDeviceID)
			if err != nil || len(decoded) != len(attachmentDeviceID) || base64.RawURLEncoding.EncodeToString(decoded) != record.AttachmentDeviceID {
				return nil, fmt.Errorf("invalid attachment device ID for machine %q", record.ID)
			}
			copy(attachmentDeviceID[:], decoded)
			if attachmentDeviceID == [16]byte{} {
				return nil, fmt.Errorf("invalid attachment device ID for machine %q", record.ID)
			}
		}
		machines = append(machines, Machine{ID: record.ID, PublicKey: ed25519.PublicKey(publicKey), EndpointPrefixes: record.EndpointPrefixes, Endpoints: record.Endpoints, AttachmentDeviceID: attachmentDeviceID})
	}
	return machines, nil
}
