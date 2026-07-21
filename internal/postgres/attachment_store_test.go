package postgres

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestAttachmentReservationRequestValidation(t *testing.T) {
	valid := AttachmentReservationRequest{
		PrincipalID:    "11111111-1111-4111-8111-111111111111",
		ProjectID:      "22222222-2222-4222-8222-222222222222",
		IdempotencyKey: "33333333-3333-4333-8333-333333333333",
		SizeBytes:      4,
		SHA256:         sha256.Sum256([]byte("body")),
		DisplayName:    "report.txt",
		MediaType:      "text/plain",
		Lifetime:       30 * time.Minute,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	tests := []struct {
		name string
		edit func(*AttachmentReservationRequest)
	}{
		{name: "principal", edit: func(request *AttachmentReservationRequest) { request.PrincipalID = "friendly" }},
		{name: "project", edit: func(request *AttachmentReservationRequest) { request.ProjectID = "friendly" }},
		{name: "key", edit: func(request *AttachmentReservationRequest) { request.IdempotencyKey = "friendly" }},
		{name: "zero size", edit: func(request *AttachmentReservationRequest) { request.SizeBytes = 0 }},
		{name: "oversize", edit: func(request *AttachmentReservationRequest) { request.SizeBytes = maxAttachmentBytes + 1 }},
		{name: "display control", edit: func(request *AttachmentReservationRequest) { request.DisplayName = "bad\x00name" }},
		{name: "display utf8", edit: func(request *AttachmentReservationRequest) { request.DisplayName = string([]byte{0xff}) }},
		{name: "display long", edit: func(request *AttachmentReservationRequest) { request.DisplayName = strings.Repeat("x", 256) }},
		{name: "media parameters", edit: func(request *AttachmentReservationRequest) { request.MediaType = "text/plain; charset=utf-8" }},
		{name: "media control", edit: func(request *AttachmentReservationRequest) { request.MediaType = "text/pla\x00in" }},
		{name: "short lifetime", edit: func(request *AttachmentReservationRequest) { request.Lifetime = time.Minute }},
		{name: "long lifetime", edit: func(request *AttachmentReservationRequest) { request.Lifetime = 2 * time.Hour }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.edit(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestAttachmentReconcileCursorValidation(t *testing.T) {
	if err := (AttachmentReconcileCursor{}).Validate(); err != nil {
		t.Fatal(err)
	}
	valid := AttachmentReconcileCursor{State: AttachmentReserved, ExpiresAt: time.Now().UTC(), ArtifactID: "44444444-4444-4444-8444-444444444444"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.ArtifactID = ""
	if err := invalid.Validate(); err == nil {
		t.Fatal("partial cursor accepted")
	}
}

func TestAttachmentPublishRequestValidation(t *testing.T) {
	valid := AttachmentPublishRequest{
		PrincipalID:       "11111111-1111-4111-8111-111111111111",
		ArtifactID:        "22222222-2222-4222-8222-222222222222",
		AttemptGeneration: 1,
		ClaimToken:        "33333333-3333-4333-8333-333333333333",
		StoragePath:       "ready/22222222-2222-4222-8222-222222222222.blob",
		SizeBytes:         4,
		SHA256:            sha256.Sum256([]byte("body")),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*AttachmentPublishRequest){
		"principal":  func(request *AttachmentPublishRequest) { request.PrincipalID = "friendly" },
		"artifact":   func(request *AttachmentPublishRequest) { request.ArtifactID = "friendly" },
		"generation": func(request *AttachmentPublishRequest) { request.AttemptGeneration = 0 },
		"token":      func(request *AttachmentPublishRequest) { request.ClaimToken = "friendly" },
		"path":       func(request *AttachmentPublishRequest) { request.StoragePath = "ready/other.blob" },
		"size":       func(request *AttachmentPublishRequest) { request.SizeBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			edit(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("invalid publication accepted")
			}
		})
	}
}

func TestAttachmentDownloadRequestValidation(t *testing.T) {
	valid := AttachmentDownloadRequest{
		PrincipalID:          "11111111-1111-4111-8111-111111111111",
		CredentialLookupID:   "22222222-2222-4222-8222-222222222222",
		CredentialGeneration: 2,
		ArtifactID:           "33333333-3333-4333-8333-333333333333",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*AttachmentDownloadRequest){
		"principal":  func(request *AttachmentDownloadRequest) { request.PrincipalID = "friendly" },
		"lookup":     func(request *AttachmentDownloadRequest) { request.CredentialLookupID = "friendly" },
		"generation": func(request *AttachmentDownloadRequest) { request.CredentialGeneration = 0 },
		"artifact":   func(request *AttachmentDownloadRequest) { request.ArtifactID = "friendly" },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			edit(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("invalid download request accepted")
			}
		})
	}
}
