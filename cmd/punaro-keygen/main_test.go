package main

import (
	"crypto/ed25519"
	"testing"
)

func TestNewMachineKeyProducesEd25519KeypairAndPublicEnrollment(t *testing.T) {
	t.Parallel()
	private, enrollment, err := newMachineKey("mac-review", "agent/mac-review/")
	if err != nil {
		t.Fatal(err)
	}
	if len(private) != ed25519.PrivateKeySize || enrollment.ID != "mac-review" || len(enrollment.PublicKey) != ed25519.PublicKeySize || len(enrollment.EndpointPrefixes) != 1 {
		t.Fatal("invalid generated machine enrollment")
	}
}
