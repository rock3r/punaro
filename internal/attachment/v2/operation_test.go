package v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestOperationRecordBindsSignedRequestToPermitHolderAndExactTarget(t *testing.T) {
	t.Parallel()
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := samplePermit()
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(30*time.Second))
	record := sampleOperation(permit)
	record.IssuedAt, record.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(10*time.Second))
	if err := SignOperation(&record, holderPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOperation(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolver := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	if err := VerifyOperation(decoded, permit, resolver, clock); err != nil {
		t.Fatal(err)
	}
	decoded.TargetCommitment[0] ^= 1
	if err := VerifyOperation(decoded, permit, resolver, clock); err == nil {
		t.Fatal("changed target operation retry was accepted")
	}
}

type operationHolderStub struct {
	device     [16]byte
	generation uint64
	key        ed25519.PublicKey
}

func (s operationHolderStub) CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error) {
	if deviceID != s.device || generation != s.generation {
		return nil, errUnknownOperationHolder
	}
	return s.key, nil
}

func sampleOperation(permit Permit) OperationRecord {
	return OperationRecord{PermitSerial: permit.Serial, OperationID: bytes16(20), Operation: permit.Operation, Method: 3, PathCommitment: bytes32(21), TargetCommitment: bytes32(22), BodyCommitment: bytes32(23), IdempotencyKey: bytes32(24), IssuedAt: permit.IssuedAt, ExpiresAt: permit.ExpiresAt}
}
