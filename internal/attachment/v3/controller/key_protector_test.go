package controller

import (
	"context"
	"testing"
)

func TestHostAEADFileKeyProtectorBindsAADAndCiphertext(t *testing.T) {
	p, err := NewHostAEADFileKeyProtector(hostKeyProviderStub{key: bytes32(1), id: bytes32(2)})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes32(3)
	sealed, err := p.SealSenderFileKey(context.Background(), key, []byte("transfer-and-manifest"))
	if err != nil || len(sealed) <= len(key) {
		t.Fatalf("sealed=%x err=%v", sealed, err)
	}
	opened, err := p.OpenSenderFileKey(context.Background(), sealed, []byte("transfer-and-manifest"))
	if err != nil || opened != key {
		t.Fatalf("opened=%x err=%v", opened, err)
	}
	if _, err := p.OpenSenderFileKey(context.Background(), sealed, []byte("other")); err == nil {
		t.Fatal("changed AAD opened sealed key")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := p.OpenSenderFileKey(context.Background(), sealed, []byte("transfer-and-manifest")); err == nil {
		t.Fatal("changed ciphertext opened sealed key")
	}
}

type hostKeyProviderStub struct{ key, id [32]byte }

func (p hostKeyProviderStub) SenderKeyEncryptionKey(context.Context) ([32]byte, error) {
	return p.key, nil
}
func (p hostKeyProviderStub) SenderKeyEncryptionKeyID(context.Context) ([32]byte, error) {
	return p.id, nil
}
