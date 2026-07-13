package v2

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRFC9180CorpusProvenanceAndSelectedSuite(t *testing.T) {
	goRoot, err := exec.CommandContext(t.Context(), "go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goRoot)), "src", "crypto", "hpke", "testdata", "rfc9180.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	const expected = "908a08888ba7406f18a00dcfe13f4e068a892c3ed2ec1312cbf43945596741e7"
	if got := hex.EncodeToString(digest[:]); got != expected {
		t.Fatalf("RFC 9180 corpus digest = %s", got)
	}
	var suites []struct {
		Mode       uint16 `json:"mode"`
		KEM        uint16 `json:"kem_id"`
		KDF        uint16 `json:"kdf_id"`
		AEAD       uint16 `json:"aead_id"`
		Info       string `json:"info"`
		SkRm       string `json:"skRm"`
		Enc        string `json:"enc"`
		AccExports string `json:"exports_accumulated"`
	}
	if err := json.Unmarshal(raw, &suites); err != nil {
		t.Fatal(err)
	}
	for _, suite := range suites {
		if suite.Mode == 0 && suite.KEM == hpkeKEMID && suite.KDF == hpkeKDFID && suite.AEAD == hpkeAEADID {
			testRFC9180RecipientExports(t, suite)
			return
		}
	}
	t.Fatal("selected HPKE base-mode suite is absent from the RFC 9180 corpus")
}

func testRFC9180RecipientExports(t *testing.T, suite struct {
	Mode       uint16 `json:"mode"`
	KEM        uint16 `json:"kem_id"`
	KDF        uint16 `json:"kdf_id"`
	AEAD       uint16 `json:"aead_id"`
	Info       string `json:"info"`
	SkRm       string `json:"skRm"`
	Enc        string `json:"enc"`
	AccExports string `json:"exports_accumulated"`
}) {
	if suite.AccExports == "" {
		t.Fatal("selected RFC 9180 suite has no export known-answer value")
	}
	privateBytes, err := hex.DecodeString(suite.SkRm)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := hex.DecodeString(suite.Enc)
	if err != nil {
		t.Fatal(err)
	}
	info, err := hex.DecodeString(suite.Info)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(enc, sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		t.Fatal(err)
	}
	source, sink := sha3.NewSHAKE128(), sha3.NewSHAKE128()
	for length := range 1000 {
		context := string(drawRFC9180Input(t, source))
		value, err := recipient.Export(context, length)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sink.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]byte, 16)
	if _, err := sink.Read(got); err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(suite.AccExports)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("RFC 9180 export KAT = %x, want %x", got, want)
	}
}

func drawRFC9180Input(t *testing.T, source *sha3.SHAKE) []byte {
	t.Helper()
	length := []byte{0}
	if _, err := source.Read(length); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, int(length[0]))
	if _, err := source.Read(result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRecipientEnvelopeFixedHPKEVector(t *testing.T) {
	signerSeed := bytes32(0x0a)
	recipientSeed := bytes32(0x0b)
	signer := ed25519.NewKeyFromSeed(signerSeed[:])
	private, err := ecdh.X25519().NewPrivateKey(recipientSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.SignerKeyID = bytes32(99)
	if err := SignManifest(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: manifest.SignerKeyID, signer: signer.Public().(ed25519.PublicKey), recipientID: bytes32(23), recipient: private.PublicKey()}
	verified, err := verifyManifestFromDirectory(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	hexVector, err := os.ReadFile("testdata/hpke-envelope-v2-positive.hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(hexVector)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnvelope(raw); err != nil {
		t.Fatal(err)
	}
	key, err := OpenRecipientEnvelope(raw, verified, directory, private)
	if err != nil {
		t.Fatal(err)
	}
	if key != bytes32(42) {
		t.Fatal("fixed HPKE vector decrypted the wrong key")
	}
}

func TestEnvelopeFixedNegativeCDEVectors(t *testing.T) {
	rawVectors, err := os.ReadFile("testdata/cde/envelope-v2-negative.hex")
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range strings.Fields(string(rawVectors)) {
		raw, err := hex.DecodeString(vector)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEnvelope(raw); err == nil {
			t.Fatalf("DecodeEnvelope accepted fixed malformed vector %q", vector)
		}
	}
}

type directoryStub struct {
	signerID    [32]byte
	signer      ed25519.PublicKey
	recipientID [32]byte
	recipient   *ecdh.PublicKey
	reject      bool
}

func (d directoryStub) ValidateManifestAuthority(manifest Manifest, now time.Time) (ed25519.PublicKey, error) {
	if d.reject || now.IsZero() || manifest.SignerKeyID != d.signerID || manifest.Audience == [32]byte{} ||
		manifest.SenderDeviceID == [16]byte{} || manifest.SenderGeneration == 0 ||
		manifest.RecipientDeviceID == [16]byte{} || manifest.RecipientGeneration == 0 ||
		manifest.DirectoryHead == [32]byte{} || manifest.MembershipCommitment == [32]byte{} {
		return nil, errors.New("unknown signing key")
	}
	return d.signer, nil
}

func (d directoryStub) CurrentRecipientHPKEKey(deviceID [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error) {
	if deviceID == [16]byte{} || generation == 0 {
		return [32]byte{}, nil, errors.New("unknown recipient")
	}
	return d.recipientID, d.recipient, nil
}

func (d directoryStub) ResolveRecipientHPKEKey(deviceID [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error) {
	if deviceID == [16]byte{} || generation == 0 || keyID != d.recipientID {
		return nil, errors.New("unknown recipient key")
	}
	return d.recipient, nil
}

func TestRecipientEnvelopeCanonicalRoundTripAndBindings(t *testing.T) {
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.SignerKeyID = bytes32(99)
	if err := SignManifest(&manifest, signerPrivate); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: manifest.SignerKeyID, signer: signerPublic, recipientID: bytes32(23), recipient: private.PublicKey()}
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifyManifest(manifestRaw, directory)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := bytes32(42)
	envelope, err := SealRecipientEnvelope(verified, directory, fileKey, signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyEnvelope(decoded, verified) {
		t.Fatal("envelope signature invalid")
	}
	got, err := OpenRecipientEnvelope(raw, verified, directory, private)
	if err != nil {
		t.Fatal(err)
	}
	if got != fileKey {
		t.Fatal("decrypted file key mismatch")
	}
}

func TestRecipientEnvelopeRejectsManifestOrOuterBindingMismatch(t *testing.T) {
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.SignerKeyID = bytes32(99)
	if err := SignManifest(&manifest, signerPrivate); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: manifest.SignerKeyID, signer: signerPublic, recipientID: bytes32(23), recipient: private.PublicKey()}
	verified, err := verifyManifestFromDirectory(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRecipientEnvelope(verified, directory, bytes32(42), signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Audience[0] ^= 1
	changedRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecipientEnvelope(changedRaw, verified, directory, private); err == nil {
		t.Fatal("opened envelope with changed outer binding")
	}

	changed := manifest
	changed.Audience[0] ^= 1
	if err := SignManifest(&changed, signerPrivate); err != nil {
		t.Fatal(err)
	}
	other, err := verifyManifestFromDirectory(changed, directory)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecipientEnvelope(raw, other, directory, private); err == nil {
		t.Fatal("opened envelope against another verified manifest")
	}
}

func TestRecipientEnvelopeRechecksFreshDirectoryAuthority(t *testing.T) {
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.SignerKeyID = bytes32(99)
	if err := SignManifest(&manifest, signerPrivate); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: manifest.SignerKeyID, signer: signerPublic, recipientID: bytes32(23), recipient: private.PublicKey()}
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifyManifest(manifestRaw, directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRecipientEnvelope(verified, directory, bytes32(42), signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	directory.reject = true
	if _, err := OpenRecipientEnvelope(raw, verified, directory, private); err == nil {
		t.Fatal("opened envelope after directory authority withdrew it")
	}
}

func TestEnvelopeDecodeRejectsTrailingAndOversizedInput(t *testing.T) {
	if _, err := DecodeEnvelope([]byte{0xa0, 0}); err == nil {
		t.Fatal("accepted trailing data")
	}
	if _, err := DecodeEnvelope(make([]byte, maxEnvelopeEncodedBytes+1)); err == nil {
		t.Fatal("accepted oversized envelope")
	}
}

func TestDirectoryAuthorityRejectsUnboundSigner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.SignerKeyID = bytes32(31)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: bytes32(32), signer: public}
	if _, err := verifyManifestFromDirectory(manifest, directory); err == nil {
		t.Fatal("accepted signer key under an unbound key ID")
	}
}
