package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/zeebo/blake3"
)

func TestHTTPRelayClientIssuesHolderSignedPermitRequest(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permitRequest := attachmentv2.PermitRequest{RequestID: [16]byte{1}, HolderDeviceID: [16]byte{2}, HolderGeneration: 1, HolderRole: attachmentv2.PermitHolderSender, TransferID: [16]byte{3}, ConversationID: [16]byte{4}, SenderDeviceID: [16]byte{2}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, AttemptGeneration: 1, Operation: attachmentv2.PermitOperationOffer, MembershipCommitment: [32]byte{6}, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
	if err := attachmentv2.SignPermitRequest(&permitRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	expectedPermit := attachmentv2.Permit{Audience: [32]byte{7}, Serial: [16]byte{8}, IssuerKeyID: [32]byte{9}, HolderDeviceID: permitRequest.HolderDeviceID, HolderGeneration: permitRequest.HolderGeneration, HolderRole: permitRequest.HolderRole, TransferID: permitRequest.TransferID, ConversationID: permitRequest.ConversationID, SenderDeviceID: permitRequest.SenderDeviceID, SenderGeneration: permitRequest.SenderGeneration, RecipientDeviceID: permitRequest.RecipientDeviceID, RecipientGeneration: permitRequest.RecipientGeneration, AttemptGeneration: permitRequest.AttemptGeneration, Operation: permitRequest.Operation, DirectoryHead: [32]byte{10}, MembershipCommitment: permitRequest.MembershipCommitment, RevocationEpoch: 1, IssuedAt: testUnix(t, clock), ExpiresAt: testUnix(t, clock.Add(15*time.Second)), MaxBytes: permitRequest.MaxBytes, MaxChunks: permitRequest.MaxChunks, MaxOperations: permitRequest.MaxOperations}
	if err := attachmentv2.SignPermit(&expectedPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	expectedRaw, err := attachmentv2.EncodePermit(expectedPermit)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/permits" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/cbor" {
			t.Fatalf("unexpected request %s %s type=%q", r.Method, r.URL.String(), r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := attachmentv2.DecodePermitRequest(body)
		if err != nil || decoded != permitRequest {
			t.Fatalf("request=%+v err=%v", decoded, err)
		}
		timestamp, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Punaro-Timestamp"))
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Punaro-Signature"))
		if err != nil || !ed25519.Verify(machinePublic, relay.CanonicalRequest(relay.SignedRequest{MachineID: "machine-a", Method: http.MethodPost, Path: "/v2/permits", Body: body, Timestamp: timestamp, Nonce: r.Header.Get("X-Punaro-Nonce")}), signature) {
			t.Fatal("permit request did not have a valid machine signature")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(expectedRaw)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := client.IssuePermit(context.Background(), permitRequest)
	if err != nil || permit != expectedPermit {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
}

func TestHTTPRelayClientIssuesV3HolderSignedPermitRequest(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permitRequest := attachmentv3.PermitRequest{RequestID: [16]byte{1}, HolderDeviceID: [16]byte{2}, HolderGeneration: 1, HolderRole: attachmentv3.PermitHolderSender, TransferID: [16]byte{3}, ConversationID: [16]byte{4}, SenderDeviceID: [16]byte{2}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, Operation: attachmentv3.PermitOperationSourceInit, MembershipCommitment: [32]byte{6}, StagedManifestCommitment: [32]byte{7}, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
	if err := attachmentv3.SignPermitRequest(&permitRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	expectedPermit := attachmentv3.Permit{Audience: [32]byte{8}, Serial: [16]byte{9}, IssuerKeyID: [32]byte{10}, HolderDeviceID: permitRequest.HolderDeviceID, HolderGeneration: permitRequest.HolderGeneration, HolderRole: permitRequest.HolderRole, TransferID: permitRequest.TransferID, ConversationID: permitRequest.ConversationID, SenderDeviceID: permitRequest.SenderDeviceID, SenderGeneration: permitRequest.SenderGeneration, RecipientDeviceID: permitRequest.RecipientDeviceID, RecipientGeneration: permitRequest.RecipientGeneration, Operation: permitRequest.Operation, DirectoryHead: [32]byte{11}, MembershipCommitment: permitRequest.MembershipCommitment, RevocationEpoch: 1, IssuedAt: testUnix(t, clock), ExpiresAt: testUnix(t, clock.Add(15*time.Second)), MaxBytes: permitRequest.MaxBytes, MaxChunks: permitRequest.MaxChunks, MaxOperations: permitRequest.MaxOperations, StagedManifestCommitment: permitRequest.StagedManifestCommitment}
	if err := attachmentv3.SignPermit(&expectedPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	expectedRaw, err := attachmentv3.EncodePermit(expectedPermit)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v3/permits" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/cbor" {
			t.Fatalf("unexpected request %s %s type=%q", r.Method, r.URL.String(), r.Header.Get("Content-Type"))
		}
		body := mustReadAll(t, r)
		decoded, err := attachmentv3.DecodePermitRequest(body)
		if err != nil || decoded != permitRequest {
			t.Fatalf("request=%+v err=%v", decoded, err)
		}
		timestamp, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Punaro-Timestamp"))
		if err != nil || !ed25519.Verify(machinePublic, relay.CanonicalRequest(relay.SignedRequest{MachineID: "machine-a", Method: http.MethodPost, Path: "/v3/permits", Body: body, Timestamp: timestamp, Nonce: r.Header.Get("X-Punaro-Nonce")}), mustDecodeSignature(t, r.Header.Get("X-Punaro-Signature"))) {
			t.Fatal("v3 permit request did not have a valid machine signature")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(expectedRaw)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := client.IssueV3Permit(context.Background(), permitRequest)
	if err != nil || permit != expectedPermit {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
}

func TestHTTPRelayClientSendsBoundV3AttachmentOperation(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := attachmentv3.Permit{Audience: [32]byte{1}, Serial: [16]byte{2}, IssuerKeyID: [32]byte{3}, HolderDeviceID: [16]byte{4}, HolderGeneration: 1, HolderRole: attachmentv3.PermitHolderSender, TransferID: [16]byte{5}, ConversationID: [16]byte{6}, SenderDeviceID: [16]byte{4}, SenderGeneration: 1, RecipientDeviceID: [16]byte{7}, RecipientGeneration: 1, Operation: attachmentv3.PermitOperationSourceUpload, DirectoryHead: [32]byte{8}, MembershipCommitment: [32]byte{9}, RevocationEpoch: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1, StagedManifestCommitment: [32]byte{10}}
	body := []byte("ciphertext")
	path := "/v3/attachments/05000000000000000000000000000000/source/chunks/0"
	op, err := attachmentv3.BuildSignedAttachmentOperation(permit, http.MethodPut, path, body, [16]byte{11}, [32]byte{12}, uint64(clock.Unix()), testUnix(t, clock.Add(time.Second)), holderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody := mustReadAll(t, r)
		if r.Method != http.MethodPut || r.URL.Path != path || string(gotBody) != string(body) {
			t.Fatalf("request=%s %s body=%q", r.Method, r.URL.Path, gotBody)
		}
		gotPermit, err := attachmentv3.DecodePermit(mustDecodeHeader(t, r.Header.Get("X-Punaro-Attachment-Permit")))
		if err != nil || gotPermit != permit {
			t.Fatalf("permit=%+v err=%v", gotPermit, err)
		}
		gotOperation, err := attachmentv3.DecodeOperation(mustDecodeHeader(t, r.Header.Get("X-Punaro-Attachment-Operation")))
		if err != nil || gotOperation != op {
			t.Fatalf("operation=%+v err=%v", gotOperation, err)
		}
		request := signedRequestFromHTTP(t, r, gotBody)
		if !ed25519.Verify(machinePublic, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("attachment request did not have valid machine signature")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write([]byte{0xa1})
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.DoV3Attachment(context.Background(), http.MethodPut, path, body, permit, op)
	if err != nil || string(result) != string([]byte{0xa1}) {
		t.Fatalf("result=%x err=%v", result, err)
	}
}

func TestHTTPRelayClientSendsV3OfferThroughDurableConversation(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawOffer := testV3OfferNotice(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/messages" || r.Header.Get("Idempotency-Key") != "offer-transfer-1" {
			t.Fatalf("unexpected offer notice request %s %s", r.Method, r.URL.String())
		}
		var body struct {
			FromEndpoint string `json:"from_endpoint"`
			Body         string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.FromEndpoint != "agent/a" {
			t.Fatalf("invalid relay message body=%+v err=%v", body, err)
		}
		notice, err := attachmentv3.DecodeOfferNotice(body.Body)
		if err != nil || string(notice.Raw) != string(rawOffer) {
			t.Fatalf("relay body was not canonical attachment notice: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"ignored","created_at":"2026-07-15T00:00:00Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := client.SendV3OfferNotice(context.Background(), "conversation-1", "agent/a", rawOffer, "offer-transfer-1")
	if err != nil || message.ID != "message-1" {
		t.Fatalf("send offer message=%+v err=%v", message, err)
	}
}

func TestHTTPRelayClientDoesNotFollowRedirectForOfferNotice(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawOffer := testV3OfferNotice(t)
	redirectTargetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		if r.Header.Get("CF-Access-Client-Secret") != "" || r.Header.Get("X-Punaro-Signature") != "" {
			t.Fatal("redirect received protected relay headers")
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	relayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer relayServer.Close()
	client, err := NewHTTPRelayClient(relayServer.URL, "machine-a", machinePrivate, relayServer.Client(), AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendV3OfferNotice(context.Background(), "conversation-1", "agent/a", rawOffer, "offer-transfer-1"); err == nil {
		t.Fatal("redirected offer notice accepted")
	}
	if redirectTargetHit {
		t.Fatal("offer notice followed redirect")
	}
}

func mustDecodeSignature(t testing.TB, raw string) []byte {
	t.Helper()
	signature, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func mustDecodeHeader(t testing.TB, raw string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		t.Fatal("invalid base64url header")
	}
	return decoded
}

func testUnix(t testing.TB, value time.Time) uint64 {
	t.Helper()
	seconds := value.Unix()
	if seconds < 0 {
		t.Fatalf("time %s predates Unix epoch", value)
	}
	return uint64(seconds) // #nosec G115 -- negative values are rejected above.
}

func TestHTTPRelayClientFetchesOnlySignedCanonicalDirectorySnapshot(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := attachmentv2.DirectoryEntry{Issuer: &attachmentv2.DirectoryPermitIssuer{KeyID: [32]byte{1}, PublicKey: [32]byte{2}}}
	head, err := attachmentv2.EncodeDirectoryHead(attachmentv2.DirectoryHead{Audience: [32]byte{3}, RootKeyID: [32]byte{4}, TreeSize: 1, TreeRoot: [32]byte{5}, Sequence: 1, IssuedAt: 1, ExpiresAt: 2, RevocationEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := attachmentv2.EncodeDirectorySnapshot(attachmentv2.DirectorySnapshot{RawHead: head, Entries: []attachmentv2.DirectoryEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/directory" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected directory request %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("CF-Access-Client-Id") != "access-id" || r.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatal("missing Access service-token headers")
		}
		request := signedRequestFromHTTP(t, r, mustReadAll(t, r))
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("directory request was not signed")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.FetchDirectorySnapshot(context.Background())
	if err != nil || len(got.Entries) != 1 || got.Entries[0].Issuer == nil || got.Entries[0].Issuer.KeyID != entry.Issuer.KeyID {
		t.Fatalf("snapshot=%#v err=%v", got, err)
	}
}

func TestHTTPRelayClientRejectsUnsafeDirectoryResponse(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cbor; charset=binary")
		_, _ = w.Write([]byte{0xa0})
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchDirectorySnapshot(context.Background()); err == nil {
		t.Fatal("unsafe directory response accepted")
	}
}

func TestHTTPRelayClientSignsBoundedProtocolRequests(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Access-Client-Id") != "access-id" || r.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatal("missing Access service-token headers")
		}
		var request relay.SignedRequest
		body := mustReadAll(t, r)
		request = signedRequestFromHTTP(t, r, body)
		if request.MachineID != "machine-a" || !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("request was not correctly signed")
		}
		switch r.URL.Path {
		case "/v1/machines/me/endpoints":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"lease_until":"2026-07-13T12:00:00Z"}`))
		case "/v1/deliveries/lease":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"deliveries":[]}`))
		case "/v1/conversations/conversation-1/messages":
			if r.Header.Get("Idempotency-Key") != "send-1" {
				t.Fatal("missing idempotency key")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"reply","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/conversations":
			if r.Header.Get("Idempotency-Key") != "create-1" {
				t.Fatal("missing create idempotency key")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"conversation-created"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Advertise(context.Background(), []string{"agent/a"}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := client.Lease(context.Background(), "agent/a")
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("lease = %#v, %v", deliveries, err)
	}
	message, err := client.Send(context.Background(), "conversation-1", "agent/a", "reply", "send-1")
	if err != nil || message.ID != "message-1" {
		t.Fatalf("send = %#v, %v", message, err)
	}
	conversation, err := client.CreateConversation(context.Background(), "agent/a", []relay.Member{{Endpoint: "agent/a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}}, "create-1")
	if err != nil || conversation.ID != "conversation-created" {
		t.Fatalf("create=%#v err=%v", conversation, err)
	}
}

func TestHTTPRelayClientReadsPayloadFreeWake(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/notifications" {
			t.Fatal("unexpected route")
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("unsigned wake handshake")
		}
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = connection.Close(websocket.StatusNormalClosure, "") }()
		if err := connection.Write(r.Context(), websocket.MessageText, []byte(`{"type":"wake","topic_id":"conversation-1","sequence":7}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan relay.WakeEvent, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.ReadNotifications(ctx, func(event relay.WakeEvent) { events <- event }); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Type != "wake" || event.TopicID != "conversation-1" || event.Sequence != 7 {
			t.Fatalf("event=%#v", event)
		}
	default:
		t.Fatal("wake was not delivered")
	}
}

func TestHTTPRelayClientRejectsInsecureRemoteURLAndPartialAccessToken(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPRelayClient("http://relay.example", "machine-a", private, http.DefaultClient, AccessServiceToken{}); err == nil {
		t.Fatal("insecure remote URL accepted")
	}
	if _, err := NewHTTPRelayClient("https://relay.example", "machine-a", private, http.DefaultClient, AccessServiceToken{ClientID: "only-id"}); err == nil {
		t.Fatal("partial Access service token accepted")
	}
}

func testV3OfferNotice(t *testing.T) []byte {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	now := time.Now().UTC().Truncate(time.Second)
	manifest := attachmentv3.Manifest{Audience: [32]byte{1}, TransferID: [16]byte{2}, ConversationID: [16]byte{3}, SenderDeviceID: [16]byte{4}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, DirectoryHead: [32]byte{6}, MembershipCommitment: [32]byte{7}, RevocationEpoch: 1, IssuedAt: uint64(now.Add(-time.Second).Unix()), ExpiresAt: uint64(now.Add(20 * time.Second).Unix()), ContentSalt: [32]byte{8}, PlaintextCommitment: [32]byte{9}, ChunkSize: 1, ChunkCount: 1, PlaintextSize: 1, SignerKeyID: [32]byte{10}}
	if err := attachmentv3.SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	rawManifest, err := attachmentv3.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := attachmentv3.Envelope{Audience: manifest.Audience, TransferID: manifest.TransferID, ConversationID: manifest.ConversationID, SenderDeviceID: manifest.SenderDeviceID, SenderGeneration: manifest.SenderGeneration, RecipientDeviceID: manifest.RecipientDeviceID, RecipientGeneration: manifest.RecipientGeneration, RecipientHPKEKeyID: [32]byte{11}, ManifestCommitment: blake3.Sum256(rawManifest), EncapsulatedKey: [32]byte{12}, Ciphertext: make([]byte, 16), SignerKeyID: manifest.SignerKeyID}
	if err := attachmentv3.SignEnvelope(&envelope, private); err != nil {
		t.Fatal(err)
	}
	offer, err := attachmentv3.EncodeOfferPayload(manifest, envelope, [32]byte{13})
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func mustReadAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedRequestFromHTTP(t *testing.T, request *http.Request, body []byte) relay.SignedRequest {
	t.Helper()
	timestamp, err := time.Parse(time.RFC3339Nano, request.Header.Get("X-Punaro-Timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Punaro-Signature"))
	if err != nil {
		t.Fatal(err)
	}
	return relay.SignedRequest{MachineID: request.Header.Get("X-Punaro-Machine"), Method: request.Method, Path: request.URL.Path, Body: body, Timestamp: timestamp, Nonce: request.Header.Get("X-Punaro-Nonce"), Signature: signature}
}
