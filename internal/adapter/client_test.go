package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/clienttransport"
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

func TestHTTPRelayClientValidatesSenderWithoutMessageMutation(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/sender-validation" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["from_endpoint"] != "agent/a" {
			t.Fatalf("request=%v err=%v", request, err)
		}
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ValidateSender(context.Background(), "conversation-1", "agent/a"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRelayClientSendsToOneDurableRole(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/messages" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			FromEndpoint string `json:"from_endpoint"`
			Body         string `json:"body"`
			TargetRole   string `json:"target_role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.FromEndpoint != "agent/a" || request.Body != "review this" || request.TargetRole != "role/reviewer" {
			t.Fatalf("request=%#v err=%v", request, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"review this","created_at":"2026-08-10T12:00:00Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendToRole(context.Background(), "conversation-1", "agent/a", "role/reviewer", "review this", "send-1"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRelayClientLeasesOneInvocationPerSync(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/invocations/lease" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			ConsumerID string `json:"consumer_id"`
			Limit      int    `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.ConsumerID != "adapter-a" || request.Limit != 1 {
			t.Fatalf("request=%#v err=%v", request, err)
		}
		_, _ = w.Write([]byte(`{"invocations":[]}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	client.consumerID = "adapter-a"
	if invocations, err := client.LeaseInvocations(context.Background()); err != nil || len(invocations) != 0 {
		t.Fatalf("invocations=%#v err=%v", invocations, err)
	}
}

func TestHTTPRelayClientSendsTypedMembershipControl(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/controls" || r.Header.Get("Idempotency-Key") != "control-1" {
			t.Fatalf("unexpected control request %s %s key=%q", r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"))
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if request.MachineID != "machine-a" || !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("membership control request was not signed")
		}
		var payload struct {
			ActorEndpoint string                 `json:"actor_endpoint"`
			Operation     relay.ControlOperation `json:"operation"`
			Member        struct {
				Endpoint     string   `json:"endpoint"`
				Capabilities []string `json:"capabilities"`
			} `json:"member"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.ActorEndpoint != "agent/a" || payload.Operation != relay.ControlUpsertMember || payload.Member.Endpoint != "agent/b" || len(payload.Member.Capabilities) != 2 || payload.Member.Capabilities[0] != "send" || payload.Member.Capabilities[1] != "receive" {
			t.Fatalf("control payload=%#v err=%v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"control-1","conversation_id":"conversation-1","actor_endpoint":"agent/a","operation":"upsert_member","member":{"endpoint":"agent/b","capabilities":3},"created_at":"2026-08-03T13:25:00Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	event, err := client.ControlMembership(context.Background(), "conversation-1", "agent/a", relay.ControlUpsertMember, relay.Member{Endpoint: "agent/b", Capabilities: relay.CapSend | relay.CapReceive}, "control-1")
	if err != nil || event.ID != "control-1" || event.Member.Endpoint != "agent/b" || event.Member.Capabilities != relay.CapSend|relay.CapReceive {
		t.Fatalf("control event=%#v err=%v", event, err)
	}
}

func TestHTTPRelayClientReadsSignedControlAudit(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/controls/audit" {
			t.Fatalf("unexpected audit request %s %s", r.Method, r.URL.Path)
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if request.MachineID != "machine-a" || !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("control audit request was not signed")
		}
		var payload struct {
			ActorEndpoint string `json:"actor_endpoint"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.ActorEndpoint != "agent/a" {
			t.Fatalf("audit payload=%#v err=%v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"events":[{"id":"control-1","conversation_id":"conversation-1","actor_endpoint":"agent/a","operation":"upsert_member","member":{"endpoint":"agent/b","capabilities":2},"created_at":"2026-08-03T13:25:00Z"}]}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.ControlAudit(context.Background(), "conversation-1", "agent/a")
	if err != nil || len(events) != 1 || events[0].ID != "control-1" || events[0].Member.Capabilities != relay.CapReceive {
		t.Fatalf("audit events=%#v err=%v", events, err)
	}
}

func TestHTTPRelayClientClassifiesOnlyPreAppendRejectionsAsTerminalOfferFailures(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		status   int
		terminal bool
	}{{http.StatusForbidden, true}, {http.StatusNotFound, true}, {http.StatusConflict, false}, {http.StatusInternalServerError, false}} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(test.status) }))
			defer server.Close()
			client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Send(context.Background(), "conversation-1", "agent/a", "offer", "offer-1")
			var terminal terminalOfferNoticeFailure
			if err == nil || !errors.As(err, &terminal) || terminal.PermanentOfferNoticeFailure() != test.terminal {
				t.Fatalf("status=%d err=%v terminal=%v", test.status, err, terminal)
			}
		})
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
	op, err := attachmentv3.BuildSignedAttachmentOperation(permit, http.MethodPut, path, body, [16]byte{11}, [32]byte{12}, testUnix(t, clock), testUnix(t, clock.Add(time.Second)), holderPrivate)
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
	client, err := NewHTTPRelayClient(relayServer.URL, "machine-a", machinePrivate, relayServer.Client(), AccessServiceToken{})
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

func TestOpenAccessSessionSkipsCookiePreflightForServiceTokens(t *testing.T) {
	requests := 0
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := OpenAccessSession(context.Background(), "https://relay.example", &http.Client{Jar: jar, Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("service-token bootstrap should not preflight")
	})}, AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 || client.Jar != nil {
		t.Fatalf("requests=%d jar=%v", requests, client.Jar)
	}
}

func TestHTTPRelayClientServiceTokenDoesNotReplayAccessAuthorizationCookie(t *testing.T) {
	_, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(relayURL, []*http.Cookie{{Name: "CF_Authorization", Value: "stale", Path: "/", Secure: true}})
	client, err := NewHTTPRelayClient("https://relay.example", "machine-a", machinePrivate, &http.Client{Jar: jar, Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("CF-Access-Client-Id") != "access-id" || request.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatal("request omitted Access service-token headers")
		}
		if request.URL.Path == "/.well-known/punaro-access-session" {
			return testHTTPResponse(request, http.StatusNotFound, http.Header{"Set-Cookie": []string{"CF_Authorization=stale; Path=/; Secure"}}), nil
		}
		if request.URL.Path != "/v1/machines/me/endpoints" || request.Header.Get("X-Punaro-Signature") == "" {
			t.Fatalf("unexpected protected request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Cookie") != "" {
			return testHTTPResponse(request, http.StatusForbidden, nil), nil
		}
		return testHTTPResponse(request, http.StatusNoContent, nil), nil
	})}, AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Advertise(context.Background(), []string{"agent/a"}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d want 1", requests)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testHTTPResponse(request *http.Request, status int, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("")), Request: request}
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
		case "/v1/roles/bindings":
			var binding struct {
				Role            string `json:"role"`
				SessionEndpoint string `json:"session_endpoint"`
			}
			if err := json.Unmarshal(body, &binding); err != nil || binding.Role != "role/plan-reviewer" || binding.SessionEndpoint != "agent/a/session" {
				t.Fatalf("role binding body=%s err=%v", body, err)
			}
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
	conversation, err := client.CreateConversation(context.Background(), "agent/a", []relay.Member{{Endpoint: "agent/a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}}, "", "create-1")
	if err != nil || conversation.ID != "conversation-created" {
		t.Fatalf("create=%#v err=%v", conversation, err)
	}
	if err := client.BindRole(context.Background(), "role/plan-reviewer", "agent/a/session"); err != nil {
		t.Fatalf("bind durable role: %v", err)
	}
}

func TestHTTPRelayClientRegistersCanonicalRoleAndExactRetry(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/roles/register" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("role register request was not signed")
		}
		if r.Header.Get("Idempotency-Key") != "register-1" {
			t.Fatalf("idempotency key=%q", r.Header.Get("Idempotency-Key"))
		}
		var payload struct {
			Role              string `json:"role"`
			DisplayName       string `json:"display_name"`
			DirectAddressable bool   `json:"direct_addressable"`
			Machine           string `json:"machine"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.Role != "role/machine-a/reviewer" || payload.DisplayName != "  Reviewer  " || payload.DirectAddressable || payload.Machine != "" {
			t.Fatalf("payload=%s err=%v", body, err)
		}
		seen = append(seen, string(body))
		status := http.StatusCreated
		if len(seen) > 1 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"role":"role/machine-a/reviewer","display_name":"Reviewer","direct_addressable":false,"updated_at":"2026-08-18T16:00:00Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.RegisterRole(context.Background(), "role/machine-a/reviewer", "  Reviewer  ", false, "register-1")
	if err != nil || first.Role != "role/machine-a/reviewer" || first.DisplayName != "Reviewer" || first.DirectAddressable {
		t.Fatalf("register=%#v err=%v", first, err)
	}
	retry, err := client.RegisterRole(context.Background(), "role/machine-a/reviewer", "  Reviewer  ", false, "register-1")
	if err != nil || retry != first || len(seen) != 2 {
		t.Fatalf("retry=%#v seen=%d err=%v", retry, len(seen), err)
	}
	if _, err := client.RegisterRole(context.Background(), "role/plan-reviewer", "", false, "register-legacy"); err == nil {
		t.Fatal("legacy role was accepted by client")
	}
}

func TestHTTPRelayClientListsAndResolvesPublicRoles(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("directory request was not signed")
		}
		if r.URL.RawQuery != "" {
			t.Fatal("directory request used a query string")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/list":
			var payload struct {
				Cursor string `json:"cursor"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(body, &payload); err != nil || payload.Cursor != "" || payload.Limit != relay.DefaultRoleListLimit {
				t.Fatalf("list payload=%s err=%v", body, err)
			}
			_, _ = w.Write([]byte(`{"roles":[{"role":"role/machine-a/reviewer","display_name":"Reviewer","machine_id":"machine-a","online":true}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/resolve":
			var payload struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("resolve payload=%s err=%v", body, err)
			}
			switch payload.Name {
			case "role/machine-a/reviewer":
				_, _ = w.Write([]byte(`{"status":"resolved","role":"role/machine-a/reviewer","display_name":"Reviewer","machine_id":"machine-a","online":true}`))
			case "reviewer":
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"status":"ambiguous","matches":[{"role":"role/machine-a/reviewer","display_name":"Reviewer"},{"role":"role/machine-b/reviewer"}]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"role not found"}`))
			}
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListRoles(context.Background(), "", 0)
	if err != nil || len(page.Roles) != 1 || page.Roles[0].Role != "role/machine-a/reviewer" || !page.Roles[0].Online {
		t.Fatalf("list=%#v err=%v", page, err)
	}
	if encoded, err := json.Marshal(page); err != nil || strings.Contains(string(encoded), "agent/") || strings.Contains(string(encoded), "conversation") {
		t.Fatalf("list leaked inventory: %s err=%v", encoded, err)
	}
	exact, err := client.ResolveRole(context.Background(), "role/machine-a/reviewer")
	if err != nil || exact.Status != relay.RoleResolveResolved || exact.Role != "role/machine-a/reviewer" {
		t.Fatalf("exact=%#v err=%v", exact, err)
	}
	ambiguous, err := client.ResolveRole(context.Background(), "reviewer")
	if err != nil || ambiguous.Status != relay.RoleResolveAmbiguous || len(ambiguous.Matches) != 2 {
		t.Fatalf("ambiguous=%#v err=%v", ambiguous, err)
	}
	missing, err := client.ResolveRole(context.Background(), "role/plan-reviewer")
	if err != nil || missing.Status != relay.RoleResolveNotFound {
		t.Fatalf("missing=%#v err=%v", missing, err)
	}
}

func TestHTTPRelayClientSendsDirectMessageWithCanonicalRoles(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("direct message request was not signed")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/direct-messages" || r.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("Idempotency-Key") != "dm-1" {
			t.Fatalf("idempotency key=%q", r.Header.Get("Idempotency-Key"))
		}
		var payload struct {
			FromRole     string `json:"from_role"`
			ToRole       string `json:"to_role"`
			Body         string `json:"body"`
			FromEndpoint string `json:"from_endpoint"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.FromRole != "role/machine-a/reviewer" || payload.ToRole != "role/machine-b/implementer" || payload.Body != "please review" || payload.FromEndpoint != "" {
			t.Fatalf("payload=%s err=%v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_role":"role/machine-a/reviewer","body":"please review","created_at":"2026-08-18T18:00:00Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := client.SendDirectMessage(context.Background(), "role/machine-a/reviewer", "role/machine-b/implementer", "please review", "dm-1")
	if err != nil || message.ID != "message-1" || message.ConversationID != "conversation-1" || message.FromRole != "role/machine-a/reviewer" || message.FromEndpoint != "" {
		t.Fatalf("direct send=%#v err=%v", message, err)
	}
	if _, err := client.SendDirectMessage(context.Background(), "reviewer", "role/machine-b/implementer", "please review", "dm-1"); err == nil {
		t.Fatal("unqualified source role was accepted")
	}
}

func TestHTTPRelayClientEncodesDurableRoleMemberWithoutChangingEndpointMember(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("role conversation request was not signed")
		}
		var payload struct {
			Members []map[string]any `json:"members"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || len(payload.Members) != 2 {
			t.Fatalf("conversation payload=%s err=%v", body, err)
		}
		if payload.Members[0]["endpoint"] != "agent/a/session" || payload.Members[0]["role"] != nil || payload.Members[1]["role"] != "role/plan-reviewer" || payload.Members[1]["role_machine_id"] != "machine-b" || payload.Members[1]["endpoint"] != nil {
			t.Fatalf("members=%#v", payload.Members)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"role-conversation"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := client.CreateConversation(context.Background(), "agent/a/session", []relay.Member{
		{Endpoint: "agent/a/session", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Role: "role/plan-reviewer", RoleMachineID: "machine-b", Capabilities: relay.CapReceive},
	}, "", "create-role-member")
	if err != nil || conversation.ID != "role-conversation" {
		t.Fatalf("conversation=%#v err=%v", conversation, err)
	}
}

func TestHTTPRelayClientOmitsEmptyDisplayNameOnCreate(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var unnamedBody, namedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("conversation request was not signed")
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("conversation payload=%s err=%v", body, err)
		}
		if _, present := payload["display_name"]; present && unnamedBody == nil {
			t.Fatalf("unnamed create included display_name: %s", body)
		}
		if unnamedBody == nil {
			unnamedBody = append([]byte(nil), body...)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"unnamed-conversation"}`))
			return
		}
		if payload["display_name"] != "Review room" {
			t.Fatalf("named create payload=%s", body)
		}
		namedBody = append([]byte(nil), body...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"named-conversation","display_name":"Review room"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	unnamed, err := client.CreateConversation(context.Background(), "agent/a", []relay.Member{{Endpoint: "agent/a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}}, "", "create-unnamed")
	if err != nil || unnamed.ID != "unnamed-conversation" {
		t.Fatalf("unnamed=%#v err=%v", unnamed, err)
	}
	named, err := client.CreateConversation(context.Background(), "agent/a", []relay.Member{{Endpoint: "agent/a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}}, "Review room", "create-named")
	if err != nil || named.ID != "named-conversation" || named.DisplayName != "Review room" {
		t.Fatalf("named=%#v err=%v", named, err)
	}
	if unnamedBody == nil || namedBody == nil {
		t.Fatal("create requests were not observed")
	}
}

func TestHTTPRelayClientTelegramClaimAndInboundMethods(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("telegram claim request was not signed")
		}
		seen[r.Method+" "+r.URL.Path] = append([]byte(nil), body...)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/conversations/conversation-1/telegram-claim":
			if r.Header.Get("Idempotency-Key") != "claim-conversation-1" {
				t.Fatal("missing claim idempotency key")
			}
			_, _ = w.Write([]byte(`{"conversation_id":"conversation-1","status":"pending","display_name":"Ops","created_at":"2026-08-16T12:00:00Z"}`))
		case "/v1/conversations/conversation-1/telegram-claim/complete":
			if string(body) != "{}" {
				t.Fatalf("complete body=%s", body)
			}
			_, _ = w.Write([]byte(`{"conversation_id":"conversation-1","status":"complete","display_name":"Ops","created_at":"2026-08-16T12:00:00Z","completed_at":"2026-08-16T12:00:05Z"}`))
		case "/v1/telegram/claims/pending":
			_, _ = w.Write([]byte(`{"claims":[{"conversation_id":"conversation-1","status":"pending","display_name":"Ops","created_at":"2026-08-16T12:00:00Z"}]}`))
		case "/v1/telegram/unclaimed":
			_, _ = w.Write([]byte(`{"topics":[{"id":"conversation-1","display_name":"Ops"}]}`))
		case "/v1/sessions/topic":
			_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":true}`))
		case "/v1/conversations/conversation-1/telegram-inbound":
			if r.Header.Get("Idempotency-Key") != "telegram-update:42" {
				t.Fatal("missing inbound idempotency key")
			}
			_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"telegram/primary","from_participant":"user-telegram","body":"ship it","created_at":"2026-08-16T12:00:00Z"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := client.ClaimConversation(context.Background(), "conversation-1", "agent/a", "claim-conversation-1")
	if err != nil || claim.Status != "pending" {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	completed, err := client.CompleteTelegramClaim(context.Background(), "conversation-1")
	if err != nil || completed.Status != "complete" {
		t.Fatalf("complete=%#v err=%v", completed, err)
	}
	pending, err := client.PendingTelegramClaims(context.Background(), 1)
	if err != nil || len(pending) != 1 || pending[0].ConversationID != "conversation-1" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	topics, err := client.ListUnclaimed(context.Background())
	if err != nil || len(topics) != 1 || topics[0].ID != "conversation-1" {
		t.Fatalf("unclaimed=%#v err=%v", topics, err)
	}
	topic, err := client.GetSessionTopic(context.Background(), "agent/a")
	if err != nil || !topic.Claimed || topic.ID != "conversation-1" {
		t.Fatalf("topic=%#v err=%v", topic, err)
	}
	message, err := client.SendTelegramInbound(context.Background(), "conversation-1", relay.TelegramGatewayEndpoint, relay.TelegramUserParticipant, "ship it", "", "", 0, "telegram-update:42")
	if err != nil || message.FromParticipant != relay.TelegramUserParticipant {
		t.Fatalf("inbound=%#v err=%v", message, err)
	}
	if _, ok := seen["POST /v1/conversations/conversation-1/telegram-claim/complete"]; !ok {
		t.Fatal("complete request was not observed")
	}
}

func TestHTTPRelayClientClaimConversationTreatsCompleteAsSuccess(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/telegram-claim" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Idempotency-Key") != "claim-conversation-1" {
			t.Fatal("missing claim idempotency key")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"conversation_id":"conversation-1","status":"complete","display_name":"Ops","created_at":"2026-08-16T12:00:00Z","completed_at":"2026-08-16T12:00:05Z"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := client.ClaimConversation(context.Background(), "conversation-1", "agent/a", "claim-conversation-1")
	if err != nil || claim.Status != "complete" || claim.ConversationID != "conversation-1" {
		t.Fatalf("complete claim=%#v err=%v", claim, err)
	}
}

func TestHTTPRelayClientGetSessionTopicExposesForbiddenStatus(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sessions/topic" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"authorization denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetSessionTopic(context.Background(), "agent/a")
	if RelayHTTPStatus(err) != http.StatusForbidden {
		t.Fatalf("forbidden topic status=%d err=%v", RelayHTTPStatus(err), err)
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
		if !strings.Contains(r.Header.Get("Cookie"), "CF_Authorization=wake-session") {
			t.Fatal("wake handshake omitted Access session cookie")
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
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Jar = jar
	jar.SetCookies(client.baseURL, []*http.Cookie{{Name: "CF_Authorization", Value: "wake-session", Path: "/"}})
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
	if _, err := NewHTTPRelayClientWithPolicy("http://192.168.1.4:8080", "machine-a", private, nil, AccessServiceToken{}, clienttransport.Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}); err != nil {
		t.Fatalf("explicit trusted-LAN client rejected: %v", err)
	}
	if _, err := NewHTTPRelayClientWithPolicy("http://192.168.2.4:8080", "machine-a", private, nil, AccessServiceToken{}, clienttransport.Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}); err == nil {
		t.Fatal("trusted-LAN client accepted an origin outside its CIDR")
	}
	if _, err := NewHTTPRelayClient("https://relay.example", "machine-a", private, http.DefaultClient, AccessServiceToken{ClientID: "only-id"}); err == nil {
		t.Fatal("partial Access service token accepted")
	}
}

func testV3OfferNotice(t *testing.T) []byte {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	now := time.Now().UTC().Truncate(time.Second)
	manifest := attachmentv3.Manifest{Audience: [32]byte{1}, TransferID: [16]byte{2}, ConversationID: [16]byte{3}, SenderDeviceID: [16]byte{4}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, DirectoryHead: [32]byte{6}, MembershipCommitment: [32]byte{7}, RevocationEpoch: 1, IssuedAt: testUnix(t, now.Add(-time.Second)), ExpiresAt: testUnix(t, now.Add(20*time.Second)), ContentSalt: [32]byte{8}, PlaintextCommitment: [32]byte{9}, ChunkSize: 1, ChunkCount: 1, PlaintextSize: 1, SignerKeyID: [32]byte{10}}
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
