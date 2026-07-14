package v2

import "testing"

func TestParseAttachmentRouteAcceptsOnlyCanonicalVersionedRoutes(t *testing.T) {
	t.Parallel()
	transfer := bytes16(11)
	transferHex := "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	cases := []struct {
		method    string
		path      string
		operation uint64
		action    TransferAction
		chunk     uint64
		attempt   uint64
	}{
		{"POST", "/v2/attachments/" + transferHex + "/offer", PermitOperationOffer, TransferActionOffer, 0, 0},
		{"POST", "/v2/attachments/" + transferHex + "/accept", PermitOperationAccept, TransferActionAccept, 0, 0},
		{"PUT", "/v2/attachments/" + transferHex + "/chunks/0", PermitOperationUpload, 0, 0, 0},
		{"GET", "/v2/attachments/" + transferHex + "/chunks/17", PermitOperationDownload, 0, 17, 0},
		{"POST", "/v2/attachments/" + transferHex + "/attempts/1/begin", PermitOperationSignal, TransferActionBegin, 0, 1},
		{"POST", "/v2/attachments/" + transferHex + "/complete", PermitOperationComplete, TransferActionComplete, 0, 0},
	}
	for _, tc := range cases {
		route, err := ParseAttachmentRoute(tc.method, tc.path)
		if err != nil || route.TransferID != transfer || route.Operation != tc.operation || route.Action != tc.action || route.ChunkIndex != tc.chunk || route.AttemptGeneration != tc.attempt {
			t.Fatalf("%s %s route=%+v err=%v", tc.method, tc.path, route, err)
		}
	}
	for _, invalid := range []struct{ method, path string }{
		{"POST", "/v2/attachments/0B0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b/offer"},
		{"POST", "/v2/attachments/" + transferHex + "/chunks/01"},
		{"POST", "/v2/attachments/" + transferHex + "/offer?x=1"},
		{"GET", "/v2/attachments/" + transferHex + "/accept"},
	} {
		if _, err := ParseAttachmentRoute(invalid.method, invalid.path); err == nil {
			t.Fatalf("accepted invalid route: %s %s", invalid.method, invalid.path)
		}
	}
}

func TestNewAttachmentOperationRequestBindsRouteAndDownloadCiphertext(t *testing.T) {
	t.Parallel()
	transferHex := "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	route, request, err := NewAttachmentOperationRequest("PUT", "/v2/attachments/"+transferHex+"/chunks/0", []byte("ciphertext"), nil)
	if err != nil || route.Operation != PermitOperationUpload {
		t.Fatalf("route=%+v err=%v", route, err)
	}
	if _, _, err := operationUsage(route.Operation, request); err != nil {
		t.Fatal(err)
	}
	route, request, err = NewAttachmentOperationRequest("GET", "/v2/attachments/"+transferHex+"/chunks/0", nil, []byte("stored ciphertext"))
	if err != nil || route.Operation != PermitOperationDownload {
		t.Fatalf("route=%+v err=%v", route, err)
	}
	if bytes, chunks, err := operationUsage(route.Operation, request); err != nil || bytes != uint64(len("stored ciphertext")) || chunks != 1 {
		t.Fatalf("bytes=%d chunks=%d err=%v", bytes, chunks, err)
	}
	if _, _, err := NewAttachmentOperationRequest("GET", "/v2/attachments/"+transferHex+"/chunks/0", []byte("must be empty"), []byte("stored ciphertext")); err == nil {
		t.Fatal("download with a request body was accepted")
	}
}
