package mcphttp

import (
	"bytes"
	"testing"
)

func TestParseJSONRPCRequestAcceptsBoundedSingleRequest(t *testing.T) {
	request, ok := parseJSONRPCRequest([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if !ok || string(request.ID) != "1" || request.Method != "tools/list" || string(request.Params) != "{}" || request.Notification {
		t.Fatalf("request=%#v ok=%t", request, ok)
	}
}

func TestParseJSONRPCRequestRejectsAmbiguousOrInvalidEnvelope(t *testing.T) {
	for _, raw := range []string{
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":{},"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true}`,
		`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
	} {
		if _, ok := parseJSONRPCRequest([]byte(raw)); ok {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestParseJSONRPCRequestRejectsMalformedUTF8(t *testing.T) {
	raw := bytes.ReplaceAll([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"query":"x"}}`), []byte("x"), []byte{0xff})
	if _, ok := parseJSONRPCRequest(raw); ok {
		t.Fatal("accepted malformed UTF-8")
	}
}

func TestParseJSONRPCRequestRejectsUnpairedSurrogateEscape(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/\ud800list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"query":"\udc00"}}`,
	} {
		if _, ok := parseJSONRPCRequest([]byte(raw)); ok {
			t.Fatalf("accepted unpaired surrogate: %s", raw)
		}
	}
}
