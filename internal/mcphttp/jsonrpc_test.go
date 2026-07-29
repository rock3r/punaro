package mcphttp

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseJSONRPCRequestAcceptsBoundedSingleRequest(t *testing.T) {
	request, ok := parseJSONRPCRequest([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if !ok || string(request.ID) != "1" || request.Method != "tools/list" || string(request.Params) != "{}" || request.Notification {
		t.Fatalf("request=%#v ok=%t", request, ok)
	}
}

func TestParseJSONRPCRequestPreservesValidLargeNumbers(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1e400,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"n":1e400}}`,
	} {
		if _, ok := parseJSONRPCRequest([]byte(raw)); !ok {
			t.Fatalf("rejected valid large number: %s", raw)
		}
	}
}

func TestParseJSONRPCRequestEnforcesSizeBoundary(t *testing.T) {
	prefix := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"query":"`
	suffix := `"}}`
	accepted := []byte(prefix + strings.Repeat("x", maxJSONRPCRequestBytes-len(prefix)-len(suffix)) + suffix)
	if len(accepted) != maxJSONRPCRequestBytes {
		t.Fatalf("accepted length=%d", len(accepted))
	}
	if _, ok := parseJSONRPCRequest(accepted); !ok {
		t.Fatal("rejected request at size limit")
	}
	if _, ok := parseJSONRPCRequest(append(accepted[:len(accepted)-len(suffix)], append([]byte("x"), []byte(suffix)...)...)); ok {
		t.Fatal("accepted request over size limit")
	}
}

func TestParseJSONRPCRequestEnforcesDepthBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		arrays  int
		accepted bool
	}{
		{name: "at limit", arrays: maxJSONRPCDepth - 2, accepted: true},
		{name: "over limit", arrays: maxJSONRPCDepth - 1, accepted: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"value":` + strings.Repeat("[", test.arrays) + "0" + strings.Repeat("]", test.arrays) + "}}"
			if _, ok := parseJSONRPCRequest([]byte(raw)); ok != test.accepted {
				t.Fatalf("accepted=%t want %t", ok, test.accepted)
			}
		})
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
