package mcphttp

import "testing"

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
