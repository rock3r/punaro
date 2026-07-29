package mcphttp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const maxJSONRPCRequestBytes = 64 << 10
const maxJSONRPCDepth = 32

// jsonRPCRequest is a strictly parsed single JSON-RPC request. It is not
// mounted by the remote MCP handler yet; a later transport adapter consumes it
// only after OAuth and Punaro capability authorization.
type jsonRPCRequest struct {
	ID           json.RawMessage
	Method       string
	Params       json.RawMessage
	Notification bool
}

func parseJSONRPCRequest(raw []byte) (jsonRPCRequest, bool) {
	if len(raw) == 0 || len(raw) > maxJSONRPCRequestBytes || !utf8.Valid(raw) {
		return jsonRPCRequest{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return jsonRPCRequest{}, false
	}
	fields := make(map[string]json.RawMessage, 4)
	for decoder.More() {
		name, err := decoder.Token()
		key, ok := name.(string)
		if err != nil || !ok || (key != "jsonrpc" && key != "id" && key != "method" && key != "params") || fields[key] != nil {
			return jsonRPCRequest{}, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || !validJSONRPCValue(value, maxJSONRPCDepth) {
			return jsonRPCRequest{}, false
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return jsonRPCRequest{}, false
	}
	var version, method string
	if len(fields) < 2 || json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" || json.Unmarshal(fields["method"], &method) != nil || !validJSONRPCMethod(method) {
		return jsonRPCRequest{}, false
	}
	request := jsonRPCRequest{Method: method, Params: append(json.RawMessage(nil), fields["params"]...)}
	if id, present := fields["id"]; present {
		if !validJSONRPCID(id) {
			return jsonRPCRequest{}, false
		}
		request.ID = append(json.RawMessage(nil), id...)
	} else {
		request.Notification = true
	}
	if len(request.Params) > 0 && !validJSONObject(request.Params, maxJSONRPCDepth) {
		return jsonRPCRequest{}, false
	}
	return request, true
}

func validJSONRPCMethod(method string) bool {
	return method != "" && len(method) <= 128 && strings.TrimSpace(method) == method && !strings.ContainsAny(method, "\x00\r\n")
}

func validJSONRPCID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	var stringID string
	if json.Unmarshal(trimmed, &stringID) == nil {
		return stringID != "" && len(stringID) <= 128 && strings.TrimSpace(stringID) == stringID && !strings.ContainsAny(stringID, "\x00\r\n")
	}
	var number json.Number
	return json.Unmarshal(trimmed, &number) == nil && len(number.String()) <= 64
}

func validJSONObject(raw json.RawMessage, maxDepth int) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') || !consumeJSONRPCValue(decoder, start, 1, maxDepth) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func validJSONRPCValue(raw json.RawMessage, maxDepth int) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || !consumeJSONRPCValue(decoder, start, 1, maxDepth) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func consumeJSONRPCValue(decoder *json.Decoder, token json.Token, depth, maxDepth int) bool {
	if depth > maxDepth {
		return false
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	if delim != '{' && delim != '[' {
		return false
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[name]; duplicate {
				return false
			}
			seen[name] = struct{}{}
		}
		next, err := decoder.Token()
		if err != nil || !consumeJSONRPCValue(decoder, next, depth+1, maxDepth) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
}
