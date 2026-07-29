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
	if len(raw) == 0 || len(raw) > maxJSONRPCRequestBytes || !utf8.Valid(raw) || !validJSONUnicodeEscapes(raw) {
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

func validJSONUnicodeEscapes(raw []byte) bool {
	inString := false
	for index := 0; index < len(raw); index++ {
		if !inString {
			if raw[index] == '"' {
				inString = true
			}
			continue
		}
		if raw[index] == '"' {
			inString = false
			continue
		}
		if raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return false
		}
		if raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return false
		}
		unit, ok := jsonUTF16Unit(raw[index+1 : index+5])
		if !ok {
			return false
		}
		index += 4
		if unit >= 0xd800 && unit <= 0xdbff {
			if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
				return false
			}
			low, ok := jsonUTF16Unit(raw[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
	}
	return !inString
}

func jsonUTF16Unit(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var result uint16
	for _, value := range raw {
		result <<= 4
		switch {
		case value >= '0' && value <= '9':
			result |= uint16(value - '0')
		case value >= 'a' && value <= 'f':
			result |= uint16(value-'a') + 10
		case value >= 'A' && value <= 'F':
			result |= uint16(value-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
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
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') || !consumeJSONRPCValue(decoder, start, 1, maxDepth) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func validJSONRPCValue(raw json.RawMessage, maxDepth int) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
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
