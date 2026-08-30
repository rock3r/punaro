package fleetconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TrailerResult is the content-free trailer outcome of one apply.
type TrailerResult struct {
	State     string
	Drift     bool
	Collision bool
}

// SplitAgents separates a fleet-managed prefix from a machine-local trailer.
func SplitAgents(content []byte) (prefix, trailer []byte, ok bool) {
	text := string(content)
	start := strings.Index(text, TrailerStart)
	end := strings.LastIndex(text, TrailerEnd)
	if start < 0 || end < 0 || end < start {
		return nil, nil, false
	}
	suffix := strings.Trim(text[end+len(TrailerEnd):], "\n")
	if suffix != "" {
		return nil, nil, false
	}
	prefix = []byte(strings.TrimRight(text[:start], "\n"))
	bodyStart := start + len(TrailerStart)
	trailer = []byte(text[bodyStart:end])
	return prefix, trailer, true
}

// ComposeAgents writes fleet prefix plus reserved trailer markers.
func ComposeAgents(prefix, trailer []byte) []byte {
	var buf bytes.Buffer
	if len(prefix) > 0 {
		buf.Write(bytes.TrimRight(prefix, "\n"))
		buf.WriteByte('\n')
	}
	buf.WriteString(TrailerStart)
	if len(trailer) > 0 && trailer[0] != '\n' {
		buf.WriteByte('\n')
	}
	buf.Write(trailer)
	if len(trailer) > 0 && trailer[len(trailer)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(TrailerEnd)
	buf.WriteByte('\n')
	return buf.Bytes()
}

// ApplyAgents replaces the fleet prefix while preserving or creating the trailer.
func ApplyAgents(fleetPrefix, existing []byte, existed bool, lastPrefixDigest string) ([]byte, TrailerResult, error) {
	if !existed {
		return ComposeAgents(fleetPrefix, nil), TrailerResult{State: "present"}, nil
	}
	prefix, trailer, ok := SplitAgents(existing)
	if !ok {
		return nil, TrailerResult{State: "collision", Collision: true}, nil
	}
	result := TrailerResult{State: "present"}
	if lastPrefixDigest != "" && DigestBytes(prefix) != lastPrefixDigest && DigestBytes(prefix) != DigestBytes(fleetPrefix) {
		result.Drift = true
	}
	return ComposeAgents(fleetPrefix, trailer), result, nil
}

// DigestBytes returns the hex SHA-256 of one blob.
func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
