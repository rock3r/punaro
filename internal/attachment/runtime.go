package attachment

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ParseDeviceKeys decodes the operator-provisioned device enrollment map.
func ParseDeviceKeys(raw string) (map[string]ed25519.PublicKey, error) {
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil || len(encoded) == 0 {
		return nil, fmt.Errorf("parse attachment device keys")
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for device, value := range encoded {
		if device == "" {
			return nil, fmt.Errorf("attachment device ID is required")
		}
		decoded, err := base64.RawStdEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid attachment public key for device %q", device)
		}
		keys[device] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

type policyGrant struct {
	Sender       string   `json:"sender"`
	Conversation string   `json:"conversation"`
	Recipient    string   `json:"recipient"`
	Actions      []string `json:"actions"`
}

// StaticPolicy is an explicit operator-provisioned attachment membership policy.
type StaticPolicy struct {
	grants map[string]map[Action]struct{}
}

// ParsePolicy decodes strict allow-only attachment grants.
func ParsePolicy(raw string) (*StaticPolicy, error) {
	var grants []policyGrant
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grants); err != nil || len(grants) == 0 {
		return nil, fmt.Errorf("parse attachment membership policy")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse attachment membership policy")
	}
	policy := &StaticPolicy{grants: make(map[string]map[Action]struct{})}
	for _, grant := range grants {
		if grant.Sender == "" || grant.Conversation == "" || grant.Recipient == "" || len(grant.Actions) == 0 {
			return nil, fmt.Errorf("invalid attachment policy grant")
		}
		key := grantKey(grant.Sender, grant.Conversation, grant.Recipient)
		if policy.grants[key] == nil {
			policy.grants[key] = make(map[Action]struct{})
		}
		for _, rawAction := range grant.Actions {
			action, ok := parseAction(rawAction)
			if !ok {
				return nil, fmt.Errorf("unknown attachment policy action %q", rawAction)
			}
			policy.grants[key][action] = struct{}{}
		}
	}
	return policy, nil
}

// Allowed implements Policy.
func (p *StaticPolicy) Allowed(sender, conversation, recipient string, action Action) bool {
	_, ok := p.grants[grantKey(sender, conversation, recipient)][action]
	return ok
}

func grantKey(sender, conversation, recipient string) string {
	return sender + "\x00" + conversation + "\x00" + recipient
}

func parseAction(raw string) (Action, bool) {
	switch raw {
	case "create":
		return ActionCreate, true
	case "upload":
		return ActionUpload, true
	case "download":
		return ActionDownload, true
	case "signal":
		return ActionSignal, true
	default:
		return 0, false
	}
}
