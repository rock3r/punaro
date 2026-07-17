package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestFixedIdentifierParsingRejectsNonCanonicalValues(t *testing.T) {
	var sixteen [16]byte
	for index := range sixteen {
		sixteen[index] = byte(index + 1)
	}
	raw := base64.RawURLEncoding.EncodeToString(sixteen[:])
	if got, err := id16(raw); err != nil || got != sixteen {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if _, err := id16(raw + "="); err == nil {
		t.Fatal("padded identifier accepted")
	}
	if _, err := id32(raw); err == nil {
		t.Fatal("wrong identifier length accepted")
	}
}

func TestReceiveConfigurationFailsClosedWithoutLocalCredentials(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_URL", "")
	if _, err := loadReceiveConfig(); err == nil {
		t.Fatal("receive accepted missing local credentials")
	}
}

func TestCheckFailsClosedWithoutLocalCredentials(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_URL", "")
	if err := runCheck(nil); err == nil {
		t.Fatal("check accepted missing local credentials")
	}
}

func TestCheckRejectsArguments(t *testing.T) {
	if err := runCheck([]string{"unexpected"}); err == nil {
		t.Fatal("check accepted arguments")
	}
}

func TestParseSendArgsRequiresStableLocalStageAndAbsoluteInput(t *testing.T) {
	if _, err := parseSendArgs([]string{"--input", "relative.txt", "--relay-conversation", "relay-1", "--from", "agent/source"}); err == nil {
		t.Fatal("send accepted a relative source and no stable stage ID")
	}
	stage := make([]byte, 16)
	stage[0] = 1
	request, err := parseSendArgs([]string{"--input", "/private/source.txt", "--relay-conversation", "relay-1", "--from", "agent/source", "--stage-id", base64.RawURLEncoding.EncodeToString(stage)})
	if err != nil || request.inputPath != "/private/source.txt" || request.relayConversationID != "relay-1" || request.fromEndpoint != "agent/source" || request.stageID[0] != 1 {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestSenderConfigurationFailsClosedWithoutLocalCredentials(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_URL", "")
	if _, err := loadSenderConfig(); err == nil {
		t.Fatal("sender accepted missing local credentials")
	}
}

func TestMapSenderRejectsNonLocalSource(t *testing.T) {
	local := make([]byte, 16)
	local[0] = 1
	other := make([]byte, 16)
	other[0] = 2
	conversation := make([]byte, 16)
	conversation[0] = 3
	recipient := make([]byte, 16)
	recipient[0] = 4
	commitment := make([]byte, 32)
	commitment[0] = 5
	t.Setenv("PUNARO_ATTACHMENT_SENDER_ID", base64.RawURLEncoding.EncodeToString(local))
	t.Setenv("PUNARO_ATTACHMENT_SENDER_GENERATION", "1")
	args := []string{
		"--relay-conversation", "relay-1",
		"--conversation-id", base64.RawURLEncoding.EncodeToString(conversation),
		"--sender-id", base64.RawURLEncoding.EncodeToString(other),
		"--sender-generation", "1",
		"--recipient-id", base64.RawURLEncoding.EncodeToString(recipient),
		"--recipient-generation", "1",
		"--membership-commitment", base64.RawURLEncoding.EncodeToString(commitment),
	}
	if err := runMapSender(args); err == nil {
		t.Fatal("sender mapping accepted a non-local source identity")
	}
}

func TestReadPlaintextInputRejectsSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(target, []byte("local only"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := target + "-link"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPlaintextInput(link); err == nil {
		t.Fatal("sender accepted a symlinked source file")
	}
}
