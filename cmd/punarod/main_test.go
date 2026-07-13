package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunFailsClosedBeforeStartingAttachmentRuntime(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENTS_ENABLED", "true")
	t.Setenv("PUNARO_ATTACHMENT_DEVICE_KEYS_JSON", `{}`)
	t.Setenv("PUNARO_ATTACHMENT_MEMBERSHIP_JSON", `[]`)
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run exit code = %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "runtime is withheld") {
		t.Fatalf("stderr = %q, want fail-closed explanation", stderr.String())
	}
}
