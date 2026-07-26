package postgres

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemoryConsistencyRequestRequiresDirectBoundedCursor(t *testing.T) {
	valid := MemoryConsistencyRequest{
		PrincipalID: "23232323-2323-4232-8232-232323232301",
		ProjectID:   "23232323-2323-4232-8232-232323232302",
		AfterItemID: "23232323-2323-4232-8232-232323232303",
		Limit:       maxMemoryConsistencyRows,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	withoutCursor := valid
	withoutCursor.AfterItemID = ""
	if _, err := withoutCursor.normalized(); err != nil {
		t.Fatalf("initial request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*MemoryConsistencyRequest){
		"principal": func(request *MemoryConsistencyRequest) { request.PrincipalID = "friendly" },
		"project":   func(request *MemoryConsistencyRequest) { request.ProjectID = "friendly" },
		"cursor":    func(request *MemoryConsistencyRequest) { request.AfterItemID = "friendly" },
		"zero":      func(request *MemoryConsistencyRequest) { request.Limit = 0 },
		"over":      func(request *MemoryConsistencyRequest) { request.Limit = maxMemoryConsistencyRows + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid consistency request accepted")
			}
		})
	}
}

func TestMemoryConsistencyPageIsContentFree(t *testing.T) {
	page := MemoryConsistencyPage{
		Checked:                   2,
		LexicalControlsConsistent: true,
		Issues: []MemoryConsistencyIssue{{
			ItemID:   "23232323-2323-4232-8232-232323232304",
			Revision: 7,
			Class:    MemoryConsistencyContentHash,
		}},
		NextAfterItemID: "23232323-2323-4232-8232-232323232305",
		More:            true,
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"document", "content_sha256", "search_title", "search_vector", "secret-value"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("consistency page leaked %q: %s", forbidden, text)
		}
	}
	for _, required := range []string{`"checked":2`, `"lexical_controls_consistent":true`, `"class":"content_hash"`, `"more":true`} {
		if !strings.Contains(text, required) {
			t.Fatalf("consistency page missing %q: %s", required, text)
		}
	}
}
