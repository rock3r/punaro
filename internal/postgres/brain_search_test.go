package postgres

import (
	"strings"
	"testing"
)

func TestMemorySearchRequestNormalizesBoundedQuery(t *testing.T) {
	t.Parallel()
	request := MemorySearchRequest{
		PrincipalID: "18181818-1818-4818-8818-181818181901",
		ProjectID:   "18181818-1818-4818-8818-181818181902",
		Query:       "  focused tests  ",
		Limit:       7,
	}
	normalized, err := request.normalized()
	if err != nil || normalized.Query != "focused tests" || normalized.Limit != 7 {
		t.Fatalf("normalized=%#v err=%v", normalized, err)
	}

	for name, invalid := range map[string]MemorySearchRequest{
		"principal":   {PrincipalID: "bad", ProjectID: request.ProjectID, Query: "focused", Limit: 1},
		"project":     {PrincipalID: request.PrincipalID, ProjectID: "bad", Query: "focused", Limit: 1},
		"empty":       {PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, Query: " \t\n", Limit: 1},
		"control":     {PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, Query: "focus\x00escape", Limit: 1},
		"query":       {PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, Query: strings.Repeat("x", maxMemorySearchQueryBytes+1), Limit: 1},
		"zero limit":  {PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, Query: "focused", Limit: 0},
		"large limit": {PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, Query: "focused", Limit: maxMemorySearchResults + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := invalid.normalized(); err == nil {
				t.Fatal("invalid search request accepted")
			}
		})
	}
}
