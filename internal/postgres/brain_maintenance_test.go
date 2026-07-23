package postgres

import "testing"

func TestMemoryDuplicateRequestRequiresStrictBoundedAuthority(t *testing.T) {
	valid := MemoryDuplicateRequest{
		PrincipalID: "21212121-2121-4121-8121-212121212101",
		ProjectID:   "21212121-2121-4121-8121-212121212102",
		Limit:       maxMemoryDuplicateCandidates,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*MemoryDuplicateRequest){
		"principal": func(request *MemoryDuplicateRequest) { request.PrincipalID = "friendly" },
		"project":   func(request *MemoryDuplicateRequest) { request.ProjectID = "friendly" },
		"zero":      func(request *MemoryDuplicateRequest) { request.Limit = 0 },
		"over":      func(request *MemoryDuplicateRequest) { request.Limit = maxMemoryDuplicateCandidates + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid duplicate request accepted")
			}
		})
	}
}
