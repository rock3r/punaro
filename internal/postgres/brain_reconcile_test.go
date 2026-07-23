package postgres

import "testing"

func TestMemoryReconcileRequestRequiresDirectBoundedAuthority(t *testing.T) {
	valid := MemoryReconcileRequest{
		PrincipalID: "22222222-2222-4222-8222-222222222201",
		ProjectID:   "22222222-2222-4222-8222-222222222202",
		Limit:       maxMemoryReconcileBatch,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*MemoryReconcileRequest){
		"principal": func(request *MemoryReconcileRequest) { request.PrincipalID = "friendly" },
		"project":   func(request *MemoryReconcileRequest) { request.ProjectID = "friendly" },
		"zero":      func(request *MemoryReconcileRequest) { request.Limit = 0 },
		"over":      func(request *MemoryReconcileRequest) { request.Limit = maxMemoryReconcileBatch + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid reconciliation request accepted")
			}
		})
	}
}
