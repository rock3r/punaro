package postgres

import (
	"testing"
	"time"
)

func TestMemoryArchiveCandidateRequestRequiresBoundedPolicy(t *testing.T) {
	valid := MemoryArchiveCandidateRequest{
		PrincipalID:    "23232323-2323-4323-8323-232323232301",
		ProjectID:      "23232323-2323-4323-8323-232323232302",
		InactiveFor:    minMemoryArchiveInactiveFor,
		MaxRecallCount: 5,
		Limit:          maxMemoryArchiveCandidates,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*MemoryArchiveCandidateRequest){
		"principal": func(request *MemoryArchiveCandidateRequest) { request.PrincipalID = "friendly" },
		"project":   func(request *MemoryArchiveCandidateRequest) { request.ProjectID = "friendly" },
		"short inactivity": func(request *MemoryArchiveCandidateRequest) {
			request.InactiveFor = minMemoryArchiveInactiveFor - time.Nanosecond
		},
		"long inactivity": func(request *MemoryArchiveCandidateRequest) {
			request.InactiveFor = maxMemoryArchiveInactiveFor + time.Nanosecond
		},
		"negative recalls": func(request *MemoryArchiveCandidateRequest) { request.MaxRecallCount = -1 },
		"zero limit":       func(request *MemoryArchiveCandidateRequest) { request.Limit = 0 },
		"large limit":      func(request *MemoryArchiveCandidateRequest) { request.Limit = maxMemoryArchiveCandidates + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid archive-candidate policy accepted")
			}
		})
	}
}

func TestUniqueMemoryRecallIDsAreStableAndBounded(t *testing.T) {
	input := []string{
		"23232323-2323-4323-8323-232323232311",
		"23232323-2323-4323-8323-232323232312",
		"23232323-2323-4323-8323-232323232311",
		"invalid",
	}
	got := uniqueMemoryRecallIDs(input, 2)
	want := []string{input[0], input[1]}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unique recall IDs=%v, want %v", got, want)
	}
}
