package postgres

import "testing"

func TestV5UpdateBridgeBoundary(t *testing.T) {
	valid := UpdateRequest{
		UpdateID:                "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		SourceRelease:           "v0.6.0",
		TargetRelease:           "v0.7.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SourceSchema:            5,
		TargetSchema:            6,
		SchemaMin:               5,
		SchemaMax:               6,
		RollbackFloor:           5,
		PostgresMajor:           17,
		ReleaseSHA256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ComposeSHA256:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		MigrationManifestSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	if err := validateV5BridgeRequest(valid); err != nil {
		t.Fatalf("valid bridge rejected: %v", err)
	}
	for name, mutate := range map[string]func(*UpdateRequest){
		"wrong source": func(r *UpdateRequest) { r.SourceSchema = 4 },
		"wrong target": func(r *UpdateRequest) { r.TargetSchema = 7 },
		"image only":   func(r *UpdateRequest) { r.TargetSchema = 5 },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if validateV5BridgeRequest(request) == nil {
				t.Fatal("unsafe bridge boundary accepted")
			}
		})
	}
}
