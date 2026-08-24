package protocol

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSchemaRestrictsWaitingReasonToWaitingState(t *testing.T) {
	payload, err := os.ReadFile("agent-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		AllOf []struct {
			If struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
				Required []string `json:"required"`
			} `json:"if"`
			Then struct {
				Properties map[string]struct {
					Const string `json:"const"`
				} `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(payload, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.AllOf) != 1 || len(schema.AllOf[0].If.Required) != 1 ||
		schema.AllOf[0].If.Required[0] != "waiting_reason" ||
		schema.AllOf[0].If.Properties["waiting_reason"].Type != "string" ||
		schema.AllOf[0].Then.Properties["state"].Const != string(StateWaitingForUser) {
		t.Fatalf("schema does not constrain non-null waiting_reason to %q", StateWaitingForUser)
	}
}
