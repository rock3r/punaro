package postgres

import (
	"errors"
	"testing"
)

func TestValidateCursorRejectsAbandonedTimelineAndFutureSequence(t *testing.T) {
	current := InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 20}
	tests := []struct {
		name   string
		cursor InstallationState
		want   error
	}{
		{name: "current", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 20}},
		{name: "earlier current timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 10}},
		{name: "abandoned pre-restore timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "before", ChangeSequence: 30}, want: ErrCursorTimelineChanged},
		{name: "other installation", cursor: InstallationState{InstallationID: "other", TimelineID: "restored", ChangeSequence: 10}, want: ErrCursorTimelineChanged},
		{name: "future same timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 21}, want: ErrCursorFromFuture},
		{name: "negative", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: -1}, want: ErrCursorFromFuture},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCursor(current, test.cursor)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateCursor() error=%v, want %v", err, test.want)
			}
		})
	}
}
