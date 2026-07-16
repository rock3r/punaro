package relay

import (
	"testing"
	"time"
)

func TestNotifierTargetsOnlyRegisteredMachineAndDropsOverflow(t *testing.T) {
	t.Parallel()
	notifier := NewNotifier()
	a := notifier.Register("machine-a")
	b := notifier.Register("machine-b")
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)
	notifier.Publish("machine-a", "conversation-1", 7)
	select {
	case event := <-a.Events():
		if event.Type != "wake" || event.TopicID != "conversation-1" || event.Sequence != 7 {
			t.Fatalf("event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("target machine did not receive wake")
	}
	select {
	case event := <-b.Events():
		t.Fatalf("wrong machine received wake %#v", event)
	default:
	}
}
