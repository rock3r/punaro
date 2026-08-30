package relay

import (
	"strings"
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

func TestNotifierPublishAllIsPayloadFreeAndFanout(t *testing.T) {
	t.Parallel()
	notifier := NewNotifier()
	a := notifier.Register("machine-a")
	b := notifier.Register("machine-b")
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)
	notifier.PublishAll("fleet-config", 9)
	for _, client := range []*NotificationClient{a, b} {
		select {
		case event := <-client.Events():
			if event.Type != "wake" || event.TopicID != "fleet-config" || event.Sequence != 9 {
				t.Fatalf("event=%#v", event)
			}
			if strings.Contains(event.TopicID, "AGENTS") {
				t.Fatal("wake contained configuration contents")
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber missed fleet-config wake")
		}
	}
}
