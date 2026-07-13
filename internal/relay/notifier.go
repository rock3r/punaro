package relay

import "sync"

// WakeEvent is intentionally content-free. Fetching durable deliveries remains
// the sole source of truth after a hint is received.
type WakeEvent struct {
	Type     string `json:"type"`
	TopicID  string `json:"topic_id"`
	Sequence int64  `json:"sequence"`
}

// Notifier tracks best-effort machine-local subscriptions. Its bounded queues
// may drop hints under load; they can never affect durable delivery state.
type Notifier struct {
	mu      sync.Mutex
	clients map[string]map[*NotificationClient]struct{}
}

func NewNotifier() *Notifier {
	return &Notifier{clients: make(map[string]map[*NotificationClient]struct{})}
}

func (n *Notifier) Register(machineID string) *NotificationClient {
	client := &NotificationClient{machineID: machineID, notifier: n, events: make(chan WakeEvent, 16)}
	n.mu.Lock()
	if n.clients[machineID] == nil {
		n.clients[machineID] = make(map[*NotificationClient]struct{})
	}
	n.clients[machineID][client] = struct{}{}
	n.mu.Unlock()
	return client
}

func (n *Notifier) Publish(machineID, topicID string, sequence int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for client := range n.clients[machineID] {
		select {
		case client.events <- WakeEvent{Type: "wake", TopicID: topicID, Sequence: sequence}:
		default:
		}
	}
}

type NotificationClient struct {
	machineID string
	notifier  *Notifier
	events    chan WakeEvent
	once      sync.Once
}

func (c *NotificationClient) Events() <-chan WakeEvent { return c.events }

func (c *NotificationClient) Close() {
	c.once.Do(func() {
		c.notifier.mu.Lock()
		delete(c.notifier.clients[c.machineID], c)
		if len(c.notifier.clients[c.machineID]) == 0 {
			delete(c.notifier.clients, c.machineID)
		}
		c.notifier.mu.Unlock()
	})
}
