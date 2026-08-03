// Package adapter bridges an enrolled Punaro machine to its own local
// agent-mailbox installation. It never exposes the mailbox database or CLI to
// the network.
package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/relay"
	// sqlite is the local durable adapter journal driver.
	_ "modernc.org/sqlite"
)

// Mailbox exposes the minimal local-only boundary used by a Syncer.
type Mailbox interface {
	Attached(context.Context) ([]string, error)
	Send(ctx context.Context, endpoint string, message InboundMessage) error
}

// RelayClient is the authenticated remote-facing protocol used by a Syncer.
type RelayClient interface {
	Advertise(ctx context.Context, endpoints []string) error
	Lease(ctx context.Context, endpoint string) ([]relay.Delivery, error)
	Ack(ctx context.Context, delivery relay.Delivery) error
}

// InvocationRelayClient is the separate, body-free control-plane surface.
type InvocationRelayClient interface {
	LeaseInvocations(context.Context) ([]relay.Invocation, error)
	ReportInvocation(context.Context, relay.Invocation, bool) error
}

// Invoker is a host-local, operator-configured process-start boundary. Its
// implementation must deduplicate the stable invocation fence before starting
// a role; no remote body reaches this interface.
type Invoker interface {
	Invoke(context.Context, relay.Invocation) error
}

// InboundMessage is an inert envelope injected into the local mailbox. The
// original body remains data, while the stable relay IDs let downstream agents
// identify duplicate at-least-once deliveries.
type InboundMessage struct {
	PunaroMessageID string    `json:"punaro_message_id"`
	ConversationID  string    `json:"conversation_id"`
	Sequence        int64     `json:"sequence"`
	FromEndpoint    string    `json:"from_endpoint"`
	Body            string    `json:"body"`
	CreatedAt       time.Time `json:"created_at"`
}

// Syncer performs one poll-driven delivery cycle. Polling remains authoritative
// and works with no WebSocket notifier.
type Syncer struct {
	Mailbox Mailbox
	Relay   RelayClient
	Journal *Journal
	Invoker Invoker
	Now     func() time.Time
}

// SyncOnce synchronizes attached local sessions, then injects and acknowledges
// each leased relay delivery. If mailbox injection fails, no acknowledgement is
// sent. A crash after injection can yield a duplicate; this is the explicitly
// documented at-least-once boundary.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	if s.Mailbox == nil || s.Relay == nil || s.Journal == nil {
		return fmt.Errorf("adapter requires mailbox, relay, and journal")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	endpoints, err := s.Mailbox.Attached(ctx)
	if err != nil {
		return fmt.Errorf("read attached mailbox sessions: %w", err)
	}
	endpoints, err = uniqueEndpoints(endpoints)
	if err != nil {
		return err
	}
	if err := s.Relay.Advertise(ctx, endpoints); err != nil {
		return fmt.Errorf("advertise attached sessions: %w", err)
	}
	for _, endpoint := range endpoints {
		deliveries, err := s.Relay.Lease(ctx, endpoint)
		if err != nil {
			return fmt.Errorf("lease deliveries for %q: %w", endpoint, err)
		}
		for _, delivery := range deliveries {
			if err := s.forwardAndAcknowledge(ctx, endpoint, delivery, now().UTC()); err != nil {
				return err
			}
		}
	}
	if s.Invoker != nil {
		invocationRelay, ok := s.Relay.(InvocationRelayClient)
		if !ok {
			return fmt.Errorf("adapter invocation relay is unavailable")
		}
		if err := s.syncInvocations(ctx, invocationRelay, now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Syncer) syncInvocations(ctx context.Context, relayClient InvocationRelayClient, now time.Time) error {
	if err := s.Journal.pruneInvocationRecoveryRows(now); err != nil {
		return fmt.Errorf("prune invocation recovery rows: %w", err)
	}
	invocations, err := relayClient.LeaseInvocations(ctx)
	if err != nil {
		return fmt.Errorf("lease runtime invocations: %w", err)
	}
	for _, invocation := range invocations {
		state, err := s.Journal.ensureInvocation(invocation.ID, invocation.Fence, now)
		if err != nil {
			return fmt.Errorf("record invocation %q: %w", invocation.ID, err)
		}
		accepted := state == invocationAccepted
		if !accepted {
			if invocation.RecoveryOnly {
				// The relay has exhausted runtime-start attempts. A missing local
				// acceptance record means we cannot safely cross the start boundary
				// again; terminalize the handoff instead.
				if err := relayClient.ReportInvocation(ctx, invocation, false); err != nil {
					return fmt.Errorf("report unconfirmed recovery invocation %q: %w", invocation.ID, err)
				}
				if err := s.Journal.removeInvocation(invocation.ID, invocation.Fence); err != nil {
					return fmt.Errorf("remove unconfirmed recovery invocation %q: %w", invocation.ID, err)
				}
				return fmt.Errorf("recovery-only invocation %q has no accepted local handoff", invocation.ID)
			}
			attached, err := s.Mailbox.Attached(ctx)
			if err != nil {
				return fmt.Errorf("recheck attached mailbox sessions: %w", err)
			}
			attached, err = uniqueEndpoints(attached)
			if err != nil {
				return err
			}
			if containsEndpoint(attached, invocation.TargetEndpoint) {
				// The relay can only observe the attachment advertised at the
				// beginning of this cycle. If it appeared meanwhile, release the
				// handoff without crossing the process-start boundary; the next
				// cycle advertises the live role and terminalizes the stale lease.
				if err := relayClient.ReportInvocation(ctx, invocation, true); err != nil {
					return fmt.Errorf("record locally attached invocation %q: %w", invocation.ID, err)
				}
				if err := s.Journal.removeInvocation(invocation.ID, invocation.Fence); err != nil {
					return fmt.Errorf("remove locally attached invocation %q: %w", invocation.ID, err)
				}
				continue
			}
			if err := s.Invoker.Invoke(ctx, invocation); err != nil {
				if reportErr := relayClient.ReportInvocation(ctx, invocation, false); reportErr != nil {
					return fmt.Errorf("runtime invocation %q failed and retry report failed: %w", invocation.ID, reportErr)
				}
				if removeErr := s.Journal.removeInvocation(invocation.ID, invocation.Fence); removeErr != nil {
					return fmt.Errorf("remove failed invocation %q: %w", invocation.ID, removeErr)
				}
				return fmt.Errorf("run runtime invocation %q: %w", invocation.ID, err)
			}
			if err := s.Journal.markInvocationAccepted(invocation.ID, invocation.Fence, now); err != nil {
				return fmt.Errorf("record accepted invocation %q: %w", invocation.ID, err)
			}
			accepted = true
		}
		if err := relayClient.ReportInvocation(ctx, invocation, accepted); err != nil {
			return fmt.Errorf("report runtime invocation %q: %w", invocation.ID, err)
		}
		if accepted {
			// A successful server outcome is the terminal acknowledgement for this
			// handoff. The runtime owns the durable fence; retaining this adapter
			// recovery row longer would grow local state without improving recovery.
			if err := s.Journal.removeInvocation(invocation.ID, invocation.Fence); err != nil {
				return fmt.Errorf("remove accepted invocation %q: %w", invocation.ID, err)
			}
		}
	}
	return nil
}

func containsEndpoint(endpoints []string, endpoint string) bool {
	for _, candidate := range endpoints {
		if candidate == endpoint {
			return true
		}
	}
	return false
}

func (s *Syncer) forwardAndAcknowledge(ctx context.Context, endpoint string, delivery relay.Delivery, now time.Time) error {
	state, err := s.Journal.ensureReceived(delivery.ID, delivery.Message.ID, now)
	if err != nil {
		return fmt.Errorf("record received delivery %q: %w", delivery.ID, err)
	}
	switch state {
	case deliveryAcknowledged:
		return nil
	case deliveryReceived:
		message := InboundMessage{PunaroMessageID: delivery.Message.ID, ConversationID: delivery.Message.ConversationID, Sequence: delivery.Message.Sequence, FromEndpoint: delivery.Message.FromEndpoint, Body: delivery.Message.Body, CreatedAt: delivery.Message.CreatedAt}
		if err := s.Mailbox.Send(ctx, endpoint, message); err != nil {
			return fmt.Errorf("inject delivery %q into local mailbox: %w", delivery.ID, err)
		}
		if err := s.Journal.MarkForwarded(delivery.ID, delivery.Message.ID, now); err != nil {
			return fmt.Errorf("record local delivery handoff %q: %w", delivery.ID, err)
		}
	case deliveryForwarded:
		// The mailbox accepted this before a prior acknowledgement attempt.
	default:
		return fmt.Errorf("unknown adapter journal state")
	}
	if err := s.Relay.Ack(ctx, delivery); err != nil {
		return fmt.Errorf("acknowledge relay delivery %q: %w", delivery.ID, err)
	}
	if err := s.Journal.MarkAcknowledged(delivery.ID, now); err != nil {
		return fmt.Errorf("record relay acknowledgement %q: %w", delivery.ID, err)
	}
	return nil
}

func uniqueEndpoints(endpoints []string) ([]string, error) {
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint) == "" {
			return nil, fmt.Errorf("attached mailbox contains an empty endpoint")
		}
		seen[endpoint] = struct{}{}
	}
	unique := make([]string, 0, len(seen))
	for endpoint := range seen {
		unique = append(unique, endpoint)
	}
	sort.Strings(unique)
	return unique, nil
}

type deliveryState string

const (
	deliveryReceived     deliveryState = "received"
	deliveryForwarded    deliveryState = "forwarded"
	deliveryAcknowledged deliveryState = "acknowledged"
)

type invocationState string

const (
	invocationPending  invocationState = "pending"
	invocationAccepted invocationState = "accepted"
	// Keep an accepted local fence through the relay's pending crash-recovery
	// window. After that, an unreported accepted outcome has expired remotely
	// and can no longer be leased to cause a duplicate runtime start.
	invocationJournalRetention = 24 * time.Hour
)

// Journal records the local side of the delivery transaction. It is deliberately
// separate from agent-mailbox state so it remains available across mailbox CLI
// process restarts.
type Journal struct{ db *sql.DB }

// OpenJournal opens a private SQLite journal in WAL mode.
func OpenJournal(database string) (*Journal, error) {
	if strings.TrimSpace(database) == "" {
		return nil, fmt.Errorf("adapter journal path is required")
	}
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		return nil, fmt.Errorf("create adapter data directory: %w", err)
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, fmt.Errorf("open adapter journal: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS inbound_deliveries (
			delivery_id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('received', 'forwarded', 'acknowledged')),
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS inbound_invocations (
			invocation_id TEXT PRIMARY KEY,
			fence TEXT NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('pending', 'accepted')),
			updated_at INTEGER NOT NULL
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize adapter journal: %w", err)
		}
	}
	return &Journal{db: db}, nil
}

// Close closes the local journal.
func (j *Journal) Close() error { return j.db.Close() }

func (j *Journal) ensureReceived(deliveryID, messageID string, now time.Time) (deliveryState, error) {
	if strings.TrimSpace(deliveryID) == "" || strings.TrimSpace(messageID) == "" {
		return "", fmt.Errorf("delivery and message IDs are required")
	}
	_, err := j.db.ExecContext(context.Background(), "INSERT INTO inbound_deliveries(delivery_id, message_id, state, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(delivery_id) DO NOTHING", deliveryID, messageID, deliveryReceived, now.UnixMilli())
	if err != nil {
		return "", err
	}
	var storedMessageID string
	var state deliveryState
	err = j.db.QueryRowContext(context.Background(), "SELECT message_id, state FROM inbound_deliveries WHERE delivery_id = ?", deliveryID).Scan(&storedMessageID, &state)
	if err != nil {
		return "", err
	}
	if storedMessageID != messageID {
		return "", fmt.Errorf("delivery ID was reused with another message")
	}
	return state, nil
}

// MarkForwarded records successful local mailbox acceptance before relay ack.
func (j *Journal) MarkForwarded(deliveryID, messageID string, now time.Time) error {
	_, err := j.db.ExecContext(context.Background(), `INSERT INTO inbound_deliveries(delivery_id, message_id, state, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(delivery_id) DO UPDATE SET state = CASE WHEN inbound_deliveries.state = 'acknowledged' THEN 'acknowledged' ELSE 'forwarded' END, updated_at = excluded.updated_at`, deliveryID, messageID, deliveryForwarded, now.UnixMilli())
	return err
}

// MarkAcknowledged records a successful remote acknowledgement after a local
// mailbox handoff has been journaled.
func (j *Journal) MarkAcknowledged(deliveryID string, now time.Time) error {
	result, err := j.db.ExecContext(context.Background(), "UPDATE inbound_deliveries SET state = ?, updated_at = ? WHERE delivery_id = ?", deliveryAcknowledged, now.UnixMilli(), deliveryID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("adapter journal delivery is missing")
	}
	return nil
}

func (j *Journal) ensureInvocation(invocationID, fence string, now time.Time) (invocationState, error) {
	if strings.TrimSpace(invocationID) == "" || strings.TrimSpace(fence) == "" {
		return "", fmt.Errorf("invocation ID and fence are required")
	}
	if _, err := j.db.ExecContext(context.Background(), `INSERT INTO inbound_invocations(invocation_id,fence,state,updated_at) VALUES(?,?,?,?) ON CONFLICT(invocation_id) DO NOTHING`, invocationID, fence, invocationPending, now.UnixMilli()); err != nil {
		return "", err
	}
	var storedFence string
	var state invocationState
	if err := j.db.QueryRowContext(context.Background(), `SELECT fence,state FROM inbound_invocations WHERE invocation_id=?`, invocationID).Scan(&storedFence, &state); err != nil {
		return "", err
	}
	if storedFence != fence {
		return "", fmt.Errorf("invocation ID was reused with another fence")
	}
	return state, nil
}

// pruneInvocationRecoveryRows bounds rows left by a crash after a terminal
// relay outcome. The relay closes previously leased pending work before that
// same recovery window can be leased again.
func (j *Journal) pruneInvocationRecoveryRows(now time.Time) error {
	_, err := j.db.ExecContext(context.Background(), `DELETE FROM inbound_invocations WHERE updated_at<?`, now.Add(-invocationJournalRetention).UnixMilli())
	return err
}

func (j *Journal) markInvocationAccepted(invocationID, fence string, now time.Time) error {
	result, err := j.db.ExecContext(context.Background(), `UPDATE inbound_invocations SET state=?,updated_at=? WHERE invocation_id=? AND fence=?`, invocationAccepted, now.UnixMilli(), invocationID, fence)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("adapter invocation journal is missing")
	}
	return nil
}

func (j *Journal) removeInvocation(invocationID, fence string) error {
	result, err := j.db.ExecContext(context.Background(), `DELETE FROM inbound_invocations WHERE invocation_id=? AND fence=?`, invocationID, fence)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("adapter journal invocation is missing")
	}
	return nil
}
