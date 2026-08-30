package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"time"
)

// FleetConfigTopic is the payload-free wake topic for desired-generation advances.
const FleetConfigTopic = "fleet-config"

var fleetDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FleetDesiredMetadata is content-free desired-revision metadata.
type FleetDesiredMetadata struct {
	Generation   int64
	Digest       string
	SourceCommit string
	SkillCount   int
	TotalBytes   int64
}

// FleetStatusReport is a bounded client status write.
type FleetStatusReport struct {
	Generation        int64
	AppliedDigest     string
	State             string
	Activation        string
	TrailerState      string
	AliasState        string
	ProjectMatchState string
	ReportGeneration  int64
	IdempotencyKey    string
	RequestHash       string
}

// FleetConfigStore is the server-side desired/fetch/status boundary.
type FleetConfigStore interface {
	FleetDesired(ctx context.Context) (FleetDesiredMetadata, error)
	FleetRelease(ctx context.Context, digest string) ([]byte, error)
	PutFleetStatus(ctx context.Context, machineID string, report FleetStatusReport) error
}

func validFleetStatus(report FleetStatusReport) bool {
	if report.Generation < 1 || report.ReportGeneration < 1 || report.IdempotencyKey == "" || len(report.IdempotencyKey) > 128 {
		return false
	}
	if report.AppliedDigest != "" && !fleetDigestPattern.MatchString(report.AppliedDigest) {
		return false
	}
	switch report.State {
	case "current", "pending", "applying", "failed", "offline", "drifted", "unsupported", "restart_required":
	default:
		return false
	}
	if report.Activation != "" {
		switch report.Activation {
		case "immediate", "next_turn", "next_session", "restart_required":
		default:
			return false
		}
	}
	return true
}

func fleetStatusRequestHash(machineID string, report FleetStatusReport) string {
	sum := sha256.Sum256([]byte(machineID + "\n" + report.AppliedDigest + "\n" + report.State + "\n" + report.Activation + "\n" + report.TrailerState + "\n" + report.AliasState + "\n" + report.ProjectMatchState + "\n" + strconv.FormatInt(report.Generation, 10) + "\n" + strconv.FormatInt(report.ReportGeneration, 10)))
	return hex.EncodeToString(sum[:])
}

// BroadcastFleetWake emits a payload-free hint when desired generation advances.
func BroadcastFleetWake(notifier *Notifier, previous, current int64) int64 {
	if notifier == nil || current <= previous {
		return previous
	}
	notifier.PublishAll(FleetConfigTopic, current)
	return current
}

// WatchFleetDesired polls desired generation and emits payload-free wake hints.
func WatchFleetDesired(ctx context.Context, store FleetConfigStore, notifier *Notifier, interval time.Duration) {
	if store == nil || notifier == nil || interval <= 0 {
		return
	}
	var previous int64
	poll := func() {
		desired, err := store.FleetDesired(ctx)
		if err != nil {
			return
		}
		previous = BroadcastFleetWake(notifier, previous, desired.Generation)
	}
	poll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}
