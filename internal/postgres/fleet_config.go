package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/fleetconfig"
	"github.com/rock3r/punaro/internal/relay"
)

// FleetDesired is the singleton published fleet-config revision.
type FleetDesired struct {
	Digest       string
	SourceCommit string
	Generation   int64
	SkillCount   int
	TotalBytes   int64
}

// FleetClientStatus is one enrolled client's content-free convergence row.
type FleetClientStatus struct {
	MachineID         string `json:"machine_id"`
	AppliedDigest     string `json:"applied_digest"`
	State             string `json:"state"`
	Activation        string `json:"activation"`
	TrailerState      string `json:"trailer_state"`
	AliasState        string `json:"alias_state"`
	ProjectMatchState string `json:"project_match_state"`
	Generation        int64  `json:"generation"`
}

const fleetClientOfflineAfter = 10 * time.Minute

// ExpireFleetClientState records offline when a report is missing or older than twice the maximum adapter poll.
func ExpireFleetClientState(state string, reportedAt, now time.Time) string {
	if state == "" || reportedAt.IsZero() || now.Sub(reportedAt) > fleetClientOfflineAfter {
		return "offline"
	}
	return state
}

// LoadFleetDesired returns the current desired revision, or a zero value when none exists.
func (a *Administration) LoadFleetDesired(ctx context.Context) (FleetDesired, error) {
	if a == nil {
		return FleetDesired{}, errors.New("fleet-config store is unavailable")
	}
	var desired FleetDesired
	err := a.db.QueryRowContext(ctx, `
SELECT desired.release_digest, release.source_commit, desired.generation, release.skill_count, release.total_bytes
FROM fleet.desired AS desired
JOIN fleet.releases AS release ON release.digest = desired.release_digest
WHERE desired.id`).Scan(&desired.Digest, &desired.SourceCommit, &desired.Generation, &desired.SkillCount, &desired.TotalBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return FleetDesired{}, nil
	}
	if err != nil {
		return FleetDesired{}, errors.New("fleet-config desired revision is unavailable")
	}
	return desired, nil
}

// LoadFleetReleaseByCommit returns the newest stored release for a source commit.
func (a *Administration) LoadFleetReleaseByCommit(ctx context.Context, commit string) (fleetconfig.Release, error) {
	if a == nil || a.db == nil {
		return fleetconfig.Release{}, errors.New("fleet-config store is unavailable")
	}
	if _, err := fleetconfig.ParseCommitID(commit); err != nil {
		return fleetconfig.Release{}, err
	}
	var release fleetconfig.Release
	var fileCount int
	err := a.db.QueryRowContext(ctx, `
SELECT digest, source_commit, archive, skill_count, file_count, total_bytes
FROM fleet.releases
WHERE source_commit = $1
ORDER BY created_at DESC
LIMIT 1`, commit).Scan(&release.Digest, &release.SourceCommit, &release.Archive, &release.SkillCount, &fileCount, &release.TotalBytes)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return fleetconfig.Release{}, errors.New("fleet-config stored release is unavailable")
	}
	release.DataOnly = true
	release.Schema = fleetconfig.SchemaV1
	if fileCount > 0 {
		release.Files = make([]fleetconfig.ManifestFile, fileCount)
	}
	return release, nil
}

// PublishFleetRelease stores the immutable archive first, then sets desired state.
// An identical digest does not increment generation. expected must match the
// locked singleton (zero when none exists) or publication is rejected as stale.
func (a *Administration) PublishFleetRelease(ctx context.Context, release fleetconfig.Release, previewHash string, expected FleetDesired) (FleetDesired, error) {
	if a == nil || a.db == nil || !release.DataOnly || release.Digest == "" || len(release.Archive) == 0 || previewHash == "" {
		return FleetDesired{}, errors.New("fleet-config release is invalid")
	}
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return FleetDesired{}, mutationStartError(err, "fleet-config publication failed")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO fleet.releases (digest, source_commit, archive, skill_count, file_count, total_bytes)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (digest) DO NOTHING`,
		release.Digest, release.SourceCommit, release.Archive, release.SkillCount, len(release.Files), release.TotalBytes); err != nil {
		return FleetDesired{}, errors.New("fleet-config publication failed")
	}
	var currentDigest string
	var currentGeneration int64
	err = tx.QueryRowContext(ctx, `SELECT release_digest, generation FROM fleet.desired WHERE id FOR UPDATE`).Scan(&currentDigest, &currentGeneration)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return FleetDesired{}, errors.New("fleet-config publication failed")
	}
	if errors.Is(err, sql.ErrNoRows) {
		if expected.Digest != "" || expected.Generation != 0 {
			return FleetDesired{}, errors.New("fleet-config preview is stale")
		}
		if err := tx.QueryRowContext(ctx, `
INSERT INTO fleet.desired (id, release_digest, generation, preview_hash)
VALUES (true, $1, 1, $2)
RETURNING generation`, release.Digest, previewHash).Scan(&currentGeneration); err != nil {
			return FleetDesired{}, errors.New("fleet-config publication failed")
		}
	} else {
		if currentDigest != expected.Digest || currentGeneration != expected.Generation {
			return FleetDesired{}, errors.New("fleet-config preview is stale")
		}
		if currentDigest != release.Digest {
			if err := tx.QueryRowContext(ctx, `
UPDATE fleet.desired
SET release_digest = $1, generation = generation + 1, published_at = statement_timestamp(), preview_hash = $2
WHERE id
RETURNING generation`, release.Digest, previewHash).Scan(&currentGeneration); err != nil {
				return FleetDesired{}, errors.New("fleet-config publication failed")
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return FleetDesired{}, errors.New("fleet-config publication failed")
	}
	return FleetDesired{
		Digest:       release.Digest,
		SourceCommit: release.SourceCommit,
		Generation:   currentGeneration,
		SkillCount:   release.SkillCount,
		TotalBytes:   release.TotalBytes,
	}, nil
}

// FleetDesired returns content-free desired metadata for an enrolled application connection.
func (d *Database) FleetDesired(ctx context.Context) (relay.FleetDesiredMetadata, error) {
	if d == nil {
		return relay.FleetDesiredMetadata{}, errors.New("fleet-config store is unavailable")
	}
	var desired relay.FleetDesiredMetadata
	err := d.db.QueryRowContext(ctx, `
SELECT desired.generation, desired.release_digest, release.source_commit, release.skill_count, release.total_bytes
FROM fleet.desired AS desired
JOIN fleet.releases AS release ON release.digest = desired.release_digest
WHERE desired.id`).Scan(&desired.Generation, &desired.Digest, &desired.SourceCommit, &desired.SkillCount, &desired.TotalBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.FleetDesiredMetadata{}, nil
	}
	if err != nil {
		return relay.FleetDesiredMetadata{}, errors.New("fleet-config desired revision is unavailable")
	}
	return desired, nil
}

// FleetRelease returns exact stored archive bytes for one digest.
func (d *Database) FleetRelease(ctx context.Context, digest string) ([]byte, error) {
	if d == nil || digest == "" {
		return nil, errors.New("fleet-config release is unavailable")
	}
	var archive []byte
	err := d.db.QueryRowContext(ctx, `SELECT archive FROM fleet.releases WHERE digest = $1`, digest).Scan(&archive)
	if err != nil {
		return nil, errors.New("fleet-config release is unavailable")
	}
	return archive, nil
}

// PutFleetStatus records one enrolled client's bounded status row.
func (d *Database) PutFleetStatus(ctx context.Context, machineID string, report relay.FleetStatusReport) error {
	if d == nil || machineID == "" {
		return errors.New("fleet-config access is not authorized")
	}
	_, err := d.db.ExecContext(ctx, `SELECT fleet.put_client_status($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		machineID, report.Generation, nullIfEmpty(report.AppliedDigest), report.State, nullIfEmpty(report.Activation),
		nullIfEmpty(report.TrailerState), nullIfEmpty(report.AliasState), nullIfEmpty(report.ProjectMatchState),
		report.ReportGeneration, report.IdempotencyKey, report.RequestHash)
	if err != nil {
		return errors.New(postgresFleetStatusError(err))
	}
	return nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ListFleetClientStatus returns bounded client rows without configuration contents.
func (a *Administration) ListFleetClientStatus(ctx context.Context) ([]FleetClientStatus, error) {
	if a == nil {
		return nil, errors.New("fleet-config store is unavailable")
	}
	rows, err := a.db.QueryContext(ctx, `
SELECT machine_id, COALESCE(applied_digest, ''), COALESCE(state, ''),
       COALESCE(activation, ''), COALESCE(trailer_state, ''), COALESCE(alias_state, ''),
       COALESCE(project_match_state, ''), generation, reported_at
FROM fleet.client_status
ORDER BY machine_id
LIMIT 256`)
	if err != nil {
		return nil, errors.New("fleet-config status is unavailable")
	}
	defer func() { _ = rows.Close() }()
	result := []FleetClientStatus{}
	now := time.Now().UTC()
	for rows.Next() {
		var row FleetClientStatus
		var reportedAt time.Time
		if err := rows.Scan(&row.MachineID, &row.AppliedDigest, &row.State, &row.Activation, &row.TrailerState, &row.AliasState, &row.ProjectMatchState, &row.Generation, &reportedAt); err != nil {
			return nil, errors.New("fleet-config status is unavailable")
		}
		row.State = ExpireFleetClientState(row.State, reportedAt, now)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("fleet-config status is unavailable")
	}
	return result, nil
}

func postgresFleetStatusError(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "stale"):
		return "fleet-config status generation is stale"
	case strings.Contains(message, "idempotency"):
		return "fleet-config status idempotency conflict"
	default:
		return "fleet-config access is not authorized"
	}
}
