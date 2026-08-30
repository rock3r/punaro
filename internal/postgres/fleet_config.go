package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

// FleetDesired is the singleton published fleet-config revision.
type FleetDesired struct {
	Digest       string
	SourceCommit string
	Generation   int64
	SkillCount   int
	TotalBytes   int64
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
