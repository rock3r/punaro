package postgres

import (
	"context"
	"errors"
)

const requiredPGVectorVersion = "0.8.2"

// RequirePGVector verifies the exact extension package is available before an
// update crosses its irreversible migration boundary.
func RequirePGVector(ctx context.Context, cfg Config) error {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return err
	}
	db, err := open(ctx, dsn)
	if err != nil {
		return errors.New("PostgreSQL pgvector prerequisite is unavailable")
	}
	defer func() { _ = db.Close() }()
	var available bool
	err = db.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_available_extensions
    WHERE name='vector' AND default_version=$1
)`, requiredPGVectorVersion).Scan(&available)
	if err != nil || !available {
		return errors.New("PostgreSQL pgvector 0.8.2 prerequisite is unavailable")
	}
	return nil
}
