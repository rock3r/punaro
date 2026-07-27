package postgres

import (
	"context"
	"errors"
)

const requiredPGVectorVersion = "0.8.2"

var pgVectorAvailableFn = pgVectorAvailable

// RequirePGVector verifies the exact extension package is available before an
// update crosses its irreversible migration boundary.
func RequirePGVector(ctx context.Context, cfg Config) error {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return err
	}
	available, err := pgVectorAvailableFn(ctx, dsn)
	if err != nil || !available {
		return errors.New("PostgreSQL pgvector 0.8.2 prerequisite is unavailable")
	}
	return nil
}

func pgVectorAvailable(ctx context.Context, dsn string) (bool, error) {
	db, err := open(ctx, dsn)
	if err != nil {
		return false, err
	}
	defer func() { _ = db.Close() }()
	var available bool
	err = db.QueryRowContext(ctx, `SELECT
    (NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')
     AND EXISTS (
         SELECT 1 FROM pg_available_extension_versions
         WHERE name='vector' AND version=$1
     )
     AND EXISTS (
         SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper
     ))
    OR EXISTS (
        SELECT 1
        FROM pg_extension AS ext
        WHERE ext.extname='vector'
          AND pg_get_userbyid(ext.extowner)=current_user
          AND (
              ext.extversion=$1
              OR EXISTS (
                  SELECT 1
                  FROM pg_extension_update_paths('vector') AS path
                  WHERE path.source=ext.extversion AND path.target=$1
                    AND path.path IS NOT NULL
              )
          )
    )`, requiredPGVectorVersion).Scan(&available)
	return available, err
}
