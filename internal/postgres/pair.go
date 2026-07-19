package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrMigrationNotAttempted marks failures that occurred before any schema
// mutation, allowing first-install staging to be rolled back safely.
var ErrMigrationNotAttempted = errors.New("PostgreSQL migration was not attempted")

// MigratePristinePair proves that the application and schema-owner DSNs reach
// the same pristine database, then migrates through the already-verified owner
// pool while the proof remains held. The random advisory-lock probe is scoped
// by PostgreSQL to one database, so a second session can observe it only when
// both connections share that target.
func MigratePristinePair(ctx context.Context, appConfig, ownerConfig Config) (SchemaState, error) {
	return withPristinePair(ctx, appConfig, ownerConfig, func(ownerConn *sql.Conn) (SchemaState, error) {
		return migrateConn(ctx, ownerConn, CurrentManifest())
	})
}

// VerifyPristinePair proves both roles target the same pristine database and
// performs no schema mutation. Clean-stack restore runs only after this gate.
func VerifyPristinePair(ctx context.Context, appConfig, ownerConfig Config) error {
	_, err := withPristinePair(ctx, appConfig, ownerConfig, func(*sql.Conn) (SchemaState, error) {
		return SchemaState{Classification: Pristine}, nil
	})
	return err
}

func withPristinePair(ctx context.Context, appConfig, ownerConfig Config, action func(*sql.Conn) (SchemaState, error)) (SchemaState, error) {
	appDSN, err := ReadDSNFile(appConfig.DSNFile)
	if err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	ownerDSN, err := ReadDSNFile(ownerConfig.DSNFile)
	if err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	appDB, err := open(ctx, appDSN)
	if err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	defer func() { _ = appDB.Close() }()
	ownerDB, err := open(ctx, ownerDSN)
	if err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	defer func() { _ = ownerDB.Close() }()
	appConn, err := appDB.Conn(ctx)
	if err != nil {
		return SchemaState{}, preMigrationError(errors.New("PostgreSQL application target cannot be verified"))
	}
	defer func() { _ = appConn.Close() }()
	ownerConn, err := ownerDB.Conn(ctx)
	if err != nil {
		return SchemaState{}, preMigrationError(errors.New("PostgreSQL owner target cannot be verified"))
	}
	defer func() { _ = ownerConn.Close() }()
	if err := verifyApplicationRole(ctx, appConn); err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	if err := verifyMigrationRoles(ctx, ownerConn); err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	if err := requirePristine(ctx, appConn); err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	if err := requirePristine(ctx, ownerConn); err != nil {
		return SchemaState{}, preMigrationError(err)
	}
	key, err := randomAdvisoryKey()
	if err != nil {
		return SchemaState{}, preMigrationError(errors.New("PostgreSQL target proof cannot be created"))
	}
	var ownerLocked bool
	if err := ownerConn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ownerLocked); err != nil || !ownerLocked {
		return SchemaState{}, preMigrationError(errors.New("PostgreSQL owner target cannot be locked for verification"))
	}
	defer unlockAdvisory(ownerConn, key)
	var appLocked bool
	if err := appConn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&appLocked); err != nil {
		return SchemaState{}, preMigrationError(errors.New("PostgreSQL application target cannot be probed"))
	}
	if appLocked {
		unlockAdvisory(appConn, key)
		return SchemaState{}, preMigrationError(errors.New("application and owner DSNs target different pristine databases"))
	}
	return action(ownerConn)
}

func preMigrationError(err error) error {
	return fmt.Errorf("%w: %w", ErrMigrationNotAttempted, err)
}

func requirePristine(ctx context.Context, conn *sql.Conn) error {
	snapshot, err := inspect(ctx, conn)
	if err != nil {
		return err
	}
	if Classify(snapshot, CurrentManifest()).Classification != Pristine {
		return errors.New("PostgreSQL initialization requires a pristine database")
	}
	return nil
}

func randomAdvisoryKey() (int64, error) {
	var key int64
	if err := binary.Read(rand.Reader, binary.BigEndian, &key); err != nil {
		return 0, err
	}
	return key, nil
}

func unlockAdvisory(conn *sql.Conn, key int64) {
	unlockCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, key)
}
