package main

import (
	"context"
	"errors"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type updateExecution struct {
	Request      punaropostgres.UpdateRequest
	Abort        bool
	RecoveryMode string
}

type updateExecutor interface {
	Active(context.Context) (punaropostgres.UpdateTransaction, error)
	PreflightAndPull(context.Context) error
	PrepareResume(context.Context, punaropostgres.UpdateTransaction) error
	Fence(context.Context, punaropostgres.UpdateRequest) (punaropostgres.UpdateTransaction, error)
	StopWriters(context.Context) error
	Backup(context.Context, punaropostgres.UpdateTransaction) (punaropostgres.UpdateBackupMarker, error)
	Migrate(context.Context, punaropostgres.UpdateTransaction) error
	StartCandidate(context.Context, punaropostgres.UpdateTransaction) error
	Doctor(context.Context, punaropostgres.UpdateTransaction) error
	Publish(context.Context, punaropostgres.UpdateTransaction, bool) error
	AbortToPrevious(context.Context, punaropostgres.UpdateTransaction) error
	Recover(context.Context, punaropostgres.UpdateTransaction, string) error
	Advance(context.Context, punaropostgres.UpdateTransaction, punaropostgres.UpdatePhase, *punaropostgres.UpdateBackupMarker) (punaropostgres.UpdateTransaction, error)
}

func executeUpdate(ctx context.Context, execution updateExecution, executor updateExecutor) (punaropostgres.UpdateTransaction, error) {
	if executor == nil || execution.Request.Validate() != nil {
		return punaropostgres.UpdateTransaction{}, errors.New("update execution is invalid")
	}
	transaction, err := executor.Active(ctx)
	if errors.Is(err, punaropostgres.ErrNotFound) {
		if execution.Abort || execution.RecoveryMode != "" {
			return punaropostgres.UpdateTransaction{}, errors.New("no update transaction is active")
		}
		if err := executor.PreflightAndPull(ctx); err != nil {
			return punaropostgres.UpdateTransaction{}, err
		}
		transaction, err = executor.Fence(ctx, execution.Request)
	}
	if err != nil {
		return punaropostgres.UpdateTransaction{}, err
	}
	if transaction.UpdateRequest != execution.Request {
		return transaction, errors.New("active update target does not match the requested release")
	}
	if execution.Abort {
		switch transaction.Phase {
		case punaropostgres.UpdateFenced, punaropostgres.UpdateWritersStopped, punaropostgres.UpdateBackupVerified:
			if err := executor.AbortToPrevious(ctx, transaction); err != nil {
				return transaction, err
			}
			return executor.Advance(ctx, transaction, punaropostgres.UpdateAborted, nil)
		default:
			return transaction, errors.New("update cannot be aborted after migration starts")
		}
	}
	if execution.RecoveryMode != "" {
		switch transaction.Phase {
		case punaropostgres.UpdateMigrationStarted, punaropostgres.UpdateMigrated, punaropostgres.UpdateCandidateReady, punaropostgres.UpdateDoctorPassed:
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateRecoveryRequired, nil)
			if err != nil {
				return transaction, err
			}
		case punaropostgres.UpdateRecoveryRequired, punaropostgres.UpdateRecoveryReady, punaropostgres.UpdateRecoveryDoctor, punaropostgres.UpdateRecoveryConfig:
			// Resume the explicitly selected recovery path below.
		default:
			return transaction, errors.New("update recovery cannot start in the current phase")
		}
	}
	if execution.RecoveryMode == "" && transaction.Phase != punaropostgres.UpdateRecoveryRequired && transaction.Phase != punaropostgres.UpdateRecoveryReady && transaction.Phase != punaropostgres.UpdateRecoveryDoctor && transaction.Phase != punaropostgres.UpdateRecoveryConfig {
		if err := executor.PrepareResume(ctx, transaction); err != nil {
			return transaction, err
		}
	}
	if execution.RecoveryMode == "" && (transaction.Phase == punaropostgres.UpdateRecoveryRequired || transaction.Phase == punaropostgres.UpdateRecoveryReady || transaction.Phase == punaropostgres.UpdateRecoveryDoctor) {
		return transaction, errors.New("update recovery choice is required")
	}

	for {
		switch transaction.Phase {
		case punaropostgres.UpdateFenced:
			if err := executor.StopWriters(ctx); err != nil {
				return transaction, err
			}
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateWritersStopped, nil)
		case punaropostgres.UpdateWritersStopped:
			var marker punaropostgres.UpdateBackupMarker
			marker, err = executor.Backup(ctx, transaction)
			if err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateBackupVerified, &marker)
			}
		case punaropostgres.UpdateBackupVerified:
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateMigrationStarted, nil)
		case punaropostgres.UpdateMigrationStarted:
			if err = executor.Migrate(ctx, transaction); err != nil {
				return transaction, err
			}
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateMigrated, nil)
		case punaropostgres.UpdateMigrated:
			if err = executor.StartCandidate(ctx, transaction); err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateCandidateReady, nil)
			}
		case punaropostgres.UpdateCandidateReady:
			if err = executor.Doctor(ctx, transaction); err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateDoctorPassed, nil)
			}
		case punaropostgres.UpdateDoctorPassed:
			if err = executor.Publish(ctx, transaction, false); err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateConfigPublished, nil)
			}
		case punaropostgres.UpdateConfigPublished:
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateCommitted, nil)
		case punaropostgres.UpdateRecoveryRequired:
			if execution.RecoveryMode == "" {
				return transaction, errors.New("update recovery choice is required")
			}
			if err = executor.Recover(ctx, transaction, execution.RecoveryMode); err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateRecoveryReady, nil)
			}
		case punaropostgres.UpdateRecoveryReady:
			if err = executor.Recover(ctx, transaction, execution.RecoveryMode); err == nil {
				err = executor.Doctor(ctx, transaction)
			}
			if err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateRecoveryDoctor, nil)
			}
		case punaropostgres.UpdateRecoveryDoctor:
			if err = executor.Recover(ctx, transaction, execution.RecoveryMode); err == nil {
				err = executor.Publish(ctx, transaction, true)
			}
			if err == nil {
				transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateRecoveryConfig, nil)
			}
		case punaropostgres.UpdateRecoveryConfig:
			transaction, err = executor.Advance(ctx, transaction, punaropostgres.UpdateRecovered, nil)
		case punaropostgres.UpdateCommitted, punaropostgres.UpdateRecovered, punaropostgres.UpdateAborted:
			return transaction, nil
		default:
			return transaction, errors.New("update transaction has an unsupported phase")
		}
		if err != nil {
			return transaction, err
		}
	}
}
