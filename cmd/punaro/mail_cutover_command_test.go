package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/cutover"
	"github.com/rock3r/punaro/internal/operator"
	"github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

func TestMailCutoverCommandRequiresDryRunBindingAndExplicitConfirmation(t *testing.T) {
	directory := testInstallation(t)
	called := false
	execute := func(_ context.Context, _ operator.Installation, dryRun, abort bool, request cutover.Request) (any, error) {
		called = true
		if !dryRun || abort || request.EpochID != "" || request.ExpectedSourceFingerprint != "" {
			t.Fatalf("dry-run request=%#v dry=%t abort=%t", request, dryRun, abort)
		}
		return cutover.Plan{SourcePhase: relay.MigrationSourceActive, SourceFingerprint: strings.Repeat("a", 64), TargetIdentity: strings.Repeat("b", 64)}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := runMailCutover([]string{"--directory", directory, "--dry-run"}, &stdout, &stderr, execute); code != 0 || !called || !strings.Contains(stdout.String(), `"source_fingerprint"`) {
		t.Fatalf("dry-run code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	called = false
	stdout.Reset()
	stderr.Reset()
	if code := runMailCutover([]string{"--directory", directory, "--epoch-id", "019f7f07-8b88-7c12-a394-b663274a6555", "--expected-source-fingerprint", strings.Repeat("a", 64)}, &stdout, &stderr, execute); code != 2 || called {
		t.Fatalf("unconfirmed code=%d called=%t stderr=%q", code, called, stderr.String())
	}
}

func TestMailCutoverCommandPassesExactIrreversibleAuthorization(t *testing.T) {
	directory := testInstallation(t)
	epoch := "019f7f07-8b88-7c12-a394-b663274a6555"
	fingerprint := strings.Repeat("a", 64)
	execute := func(_ context.Context, installation operator.Installation, dryRun, abort bool, request cutover.Request) (any, error) {
		if dryRun || abort || request.ActorPrincipalID != installation.OwnerPrincipalID || request.EpochID != epoch || request.ExpectedSourceFingerprint != fingerprint || request.Cutoff.IsZero() {
			t.Fatalf("installation=%#v request=%#v dry=%t abort=%t", installation, request, dryRun, abort)
		}
		return cutover.Result{EpochID: epoch, SourceFingerprint: fingerprint, SourcePhase: relay.MigrationSourceRetired, Phase: postgres.MailCutoverActive}, nil
	}
	var stdout, stderr bytes.Buffer
	args := []string{"--directory", directory, "--epoch-id", epoch, "--expected-source-fingerprint", fingerprint, "--yes"}
	if code := runMailCutover(args, &stdout, &stderr, execute); code != 0 || !strings.Contains(stdout.String(), `"phase": "active"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestMailCutoverCommandPassesExplicitAbort(t *testing.T) {
	directory := testInstallation(t)
	epoch := "019f7f07-8b88-7c12-a394-b663274a6555"
	execute := func(_ context.Context, installation operator.Installation, dryRun, abort bool, request cutover.Request) (any, error) {
		if dryRun || !abort || request.ActorPrincipalID != installation.OwnerPrincipalID || request.EpochID != epoch || request.ExpectedSourceFingerprint != "" {
			t.Fatalf("request=%#v dry=%t abort=%t", request, dryRun, abort)
		}
		return cutover.Result{EpochID: epoch, SourcePhase: relay.MigrationSourceActive, Phase: postgres.MailCutoverAborted}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := runMailCutover([]string{"--directory", directory, "--abort", "--epoch-id", epoch, "--yes"}, &stdout, &stderr, execute); code != 0 || !strings.Contains(stdout.String(), `"phase": "aborted"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
