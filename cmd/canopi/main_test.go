package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeUntilShutdownWaitsForActiveHandlers(t *testing.T) {
	shutdownStarted := make(chan struct{})
	allowShutdown := make(chan struct{})
	serveReturned := make(chan struct{})
	signals := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(func() error {
			<-shutdownStarted
			close(serveReturned)
			return http.ErrServerClosed
		}, signals, func(context.Context) error {
			close(shutdownStarted)
			<-allowShutdown
			return nil
		})
	}()
	signals <- os.Interrupt
	<-serveReturned
	select {
	case err := <-done:
		t.Fatalf("serveUntilShutdown() returned before Shutdown completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowShutdown)
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serveUntilShutdown() = %v, want ErrServerClosed", err)
	}
}

func TestServeUntilShutdownDoesNotDeadlineActiveHandlers(t *testing.T) {
	shutdownContext := make(chan context.Context, 1)
	shutdownStarted := make(chan struct{})
	signals := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(func() error {
			<-shutdownStarted
			return http.ErrServerClosed
		}, signals, func(ctx context.Context) error {
			shutdownContext <- ctx
			close(shutdownStarted)
			return nil
		})
	}()
	signals <- os.Interrupt
	ctx := <-shutdownContext
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("shutdown context has a deadline that can release the store lock before handlers exit")
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serveUntilShutdown() = %v, want ErrServerClosed", err)
	}
}

func TestServeUntilShutdownDrainsAfterUnexpectedServeError(t *testing.T) {
	serveFailure := errors.New("listener failed")
	shutdownStarted := make(chan context.Context, 1)
	allowShutdown := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveUntilShutdown(func() error {
			return serveFailure
		}, make(chan os.Signal), func(ctx context.Context) error {
			shutdownStarted <- ctx
			<-allowShutdown
			return nil
		})
	}()
	ctx := <-shutdownStarted
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("unexpected Serve failure used a bounded shutdown context")
	}
	select {
	case err := <-done:
		t.Fatalf("serveUntilShutdown() returned before unexpected-exit drain completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowShutdown)
	if err := <-done; !errors.Is(err, serveFailure) {
		t.Fatalf("serveUntilShutdown() = %v, want listener failure", err)
	}
}

func TestParseConfigRequiresExplicitLANBinding(t *testing.T) {
	directory := t.TempDir()
	common := []string{"--token-file", filepath.Join(directory, "token"), "--state-file", filepath.Join(directory, "state.json")}
	if _, err := parseConfig(append(common, "--listen", "192.168.1.20:8090")); err == nil {
		t.Fatal("parseConfig() accepted LAN bind without --allow-lan")
	}
	if _, err := parseConfig(append(common, "--listen", "192.168.1.20:8090", "--allow-lan")); err == nil {
		t.Fatal("parseConfig() accepted plaintext LAN listener")
	}
	config, err := parseConfig(append(common, "--listen", "192.168.1.20:8090", "--allow-lan", "--tls-cert-file", filepath.Join(directory, "server.crt"), "--tls-key-file", filepath.Join(directory, "server.key")))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if config.grid.Columns != 2 || config.grid.Rows != 6 {
		t.Fatalf("default grid = %dx%d, want 2x6", config.grid.Columns, config.grid.Rows)
	}
	if config.maxLiveRecords != 2_048 || config.maxStateBytes != 8<<20 || config.maxFutureSkew != 5*time.Minute {
		t.Fatalf("default admission bounds = %d records, %d bytes, %s skew", config.maxLiveRecords, config.maxStateBytes, config.maxFutureSkew)
	}
}

func TestParseConfigRejectsWildcardAndInvalidCapacity(t *testing.T) {
	directory := t.TempDir()
	base := []string{"--token-file", filepath.Join(directory, "token"), "--state-file", filepath.Join(directory, "state.json")}
	if _, err := parseConfig(append(base, "--listen", ":8090")); err == nil {
		t.Fatal("parseConfig() accepted wildcard listener")
	}
	if _, err := parseConfig(append(base, "--columns", "0")); err == nil {
		t.Fatal("parseConfig() accepted zero grid columns")
	}
	if _, err := parseConfig(append(base, "--columns", "9223372036854775807", "--rows", "2")); err == nil {
		t.Fatal("parseConfig() accepted overflowing grid capacity")
	}
	if _, err := parseConfig(append(base, "--columns", "3", "--rows", "1")); err == nil {
		t.Fatal("parseConfig() accepted grid columns too narrow for the fixed renderer")
	}
	if _, err := parseConfig(append(base, "--columns", "1", "--rows", "7")); err == nil {
		t.Fatal("parseConfig() accepted grid rows too short for the fixed renderer")
	}
	if _, err := parseConfig(append(base, "--max-live-records", "0")); err == nil {
		t.Fatal("parseConfig() accepted zero live-record capacity")
	}
	if _, err := parseConfig(append(base, "--max-state-bytes", "1024")); err == nil {
		t.Fatal("parseConfig() accepted an undersized state byte budget")
	}
	if _, err := parseConfig(append(base, "--max-future-skew", "0s")); err == nil {
		t.Fatal("parseConfig() accepted zero future clock skew")
	}
	if _, err := parseConfig(append(base, "--tls-cert-file", filepath.Join(directory, "server.crt"))); err == nil {
		t.Fatal("parseConfig() accepted incomplete TLS configuration")
	}
}
