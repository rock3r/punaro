package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

func TestRunFailsClosedBeforeStartingAttachmentRuntime(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENTS_ENABLED", "true")
	t.Setenv("PUNARO_ATTACHMENT_DEVICE_KEYS_JSON", `{}`)
	t.Setenv("PUNARO_ATTACHMENT_MEMBERSHIP_JSON", `[]`)
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run exit code = %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "runtime is withheld") {
		t.Fatalf("stderr = %q, want fail-closed explanation", stderr.String())
	}
}

type refusingPlatformDatabase struct {
	readyCalled bool
	closed      bool
}

func (d *refusingPlatformDatabase) Ready(context.Context) error {
	d.readyCalled = true
	return errors.New("PostgreSQL schema is incompatible")
}

func (d *refusingPlatformDatabase) Close() error {
	d.closed = true
	return nil
}

func TestRunRejectsIncompatiblePostgresWithoutStartingServer(t *testing.T) {
	original := openPlatformDatabase
	t.Cleanup(func() { openPlatformDatabase = original })
	database := &refusingPlatformDatabase{}
	openPlatformDatabase = func(_ context.Context, cfg punaropostgres.Config) (platformDatabase, error) {
		if cfg.DSNFile != "/run/secrets/punaro-app-dsn" {
			t.Fatalf("DSN file=%q", cfg.DSNFile)
		}
		return database, nil
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}
	if !database.readyCalled || !database.closed || !strings.Contains(stderr.String(), "readiness error") {
		t.Fatalf("ready=%t closed=%t stderr=%q", database.readyCalled, database.closed, stderr.String())
	}
}

func TestRunDoesNotServePublicSocketWhenHealthBindFails(t *testing.T) {
	originalListen := listenTCP
	t.Cleanup(func() { listenTCP = originalListen })
	tracked := &trackingListener{}
	calls := 0
	listenTCP = func(string, string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return tracked, nil
		}
		return nil, errors.New("health address occupied")
	}
	t.Setenv("PUNARO_LISTEN_ADDR", "127.0.0.1:18080")
	t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", "127.0.0.1:18081")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if tracked.acceptCalled {
		t.Fatal("public server began accepting before the health bind succeeded")
	}
	if !tracked.closed {
		t.Fatal("public listener remained open after the health bind failed")
	}
}

type trackingListener struct {
	acceptCalled bool
	closed       bool
}

func (l *trackingListener) Accept() (net.Conn, error) {
	l.acceptCalled = true
	return nil, errors.New("unexpected Accept call")
}

func (l *trackingListener) Close() error { l.closed = true; return nil }
func (*trackingListener) Addr() net.Addr { return testAddr("127.0.0.1:18080") }

type testAddr string

func (testAddr) Network() string  { return "tcp" }
func (a testAddr) String() string { return string(a) }
