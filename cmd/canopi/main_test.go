package main

import (
	"path/filepath"
	"testing"
	"time"
)

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
	if config.maxLiveRecords != 2_048 || config.maxFutureSkew != 5*time.Minute {
		t.Fatalf("default admission bounds = %d records, %s skew", config.maxLiveRecords, config.maxFutureSkew)
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
	if _, err := parseConfig(append(base, "--max-future-skew", "0s")); err == nil {
		t.Fatal("parseConfig() accepted zero future clock skew")
	}
	if _, err := parseConfig(append(base, "--tls-cert-file", filepath.Join(directory, "server.crt"))); err == nil {
		t.Fatal("parseConfig() accepted incomplete TLS configuration")
	}
}
