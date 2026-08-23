package main

import (
	"path/filepath"
	"testing"
)

func TestParseConfigRequiresExplicitLANBinding(t *testing.T) {
	directory := t.TempDir()
	common := []string{"--token-file", filepath.Join(directory, "token"), "--state-file", filepath.Join(directory, "state.json")}
	if _, err := parseConfig(append(common, "--listen", "192.168.1.20:8090")); err == nil {
		t.Fatal("parseConfig() accepted LAN bind without --allow-lan")
	}
	config, err := parseConfig(append(common, "--listen", "192.168.1.20:8090", "--allow-lan"))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if config.grid.Columns != 2 || config.grid.Rows != 6 {
		t.Fatalf("default grid = %dx%d, want 2x6", config.grid.Columns, config.grid.Rows)
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
}
