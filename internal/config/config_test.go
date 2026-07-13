package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesExplicitDotEnvWithoutOverridingProcess(t *testing.T) {
	t.Setenv("PUNARO_LISTEN_ADDR", "127.0.0.1:9999")
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PUNARO_LISTEN_ADDR=0.0.0.0:8080\nPUNARO_LOG_LEVEL=debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("listen address = %q", cfg.ListenAddr)
	}
}
func TestLoadRejectsInvalidLevel(t *testing.T) {
	t.Setenv("PUNARO_LOG_LEVEL", "nope")
	if _, err := Load(""); err == nil {
		t.Fatal("Load succeeded for invalid log level")
	}
}
