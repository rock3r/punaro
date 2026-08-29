package fleetconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ApplyState is persisted next to the live tree without configuration contents.
type ApplyState struct {
	Digest         string            `json:"digest"`
	PrefixDigests  map[string]string `json:"prefix_digests,omitempty"`
	LastGoodDigest string            `json:"last_good_digest,omitempty"`
}

var reconcileMu sync.Mutex

// ReconcileLock serializes local apply attempts in-process.
func ReconcileLock() func() {
	reconcileMu.Lock()
	return reconcileMu.Unlock
}

// PublishTree writes files into staging and atomically replaces live.
func PublishTree(root string, files map[string][]byte, digest string) error {
	if root == "" || digest == "" || len(files) == 0 {
		return errors.New("fleet-config apply input is invalid")
	}
	unlock := ReconcileLock()
	defer unlock()
	live := filepath.Join(root, "current")
	stage := filepath.Join(root, "staging")
	lastGood := filepath.Join(root, "last-good")
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return errors.New("fleet-config staging failed")
	}
	for path, body := range files {
		full := filepath.Join(append([]string{stage}, strings.Split(path, "/")...)...)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return errors.New("fleet-config staging failed")
		}
		if err := os.WriteFile(full, body, 0o600); err != nil {
			return errors.New("fleet-config staging failed")
		}
	}
	if info, err := os.Lstat(live); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fleet-config live tree is unsafe")
		}
		_ = os.RemoveAll(lastGood)
		if err := os.Rename(live, lastGood); err != nil {
			return errors.New("fleet-config last-known-good failed")
		}
	}
	if err := os.Rename(stage, live); err != nil {
		if _, lastErr := os.Lstat(lastGood); lastErr == nil {
			_ = os.Rename(lastGood, live)
		}
		return errors.New("fleet-config apply failed")
	}
	state := ApplyState{Digest: digest, LastGoodDigest: digest}
	body, err := json.Marshal(state)
	if err != nil {
		return errors.New("fleet-config apply state failed")
	}
	if err := os.WriteFile(filepath.Join(root, "applied.json"), append(body, '\n'), 0o600); err != nil {
		return errors.New("fleet-config apply state failed")
	}
	return nil
}

// RestoreLastGood puts the retained tree back after a failed activation.
func RestoreLastGood(root string) error {
	unlock := ReconcileLock()
	defer unlock()
	live := filepath.Join(root, "current")
	lastGood := filepath.Join(root, "last-good")
	if _, err := os.Lstat(lastGood); err != nil {
		return errors.New("fleet-config last-known-good is unavailable")
	}
	_ = os.RemoveAll(live)
	if err := os.Rename(lastGood, live); err != nil {
		return errors.New("fleet-config last-known-good restore failed")
	}
	return nil
}
