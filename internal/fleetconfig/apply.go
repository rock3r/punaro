package fleetconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ApplyState is persisted next to the live tree without configuration contents.
type ApplyState struct {
	Digest           string            `json:"digest"`
	PrefixDigests    map[string]string `json:"prefix_digests,omitempty"`
	LastGoodDigest   string            `json:"last_good_digest,omitempty"`
	ReportGeneration int64             `json:"report_generation,omitempty"`
	ProjectPaths     map[string]string `json:"project_paths,omitempty"`
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
	unlockFile, err := lockReconcile(filepath.Join(root, "reconcile.lock"))
	if err != nil {
		return fmt.Errorf("fleet-config reconcile lock failed: %w", err)
	}
	defer unlockFile()
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
	nextGood := lastGood + ".next"
	if err := recoverPublishSwap(live, lastGood, nextGood); err != nil {
		return err
	}
	if info, err := os.Lstat(live); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fleet-config live tree is unsafe")
		}
		if err := os.Rename(live, nextGood); err != nil {
			return errors.New("fleet-config last-known-good failed")
		}
	}
	if err := os.Rename(stage, live); err != nil {
		if _, nextErr := os.Lstat(nextGood); nextErr == nil {
			_ = os.Rename(nextGood, live)
		}
		return errors.New("fleet-config apply failed")
	}
	if _, err := os.Lstat(nextGood); err == nil {
		_ = os.RemoveAll(lastGood)
		_ = os.Rename(nextGood, lastGood)
	}
	prefixDigests := map[string]string{}
	for path, content := range files {
		if !stringsHasSuffixAgents(path) {
			continue
		}
		prefix, _, ok := SplitAgents(content)
		if !ok {
			continue
		}
		prefixDigests[path] = DigestBytes(prefix)
	}
	state := ApplyState{Digest: digest, LastGoodDigest: digest, PrefixDigests: prefixDigests}
	body, err := json.Marshal(state)
	if err != nil {
		return errors.New("fleet-config apply state failed")
	}
	if err := os.WriteFile(filepath.Join(root, "applied.json"), append(body, '\n'), 0o600); err != nil {
		return errors.New("fleet-config apply state failed")
	}
	return nil
}

func recoverPublishSwap(live, lastGood, nextGood string) error {
	liveInfo, liveErr := os.Lstat(live)
	nextInfo, nextErr := os.Lstat(nextGood)
	liveOK := liveErr == nil && liveInfo.IsDir() && liveInfo.Mode()&os.ModeSymlink == 0
	nextOK := nextErr == nil && nextInfo.IsDir() && nextInfo.Mode()&os.ModeSymlink == 0
	if liveErr == nil && !liveOK {
		return errors.New("fleet-config live tree is unsafe")
	}
	if nextErr == nil && !nextOK {
		return errors.New("fleet-config last-known-good failed")
	}
	if liveErr != nil && nextOK {
		if err := os.Rename(nextGood, live); err != nil {
			return errors.New("fleet-config last-known-good failed")
		}
		return nil
	}
	if liveOK && nextOK {
		_ = os.RemoveAll(lastGood)
		if err := os.Rename(nextGood, lastGood); err != nil {
			return errors.New("fleet-config last-known-good failed")
		}
	}
	return nil
}

// RestoreLastGood puts the retained tree back after a failed activation.
func RestoreLastGood(root string) error {
	unlockFile, err := lockReconcile(filepath.Join(root, "reconcile.lock"))
	if err != nil {
		return fmt.Errorf("fleet-config reconcile lock failed: %w", err)
	}
	defer unlockFile()
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
