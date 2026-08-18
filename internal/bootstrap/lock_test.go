package bootstrap

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLockDirectoryRejectsSecondProcess(t *testing.T) {
	if dir := os.Getenv("PUNARO_BOOTSTRAP_LOCK_DIR"); dir != "" {
		unlock, err := lockDirectory(dir)
		if err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("locked\n")
		_, _ = os.Stdin.Read(make([]byte, 1))
		unlock()
		os.Exit(0)
	}
	dir := t.TempDir()
	helper := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestLockDirectoryRejectsSecondProcess$") // #nosec G204,G702 -- same test binary.
	helper.Env = append(os.Environ(), "PUNARO_BOOTSTRAP_LOCK_DIR="+dir)
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("helper lock=%q err=%v", line, err)
	}
	if _, err := lockDirectory(dir); err == nil {
		t.Fatal("second process lock accepted")
	}
	_ = stdin.Close()
	if err := helper.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireRunLeaseTerminatesStaleChild(t *testing.T) {
	dir := privateDir(t)
	cmd := exec.CommandContext(context.Background(), "sleep", "30") // #nosec G204,G702 -- local test helper.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	if err := writeRunPID(dir, cmd.Process.Pid, cmd.Path); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireRunLease(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stale child was not terminated")
	}
}

func TestRunLeaseRejectsSecondProcessAndLeavesTransactionLockFree(t *testing.T) {
	if dir := os.Getenv("PUNARO_BOOTSTRAP_RUN_LEASE_DIR"); dir != "" {
		unlock, err := acquireRunLease(dir)
		if err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("locked\n")
		_, _ = os.Stdin.Read(make([]byte, 1))
		unlock()
		os.Exit(0)
	}
	dir := t.TempDir()
	helper := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunLeaseRejectsSecondProcessAndLeavesTransactionLockFree$") // #nosec G204,G702 -- same test binary.
	helper.Env = append(os.Environ(), "PUNARO_BOOTSTRAP_RUN_LEASE_DIR="+dir)
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("helper lease=%q err=%v", line, err)
	}
	if _, err := acquireRunLease(dir); err == nil {
		t.Fatal("second process run lease accepted")
	}
	unlock, err := lockDirectory(dir)
	if err != nil {
		t.Fatalf("transaction lock blocked by run lease: %v", err)
	}
	unlock()
	_ = stdin.Close()
	if err := helper.Wait(); err != nil {
		t.Fatal(err)
	}
}
