package bootstrap

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
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
	cmd, image := startSleepProcess(t)
	if err := writeRunPID(dir, cmd.Process.Pid, image); err != nil {
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
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); !os.IsNotExist(err) {
		t.Fatal("run.pid survived a successful terminate")
	}
}

func TestAcquireRunLeaseLeavesMismatchedProcess(t *testing.T) {
	dir := privateDir(t)
	cmd, _ := startSleepProcess(t)
	if err := writeRunPID(dir, cmd.Process.Pid, os.Args[0]); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireRunLease(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("mismatched pid was killed")
	}
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); !os.IsNotExist(err) {
		t.Fatal("mismatched run.pid was kept")
	}
}

func TestAcquireRunLeaseClearsDeadPID(t *testing.T) {
	dir := privateDir(t)
	cmd, image := startSleepProcess(t)
	pid := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := writeRunPID(dir, pid, image); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireRunLease(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); !os.IsNotExist(err) {
		t.Fatal("dead run.pid was kept")
	}
}

func TestAcquireRunLeaseRejectsUnverifiableChild(t *testing.T) {
	dir := privateDir(t)
	cmd, _ := startSleepProcess(t)
	body := []byte(`{"schema":1,"pid":` + strconv.Itoa(cmd.Process.Pid) + `,"path":""}`)
	if err := os.WriteFile(filepath.Join(dir, runPIDFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRunLease(dir); err == nil {
		t.Fatal("unverifiable pid was leased")
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("unverifiable pid was killed")
	}
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); err != nil {
		t.Fatal("unverifiable run.pid was cleared")
	}
}

func startSleepProcess(t *testing.T) (*exec.Cmd, string) {
	t.Helper()
	image, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.CommandContext(context.Background(), image, "30") // #nosec G204,G702 -- local test helper.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd, image
}

func TestStartAdapterStopsChildWhenPIDCannotBeRecorded(t *testing.T) {
	dir := privateDir(t)
	image := filepath.Join(dir, "adapter")
	if err := os.WriteFile(image, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil { // #nosec G306 -- test helper adapter script.
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, runPIDFile), 0o700); err != nil {
		t.Fatal(err)
	}
	child, err := startAdapter(context.Background(), RunRequest{Directory: dir}, startOSProcess, image)
	if err == nil {
		t.Fatal("pid write failure was ignored")
	}
	if child != nil {
		t.Fatal("child returned after pid write failure")
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
