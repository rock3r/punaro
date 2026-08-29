package bootstrap

import (
	"errors"
	"runtime"
	"testing"
)

func TestPidsMatchingImageRejectsEmptyPath(t *testing.T) {
	if _, err := pidsMatchingImage(""); !errors.Is(err, errProcessImageUnknown) {
		t.Fatalf("empty path: %v", err)
	}
}

func TestPidsMatchingImageFindsCopiedImage(t *testing.T) {
	dir := privateDir(t)
	cmd, image := startUniqueSleepProcess(t, dir)
	waitMatchingImage(t, cmd.Process.Pid, image)
}

func TestSameImagePathFoldsWindowsDriveCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows path fold")
	}
	if !sameImagePath(`C:\Punaro\adapter.exe`, `c:\punaro\ADAPTER.exe`) {
		t.Fatal("windows image paths must match case-insensitively")
	}
}
