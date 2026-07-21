//go:build !windows

package trustedattachment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBlobStoreArtifactLockSerializesProcessesAndHonorsCancellation(t *testing.T) {
	root := privateBlobRoot(t)
	first, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := first.LockArtifact(context.Background(), testArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := second.LockArtifact(ctx, testArtifactID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent artifact lock error=%v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	secondUnlock, err := second.LockArtifact(context.Background(), testArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondUnlock(); err != nil {
		t.Fatal(err)
	}
}
