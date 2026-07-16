package v3

import (
	"context"
	"testing"
	"time"
)

func TestDirectoryAuthorityAdapterRejectsTransferBindingWithoutFreshProvider(t *testing.T) {
	t.Parallel()
	adapter := &DirectoryAuthorityAdapter{}
	if _, err := adapter.ResolveTransferBinding(context.Background(), testID(1), testID(2), 1, testID(3), 1, testHash(4), time.Unix(100, 0)); err == nil {
		t.Fatal("adapter resolved a transfer binding without a fresh directory provider")
	}
}
