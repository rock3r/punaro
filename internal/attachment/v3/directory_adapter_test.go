package v3

import (
	"context"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
)

// senderDeliveryAuthorityShape is the narrow structural capability required by
// controller sender transitions. Keeping it local avoids an import cycle
// through the controller package while preventing the projection from losing
// its transfer-binding resolver.
type senderDeliveryAuthorityShape interface {
	ResolveTransferBinding(context.Context, [16]byte, [16]byte, uint64, [16]byte, uint64, [32]byte, time.Time) (attachmentv2.DirectoryTransferBinding, error)
}

var _ senderDeliveryAuthorityShape = directoryAuthorityView{}

func TestDirectoryAuthorityAdapterRejectsTransferBindingWithoutFreshProvider(t *testing.T) {
	t.Parallel()
	adapter := &DirectoryAuthorityAdapter{}
	if _, err := adapter.ResolveTransferBinding(context.Background(), testID(1), testID(2), 1, testID(3), 1, testHash(4), time.Unix(100, 0)); err == nil {
		t.Fatal("adapter resolved a transfer binding without a fresh directory provider")
	}
}
