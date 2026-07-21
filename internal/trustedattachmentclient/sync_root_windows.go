//go:build windows

package trustedattachmentclient

import "os"

// Windows does not expose a portable directory flush. The staged file itself
// is flushed before os.Root.Link creates the NTFS no-replace name; the link and
// cleanup remain safely contained by the opened root handle.
func syncRoot(*os.Root) error { return nil }
