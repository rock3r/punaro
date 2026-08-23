//go:build windows

package canopi

// Windows does not expose portable directory fsync through os.File. State file
// contents are still flushed before atomic replacement.
func syncStateDirectory(string) error { return nil }
