//go:build windows

package canopiadapter

// Windows does not expose portable directory fsync through os.File. Event
// contents are still flushed before their atomic hard-link publication.
func syncDirectory(string) error { return nil }
