package release

import "testing"

func FuzzParseReleaseManifest(f *testing.F) {
	f.Add([]byte(validReleaseManifestJSON()))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = ParseReleaseManifest(body)
	})
}

func FuzzParseCatalog(f *testing.F) {
	f.Add([]byte(validCatalogJSON()))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = ParseCatalog(body)
	})
}
