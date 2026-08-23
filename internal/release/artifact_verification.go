package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VerifyArtifactDirectory re-hashes every exact native artifact named by a
// parsed release manifest. Extra files such as the signed documents are
// ignored; every manifest-listed file is required and must be a regular,
// non-symlinked file with the signed length and SHA-256 digest.
func VerifyArtifactDirectory(directory string, manifest ReleaseManifest) error {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !validProductReleaseName(manifest.Release) || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > maxArtifacts {
		return errors.New("release artifact directory is invalid")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("release artifact directory is invalid")
	}
	for _, artifact := range manifest.Artifacts {
		if err := artifact.validate(manifest.Release); err != nil {
			return errors.New("release artifact verification failed")
		}
		name := strings.TrimPrefix(artifact.Path, manifest.Release+"/")
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path) // #nosec G703 -- the signed, validated manifest permits one fixed basename below the explicit directory.
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != artifact.Length {
			return errors.New("release artifact verification failed")
		}
		file, err := os.Open(path) // #nosec G304,G703 -- path is constrained above and verified again through the open descriptor.
		if err != nil {
			return errors.New("release artifact verification failed")
		}
		opened, statErr := file.Stat()
		hash := sha256.New()
		written, copyErr := io.Copy(hash, io.LimitReader(file, artifact.Length+1))
		closeErr := file.Close()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || written != artifact.Length || copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
			return errors.New("release artifact verification failed")
		}
	}
	return nil
}
