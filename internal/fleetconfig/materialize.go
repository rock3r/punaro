package fleetconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Materialize builds a deterministic, data-only v1 release from a source tree.
func Materialize(tree Tree, sourceCommit string) (Release, error) {
	commit, err := ParseCommitID(sourceCommit)
	if err != nil {
		return Release{}, err
	}
	if err := Validate(tree); err != nil {
		return Release{}, err
	}
	files := append([]File(nil), tree.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	manifest := make([]ManifestFile, 0, len(files))
	var total int64
	var digestPlain bytes.Buffer
	_, _ = digestPlain.WriteString("fleet-config-v1\n")
	_, _ = digestPlain.WriteString(commit)
	_, _ = digestPlain.WriteString("\n")
	for _, file := range files {
		sum := sha256.Sum256(file.Data)
		hexSum := hex.EncodeToString(sum[:])
		size := int64(len(file.Data))
		total += size
		manifest = append(manifest, ManifestFile{Path: file.Path, Size: size, SHA256: hexSum})
		_, _ = digestPlain.WriteString(file.Path)
		_ = digestPlain.WriteByte(0)
		_, _ = digestPlain.WriteString(strconv.FormatInt(size, 10))
		_ = digestPlain.WriteByte(0)
		_, _ = digestPlain.WriteString(hexSum)
		_, _ = digestPlain.WriteString("\n")
	}
	digestSum := sha256.Sum256(digestPlain.Bytes())
	digest := hex.EncodeToString(digestSum[:])
	archive, err := writeArchive(files)
	if err != nil {
		return Release{}, err
	}
	return Release{
		Schema:             SchemaV1,
		SourceCommit:       commit,
		Digest:             digest,
		Archive:            archive,
		Files:              manifest,
		SkillCount:         tree.SkillCount(),
		TotalBytes:         total,
		DataOnly:           true,
		ActivationCommands: 0,
		Destinations:       nil,
	}, nil
}

func writeArchive(files []File) ([]byte, error) {
	var raw bytes.Buffer
	gzipWriter := gzip.NewWriter(&raw)
	gzipWriter.Name = ""
	gzipWriter.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.OS = 3
	tarWriter := tar.NewWriter(gzipWriter)
	dirs := archiveDirectories(files)
	for _, dir := range dirs {
		if err := tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     dir,
			Mode:     0o755,
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		}); err != nil {
			return nil, errors.New("fleet-config archive failed")
		}
	}
	for _, file := range files {
		if err := tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     file.Path,
			Size:     int64(len(file.Data)),
			Mode:     0o644,
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		}); err != nil {
			return nil, errors.New("fleet-config archive failed")
		}
		if _, err := tarWriter.Write(file.Data); err != nil {
			return nil, errors.New("fleet-config archive failed")
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, errors.New("fleet-config archive failed")
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, errors.New("fleet-config archive failed")
	}
	if raw.Len() == 0 {
		return nil, errors.New("fleet-config archive failed")
	}
	return raw.Bytes(), nil
}

const maxArchiveBytes = 8 << 20

// ReadArchive unpacks a deterministic gzip+tar release into a validated tree.
func ReadArchive(archive []byte) (Tree, error) {
	if len(archive) == 0 || len(archive) > maxArchiveBytes {
		return Tree{}, errors.New("fleet-config archive is invalid")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return Tree{}, errors.New("fleet-config archive is invalid")
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	var files []File
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Tree{}, errors.New("fleet-config archive is invalid")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return Tree{}, errors.New("fleet-config archive contains a special file")
		}
		path, err := canonicalPath(header.Name)
		if err != nil {
			return Tree{}, errors.New("fleet-config archive path is invalid")
		}
		if header.Size < 0 || header.Size > MaxFileBytes {
			return Tree{}, errors.New("fleet-config file is too large")
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return Tree{}, errors.New("fleet-config archive is invalid")
		}
		total += int64(len(data))
		if total > MaxTotalBytes || len(files) >= MaxFiles {
			return Tree{}, errors.New("fleet-config source is too large")
		}
		files = append(files, File{Path: path, Data: data})
	}
	tree := Tree{Files: files}
	if err := Validate(tree); err != nil {
		return Tree{}, err
	}
	return tree, nil
}

func archiveDirectories(files []File) []string {
	seen := map[string]struct{}{}
	for _, file := range files {
		dir := file.Path
		for {
			slash := strings.LastIndex(dir, "/")
			if slash <= 0 {
				break
			}
			dir = dir[:slash]
			seen[dir] = struct{}{}
		}
	}
	dirs := make([]string, 0, len(seen))
	for dir := range seen {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}
