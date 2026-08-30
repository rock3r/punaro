package fleetconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestMaterializeIsDeterministicAndOmitsTrailer(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                    "# fleet\n",
		"skills/demo/SKILL.md":         skillMarkdown("demo", "A bounded demo skill."),
		"skills/demo/scripts/hint.txt": "data only\n",
		"projects/punaro/AGENTS.md":    "# punaro\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Materialize(tree, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Materialize(tree, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !bytes.Equal(first.Archive, second.Archive) {
		t.Fatal("identical input produced different release bytes")
	}
	if first.SourceCommit != testCommit || first.SkillCount != 1 || first.TotalBytes == 0 {
		t.Fatalf("manifest=%#v", first)
	}
	if len(first.Digest) != 64 {
		t.Fatalf("digest=%q", first.Digest)
	}
	for i := 0; i < len(first.Digest); i++ {
		c := first.Digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("digest=%q", first.Digest)
		}
	}
	if bytes.Contains(first.Archive, []byte(TrailerStart)) || bytes.Contains(first.Archive, []byte(TrailerEnd)) {
		t.Fatal("trailer text present in published archive")
	}
	if bytes.Contains(first.Archive, []byte("/bin/sh")) && bytes.Contains(first.Archive, []byte("post-install")) {
		t.Fatal("activation metadata leaked into archive")
	}
	seenAgents := false
	for _, file := range first.Files {
		if file.Path == "AGENTS.md" {
			seenAgents = true
		}
		if strings.Contains(file.Path, "\\") || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") {
			t.Fatalf("unsafe path %q", file.Path)
		}
		if file.Size <= 0 || len(file.SHA256) != 64 {
			t.Fatalf("file=%#v", file)
		}
	}
	if !seenAgents {
		t.Fatal("AGENTS.md missing from manifest")
	}
}

func TestMaterializeClassifiesReleaseAsDataOnly(t *testing.T) {
	t.Parallel()
	tree := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo skill."))},
		{Path: "skills/demo/scripts/run.sh", Data: []byte("#!/bin/sh\necho hi\n")},
	}}
	release, err := Materialize(tree, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if !release.DataOnly {
		t.Fatal("scripts/ caused the release to leave data-only classification")
	}
	if release.ActivationCommands != 0 || len(release.Destinations) != 0 {
		t.Fatalf("activation leaked: %#v", release)
	}
}

func TestMaterializeRejectsInvalidCommit(t *testing.T) {
	t.Parallel()
	tree := Tree{Files: []File{{Path: "AGENTS.md", Data: []byte("# fleet\n")}}}
	if _, err := Materialize(tree, "main"); err == nil {
		t.Fatal("materialized a branch name")
	}
}

func TestMaterializeArchivesHundredByteDirectory(t *testing.T) {
	t.Parallel()
	dir := strings.Repeat("c", 100)
	tree := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo skill."))},
		{Path: "skills/demo/" + dir + "/x", Data: []byte("data\n")},
	}}
	if _, err := Materialize(tree, testCommit); err != nil {
		t.Fatal(err)
	}
}

func TestReadArchiveRoundTripsMaterialize(t *testing.T) {
	t.Parallel()
	tree := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo skill."))},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
	}}
	release, err := Materialize(tree, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadArchive(release.Archive)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Materialize(got, testCommit)
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != release.Digest {
		t.Fatalf("unpacked digest=%s want %s", again.Digest, release.Digest)
	}
}

func TestReadArchiveRejectsSymlink(t *testing.T) {
	t.Parallel()
	var raw bytes.Buffer
	gzipWriter := gzip.NewWriter(&raw)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "AGENTS.md", Linkname: "/etc/passwd", Mode: 0o644, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArchive(raw.Bytes()); err == nil {
		t.Fatal("accepted a symlink archive entry")
	}
}
