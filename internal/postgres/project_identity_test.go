package postgres

import (
	"strings"
	"testing"
)

func TestNormalizeProjectIdentityLocator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind ProjectIdentityKind
		raw  string
		want string
	}{
		{name: "https strips credentials and suffix", kind: ProjectIdentityGitRemote, raw: "https://user:secret@GitHub.COM/Owner/Repo.git", want: "github.com/Owner/Repo"}, // #nosec G101 -- deliberate fake normalization fixture.
		{name: "ssh and scp converge", kind: ProjectIdentityGitRemote, raw: "git@github.com:Owner/Repo.git", want: "github.com/Owner/Repo"},
		{name: "default ssh port is omitted", kind: ProjectIdentityGitRemote, raw: "ssh://git@Example.COM:22/Group/Repo.git", want: "example.com/Group/Repo"},
		{name: "nondefault port is retained", kind: ProjectIdentityGitRemote, raw: "ssh://git@Example.COM:2222/Group/Repo.git", want: "example.com:2222/Group/Repo"},
		{name: "unknown host path case is preserved", kind: ProjectIdentityGitRemote, raw: "https://git.example/Case/Repo.GIT", want: "git.example/Case/Repo.GIT"},
		{name: "operator alias is case folded", kind: ProjectIdentityOperatorAlias, raw: "  Release Train  ", want: "release train"},
		{name: "local git id is canonical", kind: ProjectIdentityLocalGit, raw: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", want: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
		{name: "workspace id is canonical", kind: ProjectIdentityWorkspace, raw: "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB", want: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeProjectIdentityLocator(test.kind, test.raw)
			if err != nil || got != test.want {
				t.Fatalf("normalized=%q err=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestNormalizeProjectIdentityLocatorRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	longRemote := "https://example.com/" + strings.Repeat("a", maxProjectLocatorBytes)
	for name, input := range map[string]struct {
		kind ProjectIdentityKind
		raw  string
	}{
		"unknown kind":        {kind: "guess", raw: "https://example.com/a/b"},
		"empty":               {kind: ProjectIdentityGitRemote},
		"file URL":            {kind: ProjectIdentityGitRemote, raw: "file:///tmp/repo"},
		"relative path":       {kind: ProjectIdentityGitRemote, raw: "../repo"},
		"missing repository":  {kind: ProjectIdentityGitRemote, raw: "https://example.com"},
		"query":               {kind: ProjectIdentityGitRemote, raw: "https://example.com/a/b?token=secret"},
		"fragment":            {kind: ProjectIdentityGitRemote, raw: "https://example.com/a/b#main"},
		"explicit empty port": {kind: ProjectIdentityGitRemote, raw: "https://example.com:/a/b"},
		"escaped path":        {kind: ProjectIdentityGitRemote, raw: "https://example.com/a/%2e%2e/b"},
		"path traversal":      {kind: ProjectIdentityGitRemote, raw: "git@example.com:a/../b"},
		"control":             {kind: ProjectIdentityGitRemote, raw: "https://example.com/a/\nb"},
		"oversized":           {kind: ProjectIdentityGitRemote, raw: longRemote},
		"bad local id":        {kind: ProjectIdentityLocalGit, raw: "friendly-name"},
		"bad workspace id":    {kind: ProjectIdentityWorkspace, raw: "/tmp/repo"},
		"bad alias":           {kind: ProjectIdentityOperatorAlias, raw: "\x00operator"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got, err := NormalizeProjectIdentityLocator(input.kind, input.raw); err == nil {
				t.Fatalf("accepted normalized locator %q", got)
			}
		})
	}
}
