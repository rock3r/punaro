package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestNewFetcherRejectsNonLocalHTTP(t *testing.T) {
	if _, err := newFetcher("http://example.com/releases"); err == nil {
		t.Fatal("cleartext remote origin accepted")
	}
}

func TestNewFetcherRejectsUserinfoQueryAndParent(t *testing.T) {
	for _, origin := range []string{
		"https://user:pass@github.com/rock3r/punaro/releases/download",
		"https://github.com/rock3r/punaro/releases/download?x=1",
		"https://github.com/rock3r/punaro/releases/download#frag",
		"https://github.com/rock3r/punaro/releases/download/../evil",
		"ftp://127.0.0.1/releases",
	} {
		if _, err := newFetcher(origin); err == nil {
			t.Fatalf("invalid origin accepted: %s", origin)
		}
	}
}

func TestHTTPFetcherRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	t.Cleanup(server.Close)
	client, err := newFetcher(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 4); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestHTTPFetcherRejectsInvalidRelativePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("invalid relative path was fetched")
	}))
	t.Cleanup(server.Close)
	client, err := newFetcher(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "../evil/punaro-catalog.json", 64); err == nil {
		t.Fatal("parent relative path accepted")
	}
	if _, err := client.Get(context.Background(), "latest/punaro-release.json", 64); err == nil {
		t.Fatal("latest pointer accepted")
	}
}

func TestHTTPFetcherRejectsNonLocalHTTPRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/steal", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client, err := newFetcher(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64); err == nil {
		t.Fatal("non-local HTTP redirect accepted")
	}
}

func TestHTTPFetcherFollowsLocalhostRedirect(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(final.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.TrimRight(final.URL, "/")+"/"+punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	client, err := newFetcher(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body=%q", body)
	}
}
