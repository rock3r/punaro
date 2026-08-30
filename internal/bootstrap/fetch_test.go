package bootstrap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type unexpectedEOFReader struct {
	read bool
}

func (reader *unexpectedEOFReader) Read(body []byte) (int, error) {
	if reader.read {
		return 0, io.ErrUnexpectedEOF
	}
	reader.read = true
	return copy(body, "partial"), nil
}

type contextDeadlineReader struct {
	ctx context.Context
}

func (reader *contextDeadlineReader) Read([]byte) (int, error) {
	<-reader.ctx.Done()
	return 0, reader.ctx.Err()
}

func testHTTPFetcher(t *testing.T, transport http.RoundTripper) *httpFetcher {
	t.Helper()
	origin, err := url.Parse("https://release.example")
	if err != nil {
		t.Fatal(err)
	}
	return &httpFetcher{
		origin:         origin,
		client:         &http.Client{Transport: transport},
		attempts:       3,
		attemptTimeout: 20 * time.Millisecond,
		retryDelays:    []time.Duration{0, 0},
	}
}

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

func TestFetcherPreservesContextCancel(t *testing.T) {
	started := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(origin.Close)
	client, err := newFetcher(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, getErr := client.Get(ctx, punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
		errCh <- getErr
	}()
	<-started
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch err=%v", err)
	}
}

func TestHTTPFetcherRetriesConnectionResetAndReusesClient(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader("catalog")),
			ContentLength: int64(len("catalog")),
		}, nil
	}))
	body, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || string(body) != "catalog" {
		t.Fatalf("attempts=%d body=%q", attempts, body)
	}
}

func TestHTTPFetcherRetriesMidstreamTruncation(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Body:          io.NopCloser(&unexpectedEOFReader{}),
				ContentLength: int64(len("complete")),
			}, nil
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader("complete")),
			ContentLength: int64(len("complete")),
		}, nil
	}))
	body, err := client.Get(context.Background(), "v0.1.0/punaro-adapter-linux-amd64", 64)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || string(body) != "complete" {
		t.Fatalf("attempts=%d body=%q", attempts, body)
	}
}

func TestHTTPFetcherRetriesTransientStatus(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		status := http.StatusServiceUnavailable
		body := "retry"
		if attempts == 2 {
			status = http.StatusOK
			body = "catalog"
		}
		return &http.Response{
			StatusCode:    status,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}, nil
	}))
	body, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || string(body) != "catalog" {
		t.Fatalf("attempts=%d body=%q", attempts, body)
	}
}

func TestHTTPFetcherReusesConnectionAfterTransientStatus(t *testing.T) {
	var lock sync.Mutex
	var remotes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		lock.Lock()
		remotes = append(remotes, request.RemoteAddr)
		attempt := len(remotes)
		lock.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("retry"))
			return
		}
		_, _ = w.Write([]byte("catalog"))
	}))
	t.Cleanup(server.Close)
	client, err := newFetcher(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.retryDelays = []time.Duration{0, 0}
	body, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	defer lock.Unlock()
	if len(remotes) != 2 || remotes[0] != remotes[1] || string(body) != "catalog" {
		t.Fatalf("remotes=%v body=%q", remotes, body)
	}
}

func TestHTTPFetcherRetriesTimeoutThenExhausts(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		<-request.Context().Done()
		return nil, request.Context().Err()
	}))
	_, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err == nil || downloadFailureCategory(err) != downloadCategoryTimeout {
		t.Fatalf("err=%v category=%q", err, downloadFailureCategory(err))
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want=3", attempts)
	}
}

func TestHTTPFetcherClassifiesStalledResponseBodyAsTimeout(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(&contextDeadlineReader{ctx: request.Context()}),
			ContentLength: -1,
		}, nil
	}))
	_, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, 64)
	if err == nil || downloadFailureCategory(err) != downloadCategoryTimeout {
		t.Fatalf("err=%v category=%q", err, downloadFailureCategory(err))
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want=3", attempts)
	}
}

func TestHTTPFetcherDoesNotRetryPermanentStatusOrBoundFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		limit  int64
	}{
		{name: "permanent status", status: http.StatusNotFound, body: "not found", limit: 64},
		{name: "length bound", status: http.StatusOK, body: "too large", limit: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			client := testHTTPFetcher(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				attempts++
				return &http.Response{
					StatusCode:    test.status,
					Body:          io.NopCloser(strings.NewReader(test.body)),
					ContentLength: int64(len(test.body)),
				}, nil
			}))
			if _, err := client.Get(context.Background(), punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, test.limit); err == nil {
				t.Fatal("permanent failure accepted")
			}
			if attempts != 1 {
				t.Fatalf("attempts=%d want=1", attempts)
			}
		})
	}
}

func TestHTTPFetcherExhaustionIsContentFree(t *testing.T) {
	attempts := 0
	client := testHTTPFetcher(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	}))
	_, err := client.Get(context.Background(), "v0.1.0/private-artifact", 64)
	if err == nil || downloadFailureCategory(err) != downloadCategoryTransport {
		t.Fatalf("err=%v category=%q", err, downloadFailureCategory(err))
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want=3", attempts)
	}
	for _, forbidden := range []string{"release.example", "private-artifact", "connection reset"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaks %q: %v", forbidden, err)
		}
	}
}
