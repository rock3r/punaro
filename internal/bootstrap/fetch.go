package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

type fetcher interface {
	Get(ctx context.Context, relative string, limit int64) ([]byte, error)
}

type httpFetcher struct {
	origin *url.URL
	client *http.Client
}

func newFetcher(origin string) (*httpFetcher, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("release origin is invalid")
	}
	if strings.Contains(parsed.Path, "..") || strings.Contains(origin, "..") {
		return nil, errors.New("release origin is invalid")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !localhostHost(parsed.Hostname()) {
			return nil, errors.New("release origin is invalid")
		}
	default:
		return nil, errors.New("release origin is invalid")
	}
	return &httpFetcher{
		origin: parsed,
		client: &http.Client{
			Timeout:       60 * time.Second,
			CheckRedirect: boundedHTTPSRedirects,
		},
	}, nil
}

func (transport *httpFetcher) Get(ctx context.Context, relative string, limit int64) ([]byte, error) {
	if err := punarorelease.ValidateRelativePath(relative); err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, errors.New("release download is invalid")
	}
	target := strings.TrimRight(transport.origin.String(), "/") + "/" + relative
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("release download failed")
	}
	response, err := transport.client.Do(request) // #nosec G107 -- target is origin plus a validated relative path.
	if err != nil {
		return nil, errors.New("release download failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("release download failed")
	}
	if response.ContentLength > limit {
		return nil, errors.New("release download exceeds bound")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errors.New("release download failed")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("release download exceeds bound")
	}
	return body, nil
}

func boundedHTTPSRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("release download failed")
	}
	if req.URL.Scheme == "https" {
		return nil
	}
	if req.URL.Scheme == "http" && localhostHost(req.URL.Hostname()) {
		return nil
	}
	return errors.New("release download failed")
}

func localhostHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
