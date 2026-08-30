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
	origin         *url.URL
	client         *http.Client
	attempts       int
	attemptTimeout time.Duration
	retryDelays    []time.Duration
}

type downloadCategory string

const (
	downloadCategoryCanceled  downloadCategory = "canceled"
	downloadCategoryHTTP      downloadCategory = "http_status"
	downloadCategoryLength    downloadCategory = "length"
	downloadCategoryPolicy    downloadCategory = "policy"
	downloadCategoryTimeout   downloadCategory = "timeout"
	downloadCategoryTransport downloadCategory = "transport"

	defaultDownloadAttempts       = 3
	defaultDownloadAttemptTimeout = 60 * time.Second
)

var (
	defaultDownloadRetryDelays = []time.Duration{250 * time.Millisecond, time.Second}
	errReleaseDownloadPolicy   = errors.New("release download policy rejected")
)

type downloadFailure struct {
	phase     string
	category  downloadCategory
	cause     error
	retryable bool
}

func (failure *downloadFailure) Error() string {
	if failure.phase != "" {
		return "release download failed: phase=" + failure.phase + " category=" + string(failure.category)
	}
	return "release download failed: category=" + string(failure.category)
}

func (failure *downloadFailure) Unwrap() error {
	if errors.Is(failure.cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(failure.cause, context.Canceled) {
		return context.Canceled
	}
	return nil
}

func downloadFailureCategory(err error) downloadCategory {
	var failure *downloadFailure
	if errors.As(err, &failure) {
		return failure.category
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return downloadCategoryTimeout
	}
	if errors.Is(err, context.Canceled) {
		return downloadCategoryCanceled
	}
	return downloadCategoryTransport
}

func withDownloadPhase(err error, phase string) error {
	if err == nil {
		return nil
	}
	var failure *downloadFailure
	if errors.As(err, &failure) {
		return &downloadFailure{phase: phase, category: failure.category, cause: failure.cause, retryable: failure.retryable}
	}
	return &downloadFailure{phase: phase, category: downloadFailureCategory(err), cause: err}
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
			CheckRedirect: boundedHTTPSRedirects,
		},
		attempts:       defaultDownloadAttempts,
		attemptTimeout: defaultDownloadAttemptTimeout,
		retryDelays:    append([]time.Duration(nil), defaultDownloadRetryDelays...),
	}, nil
}

func (transport *httpFetcher) Get(ctx context.Context, relative string, limit int64) ([]byte, error) {
	if err := punarorelease.ValidateRelativePath(relative); err != nil {
		return nil, &downloadFailure{category: downloadCategoryPolicy, cause: err}
	}
	if limit < 1 {
		return nil, &downloadFailure{category: downloadCategoryPolicy, cause: errors.New("release download is invalid")}
	}
	target := strings.TrimRight(transport.origin.String(), "/") + "/" + relative
	if ctx == nil {
		ctx = context.Background()
	}
	attempts := transport.attempts
	if attempts < 1 {
		attempts = defaultDownloadAttempts
	}
	for attempt := 0; attempt < attempts; attempt++ {
		body, err := transport.getOnce(ctx, target, limit)
		if err == nil {
			return body, nil
		}
		var failure *downloadFailure
		if !errors.As(err, &failure) || !failure.retryable || attempt+1 == attempts {
			return nil, err
		}
		if err := waitForRetry(ctx, transport.retryDelay(attempt)); err != nil {
			return nil, &downloadFailure{category: downloadFailureCategory(err), cause: err}
		}
	}
	return nil, &downloadFailure{category: downloadCategoryTransport, cause: errors.New("release download attempts exhausted")}
}

func (transport *httpFetcher) getOnce(parent context.Context, target string, limit int64) ([]byte, error) {
	attemptTimeout := transport.attemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = defaultDownloadAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(parent, attemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, &downloadFailure{category: downloadCategoryPolicy, cause: err}
	}
	response, err := transport.client.Do(request) // #nosec G107 -- target is origin plus a validated relative path.
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if parent.Err() != nil {
			return nil, &downloadFailure{category: downloadFailureCategory(parent.Err()), cause: parent.Err()}
		}
		if errors.Is(err, errReleaseDownloadPolicy) {
			return nil, &downloadFailure{category: downloadCategoryPolicy, cause: err}
		}
		category := downloadCategoryTransport
		if errors.Is(err, context.DeadlineExceeded) {
			category = downloadCategoryTimeout
		}
		return nil, &downloadFailure{category: category, cause: err, retryable: true}
	}
	if response.StatusCode != http.StatusOK {
		retryable := transientHTTPStatus(response.StatusCode)
		if retryable {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		}
		_ = response.Body.Close()
		return nil, &downloadFailure{category: downloadCategoryHTTP, cause: errors.New("release download returned an invalid status"), retryable: retryable}
	}
	if response.ContentLength > limit {
		_ = response.Body.Close()
		return nil, &downloadFailure{category: downloadCategoryLength, cause: errors.New("release download exceeds bound")}
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		category := downloadFailureCategory(readErr)
		cause := readErr
		retryable := true
		if parent.Err() != nil {
			category = downloadFailureCategory(parent.Err())
			cause = parent.Err()
			retryable = false
		} else if ctx.Err() != nil {
			category = downloadFailureCategory(ctx.Err())
			cause = ctx.Err()
		}
		return nil, &downloadFailure{category: category, cause: cause, retryable: retryable}
	}
	if closeErr != nil {
		return nil, &downloadFailure{category: downloadCategoryTransport, cause: closeErr, retryable: true}
	}
	if int64(len(body)) > limit {
		return nil, &downloadFailure{category: downloadCategoryLength, cause: errors.New("release download exceeds bound")}
	}
	return body, nil
}

func (transport *httpFetcher) retryDelay(attempt int) time.Duration {
	if attempt < len(transport.retryDelays) {
		return transport.retryDelays[attempt]
	}
	if len(transport.retryDelays) > 0 {
		return transport.retryDelays[len(transport.retryDelays)-1]
	}
	return 0
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func transientHTTPStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func boundedHTTPSRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errReleaseDownloadPolicy
	}
	if req.URL.Scheme == "https" {
		return nil
	}
	if req.URL.Scheme == "http" && localhostHost(req.URL.Hostname()) {
		return nil
	}
	return errReleaseDownloadPolicy
}

func localhostHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
