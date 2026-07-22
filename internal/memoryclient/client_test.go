package memoryclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testProject      = "11111111-1111-4111-8111-111111111111"
	testItem         = "22222222-2222-4222-8222-222222222222"
	testProposal     = "33333333-3333-4333-8333-333333333333"
	testKey          = "44444444-4444-4444-8444-444444444444"
	testInstallation = "55555555-5555-4555-8555-555555555555"
	testTimeline     = "66666666-6666-4666-8666-666666666666"
	testScope        = "77777777-7777-4777-8777-777777777777"
	testAuthor       = "88888888-8888-4888-8888-888888888888"
	testProposalETag = `"p1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`
	testCredential   = "11111111-1111-4111-8111-111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var testMemoryETag = memoryETagFor(testItem, 1)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string, headers map[string]string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	for name, value := range headers {
		h.Set(name, value)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func jsonETag(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }

func TestNewRejectsUnsafeOriginCredentialAndProxy(t *testing.T) {
	for _, origin := range []string{"", "ftp://punaro.test", "http://punaro.test", "https://u:p@punaro.test", "https://punaro.test/path", "https://punaro.test?q=1", "https://punaro.test#x"} {
		if _, err := New(origin, testCredential); err == nil {
			t.Fatalf("origin %q accepted", origin)
		}
	}
	for _, credential := range []string{"", "two words", "line\nbreak", "11111111-1111-4111-8111-111111111111.short"} {
		if _, err := New("https://punaro.test", credential); err == nil {
			t.Fatalf("credential %q accepted", credential)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	client, err := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("proxy was retained")
	}
	if !client.http.Transport.(*http.Transport).DisableKeepAlives {
		t.Fatal("connection reuse was retained")
	}
	protocols := client.http.Transport.(*http.Transport).Protocols
	if protocols == nil || !protocols.HTTP1() || protocols.HTTP2() {
		t.Fatal("transport is not constrained to HTTP/1")
	}
}

func TestClientTranslatesEveryRouteAndPreservesMutationCoordinates(t *testing.T) {
	type observed struct{ method, path, body, key, match string }
	var mu sync.Mutex
	var requests []observed
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		bodyless := r.Method == http.MethodGet || r.Method == http.MethodDelete || strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/reject")
		if bodyless && (r.Body != nil && r.Body != http.NoBody || r.ContentLength != 0) {
			t.Fatal("bodyless request gained a body")
		}
		if !bodyless && (r.Body == nil || r.Body == http.NoBody || r.GetBody != nil) {
			t.Fatal("request body is transparently replayable")
		}
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		mu.Lock()
		requests = append(requests, observed{r.Method, r.URL.Path, string(body), r.Header.Get("Idempotency-Key"), r.Header.Get("If-Match")})
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testCredential || r.URL.Host != "punaro.test" {
			t.Fatalf("authority headers=%v url=%s", r.Header, r.URL)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/resolve":
			return response(200, `{"identity_id":"`+testInstallation+`","project_id":"`+testProject+`","kind":"git_remote"}`, nil), nil
		case strings.HasSuffix(r.URL.Path, "/search"):
			return response(200, `{"results":[],"more":false}`, nil), nil
		case strings.HasSuffix(r.URL.Path, "/brief"):
			return response(200, briefResponse(), nil), nil
		case strings.HasSuffix(r.URL.Path, "/changes"):
			return response(200, `{"changes":[],"cursor":{"installation_id":"`+testInstallation+`","timeline_id":"`+testTimeline+`","change_sequence":0},"more":false}`, nil), nil
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/memory-proposals/"):
			return response(200, proposalResponse(), map[string]string{"ETag": testProposalETag}), nil
		case strings.Contains(r.URL.Path, "/memory-proposals"):
			status := 200
			state := "rejected"
			mutations := ""
			if strings.HasSuffix(r.URL.Path, "memory-proposals") {
				status = 201
				state = "pending"
			} else if strings.HasSuffix(r.URL.Path, "/approve") {
				state = "approved"
				mutations = `,"mutations":[{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1}]`
			}
			return response(status, `{"proposal_id":"`+testProposal+`","state":"`+state+`","etag":`+jsonETag(testProposalETag)+mutations+`}`, map[string]string{"ETag": testProposalETag}), nil
		case r.Method == http.MethodGet:
			return response(200, memoryResponse(), map[string]string{"ETag": testMemoryETag}), nil
		default:
			status := 200
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/memories") {
				status = 201
			}
			revision := 2
			if status == 201 {
				revision = 1
			}
			etag := memoryETagFor(testItem, int64(revision))
			state := "active"
			if strings.HasSuffix(r.URL.Path, "/state") && strings.Contains(string(body), `"archived":true`) {
				state = "archived"
			}
			body := `{"item_id":"` + testItem + `","revision":` + fmt.Sprint(revision) + `,"etag":` + jsonETag(etag) + `,"state":"` + state + `","change_sequence":4}`
			if r.Method == http.MethodDelete {
				etag = ""
				body = `{"item_id":"` + testItem + `","revision":2,"change_sequence":4}`
			}
			headers := map[string]string{}
			if etag != "" {
				headers["ETag"] = etag
			}
			return response(status, body, headers), nil
		}
	})
	client, err := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := []func() error{
		func() error { _, err := client.Resolve(ctx, "git_remote", "github.com/Owner/Repo"); return err },
		func() error { _, err := client.Get(ctx, testProject, testItem); return err },
		func() error { _, err := client.Search(ctx, testProject, "needle", 3); return err },
		func() error { _, err := client.Brief(ctx, testProject, "needle"); return err },
		func() error { _, err := client.Changes(ctx, testProject, nil, 10); return err },
		func() error {
			_, err := client.Create(ctx, testProject, testKey, []byte(`{"logical_key":"","kind":"decision","trust":"curated","document":{}}`))
			return err
		},
		func() error {
			_, err := client.Update(ctx, testProject, testItem, testKey, testMemoryETag, []byte(`{"logical_key":"","kind":"decision","trust":"curated","document":{}}`))
			return err
		},
		func() error {
			_, err := client.SetArchived(ctx, testProject, testItem, testKey, testMemoryETag, true)
			return err
		},
		func() error { _, err := client.Delete(ctx, testProject, testItem, testKey, testMemoryETag); return err },
		func() error {
			_, err := client.CreateProposal(ctx, testProject, testKey, []byte(`{"action":"create","steps":[{"operation":"create","kind":"decision","trust":"curated","document":{}}],"evidence":[]}`))
			return err
		},
		func() error { _, err := client.GetProposal(ctx, testProject, testProposal); return err },
		func() error {
			_, err := client.DecideProposal(ctx, testProject, testProposal, testKey, testProposalETag, true)
			return err
		},
		func() error {
			_, err := client.DecideProposal(ctx, testProject, testProposal, testKey, testProposalETag, false)
			return err
		},
	}
	for index, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("call %d: %v", index, err)
		}
	}
	wantPaths := []string{"/v1/projects/resolve", "/v1/projects/" + testProject + "/memories/" + testItem, "/v1/projects/" + testProject + "/memories/search", "/v1/projects/" + testProject + "/memories/brief", "/v1/projects/" + testProject + "/memories/changes", "/v1/projects/" + testProject + "/memories", "/v1/projects/" + testProject + "/memories/" + testItem, "/v1/projects/" + testProject + "/memories/" + testItem + "/state", "/v1/projects/" + testProject + "/memories/" + testItem, "/v1/projects/" + testProject + "/memory-proposals", "/v1/projects/" + testProject + "/memory-proposals/" + testProposal, "/v1/projects/" + testProject + "/memory-proposals/" + testProposal + "/approve", "/v1/projects/" + testProject + "/memory-proposals/" + testProposal + "/reject"}
	if len(requests) != len(wantPaths) {
		t.Fatalf("requests=%d", len(requests))
	}
	for i := range requests {
		if requests[i].path != wantPaths[i] {
			t.Fatalf("request %d path=%q want=%q", i, requests[i].path, wantPaths[i])
		}
	}
	for _, index := range []int{5, 6, 7, 8, 9, 11, 12} {
		if requests[index].key != testKey {
			t.Fatalf("request %d key=%q", index, requests[index].key)
		}
	}
	for _, index := range []int{6, 7, 8} {
		if requests[index].match != testMemoryETag {
			t.Fatalf("request %d match=%q", index, requests[index].match)
		}
	}
	for _, index := range []int{11, 12} {
		if requests[index].match != testProposalETag {
			t.Fatalf("request %d match=%q", index, requests[index].match)
		}
	}
}

func memoryResponse() string {
	return `{"item_id":"` + testItem + `","scope_id":"` + testScope + `","project_id":"` + testProject + `","kind":"decision","state":"active","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"document":{},"content_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","author_id":"` + testAuthor + `","created_at":"2026-01-01T00:00:00Z","revision_at":"2026-01-01T00:00:00Z","change_sequence":1}`
}

func briefResponse() string {
	context := `{"warning":"` + promptBriefWarning + `","budget_version":"prompt-brief-v1","cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":0},"retrieval_mode":"lexical","semantic_status":"not_configured","entries":[]}`
	return `{"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":0},"project_id":"` + testProject + `","project_content_generation":1,"project_acl_generation":1,"retrieval_mode":"lexical","semantic_status":"not_configured","budget_version":"prompt-brief-v1","entries":[],"context":` + jsonETag(context) + `,"truncated":false}`
}

func proposalResponse() string {
	return `{"proposal_id":"` + testProposal + `","scope_id":"` + testScope + `","project_id":"` + testProject + `","action":"create","state":"pending","etag":` + jsonETag(testProposalETag) + `,"proposed_by":"` + testAuthor + `","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","steps":[{"ordinal":0,"operation":"create","kind":"decision","trust":"curated","document":{}}],"evidence":[]}`
}

func TestClientRejectsRedirectsMalformedResponsesAndClassifiesSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		retry  bool
		code   string
	}{
		{401, `{"error":"secret body"}`, false, ""},
		{409, `{"error":"x","code":"stale_etag"}`, false, "stale_etag"},
		{429, `{"error":"x","code":"proposal_capacity"}`, true, "proposal_capacity"},
		{503, `{"error":"sql secret","code":"maintenance"}`, true, "maintenance"},
	} {
		client, _ := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(tc.status, tc.body, map[string]string{"Retry-After": "2"}), nil
		})})
		_, err := client.Get(context.Background(), testProject, testItem)
		var requestErr *RequestError
		if !errors.As(err, &requestErr) || requestErr.Retryable != tc.retry || requestErr.Code != tc.code || strings.Contains(err.Error(), "secret") || requestErr.RetryAfter > 2*time.Second {
			t.Fatalf("status=%d err=%#v", tc.status, err)
		}
	}
	client, _ := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(302, "", map[string]string{"Location": "https://evil.test"}), nil
	})})
	if _, err := client.Get(context.Background(), testProject, testItem); err == nil {
		t.Fatal("redirect accepted")
	}
	client, _ = newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, `{"item_id":"`+testItem+`","project_id":"`+testProject+`","etag":"wrong","document":{}}`, map[string]string{"ETag": testMemoryETag}), nil
	})})
	if _, err := client.Get(context.Background(), testProject, testItem); err == nil {
		t.Fatal("mismatched ETag accepted")
	}
}

func TestClientIsConcurrentAndTransportFailureWritesNoState(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network secret https://punaro.test/path")
	})
	client, _ := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: transport})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Create(context.Background(), testProject, testKey, []byte(`{"logical_key":"","kind":"decision","trust":"curated","document":{}}`))
			var requestErr *RequestError
			if !errors.As(err, &requestErr) || !requestErr.Retryable || strings.Contains(err.Error(), "punaro.test") {
				t.Errorf("err=%v", err)
			}
		}()
	}
	wg.Wait()
}

func TestClientDoesNotReplayAReusedConnectionFailure(t *testing.T) {
	var dials atomic.Int32
	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			attempt := dials.Add(1)
			clientSide, serverSide := net.Pipe()
			go func() {
				defer func() { _ = serverSide.Close() }()
				reader := bufio.NewReader(serverSide)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				if attempt > 2 {
					writePipeResponse(serverSide, memoryResponse(), testMemoryETag)
					return
				}
				if attempt == 1 {
					writePipeResponse(serverSide, `{"identity_id":"`+testInstallation+`","project_id":"`+testProject+`","kind":"git_remote"}`, "")
				}
				// Close without a response. net/http may transparently redial only
				// when it considers the request eligible for replay.
			}()
			return clientSide, nil
		},
	}
	client, err := newWithHTTPClient("https://punaro.test", testCredential, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resolve(context.Background(), "git_remote", "github.com/Owner/Repo"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), testProject, testItem); err == nil {
		t.Fatal("reused-connection failure was hidden")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("wire attempts=%d want=2 (one per explicit operation)", got)
	}
}

func writePipeResponse(writer io.Writer, body, etag string) {
	if etag == "" {
		_, _ = fmt.Fprintf(writer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		return
	}
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nETag: %s\r\nContent-Length: %d\r\n\r\n%s", etag, len(body), body)
}
