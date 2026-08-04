//go:build memory_onboarding_e2e

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const (
	e2eOwnerDSNEnv = "PUNARO_E2E_POSTGRES_OWNER_DSN"
	e2eAppDSNEnv   = "PUNARO_E2E_POSTGRES_APP_DSN"
)

func TestMemoryOnboardingE2EImageIncludesInstallerAssets(t *testing.T) {
	t.Helper()
	root := e2eRepositoryRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile")) // #nosec G304 -- test reads the checked-out Dockerfile.
	if err != nil {
		t.Fatal("E2E image Dockerfile is unavailable")
	}
	for _, expected := range []string{
		"COPY scripts/install-client.sh scripts/install-adapter.sh ./scripts/",
		"COPY deploy/systemd/user/punaro-adapter.service ./deploy/systemd/user/",
	} {
		if !strings.Contains(string(dockerfile), expected) {
			t.Fatal("E2E image does not include required installer assets")
		}
	}
	ignored, err := os.ReadFile(filepath.Join(root, ".dockerignore")) // #nosec G304 -- test reads the checked-out build-context policy.
	if err != nil {
		t.Fatal("E2E image ignore policy is unavailable")
	}
	for _, expected := range []string{"!scripts/install-client.sh", "!scripts/install-adapter.sh", "!deploy/systemd/user/punaro-adapter.service"} {
		if !strings.Contains(string(ignored), expected) {
			t.Fatal("E2E image build context excludes required installer assets")
		}
	}
}

func TestMemoryOnboardingE2EImageUsesPrivateFixtureHome(t *testing.T) {
	t.Helper()
	root := e2eRepositoryRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile")) // #nosec G304 -- test reads the checked-out Dockerfile.
	if err != nil {
		t.Fatal("E2E image Dockerfile is unavailable")
	}
	if !strings.Contains(string(dockerfile), "chown 65532:65532 /home/punaro") {
		t.Fatal("E2E image does not create an owned private fixture home")
	}
	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.memory-onboarding-e2e.yml")) // #nosec G304 -- test reads the checked-out Compose manifest.
	if err != nil {
		t.Fatal("E2E Compose manifest is unavailable")
	}
	for _, expected := range []string{"HOME: /home/punaro", "TMPDIR: /home/punaro/tmp"} {
		if !strings.Contains(string(compose), expected) {
			t.Fatal("E2E Compose manifest does not use the protected fixture home")
		}
	}
}

func TestMemoryOnboardingE2EImageIncludesGuardSources(t *testing.T) {
	t.Helper()
	root := e2eRepositoryRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile")) // #nosec G304 -- test reads the checked-out Dockerfile.
	if err != nil {
		t.Fatal("E2E image Dockerfile is unavailable")
	}
	for _, expected := range []string{"COPY Dockerfile .dockerignore docker-compose.memory-onboarding-e2e.yml ./", "COPY scripts/verify-deployment-files.sh ./scripts/"} {
		if !strings.Contains(string(dockerfile), expected) {
			t.Fatal("E2E image does not include onboarding guard sources")
		}
	}
	ignored, err := os.ReadFile(filepath.Join(root, ".dockerignore")) // #nosec G304 -- test reads the checked-out build-context policy.
	if err != nil {
		t.Fatal("E2E image ignore policy is unavailable")
	}
	for _, expected := range []string{"!Dockerfile", "!.dockerignore", "!docker-compose.memory-onboarding-e2e.yml", "!scripts/verify-deployment-files.sh"} {
		if !strings.Contains(string(ignored), expected) {
			t.Fatal("E2E image build context excludes onboarding guard sources")
		}
	}
}

func TestMemoryOnboardingDeploymentLintKeepsDockerlessGuard(t *testing.T) {
	t.Helper()
	root := e2eRepositoryRoot(t)
	verifier, err := os.ReadFile(filepath.Join(root, "scripts", "verify-deployment-files.sh")) // #nosec G304 -- test reads the checked-out verifier.
	if err != nil {
		t.Fatal("deployment verifier is unavailable")
	}
	guard := "if command -v docker >/dev/null 2>&1; then"
	compose := "docker compose -f docker-compose.memory-onboarding-e2e.yml config --quiet"
	if !strings.Contains(string(verifier), guard) || !strings.Contains(string(verifier), compose) {
		t.Fatal("deployment verifier does not guard optional Docker Compose validation")
	}
}

func TestMemoryOnboardingE2EComposeRunsAllOnboardingChecks(t *testing.T) {
	t.Helper()
	root := e2eRepositoryRoot(t)
	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.memory-onboarding-e2e.yml")) // #nosec G304 -- test reads the checked-out Compose manifest.
	if err != nil {
		t.Fatal("E2E Compose manifest is unavailable")
	}
	if !strings.Contains(string(compose), "-run") || !strings.Contains(string(compose), "MemoryOnboarding") || !strings.Contains(string(compose), "InstalledMemoryClientOnboardingE2E") {
		t.Fatal("E2E Compose manifest excludes onboarding guard tests")
	}
}

func TestInstalledMemoryClientOnboardingE2E(t *testing.T) {
	ownerDSN, appDSN := os.Getenv(e2eOwnerDSNEnv), os.Getenv(e2eAppDSNEnv)
	if ownerDSN == "" || appDSN == "" {
		t.Skip("requires disposable PostgreSQL Compose service")
	}

	fixture := t.TempDir()
	ownerDSNFile := writePrivateFile(t, fixture, "owner.dsn", ownerDSN)
	appDSNFile := writePrivateFile(t, fixture, "app.dsn", appDSN)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if _, err := punaropostgres.Migrate(ctx, punaropostgres.Config{DSNFile: ownerDSNFile}); err != nil {
		t.Fatal("disposable relay migration failed")
	}

	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if err != nil {
		t.Fatal("disposable relay administration failed")
	}
	defer func() { _ = admin.Close() }()
	owner, err := admin.BootstrapOwner(ctx, "memory E2E owner")
	if err != nil {
		t.Fatal("disposable relay owner bootstrap failed")
	}
	application, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: appDSNFile})
	if err != nil {
		t.Fatal("disposable relay application setup failed")
	}
	defer func() { _ = application.Close() }()
	project, err := application.CreateProject(ctx, punaropostgres.ProjectCreate{PrincipalID: owner.ID, IdempotencyKey: uuid.NewString(), DisplayName: "memory E2E authorized project"})
	if err != nil {
		t.Fatal("authorized E2E project setup failed")
	}
	otherProject, err := application.CreateProject(ctx, punaropostgres.ProjectCreate{PrincipalID: owner.ID, IdempotencyKey: uuid.NewString(), DisplayName: "memory E2E isolated project"})
	if err != nil {
		t.Fatal("isolated E2E project setup failed")
	}
	relay := startE2ERelay(t, fixture, appDSNFile)
	defer relay.stop(t)
	proxy := startE2ETLSProxy(t, relay.address)
	defer proxy.close(t)

	clientHome := filepath.Join(fixture, "client-home")
	mailbox := writeE2EMailbox(t, fixture)
	runE2ECommand(t, e2eEnv(clientHome, ""), "sh", filepath.Join(e2eRepositoryRoot(t), "scripts", "install-client.sh"), "--relay-url", proxy.origin(), "--machine-id", "memory-e2e", "--agent-mailbox-bin", mailbox)
	memory := filepath.Join(clientHome, ".local", "bin", "punaro-memory")
	enroller := filepath.Join(clientHome, ".local", "bin", "punaro-enroll")
	enrollmentState := filepath.Join(clientHome, ".config", "punaro", "device-enrollment")
	preparedRaw := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), enroller, "prepare", "--origin", proxy.origin(), "--state-dir", enrollmentState)
	var prepared struct {
		Origin        string `json:"origin"`
		ClientBinding string `json:"client_binding"`
	}
	if json.Unmarshal(preparedRaw, &prepared) != nil || prepared.Origin != proxy.origin() || prepared.ClientBinding == "" {
		t.Fatal("installed enrollment client did not create a public binding")
	}
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment([]string{project.ProjectID}, false)
	if err != nil {
		t.Fatal("enrollment preview setup failed")
	}
	pending, err := admin.CreateEnrollment(ctx, owner.ID, punaropostgres.EnrollmentRequest{ClientBinding: prepared.ClientBinding, Label: "memory E2E client", ProjectIDs: []string{project.ProjectID}, TTL: time.Minute}, previewHash)
	if err != nil {
		t.Fatal("disposable enrollment setup failed")
	}
	pendingRaw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal("encode enrollment material")
	}
	material := writePrivateFile(t, enrollmentState, "enrollment-material.json", string(pendingRaw))
	credentialFile := filepath.Join(enrollmentState, "device.credential")
	redeemed := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), enroller, "redeem", "--state-dir", enrollmentState, "--enrollment-file", material, "--credential-file", credentialFile)
	if bytes.Contains(redeemed, []byte(pending.Code)) || bytes.Contains(redeemed, []byte(`"credential"`)) {
		t.Fatal("installed enrollment client leaked secret material")
	}
	profile := filepath.Join(clientHome, ".config", "punaro", "memory-profile.json")
	runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), memory, "profile-write", "--profile", profile, "--origin", proxy.origin(), "--credential-file", credentialFile, "--project", project.ProjectID)

	missingCredential := filepath.Join(clientHome, ".config", "punaro", "unavailable-device-credential")
	assertE2EFailure(t, e2eEnv(clientHome, proxy.caFile), "punaro-memory: protected credential is unavailable\n", memory, "get", "--origin", proxy.origin(), "--credential-file", missingCredential, "--project", project.ProjectID, "--item", uuid.NewString())

	input := writePrivateFile(t, fixture, "memory-input.json", `{"logical_key":"e2e.memory","kind":"decision","trust":"curated","document":{"title":"onboarding-memory-e2e"}}`)
	create := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), memory, "create", "--profile", profile, "--idempotency-key", uuid.NewString(), "--input", input)
	itemID := e2EMutationID(t, create)
	get := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), memory, "get", "--profile", profile, "--item", itemID)
	assertE2EItem(t, get, itemID)
	search := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), memory, "search", "--profile", profile, "--query", "onboarding-memory-e2e", "--limit", "5")
	assertE2ESearch(t, search, itemID)
	changes := runE2ECommand(t, e2eEnv(clientHome, proxy.caFile), memory, "changes", "--profile", profile, "--limit", "10")
	assertE2EChanges(t, changes, itemID)

	assertE2EFailure(t, e2eEnv(clientHome, proxy.caFile), "punaro-memory: request failed\n", memory, "get", "--profile", profile, "--project", otherProject.ProjectID, "--item", itemID)

	mcp := startE2EMCP(t, e2eEnv(clientHome, proxy.caFile), memory, profile)
	defer mcp.close(t)
	mcp.request(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`)
	mcp.expectResult(t)
	mcp.request(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	mcp.expectResult(t)
	mcp.request(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"punaro_memory_get","arguments":{"item":"`+itemID+`"}}}`)
	mcp.expectTool(t, false)
	mcp.request(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"punaro_memory_search","arguments":{"project":"`+otherProject.ProjectID+`","query":"onboarding-memory-e2e","limit":5}}}`)
	mcp.expectTool(t, true)

	proxy.available.Store(false)
	mcp.request(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"punaro_memory_get","arguments":{"item":"`+itemID+`"}}}`)
	mcp.expectTool(t, true)
	proxy.available.Store(true)
	relay.restart(t)
	mcp.request(t, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"punaro_memory_get","arguments":{"item":"`+itemID+`"}}}`)
	mcp.expectTool(t, false)

	before := e2eTree(t, clientHome)
	proxy.available.Store(false)
	assertE2EFailure(t, e2eEnv(clientHome, proxy.caFile), "punaro-memory: request failed\n", memory, "search", "--profile", profile, "--query", "onboarding-memory-e2e", "--limit", "5")
	proxy.available.Store(true)
	after := e2eTree(t, clientHome)
	if before != after {
		t.Fatal("native memory command wrote local fallback state")
	}
}

type e2eRelay struct {
	address string
	binary  string
	env     []string
	command *exec.Cmd
}

func startE2ERelay(t *testing.T, fixture, appDSNFile string) *e2eRelay {
	t.Helper()
	binary := filepath.Join(fixture, "punarod")
	runE2ECommand(t, nil, "go", "build", "-trimpath", "-o", binary, filepath.Join(e2eRepositoryRoot(t), "cmd", "punarod"))
	address := e2eFreeAddress(t)
	healthAddress := e2eFreeAddress(t)
	relay := &e2eRelay{address: address, binary: binary, env: append(os.Environ(),
		"PUNARO_POSTGRES_ENABLED=true", "PUNARO_POSTGRES_DSN_FILE="+appDSNFile,
		"PUNARO_DEVICE_AUTH_ENABLED=true", "PUNARO_MEMORY_API_ENABLED=true", "PUNARO_MEMORY_MUTATIONS_ENABLED=true",
		"PUNARO_INGRESS_MODE=internet", "PUNARO_PUBLIC_URL=https://memory-e2e.invalid",
		"PUNARO_LISTEN_ADDR="+address, "PUNARO_HEALTH_LISTEN_ADDR="+healthAddress,
	)}
	relay.start(t)
	return relay
}

func (r *e2eRelay) start(t *testing.T) {
	t.Helper()
	r.command = exec.Command(r.binary) // #nosec G204 -- test executes the binary built from this checkout.
	r.command.Env = r.env
	r.command.Stdout = io.Discard
	r.command.Stderr = io.Discard
	if err := r.command.Start(); err != nil {
		t.Fatal("disposable relay did not start")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", r.address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.stop(t)
	t.Fatal("disposable relay did not become reachable")
}

func (r *e2eRelay) stop(t *testing.T) {
	t.Helper()
	if r.command == nil || r.command.Process == nil {
		return
	}
	_ = r.command.Process.Kill()
	if err := r.command.Wait(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		// A killed disposable relay is the expected shutdown path.
	}
	r.command = nil
}

func (r *e2eRelay) restart(t *testing.T) {
	t.Helper()
	r.stop(t)
	r.start(t)
}

type e2eTLSProxy struct {
	listener  net.Listener
	server    *http.Server
	caFile    string
	originURL string
	available atomic.Bool
}

func startE2ETLSProxy(t *testing.T, target string) *e2eTLSProxy {
	t.Helper()
	certificate, caFile := e2ETLSCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("TLS proxy listener setup failed")
	}
	proxy := &e2eTLSProxy{listener: listener, caFile: caFile, originURL: "https://" + listener.Addr().String()}
	proxy.available.Store(true)
	targetURL := &url.URL{Scheme: "http", Host: target}
	reverse := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !proxy.available.Load() {
			if hijacker, ok := w.(http.Hijacker); ok {
				connection, _, err := hijacker.Hijack()
				if err == nil {
					_ = connection.Close()
				}
			}
			return
		}
		reverse.ServeHTTP(w, request)
	})}
	go func() {
		_ = proxy.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}))
	}()
	return proxy
}

func (p *e2eTLSProxy) origin() string { return p.originURL }

func (p *e2eTLSProxy) client() *http.Client {
	pool := x509.NewCertPool()
	certificate, err := os.ReadFile(p.caFile) // #nosec G304 -- test reads its own generated CA file.
	if err != nil || !pool.AppendCertsFromPEM(certificate) {
		return &http.Client{Timeout: time.Second}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
}

func (p *e2eTLSProxy) close(t *testing.T) {
	t.Helper()
	if err := p.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal("TLS proxy shutdown failed")
	}
}

func e2ETLSCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("test CA generation failed")
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Punaro memory E2E CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("test CA certificate generation failed")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("test TLS key generation failed")
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("test TLS certificate generation failed")
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustE2eMarshalKey(t, leafKey)}))
	if err != nil {
		t.Fatal("test TLS certificate assembly failed")
	}
	return certificate, writePrivateFile(t, t.TempDir(), "memory-e2e-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
}

func mustE2eMarshalKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("test TLS key encoding failed")
	}
	return encoded
}

func redeemE2EEnrollment(t *testing.T, client *http.Client, origin string, pending punaropostgres.PendingEnrollment) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"enrollment_id": pending.ID, "client_binding": pending.ClientBinding, "code": pending.Code, "idempotency_key": uuid.NewString()})
	if err != nil {
		t.Fatal("enrollment request encoding failed")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin+"/v1/enrollments/redeem", bytes.NewReader(body))
	if err != nil {
		t.Fatal("enrollment request setup failed")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("enrollment request failed")
	}
	defer func() { _ = response.Body.Close() }()
	var credential struct {
		Credential string `json:"credential"`
	}
	if response.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&credential) != nil || credential.Credential == "" {
		t.Fatal("enrollment credential response failed")
	}
	return credential.Credential
}

func writeE2EMailbox(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join(fixture, "agent-mailbox")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
case " $* " in *' group create '*) exit 0;; *' group list '*) printf '%s\n' '["group/punaro-attached"]'; exit 0;; esac
exit 1
`), 0o600); err != nil {
		t.Fatal("test mailbox script setup failed")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal("test mailbox setup failed")
	}
	return path
}

func writePrivateFile(t *testing.T, directory, name, value string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal("private fixture directory setup failed")
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal("private fixture file setup failed")
	}
	return path
}

func e2eRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository root resolution failed")
	}
	return root
}

func e2eEnv(home, caFile string) []string {
	env := append([]string(nil), os.Environ()...)
	if home != "" {
		env = append(env, "HOME="+home)
	}
	if caFile != "" {
		env = append(env, "SSL_CERT_FILE="+caFile)
	}
	return env
}

func runE2ECommand(t *testing.T, env []string, name string, args ...string) []byte {
	t.Helper()
	command := exec.Command(name, args...) // #nosec G204 -- E2E test commands are fixed checkout tools and generated fixture paths.
	if env != nil {
		command.Env = env
	}
	stdout, err := command.Output()
	if err != nil {
		t.Fatal("E2E command failed")
	}
	return stdout
}

func assertE2EFailure(t *testing.T, env []string, want string, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...) // #nosec G204 -- E2E test commands are fixed checkout tools and generated fixture paths.
	command.Env = env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err == nil || stdout.Len() != 0 || stderr.String() != want {
		t.Fatal("native memory failure was not safely classified")
	}
}

func e2EMutationID(t *testing.T, raw []byte) string {
	t.Helper()
	var result struct {
		ItemID string `json:"item_id"`
	}
	if json.Unmarshal(raw, &result) != nil || result.ItemID == "" {
		t.Fatal("memory create response was invalid")
	}
	return result.ItemID
}

func assertE2EItem(t *testing.T, raw []byte, itemID string) {
	t.Helper()
	var result struct {
		ItemID   string `json:"item_id"`
		Document struct {
			Title string `json:"title"`
		} `json:"document"`
	}
	if json.Unmarshal(raw, &result) != nil || result.ItemID != itemID || result.Document.Title != "onboarding-memory-e2e" {
		t.Fatal("memory get did not observe the created relay state")
	}
}

func assertE2ESearch(t *testing.T, raw []byte, itemID string) {
	t.Helper()
	var result struct {
		Results []struct {
			ItemID string `json:"item_id"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Results) != 1 || result.Results[0].ItemID != itemID {
		t.Fatal("memory search did not observe the created relay state")
	}
}

func assertE2EChanges(t *testing.T, raw []byte, itemID string) {
	t.Helper()
	var result struct {
		Changes []struct {
			ItemID string `json:"item_id"`
		} `json:"changes"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Changes) == 0 || result.Changes[len(result.Changes)-1].ItemID != itemID {
		t.Fatal("memory changes did not observe the created relay state")
	}
}

type e2eMCP struct {
	input  io.WriteCloser
	output *json.Decoder
	cmd    *exec.Cmd
}

func startE2EMCP(t *testing.T, env []string, memory, profile string) *e2eMCP {
	t.Helper()
	command := exec.Command(memory, "mcp", "--profile", profile) // #nosec G204 -- test executes the installed local client fixture.
	command.Env = env
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal("MCP input setup failed")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("MCP output setup failed")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("MCP startup failed")
	}
	return &e2eMCP{input: stdin, output: json.NewDecoder(stdout), cmd: command}
}

func (m *e2eMCP) request(t *testing.T, raw string) {
	t.Helper()
	if _, err := io.WriteString(m.input, raw+"\n"); err != nil {
		t.Fatal("MCP request write failed")
	}
}

func (m *e2eMCP) expectResult(t *testing.T) {
	t.Helper()
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if m.output.Decode(&response) != nil || len(response.Result) == 0 || len(response.Error) != 0 {
		t.Fatal("MCP initialization response failed")
	}
}

func (m *e2eMCP) expectTool(t *testing.T, wantError bool) {
	t.Helper()
	var response struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if m.output.Decode(&response) != nil || response.Result.IsError != wantError || len(response.Result.Content) != 1 {
		t.Fatal("MCP tool response failed")
	}
	if strings.Contains(response.Result.Content[0].Text, "onboarding-memory-e2e") && wantError {
		t.Fatal("MCP error exposed memory content")
	}
}

func (m *e2eMCP) close(t *testing.T) {
	t.Helper()
	_ = m.input.Close()
	if err := m.cmd.Wait(); err != nil {
		t.Fatal("MCP shutdown failed")
	}
}

func e2eTree(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			body, err := os.ReadFile(path) // #nosec G304 -- test snapshots its own private client fixture for fallback writes.
			if err != nil {
				return err
			}
			sum := sha256.Sum256(body)
			paths = append(paths, fmt.Sprintf("%s:%o:%x", relative, info.Mode().Perm(), sum))
		} else {
			paths = append(paths, fmt.Sprintf("%s:%o", relative, info.Mode().Perm()))
		}
		return nil
	})
	if err != nil {
		t.Fatal("local fallback snapshot failed")
	}
	return strings.Join(paths, "\n")
}

func e2eFreeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("test loopback address allocation failed")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("test loopback address release failed")
	}
	return address
}
