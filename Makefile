.PHONY: test test-race test-postgres remote-mcp-e2e memory-onboarding-e2e complete-product-e2e test-real-relay-e2e plugin-validate vet staticcheck golangci windows-build vuln gosec secrets lint security ci fmt dockerfile-lint workflow-lint deployment-lint release-gates fuzz operator-binary trusted-attachment-client memory-client

PUNARO_OPERATOR_OUTPUT ?= ./bin/punaro
PUNARO_TRUSTED_ATTACHMENT_OUTPUT ?= ./bin/punaro-trusted-attachment
PUNARO_MEMORY_OUTPUT ?= ./bin/punaro-memory

operator-binary:
	mkdir -p "$$(dirname "$(PUNARO_OPERATOR_OUTPUT)")"
	go build -trimpath -o "$(PUNARO_OPERATOR_OUTPUT)" ./cmd/punaro

trusted-attachment-client:
	mkdir -p "$$(dirname "$(PUNARO_TRUSTED_ATTACHMENT_OUTPUT)")"
	go build -trimpath -o "$(PUNARO_TRUSTED_ATTACHMENT_OUTPUT)" ./cmd/punaro-trusted-attachment

memory-client:
	mkdir -p "$$(dirname "$(PUNARO_MEMORY_OUTPUT)")"
	go build -trimpath -o "$(PUNARO_MEMORY_OUTPUT)" ./cmd/punaro-memory

test:
	python3 ./scripts/test-agent-plugin.py
	go test -covermode=atomic ./...
	PUNARO_REMOTE_MCP_E2E_LIVE= PUNARO_REMOTE_MCP_E2E_CONFIG= go test -tags=e2e ./internal/mcphttp

plugin-validate:
	python3 ./scripts/test-agent-plugin.py

test-race:
	go test -race -count=1 ./...

test-real-relay-e2e:
	@test "$(shell uname -s)" = Darwin || { printf '%s\n' 'test-real-relay-e2e requires a disposable macOS GUI login for the supported LaunchAgent lifecycle' >&2; exit 2; }
	PUNARO_REAL_RELAY_E2E=1 go test -tags=e2e -count=1 -timeout=8m ./cmd/punaro-adapter -run '^TestE2ERealTwoClientRelayLifecycle$$'

remote-mcp-e2e:
	@test -n "$${PUNARO_REMOTE_MCP_E2E_CONFIG:-}" || { printf '%s\n' 'set PUNARO_REMOTE_MCP_E2E_CONFIG to a private release-candidate config' >&2; exit 2; }
	GOENV=off GOFLAGS= PUNARO_REMOTE_MCP_E2E_LIVE=1 GOCACHE="$${GOCACHE:-/tmp/punaro-go-cache}" go test -tags=e2e ./internal/mcphttp -run '^TestRemoteMCPE2EReleaseCandidate$$' -count=1

test-postgres:
	./scripts/test-postgres-integration.sh

memory-onboarding-e2e:
	./scripts/test-memory-onboarding-e2e.sh

complete-product-e2e: memory-onboarding-e2e

vet:
	go vet ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...

golangci:
	@lint_dir="$$(mktemp -d)"; \
		trap 'rm -f "$$lint_dir/golangci-lint"; rmdir "$$lint_dir"' EXIT; \
		GOBIN="$$lint_dir" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.1; \
		"$$lint_dir/golangci-lint" run ./...; \
		GOOS=linux "$$lint_dir/golangci-lint" run ./...; \
		GOOS=windows "$$lint_dir/golangci-lint" run ./...

windows-build:
	GOOS=windows go build ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

gosec:
	CGO_ENABLED=0 go run github.com/securego/gosec/v2/cmd/gosec@v2.22.10 -exclude-generated ./...

secrets:
	go run github.com/zricethezav/gitleaks/v8@v8.27.2 detect --source . --no-git

deployment-lint:
	./scripts/verify-deployment-files.sh

lint: vet staticcheck golangci windows-build deployment-lint

security: vuln gosec secrets

release-gates:
	./scripts/verify-release-gates.sh

fuzz:
	go test -run '^$$' -fuzz=FuzzDecodeManifest -fuzztime=2s -parallel=1 ./internal/attachment/v2
	go test -run '^$$' -fuzz=FuzzDecodeEnvelope -fuzztime=2s -parallel=1 ./internal/attachment/v2

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

dockerfile-lint:
	docker run --rm -i hadolint/hadolint@sha256:27086352fd5e1907ea2b934eb1023f217c5ae087992eb59fde121dce9c9ff21e < Dockerfile

workflow-lint:
	docker run --rm -v "$$(pwd):/repo:ro" -w /repo rhysd/actionlint@sha256:887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9

ci: test test-race lint security fuzz release-gates
