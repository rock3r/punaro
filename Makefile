.PHONY: test test-race vet staticcheck golangci vuln gosec secrets lint security ci fmt dockerfile-lint workflow-lint release-gates fuzz

test:
	go test -covermode=atomic ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...

golangci:
	@lint_dir="$$(mktemp -d)"; \
		trap 'rm -f "$$lint_dir/golangci-lint"; rmdir "$$lint_dir"' EXIT; \
		GOBIN="$$lint_dir" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.1; \
		"$$lint_dir/golangci-lint" run ./...; \
		GOOS=linux "$$lint_dir/golangci-lint" run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.22.10 ./...

secrets:
	go run github.com/zricethezav/gitleaks/v8@v8.27.2 detect --source . --no-git

lint: vet staticcheck golangci

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
