.PHONY: test test-race vet staticcheck vuln gosec secrets lint security ci fmt dockerfile-lint workflow-lint

test:
	go test -covermode=atomic ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.22.10 ./...

secrets:
	go run github.com/zricethezav/gitleaks/v8@v8.27.2 detect --source . --no-git

lint: vet staticcheck

security: vuln gosec secrets

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

dockerfile-lint:
	docker run --rm -i hadolint/hadolint < Dockerfile

workflow-lint:
	docker run --rm -v "$$(pwd):/repo" -w /repo rhysd/actionlint:1.7.7

ci: test test-race lint security
