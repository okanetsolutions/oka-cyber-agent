VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/okanetsolutions/oka-cyber-agent/internal/agent.Version=$(VERSION)
GOARCHES := amd64 arm64

.PHONY: build build-all test lint fmt

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/oka-cyber-agent ./cmd/oka-cyber-agent

build-all:
	@for arch in $(GOARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o bin/oka-cyber-agent-linux-$$arch ./cmd/oka-cyber-agent || exit 1; \
	done

test:
	go test -race ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	staticcheck ./...

fmt:
	gofmt -w .
