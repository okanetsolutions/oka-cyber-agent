# Agent Guide

The implementation guide for this repository lives in [CLAUDE.md](CLAUDE.md). Read it in full before making changes: it covers what the agent is, the privacy and safety invariants, the repository layout, the API contract with Oka Core, the Go conventions and the testing expectations.

## Non negotiable

- The privacy and safety invariants in [CLAUDE.md](CLAUDE.md) are product promises. Never weaken them to make a feature easier.
- Every production change ships with a test in the same PR. Collectors and parsers are tested against real sample files under `testdata`.
- Never log or print the enrollment token or the agent token.
- Run `gofmt -l .`, `go vet ./...`, `staticcheck ./...` and `go test -race ./...` before pushing. All four must be clean.
