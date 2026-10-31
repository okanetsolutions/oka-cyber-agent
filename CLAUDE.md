# Claude Guide for Oka Cyber Agent

Oka Cyber Agent is the open source (Apache-2.0) server agent of Oka Cyber, a vertical of Oka Core. It runs on a customer's Linux server, reports OS facts, installed packages, dependency files and listening services to the customer's Oka Cyber tenant, and ships redacted security log events when an admin enables log collection. The platform matches the packages against OSV.dev and runs detection on the logs.

Customers install this binary on their own servers, often as a privileged service, and they are invited to read the code before they do. Every rule below follows from that: the agent must be small, predictable, read only and easy to audit.

The product epic is okanetsolutions/oka-core#3705. The server side of the protocol lives in Oka Core under `app-modules/cyber`.

## Privacy and Safety Invariants (non negotiable)

These are product promises written in the README. A change that breaks one is a blocking finding, whatever else it fixes.

- Read only. The agent never writes outside `/etc/oka-cyber-agent`, `/var/lib/oka-cyber-agent` and, during install or uninstall only, the binary, the systemd unit and the `oka-cyber` system user. It never changes packages, services, firewall rules or users at runtime.
- No remote control. The server can only tune what the agent already supports (report interval, which built in log sources are on). It can never send a command, a file path, a glob or a regular expression for the agent to act on. File paths come only from the local config file.
- Never collected: file contents (other than the listed package databases, dependency lock files, the Go build info embedded in executables in the scan roots and log files), secrets, environment variables, shell history, users' data, process arguments.
- Dependency discovery opens only the documented lock file names and, when `collect_go_binaries` is on, executables in the scan roots, from which it reads only the Go build info (`debug/buildinfo`). It never follows symlinks out of the scan roots.
- Log events are redacted on the host before they reach the spool (see okanetsolutions/oka-cyber-agent#7). Never send a raw line that has not been through redaction.
- Never log, print or include in an error the enrollment token or the agent token. Error messages from the API client must not echo request bodies.
- HTTPS only. `http://` is rejected unless the explicit `--insecure-dev` flag is set for local testing.
- Install footprint. `install.sh` and the .deb/.rpm maintainer scripts (`postinstall`, `preremove`, `postremove`) make these changes and nothing else:
  - Install the binary (`/usr/local/bin/oka-cyber-agent` from `install.sh`, `/usr/bin/oka-cyber-agent` from a package) and the systemd unit (`/etc/systemd/system/oka-cyber-agent.service` or `/usr/lib/systemd/system/oka-cyber-agent.service`).
  - Create the `oka-cyber` system user (nologin shell, home directory not created) with its own `oka-cyber` group, and add it to the `adm` and `systemd-journal` groups where they exist so it can read auth logs and the journal (okanetsolutions/oka-cyber-agent#7).
  - Create `/etc/oka-cyber-agent` (through `enroll`) and set the owner and mode of its `token` file. systemd creates `/var/lib/oka-cyber-agent` as the unit's `StateDirectory`.
  - Reload systemd and enable, start, stop or disable `oka-cyber-agent.service` only.
  - On deb purge or rpm erase only (`rpm -e` or `dnf remove`, not an upgrade), delete both directories, the `oka-cyber` user and its group. A deb `remove` keeps them.

## Repository Layout

- `cmd/oka-cyber-agent`: the CLI entry point and subcommand wiring only. No business logic.
- `internal/collect`: collectors (OS facts, package databases, listening services, dependency file discovery). Each collector implements the collector interface and is tested against fixture files.
- `internal/collect/lockfile`: one parser per dependency file format, pure functions from bytes to resolved versions. Fixtures under its `testdata` were produced by the real tools (composer, npm, yarn, pnpm, poetry, pipenv, uv, bundler, go, cargo, gradle, dotnet).
- `internal/api`: the HTTP client for the Oka Cyber agent API and the wire types.
- `internal/config`: the local configuration file and token storage.
- `internal/agent`: the run loop (heartbeat, inventory, log shipping) and its persisted state.
- `testdata` directories next to the code they feed: real sample files, never generated at test time.
- `install.sh`: the one line installer (POSIX `sh`, it runs as `curl ... | sudo sh -s --`). It embeds the systemd unit, which must stay identical to `packaging/oka-cyber-agent.service` apart from the binary path (`test/install/check-unit.sh` enforces it).
- `packaging`: the systemd unit and the `.deb`/`.rpm` maintainer scripts used by `.goreleaser.yaml`.
- `test/faketenant` and `test/install`: a stand in for the agent API and the CI scripts that install, rerun and uninstall the agent (script and packages) on Ubuntu, Debian and Rocky.

Update this section in the same PR when a package is added, moved or removed.

## API Contract

The agent talks to `https://<tenant host>/cyber-agent/v1`. The source of truth is Oka Core, not this repository: read the controller and validators there before changing a payload.

- `POST /enroll` (okanetsolutions/oka-core#3709): `enrollment_token` plus host facts; returns `server_id`, `agent_token`, `report_interval_seconds` with status 201.
- `POST /heartbeat`: bearer agent token, body `agent_version`; returns `report_interval_seconds` and, once okanetsolutions/oka-core#3778 lands, `log_collection`.
- `PUT /inventory`: bearer agent token, full snapshot `{os, packages, skipped_files, services}`; validated by `InventorySnapshotValidator`.
- `POST /logs` (okanetsolutions/oka-core#3779): batches of normalized log events.

Server limits the agent must respect, because a violation rejects the whole request: 5 MB request body measured both compressed and decompressed, 20 000 packages, 1000 `skipped_files`, 4096 `services`, unique `(ecosystem, name, architecture, manifest_path)` per snapshot, no whitespace or control characters in package names and versions, absolute `manifest_path` up to 1024 characters. A 401 from the bearer authenticated endpoints (`/heartbeat`, `/inventory`, `/logs`) means the server was revoked: stop, do not retry. A 401 from `POST /enroll` means the enrollment token was rejected (invalid or expired): report that clearly to the user and do not treat it as a revocation.

## Go Conventions

- Go version from `go.mod`; builds use `CGO_ENABLED=0` and produce one static binary for Linux amd64 and arm64.
- Standard library first. A new dependency needs a reason in the PR description (for example a YAML or TOML parser); never add a dependency for something the standard library already does.
- Linux specific code sits behind `_linux.go` files with a portable fallback, so `go test ./...` and `go vet ./...` also pass on macOS for contributors.
- Accept a `context.Context` on anything that does I/O, and pass it through.
- Inject the filesystem root, command runners and clocks so tests never touch the real host: collectors read from a configurable root (`/` in production, a `testdata` directory in tests) and never shell out in tests.
- Errors are wrapped with `%w` and context about what failed (`dpkg status: %w`). Typed sentinel errors (`errors.Is`) for conditions callers branch on, such as an unauthorized response.
- Code explains itself through names. Add a comment only for a non obvious reason (a file format quirk, a security decision); no commented out code.
- Keep output deterministic: sort packages, services and skipped files before hashing or sending, so an unchanged host produces an identical snapshot.
- `gofmt`, `go vet` and `staticcheck` must be clean.

## Testing Expectations

Every change to production code ships with a new or updated test in the same PR.

- Parsers and collectors: fixture based unit tests with real sample files committed under `testdata`, one per distribution or format version where formats differ.
- API client: `httptest.Server`, never a live endpoint. Cover success, validation error, 401, 429 with `Retry-After`, 5xx retry and timeout.
- Cover the empty and missing cases (no package database, unreadable file, empty lock file), not only the happy path.
- Assert behaviour and data, not the wording of human readable messages.
- Run before pushing:

```bash
gofmt -l .
go vet ./...
staticcheck ./...
go test -race ./...
shellcheck -s sh install.sh packaging/*.sh test/install/*.sh   # when shell scripts changed
```

Installer and packaging changes are verified by the `install` and `packages` CI jobs; to run them locally, start the fake tenant with `sh test/install/prepare.sh` and run `test/install/run.sh` or `test/install/packages.sh` as root in a disposable container (`docker run --rm --network host -v "$PWD:/src:ro" debian:12 sh /src/test/install/run.sh`).

## Pull Requests

- One issue is one PR. Dependent issues are stacked: each PR targets the branch of the PR below it, and must be green and reviewable by itself.
- Follow the PR template provided to agents (Technical Issue, What does this PR change, How to QA, Risk Assessment). The risk tier is at least medium for anything touching the API client, tokens, the installer, redaction or what data leaves the server.
- Link the issue with `Closes #n`.

## Writing Style for Prose

Never use a dash as a sentence connector in any text a human reads: README and docs, CLI help and messages, commit messages, PR titles and descriptions, review comments. That means no em dashes, no en dashes used as punctuation and no spaced hyphens. Split the sentence, or use a comma, a colon or parentheses. Hyphens inside a word (`read-only` is fine as an adjective, `multi-arch`), CLI flags (`--url`) and Markdown list bullets are allowed.
