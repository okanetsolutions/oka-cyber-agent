# Oka Cyber Agent

Oka Cyber Agent is the open source, lightweight server agent of [Oka Cyber](https://github.com/okanetsolutions). It reports the software installed on a Linux server to your Oka Cyber dashboard, where every package is matched against known vulnerabilities (OSV.dev, with CVE aliases).

It is a single static binary with no runtime dependencies. This repository is public so you can read exactly what you install on your servers before you install it.

> Status: under active development. The collectors, enrollment, installer and log shipping are tracked in the [issues](https://github.com/okanetsolutions/oka-cyber-agent/issues).

## What it collects

- OS facts: hostname, OS family, name and version, kernel version, CPU architecture.
- Installed OS packages: name, version, architecture and source package, read from the package database (dpkg on Debian and Ubuntu, rpm on Rocky Linux, AlmaLinux and Red Hat, apk on Alpine).
- Application dependencies: name and resolved version of the libraries listed in common lock files, with the path of the file each one came from (see [Dependency files](#dependency-files)). You can turn this off.
- Listening services: protocol, address and port of listening TCP sockets, plus the process name when the agent is allowed to see it. You can turn this off.
- Security log events, only when an admin turns log collection on for that server in the dashboard: SSH logins, sudo and su use, account and cron changes, suspicious web requests and application errors. Lines are redacted on your server before they are sent, and normal web traffic is only sent as counts per IP and minute.

To see exactly what the agent would report from a server, without sending anything:

```bash
oka-cyber-agent inventory
```

## What it never collects

- The contents of your files, other than the package databases, the dependency lock files and the log files listed above.
- Secrets, passwords, keys or tokens, environment variables, shell history or command line arguments of other processes.
- Your users' data: databases, uploads, mail or application data.
- Anything from a path chosen by the dashboard. The dashboard can only switch built in sources on and off; every file path the agent reads comes from its local configuration on your server.

The agent is read only. It never installs, updates or removes packages, never changes services, firewall rules or users, and never runs commands sent from the dashboard.

## Where it sends it

Only to the Oka Cyber tenant URL you enroll it with, over HTTPS, authenticated with a per server token stored in `/etc/oka-cyber-agent/token` (mode 0600, owned by root). It talks to these endpoints under `https://<your tenant>/cyber-agent/v1`:

| Endpoint | When |
| --- | --- |
| `POST /enroll` | Once, when you enroll the server. |
| `POST /heartbeat` | Every report interval (5 minutes by default). |
| `PUT /inventory` | When the inventory changed, and at least once a day. |
| `POST /logs` | Every 30 seconds while log collection is enabled, plus an empty batch at least every 5 minutes. |

Nothing is sent to any other host. There is no telemetry.

## Install

Create an enrollment token in your Oka Cyber dashboard (Server agents) and run the install command it shows:

```bash
curl -fsSL https://github.com/okanetsolutions/oka-cyber-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://<your tenant> --token <enrollment token>
```

The [install script](install.sh) is short; read it first if you like. It:

1. resolves one release and downloads the binary for your architecture (x86_64 or aarch64) and `checksums.txt` from it,
2. verifies the binary's SHA-256 against `checksums.txt`, and the cosign signature of `checksums.txt` when `cosign` is installed,
3. installs `/usr/local/bin/oka-cyber-agent` and creates the `oka-cyber` system user,
4. writes a hardened systemd unit (`/etc/systemd/system/oka-cyber-agent.service`),
5. enrolls the server and starts the service.

Rerunning it upgrades the agent and keeps the enrollment. Pass `--version v1.2.3` to install a specific release.

The service runs as the unprivileged `oka-cyber` user with a read only view of the system (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, no capabilities). It can only write its state directory, `/var/lib/oka-cyber-agent`. The agent token stays root only (mode 0600) and systemd hands it to the service with `LoadCredential`. On systemd older than 247 (the RHEL 8 family) the installer makes the token readable by the `oka-cyber` group instead.

### Packages

Every release also ships `.deb` and `.rpm` packages, which install `/usr/bin/oka-cyber-agent`, the same systemd unit and the `oka-cyber` user. Then enroll and start it:

```bash
sudo apt install ./oka-cyber-agent_<version>_amd64.deb        # or: sudo dnf install ./oka-cyber-agent-<version>.x86_64.rpm
sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>
sudo systemctl enable --now oka-cyber-agent
```

### Verify a release

Releases are built by GitHub Actions and `checksums.txt` is signed keylessly with [cosign](https://github.com/sigstore/cosign). Each binary also has an SPDX SBOM.

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/okanetsolutions/oka-cyber-agent/.github/workflows/release.yml@refs/tags/<version>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

### Build from source

```bash
make build        # bin/oka-cyber-agent for this machine
make build-all    # static Linux amd64 and arm64 binaries in bin/
```

## Usage

```bash
sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>
oka-cyber-agent status       # enrollment, service state, last heartbeat and inventory, last error
oka-cyber-agent inventory    # what would be reported, as JSON; sends nothing
oka-cyber-agent run --once   # one heartbeat and inventory report, then exit
```

`enroll` is idempotent: on an enrolled server it does nothing unless you pass `--force`. The enrollment token can also be passed in the `OKA_CYBER_ENROLLMENT_TOKEN` environment variable so it does not show up in the process list.

## Configuration

`enroll` writes `/etc/oka-cyber-agent/config.yaml`:

```yaml
url: https://acme.oka.example   # your tenant, https only
server_id: "42"                  # assigned at enrollment
report_interval_seconds: 300     # the server may change it, between 60 and 86400
collect_services: true           # set to false to stop reporting listening services
```

Dependency file options, with their defaults:

```yaml
collect_dependency_files: true                 # set to false to stop scanning for lock files
scan_paths: [/var/www, /srv, /opt, /home]       # where to look
exclude_paths: []                              # absolute paths to leave out
max_depth: 6                                   # path components below a scan path, like find -maxdepth
max_file_size: 20971520                        # bytes; larger lock files are skipped
collect_go_binaries: false                     # also read module lists from Go executables
```

Unknown keys are rejected, so a typo cannot silently turn an option off. The agent token lives in `/etc/oka-cyber-agent/token` (mode 0600, owned by root) and is never written to the configuration file or the logs. Restart the service after editing the file.

## Dependency files

The agent looks for these files under `scan_paths` and reports the resolved versions they list:

| File | Ecosystem |
| --- | --- |
| `composer.lock` | Packagist |
| `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and berry), `pnpm-lock.yaml` (5.x, 6.x, 9.x) | npm |
| `requirements.txt` (pinned `==` only), `poetry.lock`, `Pipfile.lock`, `uv.lock` | PyPI |
| `Gemfile.lock` | RubyGems |
| `go.mod`, plus Go executables when `collect_go_binaries` is on | Go |
| `Cargo.lock` | crates.io |
| `gradle.lockfile`, `pom.xml` (literal versions only) | Maven |
| `packages.lock.json` | NuGet |

It opens only those file names (and executables, when `collect_go_binaries` is on). It skips installed dependency trees (`node_modules`, `vendor`, `site-packages` and similar), hidden directories (`.git` and package manager caches such as `.npm` or `.cargo`), the Go module cache, `/proc`, `/sys` and `/dev`, and it never follows a symlink out of the scan path it started from.

Versions are never guessed. A file it cannot use is reported to the dashboard with a reason instead: `unresolved_versions` (for example unpinned `requirements.txt` lines), `no_lock_file` (a `package.json`, `composer.json`, `Gemfile`, `Pipfile` or `Cargo.toml` without its lock file), `too_large`, `parse_error`, `permission_denied` or `symlink_outside_scan_root`. When one name appears in several versions in one lock file, the top level (hoisted) version is reported.

## Log collection

Log collection is off until an admin enables it for the server in the dashboard, per built in source. The agent learns the choice from each heartbeat; the dashboard can only switch these sources on and off and never sends a file path.

| Source | What it reads |
| --- | --- |
| `auth` | journald when `journalctl` is available (identifiers `sshd`, `sshd-session`, `sudo`, `su`, `useradd`, `usermod`, `groupadd`, `gpasswd`, `passwd`, `chpasswd`, `crontab`); otherwise `/var/log/auth.log`, `/var/log/secure` or `/var/log/messages`, plus the cron log |
| `web` | nginx and Apache access logs in combined format (`/var/log/nginx/*access*.log`, `/var/log/apache2/*access*.log`, `/var/log/httpd/*access_log`) |
| `app` | only the files you list under `log_paths` in `config.yaml` (at most 10 absolute paths or glob patterns); Monolog entries at `ERROR` or above |

```yaml
log_paths:
  - /var/www/shop/storage/logs/laravel-*.log
```

On the server, before anything is stored or sent:

- Lines are parsed into security events (SSH logins, sudo, su, account and group changes, password changes, crontab changes, web requests, application errors). Every other line is discarded.
- Secrets are redacted: values of query parameters whose name contains `pass`, `pwd`, `secret`, `token`, `key`, `auth`, `session`, `sessid`, `sig`, `code`, `jwt`, `mail`, `phone`, `user` or `login`; JWT shaped strings and email addresses anywhere; password arguments of sudo commands (`-p`, `--password`, `PASSWORD=`, `TOKEN=`, `SECRET=`); and SSH user names on failed logins that are not valid user names, since people type passwords into the user prompt.
- Noise is condensed: failed SSH logins are counted per IP, user name and minute, and ordinary web requests per IP and minute. A web request is sent in full only when it looks suspicious (status 400 or more, an unusual method, a URI over 512 characters, or a token from [the list](internal/logs/testdata/suspicious_tokens.txt) such as `..`, `${`, `union`, `wp-` or a scanner name).
- Messages are cut to 2000 characters.

Events wait in a spool under `/var/lib/oka-cyber-agent/spool` (at most 100 MB; when full, the oldest events are dropped and counted) and are sent in order every 30 seconds. Read positions are saved only after the server acknowledged a batch, so nothing is lost when the server is unreachable. When collection is enabled the agent starts at the current end of every log: no history is uploaded. Turning every source off stops the readers and deletes the spool.

The installer adds the `oka-cyber` user to the `adm` and `systemd-journal` groups when they exist, so logs are readable without root. On the RHEL family `/var/log/secure` is readable by root only, so the agent reads the journal there.

## Uninstall

If you used the install script:

```bash
sudo oka-cyber-agent uninstall
```

This stops and disables the service and removes the unit, `/etc/oka-cyber-agent` (configuration and token), `/var/lib/oka-cyber-agent` (state), the `oka-cyber` user and `/usr/local/bin/oka-cyber-agent`.

If you installed a package, remove it with the package manager instead: `sudo apt purge oka-cyber-agent` or `sudo dnf remove oka-cyber-agent`. Both remove the same files and the user (`apt remove` without purge keeps the enrollment).

Then revoke the server in your Oka Cyber dashboard so its token stops working. Both uninstall paths are tested in CI on Ubuntu, Debian and Rocky Linux.

## Development

Requires Go (version in `go.mod`).

```bash
make test   # go test -race ./...
make lint   # gofmt, go vet, staticcheck
```

Read [CLAUDE.md](CLAUDE.md) for the conventions and the privacy rules every change must keep.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
