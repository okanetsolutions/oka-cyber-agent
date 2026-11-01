# Oka Cyber Agent

Oka Cyber Agent is the open source, lightweight server agent of [Oka Cyber](https://github.com/okanetsolutions). It reports the software installed on a Linux server to your Oka Cyber dashboard, where every package is matched against known vulnerabilities (OSV.dev, with CVE aliases).

It is a single static binary with no runtime dependencies. This repository is public so you can read exactly what you install on your servers before you install it.

> Status: under active development. The collectors, enrollment, installer and log shipping are tracked in the [issues](https://github.com/okanetsolutions/oka-cyber-agent/issues).

## What it collects

- OS facts: hostname, OS family, name and version, kernel version, CPU architecture.
- Installed OS packages: name, version, architecture and source package, read from the package database (dpkg on Debian and Ubuntu, rpm on Rocky Linux, AlmaLinux and Red Hat, apk on Alpine). On Red Hat Enterprise Linux it also reads which repository each package was installed from in the dnf history database, never the commands recorded there.
- Application dependencies: name and resolved version of the libraries listed in common lock files, with the path of the file each one came from (see [Dependency files](#dependency-files)). You can turn this off.
- Listening services: protocol, address and port of listening TCP sockets, plus the process name when the agent is allowed to see it. The process ID is not sent, so restarting a service does not count as an inventory change. You can turn this off.
- Security log events, only when an admin turns log collection on for that server in the dashboard: SSH logins, sudo and su use, account and cron changes, suspicious web requests and application errors. Lines are redacted on your server before they are sent, and normal web traffic is only sent as counts per IP and minute.

To see exactly what the agent would report from a server, without sending anything:

```bash
oka-cyber-agent inventory
```

## What it never collects

- The contents of your files, other than the package databases, the dnf history database, the dependency lock files and the log files listed above.
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
| `POST /logs` | Only while log collection is enabled. |

Nothing is sent to any other host. There is no telemetry.

## Install

Create an enrollment token in your Oka Cyber dashboard (Server agents) and run the install command it shows:

```bash
curl -fsSL https://github.com/okanetsolutions/oka-cyber-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://<your tenant> --token <enrollment token>
```

The [install script](install.sh) is short; read it first if you like. It:

1. resolves one release and downloads the binary for your architecture (x86_64 or aarch64) and `checksums.txt` from it,
2. verifies the binary's SHA-256 against `checksums.txt`, and the cosign signature of `checksums.txt` when `cosign` is installed (cosign v3 or newer: the installer stops and asks you to upgrade an older cosign that cannot read the signature),
3. installs `/usr/local/bin/oka-cyber-agent` and creates the `oka-cyber` system user,
4. writes a hardened systemd unit (`/etc/systemd/system/oka-cyber-agent.service`),
5. enrolls the server and starts the service.

Rerunning it upgrades the agent, keeps the enrollment and restarts the service on the new binary. A service you disabled stays disabled. Pass `--version v1.2.3` to install a specific release. It refuses to run on a server where the agent was installed from a package: upgrade that one with your package manager.

The service runs as the unprivileged `oka-cyber` user with a read only view of the system (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, no capabilities). It can only write its state directory, `/var/lib/oka-cyber-agent`. The agent token stays root only (mode 0600) and systemd hands it to the service with `LoadCredential`. systemd older than 247 (the RHEL 8 family) has no `LoadCredential`, so there `enroll` makes the token readable by the `oka-cyber` group only (mode 0640), for the install script and the packages alike.

### Packages

Every release also ships `.deb` and `.rpm` packages, which install `/usr/bin/oka-cyber-agent`, the same systemd unit and the `oka-cyber` user. Then enroll and start it:

```bash
sudo apt install ./oka-cyber-agent_<version>_amd64.deb        # or: sudo dnf install ./oka-cyber-agent-<version>.x86_64.rpm
sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>
sudo systemctl enable --now oka-cyber-agent
```

Upgrading the package restarts the service on the new binary, and leaves it disabled if you disabled it. Installing the package on a server that is already enrolled enables and starts the service. After `apt remove`, which keeps the enrollment, installing it again starts the service only if it was enabled before the removal.

The package does not install over an agent installed by the install script, whose unit would take precedence over the package's. Run `sudo /usr/local/bin/oka-cyber-agent uninstall` first, which also deletes the enrollment. To keep the enrollment instead, run `sudo systemctl disable --now oka-cyber-agent` and delete `/usr/local/bin/oka-cyber-agent` and `/etc/systemd/system/oka-cyber-agent.service`: the package then enables and starts the service on its first install.

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
sudo oka-cyber-agent status  # enrollment, service state, last heartbeat and inventory, last error
oka-cyber-agent inventory    # what would be reported, as JSON; sends nothing
oka-cyber-agent run --once   # one heartbeat and inventory report, then exit (non zero if it failed)
```

`enroll` is idempotent: on an enrolled server it does nothing unless you pass `--force`. When only one of `config.yaml` and `token` loads (an interrupted enrollment, or a deleted or broken file), it stops with an error and enrolls again only with `--force`. A running service notices the new enrollment within about a minute and exits, so systemd restarts it with the new token. It checks that it can write to `/etc/oka-cyber-agent` before it uses the enrollment token, so run it as root. The enrollment token can also be passed in the `OKA_CYBER_ENROLLMENT_TOKEN` environment variable so it does not show up in the process list.

`status` reads the state in `/var/lib/oka-cyber-agent`, which only the service user and root can read, so run it with sudo; it exits with an error rather than show the last reports as never when it cannot read the state. `run --once` reads the root owned agent token, so run it with sudo. A state file it writes as root is given to the owner of `/var/lib/oka-cyber-agent`, so the service can keep using it, and the agent starts from an empty state (with a warning) when its state file is unreadable or corrupt.

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
exclude_paths: []                              # absolute paths (directories or files) never opened
max_depth: 6                                   # path components below a scan path, like find -maxdepth
max_file_size: 20971520                        # bytes; larger lock files are skipped (not Go executables)
collect_go_binaries: false                     # also read module lists from Go executables
```

Unknown keys are rejected, so a typo cannot silently turn an option off. The agent token lives in `/etc/oka-cyber-agent/token` (mode 0600, owned by root) and is never written to the configuration file or the logs. The running service checks the file and the token every 30 seconds and, when either changed, exits so systemd restarts it with the new settings. An edit that does not load is ignored with a warning in the journal, and the service keeps its current settings.

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

It opens only those file names (and executables, when `collect_go_binaries` is on). It skips installed dependency trees (`node_modules`, `vendor`, `site-packages` and similar), hidden directories (`.git` and package manager caches such as `.npm` or `.cargo`), the Go module cache, `/proc`, `/sys` and `/dev`. It never follows a symlink below a scan path: a symlinked lock file is listed with the reason `symlink` without being opened (its target is reported under its own path when a scan path reaches it), and a symlinked directory or executable is skipped. Nothing under `exclude_paths` is ever opened, whatever path leads to it: an excluded directory is also recognised when the walk reaches it under another name (an exclude path or a scan path that goes through a symlink, or a bind mount).

Versions are never guessed. Entries without a pinned version are left out, and so are packages that do not come from their registry (a git repository, a URL, a local path or workspace), because their version is not a registry release; an npm alias is reported under the real package name. A file the agent reports no package from is listed on the dashboard with a reason instead: `unresolved_versions` (for example a `requirements.txt` with only unpinned lines), `invalid_entries` (names or versions the server does not accept), `no_lock_file` (a `package.json`, `composer.json`, `Gemfile`, `Pipfile` or `Cargo.toml` without its lock file), `too_large`, `parse_error`, `permission_denied`, `symlink` or `package_limit` (left out to stay within the server limits). Oka Cyber keeps what it last stored for a listed file. It accepts at most 1000 listed files per server. Above that, the agent lists first the files Oka Cyber has packages stored for (it keeps a digest of their paths in its state file), so lock files someone plants under a scan path can never make Oka Cyber drop what it stored for another file, nor stop the inventory. In the unlikely case that more than 1000 such files are skipped at once, the inventory is still sent and the agent logs a warning naming how many files lost their stored packages. A file the agent reports packages from is never listed, even when some of its entries were left out, so a package removed from it disappears from the inventory and its findings close. When one name appears in several versions in one lock file, one version is reported, because Oka Cyber stores one per name and file: the direct dependency when the file says which one it is (pnpm, Cargo, Bundler, uv, NuGet, Go), the top level (hoisted) install in an npm lock file, the entry a workspace or the project's `package.json` asks for in a yarn lock file when the file shows it, and otherwise the highest version.

## Log collection

Log collection is off until an admin turns it on for the server in the dashboard. The dashboard can switch each built in source on or off, never point the agent at another file.

- `auth`: SSH logins, sudo and su use, account, group and password changes, and crontab edits. On a server with a system journal the agent reads them with `journalctl`, and accepts an entry only when journald's own record of the sender matches the program it claims to be: the executable (`_EXE`) must be that program in a system directory such as `/usr/sbin`, and it must run as root (`_UID` 0) unless it is a set-user-ID program (`sudo`, `su`, `passwd`, `gpasswd`, `crontab`). An entry another user logged under one of these names, for example with `logger -t sshd`, is dropped. When the journal exists the agent never reads the auth log files, even if it cannot read the journal (the dashboard then shows the journal as `permission_denied`).
- Without a system journal (Alpine, or journald with `Storage=none`), `auth` reads `/var/log/auth.log`, `/var/log/secure` or `/var/log/messages`, plus the cron log. These files do not record who wrote a line, and any local user can add one under any program name (`logger -p auth.info -t sshd ...`). On such a server a local user can make up auth events, and Oka Cyber cannot tell them from real ones.
- `web`: the nginx and Apache access logs in `/var/log/nginx`, `/var/log/apache2` and `/var/log/httpd`.
- `app`: the files listed in `log_paths` in the configuration file (at most 10, glob patterns such as `/var/www/shop/storage/logs/laravel-*.log` allowed).

When a log file the agent follows disappears and is not created again within 5 minutes, it reports `log_file_removed`. That applies to the auth log files and to the files named in full in `log_paths`. Files found through a glob pattern (the web access logs and patterns in `log_paths`) come and go with normal retention, so the agent stops following them without reporting anything once they are gone. A file rotated by renaming it is read to its end, then followed again from the start of the new file.

## Uninstall

If you used the install script:

```bash
sudo oka-cyber-agent uninstall
```

This stops and disables the service and removes the unit, `/etc/oka-cyber-agent` (configuration and token), `/var/lib/oka-cyber-agent` (state), the `oka-cyber` user and `/usr/local/bin/oka-cyber-agent`. If the service cannot be stopped, it removes nothing and exits with an error.

If you installed a package, remove it with the package manager instead: `sudo apt purge oka-cyber-agent` or `sudo dnf remove oka-cyber-agent`. Both remove the same files and the user (`apt remove` without purge keeps the enrollment).

Then revoke the server in your Oka Cyber dashboard so its token stops working. Both uninstall paths are tested in CI on Ubuntu, Debian, Rocky Linux 8 and 9 and Red Hat Enterprise Linux 8 and 9.

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
