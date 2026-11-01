# Oka Cyber Agent

Oka Cyber Agent is the open source, lightweight server agent of [Oka Cyber](https://github.com/okanetsolutions). It reports the software installed on a Linux server to your Oka Cyber dashboard, where every package is matched against known vulnerabilities (OSV.dev, with CVE aliases).

It is a single static binary with no runtime dependencies. This repository is public so you can read exactly what you install on your servers before you install it.

> Status: under active development. The collectors, enrollment, installer and log shipping are tracked in the [issues](https://github.com/okanetsolutions/oka-cyber-agent/issues).

## What it collects

- OS facts: hostname, OS family, name and version, kernel version, CPU architecture.
- Installed OS packages: name, version, architecture and source package, read from the package database (dpkg on Debian and Ubuntu, rpm on Rocky Linux, AlmaLinux and Red Hat, apk on Alpine). On Red Hat Enterprise Linux it also reads which repository each package was installed from in the dnf history database, never the commands recorded there.
- Application dependencies: name and resolved version of the libraries listed in common lock files (`composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Gemfile.lock`, `go.sum`, `Cargo.lock` and others), with the path of the file each one came from. You can turn this off.
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

The signed release, the one line installer and the systemd service are tracked in [#4](https://github.com/okanetsolutions/oka-cyber-agent/issues/4). To build from source:

```bash
make build        # bin/oka-cyber-agent for this machine
make build-all    # static Linux amd64 and arm64 binaries in bin/
```

## Uninstall

```bash
sudo oka-cyber-agent uninstall
```

This stops and removes the service, its configuration (`/etc/oka-cyber-agent`), its state (`/var/lib/oka-cyber-agent`) and the binary. Then revoke the server in your Oka Cyber dashboard so its token stops working.

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
