# Oka Cyber Agent

Oka Cyber Agent is the open source, lightweight server agent of [Oka Cyber](https://github.com/okanetsolutions). It reports the software installed on a Linux server to your Oka Cyber dashboard, where every package is matched against known vulnerabilities (OSV.dev, with CVE aliases).

It is a single static binary with no runtime dependencies for inventory; optional log sources use the host journal tools, and command metadata also requires auditd and its auditctl tool. This repository is public so you can read exactly what you install on your servers before you install it.

> Status: under active development. The collectors, enrollment, installer and log shipping are tracked in the [issues](https://github.com/okanetsolutions/oka-cyber-agent/issues).

## What it collects

- OS facts: hostname, OS family, name and version, kernel version, CPU architecture.
- Installed OS packages: name, version, architecture and source package, read from the package database (dpkg on Debian and Ubuntu, rpm on Rocky Linux, AlmaLinux and Red Hat, apk on Alpine). For dpkg packages it reports the repository's `Origin` from local APT metadata when available. It uses an exact name, version and architecture match, or the highest listed version of the package name if there is no exact match. On Red Hat Enterprise Linux it also reads which repository each package was installed from in the dnf history database, never the commands recorded there.
- Application dependencies: name and resolved version of the libraries listed in common lock files, with the path of the file each one came from (see [Dependency files](#dependency-files)). You can turn this off.
- For each folder it reports a lock file from, the agent reports the application name and PHP or Node.js requirements from `composer.json` and `package.json`. It also reports the checked-out branch and commit and the `origin` remote without passwords or tokens from `.git`. The agent strips URL-form userinfo and keeps the user in an scp-style `user@host:path` address (see [Application details](#application-details)). You can turn this off.
- For listening TCP sockets and bound, unconnected UDP sockets, the agent reports the protocol, local address and port, plus the process name when it is allowed to see it. UDP sockets bound to ports in the host's ephemeral range (32768 to 60999 if the range cannot be read) are omitted, except for ports 51820 (WireGuard) and 41641 (Tailscale). The process ID is not sent, so restarting a service does not count as an inventory change. You can turn this off.
- Security log events, only when an admin turns log collection on for that server in the dashboard: SSH logins and session boundaries, sudo and su use, account and cron changes, suspicious web requests and application errors; a separate `commands` toggle adds interactive SSH command metadata through auditd. Lines are redacted on your server before they are sent, and normal web traffic is only sent as counts per IP and minute.

To see exactly what the agent would report from a server, without sending anything:

```bash
oka-cyber-agent inventory
```

## What it never collects

- The contents of your files, other than the package databases, local APT metadata, the dnf history database, the dependency lock files, the application details and the log files listed above.
- Your source code or your git history. Under `.git` the agent opens only `HEAD`, `config`, the one ref file `HEAD` names and `packed-refs`. It never lists that directory and never reads objects, logs, hooks, the index or stashes.
- Git credentials. The agent removes URL-form userinfo from the `origin` remote on your server and keeps the user in an scp-style `user@host:path` address. The agent omits addresses it cannot clean with certainty. Nothing else in `.git/config` is sent, and credential stores such as `.git-credentials` are never opened.
- Secrets, passwords, keys or tokens, environment variables, shell history or command line arguments of other processes.
- The arguments of commands run with sudo and the variables sudo passes them: a sudo event carries only the executable and the number of arguments (`/usr/bin/ldapmodify [5 args]`).
- Your users' data: databases, uploads, mail or application data.
- Anything from a path chosen by the dashboard. The dashboard can only switch built in sources on and off; every file path the agent reads comes from its local configuration on your server.

The main agent is read only. It never installs, updates or removes packages (the daily update of the agent itself is a separate root timer, see [Daily updates](#daily-updates)), never changes services, firewall rules or users, and never runs commands sent from the dashboard. The optional `commands` source has one fixed exception: an isolated systemd helper installs or removes only the packaged Oka command audit rule when its on/off flag changes.

## Where it sends it

Only to the Oka Cyber tenant URL you enroll it with, over HTTPS, authenticated with a per server token stored in `/etc/oka-cyber-agent/token` (mode 0600, owned by the service user). It talks to these endpoints under `https://<your tenant>/cyber-agent/v1`:

| Endpoint | When |
| --- | --- |
| `POST /enroll` | Once, when you enroll the server. |
| `POST /heartbeat` | Every report interval (5 minutes by default). |
| `PUT /inventory` | When the inventory changed, and at least once a day. |
| `POST /logs` | Every 30 seconds while log collection is enabled, plus an empty batch at least every 5 minutes. |

Nothing is sent to any other host. There is no telemetry. The daily update timer (install script only) downloads releases from `github.com`; it sends nothing about the server.

## Install

Create an enrollment token in your Oka Cyber dashboard (Server agents) and run the install command it shows:

```bash
curl -fsSL https://github.com/okanetsolutions/oka-cyber-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://<your tenant> --token <enrollment token>
```

The [install script](install.sh) is short; read it first if you like. It:

1. resolves one release and downloads the binary for your architecture (x86_64 or aarch64), its `install.sh` and `checksums.txt` from it,
2. verifies the SHA-256 of both against `checksums.txt`, and the cosign signature of `checksums.txt` when `cosign` is installed (cosign v3 or newer: the installer stops and asks you to upgrade an older cosign that cannot read the signature),
3. installs `/usr/local/bin/oka-cyber-agent` and creates the `oka-cyber` system user,
4. writes a hardened systemd unit (`/etc/systemd/system/oka-cyber-agent.service`),
5. enrolls the server and starts the service,
6. keeps the release's `install.sh` in `/usr/local/lib/oka-cyber-agent` and turns on the daily update timer (see [Daily updates](#daily-updates)).

Rerunning it upgrades the agent, keeps the enrollment and restarts the service on the new binary (`--url` and `--token` are only needed to enroll). A service you disabled stays disabled. Pass `--version v1.2.3` to install a specific release, with `--no-auto-update` if it must stay on that release. A release older than the daily update gets no timer, and any timer from a newer install is removed. It refuses to run on a server where the agent was installed from a package: upgrade that one with your package manager.

The service runs as the unprivileged `oka-cyber` user with a read only view of the system (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, no capabilities). It writes its state directory, `/var/lib/oka-cyber-agent`, and the empty command-source flag in its systemd runtime directory, `/run/oka-cyber-agent`. Enrollment stores the agent token with mode 0600 and gives it to the `oka-cyber` user. The service uses the copy provided by systemd through `LoadCredential` when it is accessible and reads the original file otherwise.

### Daily updates

The install script writes `oka-cyber-agent-update.timer` and `oka-cyber-agent-update.service` to `/etc/systemd/system` and enables the timer. Once a day, at a random time within six hours after midnight (or at the next boot when the server was off), the service runs `/usr/local/lib/oka-cyber-agent/install.sh --update` as root. It resolves the latest release and downloads its `checksums.txt` (and verifies its cosign signature when `cosign` is installed). When the release's binary has the same SHA-256 as the installed one, it stops there and changes nothing. Otherwise it downloads that release's `install.sh`, checks it against the same `checksums.txt` and runs it, which upgrades the agent exactly like a rerun of the install command: the enrollment is kept, and the service is restarted unless you disabled it. A failed download or check leaves the installed agent untouched. See the runs with `journalctl -u oka-cyber-agent-update`.

The update installs whatever is the latest release on GitHub, so it trusts the release pipeline the same way the install command does. Turn it off with `sudo systemctl disable --now oka-cyber-agent-update.timer` (or install with `--no-auto-update`); rerunning the install script keeps it off. Turn it on again with `sudo systemctl enable --now oka-cyber-agent-update.timer`. Servers without systemd get no timer. The packages have no daily update: upgrade them with your package manager.

### Packages

Every release also ships `.deb` and `.rpm` packages, which install `/usr/bin/oka-cyber-agent`, the same systemd unit and the `oka-cyber` user. Then enroll and start it:

```bash
sudo apt install ./oka-cyber-agent_<version>_amd64.deb        # or: sudo dnf install ./oka-cyber-agent-<version>.x86_64.rpm
sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>
sudo systemctl enable --now oka-cyber-agent
```

Upgrading the package restarts the service on the new binary, and leaves it disabled if you disabled it. Installing the package on a server that is already enrolled enables and starts the service. After `apt remove`, which keeps the enrollment, installing it again starts the service only if it was enabled before the removal.

The package does not install over an agent installed by the install script, whose unit would take precedence over the package's. Run `sudo /usr/local/bin/oka-cyber-agent uninstall` first, which also deletes the enrollment. To keep the enrollment instead, run `sudo systemctl disable --now oka-cyber-agent-update.timer oka-cyber-agent oka-cyber-audit.service` and delete `/usr/local/bin/oka-cyber-agent`, `/etc/systemd/system/oka-cyber-agent.service`, `/etc/systemd/system/oka-cyber-audit.service`, `/etc/systemd/system/oka-cyber-audit.path`, `/etc/systemd/system/oka-cyber-agent-update.timer`, `/etc/systemd/system/oka-cyber-agent-update.service` and `/usr/local/lib/oka-cyber-agent`: the package then enables and starts the service on its first install.

### Verify a release

Every pull request merged into `main` is released once CI passes on it: the next patch version is tagged (`v0.1.0` for the first release) and GitHub Actions builds and publishes it. Minor and major releases come from the Tag workflow, run by hand on `main`. Only that workflow can create tags: it pushes them with a deploy key that no other branch can read. Releases are built by GitHub Actions and `checksums.txt` is signed keylessly with [cosign](https://github.com/sigstore/cosign). Each binary also has an SPDX SBOM.

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

`status` reads the state in `/var/lib/oka-cyber-agent`, which only the service user and root can read, so run it with sudo; it exits with an error rather than show the last reports as never when it cannot read the state. `run --once` needs access to the private agent token, so run it with sudo. A state file it writes as root is given to the owner of `/var/lib/oka-cyber-agent`, so the service can keep using it, and the agent starts from an empty state (with a warning) when its state file is unreadable or corrupt.

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
collect_application_details: true              # set to false to stop reporting application names, git details and runtimes
```

Unknown keys are rejected, so a typo cannot silently turn an option off. The agent token lives in `/etc/oka-cyber-agent/token` (mode 0600, owned by the service user) and is never written to the configuration file or the logs. The running service checks the file and the token every 30 seconds and, when either changed, exits so systemd restarts it with the new settings. An edit that does not load is ignored with a warning in the journal, and the service keeps its current settings.

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

It opens only those file names (and executables, when `collect_go_binaries` is on, and the files listed under [Application details](#application-details), when `collect_application_details` is on). It skips installed dependency trees (`node_modules`, `vendor`, `site-packages` and similar), hidden directories (`.git` and package manager caches such as `.npm` or `.cargo`), the Go module cache, `/proc`, `/sys` and `/dev`. It never follows a symlink below a scan path (the `current` link of a deployment folder, below, is only read to choose a release, never opened): a symlinked lock file is listed with the reason `symlink` without being opened (its target is reported under its own path when a scan path reaches it), and a symlinked directory or executable is skipped. Nothing under `exclude_paths` is ever opened, whatever path leads to it: an excluded directory is also recognised when the walk reaches it under another name (an exclude path or a scan path that goes through a symlink, or a bind mount).

Deployment folders of Forge, Envoyer, Deployer and Capistrano keep one directory per deploy under `releases` and link the live one as `current`. When a directory holds a `releases` directory and a `current` symlink to one of its direct subdirectories (written as `releases/<name>`, or as a full path to that same `releases` directory, for example `/home/forge/example.com/releases/20261108120000`), the agent scans only that release and reports its files under the `current` path (`/home/forge/example.com/current/composer.lock`), so a deploy does not change them. It reads the text of `current` to choose the release and opens `releases` and the release like any other directory, without following a symlink; `max_depth` and `exclude_paths` apply to the `current` path, and an exclude path written with the `releases/<name>` path applies as well. The other releases are not scanned: this keeps the inventory to the code that is live, but a process still running from an older release (a queue worker or daemon not restarted after the deploy, a cron job with a release path) is not covered, so restart them on deploy. A `current` that points anywhere else is not followed, and that directory is scanned like any other, every release under its own path.

Versions are never guessed. Entries without a pinned version are left out, and so are packages that do not come from their registry (a git repository, a URL, a local path or workspace), because their version is not a registry release; an npm alias is reported under the real package name. A file the agent reports no package from is listed on the dashboard with a reason instead: `unresolved_versions` (for example a `requirements.txt` with only unpinned lines), `invalid_entries` (names or versions the server does not accept), `no_lock_file` (a `package.json`, `composer.json`, `Gemfile`, `Pipfile` or `Cargo.toml` without its lock file), `too_large`, `parse_error`, `permission_denied`, `symlink` or `package_limit` (left out to stay within the server limits). Oka Cyber keeps what it last stored for a listed file. It accepts at most 1000 listed files per server. When the count or body size limit requires leaving out skipped files, the agent gives priority to files Oka Cyber has packages stored for (it keeps a digest of their paths in its state file). If some of those records still cannot fit, the agent sends the inventory and logs a warning with the number of files that lost their stored packages. A file the agent reports packages from is never listed, even when some of its entries were left out, so a package removed from it disappears from the inventory and its findings close. When one name appears in several versions in one lock file, one version is reported, because Oka Cyber stores one per name and file: the direct dependency when the file says which one it is (pnpm, Cargo, Bundler, uv, NuGet, Go), the top level (hoisted) install in an npm lock file, the entry a workspace or the project's `package.json` asks for in a yarn lock file when the file shows it, and otherwise the highest version.

## Application details

For each directory it reports a lock file from, the agent also reports what that directory says about the application, so the dashboard can show its name and the commit that is deployed:

| Detail | Read from |
| --- | --- |
| Name | `name` in `composer.json`, otherwise `name` in `package.json` |
| Runtimes | `require.php` in `composer.json` and `engines.node` in `package.json` |
| Repository | `url` of `remote "origin"` in `.git/config` |
| Branch and commit | `.git/HEAD`, then the ref file it names or `.git/packed-refs` |

Only those values are sent, never the rest of the files. Each detail is left out when the directory does not have it: a detached `HEAD` has a commit and no branch, and a directory without `.git` has neither. A deployment folder reports its details under the `current` path, like its lock files. A Go executable reported with `collect_go_binaries` has no details.

The repository address is sent without passwords or tokens. The agent removes userinfo from `http`, `https`, `ssh` and `git` URLs on your server (`https://token@github.com/acme/shop.git` becomes `https://github.com/acme/shop.git`). An scp-style `user@host:path` address keeps its user, as in `git@github.com:acme/shop.git`. The agent omits addresses it cannot clean with certainty, including addresses with a query string, a fragment or an `@` left after the host, other transports and local paths.

Under `.git` the agent opens only `HEAD`, `config`, the one ref file `HEAD` names and `packed-refs`, and only when `.git` is a real directory. A `.git` that is a symlink or a file (a worktree or a submodule) is skipped. The agent never lists `.git`. These files and the two manifests are opened like lock files: without following a symlink, up to `max_file_size`, and never under `exclude_paths`. A file that is missing, too large or cannot be parsed only leaves its details out and never stops the inventory. A value longer than 255 characters (1024 for the repository) is left out, and at most 1000 applications are reported per server, the first ones by path.

Application details use the space left in the 5 MiB inventory after packages and skipped files. When skipped files also need to be trimmed to fit, the agent gives priority to records that keep packages already stored in Oka Cyber.

Set `collect_application_details: false` to stop reading and sending all of this. With `collect_dependency_files: false` there is no lock file to report an application from, so no details are read either.

## Log collection

Log collection is off until an admin turns it on for the server in the dashboard. The dashboard can switch each built in source on or off, never point the agent at another file.

- `auth`: SSH logins and session boundaries, sudo and su use, account, group and password changes, and crontab edits. On a server with a system journal the agent reads them with `journalctl` (run only from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin`, never through the agent's own `PATH`), and accepts an entry only when journald's own record of the sender matches the program it claims to be: the executable (`_EXE`) must be that program in a system directory such as `/usr/sbin`, and it must run as root (`_UID` 0) unless it is a set-user-ID program (`sudo`, `su`, `passwd`, `gpasswd`, `crontab`). An entry another user logged under one of these names, for example with `logger -t sshd`, is dropped. sudo writes the working directory, the variables and the arguments of a command without escaping its own ` ; KEY=` separators, so when a sudo line can be read in more than one way the event leaves out the target user it cannot tell apart, and reports the command as `[unparsed]` unless every reading gives the same executable and number of arguments, rather than report values the user chose. When the journal exists the agent never reads the auth log files, even if it cannot read the journal (the dashboard then shows the journal directory, such as `/var/log/journal`, as `permission_denied`).
- Without a system journal (Alpine, or journald with `Storage=none`), `auth` reads `/var/log/auth.log`, `/var/log/secure` or `/var/log/messages`, plus the cron log. These files do not record who wrote a line, and any local user can add one under any program name (`logger -p auth.info -t sshd ...`). On such a server a local user can make up auth events, and Oka Cyber cannot tell them from real ones. A forged syslog header can claim a real sshd PID, so a forged session close can prematurely end that session's timeline.
- `web`: the nginx and Apache access logs in `/var/log/nginx`, `/var/log/apache2` and `/var/log/httpd`.
- `app`: the files listed in `log_paths` in the configuration file (at most 10, glob patterns such as `/var/www/shop/storage/logs/laravel-*.log` allowed).

The agent reads only regular files and never follows a symlink to a log file. A symlink, FIFO or other special file where a log file is expected is not opened (or, for a FIFO, opened without waiting for a writer, so it cannot stop collection) and is listed on the dashboard as `symlink` or `not_regular_file`. In `log_paths`, the directories you write out literally may be symlinks, because deploy tools such as Envoyer or Deployer link `current/` and `storage/`. A directory a wildcard matches (the `*` in `/var/www/*/storage/logs/laravel.log`) and the log file itself must not be: whoever can write to a log directory could otherwise point the agent at any file it can read. The agent opens these names relative to their parent directory without following a symlink, so one swapped in later is refused as well. A directory you write out is trusted as it is, so if a user can replace it with a symlink, the agent may read the files with matching names in the directory it points to: keep file name patterns specific (`laravel-*.log` rather than `*`).

When a log file the agent follows disappears and is not created again within 5 minutes, it reports `log_file_removed`. That applies to the auth log files and to the files named in full in `log_paths`. Files found through a glob pattern (the web access logs and patterns in `log_paths`) come and go with normal retention, so the agent stops following them without reporting anything once they are gone. A file rotated by renaming it is read to its end, then followed again from the start of the new file. A large backlog in the rotated file is read over several polls (at most 4 MB per file and poll) before the new file, so no line is skipped. When a glob pattern also matches the rotated name (`/var/log/myapp/*` matching `app.log.1`, or `*access*.log` with logrotate's `dateext` and `extension .log`), the agent recognizes the file by its device and inode and goes on from where it stopped reading it, so no line is sent twice and lines still written to the rotated file are read. Compressed rotated files are never read: a glob match ending in `.gz`, `.xz`, `.bz2`, `.zst` or `.zip`, or starting with the signature of one of these formats, is left out without being listed on the dashboard. Saved positions carry the device, inode and a checksum of the bytes just before them, so after a restart the agent also recognizes a file that a rotation renamed while it was stopped, when a glob pattern matches the new name, and goes on from where it stopped. Otherwise it knows the rotated file only while it holds it open: if it restarts before it finished reading it, it follows the new file from its start and the rest of the rotated file is not read.

No log history is uploaded. When a source is switched on, the agent starts at the current end of the journal and of every file, also when it was on before: the lines written while it was off are never read. The same applies whenever it starts following a file that already existed, for example a file added to `log_paths` or a file whose position it lost: it reads only the lines written after that. Only a file created while the agent follows its directory, such as a new daily `laravel-YYYY-MM-DD.log` or a new vhost access log, is read from its start.

On the server, before anything is stored or sent:

- Lines are parsed into security events (SSH logins and session boundaries, sudo, su, account and group changes, password changes, crontab changes, web requests, application errors). Every other line is discarded.
- sudo command arguments are never collected. Many tools take a password through an option of their own or as a plain argument (`ldapmodify -w`, `htpasswd -b`, `redis-cli AUTH`), so a sudo event keeps only the executable sudo ran and its number of arguments, in the `command` field and in the message (`COMMAND=/usr/bin/ldapmodify [5 args]`), and the variables sudo logs become `ENV=[redacted]`. sudo logs a command longer than its line limit in several lines: the later ones (`(command continued) ...`) hold only arguments and are dropped, so the count of such a command covers the arguments of its first line. A sudo line is kept only as far as it is read: sudo's own fields and the failures it logs (incorrect password, not in sudoers, command not allowed). Any other status is replaced by `[unparsed]`, and a line without the fields of a command is dropped.
- SSH logins and PAM session open/close events carry the sshd PID as `session` when present in the syslog header or journald `_PID`. The PID may be reused within or across boots. Alpine needs a PAM-enabled OpenSSH server to emit PAM session boundaries. sudo events keep `tty` and `tsid` when logged, omitting an empty or `unknown` TTY. TSID identifies a sudo I/O log.
- Trusted journal auth events can carry a login session key in `logind_session`, read from `_SYSTEMD_SESSION` or, when that field is absent, from a set `_AUDIT_SESSION`. For an SSH session open, a trusted systemd-logind start entry whose `LEADER` matches the sshd PID in the same boot and within five seconds takes precedence. The collector waits up to five seconds for that match, holding the journal cursor before pending events. Auth events from files and journal events without a session omit `logind_session`. Logind lines never become separate events.
- Authentication events and audit command events carry `fields.boot_id` when the original boot is known, so reused session IDs cannot join timelines across reboots. Journal paths use each entry's trusted `_BOOT_ID`, including older entries replayed after a reboot. Syslog paths use `/proc/sys/kernel/random/boot_id` and the boot start time in `/proc/stat`, only for lines appended after the file was first observed and timestamped after boot and no later than collection. File checkpoints preserve that boundary across agent restarts within a boot. After a reboot, or when provenance is missing or invalid, existing file bytes have no boot ID; they are never assigned the new boot. Aggregation keeps different boots and unknown provenance separate, and spooling and retries keep the original ID.
- Secrets are redacted. One rule decides which names hold a secret, wherever the name appears: a name is secret when, lower cased and without leading dashes and separators (`-`, `_`, `.`), it contains `pass`, `pwd`, `secret`, `token`, `key`, `cred`, `auth`, `cookie`, `session` or `sessid`. A short list of exceptions keeps harmless names readable: words that only contain one of these (`keyboard`, `keyword`, `monkey`, `author`, `passive`, `bypass`, `keyring`, `keyserver`, `keystore`, `pubkey`), names that tell where or what kind of secret rather than holding it (ending in `file`, `path`, `dir`, `sock`, `stdin`, `ttl`, `size`, `length`, `bits` or `type`, such as `--password-file` or `--token-ttl`), and a few gpg, openssl and kubeadm options that name a public key or a key file. A word in front of a secret name never makes it harmless: `require_password=x`, `skip_auth_token=x` and `--no-ask-password x` are redacted. A value that is empty, masked (`***`), a boolean or `null` is kept. Any other value is redacted when the agent cannot tell it is no secret, so `PWD=/...` is redacted like `pwd=x` (sudo events show `PWD=[redacted]`). The value of a secret name is redacted:
  - in query parameters, also in a query nested in another parameter (`next=/reset?token=...`; when the nested query is percent encoded, the whole value), along with parameters whose name contains `sig`, `code`, `jwt`, `mail`, `phone`, `user` or `login`;
  - in a command line an application error quotes (a failed process), for options with one or two dashes (`--password x`, `--api-key=x`, `-storepass x`, `-passin pass:x`), plus `-p` (its next argument, or anything attached to it, since `-pS3cret` cannot be told from a group of flags such as `tar -pczf`), `-a` for `redis-cli`, `-k` for `openssl`, `-b` for `curl` and the password of `-u user:password`; a quoted argument (`sh -c '...'`, `psql -c '...'`) is read as a command too;
  - in every event (application errors, web requests and the auth messages), for `key=value`, `key: value`, `"key": "value"`, PHP `'key' => 'value'` and `[key] => value` pairs, also in JSON escaped inside a JSON string (`{\"password\":\"x\"}`, at any depth), connection strings (`Uid=app;Pwd=x`), headers (`Authorization: Bearer x`, keeping the scheme) and SQL password literals (`PASSWORD 'x'`, `IDENTIFIED BY 'x'`). When the value is a JSON array or object or a PHP array, all of it is redacted up to its matching bracket or parenthesis, also over several lines (`{"authorization":["Bearer x"]}`, `[authorization] => Array ( [0] => Bearer x )`).

  Passwords in URLs (`https://user:password@host`, and a user name that is not a valid one, such as a token), JWT shaped strings and email addresses are redacted anywhere: in the message (for a web request, the request, the referer and the user agent) and in every field of every event. So are SSH user names on failed logins that are not valid user names, since people type passwords into the user prompt. A password may hold `/`, `?`, `#`, `@` and digits unencoded, which cannot be told apart from a port, a path or a query, so the agent redacts everything from the first `:` after `//` to the last `@` before a blank, a quote or `>`: `https://host:8080/p?e=a@b` becomes `https://host:[redacted]@b`. A URL without `@` is kept as it is.
- Noise is condensed: failed SSH logins are counted per IP, user name and minute, with separate counts by boot and login session. Ordinary web requests are counted per IP and minute. A web request is sent in full only when it looks suspicious (status 400 or more, an unusual method, a URI over 512 characters, or a token from [the list](internal/logs/testdata/suspicious_tokens.txt) such as `..`, `${`, `union`, `wp-` or a scanner name). This is decided on the request before redaction, so an attack hidden in a redacted parameter is still sent (with the parameter redacted).
- Messages are cut to 2000 characters, and every event, skipped source and count is brought within what the server accepts before it is sent (an unreadable file whose path is over 1024 characters is listed with its path cut).

Events wait in a spool under `/var/lib/oka-cyber-agent/spool` (at most 100 MB; when full, the oldest events are dropped and counted) and are sent in order every 30 seconds. Audit command events go in batches of their own, sent in order with their own retry delay, so a server that throttles the other events (429 once the daily allowance is used) keeps receiving commands. Read positions are saved in `/var/lib/oka-cyber-agent/logs.json` only after the server acknowledged a batch and every older one, so nothing is lost when the server is unreachable. When the server rejects a request, the agent leaves out only what it names (one event, one unreadable file of the list); a request it rejects without saying why, or as too large, is split in halves. An event is dropped (and counted) only when the server rejects it alone while it accepts an empty request, so a server or proxy that rejects everything never makes the agent drop events. Turning every source off stops the readers and deletes the spool and the positions. If your Oka Cyber does not accept logs yet (it answers `POST /logs` with 404), the agent stops reading, keeps what it already read, and tries again an hour later.

The installer and the packages add the `oka-cyber` user to the `adm` and `systemd-journal` groups when they exist, so it can read the journal and the logs in `/var/log` without root.

### Optional SSH command metadata through auditd

`commands` is off by default and is enabled only by the server setting supplied by the panel; Oka Core #4074 supplies the administrator acknowledgement and privacy disclosures, which must be deployed before enabling it in production. It requires a running auditd, a mutable audit policy, systemd, and a system journal already readable by `oka-cyber`. The agent reads only journald's trusted `_TRANSPORT=audit` entries through its existing journal group membership. It never changes audit.log permissions or grants the main agent capabilities.

An enabled source requests the packaged fixed rule with an empty `/run/oka-cyber-agent/commands.enabled` flag. `oka-cyber-audit.path` starts the separate `oka-cyber-audit.service`, which runs the fixed helper with only `CAP_AUDIT_CONTROL`; root ownership lets it write `/etc/audit/rules.d/oka-cyber-commands.rules` without a DAC override capability. Its systemd sandbox permits writes only to the audit rules directory and its own status directory, hides agent credentials and denies privilege escalation. The runtime flag directory is traversable so the helper needs no access to the private state directory. Flag contents, panel paths, rule text and command arguments are never accepted as input.

The helper loads the compiled-in copy of the shipped template with `auditctl -R` at the fixed path; a key-scoped deletion makes application idempotent. Disabling collection or stopping the agent removes the flag and the helper removes the persistent file and only the running rules keyed `oka_cyber_commands` using `auditctl -D -k`. It never reloads the whole host policy or removes another key. The helper also runs once at boot, before any flag exists, so a persistent rule left by a crash or a shutdown is removed unless collection is turned on again; a flag change during a helper run is applied before it exits. Install, upgrade and uninstall manage the helper units alongside the main unit; uninstall confirms removal before deleting the helper. A package upgrade removes the rule before the new version starts (the restarted agent requests it again), so a downgrade to a version without the helper never leaves it loaded. Immutable audit policies can prevent removal of a running rule and need operator intervention, normally a reboot. A missing helper, missing auditd, inaccessible journal or failed rule application is reported as a skipped `commands` source, with a reason such as `helper_missing`, `auditd_missing`, `journal_permission_denied` or `rule_apply_failed`; `helper_pending` means its acknowledgement has not arrived. The agent rechecks prerequisites every minute and reads the acknowledgement on every poll.

The fixed rules audit successful and failed exec attempts with login UID 0 or at least 1000, excluding the unset UID; the collector emits only successful executions with a PTY in an SSH session proven by a successful audit `USER_LOGIN` or SSH PAM `USER_START` from a system sshd executable with a kernel-supplied root UID and a PTY reported on the login record itself. Cron, services, other login types, missing login/session IDs and the agent's own processes are ignored. The kernel labels an exec with the key of the first matching rule only, so when the host loads its own execve rule first (a CIS profile or a SIEM agent), the records carry that key; the collector accepts any key, because an EXECVE record proves the exec, and applies the same session checks. Open a new interactive SSH login after enabling collection: existing sessions whose login the collector did not observe are deliberately excluded. SSH shell builtins do not exec a process and produce no command event; commands launched by a script inside an interactive SSH session do, and a non-interactive SSH command without a PTY does not. Checkpoints retain only the audit cursor and proven session metadata across agent restarts, never raw records or arguments. No equality with a logind identifier is assumed: the event sends the kernel audit `ses` and the panel correlates it.

A `command` event carries `ses`, `auid`, `cwd`, `executable`, `arg_count` and `tty`, with the login user name when present (otherwise the numeric login UID). `arg_count` excludes argv[0], as with sudo. EXECVE argument strings, hex-encoded strings, split arguments, PROCTITLE and syscall argument registers are discarded without decoding or copying into an event, checkpoint or spool. Metadata still passes through the existing redaction pipeline. Identical metadata is aggregated per boot, audit session and minute; short flushes may split a minute into several count events. Distinct groups are limited to 60 per session and 512 globally per minute, preserving the budget across flushes and counting rejected commands in `dropped_events`. These bounds protect the spool even when executable paths change in a loop. Local spool capacity and upload-age compatibility are unchanged; the 30-day retention policy belongs to the server.

The audit framework also writes raw EXECVE arguments to its own local audit logs when these rules are active. The agent never ships those arguments and does not manage auditd's own storage or retention. Disabling the source removes the Oka rules, not existing local audit records.

## Uninstall

If you used the install script:

```bash
sudo oka-cyber-agent uninstall
```

This turns off the daily update, stops and disables the service and removes the units, `/usr/local/lib/oka-cyber-agent`, `/etc/oka-cyber-agent` (configuration and token), `/var/lib/oka-cyber-agent` (state), the `oka-cyber` user and `/usr/local/bin/oka-cyber-agent`. If the service cannot be stopped, it removes nothing and exits with an error.

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
