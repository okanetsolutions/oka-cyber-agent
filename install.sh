#!/bin/sh
# Oka Cyber Agent installer: https://github.com/okanetsolutions/oka-cyber-agent
#
#   curl -fsSL https://github.com/okanetsolutions/oka-cyber-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://<tenant> --token <enrollment token>
#
# Downloads the binary, install.sh and checksums.txt from one release, verifies the SHA-256 (and the cosign
# signature of checksums.txt when cosign is installed), installs /usr/local/bin/oka-cyber-agent, creates the
# oka-cyber system user, writes a hardened systemd unit, enrolls the server and starts the service. Rerunning
# it upgrades the binary, keeps the enrollment and restarts the service, unless the admin disabled it.
#
# It also keeps the release's install.sh in /usr/local/lib/oka-cyber-agent and turns on a daily systemd timer
# that runs it with --update: when the latest release's binary differs from the installed one, that release's
# install.sh, verified against the release's checksums.txt, upgrades the agent the same way a rerun does.
set -eu

REPOSITORY="okanetsolutions/oka-cyber-agent"
BINARY_PATH="/usr/local/bin/oka-cyber-agent"
CONFIG_DIR="/etc/oka-cyber-agent"
UNIT_PATH="/etc/systemd/system/oka-cyber-agent.service"
LIB_DIR="/usr/local/lib/oka-cyber-agent"
UPDATE_SERVICE="oka-cyber-agent-update.service"
UPDATE_TIMER="oka-cyber-agent-update.timer"
SERVICE_USER="oka-cyber"

TENANT_URL=""
ENROLLMENT_TOKEN="${OKA_CYBER_ENROLLMENT_TOKEN:-}"
TOKEN_FILE=""
VERSION=""
INSECURE_DEV=""
DOWNLOAD_URL="${OKA_CYBER_AGENT_DOWNLOAD_URL:-}"
WORK_DIR=""
FIRST_INSTALL=""
AUTO_UPDATE=1
UPDATE=""
TIMER_EXISTED=""
RELEASE_UPDATES=""

say() {
	printf 'oka-cyber-agent: %s\n' "$*"
}

fail() {
	printf 'oka-cyber-agent: error: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<USAGE
Usage: install.sh --url <tenant URL> --token <enrollment token> [--version vX.Y.Z] [--no-auto-update]
       install.sh --url <tenant URL> --token-file <file>
       install.sh --update

  --url             your Oka Cyber tenant URL, for example https://acme.oka.example (not needed once enrolled)
  --token           enrollment token from the dashboard (or set OKA_CYBER_ENROLLMENT_TOKEN)
  --token-file      file that holds the enrollment token, so other users of this server cannot read it in the process list
  --version         release to install (default: the latest release)
  --no-auto-update  turn the daily update off (turn it on again with: systemctl enable --now $UPDATE_TIMER)
  --update          install the latest release if its binary differs from the installed one (the timer runs this)

Uninstall with: sudo oka-cyber-agent uninstall
USAGE
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--url) [ $# -ge 2 ] || fail "--url needs a value"; TENANT_URL="$2"; shift 2 ;;
			--url=*) TENANT_URL="${1#*=}"; shift ;;
			--token) [ $# -ge 2 ] || fail "--token needs a value"; ENROLLMENT_TOKEN="$2"; shift 2 ;;
			--token=*) ENROLLMENT_TOKEN="${1#*=}"; shift ;;
			--token-file) [ $# -ge 2 ] || fail "--token-file needs a value"; TOKEN_FILE="$2"; shift 2 ;;
			--token-file=*) TOKEN_FILE="${1#*=}"; shift ;;
			--version) [ $# -ge 2 ] || fail "--version needs a value"; VERSION="$2"; shift 2 ;;
			--version=*) VERSION="${1#*=}"; shift ;;
			--insecure-dev) INSECURE_DEV="--insecure-dev"; shift ;;
			--no-auto-update) AUTO_UPDATE=""; shift ;;
			--update) UPDATE=1; shift ;;
			-h | --help) usage; exit 0 ;;
			*) usage >&2; fail "unknown argument: $1" ;;
		esac
	done
}

is_enrolled() {
	[ -f "$CONFIG_DIR/token" ] && [ -f "$CONFIG_DIR/config.yaml" ]
}

require_root() {
	[ "$(id -u)" -eq 0 ] || fail "run as root, for example: curl -fsSL ... | sudo sh -s -- --url ... --token ..."
}

# A package install has its unit in /usr/lib/systemd/system, which the unit this script writes to /etc/systemd/system
# would shadow, so the package's own binary would never run again. A deb removed but not purged still owns the
# enrollment and its purge would delete it under this script's install.
refuse_package_install() {
	package=""
	if [ -e /usr/bin/oka-cyber-agent ]; then
		package="/usr/bin/oka-cyber-agent"
	elif command -v dpkg-query >/dev/null 2>&1; then
		case "$(dpkg-query -W -f='${Status}' oka-cyber-agent 2>/dev/null || true)" in
			"" | *" not-installed") ;;
			*) package="the oka-cyber-agent deb package" ;;
		esac
	fi
	if [ -z "$package" ] && command -v rpm >/dev/null 2>&1 && rpm -q oka-cyber-agent >/dev/null 2>&1; then
		package="the oka-cyber-agent rpm package"
	fi
	[ -z "$package" ] || fail "this server already has the agent from a package ($package). Upgrade it with your package manager (apt install --only-upgrade oka-cyber-agent, or dnf upgrade oka-cyber-agent), or remove it completely (apt purge oka-cyber-agent, or dnf remove oka-cyber-agent) before you use install.sh"
}

detect_arch() {
	[ "$(uname -s)" = "Linux" ] || fail "only Linux is supported"
	case "$(uname -m)" in
		x86_64 | amd64) ARCH="amd64" ;;
		aarch64 | arm64) ARCH="arm64" ;;
		*) fail "unsupported architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
	esac
}

download() {
	protocols="=https"
	[ -z "$DOWNLOAD_URL" ] || protocols="=https,http"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto "$protocols" --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		fail "curl or wget is required"
	fi
}

# The release is resolved once, so the binary and checksums.txt always come from the same release.
resolve_release_url() {
	if [ -n "$DOWNLOAD_URL" ]; then
		RELEASE_URL="${DOWNLOAD_URL%/}"
		return
	fi
	if [ -z "$VERSION" ]; then
		if command -v curl >/dev/null 2>&1; then
			latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPOSITORY/releases/latest")
		else
			latest=$(wget -q -S --spider --max-redirect=5 "https://github.com/$REPOSITORY/releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r')
		fi
		VERSION="${latest##*/}"
		case "$VERSION" in
			v[0-9]*) ;;
			*) fail "could not resolve the latest release (got: $latest)" ;;
		esac
	fi
	RELEASE_URL="https://github.com/$REPOSITORY/releases/download/$VERSION"
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
	else
		fail "sha256sum, shasum or openssl is required to verify the download"
	fi
}

# Releases are signed by cosign v3, whose sigstore bundle (v0.3) cosign v2 cannot read. That failure says
# nothing about the release, so it asks for a newer cosign instead of reporting a bad signature.
verify_signature() {
	if cosign verify-blob \
		--bundle "$2" \
		--certificate-identity-regexp "^https://github.com/$REPOSITORY/\.github/workflows/release\.yml@refs/tags/v" \
		--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
		"$1" >/dev/null 2>"$WORK_DIR/cosign.log"; then
		say "verified the cosign signature of checksums.txt"
		return
	fi
	sed 's/^/  cosign: /' "$WORK_DIR/cosign.log" >&2
	cosign_version=$(cosign version 2>/dev/null | sed -n 's/^GitVersion: *//p' | head -n 1)
	case "$cosign_version" in
		v[0-2].* | [0-2].*) old_cosign=1 ;;
		*) old_cosign="" ;;
	esac
	if [ -n "$old_cosign" ] || grep -q -i -e 'bundle does not contain' -e 'unsupported bundle' -e 'unknown bundle' -e 'unknown field' "$WORK_DIR/cosign.log"; then
		fail "cosign ${cosign_version:-(unknown version)} cannot read the signature bundle of this release. Upgrade cosign to v3 or newer (https://docs.sigstore.dev/cosign/system_config/installation/) and run the installer again"
	fi
	fail "the cosign signature of checksums.txt does not verify: the release files may have been tampered with, do not install them"
}

# checksums.txt lists the binaries and install.sh of the release, so its signature covers both.
fetch_checksums() {
	download "$RELEASE_URL/checksums.txt" "$WORK_DIR/checksums.txt"
	if command -v cosign >/dev/null 2>&1 && [ -z "$DOWNLOAD_URL" ]; then
		download "$RELEASE_URL/checksums.txt.sigstore.json" "$WORK_DIR/checksums.txt.sigstore.json"
		verify_signature "$WORK_DIR/checksums.txt" "$WORK_DIR/checksums.txt.sigstore.json"
	fi
}

listed_checksum() {
	awk -v name="$1" '$2 == name || $2 == "*" name { print $1 }' "$WORK_DIR/checksums.txt"
}

fetch_verified() {
	say "downloading $1 from $RELEASE_URL"
	download "$RELEASE_URL/$1" "$WORK_DIR/$1"
	expected=$(listed_checksum "$1")
	[ -n "$expected" ] || fail "$1 is not listed in checksums.txt"
	actual=$(sha256_of "$WORK_DIR/$1")
	[ "$expected" = "$actual" ] || fail "checksum mismatch for $1 (expected $expected, got $actual)"
	say "verified sha256 of $1: $actual"
}

download_and_verify() {
	fetch_checksums
	fetch_verified "oka-cyber-agent_linux_$ARCH"
	fetch_verified install.sh
}

# Releases older than the daily update reject --update, and their binary's uninstall does not know the timer, so
# their install.sh is not kept and the update units are removed (see write_unit).
release_has_updates() {
	sh "$WORK_DIR/install.sh" --update --help >/dev/null 2>&1
}

install_binary() {
	install -d -m 0755 "$(dirname "$BINARY_PATH")"
	install -m 0755 "$WORK_DIR/oka-cyber-agent_linux_$ARCH" "$BINARY_PATH.new"
	mv -f "$BINARY_PATH.new" "$BINARY_PATH"
	say "installed $("$BINARY_PATH" version)"
	if release_has_updates; then
		RELEASE_UPDATES=1
		install -d -m 0755 "$LIB_DIR"
		install -m 0755 "$WORK_DIR/install.sh" "$LIB_DIR/install.sh.new"
		mv -f "$LIB_DIR/install.sh.new" "$LIB_DIR/install.sh"
	fi
}

create_user() {
	if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
		return
	fi
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --no-create-home --home-dir /var/lib/oka-cyber-agent --shell "$nologin" "$SERVICE_USER"
	elif command -v adduser >/dev/null 2>&1; then
		addgroup -S "$SERVICE_USER" 2>/dev/null || true
		adduser -S -D -H -h /var/lib/oka-cyber-agent -s "$nologin" -G "$SERVICE_USER" "$SERVICE_USER"
	else
		fail "useradd or adduser is required to create the $SERVICE_USER user"
	fi
	say "created the $SERVICE_USER system user"
}

# Log collection reads auth logs and the journal without root: Debian family logs are readable by the adm
# group and the journal by systemd-journal. On RHEL family systems /var/log/secure is root only, so the
# agent reads the journal there. Run on every install, so an upgrade from a version without log collection
# gets the groups too; a running service picks them up when start_service restarts it.
grant_log_access() {
	for group in adm systemd-journal; do
		if getent group "$group" >/dev/null 2>&1 && ! id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx "$group"; then
			usermod -a -G "$group" "$SERVICE_USER" 2>/dev/null || addgroup "$SERVICE_USER" "$group" 2>/dev/null || true
		fi
	done
}

has_systemd() {
	[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

write_unit() {
	install -d -m 0755 "$(dirname "$UNIT_PATH")"
	cat >"$UNIT_PATH.new" <<'UNIT'
[Unit]
Description=Oka Cyber Agent
Documentation=https://github.com/okanetsolutions/oka-cyber-agent
After=network-online.target oka-cyber-audit.path
Wants=network-online.target oka-cyber-audit.path

[Service]
Type=simple
User=oka-cyber
Group=oka-cyber
ExecStart=/usr/local/bin/oka-cyber-agent run
LoadCredential=token:/etc/oka-cyber-agent/token
RuntimeDirectory=oka-cyber-agent
RuntimeDirectoryMode=0755
StateDirectory=oka-cyber-agent
StateDirectoryMode=0700
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=77
UMask=0077
Nice=10
IOSchedulingClass=idle
MemoryMax=1G
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT
	chmod 0644 "$UNIT_PATH.new"
	mv -f "$UNIT_PATH.new" "$UNIT_PATH"
	install -d -m 0755 "/etc/systemd/system"
	cat >"/etc/systemd/system/oka-cyber-audit.service.new" <<'AUDIT_SERVICE'
[Unit]
Description=Oka Cyber fixed command audit rule
After=auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/oka-cyber-agent audit-rules
User=root
Group=root
RuntimeDirectory=oka-cyber-audit
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
UMask=0022
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_AUDIT_CONTROL
AmbientCapabilities=CAP_AUDIT_CONTROL
ProtectSystem=strict
ReadWritePaths=-/etc/audit/rules.d /run/oka-cyber-audit
ProtectHome=yes
InaccessiblePaths=-/etc/oka-cyber-agent
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
AUDIT_SERVICE
	chmod 0644 "/etc/systemd/system/oka-cyber-audit.service.new"
	mv -f "/etc/systemd/system/oka-cyber-audit.service.new" "/etc/systemd/system/oka-cyber-audit.service"

	install -d -m 0755 "/etc/systemd/system"
	cat >"/etc/systemd/system/oka-cyber-audit.path.new" <<'AUDIT_PATH'
[Unit]
Description=Watch Oka Cyber command collection opt-in

[Path]
PathChanged=/run/oka-cyber-agent/commands.enabled
Unit=oka-cyber-audit.service

[Install]
WantedBy=multi-user.target
AUDIT_PATH
	chmod 0644 "/etc/systemd/system/oka-cyber-audit.path.new"
	mv -f "/etc/systemd/system/oka-cyber-audit.path.new" "/etc/systemd/system/oka-cyber-audit.path"

	install -d -m 0755 "/usr/share/oka-cyber-agent"
	cat >"/usr/share/oka-cyber-agent/commands.rules.new" <<'AUDIT_RULES'
# Owned by Oka Cyber Agent. The helper replaces only the rules with this key.
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k oka_cyber_commands
-a always,exit -F arch=b64 -S execve,execveat -F auid=0 -k oka_cyber_commands
-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k oka_cyber_commands
-a always,exit -F arch=b32 -S execve,execveat -F auid=0 -k oka_cyber_commands
AUDIT_RULES
	chmod 0644 "/usr/share/oka-cyber-agent/commands.rules.new"
	mv -f "/usr/share/oka-cyber-agent/commands.rules.new" "/usr/share/oka-cyber-agent/commands.rules"

	if [ -z "$RELEASE_UPDATES" ]; then
		remove_updates
		return
	fi
	cat >"/etc/systemd/system/$UPDATE_SERVICE.new" <<'UPDATE_SERVICE'
[Unit]
Description=Oka Cyber Agent update to the latest release
Documentation=https://github.com/okanetsolutions/oka-cyber-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh /usr/local/lib/oka-cyber-agent/install.sh --update
PrivateTmp=yes
TimeoutStartSec=15min
UPDATE_SERVICE
	chmod 0644 "/etc/systemd/system/$UPDATE_SERVICE.new"
	mv -f "/etc/systemd/system/$UPDATE_SERVICE.new" "/etc/systemd/system/$UPDATE_SERVICE"

	cat >"/etc/systemd/system/$UPDATE_TIMER.new" <<'UPDATE_TIMER'
[Unit]
Description=Daily Oka Cyber Agent update
Documentation=https://github.com/okanetsolutions/oka-cyber-agent

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
UPDATE_TIMER
	chmod 0644 "/etc/systemd/system/$UPDATE_TIMER.new"
	mv -f "/etc/systemd/system/$UPDATE_TIMER.new" "/etc/systemd/system/$UPDATE_TIMER"
}

remove_updates() {
	if has_systemd && [ -e "/etc/systemd/system/$UPDATE_TIMER" ]; then
		systemctl disable --now "$UPDATE_TIMER" >/dev/null 2>&1 || true
	fi
	rm -f "/etc/systemd/system/$UPDATE_TIMER" "/etc/systemd/system/$UPDATE_SERVICE"
	rm -rf "$LIB_DIR"
}

# A half written enrollment (only one of the two files) goes to enroll, which stops and asks for --force.
enroll() {
	if is_enrolled; then
		say "already enrolled, keeping the existing enrollment"
		return
	fi
	if [ -n "$TOKEN_FILE" ]; then
		[ -r "$TOKEN_FILE" ] || fail "cannot read the enrollment token file $TOKEN_FILE"
		ENROLLMENT_TOKEN=$(tr -d '\r\n' <"$TOKEN_FILE")
	fi
	[ -n "$ENROLLMENT_TOKEN" ] || fail "--token or --token-file is required to enroll this server"
	OKA_CYBER_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" "$BINARY_PATH" enroll --url "$TENANT_URL" $INSECURE_DEV
}

# Taken before write_unit. A host without the unit or without an enrollment has never run the service, so it and
# the update timer are enabled and started; otherwise the admin's choice stands and a disabled service or timer
# stays disabled.
detect_first_install() {
	if [ ! -f "$UNIT_PATH" ] || ! is_enrolled; then
		FIRST_INSTALL=1
	fi
	if [ -z "$FIRST_INSTALL" ] && [ -f "/etc/systemd/system/$UPDATE_TIMER" ]; then
		TIMER_EXISTED=1
	fi
}

start_service() {
	if ! has_systemd; then
		say "systemd is not running here: the service was not started and there are no daily updates. Run '$BINARY_PATH run' under your init system."
		return
	fi
	systemctl daemon-reload
	# The helper also runs once at boot, where no flag exists yet, so a rule kept in rules.d by a crash or a
	# shutdown is removed even when commands were turned off meanwhile or the agent is disabled.
	systemctl enable oka-cyber-audit.service >/dev/null 2>&1
	if [ -n "$FIRST_INSTALL" ]; then
		systemctl enable oka-cyber-agent.service >/dev/null 2>&1
		systemctl restart oka-cyber-agent.service
		say "service enabled and started: systemctl status oka-cyber-agent"
	elif systemctl is-enabled --quiet oka-cyber-agent.service || systemctl is-active --quiet oka-cyber-agent.service; then
		systemctl restart oka-cyber-agent.service
		say "service restarted on the new binary: systemctl status oka-cyber-agent"
	else
		say "the service is disabled, so it was left disabled and stopped. Enable and start it with: systemctl enable --now oka-cyber-agent"
	fi
	configure_updates
}

# A timer the admin disabled stays disabled, like the service. The update run itself reruns this script, so it
# never stops or restarts the timer (or the update service it runs in).
configure_updates() {
	if [ -z "$RELEASE_UPDATES" ]; then
		say "release ${VERSION:-at $RELEASE_URL} has no daily update, so there is none. Install a newer release to get it."
	elif [ -z "$AUTO_UPDATE" ]; then
		systemctl disable --now "$UPDATE_TIMER" >/dev/null 2>&1 || true
		say "daily updates are off. Turn them on with: systemctl enable --now $UPDATE_TIMER"
	elif [ -z "$TIMER_EXISTED" ]; then
		if ! systemctl enable --now "$UPDATE_TIMER" >/dev/null 2>&1; then
			say "warning: the daily update timer could not be enabled. See: systemctl status $UPDATE_TIMER"
			return
		fi
		say "daily updates are on: systemctl list-timers $UPDATE_TIMER. Turn them off with: systemctl disable --now $UPDATE_TIMER"
	elif systemctl is-enabled --quiet "$UPDATE_TIMER"; then
		systemctl start "$UPDATE_TIMER"
	else
		say "daily updates are disabled, so they stay off. Turn them on with: systemctl enable --now $UPDATE_TIMER"
	fi
}

# Run daily by the timer. It installs nothing itself: when the latest release's binary differs from the installed
# one, it runs that release's install.sh, verified against the same checksums.txt, which upgrades like a rerun.
update() {
	if ! is_enrolled; then
		say "this server is not enrolled: nothing to update"
		return
	fi
	# Without the binary the script install was removed, for example to replace it with the package keeping the
	# enrollment: the update must not install it again.
	if [ ! -f "$BINARY_PATH" ]; then
		say "$BINARY_PATH is not installed: nothing to update"
		return
	fi
	detect_arch
	resolve_release_url
	WORK_DIR=$(mktemp -d)
	trap cleanup EXIT INT TERM
	fetch_checksums
	expected=$(listed_checksum "oka-cyber-agent_linux_$ARCH")
	[ -n "$expected" ] || fail "oka-cyber-agent_linux_$ARCH is not listed in checksums.txt"
	if [ "$(sha256_of "$BINARY_PATH")" = "$expected" ]; then
		say "already up to date ($("$BINARY_PATH" version))"
		return
	fi
	fetch_verified install.sh
	set --
	[ -z "$VERSION" ] || set -- --version "$VERSION"
	say "updating to ${VERSION:-the release at $RELEASE_URL}"
	sh "$WORK_DIR/install.sh" "$@"
}

cleanup() {
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}

main() {
	parse_args "$@"
	require_root
	refuse_package_install
	if [ -n "$UPDATE" ]; then
		update
		return
	fi
	if [ -z "$TENANT_URL" ] && ! is_enrolled; then
		usage >&2
		fail "--url is required to enroll this server"
	fi
	detect_arch
	resolve_release_url
	WORK_DIR=$(mktemp -d)
	trap cleanup EXIT INT TERM
	download_and_verify
	install_binary
	create_user
	grant_log_access
	detect_first_install
	write_unit
	enroll
	start_service
	say "done. Check it with: $BINARY_PATH status"
}

main "$@"
