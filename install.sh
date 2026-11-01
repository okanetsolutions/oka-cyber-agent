#!/bin/sh
# Oka Cyber Agent installer: https://github.com/okanetsolutions/oka-cyber-agent
#
#   curl -fsSL https://github.com/okanetsolutions/oka-cyber-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://<tenant> --token <enrollment token>
#
# Downloads the binary and checksums.txt from one release, verifies the SHA-256 (and the cosign signature of
# checksums.txt when cosign is installed), installs /usr/local/bin/oka-cyber-agent, creates the oka-cyber
# system user, writes a hardened systemd unit, enrolls the server and starts the service. Rerunning it
# upgrades the binary, keeps the enrollment and restarts the service, unless the admin disabled it.
set -eu

REPOSITORY="okanetsolutions/oka-cyber-agent"
BINARY_PATH="/usr/local/bin/oka-cyber-agent"
CONFIG_DIR="/etc/oka-cyber-agent"
UNIT_PATH="/etc/systemd/system/oka-cyber-agent.service"
SERVICE_USER="oka-cyber"

TENANT_URL=""
ENROLLMENT_TOKEN="${OKA_CYBER_ENROLLMENT_TOKEN:-}"
VERSION=""
INSECURE_DEV=""
DOWNLOAD_URL="${OKA_CYBER_AGENT_DOWNLOAD_URL:-}"
WORK_DIR=""
FIRST_INSTALL=""

say() {
	printf 'oka-cyber-agent: %s\n' "$*"
}

fail() {
	printf 'oka-cyber-agent: error: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<USAGE
Usage: install.sh --url <tenant URL> --token <enrollment token> [--version vX.Y.Z]

  --url        your Oka Cyber tenant URL, for example https://acme.oka.example
  --token      enrollment token from the dashboard (or set OKA_CYBER_ENROLLMENT_TOKEN)
  --version    release to install (default: the latest release)

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
			--version) [ $# -ge 2 ] || fail "--version needs a value"; VERSION="$2"; shift 2 ;;
			--version=*) VERSION="${1#*=}"; shift ;;
			--insecure-dev) INSECURE_DEV="--insecure-dev"; shift ;;
			-h | --help) usage; exit 0 ;;
			*) usage >&2; fail "unknown argument: $1" ;;
		esac
	done
	[ -n "$TENANT_URL" ] || { usage >&2; fail "--url is required"; }
}

require_root() {
	[ "$(id -u)" -eq 0 ] || fail "run as root, for example: curl -fsSL ... | sudo sh -s -- --url ... --token ..."
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

download_and_verify() {
	asset="oka-cyber-agent_linux_$ARCH"
	say "downloading $asset from $RELEASE_URL"
	download "$RELEASE_URL/$asset" "$WORK_DIR/$asset"
	download "$RELEASE_URL/checksums.txt" "$WORK_DIR/checksums.txt"

	if command -v cosign >/dev/null 2>&1 && [ -z "$DOWNLOAD_URL" ]; then
		download "$RELEASE_URL/checksums.txt.sigstore.json" "$WORK_DIR/checksums.txt.sigstore.json"
		verify_signature "$WORK_DIR/checksums.txt" "$WORK_DIR/checksums.txt.sigstore.json"
	fi

	expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$WORK_DIR/checksums.txt")
	[ -n "$expected" ] || fail "$asset is not listed in checksums.txt"
	actual=$(sha256_of "$WORK_DIR/$asset")
	[ "$expected" = "$actual" ] || fail "checksum mismatch for $asset (expected $expected, got $actual)"
	say "verified sha256 $actual"
}

install_binary() {
	install -d -m 0755 "$(dirname "$BINARY_PATH")"
	install -m 0755 "$WORK_DIR/oka-cyber-agent_linux_$ARCH" "$BINARY_PATH.new"
	mv -f "$BINARY_PATH.new" "$BINARY_PATH"
	say "installed $("$BINARY_PATH" version)"
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

has_systemd() {
	[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

write_unit() {
	install -d -m 0755 "$(dirname "$UNIT_PATH")"
	cat >"$UNIT_PATH.new" <<'UNIT'
[Unit]
Description=Oka Cyber Agent
Documentation=https://github.com/okanetsolutions/oka-cyber-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=oka-cyber
Group=oka-cyber
ExecStart=/usr/local/bin/oka-cyber-agent run
LoadCredential=token:/etc/oka-cyber-agent/token
StateDirectory=oka-cyber-agent
StateDirectoryMode=0700
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=77
UMask=0077
Nice=10
IOSchedulingClass=idle
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
}

# A half written enrollment (only one of the two files) goes to enroll, which stops and asks for --force.
enroll() {
	if [ -f "$CONFIG_DIR/token" ] && [ -f "$CONFIG_DIR/config.yaml" ]; then
		say "already enrolled, keeping the existing enrollment"
		return
	fi
	[ -n "$ENROLLMENT_TOKEN" ] || fail "--token is required to enroll this server"
	OKA_CYBER_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" "$BINARY_PATH" enroll --url "$TENANT_URL" $INSECURE_DEV
}

# Taken before write_unit. A host without the unit or without an enrollment has never run the service, so it is
# enabled and started; otherwise the admin's choice stands and a disabled service stays disabled.
detect_first_install() {
	if [ ! -f "$UNIT_PATH" ] || [ ! -f "$CONFIG_DIR/token" ] || [ ! -f "$CONFIG_DIR/config.yaml" ]; then
		FIRST_INSTALL=1
	fi
}

start_service() {
	if ! has_systemd; then
		say "systemd is not running here: the service was not started. Run '$BINARY_PATH run' under your init system."
		return
	fi
	systemctl daemon-reload
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
}

cleanup() {
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}

main() {
	parse_args "$@"
	require_root
	detect_arch
	resolve_release_url
	WORK_DIR=$(mktemp -d)
	trap cleanup EXIT INT TERM
	download_and_verify
	install_binary
	create_user
	detect_first_install
	write_unit
	enroll
	start_service
	say "done. Check it with: $BINARY_PATH status"
}

main "$@"
