#!/bin/sh
# Installs the .deb or .rpm built by GoReleaser, enrolls against the fake tenant, upgrades (reinstalls) the
# package, on deb removes and reinstalls it, then purges or erases it, checking nothing is left behind. Runs as
# root in a disposable container or host with the packages in $DIST. Under systemd it also checks that the
# service reports and stays enabled across the upgrade and the reinstall.
set -eu

TENANT="${TENANT:-http://127.0.0.1:8090}"
DIST="${DIST:-/dist}"

# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

# The service only runs under systemd; without it (and without curl) the counts are not needed.
stat_of_systemd() {
	if has_systemd; then stat_of "$1"; else echo 0; fi
}

# $1 is the heartbeat count before the step that should leave the service enabled and running.
check_enabled_and_reporting() {
	has_systemd || return 0
	systemctl is-enabled --quiet oka-cyber-agent || fail "the service is not enabled $2"
	check_service_reports "$1"
}

if command -v apt-get >/dev/null 2>&1; then
	deb="$(ls "$DIST"/*_amd64.deb)"
	apt-get update -qq
	install_package() { apt-get install -y -qq "$deb" >/dev/null; }
	upgrade_package() { apt-get install -y -qq --reinstall "$deb" >/dev/null; }
	remove_package() { apt-get remove -y -qq oka-cyber-agent >/dev/null; }
	erase_package() { apt-get purge -y -qq oka-cyber-agent >/dev/null; }
else
	rpm="$(ls "$DIST"/*x86_64.rpm)"
	install_package() { dnf install -y -q "$rpm" >/dev/null; }
	upgrade_package() { dnf reinstall -y -q "$rpm" >/dev/null; }
	remove_package() { :; }
	erase_package() { dnf remove -y -q oka-cyber-agent >/dev/null; }
fi

if has_systemd; then
	ensure_curl
fi

echo "== package installed"
install_package
[ -x /usr/bin/oka-cyber-agent ] || fail "binary missing"
[ -f /usr/lib/systemd/system/oka-cyber-agent.service ] || fail "unit missing"
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"

echo "== enroll"
OKA_CYBER_ENROLLMENT_TOKEN=test-enrollment-token oka-cyber-agent enroll --url "$TENANT" --insecure-dev
[ -f /etc/oka-cyber-agent/token ] || fail "token missing after enroll"
check_token_access
if oka-cyber-agent uninstall --yes; then
	fail "uninstall must point package installs to the package manager"
fi
if has_systemd; then
	echo "== the service reports as the oka-cyber user"
	before=$(stat_of heartbeats)
	systemctl enable --now oka-cyber-agent
	check_enabled_and_reporting "$before" "after enable --now"
fi

echo "== upgrade keeps the service enabled"
before=$(stat_of_systemd heartbeats)
upgrade_package
check_token_access
check_enabled_and_reporting "$before" "after an upgrade"

if command -v apt-get >/dev/null 2>&1; then
	echo "== remove keeps the enrollment, reinstall starts the service again"
	remove_package
	[ -f /etc/oka-cyber-agent/token ] || fail "remove deleted the token"
	[ ! -e /usr/bin/oka-cyber-agent ] || fail "remove kept the binary"
	if has_systemd; then
		! systemctl is-active --quiet oka-cyber-agent || fail "the service still runs after remove"
	fi
	before=$(stat_of_systemd heartbeats)
	install_package
	check_token_access
	check_enabled_and_reporting "$before" "after a reinstall"
fi

echo "== erase the package"
erase_package
for path in /usr/bin/oka-cyber-agent /usr/lib/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /var/lib/oka-cyber-agent; do
	[ ! -e "$path" ] || fail "$path still exists after erasing the package"
done
! getent passwd oka-cyber >/dev/null || fail "the oka-cyber user still exists after erasing the package"
if has_systemd; then
	! systemctl is-active --quiet oka-cyber-agent || fail "the service still runs after erasing the package"
fi
echo "PASS"
