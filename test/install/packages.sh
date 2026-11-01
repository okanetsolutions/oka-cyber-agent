#!/bin/sh
# Installs the .deb or .rpm built by GoReleaser and enrolls against the fake tenant, then checks how the
# maintainer scripts treat the service: a first install on an enrolled host enables and starts it, an upgrade
# restarts it but keeps it disabled when the admin disabled it, and on deb a reinstall after "remove" enables
# it again only if it was enabled. Finally it erases the package and checks nothing is left behind. Runs as root
# in a disposable container or host with the packages in $DIST; the service checks need systemd.
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

check_disabled() {
	has_systemd || return 0
	! systemctl is-enabled --quiet oka-cyber-agent || fail "the service is enabled $1"
	! systemctl is-active --quiet oka-cyber-agent || fail "the service runs $1"
}

admin_disable() {
	if has_systemd; then systemctl disable --now oka-cyber-agent; fi
}

admin_enable() {
	before=$(stat_of_systemd heartbeats)
	if has_systemd; then systemctl enable --now oka-cyber-agent; fi
	check_enabled_and_reporting "$before" "after enable --now"
}

# erase_keeping_enrollment erases the package but skips the script that deletes the enrollment and the user, which
# leaves an enrolled host without the package, as if it was enrolled before the package was installed.
if command -v apt-get >/dev/null 2>&1; then
	deb="$(ls "$DIST"/*_amd64.deb)"
	apt-get update -qq
	install_package() { apt-get install -y -qq "$deb" >/dev/null; }
	upgrade_package() { apt-get install -y -qq --reinstall "$deb" >/dev/null; }
	remove_package() { apt-get remove -y -qq oka-cyber-agent >/dev/null; }
	erase_keeping_enrollment() {
		printf '#!/bin/sh\nexit 0\n' >/var/lib/dpkg/info/oka-cyber-agent.postrm
		dpkg --purge oka-cyber-agent >/dev/null
	}
	erase_package() { apt-get purge -y -qq oka-cyber-agent >/dev/null; }
else
	rpm="$(ls "$DIST"/*x86_64.rpm)"
	install_package() { dnf install -y -q "$rpm" >/dev/null; }
	upgrade_package() { dnf reinstall -y -q "$rpm" >/dev/null; }
	remove_package() { :; }
	erase_keeping_enrollment() { rpm -e --nopostun oka-cyber-agent; }
	erase_package() { dnf remove -y -q oka-cyber-agent >/dev/null; }
fi

if has_systemd; then
	ensure_curl
fi

echo "== first install on a host that is not enrolled"
install_package
[ -x /usr/bin/oka-cyber-agent ] || fail "binary missing"
[ -f /usr/lib/systemd/system/oka-cyber-agent.service ] || fail "unit missing"
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"
check_disabled "before enroll"

echo "== enroll"
OKA_CYBER_ENROLLMENT_TOKEN=test-enrollment-token oka-cyber-agent enroll --url "$TENANT" --insecure-dev
[ -f /etc/oka-cyber-agent/token ] || fail "token missing after enroll"
check_token_access
if oka-cyber-agent uninstall --yes; then
	fail "uninstall must point package installs to the package manager"
fi
echo "== the service reports as the oka-cyber user"
admin_enable

echo "== upgrade restarts an enabled service"
before=$(stat_of_systemd heartbeats)
upgrade_package
check_token_access
check_enabled_and_reporting "$before" "after an upgrade"

echo "== upgrade keeps a service the admin disabled disabled"
admin_disable
upgrade_package
check_disabled "after an upgrade of a disabled service"
admin_enable

if command -v apt-get >/dev/null 2>&1; then
	echo "== remove keeps the enrollment, reinstall starts the service again"
	remove_package
	[ -f /etc/oka-cyber-agent/token ] || fail "remove deleted the token"
	[ ! -e /usr/bin/oka-cyber-agent ] || fail "remove kept the binary"
	check_disabled "after remove"
	before=$(stat_of_systemd heartbeats)
	install_package
	[ ! -e /etc/oka-cyber-agent/package-removed ] || fail "reinstall kept the remove marker"
	check_token_access
	check_enabled_and_reporting "$before" "after a reinstall"

	echo "== remove and reinstall keep a service the admin disabled disabled"
	admin_disable
	remove_package
	install_package
	check_disabled "after a reinstall of a disabled service"
	admin_enable
fi

echo "== first install on an enrolled host starts the service"
admin_disable
erase_keeping_enrollment
[ ! -e /usr/bin/oka-cyber-agent ] || fail "erase kept the binary"
[ -f /etc/oka-cyber-agent/token ] || fail "token missing before the first install"
before=$(stat_of_systemd heartbeats)
install_package
check_token_access
check_enabled_and_reporting "$before" "after a first install on an enrolled host"

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
