#!/bin/sh
# Installs the .deb or .rpm built by GoReleaser, enrolls against the fake tenant and removes the package,
# checking nothing is left behind. Runs as root in a disposable container with the packages in $DIST.
set -eu

TENANT="${TENANT:-http://127.0.0.1:8090}"
DIST="${DIST:-/dist}"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if command -v apt-get >/dev/null 2>&1; then
	apt-get update -qq
	apt-get install -y -qq "$(ls "$DIST"/*_amd64.deb)" >/dev/null
	remove() { apt-get purge -y -qq oka-cyber-agent >/dev/null; }
else
	dnf install -y -q "$(ls "$DIST"/*x86_64.rpm)" >/dev/null
	remove() { dnf remove -y -q oka-cyber-agent >/dev/null; }
fi

echo "== package installed"
[ -x /usr/bin/oka-cyber-agent ] || fail "binary missing"
[ -f /usr/lib/systemd/system/oka-cyber-agent.service ] || fail "unit missing"
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"

echo "== enroll"
OKA_CYBER_ENROLLMENT_TOKEN=test-enrollment-token oka-cyber-agent enroll --url "$TENANT" --insecure-dev
[ -f /etc/oka-cyber-agent/token ] || fail "token missing after enroll"
if oka-cyber-agent uninstall --yes; then
	fail "uninstall must point package installs to the package manager"
fi

echo "== remove the package"
remove
for path in /usr/bin/oka-cyber-agent /usr/lib/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /var/lib/oka-cyber-agent; do
	[ ! -e "$path" ] || fail "$path still exists after removing the package"
done
! getent passwd oka-cyber >/dev/null || fail "the oka-cyber user still exists after removing the package"
echo "PASS"
