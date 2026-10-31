#!/bin/sh
# End to end test of install.sh, a rerun and the uninstall command. Runs as root on a disposable host or
# container with the fake tenant from prepare.sh reachable at $TENANT.
set -eu

TENANT="${TENANT:-http://127.0.0.1:8090}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TOKEN="test-enrollment-token"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

stat_of() {
	curl -fsS "$TENANT/stats" | tr -d ' \n' | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"
}

has_systemd() {
	[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

if ! command -v curl >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y -qq curl >/dev/null
	else
		dnf install -y -q curl >/dev/null
	fi
fi

echo "== a tampered checksum is refused"
if OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/bad" sh "$REPO/install.sh" --url "$TENANT" --token "$TOKEN" --insecure-dev; then
	fail "install.sh accepted a binary whose checksum does not match"
fi
[ ! -e /usr/local/bin/oka-cyber-agent ] || fail "a binary was installed despite the checksum mismatch"

echo "== install"
enrollments_before=$(stat_of enrollments)
OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --url "$TENANT" --token "$TOKEN" --insecure-dev
/usr/local/bin/oka-cyber-agent version | grep -q 'v0.0.0-test' || fail "wrong binary installed"
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"
[ -f /etc/systemd/system/oka-cyber-agent.service ] || fail "the systemd unit was not written"
grep -q '^server_id:' /etc/oka-cyber-agent/config.yaml || fail "config.yaml has no server_id"
[ "$(stat -c '%a %U %G' /etc/oka-cyber-agent/token)" = "600 root root" ] || fail "token is not 0600 root:root"
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "expected exactly one enrollment"

if has_systemd; then
	echo "== the service reports as the oka-cyber user"
	for _ in $(seq 1 30); do
		[ "$(stat_of inventories)" -ge 1 ] && break
		sleep 2
	done
	systemctl is-active --quiet oka-cyber-agent || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "service is not active"; }
	[ "$(ps -o user= -C oka-cyber-agent | head -n 1)" = "oka-cyber" ] || fail "service does not run as oka-cyber"
	[ "$(stat_of heartbeats)" -ge 1 ] || fail "no heartbeat from the service"
	[ "$(stat_of inventories)" -ge 1 ] || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "no inventory from the service"; }
	[ "$(stat_of last_inventory_packages)" -gt 0 ] || fail "the service sent an inventory without packages"
	id -nG oka-cyber | tr ' ' '\n' | grep -qx systemd-journal || fail "oka-cyber is not in the systemd-journal group"

	echo "== an auth event reaches the tenant through journald, redacted"
	sleep 3
	logger -t sshd "Failed password for invalid user Typed-Pa55word! from 203.0.113.77 port 40000 ssh2"
	for _ in $(seq 1 30); do
		curl -fsS "$TENANT/log-events" | grep -q '203.0.113.77' && break
		sleep 2
	done
	events=$(curl -fsS "$TENANT/log-events")
	echo "$events" | grep -q '"kind":"ssh_login_failed"' || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "the failed SSH login was not shipped"; }
	echo "$events" | grep -q '203.0.113.77' || fail "the event has no source IP"
	if echo "$events" | grep -q 'Typed-Pa55word'; then
		fail "a password typed as a user name was shipped"
	fi
else
	echo "== no systemd: one report as root"
	/usr/local/bin/oka-cyber-agent run --once
	[ "$(stat_of inventories)" -ge 1 ] || fail "no inventory sent"
	[ "$(stat_of last_inventory_packages)" -gt 0 ] || fail "inventory has no packages"
fi
/usr/local/bin/oka-cyber-agent status

echo "== rerun keeps the enrollment"
OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --url "$TENANT" --token "$TOKEN" --insecure-dev
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "rerunning install.sh enrolled again"

echo "== uninstall"
/usr/local/bin/oka-cyber-agent uninstall --yes
for path in /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /var/lib/oka-cyber-agent; do
	[ ! -e "$path" ] || fail "$path still exists after uninstall"
done
! getent passwd oka-cyber >/dev/null || fail "the oka-cyber user still exists after uninstall"
if has_systemd; then
	! systemctl is-active --quiet oka-cyber-agent || fail "the service still runs after uninstall"
fi
echo "PASS"
