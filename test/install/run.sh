#!/bin/sh
# End to end test of install.sh, reruns with the service enabled and disabled, a rerun after a failed enrollment
# and the uninstall command. Runs as root on a disposable host or container with the fake tenant from prepare.sh
# reachable at $TENANT.
set -eu

TENANT="${TENANT:-http://127.0.0.1:8090}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TOKEN="test-enrollment-token"

# shellcheck disable=SC1091
. "$REPO/test/install/lib.sh"

ensure_curl

install_agent() {
	OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --url "$TENANT" --token "$1" --insecure-dev
}

invocation_id() {
	systemctl show -p InvocationID --value oka-cyber-agent
}

check_enabled() {
	systemctl is-enabled --quiet oka-cyber-agent || fail "the service is not enabled $1"
}

check_disabled() {
	! systemctl is-enabled --quiet oka-cyber-agent || fail "the service is enabled $1"
	! systemctl is-active --quiet oka-cyber-agent || fail "the service runs $1"
}

uninstall_agent() {
	/usr/local/bin/oka-cyber-agent uninstall --yes
	for path in /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /var/lib/oka-cyber-agent; do
		[ ! -e "$path" ] || fail "$path still exists after uninstall"
	done
	! getent passwd oka-cyber >/dev/null || fail "the oka-cyber user still exists after uninstall"
	if has_systemd; then
		! systemctl is-active --quiet oka-cyber-agent || fail "the service still runs after uninstall"
	fi
}

echo "== a tampered checksum is refused"
if OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/bad" sh "$REPO/install.sh" --url "$TENANT" --token "$TOKEN" --insecure-dev; then
	fail "install.sh accepted a binary whose checksum does not match"
fi
[ ! -e /usr/local/bin/oka-cyber-agent ] || fail "a binary was installed despite the checksum mismatch"

echo "== install"
enrollments_before=$(stat_of enrollments)
heartbeats_before=$(stat_of heartbeats)
install_agent "$TOKEN"
/usr/local/bin/oka-cyber-agent version | grep -q 'v0.0.0-test' || fail "wrong binary installed"
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"
[ -f /etc/systemd/system/oka-cyber-agent.service ] || fail "the systemd unit was not written"
grep -q '^server_id:' /etc/oka-cyber-agent/config.yaml || fail "config.yaml has no server_id"
check_token_access
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "expected exactly one enrollment"

if has_systemd; then
	echo "== the service is enabled and reports as the oka-cyber user"
	check_enabled "after install"
	check_service_reports "$heartbeats_before"
	for _ in $(seq 1 15); do
		[ "$(stat_of inventories)" -ge 1 ] && break
		sleep 2
	done
	[ "$(stat_of inventories)" -ge 1 ] || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "no inventory from the service"; }
	[ "$(stat_of last_inventory_packages)" -gt 0 ] || fail "the service sent an inventory without packages"
else
	echo "== no systemd: one report as root"
	/usr/local/bin/oka-cyber-agent run --once
	[ "$(stat_of inventories)" -ge 1 ] || fail "no inventory sent"
	[ "$(stat_of last_inventory_packages)" -gt 0 ] || fail "inventory has no packages"
fi
/usr/local/bin/oka-cyber-agent status

echo "== rerun keeps the enrollment and restarts the enabled service"
heartbeats_before=$(stat_of heartbeats)
if has_systemd; then invocation_before=$(invocation_id); fi
install_agent "$TOKEN"
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "rerunning install.sh enrolled again"
if has_systemd; then
	check_enabled "after a rerun"
	check_service_reports "$heartbeats_before"
	[ "$(invocation_id)" != "$invocation_before" ] || fail "rerunning install.sh did not restart the service"
fi

if has_systemd; then
	echo "== rerun keeps a service the admin disabled disabled"
	systemctl disable --now oka-cyber-agent
	install_agent "$TOKEN"
	check_disabled "after a rerun of a disabled service"
fi

echo "== uninstall"
uninstall_agent

echo "== a rerun after a failed enrollment enables and starts the service"
if install_agent "wrong-enrollment-token"; then
	fail "install.sh succeeded with a rejected enrollment token"
fi
[ -f /etc/systemd/system/oka-cyber-agent.service ] || fail "the systemd unit was not written before enrolling"
if has_systemd; then check_disabled "after a failed enrollment"; fi
heartbeats_before=$(stat_of heartbeats)
install_agent "$TOKEN"
if has_systemd; then
	check_enabled "after a rerun that enrolled"
	check_service_reports "$heartbeats_before"
fi
uninstall_agent
echo "PASS"
