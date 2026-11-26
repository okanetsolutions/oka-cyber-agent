#!/bin/sh
# End to end test of install.sh, reruns with the service enabled and disabled, the daily update (no new release,
# a tampered one and a new one through the timer's service, the timer kept off), a rerun after a failed enrollment,
# an install under a hardened umask, the refusal to install over a package and the uninstall command. Runs as root on a disposable host or container with the fake tenant from prepare.sh
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

# update_agent <release dir> runs the daily update the way the timer does, against a fake tenant release.
update_agent() {
	OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/$1" sh /usr/local/lib/oka-cyber-agent/install.sh --update
}

check_version() {
	/usr/local/bin/oka-cyber-agent version | grep -q "$1" || fail "the installed binary is not $1 $2"
}

# prepare.sh ends each release's install.sh with a comment naming the release.
check_installer() {
	[ "$(tail -n 1 /usr/local/lib/oka-cyber-agent/install.sh)" = "# $1" ] || fail "the install.sh of $1 was not kept for the daily update $2"
}

check_updates_on() {
	systemctl is-enabled --quiet oka-cyber-agent-update.timer || fail "the update timer is not enabled $1"
	systemctl is-active --quiet oka-cyber-agent-update.timer || fail "the update timer is not active $1"
}

check_updates_off() {
	! systemctl is-enabled --quiet oka-cyber-agent-update.timer || fail "the update timer is enabled $1"
	! systemctl is-active --quiet oka-cyber-agent-update.timer || fail "the update timer is active $1"
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

check_inventory() {
	for _ in $(seq 1 15); do
		[ "$(stat_of inventories)" -gt "$1" ] && break
		sleep 2
	done
	[ "$(stat_of inventories)" -gt "$1" ] || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "no inventory from the service"; }
	[ "$(stat_of last_inventory_packages)" -gt 0 ] || fail "the service sent an inventory without packages"
}

uninstall_agent() {
	/usr/local/bin/oka-cyber-agent uninstall --yes
	for path in /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /var/lib/oka-cyber-agent /etc/systemd/system/oka-cyber-agent-update.timer /etc/systemd/system/oka-cyber-agent-update.service /usr/local/lib/oka-cyber-agent /etc/systemd/system/oka-cyber-audit.service /etc/systemd/system/oka-cyber-audit.path /usr/share/oka-cyber-agent /run/oka-cyber-audit /etc/audit/rules.d/oka-cyber-commands.rules; do
		[ ! -e "$path" ] || fail "$path still exists after uninstall"
	done
	[ ! -L /etc/systemd/system/multi-user.target.wants/oka-cyber-audit.service ] || fail "the audit helper is still enabled after uninstall"
	[ ! -L /etc/systemd/system/timers.target.wants/oka-cyber-agent-update.timer ] || fail "the update timer is still enabled after uninstall"
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
inventories_before=$(stat_of inventories)
install_agent "$TOKEN"
check_audit_assets /etc/systemd/system
check_version v0.0.0-test "after install"
check_installer v0.0.0-test "after install"
[ "$(stat -c '%a %U' /usr/local/lib/oka-cyber-agent/install.sh)" = "755 root" ] || fail "the kept install.sh is not root owned"
for name in oka-cyber-agent-update.service oka-cyber-agent-update.timer; do
	[ "$(stat -c '%a %U' "/etc/systemd/system/$name")" = "644 root" ] || fail "$name was not installed root owned"
done
getent passwd oka-cyber >/dev/null || fail "the oka-cyber user was not created"
[ -f /etc/systemd/system/oka-cyber-agent.service ] || fail "the systemd unit was not written"
grep -q '^server_id:' /etc/oka-cyber-agent/config.yaml || fail "config.yaml has no server_id"
check_enrollment_files
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "expected exactly one enrollment"

if has_systemd; then
	echo "== the service is enabled and reports as the oka-cyber user"
	check_enabled "after install"
	check_updates_on "after install"
	check_service_reports "$heartbeats_before"
	check_inventory "$inventories_before"
	getent group systemd-journal >/dev/null || fail "a systemd host without the systemd-journal group"
	check_log_groups "after install"

	# journald records which program sent an entry, and the agent drops auth entries a program like logger
	# sent under another name, so the probe is a real sudo call. It is repeated until one arrives, since the
	# service starts at the end of the journal once the heartbeat enabled the auth source. The event carries
	# the executable and the number of arguments only (sudo may log /bin/true as /usr/bin/true).
	echo "== a sudo command reaches the tenant through journald, without its arguments"
	if command -v sudo >/dev/null 2>&1; then
		for i in $(seq 1 30); do
			sudo -u nobody /bin/true -p Typed-Pa55word "oka-probe-$i" || true
			sleep 2
			curl -fsS "$TENANT/log-events" | grep -q 'true \[3 args\]' && break
		done
		events=$(curl -fsS "$TENANT/log-events")
		echo "$events" | grep -q '"kind":"sudo_command"' || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "the sudo command was not shipped"; }
		echo "$events" | grep -q '"command":"[^"]*/bin/true \[3 args\]"' || fail "the shipped sudo event has no command"
		if echo "$events" | grep -q -e 'Typed-Pa55word' -e 'oka-probe-'; then
			fail "a sudo argument was shipped"
		fi
	else
		echo "sudo is not installed here: skipped"
	fi
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
check_audit_assets /etc/systemd/system
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "rerunning install.sh enrolled again"
if has_systemd; then
	check_enabled "after a rerun"
	check_service_reports "$heartbeats_before"
	[ "$(invocation_id)" != "$invocation_before" ] || fail "rerunning install.sh did not restart the service"
	check_updates_on "after a rerun"
fi

echo "== an update finding the installed release changes nothing"
if has_systemd; then invocation_before=$(invocation_id); fi
update_agent good >/dev/null || fail "the update failed without a new release"
check_installer v0.0.0-test "after an update without a new release"
check_version v0.0.0-test "after an update without a new release"
if has_systemd; then
	[ "$(invocation_id)" = "$invocation_before" ] || fail "an update without a new release restarted the service"
fi

echo "== an update to a tampered release changes nothing"
if update_agent bad; then
	fail "the update accepted a release whose checksums do not match"
fi
check_version v0.0.0-test "after an update to a tampered release"

echo "== an update to a new release installs it and keeps the enrollment"
heartbeats_before=$(stat_of heartbeats)
if has_systemd; then
	# The timer's own service, so the update also works when it restarts the agent from inside a unit.
	systemctl set-environment OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/next"
	systemctl start oka-cyber-agent-update.service || { journalctl -u oka-cyber-agent-update --no-pager | tail -n 50; fail "the update service failed"; }
	systemctl unset-environment OKA_CYBER_AGENT_DOWNLOAD_URL
else
	update_agent next
fi
check_version v0.0.1-test "after an update to a new release"
check_installer v0.0.1-test "after an update to a new release"
[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "the update enrolled again"
if has_systemd; then
	check_enabled "after an update"
	check_updates_on "after an update"
	check_service_reports "$heartbeats_before"
fi

if has_systemd; then
	echo "== rerun keeps a service the admin disabled disabled"
	systemctl disable --now oka-cyber-agent
	install_agent "$TOKEN"
	check_audit_assets /etc/systemd/system
	check_disabled "after a rerun of a disabled service"

	echo "== --no-auto-update turns the daily update off and a rerun keeps it off"
	OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --no-auto-update
	check_updates_off "after --no-auto-update"
	install_agent "$TOKEN"
	check_updates_off "after a rerun of a disabled timer"
fi

echo "== a release without the daily update removes the timer, a newer one brings it back"
OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/old" sh "$REPO/install.sh"
for path in /usr/local/lib/oka-cyber-agent /etc/systemd/system/oka-cyber-agent-update.timer /etc/systemd/system/oka-cyber-agent-update.service; do
	[ ! -e "$path" ] || fail "$path was kept for a release without the daily update"
done
if has_systemd; then check_updates_off "after installing a release without the daily update"; fi
install_agent "$TOKEN"
check_installer v0.0.0-test "after going back to a release with the daily update"
if has_systemd; then check_updates_on "after going back to a release with the daily update"; fi

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
check_audit_assets /etc/systemd/system
if has_systemd; then
	check_enabled "after a rerun that enrolled"
	check_updates_on "after a rerun that enrolled"
	check_service_reports "$heartbeats_before"
fi
uninstall_agent

echo "== an install under umask 077 (a hardened host) still lets the service read its configuration, with the token from a file"
heartbeats_before=$(stat_of heartbeats)
inventories_before=$(stat_of inventories)
token_file=$(mktemp)
printf '%s\n' "$TOKEN" >"$token_file"
(umask 077 && OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --url "$TENANT" --token-file "$token_file" --insecure-dev)
rm -f "$token_file"
check_enrollment_files
if has_systemd; then
	check_enabled "after an install under umask 077"
	check_service_reports "$heartbeats_before"
	check_inventory "$inventories_before"

	echo "== the service can report with a replacement token after forced re-enrollment"
	enrollments_before=$(stat_of enrollments)
	heartbeats_before=$(stat_of heartbeats)
	inventories_before=$(stat_of inventories)
	OKA_CYBER_ENROLLMENT_TOKEN="$TOKEN" /usr/local/bin/oka-cyber-agent enroll --force --url "$TENANT" --insecure-dev
	check_enrollment_files
	[ "$(stat_of enrollments)" -eq $((enrollments_before + 1)) ] || fail "forced re-enrollment did not enroll again"
	systemctl restart oka-cyber-agent
	check_service_reports "$heartbeats_before"
	check_inventory "$inventories_before"
fi
uninstall_agent

echo "== install.sh refuses to install over a package"
mkdir -p /usr/bin
printf '#!/bin/sh\nexit 0\n' >/usr/bin/oka-cyber-agent
if install_agent "$TOKEN"; then
	fail "install.sh installed over a package install"
fi
rm -f /usr/bin/oka-cyber-agent
for path in /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service /etc/oka-cyber-agent /usr/local/lib/oka-cyber-agent /etc/systemd/system/oka-cyber-agent-update.timer; do
	[ ! -e "$path" ] || fail "install.sh created $path although a package install was present"
done
echo "PASS"
