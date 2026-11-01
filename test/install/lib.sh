#!/bin/sh
# Helpers shared by run.sh and packages.sh. TENANT is the fake tenant from prepare.sh.

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

ensure_curl() {
	command -v curl >/dev/null 2>&1 && return
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y -qq curl >/dev/null
	else
		dnf install -y -q curl >/dev/null
	fi
}

stat_of() {
	curl -fsS "$TENANT/stats" | tr -d ' \n' | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"
}

has_systemd() {
	[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

# The service user must reach config.yaml whatever the umask enroll ran under. enroll keeps the token root only
# and lets systemd pass it with LoadCredential, except on systemd older than 247 (RHEL 8 family), which has no
# LoadCredential: there the oka-cyber group may read it.
check_enrollment_files() {
	got=$(stat -c '%a %U %G' /etc/oka-cyber-agent)
	[ "$got" = "755 root root" ] || fail "/etc/oka-cyber-agent is $got, want 755 root root"
	got=$(stat -c '%a %U %G' /etc/oka-cyber-agent/config.yaml)
	[ "$got" = "644 root root" ] || fail "config.yaml is $got, want 644 root root"
	version=$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 }')
	want="600 root root"
	if [ -n "$version" ] && [ "$version" -lt 247 ]; then
		want="640 root oka-cyber"
	fi
	got=$(stat -c '%a %U %G' /etc/oka-cyber-agent/token)
	[ "$got" = "$want" ] || fail "token is $got, want $want (systemd ${version:-not installed})"
}

# Waits for a heartbeat from the service (it sends one each time it starts) after $1 heartbeats were received,
# then checks it runs as oka-cyber.
check_service_reports() {
	for _ in $(seq 1 30); do
		[ "$(stat_of heartbeats)" -gt "$1" ] && break
		sleep 2
	done
	systemctl is-active --quiet oka-cyber-agent || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "service is not active"; }
	[ "$(ps -o user= -C oka-cyber-agent | head -n 1)" = "oka-cyber" ] || fail "service does not run as oka-cyber"
	[ "$(stat_of heartbeats)" -gt "$1" ] || { journalctl -u oka-cyber-agent --no-pager | tail -n 50; fail "no heartbeat from the service"; }
}
