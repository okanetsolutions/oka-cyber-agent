#!/bin/sh
# Run only in a disposable systemd container. The trusted-directory auditctl stub prevents changes to the
# shared host kernel's audit policy while exercising the real helper, sandbox and path unit.
set -eu
TENANT="${TENANT:-http://127.0.0.1:8090}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "$REPO/test/install/lib.sh"
systemd-detect-virt --container >/dev/null || fail "audit helper sandbox test requires a disposable container"
ensure_curl
mkdir -p /etc/audit/rules.d
printf 'customer policy\n' >/etc/audit/rules.d/customer.rules
cat >/usr/bin/auditctl <<'STUB'
#!/bin/sh
set -eu
case "$*" in
 '-s') printf 'enabled 1\npid 123\n' ;;
 '-D -k oka_cyber_commands') printf 'off\n' >/etc/audit/rules.d/oka-helper-test.state ;;
 '-R /etc/audit/rules.d/oka-cyber-commands.rules')
  [ "$(cat /etc/audit/rules.d/oka-cyber-commands.rules)" = "$(cat /usr/share/oka-cyber-agent/commands.rules)" ]
  printf 'on\n' >/etc/audit/rules.d/oka-helper-test.state
  ;;
 *) exit 90 ;;
esac
STUB
chmod 0755 /usr/bin/auditctl

install_agent() {
 OKA_CYBER_AGENT_DOWNLOAD_URL="$TENANT/files/good" sh "$REPO/install.sh" --url "$TENANT" --token test-enrollment-token --insecure-dev
}

wait_status() {
 for _ in $(seq 1 30); do
  if [ -f /run/oka-cyber-audit/status ] && [ "$(cat /run/oka-cyber-audit/status)" = "$1" ]; then return; fi
  sleep 1
 done
 journalctl -u oka-cyber-audit --no-pager -n 30 >&2
 fail "helper did not acknowledge $1 (status: $(cat /run/oka-cyber-audit/status 2>/dev/null || true))"
}

# Keep the shipped main sandbox but replace its process for this unit-lifecycle test. Nested containers
# do not reliably provide LoadCredential's per-service mount ownership; credential delivery and the real
# reporting process remain covered by run.sh on the systemd CI host, and the shipper has Go tests.
mkdir -p /etc/systemd/system/oka-cyber-agent.service.d
cat >/etc/systemd/system/oka-cyber-agent.service.d/audit-test.conf <<'MAIN'
[Service]
ExecStart=
ExecStart=/usr/bin/sleep infinity
LoadCredential=
MAIN
install_agent
systemctl is-active --quiet oka-cyber-agent.service || fail "main sandbox is not active"
check_audit_assets /etc/systemd/system
pid=$(systemctl show -p MainPID --value oka-cyber-agent)
awk '/^CapEff:/ { if ($2 != "0000000000000000") exit 1 }' "/proc/$pid/status" || fail "main agent gained capabilities"
grep -q '^NoNewPrivs:[[:space:]]*1$' "/proc/$pid/status" || fail "main agent permits privilege escalation"

# A flag containing text is off; none of its bytes can enter the fixed audit policy.
runuser -u oka-cyber -- sh -c 'printf "%s\n" "-D" "-e 0" >/run/oka-cyber-agent/commands.enabled'
wait_status off
[ ! -e /etc/audit/rules.d/oka-cyber-commands.rules ] || fail "nonempty flag installed rules"
runuser -u oka-cyber -- truncate -s 0 /run/oka-cyber-agent/commands.enabled
wait_status on
[ "$(stat -c '%a %U' /etc/audit/rules.d/oka-cyber-commands.rules)" = '600 root' ] || fail "rules are not private and root-owned"
[ "$(cat /etc/audit/rules.d/oka-helper-test.state)" = on ] || fail "fixed rules were not loaded"
runuser -u oka-cyber -- cat /run/oka-cyber-audit/status >/dev/null || fail "agent cannot read helper acknowledgement"
runuser -u oka-cyber -- rm /run/oka-cyber-agent/commands.enabled
wait_status off
[ ! -e /etc/audit/rules.d/oka-cyber-commands.rules ] || fail "disabling kept persistent rules"

# Upgrade replaces the units and leaves the hardened main service reporting with collection off.
before=$(systemctl show -p MainPID --value oka-cyber-agent.service)
install_agent
systemctl is-active --quiet oka-cyber-agent.service || fail "main sandbox did not restart"
[ "$(systemctl show -p MainPID --value oka-cyber-agent.service)" != "$before" ] || fail "upgrade did not restart the main sandbox"
check_audit_assets /etc/systemd/system
runuser -u oka-cyber -- touch /run/oka-cyber-agent/commands.enabled
wait_status on
/usr/local/bin/oka-cyber-agent uninstall --yes
[ ! -e /etc/audit/rules.d/oka-cyber-commands.rules ] || fail "uninstall kept persistent rules"
[ "$(cat /etc/audit/rules.d/oka-helper-test.state)" = off ] || fail "uninstall did not unload the fixed key"
[ "$(cat /etc/audit/rules.d/customer.rules)" = 'customer policy' ] || fail "unrelated rules changed"
! systemctl is-active --quiet oka-cyber-audit.path || fail "uninstall kept the flag watcher"
rm -rf /etc/systemd/system/oka-cyber-agent.service.d
echo 'PASS: audit helper sandbox and lifecycle (stubbed auditctl)'
