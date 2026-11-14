#!/bin/sh
set -e

# deb passes "remove" on removal and "upgrade" on an upgrade; rpm passes the number of versions left after the
# transaction (0 on erase, 1 on upgrade). Only a removal stops and disables the service, so an upgrade keeps it
# enabled and postinstall restarts it. A deb "remove" keeps the enrollment, so when the service was enabled it
# leaves a marker for postinstall to enable it again on reinstall; a purge deletes the marker with the directory.
case "$1" in
	remove | 0)
		if [ -d /run/systemd/system ]; then
			if [ "$1" = remove ] && [ -d /etc/oka-cyber-agent ] && systemctl is-enabled --quiet oka-cyber-agent.service; then
				touch /etc/oka-cyber-agent/package-removed 2>/dev/null || true
			fi
			systemctl disable --now oka-cyber-agent.service >/dev/null 2>&1 || true
		fi
		if [ -d /run/systemd/system ]; then
		 systemctl disable --now oka-cyber-audit.path >/dev/null 2>&1 || true
		 systemctl disable --now oka-cyber-audit.service >/dev/null 2>&1 || true
		fi
		rm -f /run/oka-cyber-agent/commands.enabled
		/usr/bin/oka-cyber-agent audit-rules
		if [ -f /run/oka-cyber-audit/status ] && [ "$(cat /run/oka-cyber-audit/status)" != off ] && [ "$(cat /run/oka-cyber-audit/status)" != audit_control_unavailable ]; then
		 echo "Command audit rule removal could not be confirmed; check the host audit policy."
		 exit 1
		fi
		rm -rf /run/oka-cyber-audit /run/oka-cyber-agent
		;;
	upgrade | 1)
		# A downgrade can install a version without the helper, and then nothing would ever remove the rule, which
		# augenrules loads again at every boot. Remove it on every upgrade: the restarted agent writes the flag
		# again and the helper reloads the rule. On rpm this runs after the new binary is installed, so when that
		# binary has no helper, remove the persistent file and the rules with the fixed key here. Never block an
		# upgrade on it.
		rm -f /run/oka-cyber-agent/commands.enabled
		if ! /usr/bin/oka-cyber-agent audit-rules >/dev/null 2>&1; then
			rm -f /etc/audit/rules.d/oka-cyber-commands.rules
			auditctl -D -k oka_cyber_commands >/dev/null 2>&1 || true
		fi
		;;
esac
