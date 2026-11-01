#!/bin/sh
set -e

if ! getent passwd oka-cyber >/dev/null 2>&1; then
	useradd --system --user-group --no-create-home --home-dir /var/lib/oka-cyber-agent --shell /usr/sbin/nologin oka-cyber
fi

# On an enrolled host, a first install enables and starts the service and an upgrade only restarts it, so a
# service the admin disabled stays disabled. rpm passes 1 on install and 2 on upgrade. deb passes "configure"
# with the previously configured version, which is empty on a first install but also set when the package is
# reinstalled after "remove"; preremove leaves removed_marker when that removal disabled an enabled service, so
# the reinstall (or "abort-remove" after a failed removal) enables it again.
removed_marker=/etc/oka-cyber-agent/package-removed
start=false
case "$1" in
	1) start=true ;;
	configure) [ -n "${2:-}" ] || start=true ;;
esac
if [ -f "$removed_marker" ]; then
	start=true
	rm -f "$removed_marker"
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ -f /etc/oka-cyber-agent/token ]; then
		systemctl try-restart oka-cyber-agent.service >/dev/null 2>&1 || true
		if [ "$start" = true ]; then
			if systemctl enable --now oka-cyber-agent.service >/dev/null 2>&1; then
				echo "Oka Cyber Agent is enrolled: enabled and started oka-cyber-agent.service."
			else
				echo "Oka Cyber Agent is enrolled but oka-cyber-agent.service did not start. Check it with: systemctl status oka-cyber-agent"
			fi
		fi
	fi
fi

if [ ! -f /etc/oka-cyber-agent/token ]; then
	echo "Oka Cyber Agent installed. Enroll this server, then start the service:"
	echo "  sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>"
	echo "  sudo systemctl enable --now oka-cyber-agent"
fi
