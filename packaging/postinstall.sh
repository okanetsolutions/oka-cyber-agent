#!/bin/sh
set -e

if ! getent passwd oka-cyber >/dev/null 2>&1; then
	useradd --system --user-group --no-create-home --home-dir /var/lib/oka-cyber-agent --shell /usr/sbin/nologin oka-cyber
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ -f /etc/oka-cyber-agent/token ]; then
		systemctl try-restart oka-cyber-agent.service >/dev/null 2>&1 || true
	fi
fi

if [ ! -f /etc/oka-cyber-agent/token ]; then
	echo "Oka Cyber Agent installed. Enroll this server, then start the service:"
	echo "  sudo oka-cyber-agent enroll --url https://<your tenant> --token <enrollment token>"
	echo "  sudo systemctl enable --now oka-cyber-agent"
fi
