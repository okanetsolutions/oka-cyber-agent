#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

# deb keeps the enrollment on "remove" and deletes it on "purge"; rpm has no purge, so erase (0) deletes it.
case "$1" in
	purge | 0)
		rm -rf /etc/oka-cyber-agent /var/lib/oka-cyber-agent
		if getent passwd oka-cyber >/dev/null 2>&1; then
			userdel oka-cyber >/dev/null 2>&1 || true
		fi
		if getent group oka-cyber >/dev/null 2>&1; then
			groupdel oka-cyber >/dev/null 2>&1 || true
		fi
		;;
esac
