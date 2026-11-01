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
		;;
esac
