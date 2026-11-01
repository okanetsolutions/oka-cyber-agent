#!/bin/sh
set -e

# deb passes "remove" on removal and "upgrade" on an upgrade; rpm passes the number of versions left after the
# transaction (0 on erase, 1 on upgrade). Only a removal stops and disables the service, so an upgrade keeps it
# enabled and postinstall restarts it.
case "$1" in
	remove | 0)
		if [ -d /run/systemd/system ]; then
			systemctl disable --now oka-cyber-agent.service >/dev/null 2>&1 || true
		fi
		;;
esac
