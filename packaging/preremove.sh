#!/bin/sh
set -e

# deb passes "remove" or "upgrade"; rpm passes the number of versions left after the transaction.
case "$1" in
	remove | purge | 0)
		if [ -d /run/systemd/system ]; then
			systemctl disable --now oka-cyber-agent.service >/dev/null 2>&1 || true
		fi
		;;
esac
