#!/bin/sh
set -e

# install.sh puts the agent in /usr/local/bin with its own unit in /etc/systemd/system, which takes precedence
# over the package unit, so with both installed every upgrade would restart the script's old binary. Refuse
# before anything is unpacked instead of taking over the script's files. deb passes "install" or "upgrade" (and
# "abort-upgrade" when an upgrade to a newer version failed, which must not fail); rpm passes 1 or 2.
case "$1" in
	abort-upgrade) exit 0 ;;
esac

if [ -e /usr/local/bin/oka-cyber-agent ] || grep -qs /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service; then
	cat >&2 <<'MESSAGE'
oka-cyber-agent: this server already has the agent from install.sh (/usr/local/bin/oka-cyber-agent and
/etc/systemd/system/oka-cyber-agent.service). Remove it before installing the package:
  sudo /usr/local/bin/oka-cyber-agent uninstall
This also deletes the enrollment: revoke the server in your Oka Cyber dashboard and enroll again after
installing the package. To keep the enrollment instead, remove only the script's binary and unit:
  sudo systemctl disable --now oka-cyber-agent
  sudo rm -f /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service
MESSAGE
	exit 1
fi
