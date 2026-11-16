#!/bin/sh
set -e

# install.sh puts the agent in /usr/local/bin with its own unit in /etc/systemd/system, which takes precedence
# over the package unit, so with both installed every upgrade would restart the script's old binary. Refuse
# before anything is unpacked instead of taking over the script's files. deb passes "install" or "upgrade" (and
# "abort-upgrade" when an upgrade to a newer version failed, which must not fail); rpm passes 1 or 2.
case "$1" in
	abort-upgrade) exit 0 ;;
esac

# The script's daily update timer runs as root and would reinstall the script agent, so it counts as part of the
# script install until it is removed too.
if [ -e /usr/local/bin/oka-cyber-agent ] || grep -qs /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service ||
	[ -e /etc/systemd/system/oka-cyber-agent-update.timer ] || [ -e /usr/local/lib/oka-cyber-agent ]; then
	cat >&2 <<'MESSAGE'
oka-cyber-agent: this server already has the agent from install.sh (/usr/local/bin/oka-cyber-agent,
/etc/systemd/system/oka-cyber-agent.service and its daily update). Remove it before installing the package:
  sudo /usr/local/bin/oka-cyber-agent uninstall
This also deletes the enrollment: revoke the server in your Oka Cyber dashboard and enroll again after
installing the package. To keep the enrollment instead, remove only the script's binary, units and update:
  sudo systemctl disable --now oka-cyber-agent-update.timer oka-cyber-agent
  sudo rm -rf /usr/local/bin/oka-cyber-agent /etc/systemd/system/oka-cyber-agent.service /etc/systemd/system/oka-cyber-agent-update.timer /etc/systemd/system/oka-cyber-agent-update.service /usr/local/lib/oka-cyber-agent
MESSAGE
	exit 1
fi
