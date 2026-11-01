#!/bin/sh
# install.sh embeds the systemd unit so it works as a single downloaded file. This fails when it drifts from
# packaging/oka-cyber-agent.service (only the binary path may differ).
set -eu
cd "$(dirname "$0")/../.."
embedded=$(mktemp)
trap 'rm -f "$embedded"' EXIT
sed -n "/<<'UNIT'$/,/^UNIT$/p" install.sh | sed '1d;$d' | sed 's#/usr/local/bin/oka-cyber-agent#/usr/bin/oka-cyber-agent#' >"$embedded"
diff -u packaging/oka-cyber-agent.service "$embedded"
