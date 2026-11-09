#!/bin/sh
# install.sh embeds the systemd unit so it works as a single downloaded file. This fails when it drifts from
# packaging/oka-cyber-agent.service (only the binary path may differ).
set -eu
cd "$(dirname "$0")/../.."
embedded=$(mktemp)
trap 'rm -f "$embedded"' EXIT
sed -n "/<<'UNIT'$/,/^UNIT$/p" install.sh | sed '1d;$d' | sed 's#/usr/local/bin/oka-cyber-agent#/usr/bin/oka-cyber-agent#' >"$embedded"
diff -u packaging/oka-cyber-agent.service "$embedded"

for spec in 'AUDIT_SERVICE packaging/oka-cyber-audit.service' 'AUDIT_PATH packaging/oka-cyber-audit.path' 'AUDIT_RULES internal/auditcontrol/commands.rules'; do
 tag=${spec%% *}
 source=${spec#* }
 sed -n "/<<'$tag'$/,/^$tag$/p" install.sh | sed '1d;$d' | sed 's#/usr/local/bin/oka-cyber-agent#/usr/bin/oka-cyber-agent#' >"$embedded"
 diff -u "$source" "$embedded"
done
