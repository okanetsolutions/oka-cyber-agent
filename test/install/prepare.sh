#!/bin/sh
# Builds a release like directory for install.sh (files/good) and a tampered copy (files/bad), then starts the
# fake tenant on 127.0.0.1:8090. Run from the repository root on the CI host.
set -eu

work="${1:-/tmp/oka-install-test}"
mkdir -p "$work/files/good" "$work/files/bad"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X github.com/okanetsolutions/oka-cyber-agent/internal/agent.Version=v0.0.0-test" -o "$work/files/good/oka-cyber-agent_linux_amd64" ./cmd/oka-cyber-agent
(cd "$work/files/good" && sha256sum oka-cyber-agent_linux_amd64 >checksums.txt)

cp "$work/files/good/oka-cyber-agent_linux_amd64" "$work/files/bad/"
printf '0000000000000000000000000000000000000000000000000000000000000000  oka-cyber-agent_linux_amd64\n' >"$work/files/bad/checksums.txt"

go build -o "$work/faketenant" ./test/faketenant
"$work/faketenant" -files "$work/files" >"$work/faketenant.log" 2>&1 &
echo $! >"$work/faketenant.pid"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	if curl -fsS http://127.0.0.1:8090/stats >/dev/null 2>&1; then
		exit 0
	fi
	sleep 1
done
echo "fake tenant did not start" >&2
cat "$work/faketenant.log" >&2
exit 1
