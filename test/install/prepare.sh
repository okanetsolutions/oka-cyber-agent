#!/bin/sh
# Builds release like directories for install.sh (files/good, a newer files/next and files/old, whose install.sh
# predates the daily update) and a tampered copy (files/bad), then starts the fake tenant on 127.0.0.1:8090. Run from the repository root on the CI host.
set -eu

work="${1:-/tmp/oka-install-test}"
mkdir -p "$work/files/good" "$work/files/bad"

# files/next is a newer release for the daily update to find.
for release in good:v0.0.0-test next:v0.0.1-test; do
	dir="$work/files/${release%%:*}"
	mkdir -p "$dir"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X github.com/okanetsolutions/oka-cyber-agent/internal/agent.Version=${release#*:}" -o "$dir/oka-cyber-agent_linux_amd64" ./cmd/oka-cyber-agent
	cp install.sh "$dir/install.sh"
	printf '# %s\n' "${release#*:}" >>"$dir/install.sh"
	(cd "$dir" && sha256sum oka-cyber-agent_linux_amd64 install.sh >checksums.txt)
done

mkdir -p "$work/files/old"
cp "$work/files/good/oka-cyber-agent_linux_amd64" "$work/files/old/"
grep -v '^[[:space:]]*--update)' install.sh >"$work/files/old/install.sh"
printf '# v0.0.0-old\n' >>"$work/files/old/install.sh"
(cd "$work/files/old" && sha256sum oka-cyber-agent_linux_amd64 install.sh >checksums.txt)

# Neither the binary nor install.sh of files/bad matches its checksum.
cp "$work/files/good/oka-cyber-agent_linux_amd64" "$work/files/good/install.sh" "$work/files/bad/"
printf 'echo tampered\n' >>"$work/files/bad/install.sh"
{
	printf '0000000000000000000000000000000000000000000000000000000000000000  oka-cyber-agent_linux_amd64\n'
	grep ' install.sh$' "$work/files/good/checksums.txt"
} >"$work/files/bad/checksums.txt"

go build -o "$work/faketenant" ./test/faketenant
"$work/faketenant" -files "$work/files" -log-sources "${LOG_SOURCES:-auth}" >"$work/faketenant.log" 2>&1 &
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
