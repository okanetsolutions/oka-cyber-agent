#!/bin/sh
# Boots <image> with systemd as PID 1 and runs test/install/<script> in it as root, with the repository at /src
# and GoReleaser's dist directory at /src/dist. Used for images whose systemd differs from the CI runner's,
# such as the RHEL 8 family (systemd 239, no LoadCredential). Run from the repository root.
set -eu

image="$1"
script="$2"
name="oka-cyber-systemd-$$"

docker run -d --name "$name" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --network host -v "$PWD:/src:ro" "$image" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

state=""
for _ in $(seq 1 60); do
	state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
	case "$state" in
		running | degraded) break ;;
	esac
	sleep 1
done
case "$state" in
	running | degraded) ;;
	*) echo "systemd did not start in $image (state: ${state:-none})" >&2; docker logs "$name" >&2 || true; exit 1 ;;
esac

if ! docker exec -e DIST=/src/dist "$name" sh "/src/test/install/$script"; then
	docker exec "$name" journalctl -u oka-cyber-agent --no-pager -n 50 >&2 || true
	exit 1
fi
