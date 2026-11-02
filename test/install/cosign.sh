#!/bin/sh
# Runs verify_signature from install.sh against fake cosign commands: a good signature passes, a bad one aborts
# as a tampered release, and a cosign too old to read the bundle aborts asking for an upgrade. Run from anywhere.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

sed -n '/^REPOSITORY=/p; /^say() {/,/^}/p; /^fail() {/,/^}/p; /^verify_signature() {/,/^}/p' "$REPO/install.sh" >"$scratch/functions.sh"
grep -q '^verify_signature() {' "$scratch/functions.sh" || { echo "FAIL: verify_signature not found in install.sh" >&2; exit 1; }

# fake_cosign <version> <exit status of verify-blob> <stderr of verify-blob>
fake_cosign() {
	mkdir -p "$scratch/bin"
	cat >"$scratch/bin/cosign" <<FAKE
#!/bin/sh
case "\$1" in
	version) printf 'GitVersion:    %s\nGoVersion:     go1.26.0\n' '$1' ;;
	verify-blob) [ '$2' -eq 0 ] && echo 'Verified OK' >&2; [ '$2' -eq 0 ] || echo '$3' >&2; exit $2 ;;
esac
FAKE
	chmod +x "$scratch/bin/cosign"
}

# verify <expected exit> <text expected in the output>
verify() {
	out=$(PATH="$scratch/bin:$PATH" WORK_DIR="$scratch" sh -c ". '$scratch/functions.sh'; verify_signature '$scratch/checksums.txt' '$scratch/bundle.json'" 2>&1) && status=0 || status=$?
	if [ "$status" -ne "$1" ] || ! printf '%s' "$out" | grep -q -- "$2"; then
		echo "FAIL: want exit $1 and \"$2\", got exit $status:" >&2
		echo "$out" >&2
		exit 1
	fi
}

echo "== a good signature verifies"
fake_cosign v3.1.4 0 ''
verify 0 'verified the cosign signature'

echo "== a bad signature is reported as tampering, with cosign's error"
fake_cosign v3.1.4 1 'Error: none of the expected identities matched what was in the certificate'
verify 1 'may have been tampered with'
verify 1 'cosign: Error: none of the expected identities'

echo "== cosign v2 cannot read the v0.3 bundle: upgrade, not tampering"
fake_cosign v2.4.1 1 'Error: bundle does not contain cert for verification'
verify 1 'Upgrade cosign to v3 or newer'
verify 1 'cosign: Error: bundle does not contain cert'

echo "== an unknown version that cannot read the bundle also asks for an upgrade"
fake_cosign devel 1 'Error: bundle does not contain cert for verification'
verify 1 'Upgrade cosign to v3 or newer'
echo "PASS"
