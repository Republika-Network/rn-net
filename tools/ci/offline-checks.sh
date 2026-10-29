#!/usr/bin/env bash
# Runs RN-NET's offline checks inside a network namespace whose only interface is loopback,
# after proving that isolation. Every failure exits non-zero (fail closed).
#
#   CI:     sudo env "PATH=$PATH" unshare --net -- tools/ci/offline-checks.sh
#   Local:  unshare -rn tools/ci/offline-checks.sh
#   Negative control, which must FAIL anywhere the network is reachable:
#           sudo env "PATH=$PATH" tools/ci/offline-checks.sh --isolation-only
#
# Root is used only inside the new namespace, to bring loopback up and inspect it; the checks
# themselves run as the invoking user (SUDO_USER) in the same namespace.
set -euo pipefail

self=$(realpath "${BASH_SOURCE[0]}")
cd "$(dirname "$self")/../.."

fail() {
  echo "offline-checks: $*" >&2
  exit 1
}

# Succeeds if a TCP connection to host/port opens within 3 seconds.
probe() {
  timeout 3 bash -c "exec 3<>/dev/tcp/${1%/*}/${1##*/}" 2>/dev/null
}

# Every inspection command must succeed: a failing or missing `ip` is a failure, never an empty
# (and therefore "isolated") answer.
no_external_interfaces() {
  local links others routes
  links=$(ip -o link show) || fail "could not list network interfaces"
  awk -F': ' '$2 == "lo" { found = 1 } END { exit !found }' <<<"$links" || fail "loopback interface not listed"
  others=$(awk -F': ' '$2 != "lo" { print $2 }' <<<"$links")
  [ -z "$others" ] || fail "interfaces other than loopback present: $(echo "$others" | tr '\n' ' ')"
  routes=$(ip -4 route show) || fail "could not list IPv4 routes"
  [ -z "$routes" ] || fail "an IPv4 route exists"
  routes=$(ip -6 route show) || fail "could not list IPv6 routes"
  [ -z "$(awk '$1 != "::1"' <<<"$routes")" ] || fail "an IPv6 route exists"
}

# Positive control: the probe does connect when a listener exists, so its failures in
# no_external_reachability mean "unreachable", not "probe broken".
probe_reaches_local_listener() {
  local dir pid port=''
  dir=$(mktemp -d)
  python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
print(s.getsockname()[1], flush=True); s.settimeout(10); s.accept()[0].close()' >"$dir/port" &
  pid=$!
  for _ in $(seq 100); do
    port=$(cat "$dir/port")
    [[ "$port" =~ ^[0-9]+$ ]] && break
    sleep 0.05
  done
  rm -rf "$dir"
  [[ "$port" =~ ^[0-9]+$ ]] || fail "positive control failed: the local listener did not start"
  probe "127.0.0.1/$port" || fail "positive control failed: the probe could not reach a local listener"
  wait "$pid" || fail "positive control failed: the local listener did not complete"
}

no_external_reachability() {
  local target
  for target in 1.1.1.1/443 8.8.8.8/53 192.0.2.1/80 2606:4700:4700::1111/443; do
    if probe "$target"; then fail "reachable from inside the namespace: $target"; fi
  done
}

verify_isolation() {
  no_external_interfaces
  probe_reaches_local_listener
  no_external_reachability
}

prove_isolation() {
  # A new namespace starts with loopback down; elsewhere it is already up and left alone.
  local lo
  lo=$(ip -o link show lo) || fail "could not inspect the loopback interface"
  grep -q '[<,]UP[,>]' <<<"$lo" || ip link set lo up || fail "could not bring loopback up"
  verify_isolation
  echo "offline-checks: isolation proven (loopback only, no routes, positive control passed)"
}

# The checks run unprivileged: as the invoking user in CI, or as uid 0 inside a user namespace
# (local `unshare -rn`), which maps to an unprivileged user outside it. Never as real root.
not_real_root() {
  local inside outside count
  read -r inside outside count </proc/self/uid_map || fail "could not read the user namespace mapping"
  if [ "$(id -u)" -eq 0 ] && [ "$outside" -eq 0 ]; then fail "refusing to run the checks as real root"; fi
  echo "offline-checks: checks run as uid $(id -u) ($(id -un)); uid map: $inside $outside $count"
}

run_checks() {
  not_real_root
  # Re-checked here so that skipping the first stage cannot run the checks with network access.
  verify_isolation
  echo "::group::Syntax check"
  git ls-files -z '*.mjs' | xargs -0 -n1 node --check
  echo "::endgroup::"
  echo "::group::Tests (guards, offline preload, canonical, commitment, conformance, tamper)"
  node --import ./tools/offline.mjs --test "tools/*.test.mjs" "tools/guards/*.test.mjs" "packages/*/test/*.test.mjs"
  echo "::endgroup::"
  echo "::group::Independent Python reference against all vectors"
  python3 -I -B tools/reference/rnnet_reference.py
  python3 -I -B tools/reference/rnnet_evidence_reference.py
  python3 -I -B tools/reference/rnnet_anchor_reference.py
  echo "::endgroup::"
}

if [ "${RNNET_OFFLINE_STAGE:-}" = checks ]; then
  run_checks
  exit 0
fi

echo "offline-checks: isolation stage runs as uid $(id -u)"
prove_isolation
if [ "${1:-}" = --isolation-only ]; then exit 0; fi

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  # CI: drop back to the invoking user, staying in this namespace.
  exec sudo -u "$SUDO_USER" env "PATH=$PATH" "HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
    RNNET_OFFLINE_STAGE=checks "$self"
fi
# Local `unshare -rn`: root only inside the user namespace, already unprivileged outside it.
RNNET_OFFLINE_STAGE=checks exec "$self"
