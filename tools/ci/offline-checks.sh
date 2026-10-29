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

no_external_interfaces() {
  local others
  others=$(ip -o link show | awk -F': ' '{print $2}' | grep -vx lo || true)
  [ -z "$others" ] || fail "interfaces other than loopback present: $(echo "$others" | tr '\n' ' ')"
  [ -z "$(ip -4 route show)" ] || fail "an IPv4 route exists"
  [ -z "$(ip -6 route show | grep -v '^::1 ' || true)" ] || fail "an IPv6 route exists"
}

no_external_reachability() {
  local target
  for target in 1.1.1.1/443 8.8.8.8/53 192.0.2.1/80 2606:4700:4700::1111/443; do
    if probe "$target"; then fail "reachable from inside the namespace: $target"; fi
  done
}

prove_isolation() {
  # A new namespace starts with loopback down; elsewhere it is already up and left alone.
  ip -o link show lo | grep -q '[<,]UP[,>]' || ip link set lo up
  no_external_interfaces
  # Positive control: the probe does connect when a listener exists, so its failures below
  # mean "unreachable", not "probe broken".
  coproc LISTENER {
    python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
print(s.getsockname()[1], flush=True); s.settimeout(10); s.accept()[0].close()'
  }
  local port
  read -r port <&"${LISTENER[0]}"
  probe "127.0.0.1/$port" || fail "positive control failed: the probe could not reach a local listener"
  wait "$LISTENER_PID" || fail "positive control listener did not complete"
  no_external_reachability
  echo "offline-checks: isolation proven (loopback only, no routes, positive control passed)"
}

run_checks() {
  # Re-checked here so that skipping the first stage cannot run the checks with network access.
  no_external_interfaces
  no_external_reachability
  echo "::group::Syntax check"
  git ls-files -z '*.mjs' | xargs -0 -n1 node --check
  echo "::endgroup::"
  echo "::group::Tests (guards, offline preload, canonical, commitment, conformance, tamper)"
  node --import ./tools/offline.mjs --test "tools/*.test.mjs" "tools/guards/*.test.mjs" "packages/*/test/*.test.mjs"
  echo "::endgroup::"
  echo "::group::Independent Python reference against all vectors"
  python3 -I -B tools/reference/rnnet_reference.py
  echo "::endgroup::"
}

if [ "${RNNET_OFFLINE_STAGE:-}" = checks ]; then
  run_checks
  exit 0
fi

prove_isolation
if [ "${1:-}" = --isolation-only ]; then exit 0; fi

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  # CI: drop back to the invoking user, staying in this namespace.
  exec sudo -u "$SUDO_USER" env "PATH=$PATH" "HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
    RNNET_OFFLINE_STAGE=checks "$self"
fi
# Local `unshare -rn`: root only inside the user namespace, already unprivileged outside it.
RNNET_OFFLINE_STAGE=checks exec "$self"
