#!/usr/bin/env bash
# Tests for tools/ci/offline-checks.sh: every way isolation can be missing or unproven must fail
# the run, and the run must succeed only when isolation holds and every check passes.
#
#   tools/ci/offline-checks.test.sh
#
# Failures are simulated with small stand-ins for `ip`, `timeout`, `python3`, `node` and
# `unshare` placed first on PATH; the script under test is not modified. A network namespace is
# created with `unshare -rn` where unprivileged user namespaces are allowed, otherwise with
# `sudo unshare --net` (the GitHub runner).
set -euo pipefail

root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
script="$root/tools/ci/offline-checks.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

real_ip=$(command -v ip)
real_timeout=$(command -v timeout)
real_python=$(command -v python3)
export real_ip real_timeout real_python

if unshare -rn true 2>/dev/null; then
  sudo_namespace=false
  echo "offline-checks.test: namespaces via unshare -rn"
elif sudo -n true 2>/dev/null; then
  sudo_namespace=true
  echo "offline-checks.test: namespaces via sudo unshare --net"
else
  echo "offline-checks.test: cannot create a network namespace (no unprivileged user namespaces, no sudo)" >&2
  exit 1
fi

passed=0
failed=0

# shim <case> <name> <body>: a stand-in command for one case.
shim() {
  mkdir -p "$work/$1/bin"
  printf '#!/usr/bin/env bash\n%s\n' "$3" >"$work/$1/bin/$2"
  chmod +x "$work/$1/bin/$2"
}

# Fast stand-ins for the checks themselves, so the cases test the script and not the suite.
check_shims() {
  shim "$1" node 'case "$1" in --check) exit "${NODE_CHECK_EXIT:-0}";; *) echo "node-test-stand-in"; exit "${NODE_TEST_EXIT:-0}";; esac'
  shim "$1" python3 'case "$*" in *rnnet_reference.py*) echo "reference-stand-in"; exit "${REFERENCE_EXIT:-0}";; *) exec "$real_python" "$@";; esac'
}

# run <case> <ns|host> [env assignments...] -- <script args...>: runs the script, stores output and status.
run() {
  local name=$1 where=$2
  shift 2
  local assignments=()
  while [ "$1" != -- ]; do
    assignments+=("$1")
    shift
  done
  shift
  local path="$work/$name/bin:$PATH"
  mkdir -p "$work/$name/bin"
  local command=(env "PATH=$path" "${assignments[@]}" "$script" "$@")
  if [ "$where" = ns ]; then
    if $sudo_namespace; then
      command=(sudo env "PATH=$path" "${assignments[@]}" unshare --net -- "$script" "$@")
    else
      command=(env "PATH=$path" "${assignments[@]}" unshare -rn "$script" "$@")
    fi
  fi
  set +e
  output=$("${command[@]}" 2>&1)
  status=$?
  set -e
}

# expect <case> <fail|pass> <text>: checks the last run.
expect() {
  local ok=true
  if [ "$2" = fail ] && [ "$status" -eq 0 ]; then ok=false; fi
  if [ "$2" = pass ] && [ "$status" -ne 0 ]; then ok=false; fi
  grep -qF -- "$3" <<<"$output" || ok=false
  if $ok; then
    passed=$((passed + 1))
    echo "ok   $1"
  else
    failed=$((failed + 1))
    echo "FAIL $1 (expected $2 with \"$3\", got status $status)"
    sed 's/^/     | /' <<<"$output"
  fi
}

# --- Isolation proof ---------------------------------------------------------------------------

run normal ns -- --isolation-only
expect 'isolated namespace: isolation proven' pass 'isolation proven'

run host host -- --isolation-only
expect 'no namespace: missing isolation is detected' fail 'interfaces other than loopback present'

run skipped-stage host RNNET_OFFLINE_STAGE=checks --
expect 'no namespace, first stage skipped: still detected' fail 'interfaces other than loopback present'

shim ip-list-fails ip 'if [ "$*" = "-o link show" ]; then exit 1; fi; exec "$real_ip" "$@"'
run ip-list-fails ns -- --isolation-only
expect 'interface listing fails: run fails (N4)' fail 'could not list network interfaces'

shim ip-fails ip 'exit 1'
run ip-fails ns -- --isolation-only
expect 'ip fails entirely: run fails (N4)' fail 'could not inspect the loopback interface'

shim ip-route-fails ip 'case "$*" in *route*) exit 2;; esac; exec "$real_ip" "$@"'
run ip-route-fails ns -- --isolation-only
expect 'route listing fails: run fails (N4)' fail 'could not list IPv4 routes'

shim ip-route6-fails ip 'case "$*" in "-6 route show") exit 2;; esac; exec "$real_ip" "$@"'
run ip-route6-fails ns -- --isolation-only
expect 'IPv6 route listing fails: run fails (N4)' fail 'could not list IPv6 routes'

shim lo-up-fails ip 'case "$*" in "link set lo up") exit 2;; esac; exec "$real_ip" "$@"'
run lo-up-fails ns -- --isolation-only
expect 'loopback cannot be brought up: run fails (N4)' fail 'could not bring loopback up'

shim ip-empty ip 'case "$*" in "-o link show") exit 0;; esac; exec "$real_ip" "$@"'
run ip-empty ns -- --isolation-only
expect 'empty interface listing: run fails (N4)' fail 'loopback interface not listed'

shim unshare-fails unshare 'echo "unshare: unshare failed: Operation not permitted" >&2; exit 1'
set +e
output=$(env "PATH=$work/unshare-fails/bin:$PATH" unshare --net -- "$script" 2>&1)
status=$?
set -e
expect 'namespace creation fails: run fails, no checks run' fail 'unshare failed'
if grep -q 'isolation proven' <<<"$output"; then
  failed=$((failed + 1))
  echo "FAIL namespace creation fails: the script ran"
fi

shim listener-silent python3 'exit 0'
run listener-silent ns -- --isolation-only
expect 'positive control: listener does not start' fail 'positive control failed: the local listener did not start'

shim listener-absent python3 'echo 9; exit 0'
run listener-absent ns -- --isolation-only
expect 'positive control: probe cannot reach the listener' fail 'positive control failed: the probe could not reach'

shim reachable timeout 'case "$*" in *1.1.1.1*) exit 0;; esac; exec "$real_timeout" "$@"'
run reachable ns -- --isolation-only
expect 'external address reachable: run fails' fail 'reachable from inside the namespace: 1.1.1.1/443'

# --- Checks stage --------------------------------------------------------------------------------

for name in checks-pass checks-test-fails checks-reference-fails checks-syntax-fails; do check_shims "$name"; done

run checks-pass ns --
expect 'all checks pass: run passes' pass 'reference-stand-in'
expect 'effective uid is logged' pass 'offline-checks: checks run as uid'

run checks-test-fails ns NODE_TEST_EXIT=1 --
expect 'a failing test fails the run' fail 'node-test-stand-in'

run checks-reference-fails ns REFERENCE_EXIT=1 --
expect 'a failing Python reference fails the run' fail 'reference-stand-in'

run checks-syntax-fails ns NODE_CHECK_EXIT=1 --
expect 'a syntax error fails the run' fail 'isolation proven'

if $sudo_namespace; then
  check_shims checks-as-root
  set +e
  output=$(sudo env "PATH=$work/checks-as-root/bin:$PATH" RNNET_OFFLINE_STAGE=checks unshare --net -- "$script" 2>&1)
  status=$?
  set -e
  expect 'checks refuse to run as real root' fail 'refusing to run the checks as real root'
else
  echo "skip checks refuse to run as real root (needs sudo)"
fi

echo "offline-checks.test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
