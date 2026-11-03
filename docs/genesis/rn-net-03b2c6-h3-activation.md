# RN-NET-03B2-C6-H3: founder-controlled single-run activation

- Status: **draft activation branch; NOT authorized to run.** This document and its PR authorize no
  RPC request. The PR must not be merged before the founder's independent review, and merging it
  does not authorize the run: that needs a separate H3 authorization (§3) written by the founder.
- Basis: [the C6 document](rn-net-03b2c6-provider-compatibility.md) §8;
  [rnnet.compat-authorization.v1](../../spec/rnnet.compat-authorization.v1.md) (§3 the flow, §5 the
  run directory, §7 the switches, §8 the network boundary).
- Baseline: main `472e5161e7e62a5cf9f626220f829529c3b772ed` (PR #30 merged; tree identical to its
  reviewed head `a0002a24e55d40ec62afb7ec3da516e5a6fd0801`).

## 1. The activation change

Exactly two functional lines:

| File | Before | After |
|---|---|---|
| `tools/compat-live/compat-live.mjs` | `LIVE_NETWORK_ACCESS = false` | `LIVE_NETWORK_ACCESS = true` |
| `tools/compat-live/entry.mjs` | `AGREED_EVIDENCE_DIR = null` | `AGREED_EVIDENCE_DIR = '/home/vicvalch/rn-net-private/c6-evidence'` |

Nothing else that the run depends on changes: not the manifest (canonical SHA-256
`2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037`, 22 requests), not the providers,
URLs, budgets, method allowlists, the authorization format or its digest, the policy, the C6 or
HTTPS transport, the verifier, the signer or the broadcaster.

Test and check changes that follow from it:

- `tools/compat-live.test.mjs`: the test that pinned `false`/`null` pins the activated values;
- `tools/broadcast/live-disabled.check.mjs`: it no longer starts `compat-live.mjs` (starting the
  activated command, even with invalid arguments, is not allowed in CI or tests). It reads the two
  switches from the source instead, and fails unless they are exactly disabled or exactly this
  activation. The other four entry points are still started and must refuse;
- `tools/compat-h3.test.mjs` (new): the negative controls of the activated wiring (§7);
- one comment in `tools/compat-live-enable.test.mjs`.

## 2. The private evidence directory (PENDING FOUNDER APPROVAL)

Proposed: `/home/vicvalch/rn-net-private/c6-evidence`.

Inspected on 2026-11-03, without creating or changing anything:

| Requirement | Observed |
|---|---|
| outside every repository and worktree | `/home/vicvalch` is not a git repository; the worktrees are under `/home/vicvalch/rn-net-bootstrap/` |
| not under `/mnt/c`, not cloud-synchronized | WSL root file system, `ext4` on `/dev/sdd` (`rw,relatime,data=ordered`); no sync client under `/home/vicvalch` |
| owned by the WSL user | the parent `/home/vicvalch` is `0750`, uid 1000 (the user); `/home` is root `0755` |
| no symbolic link in the path | none: `/home`, `/home/vicvalch` are directories; the rest does not exist yet |
| `0700`, no world-readable file, no used authorization id | to be created empty, `0700` (below) |
| durability checks, 64 MiB free | 830 GB free; ext4 with `fsync` and hard links; the probe (spec §3, step 7) runs at the start of the run |

**It does not exist yet and was not created.** Once the founder approves it, the founder creates it:

```sh
install -d -m 0700 /home/vicvalch/rn-net-private
install -d -m 0700 /home/vicvalch/rn-net-private/c6-evidence
stat -c '%n %a %U' /home/vicvalch/rn-net-private /home/vicvalch/rn-net-private/c6-evidence   # both 700, vicvalch
ls -A /home/vicvalch/rn-net-private/c6-evidence                                             # empty
```

The run itself refuses unless the directory is `0700`, owned by the user and not a link, and it
creates `<dir>/<authorizationId>/` (`0700`, files `0600`) and the lock `c6-run.lock`. Nothing in it
is ever committed or published.

## 3. The H3 authorization template (NOT a valid authorization)

`rnnet.compat-authorization.v1`, canonical JSON (keys sorted, no spaces) followed by one newline,
in a file of mode `0600` owned by the founder, **outside every repository**. The three `<…>`
placeholders must be replaced by the founder; until then the text is not canonical JSON of the
right form and the command refuses it.

```json
{"authorizationId":"<AUTHORIZATION_ID>","evidenceDir":"<EVIDENCE_DIR, after approval: /home/vicvalch/rn-net-private/c6-evidence>","format":"rnnet.compat-authorization.v1","manifestSha256":"sha256:2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037","notAfter":"<NOT_AFTER>","providers":[{"id":"xrpl-testnet-ripple","requests":2,"url":"https://s.altnet.rippletest.net:51234/"},{"id":"xrpl-testnet-xrpl-labs","requests":2,"url":"https://testnet.xrpl-labs.com/"},{"id":"sepolia-publicnode","requests":9,"url":"https://ethereum-sepolia-rpc.publicnode.com/"},{"id":"sepolia-1rpc","requests":9,"url":"https://public.1rpc.io/sepolia"}],"publication":"none","requestBudget":22,"scope":"One founder-authorized, read-only C6 provider compatibility check for RN-NET Genesis Proof 01 against XRPL Testnet and Ethereum Sepolia. Exactly 22 authorized RPC requests maximum. No transaction signing, no broadcast, no account funding, no publication and no retry."}
```

- `<AUTHORIZATION_ID>`: 1 to 64 lower-case letters, digits and inner hyphens, never used before in
  the evidence directory (it names the run directory; a used id is refused).
- `<NOT_AFTER>`: `YYYY-MM-DDTHH:MM:SSZ`, in the future and **at most 60 minutes** after the time the
  command is started; it is checked at the start, after the approval, and before every request.
- `<EVIDENCE_DIR>`: exactly the approved `AGREED_EVIDENCE_DIR`.

A real authorization may be written only after (1) this PR has had its independent review, (2) the
founder has approved the evidence directory and merged or otherwise adopted the exact activation
diff, and (3) the founder explicitly approves the operational scope above. No authorization, no
authorization id, no expiry and no approval answer has been generated in this milestone. The
authorizations in `fixtures/compat-c6-live/` and those the tests write cannot authorize the run:
none names the agreed directory, and all expired in 2026-10 (`tools/compat-h3.test.mjs` checks this).

## 4. The single run (after all of §3; NOT executed in this milestone)

From a checkout of the reviewed activation commit, in a terminal (an interactive TTY), with no proxy,
TLS, `NODE_*` or `LD_*` variable set and no Node.js option:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin TERM="$TERM" \
  node tools/compat-live/compat-live.mjs \
    --authorization <path of the 0600 H3 file> \
    --endpoints config/rpc-endpoints.json \
    --evidence-dir /home/vicvalch/rn-net-private/c6-evidence
```

(`node` must be on that `PATH`; otherwise give its absolute path. `env -i` makes sure no proxy or
`NODE_OPTIONS` variable is inherited; the command refuses them anyway, `RNCL_TRANSPORT_ENVIRONMENT`.)

- Exactly these three arguments. `config/rpc-endpoints.json` must be the reviewed file (canonical
  SHA-256 `14ce613018c9f59f4c6a601e0333d979f3d3f46d84dfe8290e1445aeb4361246`; anything else is
  refused).
- **Terminal confirmation.** The prompt shows the manifest digest, each provider with its URL and
  count, the authorization id and `notAfter`, the scope, the run directory and the authorization
  digest. Press Ctrl-U, then type exactly `c6 <the last 16 hex digits of the authorization digest
  shown>` and Enter. Any other answer, or no terminal, refuses with nothing sent.
- **Exit statuses:** `0` PASS; `4` BLOCKED; `5` UNRESOLVED; `2` refused (`RNCL_*` code in the first
  line); `3` only if live access is disabled.
- **Output:** the outcome and code; the report digest with both verdicts, the Sepolia branch and
  "N of 22 requests sent"; every non-PASS check; the policy violation if any; the line "calls sent
  and durably recorded … SENT BUT NOT DURABLY RECORDED … refused before sending (never sent) …
  never reached …"; the run directory.

**Complete or incomplete.** A complete run has `report.json` in
`<dir>/<authorizationId>/`, exits 0, 4 or 5, and the Python reference says `AGREES`. An incomplete
run (`RNCL_EVIDENCE` or `RNCL_NOT_REPRODUCED`, exit 2) has no `report.json`; its journal and the
Python reference tell which calls were sent and recorded, sent (or possibly sent) but not
recorded, and never sent. An incomplete run is never completed or re-run.

**Timeouts and incompatibility: no retry.** A timeout, a refused method, a wrong network or a
disagreement is the run's evidence (UNRESOLVED or BLOCKED), never a reason to run again. The
authorization is spent whatever the outcome. Another run needs a new authorization (a new id and
expiry), the founder's new decision, and a new approval at the terminal.

**Independent verification of the evidence**, offline, before it is accepted:

```sh
python3 -I -B tools/reference/rnnet_compat_reference.py --run /home/vicvalch/rn-net-private/c6-evidence/<authorizationId> --record
```

It must end in `AGREES` (exit 0). It checks the authorization binding, rebuilds every request byte
for byte, checks every response digest and size, the journal, the evidence, and rebuilds
`report.json` byte for byte; `--record` writes `python-reference.txt` (`0600`, once). Then the founder
reviews the sanitized evidence. Nothing is published.

## 5. Post-run deactivation (mandatory; NOT performed in this milestone)

Right after the single run, whatever its outcome, and before anything else:

1. Leave the evidence directory alone: do not move, rename, edit or delete anything in
   `/home/vicvalch/rn-net-private/c6-evidence` (the authorization, journal, transcript, responses,
   evidence, report and `python-reference.txt` stay as written). The deactivation touches
   repository files only.
2. On a new branch from the current main, restore the two switches by reverting the activation
   merge commit (a new commit; no history rewritten, no force-push):
   ```sh
   git fetch origin && git switch -c fix/rn-net-03b2c6-h3-deactivate origin/main
   git revert --no-edit <the H3 activation merge commit>
   ```
   If main changed those files since, restore exactly `LIVE_NETWORK_ACCESS = false` and
   `AGREED_EVIDENCE_DIR = null`, the disabled pin in `tools/compat-live.test.mjs`, and the
   `compat-live/compat-live.mjs` entry in `tools/broadcast/live-disabled.check.mjs` by hand. The
   manifest and everything else stay as they are.
3. Verify, and record the output in the PR:
   ```sh
   git diff origin/main -- tools/compat-live/compat-live.mjs tools/compat-live/entry.mjs   # only the two lines back
   grep -n '^export const LIVE_NETWORK_ACCESS\|^export const AGREED_EVIDENCE_DIR' tools/compat-live/*.mjs
   node tools/compat-live/compat-live.mjs; echo "exit $?"                                  # RNCL_LIVE_DISABLED, exit 3
   unshare -rn node tools/broadcast/live-disabled.check.mjs                                # 5/5 entry points refuse
   unshare -rn tools/ci/offline-checks.sh                                                  # all pass
   ```
4. Open it as its own PR, have it reviewed, and merge it. The deactivation is complete when the
   merged main shows `false` and `null` and CI runs the live-disabled check at 5/5.

No automation triggers either the activation or the deactivation.

## 6. Risks and how they are bounded

| Risk | Bound |
|---|---|
| The activated command is run by accident (tests, CI, a script) | no test imports or starts it (guard: `compat-transport-join-transitive`); the live-disabled check reads it, never runs it; no package scripts, no scheduled workflow; it still needs the agreed directory to exist, a valid, unexpired H3 file and the typed approval on a terminal |
| More or other requests than reviewed | policy (byte-for-byte manifest requests, 2/2/9/9, 22) and the C6 transport (the four URLs, allowlisted methods, 22, one at a time), independently; no retry, no fallback |
| Traffic rerouted or TLS weakened | proxy, TLS, CA, preload and `LD_*` variables and any Node.js option refused; TLS verification stated; public addresses only, at DNS and on the socket; no redirect |
| Evidence lost or misread | journal before each request; whole-or-nothing files; no report for an incomplete run; the Python reference must agree |
| The activation outlives the run | the mandatory deactivation (§5), right after the run |
| The evidence directory path in the repository | it names a private directory only; it holds nothing secret, and its contents are never committed |

## 7. Offline verification of this branch

The activated wiring is tested only with injected fakes, under the offline preload and the network
namespace (`tools/compat-h3.test.mjs`): an invalid, expired or over-60-minute authorization, another
manifest digest, a changed provider URL or budget, publication, another evidence directory, the
real agreed directory unavailable (through a file system that refuses every call under it, so a
test never touches it), an unwritable directory, a used authorization id, no terminal, a refusal at
the terminal, an approved run of exactly 22 requests, and an interrupted run that is never replayed
or retried. Each refusal sends nothing.
