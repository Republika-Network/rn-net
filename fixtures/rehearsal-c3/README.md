# fixtures/rehearsal-c3 (RN-NET-03B2-C3)

**The offline end-to-end rehearsal of Genesis Proof 01.** Simulated providers, a simulated clock
and public test keys only: nothing was read from or sent to a network, and no real key exists.

`rehearsal.json` (`rnnet.genesis-rehearsal.v1`, canonical JSON) holds one report per scenario.
Each report covers the whole chain, with the elapsed time of every stage on the simulated clock:
1. evidence verification;
2. the 42-byte payload;
3. preparation (`tools/prepare/prepare-live.mjs`);
4. gate D in the key tool;
5. signing with the public B1 test key;
6. JS and Python verification;
7. the founder's broadcast authorization;
8. submission (`tools/submit/submit-anchor.mjs`);
9. the same authorization again;
10. the status check (`tools/submit/status-check.mjs`);
11. evidence assembly.

**The clock.** Requests cost 500 ms each. Human steps have the durations in `profile`. XRPL closes
a ledger every 3, 4 or 5 s, and provider b reports one ledger less than provider a. Sepolia makes a
block every 12 s.

**Scenarios:**
- **Nominal runs:** one at each ledger interval, and one on Sepolia.
- **Expiry during approval:**
  - XRPL, during gate D;
  - XRPL, during the submit approval;
  - Sepolia, `notAfter` passing during the submit approval.
- **The window:** for each ledger interval, the latest gate-D review time (found by search) that
  still lets the submission go out, recorded with the run one second longer, which is refused
  before any write.

**Rebuilding.** `node tools/rehearsal/build-c3-rehearsal.mjs <python3>` checks the file, with the
Python reference verifier as a real subprocess; `--write` writes it and refuses to overwrite.
`tools/ci/offline-checks.sh` runs the check inside the network namespace.

**Independent checks:**
- `tools/rehearsal.test.mjs` replays every scenario with the JavaScript verifier.
- `tools/reference/rnnet_rehearsal_reference.py` reproduces the decisions without the JavaScript
  code: preparation from the recorded answers, the `+ 80` binding, the clock, the expiry rule, the
  signatures, the duplicate refusal and the stage times.
