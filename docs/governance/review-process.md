# Review process while RN-NET has one maintainer

- Status: Interim process, adopted with RN-NET-01H
- Source: independent post-merge review of RN-NET-01, finding F2

## Finding

The `protect-main` ruleset requires pull requests and three status checks (`verify`, `guards`,
`dependency-review`, bound to the GitHub Actions app), but **zero approving reviews**. A pull
request runs the workflow file from its own branch. A pull request could therefore change
`.github/workflows/ci.yml` so that a job named `verify` does nothing, show every required
check as passing, and be merged by its author.

What limits this today:

- only the founder has write access, and the bypass list is empty;
- workflows from forks need approval before they run;
- after a merge, the push to `main` runs the workflow from `main`.

None of these is a second person looking at the change. **Passing required checks is not a
substitute for independent review.** They show that the checks in the pull request passed,
not that the checks themselves are the right ones.

## Interim process

Until a second maintainer exists:

1. **Sensitive paths.** A pull request that changes any of `.github/**`, `tools/**`,
   `spec/**`, `vectors/**` or `docs/adr/**` is security-relevant. Its description must say
   so and list those files.
2. **Independent review before merge.** Every pull request, and always a sensitive one, gets
   a review that does not rely on its author's reasoning: an independent reviewer (a person,
   or a separately instructed review agent given the code and not the author's conclusions)
   whose findings are recorded in the pull request before merging.
3. **Draft until reviewed.** Pull requests stay in draft until that review is recorded and
   its blocking findings are resolved.
4. **Read the workflow diff.** Before merging, the founder reads the full diff of
   `.github/workflows/` and of `tools/ci/`, and confirms that every required job still runs
   the real checks.
5. **Confirm after merge.** After merging, confirm that the push run of `CI` on `main` passed
   with `main`'s own workflow.

## When a second maintainer joins

Change `protect-main` to require at least one approving review, code-owner review and
approval of the most recent push, and extend `.github/CODEOWNERS` so that the sensitive paths
above require that review. Ruleset changes are made by the founder; they are not part of any
implementation pull request.
