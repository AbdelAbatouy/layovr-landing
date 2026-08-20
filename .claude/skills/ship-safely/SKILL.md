---
name: ship-safely
description: Full pre-PR review pipeline — typecheck, test, security review via the AI gateway, then open the PR. Use when the user says they're ready to ship, open a PR, or wants a change reviewed before merging.
argument-hint: "[optional: PR title]"
allowed-tools: Bash(git:*) Bash(npm:*) Bash(npx tsc:*) Bash(gh pr create:*) mcp__layovr-ai-gateway__review_security mcp__layovr-ai-gateway__review_architecture mcp__layovr-ai-gateway__gateway_status
---

## Current state

Branch: !`git branch --show-current`
Commit: !`git rev-parse HEAD`
Changed files: !`git diff --stat origin/HEAD...HEAD 2>/dev/null || git diff --stat`

## Pipeline

Run these in order. Stop at the first failure and report it — do not continue
past a red gate.

1. **Deterministic gates.** `npx tsc --noEmit`, then the test suite. Use the
   per-repo commands in this repo's CLAUDE.md "Definition of done" — in
   tripmesh the tsc baseline is 184 errors, not zero, and there is no lint
   step. If either gate fails, fix it and restart from step 1.

2. **Refresh the code graph.** `graphify update .` — AST only, no API cost,
   incremental. Do this before scoping so impact questions are answered from
   current structure rather than a stale build.

3. **Scope the review.** Get the diff against the base branch. Decide from the
   delegation rules in CLAUDE.md whether this needs `review_security`,
   `review_architecture`, both, or neither. State your reasoning in one line.

4. **Budget check.** Call `gateway_status`. If remaining budget is under $0.50,
   say so and ask before proceeding.

5. **Review.** Call the tools you selected, passing the real `git rev-parse HEAD`
   as `commitSha` and the actual diff as `context`. For `review_security`, write
   a one-paragraph threat model — an unauthenticated attacker, a hostile tenant
   in the same org, whatever fits the change.

6. **Triage the findings.** For each finding: CONFIRMED at HIGH or CRITICAL
   blocks the PR and you fix it now. LIKELY gets verified against the code
   before you act. SPECULATIVE gets a one-line note in the PR body, not a fix.
   Anything in `unverifiable` gets stated plainly as a review gap.

7. **Re-run step 1** if you changed anything in step 5.

8. **Open the PR.** Body must include: what changed and why, which reviewers ran
   and their verdicts, findings fixed, findings deferred with reasons, and
   review gaps. Never push to a protected branch — the guard hook blocks it,
   and it should.

9. **Ask about an ADR.** If the change altered structure, a contract, a
   dependency or a security posture, offer `/adr` — do not write one
   unprompted. An ADR nobody read is worse than none, because it looks like a
   decision was considered.
