---
name: adr
description: Draft an Architecture Decision Record from the change in progress, using MADR 4.0.0. Use when a decision has been made that changes structure, a contract, a dependency, or a security posture — or when the user asks to record a decision.
argument-hint: "[short title of the decision]"
allowed-tools: Bash(git:*) Bash(ls:*) Read Write mcp__layovr-ai-gateway__review_architecture mcp__graphify__get_community mcp__graphify__god_nodes
---

## Existing decisions

!`{ ls -1 docs/decisions/ 2>/dev/null || echo "(none yet — this will be 0001)"; } | tail -5`

## Current change

Branch: !`git branch --show-current`
Changed files: !`if git rev-parse --verify --quiet origin/HEAD >/dev/null; then git diff --stat origin/HEAD...HEAD; else git diff --stat HEAD; fi | tail -20`

## Task

Write an ADR for: $ARGUMENTS

1. **Number it.** Next consecutive four-digit number from the listing above.
   Filename `docs/decisions/NNNN-title-with-dashes.md`, lowercase, hyphenated.

2. **Fill it from evidence, not from imagination.** Use the actual diff for what
   changed. Use `git log` for when and by whom. If a gateway review ran at this
   commit, quote its verdict in `### Confirmation`. Use the graph tools to name
   the affected community and any god nodes the decision touches.

3. **Start from `~/Documents/Obsidian Vault/Layovr/_templates/adr.md`** — the
   MADR bare template. Do not invent a structure. Keep frontmatter values
   unquoted-empty or plainly quoted; never leave a `{placeholder}`, which is
   invalid YAML for Obsidian's Properties view.

4. **Considered Options must contain at least two real options**, one of which
   is what you actually did. An ADR with one option is a changelog entry. If
   there genuinely was no alternative, say so explicitly in Decision Drivers
   and note the constraint that forced it.

5. **`### Confirmation` is not optional here.** State how someone in six months
   verifies this decision is still honoured — a test, a lint rule, an RLS
   policy, a CI check. If there is no mechanical check, say that too, plainly.

6. **In `## More Information`, wikilink the code.** Reference the Code Graph
   notes for the modules this governs, e.g. `[[Code Graph/tripmesh/lib_auth.ts]]`.

7. **Stop and show me the draft.** Do not commit it. An ADR I did not read is
   worse than no ADR, because it looks like a decision was considered.

After I approve, run `npm --prefix ~/Code/layovr-ai-gateway run vault-sync` to
mirror it into the vault.
