<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes_tool` or `query_graph_tool` instead of Grep
- **Understanding impact**: `get_impact_radius_tool` instead of manually tracing imports
- **Code review**: `detect_changes_tool` + `get_review_context_tool` instead of reading entire files
- **Finding relationships**: `query_graph_tool` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview_tool` + `list_communities_tool`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
| ------ | ---------- |
| `detect_changes_tool` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context_tool` | Need source snippets for review — token-efficient |
| `get_impact_radius_tool` | Understanding blast radius of a change |
| `get_affected_flows_tool` | Finding which execution paths are impacted |
| `query_graph_tool` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes_tool` | Finding functions/classes by name or keyword |
| `get_architecture_overview_tool` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes_tool` for code review.
3. Use `get_affected_flows_tool` to understand impact.
4. Use `query_graph_tool` pattern="tests_for" to check coverage.

# Project rules
 
## Code intelligence
This repo has a code graph. ALWAYS use the code-review-graph MCP
tools before Grep/Glob/Read. Start with get_minimal_context_tool, then
query_graph_tool with a specific target. Use get_impact_radius_tool before
changing shared code.
 
## Security guardrails
- NEVER print, log, or commit secrets, API keys, or .env contents.
- NEVER place the Supabase service role key in client code or any
  NEXT_PUBLIC_ / EXPO_PUBLIC_ variable.
- App and web app access the database with the anon key and rely
  on RLS. Privileged access is server-side only.
 
## Conventions
- TypeScript strict mode. Run typecheck and lint before done.
- Write or update tests for changed logic.

## AI reviewer delegation (Layovr AI Gateway)

You are the only agent that writes code. The gateway's reviewer tools are
read-only advisors. They never edit files, run commands, or touch git.

### When to call a reviewer

Call `review_security` when the change touches any of:
- authentication, session handling, or WorkOS SSO
- Supabase RLS policies, or any query that relies on RLS for isolation
- anything that reads or writes PII, or that adds a new analytics property
- file upload, deep links, or webhook handlers
- Edge Functions, middleware, or Cloudflare Workers on a request path

Call `review_architecture` when:
- the change spans more than five files, or crosses a package boundary
- it changes a contract consumed by a sibling repo
- it adds a migration that is not trivially reversible

Call `generate_adversarial_tests` after your own tests pass, on logic with
non-obvious edge cases: date/timezone handling, concurrency, pagination,
retry logic, permission checks.

Do NOT call a reviewer for: formatting, renames, copy changes, dependency
bumps, single-file edits with existing test coverage, or anything you have
already reviewed at the same commit SHA. `review_security` runs on
`gpt-5.6-sol` at $5/$30 per 1M tokens, so a large review is real money against
a $5 daily cap — `gateway_status` shows what is left.

Always pass the true output of `git rev-parse HEAD` as `commitSha`. It is the
cache key. Fabricating it either wastes money or serves you a stale verdict.

### Disagreement resolution

Apply in strict order. Higher levels override lower ones without debate.

1. **A deterministic signal wins.** A failing `tsc --noEmit`, a failing test,
   a failing build, a real runtime error. No model opinion outranks a red
   test — including your own reasoning about why the test is wrong.
2. **A security finding wins over design.** A `review_security` finding at
   HIGH or CRITICAL with `confidence: CONFIRMED` blocks the change. Fix it or
   escalate to Abdel; do not argue it away.
3. **Architecture guidance is advisory.** `review_architecture` governs
   structure only once tests pass and no security finding is open.
4. **SPECULATIVE findings are leads, not verdicts.** Verify them against the
   code yourself before acting. If you cannot verify one, say so and move on —
   do not implement a speculative fix.
5. **Unresolvable conflict escalates.** If two reviewers disagree at
   CONFIRMED confidence, stop and present both positions with the evidence.
   Do not pick a winner.

### Definition of done — layovr-landing

- The site builds and deploys to Cloudflare Pages without error.
- `git diff` self-reviewed for unintended edits.
- This repo has no package.json and no test suite; if you add build tooling,
  update this list in the same change rather than leaving it stale.
- No secret in any file. This is a static marketing site — it has no Supabase
  client and should not acquire one without a deliberate decision.
