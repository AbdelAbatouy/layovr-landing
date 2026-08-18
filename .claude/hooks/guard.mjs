#!/usr/bin/env node
/**
 * PreToolUse guard for Bash, Write, Edit and NotebookEdit.
 *
 * Contract (Claude Code hooks):
 *   - the hook payload arrives as JSON on STDIN, not as $1
 *   - exit 0 with JSON on stdout to make a permission decision
 *   - exit 2 blocks and feeds stderr back to Claude
 *   - anything else is a non-blocking error
 *
 * This script fails OPEN on its own internal errors: a broken guard must not
 * brick the session. It fails CLOSED on the rules it actually understands.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/** @typedef {{decision:"deny"|"ask", reason:string}} Rule */

/**
 * Per-repo overrides, from `.claude/hooks/guard.config.json` next to this file.
 *
 * Exists for one real case: a repo with no pull-request workflow, where pushing
 * to its own default branch is the normal and correct thing to do. Blocking it
 * there buys nothing and teaches people to route around the guard, which is how
 * guards die. The override is a committed file rather than an env var so the
 * exemption is visible in review.
 *
 *   { "protectedBranches": [] }        // no branch protection in this repo
 *   { "protectedBranches": ["main"] }  // narrow it
 *
 * Absent or malformed config falls back to the strict default.
 */
function loadConfig() {
  const fallback = { protectedBranches: ["main", "master", "production", "release"] };
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const cfg = JSON.parse(readFileSync(path.join(here, "guard.config.json"), "utf8"));
    return {
      protectedBranches: Array.isArray(cfg.protectedBranches)
        ? cfg.protectedBranches.filter((b) => typeof b === "string")
        : fallback.protectedBranches,
    };
  } catch {
    return fallback;
  }
}

const PROTECTED_BRANCHES = loadConfig().protectedBranches;

/**
 * `git` plus any of its GLOBAL options, up to the subcommand.
 *
 * Without this, `\bgit\s+push\b` misses `git -C /path push origin main` and
 * `git -c core.pager=cat push origin main` — the subcommand isn't adjacent to
 * `git`, so every push rule silently does nothing. Options that take a separate
 * value have to be spelled out, otherwise `-C` swallows the path and the match
 * still fails.
 *
 * Verified gap, not hypothetical: `git -C ~/repo push origin main` was ALLOWED
 * by the previous pattern.
 */
const GIT = String.raw`\bgit(?:\s+(?:-C\s+\S+|-c\s+\S+|--git-dir(?:=|\s+)\S+|--work-tree(?:=|\s+)\S+` +
  String.raw`|--namespace(?:=|\s+)\S+|--exec-path(?:=\S+)?|--no-pager|--paginate|--no-replace-objects` +
  String.raw`|--bare|--literal-pathspecs|--no-optional-locks))*\s+`;

/** Commands that are never acceptable from an agent session. */
const BASH_DENY = [
  {
    re: /\bDROP\s+(DATABASE|SCHEMA)\b/i,
    reason: "DROP DATABASE/SCHEMA is blocked. Write a reversible migration in supabase/migrations/ instead.",
  },
  {
    re: /\bTRUNCATE\s+(TABLE\s+)?\w/i,
    reason: "TRUNCATE is blocked. If you need to clear data, do it in a migration with an explicit WHERE-scoped DELETE.",
  },
  {
    re: /\bDELETE\s+FROM\s+[\w."]+\s*(;|$)/i,
    reason: "Unqualified DELETE FROM (no WHERE clause) is blocked.",
  },
  {
    re: /\bUPDATE\s+[\w."]+\s+SET\b(?![\s\S]*\bWHERE\b)/i,
    reason: "UPDATE without a WHERE clause is blocked.",
  },
  {
    re: new RegExp(`${GIT}push\\b[^\\n]*--force(?!-with-lease)`),
    reason: "git push --force is blocked. Use --force-with-lease, and never on a protected branch.",
  },
  // An empty protectedBranches list must disable this rule, not compile
  // `(?:)` — which matches the empty string and would deny every git push.
  ...(PROTECTED_BRANCHES.length === 0 ? [] : [{
    // Anchored to a refspec position so `git push origin feat/main-nav` is not
    // caught by the substring "main". Bare `git push` while standing on a
    // protected branch is covered by the permissions.ask rule, not here.
    re: new RegExp(
      `${GIT}push\\b[^\\n]*\\s(?:HEAD:)?(?:refs/heads/)?(?:${PROTECTED_BRANCHES.join("|")})(?::|\\s|$)`,
    ),
    reason: `Direct push to a protected branch (${PROTECTED_BRANCHES.join(", ")}) is blocked. Open a pull request.`,
  }]),
  {
    re: new RegExp(`${GIT}(?:reset\\s+--hard\\s+origin|clean\\s+-[a-z]*f[a-z]*d|checkout\\s+--\\s+\\.)`),
    reason: "This command discards uncommitted work irreversibly. Commit or stash first, then re-run it yourself.",
  },
  {
    re: /\brm\s+-[a-z]*r[a-z]*f?\s+(\/|~|\$HOME)(\s|$)/,
    reason: "Recursive delete of a filesystem root or home directory is blocked.",
  },
  {
    re: /\b(cat|bat|less|more|head|tail|open)\s+[^\n|]*\.env(?!\.(?:example|sample|template|dist))(\.|\s|$)/,
    reason:
      "Reading .env files into the transcript is blocked — it copies live credentials into model context. " +
      "Use `grep -c . .env` to confirm a file exists, or read .env.example instead.",
  },
  {
    // Anchored to a command position. `\b(env)` alone would match the tail of
    // any path ending in ".env", denying `cp .env.example .env` with a reason
    // about environment dumping — a confusing, unrelated failure.
    re: /(^|[;&|]\s*)(printenv|env)\s*(\||$)/,
    reason: "Dumping the environment is blocked; it exposes every secret in the shell to model context.",
  },
  {
    // `supabase projects api-keys` prints legacy anon and service_role JWTs in
    // full — it redacts sb_secret_ but NOT the legacy pair. That is exactly how
    // a leaked service-role key reached a transcript on 2026-08-03. Scoped to
    // the listing form so the delete subcommand reaches its own ask rule below.
    re: /\bsupabase\s+projects\s+api-keys\b(?![\s\S]*\|)(?![\s\S]*\b(?:delete|rm|revoke|create|update)\b)/,
    reason:
      "`supabase projects api-keys` prints legacy anon and service_role JWTs in full. " +
      "Pipe it through a filter that prints only the fields you need.",
  },
  {
    re: /\bsupabase\s+db\s+reset\b(?![\s\S]*--local)/,
    reason: "`supabase db reset` without --local can destroy a linked remote database.",
  },
];

/** Commands that are legitimate but should never happen without a human saying yes. */
const BASH_ASK = [
  {
    re: /\bsupabase\s+db\s+push\b/,
    reason: "This applies migrations to the linked Supabase project. Confirm the target is the intended environment.",
  },
  {
    re: /\b(vercel|wrangler)\s+[^\n]*\b(deploy|--prod|--prod\b)/,
    reason: "This is a production deployment. Confirm before shipping.",
  },
  {
    re: /\beas\s+(build|submit|update)\b[^\n]*\bproduction\b/,
    reason: "This targets an EAS production build/submission. Confirm before spending build minutes or shipping to stores.",
  },
  {
    re: /\bgh\s+(pr\s+merge|release\s+create)\b/,
    reason: "This merges or releases. Confirm before it lands.",
  },
  {
    re: /\bnpm\s+publish\b/,
    reason: "This publishes a package to the registry.",
  },
  {
    // Deleting a Supabase API key is irreversible: the same value can never be
    // reissued, so a wrong deletion means a new key and redeploying every
    // consumer.
    re: /\bsupabase\s+[^\n]*\bapi-keys\b[^\n]*\b(delete|rm|revoke)\b/,
    reason: "Deleting a Supabase API key is irreversible; the same value can never be reissued. Confirm the key name.",
  },
];

/** Secret shapes that must never be written into a file by the agent. */
const CONTENT_DENY = [
  { re: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}/, label: "an OpenAI API key" },
  { re: /\bAIza[0-9A-Za-z_-]{35}/, label: "a Google API key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}/, label: "a GitHub token" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{50,}/, label: "a GitHub fine-grained PAT" },
  { re: /\bpplx-[A-Za-z0-9]{32,}/, label: "a Perplexity API key" },
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, label: "an AWS access key ID" },
  { re: /\bph[xsar]_[A-Za-z0-9]{32,}/, label: "a PostHog personal API key" },
  // Supabase's post-JWT service credential. Unlike a JWT it carries no decodable
  // role claim, so shape alone is the signal. The publishable half is public by
  // design and is deliberately NOT listed — it is committed in eas.json.
  { re: /\bsb_secret_[A-Za-z0-9_-]{10,}/, label: "a Supabase secret key (sb_secret_…)" },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, label: "a private key block" },
  { re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@]+@/, label: "a database URL with an inline password" },
];

/** Client-exposed prefixes that must never carry a secret-looking value. */
const PUBLIC_PREFIX = /\b(EXPO_PUBLIC_|NEXT_PUBLIC_|VITE_)[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|API_KEY|TOKEN|PASSWORD)/;

function decodeJwtRole(token) {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json).role ?? null;
  } catch {
    return null;
  }
}

/** @returns {Rule|null} */
function inspectContent(text) {
  if (typeof text !== "string" || text.length === 0) return null;

  for (const jwt of text.match(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g) ?? []) {
    const role = decodeJwtRole(jwt);
    if (role && role !== "anon" && role !== "authenticated") {
      return { decision: "deny", reason: `Refusing to write a privileged Supabase JWT (role="${role}") into a file. Reference it via process.env from a server-only context.` };
    }
  }
  for (const { re, label } of CONTENT_DENY) {
    if (re.test(text)) {
      return { decision: "deny", reason: `Refusing to write ${label} into a file. Put it in .env (gitignored) and read it via process.env.` };
    }
  }
  if (PUBLIC_PREFIX.test(text)) {
    return { decision: "deny", reason: "A client-exposed variable (EXPO_PUBLIC_/NEXT_PUBLIC_/VITE_) is being given a secret-shaped name. Anything with those prefixes ships in the client bundle." };
  }
  return null;
}

/**
 * Shell constructs that can write a file without going through Write/Edit.
 * Anything matching gets its whole command text content-inspected.
 */
const WRITES_A_FILE = /(>>?|<<|\btee\b|\bsed\s+-i|\b(?:python3?|node|perl|ruby)\s+-[ce]\b|\bdd\b)/;

/** @returns {Rule|null} */
function evaluate(payload) {
  const tool = payload.tool_name;
  const input = payload.tool_input ?? {};

  if (tool === "Bash") {
    const command = typeof input.command === "string" ? input.command : "";
    if (!command) return null;
    for (const { re, reason } of BASH_DENY) if (re.test(command)) return { decision: "deny", reason };
    for (const { re, reason } of BASH_ASK) if (re.test(command)) return { decision: "ask", reason };
    // Redirects, heredocs, tee and `-c`/`-e` one-liners can all smuggle a
    // secret into a file without ever invoking the Write or Edit tool.
    return inspectContent(WRITES_A_FILE.test(command) ? command : "");
  }

  if (tool === "Write") return inspectContent(input.content);
  if (tool === "Edit") return inspectContent(input.new_string);
  if (tool === "NotebookEdit") return inspectContent(input.new_source);
  return null;
}

function main() {
  let payload;
  try {
    payload = JSON.parse(readFileSync(0, "utf8") || "{}");
  } catch {
    // Malformed payload is not the user's fault — do not block the session.
    process.exit(0);
  }

  let rule = null;
  try {
    rule = evaluate(payload);
  } catch (err) {
    process.stderr.write(`guard.mjs internal error (failing open): ${err.message}\n`);
    process.exit(0);
  }

  if (!rule) process.exit(0);

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: rule.decision,
        permissionDecisionReason: rule.reason,
      },
    }),
  );
  process.exit(0);
}

main();
