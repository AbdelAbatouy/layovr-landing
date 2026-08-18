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

/** @typedef {{decision:"deny"|"ask", reason:string}} Rule */

const PROTECTED_BRANCHES = ["main", "master", "production", "release"];

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
    re: /\bgit\s+push\b[^\n]*--force(?!-with-lease)/,
    reason: "git push --force is blocked. Use --force-with-lease, and never on a protected branch.",
  },
  {
    // Anchored to a refspec position so `git push origin feat/main-nav` is not
    // caught by the substring "main". Bare `git push` while standing on a
    // protected branch is covered by the permissions.ask rule, not here.
    re: new RegExp(
      `\\bgit\\s+push\\b[^\\n]*\\s(?:HEAD:)?(?:refs/heads/)?(?:${PROTECTED_BRANCHES.join("|")})(?::|\\s|$)`,
    ),
    reason: `Direct push to a protected branch (${PROTECTED_BRANCHES.join(", ")}) is blocked. Open a pull request.`,
  },
  {
    re: /\bgit\s+(reset\s+--hard\s+origin|clean\s+-[a-z]*f[a-z]*d|checkout\s+--\s+\.)/,
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
    re: /\bsupabase\s+db\s+reset\b(?![\s\S]*--local)/,
    reason: "`supabase db reset` without --local can destroy a linked remote database.",
  },
  {
    // Added 2026-08-16. `supabase projects api-keys` prints legacy anon and
    // service_role JWTs in full — it redacts sb_secret_ values but NOT the
    // legacy pair. That is exactly how a leaked service-role key ended up in
    // a transcript on 2026-08-03. Pipe it through a filter instead.
    // Scoped to the LISTING form. A subcommand (delete/create/update) prints no
    // key material, and `delete` has its own ask rule below — without this
    // exclusion the deny fires first and the ask is unreachable.
    re: /\bsupabase\s+projects\s+api-keys\b(?![\s\S]*\|)(?![\s\S]*\b(?:delete|rm|revoke|create|update)\b)/,
    reason:
      "`supabase projects api-keys` prints legacy anon and service_role JWTs in full. " +
      "Pipe it through a filter that prints only the fields you need, e.g. `| node -e '…'`.",
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
    // Added 2026-08-16. Deleting a Supabase API key is irreversible — the value
    // cannot be recreated, so a wrong deletion means issuing a new key and
    // redeploying every consumer.
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
  // Added 2026-08-16: Supabase's post-JWT secret key. It carries no decodable
  // role claim, so shape alone is the signal — and it is now the live
  // production service credential.
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
