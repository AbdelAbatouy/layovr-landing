#!/usr/bin/env node
/** Table-driven test for guard.mjs. Run: node .claude/hooks/guard.test.mjs */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const guard = path.join(here, "guard.mjs");

/**
 * This suite is copied verbatim into every repo, but guard.config.json is
 * per-repo — so branch-protection expectations must be DERIVED, not hard-coded.
 * A repo that legitimately allows pushing to its default branch would otherwise
 * fail these cases forever, and the obvious "fix" is deleting the config, which
 * silently removes an exemption someone chose deliberately.
 *
 * Everything that is NOT branch protection stays hard-coded. Relaxing branches
 * must never relax anything else, and that is the property worth pinning.
 */
const PROTECTED = (() => {
  try {
    const cfg = JSON.parse(readFileSync(path.join(here, "guard.config.json"), "utf8"));
    if (Array.isArray(cfg.protectedBranches)) return cfg.protectedBranches.filter((b) => typeof b === "string");
  } catch { /* absent or malformed -> strict default, same as the guard */ }
  return ["main", "master", "production", "release"];
})();

/** Expected decision for any push whose refspec targets `branch`. */
const branchPush = (branch) => (PROTECTED.includes(branch) ? "deny" : "allow");

// Assembled at runtime so this file contains no literal secret-shaped string.
// A hard-coded one is indistinguishable from a real leak to any scanner, and a
// credential check that cries wolf is one people learn to ignore.
const SB_SECRET = "sb_" + "secret_" + "AbCdEfGhIjKlMnOpQrSt";

const serviceJwt =
  "eyJhbGciOiJIUzI1NiJ9." +
  Buffer.from(JSON.stringify({ iss: "supabase", role: "service_role" })).toString("base64url") +
  ".sig";

/** @type {[string, object, "deny"|"ask"|"allow"][]} */
const CASES = [
  ["drop database",        { tool_name: "Bash", tool_input: { command: "psql -c 'DROP DATABASE prod'" } }, "deny"],
  ["truncate",             { tool_name: "Bash", tool_input: { command: "psql -c 'TRUNCATE TABLE users'" } }, "deny"],
  ["delete without where", { tool_name: "Bash", tool_input: { command: "psql -c 'DELETE FROM bookings;'" } }, "deny"],
  ["update without where", { tool_name: "Bash", tool_input: { command: "psql -c \"UPDATE users SET role='admin'\"" } }, "deny"],
  ["push to main",         { tool_name: "Bash", tool_input: { command: "git push origin main" } }, branchPush("main")],
  ["force push",           { tool_name: "Bash", tool_input: { command: "git push --force origin feat/x" } }, "deny"],
  ["force-with-lease ok",  { tool_name: "Bash", tool_input: { command: "git push --force-with-lease origin feat/x" } }, "allow"],
  ["push to feature ok",   { tool_name: "Bash", tool_input: { command: "git push origin feat/ask-layovr-redesign" } }, "allow"],
  ["branch named main-*",  { tool_name: "Bash", tool_input: { command: "git push origin feat/main-nav" } }, "allow"],
  ["branch named *master", { tool_name: "Bash", tool_input: { command: "git push origin fix/master-detail" } }, "allow"],
  ["push HEAD:main",       { tool_name: "Bash", tool_input: { command: "git push origin HEAD:main" } }, branchPush("main")],
  // git's global options sit between `git` and the subcommand. Before these
  // existed, `git -C <path> push origin main` was silently ALLOWED.
  ["git -C push to main",  { tool_name: "Bash", tool_input: { command: "git -C /r push origin main" } }, branchPush("main")],
  ["git -c push to main",  { tool_name: "Bash", tool_input: { command: "git -c core.pager=cat push origin main" } }, branchPush("main")],
  ["--git-dir push",       { tool_name: "Bash", tool_input: { command: "git --git-dir=/x/.git --work-tree=/x push origin master" } }, branchPush("master")],
  ["git -C force push",    { tool_name: "Bash", tool_input: { command: "git -C /r push --force origin feat" } }, "deny"],
  ["git -C reset --hard",  { tool_name: "Bash", tool_input: { command: "git -C /r reset --hard origin/main" } }, "deny"],
  ["git -C feature ok",    { tool_name: "Bash", tool_input: { command: "git -C /r push origin feat/main-nav" } }, "allow"],
  ["git -C status ok",     { tool_name: "Bash", tool_input: { command: "git -C /r status --porcelain" } }, "allow"],
  ["reset --hard origin",  { tool_name: "Bash", tool_input: { command: "git reset --hard origin/main" } }, "deny"],
  ["rm -rf home",          { tool_name: "Bash", tool_input: { command: "rm -rf ~" } }, "deny"],
  ["cat .env",             { tool_name: "Bash", tool_input: { command: "cat .env.local" } }, "deny"],
  ["cat .env.example ok",  { tool_name: "Bash", tool_input: { command: "cat .env.example" } }, "allow"],
  ["printenv",             { tool_name: "Bash", tool_input: { command: "printenv | grep SUPA" } }, "deny"],
  ["supabase db reset",    { tool_name: "Bash", tool_input: { command: "supabase db reset" } }, "deny"],
  ["supabase reset local", { tool_name: "Bash", tool_input: { command: "supabase db reset --local" } }, "allow"],
  ["supabase db push",     { tool_name: "Bash", tool_input: { command: "supabase db push" } }, "ask"],
  ["wrangler deploy",      { tool_name: "Bash", tool_input: { command: "npx wrangler pages deploy dist" } }, "ask"],
  ["eas production build", { tool_name: "Bash", tool_input: { command: "eas build --profile production -p ios" } }, "ask"],
  ["gh pr merge",          { tool_name: "Bash", tool_input: { command: "gh pr merge 42 --squash" } }, "ask"],
  ["normal test run",      { tool_name: "Bash", tool_input: { command: "npm test -- --coverage" } }, "allow"],
  ["typecheck",            { tool_name: "Bash", tool_input: { command: "npx tsc --noEmit" } }, "allow"],
  ["write service jwt",    { tool_name: "Write", tool_input: { file_path: "lib/db.ts", content: `const k="${serviceJwt}"` } }, "deny"],
  ["write anon jwt ok",    { tool_name: "Write", tool_input: { file_path: "lib/db.ts", content: `const k="eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ role: "anon" })).toString("base64url")}.sig"` } }, "allow"],
  ["write openai key",     { tool_name: "Write", tool_input: { file_path: "a.ts", content: "const k='sk-proj-abcdefghijklmnopqrstuvwxyz0123'" } }, "deny"],
  ["write public secret",  { tool_name: "Write", tool_input: { file_path: ".env", content: "EXPO_PUBLIC_SERVICE_ROLE_KEY=x" } }, "deny"],
  ["edit private key",     { tool_name: "Edit", tool_input: { new_string: "-----BEGIN RSA PRIVATE KEY-----" } }, "deny"],
  ["normal write ok",      { tool_name: "Write", tool_input: { file_path: "a.ts", content: "export const x = 1;" } }, "allow"],
  ["heredoc secret",       { tool_name: "Bash", tool_input: { command: "cat > .env <<EOF\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\nEOF" } }, "deny"],
  ["redirect to src",      { tool_name: "Bash", tool_input: { command: "printf 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' > src/keys.ts" } }, "deny"],
  ["tee smuggling",        { tool_name: "Bash", tool_input: { command: "printf '%s' 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' | tee src/keys.ts" } }, "deny"],
  ["python -c smuggling",  { tool_name: "Bash", tool_input: { command: "python3 -c 'open(\"k.ts\",\"w\").write(\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\")'" } }, "deny"],
  ["fine-grained PAT",     { tool_name: "Write", tool_input: { file_path: "a.ts", content: "const t='github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ'" } }, "deny"],
  ["notebook secret",      { tool_name: "NotebookEdit", tool_input: { new_source: "KEY='ghp_abcdefghijklmnopqrstuvwxyz0123456789'" } }, "deny"],
  ["cp env example ok",    { tool_name: "Bash", tool_input: { command: "cp .env.example .env" } }, "allow"],
  ["append to gw env ok",  { tool_name: "Bash", tool_input: { command: "echo 'POSTHOG_HOST=https://us.i.posthog.com' >> ~/Code/layovr-ai-gateway/.env" } }, "allow"],
  ["count env lines ok",   { tool_name: "Bash", tool_input: { command: "grep -c . .env" } }, "allow"],
  ["unknown tool ok",      { tool_name: "Read", tool_input: { file_path: ".env" } }, "allow"],
  ["empty payload ok",     {}, "allow"],

  // ---- restored 2026-08-18: rules from incidents this project actually had ----
  // These were dropped by an upstream guard.mjs update. Re-added because each
  // one exists for something that already happened here.
  ["api-keys unpiped",     { tool_name: "Bash", tool_input: { command: "supabase projects api-keys --project-ref abc" } }, "deny"],
  ["api-keys piped ok",    { tool_name: "Bash", tool_input: { command: "supabase projects api-keys --project-ref abc | node -e 'x'" } }, "allow"],
  ["api-key delete",       { tool_name: "Bash", tool_input: { command: "supabase projects api-keys delete --name default" } }, "ask"],
  // Both of these returned allow until 2026-08-20, while db push and wrangler
  // deploy returned ask — an omission. functions deploy ships code to the live
  // project; secrets set writes a production credential.
  ["functions deploy",     { tool_name: "Bash", tool_input: { command: "supabase functions deploy whats-on-events" } }, "ask"],
  ["secrets set",          { tool_name: "Bash", tool_input: { command: "supabase secrets set PUBLIC_RATE_LIMIT_SALT=abc" } }, "ask"],
  // Interposed global flags must not walk past the gate — the `git -C` bypass
  // shape. A regex anchoring the subcommand directly after `supabase` fails these.
  ["deploy behind a flag", { tool_name: "Bash", tool_input: { command: "supabase --experimental functions deploy whats-on-events" } }, "ask"],
  ["secrets set w/ flag",  { tool_name: "Bash", tool_input: { command: "supabase --workdir /tmp/x secrets set FOO=bar" } }, "ask"],
  // Negatives: read-only and local forms stay allow, or the gate becomes noise
  // that people learn to click through.
  ["functions serve ok",   { tool_name: "Bash", tool_input: { command: "supabase functions serve" } }, "allow"],
  ["secrets list ok",      { tool_name: "Bash", tool_input: { command: "supabase secrets list" } }, "allow"],
  ["functions list ok",    { tool_name: "Bash", tool_input: { command: "supabase functions list" } }, "allow"],
  ["functions new ok",     { tool_name: "Bash", tool_input: { command: "supabase functions new my-fn" } }, "allow"],
  ["write sb_secret_",     { tool_name: "Write", tool_input: { file_path: "lib/db.ts", content: `const k='${SB_SECRET}'` } }, "deny"],
  ["redirect sb_secret_",  { tool_name: "Bash", tool_input: { command: `echo '${SB_SECRET}' > src/k.ts` } }, "deny"],
  // The publishable half is public by design and committed in eas.json — a
  // guard that blocks legitimate work gets itself disabled.
  ["write publishable ok", { tool_name: "Write", tool_input: { file_path: "eas.json", content: '"EXPO_PUBLIC_SUPABASE_ANON_KEY": "sb_publishable_AbCdEfGhIjKlMnOpQrSt"' } }, "allow"],
];

let pass = 0;
let fail = 0;
for (const [label, payload, expected] of CASES) {
  const stdout = execFileSync(process.execPath, [guard], { input: JSON.stringify(payload), encoding: "utf8" });
  const got = stdout.trim() ? JSON.parse(stdout).hookSpecificOutput.permissionDecision : "allow";
  if (got === expected) {
    pass += 1;
  } else {
    fail += 1;
    console.error(`FAIL  ${label.padEnd(22)} expected ${expected}, got ${got}`);
  }
}

console.log(`${fail === 0 ? "PASS" : "FAIL"}  guard.mjs  ${pass}/${CASES.length} cases`);
process.exit(fail === 0 ? 0 : 1);
