#!/usr/bin/env node
// Conditional instructions: fragments of agent guidance that load only while their condition holds.
//
// AGENTS.md / CLAUDE.md load in full on every session and can be lost to compaction. A fragment is
// a markdown file with front-matter instead:
//
//   ---
//   when: the task touches front-end React code        natural-language condition, judged by Jev
//   paths: ["web/**/*.tsx", "**/*.css"]                 optional globs: a mentioned or recently touched file matches
//   keywords: [react, tailwind]                         optional words in the prompt
//   ---
//   Use the design tokens in web/theme.ts ...
//
// On every user prompt, deterministic matches (paths, keywords) are taken first; the remaining
// fragments go to Jev in ONE request, one noul question each. Fragments at or above the threshold
// are injected into that turn, so they come back whenever the condition holds, compaction or not.
// Instructions are advisory, not safety: any error injects nothing and never blocks the prompt.
//
//   node instructions.mjs --claude | --codex    UserPromptSubmit hook (additionalContext)
//   node instructions.mjs --hermes              Hermes pre_llm_call shell hook ({"context": ...})
//   node instructions.mjs --select              JSON {prompt, cwd, recent_files?} on stdin -> {text, fragments}
//   node instructions.mjs --check "<prompt>" [--cwd dir] [--files a,b]
//   node instructions.mjs --selfcheck           offline, Jev stubbed
import {cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {homedir, tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {CONFIG, append, ask, cacheGet, cachePut, readText, redact, sessionContext, sha, transcriptTail} from "./gate.mjs";

const ENV = process.env;
const LOG = join(CONFIG.data, "instructions.jsonl");
export const THRESHOLD = Number(ENV.REFLEX_INSTRUCTIONS_THRESHOLD ?? 0.5);
export const MAX_CHARS = Number(ENV.REFLEX_INSTRUCTIONS_MAX_CHARS ?? 6000);   // Codex caps hook context at ~2,500 tokens

// ---------------------------------------------------------------------------------------------
// Fragments. ponytail: a front-matter subset (key: value, [a, b] lists, "- item" lists), not YAML.
const unquote = s => s.trim().replace(/^(["'])(.*)\1$/, "$2");
const list = v => v == null ? [] : Array.isArray(v) ? v.map(unquote)
  : v.replace(/^\[|\]$/g, "").split(",").map(unquote).filter(Boolean);
export function parseFragment(text, id) {
  const m = text?.match(/^---\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)([\s\S]*)$/);
  if (!m) return null;
  const meta = {};
  let key;
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([\w-]+):\s*(.*)$/);
    if (kv) { key = kv[1]; meta[key] = kv[2].trim() || undefined; continue; }
    const item = line.match(/^\s*-\s+(.*)$/);
    if (item && key) meta[key] = [...(Array.isArray(meta[key]) ? meta[key] : []), item[1].trim()];
  }
  const f = {id: meta.id ? unquote(meta.id) : id, when: meta.when ? unquote(meta.when) : null,
             paths: list(meta.paths), keywords: list(meta.keywords), body: m[2].trim()};
  return f.body && (f.when || f.paths.length || f.keywords.length) ? f : null;
}

// <dir>/.reflex/instructions/*.md from cwd up to the root, then the user's own. The nearest
// fragment with a given id wins, so a repo can override a personal one.
export function discover(cwd, home = homedir()) {
  const dirs = [];
  for (let d = cwd; d; d = dirname(d) === d ? null : dirname(d)) dirs.push(join(d, ".reflex/instructions"));
  dirs.push(join(ENV.XDG_CONFIG_HOME ?? join(home, ".config"), "reflex/instructions"));
  const found = new Map();
  for (const dir of dirs) {
    let names = [];
    try { names = readdirSync(dir).filter(n => n.endsWith(".md")).sort(); } catch { continue; }
    for (const n of names) {
      const f = parseFragment(readText(join(dir, n)), n.replace(/\.md$/, ""));
      if (f && !found.has(f.id)) found.set(f.id, {...f, file: join(dir, n)});
    }
  }
  return [...found.values()];
}

// ---------------------------------------------------------------------------------------------
// Deterministic matching. A glob matches a path or any trailing part of it, so `web/**/*.tsx`
// matches /home/me/repo/web/src/App.tsx. ponytail: suffix matching can over-match (`src/**` in
// another tree); a false match only costs context, never safety.
const globRe = g => new RegExp("^" + g.split(/(\*\*\/|\*\*|\*|\?|\{[^}]*\})/).map(t =>
  t === "**/" ? "(?:.*/)?" : t === "**" ? ".*" : t === "*" ? "[^/]*" : t === "?" ? "[^/]" :
  t.startsWith("{") ? `(?:${t.slice(1, -1).split(",").map(esc).join("|")})` : esc(t)).join("") + "$");
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export const pathMatches = (glob, p) => {
  const re = globRe(glob), parts = p.split("/");
  return parts.some((_, i) => re.test(parts.slice(i).join("/")));
};
// Words in the prompt that look like paths: contain a slash or end in a short extension.
export const pathsIn = prompt => (prompt.match(/[^\s'"`,;()<>[\]]+/g) ?? [])
  .map(t => t.replace(/[.:!?]+$/, "").replace(/:\d+(:\d+)?$/, ""))   // web/a.tsx:12 -> web/a.tsx
  .filter(t => /\/|\.[A-Za-z]\w{0,5}$/.test(t) && !/^\w+:\/\//.test(t));
const keywordHit = (k, prompt) => new RegExp(`(^|[^\\w])${esc(k)}([^\\w]|$)`, "i").test(prompt);

// Files the agent touched recently, from any transcript that keeps tool inputs as JSON (Claude
// Code: file_path; Codex: apply_patch headers). ponytail: a regex over the tail, not a parser.
export function recentFiles(transcriptPath) {
  const t = transcriptTail(transcriptPath);
  const files = [...t.matchAll(/\\?"(?:file_path|notebook_path|filePath)\\?"\s*:\s*\\?"([^"\\]+)/g),
                 ...t.matchAll(/\*\*\* (?:Update|Add|Delete) File: ([^\s\\"]+)/g)].map(m => m[1]);
  return [...new Set(files.reverse())].slice(0, 10);
}

// ---------------------------------------------------------------------------------------------
const question = f => ({type: "noul", instructions:
  `A coding agent is about to act on the user's request in \`request.prompt\` (working directory \`request.cwd\`, ` +
  `recently touched files \`request.recent_files\`, recent commands \`request.recent_commands\`). ` +
  `An instruction fragment is loaded only when this condition holds: "${f.when}". ` +
  `Does the condition hold for this request and the current work? Answer yes when doing the request will ` +
  `plausibly involve what the condition describes, not merely because a related word appears.`});

/** Pick the fragments for one prompt -> {text, fragments: [{id, via, p, included}], source, error}. */
export async function select({prompt, cwd, recent_files = [], recent_commands = [], agent, session_id},
                             {fragments = discover(cwd), askFn = ask, useCache = true} = {}) {
  const t0 = Date.now();
  const out = {text: "", fragments: [], source: "none", error: null};
  if (CONFIG.mode === "off" || !prompt?.trim() || !fragments.length) return out;
  const files = [...pathsIn(prompt), ...recent_files];
  const rows = fragments.map(f => ({f, id: f.id, p: null,
    via: f.paths.some(g => files.some(p => pathMatches(g, p))) ? "paths"
       : f.keywords.some(k => keywordHit(k, prompt)) ? "keywords" : null}));
  const pending = rows.filter(r => !r.via && r.f.when);
  let res = {usage: {}};
  if (pending.length) {
    const questions = Object.fromEntries(pending.map((r, i) => [`f${i}`, question(r.f)]));
    const key = sha(["instructions", redact(prompt), cwd, pending.map(r => r.f.when), CONFIG.model]);
    const cached = useCache && cacheGet(key);
    res = cached ? {answers: cached, usage: {}, error: null} : await askFn({request: {
      prompt: redact(prompt).slice(0, 4000), cwd, recent_files: recent_files.slice(0, 10),
      recent_commands: recent_commands.slice(-5).map(c => redact(c).slice(0, 200))}}, questions);
    const missing = pending.filter((_, i) => typeof res.answers?.[`f${i}`]?.noul !== "number");
    if (!res.error && missing.length) res.error = `incomplete answer: missing ${missing.length} of ${pending.length}`;
    out.source = res.error ? "error" : cached ? "cache" : "jev";
    out.error = res.error;
    // Jev failed: the deterministic matches still stand, the judged fragments are left out.
    if (!res.error) {
      if (!cached && useCache) cachePut(key, res.answers);
      pending.forEach((r, i) => { r.p = +res.answers[`f${i}`].noul.toFixed(3); if (r.p >= THRESHOLD) r.via = "jev"; });
    }
  } else if (rows.some(r => r.via)) out.source = "deterministic";
  // Deterministic first, then most likely; whatever does not fit the cap is dropped, not cut.
  let size = 0;
  const chosen = rows.filter(r => r.via).sort((a, b) => (a.via === "jev") - (b.via === "jev") || (b.p ?? 1) - (a.p ?? 1))
    .filter(r => { const s = render(r).length; if (size + s > MAX_CHARS) return false; size += s; return true; });
  if (chosen.length) out.text = "Reflex conditional instructions: these project instructions apply to this request " +
    "because their condition holds. Follow them.\n\n" + chosen.map(render).join("\n\n");
  out.fragments = rows.map(r => ({id: r.id, via: r.via, p: r.p, included: chosen.includes(r)}));
  try {
    append(LOG, {ts: new Date().toISOString(), agent: agent ?? null, session_id: session_id ?? null,
      prompt_sha: sha(redact(prompt)), cwd, source: out.source, model: CONFIG.model, threshold: THRESHOLD,
      latency_s: +((Date.now() - t0) / 1000).toFixed(2), input_tokens: res.usage?.input_tokens ?? 0,
      error: out.error, fragments: out.fragments, injected_chars: out.text.length});
  } catch { /* a log that cannot be written must not cost the instructions */ }
  return out;
}
const render = r => `## ${r.id}${r.f.when ? ` (when ${r.f.when})` : ""}\n${r.f.body}`;

// Any failure injects nothing: the agent carries on with its usual instructions.
async function selectSafe(call) {
  try { return await select(call); } catch (e) { console.error(`reflex instructions: ${e.message}`); return {text: ""}; }
}

// ---------------------------------------------------------------------------------------------
// Adapters. Claude Code and Codex share the UserPromptSubmit shape:
// stdin {session_id, transcript_path, cwd, prompt}, stdout {hookSpecificOutput: {additionalContext}}.
async function userPromptSubmit(input, agent) {
  const r = await selectSafe({agent, prompt: input.prompt, cwd: input.cwd, session_id: input.session_id,
    recent_files: recentFiles(input.transcript_path), recent_commands: sessionContext(input.transcript_path).recent ?? []});
  if (r.text) process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: r.text}}));
}
// Hermes pre_llm_call shell hook: the prompt is extra.user_message (a string, or content parts).
async function hermes(input) {
  const m = input.extra?.user_message;
  const prompt = Array.isArray(m) ? m.map(p => p?.text ?? "").join("\n") : m;
  const r = await selectSafe({agent: "hermes", prompt, cwd: input.cwd, session_id: input.session_id});
  process.stdout.write(JSON.stringify(r.text ? {context: r.text} : {}));
}

// ---------------------------------------------------------------------------------------------
async function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  // parsing
  const f = parseFragment('---\nwhen: "the task touches React"\npaths: [web/**/*.tsx, "**/*.css"]\nkeywords:\n  - react\n  - tailwind\n---\nUse tokens.\n', "fe");
  ok(f?.id === "fe" && f.when === "the task touches React" && f.paths.join() === "web/**/*.tsx,**/*.css" &&
     f.keywords.join() === "react,tailwind" && f.body === "Use tokens.", "front-matter: scalars, inline and dash lists");
  ok(parseFragment("no front-matter", "x") === null && parseFragment("---\nwhen: x\n---\n", "x") === null &&
     parseFragment("---\ntitle: y\n---\nbody", "x") === null, "no front-matter, empty body or no condition: not a fragment");
  // globs and prompt paths
  ok(pathMatches("web/**/*.tsx", "/r/web/src/a/App.tsx") && pathMatches("web/**/*.tsx", "web/App.tsx") &&
     !pathMatches("web/**/*.tsx", "/r/api/App.tsx"), "glob ** and suffix match");
  ok(pathMatches("*.tf", "/infra/envs/prod/main.tf") && pathMatches("**/*.{ts,tsx}", "src/a.ts") &&
     !pathMatches("*.tf", "main.tfvars"), "basename glob, braces, anchored");
  ok(pathsIn("fix web/src/App.tsx:12 and main.tf, see https://x.io/a.b.").join() === "web/src/App.tsx,main.tf", "paths in a prompt");
  ok(keywordHit("stripe", "Refund via Stripe.") && !keywordHit("tf", "the tfvars file"), "keywords are whole words");

  // discovery on the fixture repo: nearest id wins, the user dir is included
  const home = ENV.REFLEX_SELFCHECK_DATA, repo = join(home, "repo");
  cpSync(join(dirname(fileURLToPath(import.meta.url)), "examples/instructions/repo"), repo, {recursive: true});
  mkdirSync(join(home, ".config/reflex/instructions"), {recursive: true});
  writeFileSync(join(home, ".config/reflex/instructions/personal.md"), "---\nkeywords: [changelog]\n---\nKeep CHANGELOG.md current.\n");
  writeFileSync(join(home, ".config/reflex/instructions/billing.md"), "---\nwhen: never\n---\npersonal override loses\n");
  const saved = ENV.XDG_CONFIG_HOME; delete ENV.XDG_CONFIG_HOME;
  const frags = discover(join(repo, "web/src"), home);
  if (saved !== undefined) ENV.XDG_CONFIG_HOME = saved;
  const ids = frags.map(x => x.id).sort().join();
  ok(ids === "billing,frontend,personal,terraform", `discovery finds repo + user fragments (${ids})`);
  ok(frags.find(x => x.id === "billing")?.when?.includes("billing"), "the repo's fragment beats the user's with the same id");

  // selection with Jev stubbed: one request, one question per undecided fragment
  const calls = [];
  const stub = answers => async (state, questions) => { calls.push({state, questions}); return {answers: answers(questions), usage: {input_tokens: 1}, error: null}; };
  const byWhen = map => qs => Object.fromEntries(Object.entries(qs).map(([k, q]) =>
    [k, {type: "noul", noul: Object.entries(map).find(([w]) => q.instructions.includes(w))?.[1] ?? 0.1}]));
  const run = (prompt, opts = {}) => select({prompt, cwd: "/repo", session_id: "s", ...opts},
    {fragments: frags, askFn: stub(byWhen({"billing": 0.92, "React": 0.2, "Terraform": 0.05, ...opts.p}))});
  let r = await run("the refund webhook double-charges customers " + Math.random());
  ok(calls.length === 1 && Object.keys(calls[0].questions).length === 3, "deterministic misses go to Jev in one request");
  ok(r.fragments.find(x => x.id === "billing")?.included && r.fragments.find(x => x.id === "billing").p === 0.92 &&
     !r.fragments.find(x => x.id === "frontend").included && r.text.includes("## billing"), "Jev above threshold is injected");
  ok(Object.values(calls[0].questions).some(q => q.instructions.includes(frags.find(x => x.id === "billing").when)) &&
     calls[0].state.request.cwd === "/repo", "each question carries its fragment's condition");
  calls.length = 0;
  r = await run("restyle the header in web/src/Header.tsx");
  ok(r.fragments.find(x => x.id === "frontend").via === "paths" && Object.keys(calls[0].questions).length === 2,
     "a path match skips Jev for that fragment");
  calls.length = 0;
  r = await run("rename a variable", {recent_files: ["/repo/infra/envs/prod/main.tf"]});
  ok(r.fragments.find(x => x.id === "terraform").via === "paths", "recently touched files match paths");
  calls.length = 0;
  r = await run("update the CHANGELOG entry");
  ok(r.fragments.find(x => x.id === "personal").via === "keywords" && r.text.indexOf("## personal") < (r.text.indexOf("## billing") >>> 0),
     "keywords match; deterministic fragments come first");
  // secrets never reach Jev or the log; the log keeps ids and probabilities only
  calls.length = 0;
  r = await run("deploy with AKIAABCDEFGHIJKLMNOP to the billing api");
  ok(!JSON.stringify(calls[0].state).includes("AKIAABCDEFGHIJKLMNOP"), "prompt is redacted before Jev");
  const log = readText(join(home, "instructions.jsonl")) ?? "";
  ok(log.includes('"id":"billing"') && !log.includes("AKIA") && !log.includes("refund webhook"), "log has ids + p, never the prompt");
  // the cache answers a repeated prompt without a call
  calls.length = 0;
  r = await run("deploy with AKIAABCDEFGHIJKLMNOP to the billing api");
  ok(calls.length === 0 && r.source === "cache" && r.fragments.find(x => x.id === "billing").included, "prompt cache");
  // failures: Jev error keeps deterministic matches only; incomplete answers are an error, not "no"
  r = await select({prompt: "edit web/a.tsx and the invoice job " + Math.random(), cwd: "/r"},
                   {fragments: frags, askFn: async () => ({answers: {}, usage: {}, error: "HTTP 529"})});
  ok(r.source === "error" && r.fragments.filter(x => x.included).map(x => x.id).join() === "frontend", "Jev down: deterministic only");
  r = await select({prompt: "the invoice job " + Math.random(), cwd: "/r"},
                   {fragments: frags, askFn: async () => ({answers: {f0: {noul: 0.9}}, usage: {}, error: null})});
  ok(r.error?.startsWith("incomplete") && !r.text, "incomplete answers inject nothing judged");
  ok((await select({prompt: "", cwd: "/r"}, {fragments: frags})).text === "" &&
     (await select({prompt: "x", cwd: "/r"}, {fragments: []})).source === "none", "no prompt or no fragments: no call");
  // the size cap drops whole fragments, never cuts one
  const big = [{id: "a", when: null, paths: [], keywords: ["go"], body: "A".repeat(MAX_CHARS - 200)},
               {id: "b", when: null, paths: [], keywords: ["go"], body: "B".repeat(500)}];
  r = await select({prompt: "go", cwd: "/r"}, {fragments: big, askFn: async () => { throw new Error("no call expected"); }});
  ok(r.fragments.map(x => x.included).join() === "true,false" && r.text.length <= MAX_CHARS + 200, "size cap");
  console.log(process.exitCode ? "instructions selfcheck FAILED" : "instructions selfcheck OK");
}

// ---------------------------------------------------------------------------------------------
const argv = process.argv.slice(2);
const flag = f => argv.includes(f);
const opt = n => { const i = argv.indexOf(n); return i > -1 ? argv[i + 1] : undefined; };
const readStdin = () => JSON.parse(readFileSync(0, "utf8"));
const main = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
// Errors go to stderr and the process exits 0: a broken instruction layer never blocks a prompt.
const guarded = fn => Promise.resolve().then(fn).catch(e => console.error(`reflex instructions: ${e.message}`));

if (!main) { /* imported */ }
// The log and cache paths are fixed when gate.mjs loads, so the self-check reruns itself with a
// scratch data dir rather than write into the real one.
else if (flag("--selfcheck") && !ENV.REFLEX_SELFCHECK_DATA) {
  const data = mkdtempSync(join(tmpdir(), "reflex-instr-"));
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--selfcheck"], {stdio: "inherit",
    env: {...ENV, REFLEX_DATA_DIR: data, REFLEX_SELFCHECK_DATA: data, REFLEX_MODE: "shadow"}});
  rmSync(data, {recursive: true, force: true});
  process.exitCode = r.status ?? 1;
}
else if (flag("--selfcheck")) await selfcheck();
else if (flag("--claude")) await guarded(() => userPromptSubmit(readStdin(), "claude-code"));
else if (flag("--codex")) await guarded(() => userPromptSubmit(readStdin(), "codex"));
else if (flag("--hermes")) await guarded(() => hermes(readStdin()));
else if (flag("--select")) await guarded(async () => process.stdout.write(JSON.stringify(await selectSafe(readStdin())) + "\n"));
else if (flag("--check")) {
  const cwd = opt("--cwd") ?? process.cwd();
  const r = await select({agent: "cli", prompt: opt("--check"), cwd, recent_files: opt("--files")?.split(",") ?? []});
  console.log(JSON.stringify({source: r.source, error: r.error ?? undefined, threshold: THRESHOLD, fragments: r.fragments}, null, 1));
  if (r.text) console.log(`\n${r.text}`);
}
else console.error("usage: instructions.mjs --check <prompt> [--cwd d] [--files a,b] | --select | --claude | --codex | --hermes | --selfcheck");
