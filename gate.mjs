#!/usr/bin/env node
// Reflex: judges a shell command a coding agent wants to run, before it runs.
//
//   node gate.mjs --decide        JSON call on stdin -> JSON decision on stdout (any agent adapter)
//   node gate.mjs --record        JSON outcome on stdin -> feedback log
//   node gate.mjs --claude        Claude Code PreToolUse hook   (--claude-post: PostToolUse)
//   node gate.mjs --codex         Codex CLI PreToolUse hook     (--codex-post)
//   node gate.mjs --hermes        Hermes pre_tool_call hook     (--hermes-post)
//   adapters/opencode.js, adapters/pi.ts                        plugins that call --decide / --record
//   bin/reflex-sh -c "<cmd>"      bash drop-in for agents without hooks: judge, then run/confirm/refuse
//   node gate.mjs --check "<cmd>" judge one command from the terminal
//   node gate.mjs --selfcheck     offline tests, no API calls
//
// Order: read-only? -> rules -> fast lane -> cache -> Jev -> policy.
//
// The gate only tightens: it emits "ask" or "deny", never "allow", so Claude Code's own permission
// rules stay authoritative. Deterministic rules (setup/*/rules.json) are enforced in every mode.
// Jev's decisions are enforced only with REFLEX_MODE=enforce; in the default shadow mode Jev
// runs in a detached background process, so the agent never waits for it.
import {appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync,
        openSync, readSync, writeSync, closeSync, rmSync} from "node:fs";
import {createHash} from "node:crypto";
import {execFileSync, spawn, spawnSync} from "node:child_process";
import {homedir, platform, tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {compile} from "./policy.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENV = process.env;
export const CONFIG = {
  api: ENV.REFLEX_API_URL ?? "https://api.typesafe.ai/v1/systemone",
  model: ENV.REFLEX_MODEL ?? "jev-1.13.0",              // pinned so a decision can be reproduced
  // off | shadow | enforce. The environment wins, so one session can be switched for a test;
  // otherwise the --mode flag that install.mjs writes into each agent's hook command.
  mode: ENV.REFLEX_MODE ?? (process.argv.includes("--mode") ? process.argv[process.argv.indexOf("--mode") + 1] : "shadow"),
  setup: ENV.REFLEX_SETUP_DIR ?? join(HERE, "setup/tool-gate"),
  data: ENV.REFLEX_DATA_DIR ?? join(ENV.XDG_STATE_HOME ?? join(homedir(), ".local/state"), "reflex"),
  timeoutMs: Number(ENV.REFLEX_TIMEOUT_MS ?? 3000),
  keychain: ENV.REFLEX_KEYCHAIN_SERVICE ?? "typesafe-api-key",
};
const TRACE = join(CONFIG.data, "trace.jsonl");
const FEEDBACK = join(CONFIG.data, "feedback.jsonl");
const CACHE = join(CONFIG.data, "cache.json");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const ROTATE_BYTES = 50 * 1024 * 1024;

const load = f => JSON.parse(readFileSync(join(CONFIG.setup, f), "utf8"));
const sha = v => createHash("sha256").update(typeof v === "string" ? v : JSON.stringify(v)).digest("hex").slice(0, 12);
const readText = p => { try { return readFileSync(p, "utf8"); } catch { return null; } };

// ---------------------------------------------------------------------------------------------
// Read-only detection. ponytail: a prefix list plus a little shell awareness, not a parser.
// Anything it does not recognise falls through to rules and Jev, which costs latency, not safety,
// so every doubtful construct below returns false rather than trying to understand it.
const READ_ONLY = new Set(("ls cat head tail less wc grep egrep rg fd find tree pwd echo printf which type " +
  "file stat du df date uname whoami id hostname uptime sw_vers jq yq sort cut tr diff cmp sed awk " +
  "column realpath readlink dirname basename true false test [ [[ cd sleep ps pgrep lsof nvidia-smi " +
  "md5 shasum sha256sum xxd od strings nl fold paste comm exit return").split(" "));
// Flags that make an otherwise read-only tool run a program or write a file.
const UNSAFE_FLAGS = new RegExp([
  String.raw`\bsed\b[^|;&]*(--in-place|\s-[a-zA-Z]*i|[;'"{}\s][wWe]\s|\/[a-zA-Z0-9]*[we]\s)`,
  String.raw`\bawk\b.*(system|getline)`, String.raw`\bawk\b[^']*'[^']*[|>][^']*'`, String.raw`--pre\b`, String.raw`--(upload|receive)-pack`,
  String.raw`--post-renderer`, String.raw`--compress-program`, String.raw`--output\b`, String.raw`--ext-diff`,
  String.raw`\s-f(print|printf|ls)\b`, String.raw`\s-ok(dir)?\b`, String.raw`\bfd\b.*\s-[a-zA-Z]*[xX]\b`,
  String.raw`\b(sort|tree)\b[^|;&]*\s-o\b`, String.raw`--show-token`,
].join("|"));
const READ_ONLY_SUB = {
  git: /^(-C\s+\S+\s+)?((status|log|diff|show|blame|ls-files|ls-remote|rev-parse|describe|shortlog|fetch)\b|branch(\s+(-a|-r|-v|-vv|--list|--show-current|--contains\s+\S+|--merged|--no-merged))*\s*$|remote(\s+(-v|show\s+\S+|get-url\s+\S+))?\s*$|reflog(\s+show)?\b(?!.*\b(expire|delete)\b)|config\s+--get|stash\s+(list|show)|worktree\s+list|tag\s+-l)/,
  kubectl: /^(get|describe|logs|top|explain|version|api-resources|config (view|current-context|get-contexts))\b/,
  terraform: /^(-chdir=\S+\s+)?(plan|show|validate|fmt -check|output|state (list|show)|version|providers|graph)\b/,
  aws: /^(--\S+\s+\S+\s+)*(\S+ (describe|list|head)-\S+|(?!s3api\s+get-object)\S+ get-\S+|sts get-caller-identity|configure list|s3 ls)\b/,
  helm: /^(list|ls|status|get|lint|show|history|search|version)\b/,
  // gh api is a GET unless a method, field or input says otherwise, in any spelling
  gh: /^(pr|issue|run|release|repo) (view|list|checks|diff|status)\b|^auth status|^api(?!.*\s(-X\S*|--method|-[fF]\S*|--field|--raw-field|--input)(\s|=|$))\s/,
  docker: /^(ps|logs|inspect|images|version|info|stats --no-stream|compose (ps|logs|config))\b/,
  npm: /^(view|ls|list|outdated|config get)\b/,
  brew: /^(list|info|search|services list|--prefix)\b/,
  uniq: /^(-\S+\s*)*$/,          // flags only: `uniq in out` writes out
};
// Loop and condition keywords wrap commands; the command after them is what runs.
const KEYWORD = /^(do|then|else|elif|if|while|until|!|\{|\()\s+/;
// Assignments that cannot turn a reader into a runner: shell-local lowercase names, short script
// variables (S=, OUT=), and a few well-known selectors. PATH, PAGER, GIT_*, LD_* and friends are not.
const SAFE_VAR = /^([a-z_][a-z0-9_]*|[A-Z]{1,3}|AWS_PROFILE|AWS_REGION|AWS_DEFAULT_REGION|KUBECONFIG)$/;
const assignmentOk = a => SAFE_VAR.test(a.split("=")[0]);

// Blank out quoted text, keeping the quote marks. Inside double quotes `$(` and backticks still
// expand, so they are kept. Unbalanced quotes mean the mask cannot be trusted: return the input.
export function maskQuotes(s) {
  let out = "", q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q === "'") { if (ch === "'") { q = null; out += ch; } continue; }
    if (q === '"') {
      if (ch === "\\") { i++; continue; }
      if (ch === '"') { q = null; out += ch; continue; }
      if (ch === "`") out += ch;
      if (ch === "$" && s[i + 1] === "(") { out += "$("; i++; }
      continue;
    }
    if (ch === "\\") { out += ch + (s[i + 1] ?? ""); i++; continue; }
    if (ch === "'" || ch === '"') q = ch;
    out += ch;
  }
  return q ? s : out;
}

// `extra` adds segment patterns that are safe but not read-only (rules.json "pass": builds, mkdir).
export function readOnly(cmd, extra = [], depth = 0) {
  if (depth > 3) return false;
  let c = cmd.replace(/\\\n/g, " ")
    // A quoted heredoc body is data. An unquoted one is expanded by the shell, so it stays and is checked.
    .replace(/<<-?\s*(['"])(\w+)\1([^\n]*)\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, "$3")
    .replace(/[0-9&]?>{1,2}\s*\/dev\/null\b/g, "")
    .replace(/[0-9]>&[0-9]/g, "");
  // `ssh host 'cmd'` is only as safe as cmd. The quoted command must end the ssh call, or extra
  // arguments would be appended to it on the remote side; options that run local commands or
  // open tunnels are never read-only.
  for (let m; (m = c.match(/\bssh\s+((-[a-zA-Z]+(\s+[^-\s'"]\S*)?\s+)*)[^\s'"-]\S*\s+(['"])((?:(?!\4)[\s\S])*)\4(?=\s*($|[;&|\n)]))/));) {
    if (/(Proxy|Local|Remote)Command|PermitLocalCommand|(^|\s)-[a-zA-Z]*[RLDwfNW]/.test(m[1])) return false;
    if (!readOnly(m[5], extra, depth + 1)) return false;
    c = c.replace(m[0], "true");
  }
  // `$(...)` is only as safe as what runs inside it.
  for (let m; (m = c.match(/\$\(([^()`]*)\)/));) {
    if (!readOnly(m[1], extra, depth + 1)) return false;
    c = c.replace(m[0], "X");
  }
  // Tool-level dangers are checked on the raw text, quotes included (conservative).
  if (/-delete\b|-exec(dir)?\b/.test(c) || UNSAFE_FLAGS.test(c)) return false;
  // Shell structure and command words are checked with quoted text masked: `jq '.a | .b'` or
  // `grep -E 'x|y'` is one command, and `>` or `source` inside quotes is data. Expansions inside
  // double quotes stay visible.
  const m = maskQuotes(c);
  if (/>|`|\$\(|<\(|<<|(^|[;&|]\s*)\.\s|\bsudo\b|\btee\b|\bxargs\b|\beval\b|\bsource\b/.test(m)) return false;
  // `&` (background) separates commands just like `;`.
  return m.split(/&&|\|\||[;&|\n]/).map(s => s.trim()).filter(Boolean).every(seg => {
    while (KEYWORD.test(seg)) seg = seg.replace(KEYWORD, "");
    if (/^(done|fi|esac|\}|\)|else|then|do)$/.test(seg)) return true;
    const assign = seg.match(/^(export\s+)?(\w+=("[^"]*"|'[^']*'|\S*))$/);
    if (assign) return assignmentOk(assign[2]);
    if (extra.some(re => re.test(seg))) return true;
    if (/^(for|case)\s/.test(seg)) return true;             // header only; its body is its own segments
    // Prefix assignments must be safe too; wrappers run whatever follows them, so judge what follows.
    const prefixes = seg.match(/^((\w+=\S*|rtk(\s+proxy)?|timeout\s+\S+|time|nohup|command)\s+)+/)?.[0] ?? "";
    if ((prefixes.match(/\w+=\S*/g) ?? []).some(a => !assignmentOk(a))) return false;
    const [head, ...rest] = seg.slice(prefixes.length).split(/\s+/);
    if (READ_ONLY.has(head)) return true;
    if (rest.length === 1 && /^--(version|help)$/.test(rest[0]) && /^[\w.-]+$/.test(head)) return true;
    return READ_ONLY_SUB[head]?.test(rest.join(" ")) ?? false;
  });
}

// ---------------------------------------------------------------------------------------------
// Secrets never leave the machine or land in the trace. ponytail: a pattern list, not a DLP engine;
// add a pattern when a new credential shape shows up in the trace.
const SECRET_PATTERNS = [
  /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\b(sk-[A-Za-z0-9_-]{16,}|xox[abpr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{16,})\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /\b[rs]k_(live|test)_[A-Za-z0-9]{10,}\b/g, /\bAIza[0-9A-Za-z_-]{35}\b/g, /\bnpm_[A-Za-z0-9]{36}\b/g,
  /hooks\.slack\.com\/services\/\S+/g,
  // a bare 40-char AWS-style secret: mixed case, so git SHAs (lowercase hex) are left alone
  /(?<![A-Za-z0-9/+])(?=[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+]))(?=[A-Za-z0-9/+]*[A-Z])(?=[A-Za-z0-9/+]*[a-z])[A-Za-z0-9/+]{40}/g,
];
export function redact(s) {
  let out = String(s ?? "");
  for (const re of SECRET_PATTERNS) out = out.replace(re, "<redacted>");
  return out
    .replace(/(authorization:\s*(bearer|basic|token)\s+)\S+/gi, "$1<redacted>")
    .replace(/((cookie|x-[\w-]*(auth|token|key)[\w-]*):\s*)[^'"\n]+/gi, "$1<redacted>")
    .replace(/(\b[\w.-]*(secret|token|passw(or)?d|api[_-]?key|access[_-]?key|credential)[\w.-]*"?\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi, "$1<redacted>")
    .replace(/(--?(password|passwd|token|secret|api-key)[= ]\s*)("[^"]*"|'[^']*'|\S+)/gi, "$1<redacted>")
    .replace(/((\s-u|--user)\s+[^\s:]+:)\S+/g, "$1<redacted>")
    .replace(/(\b(mysql|mariadb)\b[^|;&]*\s-p)(\S+)/g, "$1<redacted>")
    .replace(/(\bsshpass\s+-p\s*)\S+/g, "$1<redacted>")
    .replace(/(:\/\/[^\s:@/]+:)\S+@/g, "$1<redacted>@");
}

// ---------------------------------------------------------------------------------------------
// Context. The hook runs in Claude Code's environment, which the Bash tool inherits, so the
// AWS profile and kube context seen here are the ones the command will use.
export function envContext(cwd) {
  const e = {};
  if (ENV.AWS_PROFILE) e.aws_profile = ENV.AWS_PROFILE;
  if (ENV.AWS_REGION ?? ENV.AWS_DEFAULT_REGION) e.aws_region = ENV.AWS_REGION ?? ENV.AWS_DEFAULT_REGION;
  const kube = readText((ENV.KUBECONFIG ?? join(homedir(), ".kube/config")).split(":")[0]);
  const ctx = kube?.match(/^current-context:\s*"?([^"\n]+)"?\s*$/m)?.[1];
  if (ctx) e.kube_context = ctx;
  if (cwd && existsSync(join(cwd, ".terraform"))) e.tf_workspace = readText(join(cwd, ".terraform/environment"))?.trim() || "default";
  for (let d = cwd; d && d !== dirname(d); d = dirname(d)) {
    const head = readText(join(d, ".git/HEAD"));
    if (head) { e.git_branch = head.match(/^ref: refs\/heads\/(.+)$/m)?.[1] ?? "detached"; break; }
  }
  return e;
}

// What the agent said right before this call, and what it ran just before. Reads the transcript
// tail. The intent is the text that precedes this call's own tool_use entry. When that entry is not
// in the transcript yet (Claude Code can write it after the hook fires), there is no intent: an
// older message would be judged against the wrong task, which is worse than none.
export function sessionContext(path, toolUseId) {
  if (!path || !existsSync(path)) return {};
  const size = statSync(path).size, len = Math.min(size, 512 * 1024), buf = Buffer.alloc(len);
  const fd = openSync(path, "r");
  readSync(fd, buf, 0, len, size - len);
  closeSync(fd);
  let lastText, intent, recent = [];
  for (const line of buf.toString("utf8").split("\n")) {
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.type === "user" && r.message?.content?.some?.(c => c.type !== "tool_result")) lastText = undefined;
    if (r.type !== "assistant") continue;
    for (const c of r.message?.content ?? []) {
      if (c.type === "text" && c.text?.trim()) lastText = c.text;
      if (c.type === "tool_use" && toolUseId && c.id === toolUseId) intent = lastText;
      if (c.type === "tool_use" && c.name === "Bash" && c.id !== toolUseId && c.input?.command) recent.push(c.input.command);
    }
  }
  const out = {};
  if (intent) out.intent = redact(intent).slice(-600);
  if (recent.length) out.recent = recent.slice(-5).map(c => redact(c).slice(0, 200));
  return out;
}

// ---------------------------------------------------------------------------------------------
// Deterministic layer: a rule fires when every pattern in `all` matches the command + context.
export function checkRules(haystack, rules) {
  for (const r of rules.rules) {
    if (r.all.every(p => new RegExp(p, "i").test(haystack))) return {outcome: r.outcome, rule: r.rule, id: r.id};
  }
  return null;
}
export const fastPass = (cmd, rules) => readOnly(cmd, rules.pass.map(p => new RegExp(p, "i")));

// A quoted heredoc whose consumer only stores or prints text (a commit message, a PR body, a file
// written by cat) is data, not a command: a PR body that mentions `git push --force origin main`
// must not trip the force-push rule. Heredocs fed to a shell, an interpreter or ssh stay in.
const DATA_CONSUMER = /(^|\s)(cat|jq|tee|git\s+(commit|tag|notes)\b[^\n]*|gh\s+(pr|issue|release|api)\b[^\n]*)\s[^\n]*$|(^|\s)cat$/;
export function stripDataHeredocs(cmd) {
  return cmd.replace(/([^\n]*?)<<-?\s*(['"])(\w+)\2([^\n]*)\n[\s\S]*?\n\s*\3\s*(?=\n|$)/g,
    (all, before, _q, _tag, after) => !/\|/.test(after) &&   // `cat <<'EOF' | bash` runs the body
      DATA_CONSUMER.test(before.replace(/.*[;&|(]\s*/, "").trimEnd() + " ") ? `${before}<<DATA${after}` : all);
}

/** Everything decided without Jev, or null when Jev has to judge. */
export function precheck(command, cwd, env) {
  const rules = load("rules.json");
  // Rules see the raw command (redaction could hide the very marker a rule looks for, such as
  // --secret-id=prod-db), minus heredoc bodies that are only data.
  const haystack = [stripDataHeredocs(command),`cwd=${cwd ?? ""}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].join(" ");
  const ruled = r => ({outcome: r.outcome, rule: r.rule, id: r.id, source: "rule", policy_version: rules.version});
  // Some rules must see reads too (printing an API key is a read).
  const early = checkRules(haystack, {rules: rules.rules.filter(r => r.before_read_only)});
  if (early) return ruled(early);
  if (readOnly(command)) return {outcome: "pass", rule: "read-only", source: "read-only"};
  // The checkout itself is protected wherever it was cloned, not only under a directory named reflex.
  const inRepo = cwd && (cwd + "/").startsWith(HERE + "/");
  if (command.includes(HERE) || command.includes(CONFIG.data) ||
      (inRepo && /\b(gate|policy|install|eval|report)\.mjs\b|\bsetup\/|\bbin\/reflex-sh\b|\badapters\/|\.git\/hooks/.test(command)))
    return ruled({outcome: "ask", rule: "touches the Reflex gate, its setup or its logs", id: "tamper"});
  const hit = checkRules(haystack, {rules: rules.rules.filter(r => !r.before_read_only)});
  if (hit) return ruled(hit);
  if (fastPass(command, rules)) return {outcome: "pass", rule: "fast lane", source: "fast-lane", policy_version: rules.version};
  return null;
}

// ---------------------------------------------------------------------------------------------
// Jev.
function apiKey() {
  if (ENV.TYPESAFE_API_KEY) return ENV.TYPESAFE_API_KEY.trim();
  if (platform() === "darwin") {
    try {
      return execFileSync("security", ["find-generic-password", "-s", CONFIG.keychain, "-w"],
                          {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 1500}).trim();
    } catch { /* fall through */ }
  }
  throw new Error(`no API key: set TYPESAFE_API_KEY or keychain item "${CONFIG.keychain}"`);
}

export async function ask(state, questions, {timeoutMs = CONFIG.timeoutMs} = {}) {
  const t0 = Date.now();
  let answers = {}, usage = {}, error = null;
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(CONFIG.api, {method: "POST", signal: AbortSignal.timeout(timeoutMs - (Date.now() - t0)),
        headers: {Authorization: `Bearer ${apiKey()}`, "Content-Type": "application/json"},
        body: JSON.stringify({state, model: CONFIG.model, questions})});
      // 429 rate limited, 529 overloaded: one quick retry if the time budget allows
      if ((r.status === 429 || r.status === 529) && attempt === 0 && Date.now() - t0 < timeoutMs / 2) {
        await new Promise(res => setTimeout(res, 250));
        continue;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 300)}`);
      const payload = await r.json();
      answers = payload.answers ?? {};
      usage = payload.usage ?? {};
      error = null;
    } catch (e) {
      error = `${e.name}: ${e.message}`;
    }
    break;
  }
  return {answers, usage, error, latency_s: +((Date.now() - t0) / 1000).toFixed(2)};
}

// Answers about a command are cached, decisions never are: the policy reruns every time, so a
// threshold change applies at once. ponytail: answers tied to one moment (on_task) are dropped on a
// hit, so a repeat of the same command skips the on-task check.
const SESSION_BOUND = ["on_task"];
function cacheGet(key) {
  let c;
  try { c = JSON.parse(readText(CACHE) ?? "{}")[key]; } catch { return null; }
  if (!c || Date.now() - c.at > CACHE_TTL_MS) return null;
  return Object.fromEntries(Object.entries(c.answers).filter(([k]) => !SESSION_BOUND.includes(k)));
}
function cachePut(key, answers) {
  // ponytail: whole-file rewrite; parallel hooks can drop an entry, which only costs a re-ask.
  try {
    mkdirSync(CONFIG.data, {recursive: true});
    const c = JSON.parse(readText(CACHE) ?? "{}");
    c[key] = {at: Date.now(), answers};
    const tmp = `${CACHE}.${process.pid}`;
    writeFileSync(tmp, JSON.stringify(Object.fromEntries(Object.entries(c).slice(-2000))));
    renameSync(tmp, CACHE);   // atomic: a parallel reader never sees half a file
  } catch { /* a cache that cannot be written only costs a re-ask */ }
}

/** Jev's judgment + the policy -> {outcome, rule, source, state, answers, ...}. */
export async function jevJudge({command, cwd, env, session = {}, useCache = true}) {
  const spec = load("questions.json");
  const policy = compile(load("policy.json"));
  const state = {[spec.item_key]: {title: redact(command).slice(0, 160), command: redact(command), cwd, env, ...session},
                 [spec.context_key]: spec.context};
  const key = sha([redact(command), cwd, env, spec.version, CONFIG.model]);
  const cached = useCache && cacheGet(key);
  const res = cached ? {answers: cached, usage: {}, error: null, latency_s: 0} : await ask(state, spec.questions);
  // Every question must come back with a value, or the policy would read missing answers as "no".
  const missing = Object.keys(spec.questions).filter(q => !(cached && SESSION_BOUND.includes(q)) &&
    (res.answers?.[q]?.noul ?? res.answers?.[q]?.choice ?? res.answers?.[q]?.score) == null);
  if (!res.error && missing.length) res.error = `incomplete answer: missing ${missing.join(", ")}`;
  if (!cached && !res.error && useCache) cachePut(key, res.answers);
  const d = res.error
    ? {outcome: policy.policy.fallback ?? "ask", rule: `jev unavailable (${res.error.slice(0, 80)})`}
    : policy.decide(res.answers, policy.values());
  return {outcome: d.outcome, rule: d.rule, source: res.error ? "fallback" : cached ? "cache" : "jev",
          state, questions: spec.questions, qset: spec.version, policy_version: policy.version, ...res};
}

/** The whole gate for one command, as eval.mjs and the hook see it. */
export async function judge({command, cwd, env = envContext(cwd), session = {}, useCache = true}) {
  return precheck(command, cwd, env) ?? jevJudge({command, cwd, env, session, useCache});
}

// ---------------------------------------------------------------------------------------------
// The agent-neutral contract. Every adapter turns its agent's event into a call:
//   {agent, command, cwd, session_id?, call_id?, intent?, recent?, transcript_path?}
// and gets back {effective, decision, reason, source, policy}. `effective` is what the agent must
// do now: "pass" (let it run), "ask" (a human confirms) or "deny" (block, show the reason).
// In shadow mode only deterministic rules are effective; Jev's decision is logged, never applied.
export async function decide(call, {background = false} = {}) {
  if (CONFIG.mode === "off" || !call.command) return {effective: "pass", decision: "pass", reason: "reflex off", source: "off"};
  const env = envContext(call.cwd);
  const quick = background ? null : precheck(call.command, call.cwd, env);
  if (quick) {
    const effective = quick.source === "rule" ? quick.outcome : "pass";
    if (quick.source !== "read-only") trace(quick, call, effective);
    return view(quick, effective);
  }
  // Shadow mode: nobody waits for Jev. A detached copy of this script judges and logs.
  if (CONFIG.mode !== "enforce" && !background) {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--bg"],
                        {detached: true, stdio: ["pipe", "ignore", "ignore"]});
    child.stdin.end(JSON.stringify(call));
    child.unref();
    return {effective: "pass", decision: "pending", reason: "reflex: judged in the background (shadow)", source: "shadow"};
  }
  const session = sessionContext(call.transcript_path, call.call_id);
  if (call.intent) session.intent = redact(call.intent).slice(-600);
  if (call.recent?.length) session.recent = call.recent.slice(-5).map(c => redact(c).slice(0, 200));
  const j = await jevJudge({command: call.command, cwd: call.cwd, env, session});
  const effective = CONFIG.mode === "enforce" ? j.outcome : "pass";
  trace(j, call, effective);
  return view(j, effective);
}
// Any internal error is a decision too: the policy fallback when enforcing, logged either way.
export async function decideSafe(call, opts) {
  try { return await decide(call, opts); } catch (e) {
    console.error(`reflex: ${e.message}`);
    const fallback = CONFIG.mode === "enforce" ? (safeFallback() ?? "ask") : "pass";
    return {effective: fallback, decision: "error", reason: `reflex error (${e.message.slice(0, 80)}), fallback ${fallback}`, source: "error"};
  }
}
function safeFallback() { try { return load("policy.json").fallback; } catch { return null; } }
const view = (j, effective) => ({effective: ["pass", "ask", "deny"].includes(effective) ? effective : "ask", decision: j.outcome, reason: `reflex (${j.source}): ${j.rule}`,
                                 source: j.source, policy: j.policy_version ?? null});

// After the command: did it run, and how did it end. An effective "ask" followed by a record
// means a human approved it; no record (or event "denied") means it was rejected.
// Only the verdict on the run is kept, never its output.
export function record(ev) {
  if (CONFIG.mode === "off") return;
  append(FEEDBACK, {ts: new Date().toISOString(), agent: ev.agent ?? null, event: ev.event ?? "ran",
    session_id: ev.session_id ?? null, call_id: ev.call_id ?? null, exit_code: ev.exit_code ?? null});
}

// Logs. One JSON line per judged command; the same shape report.mjs replays.
function append(path, obj) {
  mkdirSync(CONFIG.data, {recursive: true});
  if (existsSync(path) && statSync(path).size > ROTATE_BYTES) renameSync(path, path.replace(/\.jsonl$/, `.${Date.now()}.jsonl`));
  appendFileSync(path, JSON.stringify(obj) + "\n");
}

function trace(j, call, effective) {
  const cmd = redact(call.command);
  const state = j.state ?? {call: {title: cmd.slice(0, 160), command: cmd, cwd: call.cwd}};
  append(TRACE, {ts: new Date().toISOString(), tag: "tool-gate", model: CONFIG.model,
    qset_version: j.qset ?? null, latency_s: j.latency_s ?? 0, state_sha: sha(state), state,
    questions: j.questions ?? {}, answers: j.answers ?? {}, usage: j.usage ?? {}, error: j.error ?? null,
    decision: j.outcome, rule: j.rule, source: j.source, policy_version: j.policy_version ?? null,
    mode: CONFIG.mode, emitted: effective === "pass" ? null : effective,
    agent: call.agent ?? null, session_id: call.session_id ?? null, call_id: call.call_id ?? null});
}

// ---------------------------------------------------------------------------------------------
// Claude Code adapter: PreToolUse / PostToolUse hook JSON <-> the contract above.
// https://docs.claude.com/en/docs/claude-code/hooks
async function claudePre(input) {
  if (input.tool_name !== "Bash") return;
  const d = await decideSafe({agent: "claude-code", command: input.tool_input?.command, cwd: input.cwd,
                          session_id: input.session_id, call_id: input.tool_use_id,
                          transcript_path: input.transcript_path});
  if (!["ask", "deny"].includes(d.effective)) return;   // silent: Claude Code's own permission rules decide
  process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: "PreToolUse",
    permissionDecision: d.effective, permissionDecisionReason: d.reason}}));
}
function claudePost(input) {
  if (input.tool_name && input.tool_name !== "Bash") return;
  // Claude's Bash result carries no exit code; PostToolUseFailure is the failure signal.
  const ev = input.hook_event_name;
  record({agent: "claude-code", event: ev === "PermissionDenied" ? "denied" : ev === "PostToolUseFailure" ? "failed" : "ran",
          session_id: input.session_id, call_id: input.tool_use_id,
          exit_code: input.tool_response?.exit_code ?? (ev === "PostToolUse" ? 0 : null)});
}

// Codex CLI adapter: hooks.json PreToolUse / PostToolUse (https://learn.chatgpt.com/docs/hooks).
// Codex PreToolUse cannot "ask" (it would fail open), so an ask becomes a deny whose reason tells
// the agent to get the user's confirmation; the user can then run the command or approve it.
async function codexPre(input) {
  if (input.tool_name !== "Bash") return;
  const d = await decideSafe({agent: "codex", command: input.tool_input?.command, cwd: input.cwd,
                              session_id: input.session_id, call_id: input.tool_use_id});
  if (!["ask", "deny"].includes(d.effective)) return;
  const reason = d.effective === "ask"
    ? `${d.reason}. Needs human approval: ask the user to confirm before running it.` : d.reason;
  process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: "PreToolUse",
    permissionDecision: "deny", permissionDecisionReason: reason}}));
}
function codexPost(input) {
  if (input.tool_name !== "Bash") return;
  record({agent: "codex", event: "ran", session_id: input.session_id, call_id: input.tool_use_id});
}

// Hermes Agent adapter: config.yaml `hooks: pre_tool_call` shell hook on the terminal tool.
// "approve" routes through Hermes' own approval prompt; rule_key is per command, so approving one
// command "for the session" never pre-approves a different one.
async function hermesPre(input) {
  if (input.tool_name !== "terminal") return process.stdout.write("{}");
  const command = input.tool_input?.command;
  const d = await decideSafe({agent: "hermes", command, cwd: input.tool_input?.workdir ?? input.cwd,
                              session_id: input.session_id, call_id: input.extra?.tool_call_id});
  const out = d.effective === "deny" ? {action: "block", message: d.reason}
    : d.effective === "ask" ? {action: "approve", message: d.reason, rule_key: `reflex:${sha(command ?? "")}`} : {};
  process.stdout.write(JSON.stringify(out));
}
function hermesPost(input) {
  if (input.tool_name !== "terminal") return;
  record({agent: "hermes", event: "ran", session_id: input.session_id, call_id: input.extra?.tool_call_id});
}

// ---------------------------------------------------------------------------------------------
async function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  // read-only detection
  ok(readOnly("ls -la && git status | head"), "read-only chain");
  ok(readOnly("AWS_PROFILE=dev aws ec2 describe-instances"), "env prefix + aws describe");
  ok(readOnly("kubectl get pods -A | grep Crash"), "kubectl get");
  ok(!readOnly("echo x > /etc/hosts"), "redirect is a write");
  ok(readOnly("ls 2>&1 | head"), "fd dup is not a write");
  ok(!readOnly("env rm -rf x"), "env is not a read-only prefix");
  ok(!readOnly("terraform apply -auto-approve"), "apply");
  ok(!readOnly("find . -name '*.tmp' -delete"), "find -delete");
  ok(!readOnly("cat $(rm -rf ~)"), "subshell");
  ok(!readOnly("ls; rm -rf build"), "second segment writes");
  ok(!readOnly("rtk proxy rm -rf build") && readOnly("rtk proxy git status"), "wrappers are transparent");
  ok(!readOnly("timeout 15 ssh host reboot") && readOnly("cd ~/w && git log -3"), "timeout wrapper; cd");
  ok(readOnly('S=/tmp/x; ls $S 2>/dev/null; echo "=== a ==="; cat $S/f > /dev/null'), "assignment, /dev/null, echo");
  ok(readOnly('f=$(ls -t *.jsonl | head -1); tail -n 5 "$f"'), "read-only subshell");
  ok(!readOnly('T=$(security find-generic-password -s x -w); echo $T'), "subshell reading a secret");
  ok(readOnly('for r in a b; do echo $r; aws ec2 describe-vpcs --region $r; done'), "loop of reads");
  ok(!readOnly('for h in a b; do ssh $h reboot; done'), "loop with a write");
  ok(!readOnly("cat <<EOF > f\nx\nEOF") && !readOnly("ls | xargs rm") && !readOnly("echo x | tee f"), "heredoc, xargs, tee");
  ok(readOnly("gh pr view 19 --json title") && !readOnly("gh pr merge 19"), "gh read vs merge");
  ok(readOnly('gh api repos/a/b/branches --jq ".[].name"'), "gh api GET");
  ok(!readOnly("gh api -X DELETE repos/a/b") && !readOnly("gh api repos/a/b/issues -f title=x"), "gh api writes");
  ok(readOnly("mytool --version") && !readOnly("mytool --install"), "--version");
  ok(readOnly("ssh -o ConnectTimeout=8 -o BatchMode=yes host 'nvidia-smi; uptime' 2>&1 | tail -3"), "ssh read");
  ok(!readOnly("ssh host 'sudo reboot'") && !readOnly("ssh -n host 'rm -rf ~/x'"), "ssh write");
  ok(!readOnly("ssh h 'echo' '; rm -rf /'") && !readOnly("ssh h reboot"), "ssh trailing args / unquoted");
  ok(!readOnly("cat > /tmp/x.json <<'EOF'\n{\"a\": 1}\nEOF"), "writes to /tmp are writes");
  ok(!readOnly("python3 - <<'PY'\nprint(1)\nPY") && !readOnly("cat > ~/.zshrc <<EOF\nx\nEOF"), "heredoc into python / home");
  ok(readOnly("export AWS_PROFILE=dev; aws s3 ls"), "export");
  // bypass shapes from the security review: each must NOT be read-only
  for (const [cmd, why] of [
    ["ls & rm -rf build", "C1 background &"], ["cat <(rm -rf build)", "C2 process substitution"],
    ["cat <<EOF\n$(rm -rf build)\nEOF", "C3 unquoted heredoc expands"], ["echo x > /tmp/../etc/hosts", "C4 /tmp .."],
    ["PATH=/tmp/evil:$PATH ls", "H1 PATH prefix"], ["GIT_EXTERNAL_DIFF=/tmp/x git diff", "H1 GIT_ var"], ["PAGER=/tmp/x git log", "H1 PAGER"],
    ["ssh -o ProxyCommand='sh -c x' host 'uptime'", "H2 ProxyCommand"], ["ssh -R 8080:localhost:80 host 'sleep 99'", "H2 tunnel"],
    ["rg --pre /tmp/x foo", "H2 rg --pre"], ["fd -x rm", "H2 fd -x"], ["sort --compress-program=/tmp/x f", "H2 sort compress"],
    ["sort -o ~/.claude/settings.json f", "H2 sort -o"], ["sed -Ei s/a/b/ f", "H2 sed -Ei"], ["sed -n 's/a/b/w out' f", "H2 sed w"],
    ["find . -fprint /tmp/x", "H2 find -fprint"], ["find . -ok rm {} ;", "H2 find -ok"],
    ["git fetch --upload-pack=/tmp/x origin", "H2 upload-pack"], ["helm template x ./c --post-renderer /tmp/x", "H2 post-renderer"],
    ["./deploy.sh -h", "H3 script -h"], ["/tmp/x --version", "H3 path --version"],
    ["git branch -D main", "M1 branch -D"], ["git remote set-url origin https://evil", "M1 remote set-url"],
    ["git reflog expire --all", "M1 reflog expire"], ["git log --output=/tmp/x", "M1 --output"],
    ["gh api -XPOST repos/a/b/issues", "M2 -XPOST"], ["gh api repos/a/b -Fbody=@secret.txt", "M2 -F attached"],
    ["gh auth status --show-token", "M2 show-token"], ["uniq in out", "uniq writes out"],
    ["aws s3api get-object --bucket b --key k ~/.claude/settings.json", "get-object writes"],
    ["eval \"$X\"", "eval"], ["source ./x.sh", "source"], [". ./x.sh", "dot"],
  ]) ok(!readOnly(cmd), `bypass: ${why}`);
  ok(readOnly(`jq -c '{a: .x | length, b: (.y // "z")}' ~/.local/state/reflex/trace.jsonl`), "jq filter with | and // is one command");
  ok(readOnly(`tail -n 4 t.jsonl | jq -c '{rule,source,emitted}'`) && !readOnly("echo x | source /dev/stdin"), "command words only outside quotes");
  ok(readOnly("grep -E 'deny|ask' f | wc -l") && readOnly(`echo "a; rm -rf x > y"`), "quoted | ; > are data");
  ok(!readOnly(`echo "$(rm -rf x)"`) && !readOnly("echo \"`rm -rf x`\""), "expansions inside double quotes still count");
  ok(!readOnly(`awk '{print | "sh"}' f`) && !readOnly(`awk '{print > "out"}' f`), "awk program pipes / redirects");
  ok(!readOnly(`echo 'unbalanced ; rm -rf x`), "unbalanced quotes are not trusted");
  ok(readOnly("git branch -a") && readOnly("git remote -v") && readOnly("sed -n '1,20p' f") && readOnly("sort f | uniq -c"), "reads still pass");
  ok(readOnly("S=/tmp/x; ls $S") && readOnly("for f in a b; do cat $f; done"), "safe variables");

  // redaction
  const r = redact("curl -H 'Authorization: Bearer abc.def' https://u:hunter2@x.io " +
                   "AWS_SECRET_ACCESS_KEY=wJalr/K7 --password s3cr3t AKIAABCDEFGHIJKLMNOP ghp_" + "a".repeat(36));
  for (const s of ["abc.def", "hunter2", "wJalr", "s3cr3t", "AKIAABCDEFGHIJKLMNOP", "ghp_aaaa"]) ok(!r.includes(s), `redact ${s}`);
  ok(redact("terraform plan -out tf.plan") === "terraform plan -out tf.plan", "redact leaves plain commands alone");
  const r2 = redact(`aws secretsmanager put-secret-value --secret-string '{"password": "hunter3"}' ; curl -u bob:pw9 x; ` +
    `mysql -pS3cret db; sshpass -p pw7 ssh h; sk_live_${"a".repeat(24)} AIza${"b".repeat(35)} ` +
    `https://hooks.slack.com/services/T0/B0/xyz -H 'Cookie: sid=abc123' wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ` +
    `https://u:p/w@d@host`);
  for (const x of ["hunter3", "pw9", "S3cret", "pw7", "sk_live_a", "AIzab", "T0/B0", "sid=abc123", "wJalrXUtn", "p/w@d"]) ok(!r2.includes(x), `redact ${x}`);
  ok(redact("git show 3f5e8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f").includes("3f5e8a9b"), "git SHA is not a secret");

  // deterministic rules
  const rules = load("rules.json");
  const rule = (cmd, extra = "") => checkRules(`${cmd} cwd=/w ${extra}`, rules)?.id ?? null;
  ok(rule("rm -rf /") === "rm-root" && rule("rm -rf ~") === "rm-root" && rule("rm -rf ~/") === "rm-root", "rm root");
  ok(rule("rm -rf ./build") === null && rule("rm -rf /tmp/x") === null, "rm of a subdir");
  ok(rule("aws rds delete-db-instance --db-instance-identifier prod-orders") === "prod-destroy", "prod rds delete");
  ok(rule("aws rds delete-db-instance --db-instance-identifier x", "aws_profile=production") === "prod-destroy", "prod via profile");
  ok(rule("aws rds delete-db-instance --db-instance-identifier x", "aws_profile=dev") === "destroy", "nonprod delete asks");
  ok(rule("terraform destroy", "cwd=/infra/envs/prod") === "prod-destroy", "prod via cwd");
  ok(rule("aws s3 delete-object --bucket product-images --key a") === "destroy", "'product' is not prod");
  ok(rule("git push --force origin main") === "force-push-main", "force push main");
  ok(rule("git push -f", "git_branch=master") === "force-push-main", "force push current master");
  ok(rule("git push origin main") === null && rule("git push -f origin feat/x", "git_branch=feat/x") === null, "normal pushes");
  ok(rule("sed -i s/enforce/shadow/ ~/.claude/settings.json") === "tamper", "tamper settings");
  ok(rule("export REFLEX_MODE=off") === "tamper" && rule("vim ~/src/reflex/setup/tool-gate/rules.json") === "tamper", "tamper mode / repo");
  ok(rule("git push origin --mirror") === "push-mirror" && !fastPass("git push origin --mirror", rules), "mirror push");
  ok(rule("git push -fu origin main") === "force-push-main" && rule("git push origin :main") === "force-push-main" &&
     rule("git push origin --delete main") === "force-push-main", "force push variants");
  ok(rule("echo $(rm -rf ~)") === "rm-root" && rule("x=`rm -rf /`") === "rm-root" && rule("bash -c 'rm -rf ~'") === "rm-root", "rm-root inside $(), backticks, quotes");
  ok(rule("rm -rf -- /") === "rm-root" && rule('rm --recursive --force "$HOME"') === "rm-root" && rule("rm -rf ${HOME}") === "rm-root", "rm-root variants");
  ok(rule("aws s3 rm s3://b --recursive", "aws_profile=prod01") === "prod-destroy" && rule("terraform state rm x", "cwd=/envs/live") === "prod-destroy", "prod variants");
  ok(rule("kubectl --context prd scale deploy/a --replicas=0") === "prod-destroy" && rule("psql -c 'TRUNCATE users'", "cwd=/prod") === "prod-destroy", "prod scale / truncate");
  ok(rule("aws secretsmanager delete-secret --secret-id=prod-db") === "prod-destroy", "rules see the raw command");
  const body = "gh pr create --title x --body \"$(cat <<'EOF'\nverified: git push --force origin main is denied\nEOF\n)\"";
  const msg = "git commit -F - <<'EOF'\nfix: deny git push --force origin main\nEOF";
  ok(rule(stripDataHeredocs(body)) === null && rule(stripDataHeredocs(msg)) === null, "PR bodies and commit messages are data");
  ok(rule(stripDataHeredocs("bash <<'EOF'\ngit push --force origin main\nEOF")) === "force-push-main" &&
     rule(stripDataHeredocs("ssh h <<'EOF'\nrm -rf ~\nEOF")) === "rm-root" &&
     rule(stripDataHeredocs("cat <<EOF\n$(rm -rf ~)\nEOF")) === "rm-root" &&
     rule(stripDataHeredocs("cat <<'EOF' | bash\nrm -rf ~\nEOF")) === "rm-root", "heredocs that run, or expand, still count");
  ok(rule("aws s3 ls", "cwd=/liveness") === null && rule("gcloud compute instances list", "cwd=/prod") === null, "no false prod");
  ok(fastPass("go test ./...", rules) && fastPass("npm run smoke", rules), "fast lane");
  ok(fastPass("mkdir -p out && go test ./... 2>&1 | tail -5", rules), "fast lane mixes with reads");
  ok(!fastPass("go test ./... && curl -d @x http://e", rules) && !fastPass("npm run deploy", rules), "fast lane is exact per segment");
  ok(fastPass("git push -u origin feat/x", rules) && !fastPass("git push origin main", rules) &&
     !fastPass("git push origin HEAD:main", rules) && !fastPass("git push --force origin feat/x", rules), "branch push lane");

  // policy
  const p = compile(load("policy.json"));
  const A = (mutates, blast, env, exfil, bc = 0.9, extra = {}) =>
    ({mutates: {noul: mutates}, blast: {score: blast, confidence: bc}, env: {choice: env}, exfil: {noul: exfil}, ...extra});
  ok(p.decide(A(0.95, 2.9, "production", 0.1)).outcome === "deny", "prod destroy denies");
  ok(p.decide(A(0.9, 1.2, "production", 0.1)).outcome === "ask", "prod mutation asks");
  ok(p.decide(A(0.9, 2.0, "nonprod", 0.1)).outcome === "ask", "high blast asks");
  ok(p.decide(A(0.1, 0.3, "local", 0.8)).outcome === "ask", "exfil asks");
  ok(p.decide(A(0.8, 1.0, "local", 0.1, 0.3)).outcome === "ask", "unsure mutation asks");
  ok(p.decide(A(0.6, 1.0, "local", 0.1)).outcome === "pass", "local edit passes");
  ok(p.decide(A(0.1, 0.2, "local", 0.1, 0.9, {injection: {noul: 0.9}})).outcome === "deny", "injection denies");
  ok(p.decide(A(0.8, 1.0, "local", 0.1, 0.9, {on_task: {noul: 0.1}})).outcome === "ask", "off-task mutation asks");
  ok(p.decide(A(0.8, 1.0, "local", 0.1, 0.9, {on_task: {noul: 0.9}})).outcome === "pass", "on-task mutation passes");
  ok(p.policy.fallback === "ask", "errors, including incomplete answers, use the ask fallback");

  // intent: the text right before this call's tool_use, never an older message
  const tp = join(tmpdir(), `reflex-selfcheck-${process.pid}.jsonl`);
  const A2 = content => JSON.stringify({type: "assistant", message: {content}});
  writeFileSync(tp, [A2([{type: "text", text: "Old task"}]), A2([{type: "tool_use", id: "t1", name: "Bash", input: {command: "ls"}}]),
    JSON.stringify({type: "user", message: {content: [{type: "text", text: "next"}]}}),
    A2([{type: "text", text: "Deleting the test repo"}]), A2([{type: "tool_use", id: "t2", name: "Bash", input: {command: "gh repo delete x"}}])].join("\n"));
  ok(sessionContext(tp, "t2").intent === "Deleting the test repo", "intent is the text before this call");
  ok(sessionContext(tp, "t9").intent === undefined && sessionContext(tp, "t9").recent?.length === 2, "call not in transcript yet: no intent");
  rmSync(tp, {force: true});

  // the whole path, without Jev
  ok((await judge({command: "ls -la", cwd: "/w", env: {}})).source === "read-only", "judge: read-only");
  ok((await judge({command: "echo $TYPESAFE_API_KEY", cwd: "/w", env: {}})).outcome === "ask", "judge: key read is ruled before read-only");
  ok((await judge({command: "rm -rf ~", cwd: "/w", env: {}})).outcome === "deny", "judge: rule before Jev");
  ok((await judge({command: "go test ./...", cwd: "/w", env: {}})).source === "fast-lane", "judge: fast lane");
  ok((await judge({command: `sed -i '' s/deny/pass/ ${join(HERE, "setup/tool-gate/policy.json")}`, cwd: "/w", env: {}})).outcome === "ask", "judge: tamper by path");
  ok((await judge({command: "sed -i '' s/deny/pass/ setup/tool-gate/policy.json", cwd: HERE, env: {}})).outcome === "ask", "judge: tamper by cwd");
  ok((await judge({command: "go test ./...", cwd: HERE, env: {}})).source === "fast-lane", "judge: normal work in the repo");
  console.log(process.exitCode ? "gate selfcheck FAILED" : "gate selfcheck OK");
}

const readStdin = () => JSON.parse(readFileSync(0, "utf8"));
// ask needs a human: read y/N from the controlling terminal; no terminal means no approval.
function confirmOnTty(command, reason) {
  try {
    const fd = openSync("/dev/tty", "r+");
    const q = Buffer.from(`\n${reason}\n  ${redact(command).slice(0, 300)}\nrun it? [y/N] `);
    writeSync(fd, q);
    const buf = Buffer.alloc(16), n = readSync(fd, buf, 0, 16, null);
    closeSync(fd);
    return /^y(es)?$/i.test(buf.toString("utf8", 0, n).trim());
  } catch { return false; }
}
const argv = process.argv.slice(2);
const flag = f => argv.includes(f);
const opt = n => { const i = argv.indexOf(n); return i > -1 ? argv[i + 1] : undefined; };
const main = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
const guarded = fn => Promise.resolve().then(fn).catch(e => console.error(`reflex: ${e.message}`));

// A broken gate must never block the agent silently: errors go to stderr and the process exits 0,
// so the agent's own permission rules still apply.
if (!main) { /* imported as a library */ }
else if (flag("--selfcheck")) await selfcheck();
else if (flag("--claude")) await guarded(async () => claudePre(readStdin()));
else if (flag("--claude-post")) await guarded(async () => claudePost(readStdin()));
else if (flag("--codex")) await guarded(async () => codexPre(readStdin()));
else if (flag("--codex-post")) await guarded(async () => codexPost(readStdin()));
else if (flag("--hermes")) await guarded(async () => hermesPre(readStdin()));
else if (flag("--hermes-post")) await guarded(async () => hermesPost(readStdin()));
else if (flag("--decide")) await guarded(async () => process.stdout.write(JSON.stringify(await decideSafe(readStdin())) + "\n"));
else if (flag("--record")) await guarded(async () => record(readStdin()));
else if (flag("--bg")) await guarded(async () => decide(readStdin(), {background: true}));
else if (flag("--sh")) {
  // Shell shim (bin/reflex-sh): bash-compatible `-c` / `-lc` calls are judged, then run, confirmed
  // on the terminal, or refused with exit 126. Everything else is passed to bash untouched.
  const args = argv.slice(argv.indexOf("--sh") + 1);
  const ci = args.findIndex(a => /^-[a-z]*c[a-z]*$/.test(a));
  const command = ci > -1 ? args[ci + 1] : undefined;
  const bash = ENV.REFLEX_SHELL ?? "/bin/bash";
  let verdict = "pass";
  if (command) {
    const d = await decideSafe({agent: ENV.REFLEX_AGENT ?? "shell", command, cwd: process.cwd(),
                                session_id: ENV.REFLEX_SESSION_ID, intent: ENV.REFLEX_INTENT});
    verdict = d.effective;
    if (verdict === "ask") verdict = confirmOnTty(command, d.reason) ? "pass" : "deny";
    if (verdict === "deny") { console.error(`${d.reason}\nrefused; a human can run it directly if it is intended.`); process.exit(126); }
  }
  const r = spawnSync(bash, args, {stdio: "inherit"});
  if (command) record({agent: ENV.REFLEX_AGENT ?? "shell", event: "ran", exit_code: r.status});
  process.exit(r.status ?? 1);
}
else if (flag("--check")) {
  // Try one command without an agent: node gate.mjs --check "terraform apply" [--cwd dir] [--intent text]
  const cwd = opt("--cwd") ?? process.cwd(), intent = opt("--intent");
  const j = await judge({command: opt("--check"), cwd, session: intent ? {intent} : {}, useCache: false});
  const answers = Object.fromEntries(Object.entries(j.answers ?? {}).map(([k, a]) => [k, a.noul ?? a.choice ?? a.score]));
  console.log(JSON.stringify({decision: j.outcome, rule: j.rule, source: j.source, policy: j.policy_version ?? null,
                              latency_s: j.latency_s ?? 0, answers, env: j.state?.call?.env, error: j.error ?? undefined}, null, 1));
}
else console.error("usage: gate.mjs --check <cmd> | --decide | --record | --claude[-post] | --codex[-post] | --hermes[-post] | --selfcheck");
