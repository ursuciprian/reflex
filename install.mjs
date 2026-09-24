#!/usr/bin/env node
// Wire Reflex into coding agents: the pre-execution gate plus conditional instructions on each
// user prompt. Idempotent: re-running replaces only Reflex's own entries. Every file it edits is
// backed up next to itself first.
//
//   node install.mjs --agent claude          Claude Code  ~/.claude/settings.json PreToolUse + UserPromptSubmit hooks
//   node install.mjs --agent codex           Codex CLI    ~/.codex/hooks.json PreToolUse + UserPromptSubmit (then trust them in /hooks)
//   node install.mjs --agent opencode        opencode     ~/.config/opencode/plugins/reflex.js (tool.execute.before, chat.message)
//   node install.mjs --agent pi | omp        pi / oh-my-pi ~/.{pi,omp}/agent/extensions/reflex.ts (tool_call, before_agent_start)
//   node install.mjs --agent hermes          prints the config.yaml pre_tool_call / pre_llm_call blocks to paste per profile
//   node install.mjs --agent all             every agent found on this machine
//
//   --mode shadow|enforce|off   (default shadow)   --node <path>   --uninstall
import {copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {homedir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";

const argv = process.argv.slice(2);
const opt = (n, d) => {
  const i = argv.indexOf(n);
  if (i < 0) return d;
  if (!argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`${n} needs a value`);
  return argv[i + 1];
};
const HOME = homedir();
const REPO = dirname(fileURLToPath(import.meta.url));
const GATE = join(REPO, "gate.mjs");
const INSTRUCTIONS = join(REPO, "instructions.mjs");
const MODE = opt("--mode", "shadow");
const NODE = opt("--node", process.execPath);   // absolute, so hooks work without the shell's PATH
const UNINSTALL = argv.includes("--uninstall");
if (!["off", "shadow", "enforce"].includes(MODE)) throw new Error("--mode must be off, shadow or enforce");
if (Number(process.versions.node.split(".")[0]) < 18) throw new Error(`node 18+ required, found ${process.versions.node}`);

const q = s => `"${s}"`;
const cmd = (flag, script = GATE) => `${q(NODE)} ${q(script)} ${flag} --mode ${MODE}`;
const isOurs = c => typeof c === "string" && (c.includes(q(GATE)) || c.includes(q(INSTRUCTIONS)));
const readJson = f => existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
function writeFile(f, text) {
  if (existsSync(f)) copyFileSync(f, `${f}.bak-${Date.now()}`);
  mkdirSync(dirname(f), {recursive: true});
  writeFileSync(f, text);
}
const has = bin => { try { execFileSync("which", [bin], {stdio: "ignore"}); return true; } catch { return false; } };
const fill = src => src.replaceAll("__REFLEX_GATE__", GATE).replaceAll("__REFLEX_NODE__", NODE).replaceAll("__REFLEX_MODE__", MODE);

// Remove only Reflex's hook entries; a matcher group left empty is dropped, other hooks stay.
function stripOurs(hooks) {
  for (const ev of Object.keys(hooks)) {
    hooks[ev] = hooks[ev].map(g => ({...g, hooks: (g.hooks ?? []).filter(h => !isOurs(h.command))}))
                         .filter(g => g.hooks.length);
    if (!hooks[ev].length) delete hooks[ev];
  }
}
const group = (matcher, flag, timeout) => ({matcher, hooks: [{type: "command", command: cmd(flag), timeout}]});
// UserPromptSubmit takes no matcher in either agent. Instructions are advisory: a slow Jev call
// must not hold the prompt for long, and a failed hook injects nothing.
const promptGroup = flag => ({hooks: [{type: "command", command: cmd(flag, INSTRUCTIONS), timeout: 10}]});

// pi and oh-my-pi load TypeScript extensions from <home>/agent/extensions/.
function piLike(agent) {
  const file = join(HOME, `.${agent}`, "agent/extensions/reflex.ts");
  if (UNINSTALL) { rmSync(file, {force: true}); return `${file} removed`; }
  writeFile(file, fill(readFileSync(join(REPO, "adapters/pi.ts"), "utf8")).replaceAll("__REFLEX_AGENT__", agent));
  return `${file} (restart ${agent})`;
}

const AGENTS = {
  claude: {bin: "claude", run() {
    const file = join(HOME, ".claude/settings.json");
    const s = readJson(file);
    s.hooks ??= {};
    stripOurs(s.hooks);
    // The agent must not quietly edit its own gate or its settings; a human confirms each change.
    // ~/.config/reflex holds personal instruction fragments, injected into every repo's sessions.
    const guard = [REPO, join(HOME, ".local/state/reflex"), join(HOME, ".config/reflex")]
      .flatMap(d => { const p = d.replace(HOME, "~"); return [`Edit(${p}/**)`, `Write(${p}/**)`]; })
      .concat(["Edit(~/.claude/settings*.json)", "Write(~/.claude/settings*.json)"]);
    s.permissions ??= {};
    s.permissions.ask = (s.permissions.ask ?? []).filter(r => !guard.includes(r));
    if (s.env?.REFLEX_MODE) delete s.env.REFLEX_MODE;
    if (!UNINSTALL) {
      s.hooks.PreToolUse = [...(s.hooks.PreToolUse ?? []), group("Bash", "--claude", 10)];
      for (const ev of ["PostToolUse", "PostToolUseFailure", "PermissionDenied"])
        s.hooks[ev] = [...(s.hooks[ev] ?? []), group("Bash", "--claude-post", 5)];
      s.hooks.UserPromptSubmit = [...(s.hooks.UserPromptSubmit ?? []), promptGroup("--claude")];
      s.permissions.ask.push(...guard);
    }
    if (!s.permissions.ask.length) delete s.permissions.ask;
    for (const k of ["permissions", "env", "hooks"]) if (s[k] && !Object.keys(s[k]).length) delete s[k];
    writeFile(file, JSON.stringify(s, null, 2) + "\n");
    return `${file} (restart sessions)`;
  }},
  codex: {bin: "codex", run() {
    const file = join(HOME, ".codex/hooks.json");
    const s = readJson(file);
    s.hooks ??= {};
    stripOurs(s.hooks);
    if (!UNINSTALL) {
      s.hooks.PreToolUse = [...(s.hooks.PreToolUse ?? []), group("^Bash$", "--codex", 15)];
      s.hooks.PostToolUse = [...(s.hooks.PostToolUse ?? []), group("^Bash$", "--codex-post", 5)];
      s.hooks.UserPromptSubmit = [...(s.hooks.UserPromptSubmit ?? []), promptGroup("--codex")];
    }
    writeFile(file, JSON.stringify(s, null, 2) + "\n");
    return `${file}${UNINSTALL ? "" : " — open Codex and trust the new hooks in /hooks, or they will not run"}`;
  }},
  opencode: {bin: "opencode", run() {
    const file = join(HOME, ".config/opencode/plugins/reflex.js");
    if (UNINSTALL) { rmSync(file, {force: true}); return `${file} removed`; }
    writeFile(file, fill(readFileSync(join(REPO, "adapters/opencode.js"), "utf8")));
    return `${file} (restart opencode)`;
  }},
  pi: {bin: "pi", run: () => piLike("pi")},
  omp: {bin: "omp", run: () => piLike("omp")},
  hermes: {bin: "hermes", run() {
    const profiles = join(HOME, ".hermes/profiles");
    const names = existsSync(profiles) ? readdirSync(profiles) : [];
    console.log(`\nHermes: ${UNINSTALL ? "remove the reflex entries under hooks: from" : "add this to"} each profile's config.yaml` +
                ` (${names.join(", ") || "none found"}), then \`hermes hooks list\` to accept it:\n`);
    if (!UNINSTALL) console.log([
      "hooks:",
      "  pre_tool_call:",
      `    - matcher: "terminal"`,
      `      command: '${cmd("--hermes")}'`,
      "      timeout: 15",
      "      fail_closed: true",
      "  post_tool_call:",
      `    - matcher: "terminal"`,
      `      command: '${cmd("--hermes-post")}'`,
      "      timeout: 5",
      "  pre_llm_call:",
      `    - command: '${cmd("--hermes", INSTRUCTIONS)}'`,
      "      timeout: 10",
      "",
    ].join("\n"));
    return "printed (Hermes config is YAML; paste it rather than have a script rewrite it)";
  }},
};

const which = opt("--agent", "claude");
const targets = which === "all" ? Object.keys(AGENTS).filter(a => has(AGENTS[a].bin)) : which.split(",");
for (const a of targets) if (!AGENTS[a]) throw new Error(`unknown agent ${a}; one of ${Object.keys(AGENTS).join(", ")}, all`);
for (const a of targets) console.log(`${a.padEnd(9)} ${UNINSTALL ? "uninstalled" : `installed (${MODE})`}: ${AGENTS[a].run()}`);
