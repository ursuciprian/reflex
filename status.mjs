#!/usr/bin/env node
// Installation checks are local. A synthetic probe cannot establish that a host trusted a hook.
import {existsSync, mkdtempSync, readFileSync, rmSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {homedir, platform, tmpdir} from "node:os";
import {join} from "node:path";
import {CONFIG, USER_CONFIG, USER_CONFIG_FILE, configurationError, load, setupFile} from "./gate.mjs";
import {compile} from "./policy.mjs";

const doctor = process.argv.includes("--doctor"), json = process.argv.includes("--json");
const errors = [], warnings = [], agents = [];
const home = homedir();
const files = {claude: ".claude/settings.json", codex: ".codex/hooks.json", pi: ".pi/agent/extensions/reflex.ts",
  omp: ".omp/agent/extensions/reflex.ts", opencode: ".config/opencode/plugins/reflex.js"};
const quote = s => `"${s.replace(/(["\\`$])/g, "\\$1")}"`;
const read = path => JSON.parse(readFileSync(path, "utf8"));
const configuration = configurationError();
if (configuration) errors.push(configuration);
if (platform() === "win32") errors.push("Native Windows is not supported; run Reflex and the agent inside WSL.");
if (CONFIG.mode === "off") warnings.push("Protection is off.");
if (CONFIG.engine === "local") warnings.push("Local coverage: shell rules and deterministic instructions; uncertain commands ask in enforce mode. Hosted features are disabled.");
if (CONFIG.mode === "shadow") warnings.push("Shadow mode enforces deterministic rules. Other decisions are logged without blocking.");
const policy = setupFile("policy.json");
try { compile(load("policy.json")); load("rules.json"); load("questions.json"); }
catch (e) { errors.push(`Cannot load policy: ${e.message}`); }
let key = "not required";
if (CONFIG.engine === "jev") {
  key = process.env.TYPESAFE_API_KEY?.trim() ? "environment" : platform() === "darwin" &&
    spawnSync("security", ["find-generic-password", "-s", CONFIG.keychain], {stdio: "ignore", timeout: 2000}).status === 0 ? "keychain" : "missing";
  if (key === "missing") errors.push("Jev needs TYPESAFE_API_KEY or a Keychain item. Use reflex setup --engine local for offline operation.");
}

for (const [name, saved] of Object.entries(USER_CONFIG.agents ?? {})) {
  if (!saved || typeof saved.root !== "string" || typeof saved.node !== "string") { errors.push(`${name}: invalid installation record`); continue; }
  const item = {name, configured: false, mode: process.env.REFLEX_MODE ?? saved.mode, allow: process.env.REFLEX_ALLOW ?? saved.allow,
    engine: CONFIG.engine, hook_observed: false, last_seen: null, version: null, checks: []};
  const gate = join(saved.root, "gate.mjs");
  const version = spawnSync(name, ["--version"], {encoding: "utf8", timeout: 3000});
  if (version.status === 0) item.version = version.stdout.trim().split("\n")[0].slice(0, 160);
  else warnings.push(`${name}: executable not available on this PATH; verify in the environment where the agent runs.`);
  if (saved.manual || name === "hermes") {
    warnings.push(`${name}: configuration is manual; use hermes hooks list in each profile. Doctor cannot verify its YAML or trust settings.`);
  } else if (files[name]) try {
    const file = join(home, files[name]), source = readFileSync(file, "utf8");
    if (["claude", "codex"].includes(name)) {
      const expected = `${quote(saved.node)} ${quote(gate)} --${name} --mode ${saved.mode} --allow ${saved.allow}`;
      const matcher = name === "claude" ? "Bash|Task|Agent" : "^(Bash|spawn_agent)$";
      item.configured = (JSON.parse(source).hooks?.PreToolUse ?? []).some(g => g.matcher === matcher &&
        g.hooks?.some(h => h.type === "command" && h.command === expected));
    } else item.configured = source.includes(JSON.stringify(gate)) && source.includes(JSON.stringify(saved.node)) &&
      source.includes(JSON.stringify(saved.mode)) && source.includes(JSON.stringify(saved.allow));
    if (!item.configured) errors.push(`${name}: expected Reflex pre-execution adapter is missing or changed in ${file}. Re-run reflex setup --agents ${name}.`);
  } catch (e) { errors.push(`${name}: cannot read its adapter: ${e.message}`); }
  if (!existsSync(gate)) errors.push(`${name}: gate is missing at ${gate}. Re-run setup.`);
  try {
    const seen = read(join(CONFIG.data, "health", `${name === "claude" ? "claude-code" : name}.json`));
    item.last_seen = seen.at;
    item.hook_observed = seen.gate === saved.root && Date.parse(seen.at) >= Date.parse(saved.installed_at) &&
      seen.mode === item.mode && seen.engine === item.engine && seen.allow === item.allow;
  } catch { /* no real hook event yet */ }
  if (!item.hook_observed) warnings.push(`${name}: awaiting a real pre-execution event. Restart the agent${name === "codex" ? " and trust the hooks in /hooks" : ""}, run a harmless command, then check status again.`);
  if (doctor && item.configured && existsSync(gate)) {
    const scratch = mkdtempSync(join(tmpdir(), "reflex-doctor-"));
    try {
      for (const [command, expected] of [["git status", "pass"], ["git push --force origin main", "deny"]]) {
        const native = ["claude", "codex"].includes(name);
        const input = native ? {tool_name: "Bash", tool_input: {command}, cwd: scratch, session_id: "reflex-doctor"}
          : {agent: name, command, cwd: scratch, session_id: "reflex-doctor"};
        // Input is only judged, never executed. Probe records live in a disposable directory.
        const result = spawnSync(saved.node, [gate, native ? `--${name}` : "--decide", "--mode", saved.mode, "--allow", saved.allow], {
          encoding: "utf8", timeout: 10000, input: JSON.stringify(input),
          env: {...process.env, REFLEX_ENGINE: "local", REFLEX_DATA_DIR: scratch}});
        let effective;
        try { const out = JSON.parse(result.stdout.trim() || "{}"); effective = native ? out.hookSpecificOutput?.permissionDecision ?? "pass" : out.effective; }
        catch { /* invalid output fails below */ }
        const ok = result.status === 0 && effective === expected;
        item.checks.push({command, expected, actual: effective ?? null, ok});
        if (!ok) errors.push(`${name}: ${expected} probe failed (${result.error?.message ?? effective ?? "invalid output"}).`);
      }
    } finally { rmSync(scratch, {recursive: true, force: true}); }
  }
  agents.push(item);
}
if (!agents.length) warnings.push("No agent installations recorded. Run reflex setup --agents claude,codex, or use reflex run in your own terminal.");
const result = {engine: CONFIG.engine, mode: CONFIG.mode, allow: CONFIG.allow, config: USER_CONFIG_FILE,
  policy, api_key: key, agents, errors, warnings};
if (json) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`Reflex: ${CONFIG.engine} engine · ${CONFIG.mode} mode · allow ${CONFIG.allow}`);
  console.log(`Settings: ${USER_CONFIG_FILE}\nPolicy: ${policy}\nAPI key: ${key}`);
  for (const a of agents) console.log(`${a.name}: ${a.configured ? "configured" : "not verified"}; ${a.mode}/${a.engine}; ${a.hook_observed ? "hook observed" : "awaiting hook event"}; ${a.version ?? "version unknown"}${a.checks.length ? `; probes ${a.checks.every(c => c.ok) ? "passed" : "FAILED"}` : ""}`);
  for (const w of warnings) console.log(`Note: ${w}`);
  for (const e of errors) console.error(`Error: ${e}`);
  if (doctor) console.log("Doctor checks local configuration and synthetic decisions; host approval dialogs require verification in a real session. No commands were executed or sent to TypeSafe.");
}
process.exitCode = errors.length ? 1 : 0;
