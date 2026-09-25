#!/usr/bin/env node
// Wire Reflex into coding agents: the pre-execution gate plus conditional instructions on each
// user prompt. Idempotent: re-running replaces only Reflex's own entries. Every file it edits is
// backed up next to itself first.
//
//   node install.mjs --agent claude          Claude Code  ~/.claude/settings.json PreToolUse, PostToolUse, PermissionRequest + UserPromptSubmit hooks
//   node install.mjs --agent codex           Codex CLI    ~/.codex/hooks.json PreToolUse + UserPromptSubmit (then trust them in /hooks)
//   node install.mjs --agent opencode        opencode     ~/.config/opencode/plugins/reflex.js (tool.execute.before, chat.message)
//   node install.mjs --agent pi | omp        pi / oh-my-pi ~/.{pi,omp}/agent/extensions/reflex.ts (tool_call, before_agent_start)
//     --context | --no-context               add / remove reflex-context.ts, the Jev context layer (context.mjs);
//                                            with neither, an installed context layer is refreshed and kept
//   node install.mjs --agent hermes          prints the config.yaml pre_tool_call / pre_llm_call blocks to paste per profile
//   node install.mjs --agent all             every agent found on this machine
//   node install.mjs --router [--agent x]    print (never apply) the MCP registration of router/server.mjs
//
//   --mode shadow|enforce|off   (default shadow)   --node <path>   --uninstall
//   --allow off|shadow|on       (default off) let clearly safe commands skip the agent's prompt (enforce only)
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
const ALLOW = opt("--allow", "off");
const UNINSTALL = argv.includes("--uninstall");
const KEYCHAIN = opt("--keychain", undefined);   // macOS Keychain item holding the TypeSafe key
const CONTEXT = argv.includes("--context") ? "on" : argv.includes("--no-context") ? "off" : "keep";
if (argv.includes("--context") && argv.includes("--no-context")) throw new Error("--context and --no-context conflict");
if (!["off", "shadow", "enforce"].includes(MODE)) throw new Error("--mode must be off, shadow or enforce");
if (!["off", "shadow", "on"].includes(ALLOW)) throw new Error("--allow must be off, shadow or on");
if (ALLOW === "on" && MODE !== "enforce") console.error(`note: --allow on only takes effect with --mode enforce; in ${MODE} mode allows are logged as would_allow`);
if (Number(process.versions.node.split(".")[0]) < 18) throw new Error(`node 18+ required, found ${process.versions.node}`);

const q = s => `"${s}"`;
const cmd = (flag, script = GATE) => `${q(NODE)} ${q(script)} ${flag} --mode ${MODE}${script === GATE ? ` --allow ${ALLOW}` : ""}`;
const isOurs = c => typeof c === "string" && (c.includes(q(GATE)) || c.includes(q(INSTRUCTIONS)));
const readJson = f => existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
function writeFile(f, text) {
  if (existsSync(f)) copyFileSync(f, `${f}.bak-${Date.now()}`);
  mkdirSync(dirname(f), {recursive: true});
  writeFileSync(f, text);
}
const has = bin => { try { execFileSync("which", [bin], {stdio: "ignore"}); return true; } catch { return false; } };
const fill = src => src.replaceAll("__REFLEX_GATE__", GATE).replaceAll("__REFLEX_NODE__", NODE)
  .replaceAll("__REFLEX_MODE__", MODE).replaceAll("__REFLEX_ALLOW__", ALLOW);

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
// The context layer sits next to the gate: --context installs it, --no-context removes it, and a
// plain re-install refreshes it only if it is already there, so re-running install never switches
// it on or off by accident. --uninstall removes both.
function piLike(agent) {
  const dir = join(HOME, `.${agent}`, "agent/extensions");
  const file = join(dir, "reflex.ts"), ctx = join(dir, "reflex-context.ts");
  if (UNINSTALL) { rmSync(file, {force: true}); rmSync(ctx, {force: true}); return `${file} and ${ctx} removed`; }
  writeFile(file, fill(readFileSync(join(REPO, "adapters/pi.ts"), "utf8")).replaceAll("__REFLEX_AGENT__", agent));
  if (CONTEXT === "off" || (CONTEXT === "keep" && !existsSync(ctx))) {
    const had = existsSync(ctx);
    rmSync(ctx, {force: true});
    return `${file}${had ? `, ${ctx} removed` : ""} (restart ${agent})`;
  }
  writeFile(ctx, readFileSync(join(REPO, "adapters/pi-context.ts"), "utf8").replaceAll("__REFLEX_CONTEXT__", join(REPO, "context.mjs")));
  return `${file}, ${ctx}${CONTEXT === "keep" ? " (context layer kept; --no-context removes it)" : ""} (restart ${agent})`;
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
    if (s.env?.REFLEX_ALLOW) delete s.env.REFLEX_ALLOW;
    if (!UNINSTALL) {
      // Task|Agent: subgoal dedup before a subagent is spawned, and its PostToolUse marks it launched
      s.hooks.PreToolUse = [...(s.hooks.PreToolUse ?? []), group("Bash|Task|Agent", "--claude", 10)];
      for (const ev of ["PostToolUse", "PostToolUseFailure", "PermissionDenied"])
        s.hooks[ev] = [...(s.hooks[ev] ?? []), group("Bash|Task|Agent", "--claude-post", 5)];
      // records that Claude Code showed its own dialog (never answers it): calibration and rejected spawns
      s.hooks.PermissionRequest = [...(s.hooks.PermissionRequest ?? []), group("Bash|Task|Agent", "--claude-prompted", 5)];
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
      // spawn_agent: subgoal dedup before a subagent is spawned, and its PostToolUse marks it launched
      s.hooks.PreToolUse = [...(s.hooks.PreToolUse ?? []), group("^(Bash|spawn_agent)$", "--codex", 15)];
      s.hooks.PostToolUse = [...(s.hooks.PostToolUse ?? []), group("^(Bash|spawn_agent)$", "--codex-post", 5)];
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
      `    - matcher: "delegate_task"`,          // subgoal dedup; never fail-closed, it only saves work
      `      command: '${cmd("--hermes")}'`,
      "      timeout: 15",
      "  post_tool_call:",
      `    - matcher: "terminal|delegate_task"`,
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

// --router: print how to register router/server.mjs as an MCP server in each agent. Printed, not
// run: `claude mcp add` and friends write global config, which stays a human's decision.
if (argv.includes("--router")) {
  const server = join(REPO, "router/server.mjs"), name = "reflex-router";
  const env = process.env.REFLEX_KEYCHAIN_SERVICE ? {REFLEX_KEYCHAIN_SERVICE: process.env.REFLEX_KEYCHAIN_SERVICE} : {};
  const envFlags = flag => Object.entries(env).map(([k, v]) => `${flag} ${k}=${v} `).join("");
  const args = [server, "--mode", MODE];
  const json = extra => JSON.stringify({mcpServers: {[name]: {...extra, command: NODE, args, ...(Object.keys(env).length ? {env} : {})}}}, null, 2);
  const out = {
    // --env takes several KEY=value pairs: an option must sit between it and the name, or the name is read as a pair
    claude: `claude mcp add --scope user ${envFlags("--env")}--transport stdio ${name} -- ${q(NODE)} ${args.map(q).join(" ")}\n` +
            `# or commit it for a repo: .mcp.json\n${json({type: "stdio"})}`,
    codex: `codex mcp add ${name} ${envFlags("--env")}-- ${q(NODE)} ${args.map(q).join(" ")}\n# or ~/.codex/config.toml:\n` +
           `[mcp_servers.${name}]\ncommand = ${q(NODE)}\nargs = [${args.map(q).join(", ")}]\n` +
           (Object.keys(env).length ? `\n[mcp_servers.${name}.env]\n${Object.entries(env).map(([k, v]) => `${k} = ${q(v)}`).join("\n")}\n` : ""),
    pi: `# pi has no built-in MCP; install the pi-mcp-adapter extension (pi install npm:pi-mcp-adapter), then\n` +
        `# ~/.pi/agent/mcp.json (or the repo's .mcp.json):\n${json({})}`,
    omp: `# ~/.omp/agent/mcp.json (or .omp/mcp.json in a repo). omp also imports ~/.claude.json and\n` +
         `# ~/.codex/config.toml, so register it in one place only.\n${json({type: "stdio"})}`,
    opencode: `# ~/.config/opencode/opencode.json (or opencode.json in a repo):\n` + JSON.stringify({mcp: {[name]: {type: "local",
      command: [NODE, ...args], ...(Object.keys(env).length ? {environment: env} : {}), enabled: true, timeout: 10000}}}, null, 2),
    hermes: `# config.yaml of each profile. Hermes passes servers a filtered environment: put anything the\n` +
            `# router needs (TYPESAFE_API_KEY or REFLEX_KEYCHAIN_SERVICE, REFLEX_*) under env:.\n` +
            `mcp_servers:\n  ${name}:\n    command: ${q(NODE)}\n    args: [${args.map(q).join(", ")}]\n` +
            (Object.keys(env).length ? `    env:\n${Object.entries(env).map(([k, v]) => `      ${k}: ${q(v)}`).join("\n")}\n` : ""),
  };
  const pick = opt("--agent", "all");
  for (const a of pick === "all" ? Object.keys(out) : pick.split(",")) {
    if (!out[a]) throw new Error(`unknown agent ${a}; one of ${Object.keys(out).join(", ")}, all`);
    console.log(`\n## ${a}\n${out[a]}`);
  }
  console.log("\nNothing was changed. Downstream MCP servers go in router/config.json (REFLEX_ROUTER_CONFIG); see docs/GUIDE.md.");
  process.exit(0);
}

// --selfcheck: every agent's install, reinstall and uninstall with every feature flag, against a
// throwaway HOME (this script in a child process), next to hooks and files that are not Reflex's.
if (argv.includes("--selfcheck")) {
  const {mkdtempSync} = await import("node:fs"), {tmpdir} = await import("node:os"), {spawnSync} = await import("node:child_process");
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  const home = mkdtempSync(join(tmpdir(), "reflex-install-"));
  const data = join(home, "data");
  const run = (...a) => { const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...a], {encoding: "utf8",
    env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), PATH: "/usr/bin:/bin"}}); ok(r.status === 0, `install ${a.join(" ")}: ${r.stderr}`); return r.stdout; };
  const read = f => existsSync(join(home, f)) ? readFileSync(join(home, f), "utf8") : null;
  const put = (f, text) => { mkdirSync(dirname(join(home, f)), {recursive: true}); writeFileSync(join(home, f), text); };
  const commands = j => Object.values(JSON.parse(j).hooks ?? {}).flat().flatMap(g => g.hooks.map(h => h.command));
  try {
    // claude and codex: JSON hook files shared with other tools
    const foreign = {type: "command", command: "/usr/local/bin/other-hook", timeout: 3};
    const seeds = {
      ".claude/settings.json": {model: "opus", env: {FOO: "1"}, permissions: {allow: ["Bash(ls)"], ask: ["Bash(rm *)"]},
        hooks: {PreToolUse: [{matcher: "Bash", hooks: [foreign]}], PermissionRequest: [{matcher: "*", hooks: [foreign]}],
                UserPromptSubmit: [{hooks: [foreign]}]}},
      ".codex/hooks.json": {hooks: {PreToolUse: [{matcher: "^Bash$", hooks: [foreign]}], Stop: [{hooks: [foreign]}]}},
    };
    const want = {
      ".claude/settings.json": {PreToolUse: ["--claude "], PostToolUse: ["--claude-post"], PostToolUseFailure: ["--claude-post"],
        PermissionDenied: ["--claude-post"], PermissionRequest: ["--claude-prompted"], UserPromptSubmit: ["instructions.mjs\" --claude"]},
      ".codex/hooks.json": {PreToolUse: ["--codex "], PostToolUse: ["--codex-post"], UserPromptSubmit: ["instructions.mjs\" --codex"]},
    };
    for (const [agent, f] of [["claude", ".claude/settings.json"], ["codex", ".codex/hooks.json"]]) {
      const seed = JSON.stringify(seeds[f], null, 2) + "\n";
      put(f, seed);
      run("--agent", agent);
      const first = read(f), hooks = JSON.parse(first).hooks;
      for (const [ev, flags] of Object.entries(want[f]))
        ok(flags.every(fl => (hooks[ev] ?? []).some(g => g.hooks.some(h => h.command.includes(fl)))), `${agent}: ${ev} hook installed`);
      ok(commands(first).filter(c => c.includes(q(GATE))).every(c => c.includes("--mode shadow --allow off")) &&
         commands(first).filter(c => c.includes(q(INSTRUCTIONS))).every(c => c.endsWith("--mode shadow")), `${agent}: gate hooks carry --allow, instructions hooks do not`);
      ok(commands(first).filter(c => c === foreign.command).length === commands(seed).length, `${agent}: foreign hooks survive the install`);
      if (agent === "claude") {
        const pre = hooks.PreToolUse.find(g => g.hooks.some(h => h.command.includes(q(GATE))));
        const s = JSON.parse(first);
        ok(pre.matcher === "Bash|Task|Agent" && s.model === "opus" && s.env.FOO === "1" && s.permissions.allow[0] === "Bash(ls)" &&
           s.permissions.ask.includes("Bash(rm *)") && s.permissions.ask.some(r => r.startsWith("Edit(")), "claude: matcher, foreign settings and guard rules");
      } else ok(hooks.PreToolUse.some(g => g.matcher === "^(Bash|spawn_agent)$"), "codex: Bash and spawn_agent");
      run("--agent", agent);
      ok(read(f) === first, `${agent}: reinstall is byte-identical`);
      run("--agent", agent, "--mode", "enforce", "--allow", "on");
      ok(commands(read(f)).filter(c => c.includes(q(GATE))).every(c => c.includes("--mode enforce --allow on")) &&
         commands(read(f)).filter(c => c.includes(q(GATE))).length === commands(first).filter(c => c.includes(q(GATE))).length, `${agent}: mode and allow switch in place, no duplicates`);
      run("--agent", agent, "--uninstall");
      ok(JSON.stringify(JSON.parse(read(f))) === JSON.stringify(JSON.parse(seed)), `${agent}: uninstall leaves exactly the foreign settings`);
      run("--agent", agent, "--uninstall");
      ok(JSON.stringify(JSON.parse(read(f))) === JSON.stringify(JSON.parse(seed)), `${agent}: a second uninstall changes nothing`);
    }
    // the installed Claude hook really runs: the force-push canary is denied, even in shadow mode
    put(".claude/settings.json", "{}\n");
    run("--agent", "claude");
    const pre = commands(read(".claude/settings.json")).find(c => c.includes("--claude "));
    const r = spawnSync("/bin/sh", ["-c", pre], {encoding: "utf8", env: {...process.env, HOME: home, REFLEX_DATA_DIR: data},
      input: JSON.stringify({hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {command: "git push --force origin main"}, session_id: "s", cwd: home})});
    ok(JSON.parse(r.stdout || "{}").hookSpecificOutput?.permissionDecision === "deny", "claude: installed hook command denies the canary");
    const pr = commands(read(".claude/settings.json")).find(c => c.includes("--claude-prompted"));
    const r2 = spawnSync("/bin/sh", ["-c", pr], {encoding: "utf8", env: {...process.env, HOME: home, REFLEX_DATA_DIR: data},
      input: JSON.stringify({hook_event_name: "PermissionRequest", tool_name: "Bash", tool_input: {command: "touch x"}, session_id: "s", prompt_id: "p"})});
    ok(r2.stdout === "" && existsSync(join(data, "feedback.jsonl")) && /"event":"prompted"/.test(readFileSync(join(data, "feedback.jsonl"), "utf8")), "claude: PermissionRequest hook records and never answers");
    run("--agent", "claude", "--uninstall");
    // opencode, pi, omp: files of their own, next to other plugins / extensions
    put(".config/opencode/plugins/other.js", "export const Other = async () => ({});\n");
    run("--agent", "opencode");
    const oc = read(".config/opencode/plugins/reflex.js");
    ok(oc && !oc.includes("__REFLEX_") && oc.includes('"--allow", ALLOW') && oc.includes("chat.message") && oc.includes('input.tool === "task"'), "opencode: plugin filled, with gate, instructions and subgoals");
    run("--agent", "opencode");
    ok(read(".config/opencode/plugins/reflex.js") === oc, "opencode: reinstall is byte-identical");
    run("--agent", "opencode", "--uninstall");
    ok(read(".config/opencode/plugins/reflex.js") === null && read(".config/opencode/plugins/other.js") !== null, "opencode: uninstall removes only reflex.js");
    for (const a of ["pi", "omp"]) {
      const dir = `.${a}/agent/extensions`, ext = `${dir}/reflex.ts`, ctx = `${dir}/reflex-context.ts`;
      put(`${dir}/other.ts`, "export default function () {}\n");
      run("--agent", a);
      const e = read(ext);
      ok(e && !e.includes("__REFLEX_") && e.includes(`const AGENT = "${a}"`) && e.includes("before_agent_start") && e.includes("subgoalsOf") && read(ctx) === null,
         `${a}: extension filled with gate, instructions and subgoals; no context layer by default`);
      run("--agent", a);
      ok(read(ext) === e, `${a}: reinstall is byte-identical`);
      run("--agent", a, "--context");
      const c = read(ctx);
      ok(c && !c.includes("__REFLEX_"), `${a}: --context adds the context layer`);
      run("--agent", a);
      ok(read(ctx) === c && read(ext) === e, `${a}: a plain reinstall keeps the context layer, byte-identical`);
      run("--agent", a, "--no-context");
      ok(read(ctx) === null && read(ext) === e, `${a}: --no-context removes only the context layer`);
      run("--agent", a, "--context");
      run("--agent", a, "--uninstall");
      ok(read(ext) === null && read(ctx) === null && read(`${dir}/other.ts`) !== null, `${a}: uninstall removes both, keeps other extensions`);
    }
    // hermes: printed, never written
    const hm = run("--agent", "hermes", "--allow", "shadow");
    ok(/pre_tool_call:[\s\S]*matcher: "terminal"[\s\S]*fail_closed: true[\s\S]*matcher: "delegate_task"[\s\S]*post_tool_call:[\s\S]*"terminal\|delegate_task"[\s\S]*pre_llm_call:/.test(hm) &&
       /--hermes --mode shadow --allow shadow'/.test(hm) && /instructions\.mjs" --hermes --mode shadow'/.test(hm) && !existsSync(join(home, ".hermes")),
       "hermes: gate, subgoal and instructions blocks printed, nothing written");
    ok(/remove the reflex entries/.test(run("--agent", "hermes", "--uninstall")), "hermes: uninstall says what to remove");
    // router registration is printed for every agent, never applied
    const ro = run("--router");
    ok(["claude", "codex", "pi", "omp", "opencode", "hermes"].every(a => ro.includes(`## ${a}`)) && /Nothing was changed/.test(ro), "router: printed for every agent");
    // --keychain: recorded once in ~/.config/reflex/config.json and read by every gate process
    run("--agent", "hermes", "--keychain", "dev/my-typesafe-key");
    const seen = spawnSync(process.execPath, ["-e", `import(${JSON.stringify(GATE)}).then(g => console.log(g.CONFIG.keychain))`],
      {encoding: "utf8", env: {PATH: "/usr/bin:/bin", HOME: home}}).stdout.trim();
    ok(JSON.parse(read(".config/reflex/config.json")).keychain === "dev/my-typesafe-key" && seen === "dev/my-typesafe-key",
       `keychain: written to config.json and read by the gate (${seen})`);
    rmSync(join(home, ".config/reflex"), {recursive: true, force: true});
    const left = spawnSync("find", [home, "-type", "f", "-not", "-name", "*.bak-*", "-not", "-path", `${data}/*`], {encoding: "utf8"}).stdout.trim().split("\n").sort();
    ok(left.join() === [".config/opencode/plugins/other.js", ".omp/agent/extensions/other.ts", ".pi/agent/extensions/other.ts",
       ".claude/settings.json", ".codex/hooks.json"].map(f => join(home, f)).sort().join(), `nothing but foreign files and the emptied settings remain: ${left.join(" ")}`);
  } finally { rmSync(home, {recursive: true, force: true}); }
  console.log(process.exitCode ? "install selfcheck FAILED" : "install selfcheck OK");
  process.exit();
}

const which = opt("--agent", "claude");
const targets = which === "all" ? Object.keys(AGENTS).filter(a => has(AGENTS[a].bin)) : which.split(",");
for (const a of targets) if (!AGENTS[a]) throw new Error(`unknown agent ${a}; one of ${Object.keys(AGENTS).join(", ")}, all`);
for (const a of targets) console.log(`${a.padEnd(9)} ${UNINSTALL ? "uninstalled" : `installed (${MODE}, allow ${ALLOW})`}: ${AGENTS[a].run()}`);
if (KEYCHAIN && !UNINSTALL) {
  // Every Reflex process reads this, whichever agent started it; the environment still wins.
  const {USER_CONFIG_FILE} = await import("./gate.mjs");
  writeFile(USER_CONFIG_FILE, JSON.stringify({...readJson(USER_CONFIG_FILE), keychain: KEYCHAIN}, null, 2) + "\n");
  console.log(`keychain  ${USER_CONFIG_FILE}: the API key is read from Keychain item "${KEYCHAIN}"`);
}
