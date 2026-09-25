// Reflex plugin for opencode (https://opencode.ai/docs/plugins).
// Installed by `node install.mjs --agent opencode` into ~/.config/opencode/plugins/reflex.js.
//
// opencode 1.4 plugins can block a tool call (throw) but cannot open a permission prompt, so an
// "ask" blocks with a reason that tells the agent to get the user's confirmation first.
//
// Conditional instructions: chat.message sees each new user message and picks the fragments that
// apply; experimental.chat.system.transform appends them to the system prompt of every model call
// in that session until the next user message, so compaction cannot drop them.
import {spawnSync} from "node:child_process";

const GATE = process.env.REFLEX_GATE ?? "__REFLEX_GATE__";
const NODE = process.env.REFLEX_NODE ?? "__REFLEX_NODE__";
const MODE = process.env.REFLEX_MODE ?? "__REFLEX_MODE__";
const ALLOW = process.env.REFLEX_ALLOW ?? "__REFLEX_ALLOW__";
const INSTRUCTIONS = GATE.replace(/gate\.mjs$/, "instructions.mjs");
const selected = new Map();   // sessionID -> injected text. ponytail: never pruned; one short string per session.

function gate(flag, payload, script = GATE) {
  const args = script === GATE ? [script, flag, "--mode", MODE, "--allow", ALLOW] : [script, flag, "--mode", MODE];
  const r = spawnSync(NODE, args, {input: JSON.stringify(payload), encoding: "utf8", timeout: 10000});
  return r.stdout;
}

export const Reflex = async ({directory}) => ({
  "chat.message": async (input, output) => {
    const prompt = (output.parts ?? []).filter(p => p.type === "text" && !p.synthetic).map(p => p.text).join("\n");
    if (!prompt.trim()) return;
    let r = null;
    try { r = JSON.parse(gate("--select", {agent: "opencode", prompt, cwd: directory, session_id: input.sessionID}, INSTRUCTIONS)); }
    catch { /* instructions are advisory: nothing is injected */ }
    selected.set(input.sessionID, r?.text ?? "");
  },
  "experimental.chat.system.transform": async (input, output) => {
    const text = input.sessionID && selected.get(input.sessionID);
    if (text) output.system.push(text);
  },
  "tool.execute.before": async (input, output) => {
    if (input.tool === "task") {
      // Subgoal dedup: a subagent asked to repeat work already delegated in this session.
      const a = output.args ?? {};
      if (!a.prompt || a.task_id) return;   // task_id resumes earlier work on purpose
      let d;
      try {
        d = JSON.parse(gate("--decide", {agent: "opencode", subgoal: [a.subagent_type && `agent: ${a.subagent_type}`, a.description, a.prompt]
          .filter(Boolean).join("\n"), cwd: directory, session_id: input.sessionID, call_id: input.callID}));
      } catch { return; }   // dedup saves work; it never blocks when the gate cannot run
      if (d.effective === "deny") throw new Error(d.reason);
      return;
    }
    if (input.tool !== "bash") return;
    let d;
    try {
      d = JSON.parse(gate("--decide", {agent: "opencode", command: output.args?.command,
        cwd: output.args?.workdir || directory, session_id: input.sessionID, call_id: input.callID}));
    } catch {
      // The gate itself failed. Only block when enforcing; shadow mode must never get in the way.
      if (MODE === "enforce") throw new Error("reflex: gate unavailable, blocked (fail-closed)");
      return;
    }
    // pass and allow both run: opencode has no prompt of its own here to skip.
    if (d.effective === "deny") throw new Error(d.reason);
      if (d.effective === "ask") throw new Error(`${d.reason}. This plugin cannot open an approval dialog. The user can review and run the exact command with reflex run in their own terminal (include --cwd). A chat confirmation does not unblock this plugin; do not retry or disable it.`);
  },
  "tool.execute.after": async (input, output) => {
    // A task that ran is a launched subgoal: dedup offers only those.
    if (input.tool === "task") return void gate("--record", {agent: "opencode", event: "ran", session_id: input.sessionID, call_id: input.callID});
    if (input.tool !== "bash") return;
    gate("--record", {agent: "opencode", event: "ran", session_id: input.sessionID, call_id: input.callID,
                      exit_code: output?.metadata?.exit ?? null});
  },
});
