// Reflex plugin for opencode (https://opencode.ai/docs/plugins).
// Installed by `node install.mjs --agent opencode` into ~/.config/opencode/plugins/reflex.js.
//
// opencode 1.4 plugins can block a tool call (throw) but cannot open a permission prompt, so an
// "ask" blocks with a reason that tells the agent to get the user's confirmation first.
import {spawnSync} from "node:child_process";

const GATE = process.env.REFLEX_GATE ?? "__REFLEX_GATE__";
const NODE = process.env.REFLEX_NODE ?? "__REFLEX_NODE__";
const MODE = process.env.REFLEX_MODE ?? "__REFLEX_MODE__";

function gate(flag, payload) {
  const r = spawnSync(NODE, [GATE, flag, "--mode", MODE], {input: JSON.stringify(payload), encoding: "utf8", timeout: 10000});
  return r.stdout;
}

export const Reflex = async ({directory}) => ({
  "tool.execute.before": async (input, output) => {
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
    if (d.effective === "deny") throw new Error(d.reason);
    if (d.effective === "ask") throw new Error(`${d.reason}. Needs human approval: ask the user to confirm before running it.`);
  },
  "tool.execute.after": async (input, output) => {
    if (input.tool !== "bash") return;
    gate("--record", {agent: "opencode", event: "ran", session_id: input.sessionID, call_id: input.callID,
                      exit_code: output?.metadata?.exit ?? null});
  },
});
