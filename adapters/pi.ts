// Reflex extension for pi and oh-my-pi. The same file works in both; install.mjs copies it to
// ~/.pi/agent/extensions/reflex.ts and ~/.omp/agent/extensions/reflex.ts with the paths filled in.
//
// tool_call runs before every tool. For bash, Reflex decides: pass, ask (native confirm dialog),
// or deny (the call is blocked and the model sees the reason). Without a UI (print/json mode) an
// ask cannot be answered, so it blocks.
import {spawn} from "node:child_process";

const GATE = process.env.REFLEX_GATE ?? "__REFLEX_GATE__";
const NODE = process.env.REFLEX_NODE ?? "__REFLEX_NODE__";
const MODE = process.env.REFLEX_MODE ?? "__REFLEX_MODE__";
const AGENT = "__REFLEX_AGENT__";

type Decision = {effective: "pass" | "ask" | "deny"; reason?: string};

function gate(flag: string, payload: unknown, signal?: AbortSignal): Promise<string> {
  return new Promise(resolve => {
    const p = spawn(NODE, [GATE, flag, "--mode", MODE], {signal, stdio: ["pipe", "pipe", "ignore"]});
    let out = "";
    const t = setTimeout(() => p.kill("SIGKILL"), 20_000);   // omp gives a handler 30 s
    p.stdout.on("data", d => (out += d));
    p.on("error", () => { clearTimeout(t); resolve(""); });
    p.on("close", () => { clearTimeout(t); resolve(out); });
    p.stdin.end(JSON.stringify(payload));
  });
}

function lastAssistantText(ctx: any): string | undefined {
  const branch = ctx.sessionManager?.getBranch?.() ?? [];
  for (let i = branch.length - 1; i >= 0; i--) {
    const m = branch[i]?.type === "message" ? branch[i].message : undefined;
    if (m?.role === "assistant") {
      const text = (m.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
      if (text.trim()) return text;
    }
  }
}

export default function (pi: any) {
  pi.on("tool_call", async (event: any, ctx: any) => {
    if (event.toolName !== "bash" || !event.input?.command) return;
    let d: Decision;
    try {
      d = JSON.parse(await gate("--decide", {
        agent: AGENT, command: event.input.command, cwd: event.input.cwd ?? ctx.cwd,
        call_id: event.toolCallId, intent: lastAssistantText(ctx),
      }, ctx.signal));
    } catch {
      // The gate itself failed. Only block when enforcing; shadow mode must never get in the way.
      return MODE === "enforce" ? {block: true, reason: "reflex: gate unavailable, blocked (fail-closed)"} : undefined;
    }
    if (d.effective === "deny") return {block: true, reason: d.reason};
    if (d.effective === "ask") {
      if (!ctx.hasUI) return {block: true, reason: `${d.reason}. Needs human approval and there is no UI to ask.`};
      const ok = await ctx.ui.confirm("Reflex: run this command?", `${event.input.command}\n\n${d.reason}`);
      if (!ok) return {block: true, reason: `${d.reason}. The user declined.`};
    }
  });

  pi.on("tool_result", async (event: any) => {
    if (event.toolName !== "bash") return;
    const text = (event.content ?? []).map((c: any) => c.text ?? "").join("");
    const exit = typeof event.details?.exitCode === "number" ? event.details.exitCode            // omp
      : event.isError ? Number(/Command exited with code (\d+)/.exec(text)?.[1] ?? -1) : 0;      // pi
    gate("--record", {agent: AGENT, event: "ran", call_id: event.toolCallId, exit_code: exit});
  });
}
