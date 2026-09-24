// Reflex extension for pi and oh-my-pi. The same file works in both; install.mjs copies it to
// ~/.pi/agent/extensions/reflex.ts and ~/.omp/agent/extensions/reflex.ts with the paths filled in.
//
// tool_call runs before every tool. For bash, Reflex decides: pass, ask (native confirm dialog),
// or deny (the call is blocked and the model sees the reason). Without a UI (print/json mode) an
// ask cannot be answered, so it blocks.
//
// before_agent_start runs once per user prompt: instructions.mjs picks the conditional instruction
// fragments that apply, and they are appended to that turn's system prompt, so they are back on
// every prompt where the condition holds and never lost to compaction. Any failure adds nothing.
import {spawn} from "node:child_process";

const GATE = process.env.REFLEX_GATE ?? "__REFLEX_GATE__";
const NODE = process.env.REFLEX_NODE ?? "__REFLEX_NODE__";
const MODE = process.env.REFLEX_MODE ?? "__REFLEX_MODE__";
const AGENT = "__REFLEX_AGENT__";
const INSTRUCTIONS = GATE.replace(/gate\.mjs$/, "instructions.mjs");

type Decision = {effective: "pass" | "ask" | "deny"; reason?: string};

function gate(flag: string, payload: unknown, signal?: AbortSignal, script = GATE): Promise<string> {
  return new Promise(resolve => {
    const p = spawn(NODE, [script, flag, "--mode", MODE], {signal, stdio: ["pipe", "pipe", "ignore"]});
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

// Paths the agent's recent tool calls touched (read, edit and write all take a path argument).
function recentFiles(ctx: any): string[] {
  const files: string[] = [];
  for (const e of (ctx.sessionManager?.getBranch?.() ?? []).slice(-40)) {
    const m = e?.type === "message" ? e.message : undefined;
    for (const c of m?.role === "assistant" ? m.content ?? [] : []) {
      const p = c?.type === "toolCall" ? c.arguments?.path ?? c.arguments?.file_path : undefined;
      if (typeof p === "string") files.push(p);
    }
  }
  return [...new Set(files.reverse())].slice(0, 10);
}

export default function (pi: any) {
  pi.on("before_agent_start", async (event: any, ctx: any) => {
    let r: {text?: string};
    try {
      r = JSON.parse(await gate("--select", {agent: AGENT, prompt: event.prompt, cwd: ctx.cwd,
                                             recent_files: recentFiles(ctx)}, ctx.signal, INSTRUCTIONS));
    } catch { return; }
    if (!r?.text) return;
    // pi passes the system prompt as a string, omp as an array of sections.
    const sp = event.systemPrompt;
    return {systemPrompt: Array.isArray(sp) ? [...sp, r.text] : `${sp ?? ""}\n\n${r.text}`};
  });

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
