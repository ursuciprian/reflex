// Reflex context layer for pi and oh-my-pi: Jev decides, per request, what the model sees.
// The same file works in both; `install.mjs --agent pi,omp --context` copies it to
// ~/.{pi,omp}/agent/extensions/reflex-context.ts with the path to context.mjs filled in.
//
//   tool_result   a large output -> one Jev choice per chunk (hide / short / long / full); the model
//                 gets the chosen lines, the full output goes to the chunk store
//   context       before each LLM call: on a new user request, one batched Jev call re-levels earlier
//                 tool results, and a cost model keeps the cached prompt prefix unless a rebuild pays
//   expand_chunk  tool: any hidden output comes back on request
//   /fresh <goal> a clean session that starts with only what Jev scores relevant to the goal
//
// It optimises, it does not gate: on any error the result or context is left as it was.
// Tool outputs (redacted) are sent to TypeSafe for judging; see docs/GUIDE.md "Data handling".
const CONTEXT = process.env.REFLEX_CONTEXT ?? "__REFLEX_CONTEXT__";
let core: Promise<any> | undefined;
const load = () => (core ??= import(CONTEXT));

// read/edit/write: the model edits against exact file text, so a shortened read would cost it an
// extra round trip. expand_chunk: the model asked for exactly this text.
const SKIP = new Set(["read", "edit", "write", "expand_chunk"]);

const sid = (ctx: any): string => ctx.sessionManager?.getSessionId?.() ?? "default";
const branchMessages = (ctx: any): any[] =>
  (ctx.sessionManager?.getBranch?.() ?? []).filter((e: any) => e?.type === "message").map((e: any) => e.message);

function lastText(ctx: any, role: string): string | undefined {
  const ms = branchMessages(ctx);
  for (let i = ms.length - 1; i >= 0; i--) {
    if (ms[i]?.role !== role) continue;
    const c = ms[i].content;
    const text = typeof c === "string" ? c : (c ?? []).filter((p: any) => p.type === "text").map((p: any) => p.text).join("\n");
    if (text.trim()) return text;
  }
}

export default function (pi: any) {
  const states = new Map<string, any>();   // per session: the current view, see assemble() in context.mjs

  pi.on("tool_result", async (event: any, ctx: any) => {
    const content = event.content ?? [];
    if (SKIP.has(event.toolName) || !content.length || content.some((c: any) => c.type !== "text")) return;
    try {
      const c = await load();
      const r = await c.ladder({text: content.map((p: any) => p.text).join("\n"), tool: event.toolName, input: event.input,
        request: lastText(ctx, "user"), intent: lastText(ctx, "assistant"), session: sid(ctx)});
      if (r) return {content: [{type: "text", text: r.text}]};
    } catch { /* fail open */ }
  });

  pi.on("context", async (event: any, ctx: any) => {
    try {
      const c = await load(), s = sid(ctx);
      if (!states.has(s)) states.set(s, {});
      const messages = await c.assemble(event.messages, states.get(s), {session: s});
      if (messages) return {messages};
    } catch { /* fail open */ }
  });

  pi.registerTool({
    name: "expand_chunk",
    label: "Expand chunk",
    description: "Return tool output that Reflex shortened or hid from your context. Use the id from a " +
      "[reflex: …] note; pass lines as \"a-b\" (1-based) to get only a range.",
    promptSnippet: "Get back tool output that Reflex shortened or hid (ids appear in [reflex: …] notes)",
    parameters: {type: "object", additionalProperties: false, required: ["id"], properties: {
      id: {type: "string", description: "Chunk id from a [reflex: …] note"},
      lines: {type: "string", description: "Optional 1-based line range, e.g. \"120-180\""},
    }},
    approval: "read",       // omp: a read-only tool, never needs an approval prompt
    loadMode: "essential",  // omp: listed up front, not behind tool discovery
    async execute(_id: string, params: any, _signal: any, _onUpdate: any, ctx: any) {
      const c = await load();
      return {content: [{type: "text", text: c.expandChunk(params.id, params.lines, sid(ctx))}], details: {}};
    },
  });

  pi.registerCommand("fresh", {
    description: "Start a clean session for <goal>, preloaded only with earlier context Jev scores relevant to it",
    handler: async (args: string, ctx: any) => {
      const goal = (args ?? "").trim();
      if (!goal) return ctx.ui?.notify?.("usage: /fresh <goal>", "warning");
      await ctx.waitForIdle?.();
      const c = await load();
      const r = await c.recall({goal, messages: branchMessages(ctx), session: sid(ctx)});
      if (!r) return ctx.ui?.notify?.("reflex: recall failed, session left as it is", "warning");
      // pi rebinds extensions to the new session and hands the new context to withSession; omp has
      // no withSession and keeps this extension's API bound, so pi.sendUserMessage works there.
      let sent = false;
      const res = await ctx.newSession({parentSession: ctx.sessionManager?.getSessionFile?.(),
        withSession: async (next: any) => { sent = true; await next.sendUserMessage(r.text); }});
      if (!res?.cancelled && !sent) pi.sendUserMessage(r.text);
    },
  });
}
