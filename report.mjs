#!/usr/bin/env node
// What the gate has been doing, and what a policy change would do. No API calls.
//
//   node report.mjs                         summary of the last 7 days
//   node report.mjs --since 30              ... of the last 30 days
//   node report.mjs --list ask              the commands that got "ask" (or pass / deny)
//   node report.mjs --policy candidate.json replay stored answers through another policy
//   node report.mjs --push http://localhost:9091   also push metrics to a Prometheus Pushgateway
import {existsSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {CONFIG} from "./gate.mjs";
import {compile} from "./policy.mjs";

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const rows = f => existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
const since = Date.now() - Number(arg("--since", 7)) * 864e5;
const trace = rows(join(CONFIG.data, "trace.jsonl")).filter(r => Date.parse(r.ts) >= since);
const ran = new Set(rows(join(CONFIG.data, "feedback.jsonl")).filter(r => r.event !== "denied").map(r => r.call_id ?? r.tool_use_id));
const policy = compile(JSON.parse(readFileSync(arg("--policy", join(CONFIG.setup, "policy.json")), "utf8")));

const count = (list, key) => list.reduce((m, r) => { const k = key(r); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const q = (xs, p) => xs.length ? xs[Math.min(xs.length - 1, Math.floor(p * xs.length))] : 0;
const jev = trace.filter(r => r.source === "jev");
const lat = jev.map(r => r.latency_s).sort((a, b) => a - b);
// An emitted ask is approved when the command then ran; rejected when it did not within 10 minutes.
const asks = trace.filter(r => r.emitted === "ask");
const resolved = count(asks, r => ran.has(r.call_id ?? r.tool_use_id) ? "approved"
                                 : Date.now() - Date.parse(r.ts) > 6e5 ? "rejected" : "pending");
// Replay: stored Jev answers through the chosen policy; rule and fast-lane decisions are code.
const replayed = jev.map(r => ({r, now: policy.decide(r.answers, policy.values()).outcome}));
const changed = replayed.filter(x => x.now !== x.r.decision);

const list = arg("--list");
if (list) {
  for (const r of trace.filter(r => r.decision === list)) {
    console.log(`${r.ts.slice(0, 16)}  ${(r.source ?? "").padEnd(9)} ${(r.rule ?? "").slice(0, 44).padEnd(44)}  ${r.state?.call?.command?.slice(0, 90)}`);
  }
  process.exit(0);
}

console.log(`reflex · last ${arg("--since", 7)} days · ${trace.length} judged commands (read-only ones are not logged)`);
console.log(`  by source    ${JSON.stringify(count(trace, r => r.source))}`);
console.log(`  by decision  ${JSON.stringify(count(trace, r => r.decision))}`);
console.log(`  by mode      ${JSON.stringify(count(trace, r => r.mode))}`);
console.log(`  jev latency  p50 ${q(lat, .5)}s · p95 ${q(lat, .95)}s · p99 ${q(lat, .99)}s · fallbacks ${trace.filter(r => r.source === "fallback").length}`);
console.log(`  tokens       ${trace.reduce((s, r) => s + (r.usage?.input_tokens ?? 0), 0)} input`);
console.log(`  emitted asks ${JSON.stringify(resolved)}   (enforce mode only; approved = a human let it run)`);
console.log(`  replay       ${changed.length} of ${jev.length} Jev decisions change under ${policy.version}`);
for (const [k, v] of Object.entries(count(changed, x => `${x.r.decision} -> ${x.now}`))) console.log(`                 ${k}: ${v}`);

const push = arg("--push");
if (push) {
  const lines = [
    "# TYPE reflex_decisions gauge",
    ...Object.entries(count(trace, r => `${r.source}|${r.decision}|${r.mode}`)).map(([k, v]) => {
      const [source, decision, mode] = k.split("|");
      return `reflex_decisions{source="${source}",decision="${decision}",mode="${mode}"} ${v}`;
    }),
    "# TYPE reflex_latency_seconds gauge",
    ...[0.5, 0.95, 0.99].map(p => `reflex_latency_seconds{quantile="${p}"} ${q(lat, p)}`),
    "# TYPE reflex_asks gauge",
    ...Object.entries(resolved).map(([k, v]) => `reflex_asks{resolution="${k}"} ${v}`),
    "# TYPE reflex_replay_changes gauge",
    `reflex_replay_changes ${changed.length}`,
    "# TYPE reflex_input_tokens gauge",
    `reflex_input_tokens ${trace.reduce((s, r) => s + (r.usage?.input_tokens ?? 0), 0)}`,
  ];
  const user = encodeURIComponent(process.env.USER ?? "unknown");
  const r = await fetch(`${push.replace(/\/$/, "")}/metrics/job/reflex/user/${user}`,
                        {method: "PUT", body: lines.join("\n") + "\n"});
  console.log(`  pushed       ${r.status} ${push}`);
}
