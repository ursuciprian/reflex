#!/usr/bin/env node
// What the gate has been doing, and what a policy change would do. No API calls.
//
//   node report.mjs                         summary of the last 7 days
//   node report.mjs --since 30              ... of the last 30 days
//   node report.mjs --list ask              the commands that got "ask" (or pass / deny)
//   node report.mjs --policy candidate.json replay stored answers through another policy
//   node report.mjs --push http://localhost:9091   also push metrics to a Prometheus Pushgateway
//   node report.mjs --calibration           how well blast / mutates predict your approvals (ECE)
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
const verdict = r => ran.has(r.call_id ?? r.tool_use_id) ? "approved" : Date.now() - Date.parse(r.ts) > 6e5 ? "rejected" : "pending";
const resolved = count(asks, verdict);
// Replay: stored Jev answers through the chosen policy; rule and fast-lane decisions are code.
// Policy is compared with policy: the logged policy_decision is what the policy said before
// REFLEX_ALLOW and the allow guards applied (older rows only have the decision).
const replayed = jev.map(r => ({r, now: policy.decide(r.answers, policy.values()).outcome}));
const changed = replayed.filter(x => x.now !== (x.r.policy_decision ?? x.r.decision));

// Calibration: the Jev-judged commands a human ruled on, approved when the command then ran:
// asks Reflex emitted in enforce mode, and commands allow would have let through (logged
// would_allow, or allow on replay) in Claude Code, the one agent where a pass still meets a
// prompt. ponytail: a pass its allowlist or permission mode let through also counts as approved;
// a PermissionRequest signal would tell a real prompt apart. Commands actually allowed ran
// without a human, so they carry no label.
const labelled = replayed.filter(({r, now}) => r.emitted !== "allow" && r.answers?.blast?.score != null &&
    ((r.emitted === "ask" && r.mode === "enforce") || (r.agent === "claude-code" && (now === "allow" || r.decision === "would_allow"))))
  .map(({r}) => ({blast: r.answers.blast.score, conf: r.answers.blast.confidence ?? 0, mutates: r.answers.mutates?.noul, v: verdict(r)}))
  .filter(x => x.v !== "pending").map(x => ({...x, ok: x.v === "approved" ? 1 : 0}));
const rate = xs => xs.length ? `${xs.filter(x => x.ok).length}/${xs.length} (${Math.round(100 * xs.filter(x => x.ok).length / xs.length)}%)` : "-";
const bucket = (xs, f, edges) => edges.slice(0, -1).map((lo, i) => `${lo}-${edges[i + 1]} ${rate(xs.filter(x => f(x) >= lo && (f(x) < edges[i + 1] || i === edges.length - 2)))}`).join(" · ");
// The band covering the most commands you approved at least 95% of (10+ labelled); among equals
// the tightest, so no threshold is recommended beyond where there is data.
// ponytail: a fixed grid and one threshold pair; per-agent or per-env thresholds when the data allows.
const MIN_N = 10;
const bands = [0.5, 0.8, 1, 1.2, 1.5, 2].flatMap(b => [0.5, 0.6, 0.7, 0.8, 0.9].map(c => {
  const xs = labelled.filter(x => x.blast <= b && x.conf >= c);
  return {b, c, n: xs.length, ok: xs.filter(x => x.ok).length};
})).filter(x => x.n >= MIN_N && x.ok / x.n >= 0.95).sort((x, y) => y.n - x.n || x.b - y.b || y.c - x.c);

if (process.argv.includes("--calibration")) {
  // Expected calibration error of each answer read as an approval probability: 1 - blast/3 and
  // 1 - mutates. ponytail: 5 equal-width bins; a reliability curve per question needs more data.
  const NEED = 20;
  console.log(`calibration · ${labelled.length} labelled commands (approved = it ran after the ask, or after Claude Code's own prompt or allowlist)`);
  if (labelled.length < NEED) {
    console.log(`  not enough data: ${labelled.length} labelled, need ${NEED}. Run in enforce mode, or with REFLEX_ALLOW=shadow, and come back.`);
    process.exit(0);
  }
  const clamp = v => Math.min(1, Math.max(0, v));
  for (const [name, p] of [["blast", x => clamp(1 - x.blast / 3)], ["mutates", x => clamp(1 - (x.mutates ?? 0.5))]]) {
    let ece = 0;
    const bins = [];
    for (let i = 0; i < 5; i++) {
      const xs = labelled.filter(x => Math.min(4, Math.floor(p(x) * 5)) === i);
      if (!xs.length) continue;
      const pm = xs.reduce((s, x) => s + p(x), 0) / xs.length, ym = xs.reduce((s, x) => s + x.ok, 0) / xs.length;
      ece += xs.length / labelled.length * Math.abs(pm - ym);
      bins.push(`${(i / 5).toFixed(1)}-${((i + 1) / 5).toFixed(1)} said ${pm.toFixed(2)} saw ${ym.toFixed(2)} (n ${xs.length})`);
    }
    console.log(`  ${name.padEnd(8)} ECE ${ece.toFixed(3)}   ${bins.join(" · ")}`);
  }
  process.exit(0);
}

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
console.log(`  allow        ${JSON.stringify(count(trace.filter(r => ["allow", "would_allow"].includes(r.decision)), r => r.decision))}   (REFLEX_ALLOW ${CONFIG.allow})`);
console.log(`  calibration  ${labelled.length} labelled (asks in enforce mode + would-be allows in Claude Code; approved = it ran)`);
if (labelled.length) {
  console.log(`    by blast       ${bucket(labelled, x => x.blast, [0, 0.5, 1, 1.5, 2, 3])}`);
  console.log(`    by confidence  ${bucket(labelled, x => x.conf, [0, 0.5, 0.7, 0.85, 1])}`);
}
const best = bands[0], pv = policy.values();
console.log(best
  ? `    recommend      of ${best.n} with blast <= ${best.b} and confidence >= ${best.c}, you approved ${Math.round(100 * best.ok / best.n)}%` +
    ` -> allowBlastMax ${best.b}, allowConfidence ${best.c} (now ${pv.allowBlastMax}, ${pv.allowConfidence})`
  : `    recommend      not enough data: no band with ${MIN_N}+ labelled commands approved 95%+ of the time; keep ${pv.allowBlastMax} / ${pv.allowConfidence}`);

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
