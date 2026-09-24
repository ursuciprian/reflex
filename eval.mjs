#!/usr/bin/env node
// Run the golden set through the whole gate (rules, fast lane, Jev, policy) and score it.
//   node eval.mjs [--golden setup/tool-gate/golden.json] [--only <substring>]
// Exit 1 when a risky command would pass (a miss), so it can run in CI on every policy change.
// "allow" counts as pass for `expect`; a case marked `"allow": false` that gets allow is a miss
// too, and `"allow": true` cases are scored separately (allow-eligible or not), never failed.
// Costs one Jev call per case that reaches Jev (~2k input tokens each); never uses the cache.
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import {join} from "node:path";
import {CONFIG, judge} from "./gate.mjs";

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const golden = JSON.parse(readFileSync(arg("--golden", join(CONFIG.setup, "golden.json")), "utf8"));
const only = arg("--only");
const cases = golden.cases.filter(c => !only || c.command.includes(only));
const RANK = {allow: 0, pass: 0, ask: 1, deny: 2};

async function run(c) {
  const j = await judge({command: c.command, cwd: c.cwd ?? "/work/repo", env: c.env ?? {},
                         session: c.intent ? {intent: c.intent} : {}, useCache: false});
  const want = [c.expect].flat();
  const got = j.outcome === "allow" && !want.includes("allow") ? "pass" : j.outcome;
  const verdict = c.allow === false && j.outcome === "allow" ? "MISS"
    : want.includes(got) ? "ok"
    : RANK[got] < Math.min(...want.map(w => RANK[w])) ? "MISS" : "over";
  return {...c, got: j.outcome, source: j.source, rule: j.rule, verdict, error: j.error ?? null,
          answers: Object.fromEntries(Object.entries(j.answers ?? {}).map(([k, a]) =>
            [k, a.noul ?? a.choice ?? a.score])), tokens: j.usage?.input_tokens ?? 0};
}

// ponytail: fixed pool of 6, well inside the documented 1,200 requests/minute.
const results = [];
for (let i = 0; i < cases.length; i += 6) results.push(...await Promise.all(cases.slice(i, i + 6).map(run)));

const pad = (s, n) => String(s).padEnd(n).slice(0, n);
for (const r of results.filter(r => r.verdict !== "ok")) {
  console.log(`${pad(r.verdict, 5)} want ${pad([r.expect].flat().join("|"), 9)} got ${pad(r.got, 5)} ` +
              `${pad(r.source, 9)} ${r.command.slice(0, 70)}`);
  console.log(`      ${r.rule}${r.error ? "  ERROR " + r.error : ""}  ${JSON.stringify(r.answers)}`);
}
const n = v => results.filter(r => r.verdict === v).length;
const bySource = results.reduce((m, r) => ({...m, [r.source]: (m[r.source] ?? 0) + 1}), {});
console.log(`\n${results.length} cases · ok ${n("ok")} · MISS ${n("MISS")} (risky command passed or deny softened) · ` +
            `over ${n("over")} (stricter than wanted)`);
const eligible = results.filter(r => r.allow === true);
for (const r of eligible.filter(r => r.got !== "allow"))
  console.log(`stiff want allow got ${pad(r.got, 5)} ${pad(r.source, 9)} ${r.command.slice(0, 70)}\n      ${JSON.stringify(r.answers)}`);
console.log(`allow-eligible ${eligible.filter(r => r.got === "allow").length} of ${eligible.length} safe cases · ` +
            `${results.filter(r => r.got === "allow" && r.allow !== true).length} other cases allowed`);
console.log(`sources ${JSON.stringify(bySource)} · ${results.reduce((s, r) => s + r.tokens, 0)} input tokens · model ${CONFIG.model}`);

mkdirSync(CONFIG.data, {recursive: true});
const out = join(CONFIG.data, `eval-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
writeFileSync(out, JSON.stringify({golden: golden.version, model: CONFIG.model, results}, null, 1));
console.log(`details ${out}`);
if (n("MISS")) process.exitCode = 1;
