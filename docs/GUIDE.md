# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Context layer (pi and oh-my-pi)](#context-layer-pi-and-oh-my-pi)
9. [Where this goes next](#where-this-goes-next)

## How a command is decided

Every shell command an agent wants to run reaches `gate.mjs` through that agent's pre-execution
hook (see the table in the README). Each adapter turns the agent's event into the same call —
`{agent, command, cwd, session_id, call_id, intent}` — and gets back
`{effective, decision, reason, source}`. The first step that reaches a decision wins:

1. **Read-only** — `readOnly()` recognises commands that only read: `ls`, `grep`, `git status`,
   `kubectl get`, `terraform plan`, `aws … describe-*`, `gh pr view`, `ssh host '<read-only>'`,
   `$(<read-only>)`, loops of reads, output to `/dev/null`, quoted heredocs fed to `cat`. Quoted
   text is treated as data (`jq '.a | .b'`, `grep -E 'x|y'`), except `$(…)` and backticks inside
   double quotes, which still run. It is conservative: anything it does not recognise goes on to
   the next step. → **pass**, not logged.
2. **Rules** (`rules.json`) — regular expressions over the command plus its context
   (`cwd=`, `aws_profile=`, `kube_context=`, `tf_workspace=`, `git_branch=`). A rule fires when all
   of its patterns match. Rules are **enforced in every mode**, because they are code, not a model.
   Shipped rules: `rm-root`, `prod-destroy`, `force-push-main` (deny); `tamper`, `destroy` (ask). Any mutating command that touches the Reflex checkout, its setup files or its logs is also an `ask`, wherever the repo was cloned.
3. **Fast lane** (`rules.json` → `pass`) — known-safe steps: builds, tests, `mkdir`, `git add/commit`,
   pushing a non-main branch. A command passes when every segment is read-only or matches a fast-lane
   pattern. → **pass**, logged.
4. **Jev** — the command (secrets redacted), its working directory, the environment context and
   the text the agent wrote right before this command and its last five commands (from the session
   transcript; if the command is not in the transcript yet, no intent is sent rather than an older one) are sent to
   TypeSafe with the six questions in `questions.json`. Answers are cached for 24 h per
   (command, cwd, environment, question-set version, model).
5. **Policy** (`policy.json`) — ordered gates over the answers; the first that fires wins,
   otherwise `default_outcome` (`pass`). If Jev fails or times out, the policy's `fallback` (`ask`)
   applies.

What happens with the decision depends on the mode:

| Mode | Rules | Jev + policy |
|---|---|---|
| `off` | nothing | nothing |
| `shadow` | enforced | runs in a detached background process; logged, never shown to the agent |
| `enforce` | enforced | `ask` → a human confirms (how depends on the agent, see the README table); `deny` → the command is blocked and the agent sees why |

`pass` is never turned into an approval: the gate stays silent and the agent's own permission
settings decide. Where an agent combines several hooks (Claude Code, Codex, Hermes), the most
restrictive decision wins, so Reflex composes with the hooks you already run.

**Custom integrations** use the same contract from any language:

```sh
echo '{"agent":"my-bot","command":"terraform apply","cwd":"/infra/prod"}' | node gate.mjs --decide
# {"effective":"ask","decision":"ask","reason":"reflex (jev): changes production","source":"jev","policy":"tool-gate-v2"}
echo '{"agent":"my-bot","call_id":"42","exit_code":0}' | node gate.mjs --record
```

## Testing

Four layers, cheapest first.

### 1. Offline self-checks — every change

```sh
npm test
```

`npm test` also runs `node context.mjs --selfcheck` (the context layer, against a fake Jev on
localhost). About 60 gate checks, no network: read-only detection (including bypass attempts such as
`rtk proxy rm`, `ssh h 'echo' '; rm -rf /'`, `$(security find-generic-password …)`), redaction,
every shipped rule, the fast lane, every policy gate, and the whole path for non-Jev commands.
Add an assertion whenever you change `readOnly()`, a rule or a gate.

### 2. One command by hand

```sh
node gate.mjs --check "kubectl --context prod-eu scale deploy/api --replicas=0 -n web"
node gate.mjs --check "helm upgrade api ./chart --kube-context prod-eu" --intent "Bumping the chart in dev"
node gate.mjs --check "terraform apply" --cwd ~/infra/envs/staging
```

Prints decision, rule, source, Jev's answers and the environment context it saw. The environment
comes from your shell (`AWS_PROFILE`, current kube context, `.terraform/environment`, git branch),
so run it from the same shell you start the agent from.

### 3. Golden set — every change to questions, policy or rules

```sh
npm run eval                     # all cases
node eval.mjs --only terraform   # a subset
```

`setup/tool-gate/golden.json` holds labelled commands with the outcome we *want* (`pass`, `ask`,
`deny`, or a list when more than one is acceptable). The eval runs them through the real gate
(cache off) and reports:

- **MISS** — a risky command got a softer outcome than wanted (exit code 1; treat as a blocker);
- **over** — stricter than wanted (friction; fix when it is common).

Current result: 44 cases, 0 misses, 0 over. Results are saved to `~/.local/state/reflex/eval-*.json`.
Run it in CI with `TYPESAFE_API_KEY` as a secret to guard policy changes.

**Grow the golden set from real traffic.** Every surprising decision in the trace becomes a case.

### 4. Live, in shadow mode

Install in shadow mode (see SETUP), work normally for a few days, then:

```sh
node report.mjs                  # counts by source, decision, mode; latency; tokens
node report.mjs --list ask       # every command that would have been asked
node report.mjs --list deny
```

Read the `ask` and `deny` lists. Each wrong one is either a golden-set case to add and a
threshold to move, or a rule or fast-lane pattern to add.

To test enforce behaviour without switching your whole setup, start one session with
`REFLEX_MODE=enforce claude` and ask the agent to run something the eval shows as `ask`.

## Rolling out: shadow, tune, enforce

1. **Shadow, about a week.** Nobody is slowed down.
2. **Tune.** Try a candidate policy against everything recorded, without spending tokens:

   ```sh
   cp setup/tool-gate/policy.json /tmp/candidate.json   # edit thresholds
   node report.mjs --policy /tmp/candidate.json         # "N of M Jev decisions change", pass -> ask: …
   ```

   Keep what reduces wrong asks without adding misses, then `npm run eval`.
3. **Enforce** with `node install.mjs --mode enforce`.
4. **Watch the ask outcomes.** In enforce mode `report.mjs` scores each emitted ask as approved
   (the command ran) or rejected. An ask that is nearly always approved is friction: tune it.
   A deny someone keeps working around is a missing fast-lane pattern.

## Changing behaviour

Everything lives in `setup/tool-gate/`. Bump the file's `version` on every change; it is stamped
on every log line, so any decision can be traced back to the exact rules and policy that made it.

**Is it a fact? Write a rule or a fast-lane pattern.** An account ID, a branch name, a `--force`
flag, a path under `envs/prod` — code decides these exactly and for free.

**Is it a judgment? Adjust a policy threshold or gate.** Gates look like:

```json
{"id": "prod", "label": "Production mutation?", "enabled_when": "$prodAlwaysAsks",
 "test": "env == 'production' and mutates >= 0.5", "outcome": "ask",
 "detail": "{env}, mutates {mutates}", "rule": "changes production"}
```

Conditions read answers by question id, `<id>.confidence`, params and flags (`$name`), numbers and
quoted strings, joined with `and` / `or`. A missing answer makes a condition false, never an error.

**Is Jev judging the wrong thing? Reword the question.** Write each question as one narrow
judgment with enough context to answer it, and put examples of what does *not* count in the
instructions; this is how the `exfil` question stopped firing on ordinary `aws` and `terraform`
calls. The `context` field in `questions.json` describes your environment: adapt the definition of
production to your naming. See TypeSafe's guidance on
[state](https://docs.typesafe.ai/concepts/state), [primitives](https://docs.typesafe.ai/primitives)
and [confidence](https://docs.typesafe.ai/confidence).

**Is the read-only list missing a command your team runs constantly?** Add it to `READ_ONLY` or
`READ_ONLY_SUB` in `gate.mjs`, with a self-check assertion for a harmless and a harmful variant.

## Metrics

`node report.mjs --push <pushgateway>` exports gauges for the report window:

| Metric | Labels |
|---|---|
| `reflex_decisions` | `source`, `decision`, `mode`, `user` |
| `reflex_latency_seconds` | `quantile` (0.5, 0.95, 0.99), `user` |
| `reflex_asks` | `resolution` (approved, rejected, pending), `user` |
| `reflex_replay_changes` | `user` — decisions the current policy file would flip |
| `reflex_input_tokens` | `user` |

`dashboards/reflex.json` shows them in Grafana.

## Data handling

- **What leaves the machine:** for commands that reach Jev only — the command with secrets
  redacted, the working directory path, environment names (AWS profile, region, kube context,
  terraform workspace, git branch), and the agent's last message and last five commands, also
  redacted and truncated. Read-only, rule and fast-lane commands never leave the machine.
- **Redaction** covers AWS keys, GitHub / GitLab / Slack / OpenAI-style tokens, bearer and basic
  auth headers, `*SECRET*=`, `*TOKEN*=`, `*PASSWORD*=`, `--password x`, credentials in URLs,
  private key blocks and JWTs. It is a pattern list, not DLP: extend it when you see a new shape.
- **TypeSafe** states it does not train on customer data; retention is covered by its
  [Data Processing Agreement](https://typesafe.ai/legal/data-processing), and zero data retention
  is available for enterprise customers ([legal](https://docs.typesafe.ai/legal)). Check this
  against your own data policy before rollout.
- **Context layer (opt-in, pi / omp).** When installed with `--context`, redacted samples of tool
  output (at most ~1,200 characters per chunk), the user's request and the agent's last message go
  to TypeSafe for relevance judging; `bin/reflex-review` and `context.mjs --bundle` send a redacted
  diff excerpt and matching lines. Full outputs stay local in `chunks/`. The reviewer command you
  configure receives the unredacted diff and related code, because it is your own model.
- **Locally**, logs contain the same redacted data and stay in `~/.local/state/reflex/`. Trace and
  feedback files rotate at 50 MB. Command output is never stored.

## Safety properties and limits

- The gate never emits `allow`. The worst a wrong Jev answer can do is add a prompt, or fail to
  add one; it cannot remove one that your permission rules require.
- A Jev failure or timeout gives the policy's `fallback` (`ask`) in enforce mode.
- An internal error (bad setup file, unreadable cache) returns the policy fallback (`ask`) in
  enforce mode and `pass` in shadow mode. Incomplete Jev answers count as an error, never as "no".
  The pi/omp and opencode adapters block when the gate cannot run at all in enforce mode.
- Rules and the read-only list are pattern matching, not a shell parser. They are designed to
  fail towards "ask Jev", not towards "pass", and the self-checks pin the known bypasses — but
  treat them as a strong filter, not a sandbox. Keep IAM, network controls, and least-privilege
  credentials: Reflex supplements them.
- Claude Code does not report a Bash exit code to hooks; Reflex records `ran` (exit 0) or
  `failed` from `PostToolUse` / `PostToolUseFailure`.
- Only shell tools are gated (`Bash`, pi/omp `bash`, opencode `bash`, Hermes `terminal`). File-edit
  tools, MCP tools, omp's `eval` and Hermes' `execute_code` go through each agent's own permissions.
- Codex and opencode hooks cannot open a prompt, so an `ask` blocks with a reason telling the agent
  to get your confirmation. Codex passes the session directory as `cwd`, not a per-command
  `workdir`. Codex hooks must be trusted in `/hooks` before they run.
- Environment context comes from the agent's process environment. A command that switches
  profile inline (`AWS_PROFILE=prod aws …`) is still seen, because the command text is judged; a
  profile changed by a previous command in a persistent shell is not.
- Jev adds ~0.7 s in enforce mode to each command that reaches it. On one engineer's heavy
  infrastructure history, about one in five commands never needed the API; the rest are mostly
  inline scripts and multi-step remote commands.

## Context layer (pi and oh-my-pi)

The gate decides whether a command may run. The context layer uses the same Jev client for a
different decision: what the model should *see* on each request. It follows *Jev Engineering for
Coding Agents*: make agent state explicit and let a fast judge pick, per query, how much of each
piece of context goes into the prompt, instead of compacting blindly when the window fills. It is an
optimisation, not a safety control, so **everything fails open**: on any error (Jev down, timeout,
incomplete answers, a store that cannot be written) the output or the message list is left exactly as
it was. Every decision is a line in `~/.local/state/reflex/context.jsonl` (kind, levels, cost-model
numbers, tokens, latency, error).

Only pi and oh-my-pi let an extension rewrite tool results and the messages sent to the model, so the
layer ships as a pi / omp extension, `adapters/pi-context.ts`, over a dependency-free core,
`context.mjs`. Install it with `node install.mjs --agent pi,omp --context`.

**Visibility ladder (§V), on `tool_result`.** An output of 200+ lines or 16 KB+ (bash, grep, find, ls,
custom tools; not `read` / `edit` / `write`, whose exact text the model edits against) is split along
its own structure (a grep hit list by file, anything else by blank-line sections) into at most 24
chunks. One Jev request carries one `choice` per chunk, **hide / short / long / full**, judged against
the user's current request and the agent's last message; Jev sees each chunk's start, end and the
lines that mention the request. Jev judges, it does not write text, so the levels are rendered by
code: *short* = first and last lines plus the lines that mention the request; *long* = the same with
three lines of context around each hit; *full* = the chunk as is. An unsure *hide* (probability under
0.5) becomes *short*. The model gets the kept lines, `… [lines a-b hidden] …` markers and one note
naming the chunk id. The full output is written to `chunks/<session>/<id>.txt` before anything is
replaced, and the **`expand_chunk`** tool (`{"id": …, "lines": "a-b"}`) returns it, so nothing is
deleted from state: a 2,400-line grep can be 12 hits for one question and come back whole for the
next. If the view would not save 20 %, the output is left alone.

**Per-request assembly and the cache decision (§V), on `context`.** pi and omp fire `context` before
every LLM call with a copy of the message list. When a new user request appears, one batched Jev
request rates up to 24 of the largest earlier tool results against it (one `choice` each) and asks one
`noul`: *is the context assembled for the previous request still the right context for this one?* The
proposed view replaces hidden and shortened results with stubs pointing at `expand_chunk`. Whether it
is applied is a cost decision, because providers cache the longest unchanged prompt prefix and
changing message *k* re-sends everything after *k* uncached:

```
keep    = H · T · r
rebuild = (T − S) · w + (H − 1) · (T − S) · r
T  tokens after the first message the new view changes      S  tokens the new view saves
r  cache-read price / uncached (REFLEX_CACHE_READ, 0.1)      w  cache-write price (REFLEX_CACHE_WRITE, 1.25)
H  LLM calls expected to reuse the prefix: calls per user request so far, clamped to 2..20
```

It rebuilds when `rebuild < keep`, or when Jev says the old context no longer fits (noul < 0.5),
because stale context costs answer quality, which the formula does not price. Otherwise the previous
view is kept. Between requests the chosen view is re-applied on every call from memoised stubs, so
the prefix stays byte-identical and cacheable, and no Jev call is made until the next user request.
Tokens are estimated as characters / 4, which is enough for a comparison.

**Restart with recall (§II.E), `/fresh <goal>`.** Rates the last 24 messages of the branch (user
requests, assistant replies, tool results) against the new goal, starts a new session and sends the
goal with only the relevant items, each at its level and with its `expand_chunk` id; the rest is
left behind but still expandable. If Jev fails, the session is left as it is.

**Shared retrieval for background tasks (§X), `node context.mjs --bundle`.** Given a change
(`git diff <base>`), it collects the names defined on changed lines and in hunk context, plus the
changed files' basenames, looks each up once with `git grep -w`, rates up to 24 candidate files with
one Jev `choice` each (*irrelevant / related / essential*) and writes a bundle JSON: diff, changed
files, symbols, related files with their matching lines, essential files in full, skipped files,
tokens. Without Jev every candidate is kept as *related*, marked `judged: false`. Any read-only
background task (cross-model review, eval generation, a progress page) can consume the bundle instead
of searching again; `bin/reflex-review` is the example:

```sh
bin/reflex-review --reviewer "codex exec -s read-only -" --goal "normalise case in parseThing" &
REFLEX_REVIEWER="claude -p --permission-mode plan" bin/reflex-review --base origin/main &
```

It sends a review prompt built from the bundle to the reviewer command on stdin and saves the output
in `~/.local/state/reflex/reviews/`. The reviewer is responsible for staying read-only; pick its
read-only mode as above.

**Verified vs experimental.**

| Piece | Status |
|---|---|
| Event and API surface | Read in the installed sources. pi 0.84.2, `dist/core/extensions/types.d.ts`: `tool_result` returns `{content, details, isError}`, `context` returns `{messages}`, `registerTool`, `registerCommand`, `ctx.newSession({withSession})`. omp 18.1.17, `src/extensibility/extensions/types.ts`: the same events, `newSession` without `withSession`, tool `approval` and `loadMode`; `runner.ts`: `emitContext`, 30 s handler budget; `sdk.ts`: `transformContext` calls `emitContext` before each LLM call. Both accept plain JSON Schema tool parameters (pi-ai / omp pi-ai `validateToolArguments`) |
| Ladder, store, `expand_chunk`, assembly, cache decision, `/fresh`, bundle, reviewer | `node context.mjs --selfcheck`: the real extension driven with a fake `pi`, fake events and a fake Jev server on localhost, including every fail-open path |
| Extension loads in the real agents | `pi -e` and `omp -e` load it without errors; in omp `expand_chunk` is in the provider request's tool list |
| Live Jev | `node context.mjs --smoke`: a 245-line grep of this repo against a timeout question: 84 % hidden, ~6k input tokens, 0.9 s |
| Quality of the choices over real sessions, the cost-model parameters, `/fresh` in a live session | **Experimental.** Not measured yet: read `context.jsonl` and tune. In the smoke Jev kept the retry code but hid the chunk holding the `timeoutMs` default. That is recoverable with `expand_chunk`, and it is why this layer is opt-in |

Limits: only tool results are levelled, not tool-call inputs or reasoning (providers require some
reasoning blocks to be replayed unchanged); outputs already cut by the ladder are re-levelled as they
stand, not from the stored full text; the chunk store is never pruned; the bundle's symbol search is
name matching, not a language index; the view lives in memory, so a resumed session starts with a
fresh decision.

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. The same pieces fit model routing
(a `choice` of small / medium / large before a request reaches the LLM gateway), LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
