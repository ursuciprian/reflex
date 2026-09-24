# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Model routing](#model-routing)
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

About 60 checks, no network: read-only detection (including bypass attempts such as
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
  The patterns live in `setup/redact.json`, shared by the gate and the model router; its `corpus`
  lists inputs with their exact redacted outputs, and both selfchecks assert them.
- **TypeSafe** states it does not train on customer data; retention is covered by its
  [Data Processing Agreement](https://typesafe.ai/legal/data-processing), and zero data retention
  is available for enterprise customers ([legal](https://docs.typesafe.ai/legal)). Check this
  against your own data policy before rollout.
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

## Model routing

`routing/reflex_router.py` is a LiteLLM `CustomLogger` whose `async_pre_call_hook` runs before
LiteLLM's router picks a deployment, so changing `data["model"]` there changes which model group
serves the request. It only touches conversation calls (chat completions, `/v1/messages`,
Responses); embeddings, images and files pass untouched.

Per request:

1. **Family.** The requested model must be one of a family's `models` in `routing/policy.json`
   (a dated or suffixed id such as `claude-haiku-4-5-20251001` or `claude-opus-5[1m]` counts) or
   one of its `aliases` (a gateway's own router, e.g. `claude-auto`, `auto`). Any other model,
   including a newer one the policy does not list yet, is logged as `skip` and left alone. Routing
   never leaves the family: on a subscription gateway the clients' credentials are not
   interchangeable across providers.
2. **Floors, no model.** A credential shape anywhere in the conversation (the `shapes` of
   `setup/redact.json`, shared with the gate; tool results included) or a path matching
   `restricted_paths` (`.env`, `*.pem`, `*.tfvars`, `envs/prod`, `secret` …) makes the request at
   least `restricted`, whatever Jev says. Both checks run locally on the full text and full paths.
3. **Jev**, one call, cached for an hour by a hash of the question state. The state is the last
   thing the user typed (tool results and `<system-reminder>` blocks removed), the first 400
   characters of the system prompt, the tool names, the file paths mentioned anywhere in the
   conversation, and the turn number — all redacted. `paths_to_jev` decides how much of a path
   Jev sees: `shape_outside_repo` (default) sends paths inside the agent's working directory
   (read from Claude Code's "Primary working directory" or Codex's `<cwd>`) repo-relative, and any
   other path only as its file name with flags, e.g. `.../rds.tf [outside repo, sensitive]`;
   `shape` does that for every path, `full` sends paths as written. Questions
   (`routing/questions.json`):

   | Question | Type | Meaning |
   |---|---|---|
   | `sensitivity` | choice | public / application / restricted / proprietary |
   | `difficulty` | score 0–2 | small / medium / large model tier |
   | `needs_tools` | noul | does the answer need the offered tools |

   `restricted` is also taken when P(restricted) + P(proprietary) ≥ `restricted_at` (0.25), so a
   hesitant answer errs towards the safer pool.
4. **Pool and tier.** `sensitivity.pools` names the model tags a sensitivity requires: `public`
   any, `application` `first_party`, `restricted` and `proprietary` `first_party` + `frontier`.
   A model with `"tools": false` is skipped when tools are needed, and one with `max_context` is
   skipped when the estimated context is larger. The model is the cheapest eligible one at or
   above the difficulty tier. When it is the requested model under another name, the requested
   name is kept (`claude-opus-5[1m]` stays `claude-opus-5[1m]`).
5. **Key limits.** LiteLLM checks the requested model against the caller's key before pre-call
   hooks and does not check again after them, so the router runs LiteLLM's own check
   (`can_key_call_resolved_model`: key and team models, wildcards, access groups, team members,
   projects) on every candidate. A model the caller may not use is never chosen.
6. **No eligible model.** When nothing in the family is both eligible for the content and allowed
   for the key, `no_eligible.action` decides: `block` (default; enforce rejects the request with
   HTTP 400 and a message naming the family and sensitivity), `keep` (serve the requested model,
   log the violation) or `fallback_model` (serve `no_eligible.model`, if the key may call it;
   otherwise block). Shadow logs the action and never blocks. With the fallback answer below
   (restricted), a Jev outage blocks requests whose key has no first-party frontier model.
7. **Stickiness** (paper §II.A). Changing model mid-conversation makes the new model reprocess the
   whole context. Per conversation (LiteLLM's `litellm_session_id`, set from `x-*-session-id`
   headers and Claude Code's metadata; otherwise a hash of the system prompt and first message) the
   last model is kept, and a move to a cheaper model happens only when

   `(context × cache_read_factor + turn_tokens) × (old − new input price) × remaining_turns > context × new input price`

   With `remaining_turns: 1` the switch must pay for itself on the next turn: small conversations
   move down freely, large ones stay. Moving up a tier and moves forced by sensitivity always
   happen; a Responses call with `previous_response_id` never moves for cost. `context` is an
   estimate (characters / 4), logged as `ctx_tokens_est`.

| Mode (`REFLEX_ROUTING_MODE`) | Request | Decision |
|---|---|---|
| `off` | untouched | none |
| `shadow` (default) | keeps the requested model; no wait for Jev | made in a background task and logged |
| `enforce` | model rewritten, or blocked by `no_eligible` | made inline within `latency_budget_ms` (1.5 s) |

Reading the request (text, paths, secret shapes) runs inline in both modes: a few milliseconds,
about 50 ms per MB of conversation.

**Errors.** A Jev error, timeout or incomplete answer uses `fallback` (restricted, medium): safe,
not cheap. An internal error, including a missing `setup/redact.json`, keeps the requested model
and prints `reflex routing: …` to the proxy's stderr; a routing bug never fails a request.

**Log.** `routing.jsonl` in `REFLEX_DATA_DIR`: conversation hash, state hash, requested / chosen /
applied model, sensitivity, tier, Jev's raw answers, which floors fired, the stickiness reason,
the estimated context size (`ctx_tokens_est`), Jev's token usage, latency, `action` when no model
was eligible, and `violation: true` when the requested model was not eligible for the content. No
message text or paths are written; a Jev HTTP error is logged by status only. In shadow mode
`chosen` is what enforce would have used. The response's `model` field can still show the
requested name; the log has the one that served it.

**Test.**

```sh
python3 routing/reflex_router.py --selfcheck           # offline, Jev stubbed; part of npm test
python3 routing/reflex_router.py --check "Rotate the prod DB password in .env" --model claude-haiku-4-5
python3 routing/reflex_router.py --smoke               # 10 labelled prompts through live Jev
```

**Limits.** The Jev answer cache is per process: another worker asks Jev again (one call). The
model each conversation is on is per process too, unless the proxy shares a Redis with its
key cache (`litellm_settings.enable_redis_auth_cache: true` plus the proxy's Redis settings): then
it is also stored there (`reflex:model:<conversation hash>`, 24 h) and stickiness holds across
workers and restarts. Token counts are estimates (characters / 4). Prices in `policy.json` are
list prices you maintain. LiteLLM merges model-level guardrails for the requested model before
any pre-call hook runs, so a guardrail attached only to the routed-to model does not run; per-model
rate limits and budgets enforced by hooks that run before this one count the requested model.

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. Model routing is the first
of these ([above](#model-routing)); the same pieces fit LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
