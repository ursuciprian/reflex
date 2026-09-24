# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Conditional instructions](#conditional-instructions)
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
- **TypeSafe** states it does not train on customer data; retention is covered by its
  [Data Processing Agreement](https://typesafe.ai/legal/data-processing), and zero data retention
  is available for enterprise customers ([legal](https://docs.typesafe.ai/legal)). Check this
  against your own data policy before rollout.
- **Conditional instructions** send, per prompt that has undecided fragments: the prompt (redacted,
  first 4,000 characters), the working directory, recently touched file paths, the last five
  commands (redacted), and each fragment's `when` condition. The fragment bodies stay local.
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

## Conditional instructions

`AGENTS.md` and `CLAUDE.md` are loaded in full at the start of a session. Guidance for billing, the
front end and Terraform all sits in the context for a typo fix, and compaction can drop any of it
halfway through a task. `instructions.mjs` loads each piece of guidance only while its condition
holds, and adds it again on every prompt where the condition still holds.

**A fragment** is a markdown file with front-matter:

```markdown
---
when: the task involves billing, payments, invoices, refunds, subscriptions or money amounts
paths: ["billing/**"]          # optional globs, matched against files named in the prompt or recently touched
keywords: [stripe, ledger]     # optional whole words in the prompt
id: billing                    # optional; defaults to the file name
---
- Money is integer minor units (`amount_cents`); never floats.
- ...
```

**Where fragments live:** `.reflex/instructions/*.md` in the working directory and in each parent
directory up to the repo root (the nearest one holding `.git`), then
`~/.config/reflex/instructions/*.md` (or `$XDG_CONFIG_HOME/reflex/instructions`). Directories above
the repo root are never read; outside a repo only the working directory is. Only regular files up
to 64 KB are read, so a symlink to a file elsewhere is skipped.
When two fragments share an id, the one nearest the working directory wins, so a repo can override a
personal fragment. `examples/instructions/repo/` shows the layout with three fragments.

**Per prompt:**

1. **Deterministic.** A fragment is selected, with no API call, when one of its `paths` globs
   matches a file named in the prompt or one the agent touched recently. Recent files come from
   `file_path` in the Claude Code transcript, `apply_patch` headers in the Codex transcript, and the
   `path` argument of tool calls in pi/omp. A fragment is also selected when one of its `keywords`
   appears in the prompt. Globs match any trailing part of a path, so `web/**/*.tsx` matches
   `/home/me/repo/web/src/App.tsx`.
2. **Jev.** Every other fragment that has a `when` gets one `noul` question: *does this condition hold
   for this request and the current work?* All the questions go in **one** request. The state is the
   redacted prompt, the working directory, recent files and the last five commands. A fragment is
   selected at `p >= REFLEX_INSTRUCTIONS_THRESHOLD` (0.5). Answers are cached for 24 h by prompt
   hash, working directory and conditions.
3. **Inject.** Deterministic matches come first, then Jev matches by probability. Whole fragments
   are added until `REFLEX_INSTRUCTIONS_MAX_CHARS` (6000) is reached; a fragment is never cut.

| Agent | Where the fragments go | Installed by `install.mjs` |
|---|---|---|
| Claude Code | `UserPromptSubmit` hook, `additionalContext` | yes, a `UserPromptSubmit` entry in `~/.claude/settings.json` |
| Codex CLI | `UserPromptSubmit` hook, `additionalContext`. The matcher is ignored for this event; Codex caps hook context at ~2,500 tokens by default | yes, in `~/.codex/hooks.json`. Trust it again in `/hooks` |
| pi, oh-my-pi | `before_agent_start` handler; appended to that turn's system prompt | yes, in the same `reflex.ts` extension |
| opencode | `chat.message` picks the fragments; `experimental.chat.system.transform` appends them to the system prompt for the rest of the turn | yes, in the same `reflex.js` plugin. The system hook is marked experimental in opencode |
| Hermes | `pre_llm_call` shell hook; the text is appended to the turn's user message | printed with the rest of the `hooks:` block |
| `reflex-sh` | not supported, because the shell never sees the prompt | — |

**Advisory, not safety.** Any failure injects nothing and never blocks a prompt: a bad fragment
file, a Jev error or timeout, a missing key, or a crash. If only the Jev call fails, fragments
matched by path or keyword are still injected. `REFLEX_MODE=off` turns this off too. With no
fragment files there is no API call.

**Try it:**

```sh
node instructions.mjs --check "customers are charged twice on webhook retries" --cwd examples/instructions/repo
node instructions.mjs --check "rename a variable" --cwd examples/instructions/repo --files infra/envs/prod/main.tf
npm run eval-instructions     # golden prompts through the live API, paths/keywords off, so Jev judges every case
```

Current result: 20 prompts, all exact, precision 100 %, recall 100 % at threshold 0.5
(`jev-1.13.0`, ~690 input tokens and ~0.35 s median per prompt).

**Logs.** `instructions.jsonl` in the data directory holds one line per prompt: the prompt hash
(never the text), fragment ids, how each was matched, Jev's probability, whether it was injected,
latency and tokens.

**Writing conditions.** Describe the work, not a topic: *"the task changes Terraform or runs
infrastructure commands"* rather than *"Terraform"*. A question about Terraform is not a change to
Terraform, and the golden set checks that such a question does not load the fragment. Use `paths`
for what is certain, and keep `when` for the cases paths cannot see.

**Why not sections of AGENTS.md?** Agents load `AGENTS.md` in full themselves, so a marked section
there would be loaded twice, not saved. Move conditional sections into `.reflex/instructions/`
instead.

**Trust.** A fragment in a cloned repo is text someone else wrote, injected into your agent's
context: the same trust boundary as the `AGENTS.md` / `CLAUDE.md` the agent already loads from that
repo, and no wider. Reflex keeps it there: fragments come only from the repo (up to its root) and
your own config directory; each injected fragment is labelled with its source file; the injected
text tells the agent the fragments are guidance that cannot override the user, the system prompt or
permission settings; at most 20 conditions go to Jev per prompt. None of this changes what the gate
allows: a command a fragment talks the agent into is still judged like any other. The Claude Code
install also makes Claude ask before editing `~/.config/reflex`, whose fragments apply to every
repo. Review `.reflex/instructions/` in a repo you did not write, as you would its `AGENTS.md`.
Fragment text itself is sent to the agent's model, not to Jev; only the `when` conditions go to Jev.

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. The same pieces fit model routing
(a `choice` of small / medium / large before a request reaches the LLM gateway), LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
