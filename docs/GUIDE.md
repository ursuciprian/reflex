# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
   - [Calibrated allow](#calibrated-allow)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Where this goes next](#where-this-goes-next)

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
   Shipped rules: `rm-root`, `prod-destroy`, `force-push-main`, `push-mirror` (deny); `secret-read`, `tamper`, `destroy`, and for scripts `secret-exfil` (ask). Any mutating command that touches the Reflex checkout, its setup files or its logs is also an `ask`, wherever the repo was cloned.
   **Local scripts.** `bash deploy.sh` says nothing about what it does, so Reflex reads the local
   file a command runs. It recognises:
   - `bash`, `sh` and `zsh x.sh` (quoted paths, `< x.sh` and options included);
   - `source x.sh`, `./x` and `scripts/x`;
   - `python3`, `node`, `tsx`, `npx tsx`, `bun`, `ruby`, `perl` and `php` with a script, including
     one run through a path such as `.venv/bin/python`;
   - `make <target>`: that target's recipe, its direct prerequisites' recipes, and `$(MAKE)` calls;
   - `npm`, `pnpm` and `yarn` scripts (`run x`, `yarn x`, `test`, and install lifecycle scripts),
     with their `pre`/`post` hooks.

   It finds these behind subshells, `$(…)`, `if`/`then`, `env`, `sudo`, `nice`, `cd` and line
   continuations. What a shell script, recipe or package script runs in turn is followed one more
   level.

   Rules with `"applies_to"` including `"script"` read up to 256 KB of each file. Those rules are
   `rm-root`, `prod-destroy`, `force-push-main`, `push-mirror`, `destroy` and `tamper`, plus a
   check for the Reflex checkout and logs. The file is read line by line, with the script's own
   `VAR=value` assignments expanded and whole-line `#` and `//` comments dropped, so a word on
   one line cannot combine with a verb on another. The script-only `secret-exfil` rule
   (`whole_script`) asks when a script copies `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg` or a
   `.env` file and also talks to the network. Using a key with `-i` does not count.

   A hit names the script: `reflex (rule): recursive delete of / or home (in /repo/scripts/reset.sh)`.
   This runs before the fast lane, so `npm test` is only as safe as the test script. The command
   line `sh -c '…'` runs is inspected like the command itself; `bash -n` is not a read. A compiled
   program under a system directory (`/usr`, `/bin`, `/opt/homebrew`, …) is judged by its command.
   A credentials file that gets sourced (`.env`, `.netrc`, keys) is scanned by the rules but never
   sent to Jev.

   Some code is marked unseen, so the command is never allowed:
   - a named script that cannot be read (missing, or a package script the `package.json` lacks,
     which yarn, pnpm and bun run as a bin);
   - a package fetched or installed (`npx`, `pnpm dlx`, `bunx`, `uvx`, `npm install x`, `pip install`),
     a module or preload by name (`python -m`, `node -r` / `--import`, `NODE_OPTIONS`, `BASH_ENV`,
     `PYTHONPATH`, `LD_PRELOAD`), a task runner (`just`, `task`, `gradle` …), `go generate` / `go run`,
     and `find -exec` of a script;
   - the local modules a Python or JavaScript script imports (`import helper`, `require('./x')`);
   - a compiled program outside the system directories (built in the repo, downloaded);
   - a workspace or filter script (`npm -w`, `pnpm --filter`, `yarn workspace`);
   - code piped into a shell (`curl … | bash`);
   - a file an earlier step of the same command wrote (`curl -o x.sh … && bash x.sh`);
   - a third level of nesting;
   - anything past 8 scripts.

   Lines over 2,000 characters (minified bundles) are left out of the rules, and the script
   then counts as partly seen. If the scan takes more than 1.5 s, the command gets an `ask`
   instead of risking the hook's timeout.
3. **Fast lane** (`rules.json` → `pass`) — known-safe steps: builds, tests, `mkdir`, `git add/commit`,
   pushing a non-main branch. A command passes when every segment is read-only or matches a fast-lane
   pattern. → **pass**, logged.
4. **Jev** — the command (secrets redacted), its working directory, the environment context and
   the text the agent wrote right before this command and its last five commands (from the session
   transcript; if the command is not in the transcript yet, no intent is sent rather than an older one) are sent to
   TypeSafe with the six questions in `questions.json`. When the command runs a local script, its
   redacted excerpt goes along as `call.script = {path, excerpt}` and the question context tells Jev
   to judge the script, not its name (`node clean.mjs` that deletes `$HOME` is an ask, not a pass).
   Answers are cached for 24 h per (command, cwd, environment, question-set version, model, script
   content), so an edited script is judged again.
5. **Policy** (`policy.json`) — ordered gates over the answers; the first that fires wins,
   otherwise `default_outcome` (`pass`). If Jev fails or times out, the policy's `fallback` (`ask`)
   applies. The last gate, `allow`, marks clearly safe commands; what that means depends on
   `REFLEX_ALLOW` (see [Calibrated allow](#calibrated-allow)).

What happens with the decision depends on the mode:

| Mode | Rules | Jev + policy |
|---|---|---|
| `off` | nothing | nothing |
| `shadow` | enforced | runs in a detached background process; logged, never shown to the agent |
| `enforce` | enforced | `ask` → a human confirms (how depends on the agent, see the README table); `deny` → the command is blocked and the agent sees why |

`pass` is never turned into an approval: the gate stays silent and the agent's own permission
settings decide. Only an `allow` with `REFLEX_ALLOW=on` in enforce mode approves anything. Where an agent combines several hooks (Claude Code, Codex, Hermes), the most
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

A case can also carry `"allow": true` (a clearly safe command that should be allow-eligible;
reported as `stiff` when it is not, never a failure) or `"allow": false` (must never be
auto-allowed; a MISS if it is). An `allow` counts as `pass` for `expect`.

Cases with `"cwd": "$FIXTURES"` run in a temporary copy of `setup/tool-gate/fixtures/`, the
scripts, Makefile and `package.json` those commands run (each guarded so it exits if run by hand).

Current result: 65 cases, 0 misses, 0 over; 5 of 6 `allow: true` cases allow-eligible. Results are saved to `~/.local/state/reflex/eval-*.json`.
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

### Calibrated allow

Autonomous agents stop at every prompt their own permissions require, even for `npx prettier
--write src/`. The policy's last gate, `allow`, marks commands Jev judges clearly safe:

```
blast <= $allowBlastMax (1.2) and blast.confidence >= $allowConfidence (0.7)
and mutates, exfil, injection < $allowRiskBelow (0.3) and on_task >= $allowOnTask (0.5)
and env == 'local'
```

It is the last gate, so every deny and ask gate wins over it, and a missing answer makes it false.
`REFLEX_ALLOW` (or `node install.mjs --allow …`) decides what an allow does:

| `REFLEX_ALLOW` | Logged decision | Effect |
|---|---|---|
| `off` (default) | `pass` | none: the gate only tightens |
| `shadow` | `would_allow` | none; `report.mjs` measures it |
| `on` | `allow` in enforce mode, `would_allow` otherwise | the agent's own prompt is skipped (see the README table per agent) |

Never allowed, whatever the answers: anything a rule decided (including tamper and secret reads),
read-only and fast-lane commands (they stay `pass`, so your permission allowlist still governs
them), Jev errors and incomplete answers (the `ask` fallback), cached answers (they have lost
`on_task`), commands without a stated intent (`on_task` defaults to yes then), commands that
redaction changed (a redacted `--token "$(…)"` could hide a payload), commands that run code Jev
did not see in full (a script that is redacted, over 16 KB, unreadable, a credentials file such as
`.env`, or imports local modules; a make target, whose variables are not expanded; a compiled
program outside the system directories; `python -m`, `node -r` / `--import`, `NODE_OPTIONS`,
`BASH_ENV`, `PYTHONPATH`; `npx` / `dlx` / `uvx`, package installs, task runners, `go generate` /
`go run`), commands run from the home directory or `/` (where "inside the working directory" means everything),
and a policy whose `default_outcome` is allow (only the allow gate allows). In Claude Code, a
command retried outside the sandbox (`dangerouslyDisableSandbox`) and any command in plan mode
keep their prompt. The trace logs why as `low risk (not allowed: …)`. `export REFLEX_ALLOW=…` in a command is a tamper `ask`. In Claude Code an allow skips
the prompt but its deny and ask permission rules still apply.

**Calibrate from your own approvals.** Run with `REFLEX_ALLOW=shadow` in enforce mode for a
while. `node report.mjs` then shows, for the Jev-judged commands a human ruled on (asks it emitted
in enforce mode, and in Claude Code the commands allow would have let through — logged
`would_allow` or allowed on replay), how often you approved them (approved = the command ran), by
blast and by confidence bucket, and recommends
thresholds (illustrative output):

```
  calibration  64 labelled (asks in enforce mode + would-be allows; approved = it ran)
    by blast       0-0.5 12/12 (100%) · 0.5-1 30/31 (97%) · 1-1.5 9/11 (82%) · …
    recommend      of 41 with blast <= 1 and confidence >= 0.8, you approved 98% -> allowBlastMax 1, allowConfidence 0.8
```

It recommends the band covering the most commands you approved at least 95% of (10 or more
labelled), the tightest among equals, and says "not enough data" otherwise. Other agents have no
prompt for a pass, so their would-be allows are not labels, and neither are Claude Code's in a
permission mode other than `default` (the trace logs `permission_mode`); a command its allowlist
let through still counts as approved, which flatters the rate a little.
`node report.mjs --calibration` prints the expected calibration error of `blast` and `mutates`
read as approval probabilities (1 − blast/3, 1 − mutates) against your approvals, per bin; it
needs 20 labelled commands. Move the `allow*` params in `policy.json`, check with
`node report.mjs --policy`, then switch to `REFLEX_ALLOW=on`.

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
  redacted and truncated, and the first 16 KB of a local script the command runs (a make recipe,
  an npm script), redacted, never a credentials file such as `.env`. Read-only, rule and fast-lane commands never leave the machine.
- **Redaction** covers AWS keys, GitHub / GitLab / Slack / OpenAI-style tokens, bearer and basic
  auth headers, `*SECRET*=`, `*TOKEN*=`, `*PASSWORD*=`, `--password x`, credentials in URLs,
  private key blocks and JWTs. It is a pattern list, not DLP: extend it when you see a new shape.
- **TypeSafe** states it does not train on customer data; retention is covered by its
  [Data Processing Agreement](https://typesafe.ai/legal/data-processing), and zero data retention
  is available for enterprise customers ([legal](https://docs.typesafe.ai/legal)). Check this
  against your own data policy before rollout.
- **Locally**, logs contain the same redacted data and stay in `~/.local/state/reflex/`. Trace and
  feedback files rotate at 50 MB. Command output is never stored.

## Safety properties and limits

- By default the gate never emits `allow`. The worst a wrong Jev answer can do is add a prompt, or
  fail to add one; it cannot remove one that your permission rules require. With
  `REFLEX_ALLOW=on` a wrong answer can remove one, for the narrow allow gate only: calibrate in
  shadow first.
- A Jev failure or timeout gives the policy's `fallback` (`ask`) in enforce mode.
- An internal error (bad setup file, unreadable cache) returns the policy fallback (`ask`) in
  enforce mode and `pass` in shadow mode. Incomplete Jev answers count as an error, never as "no".
  The pi/omp and opencode adapters block when the gate cannot run at all in enforce mode.
- Script inspection recognises the launchers listed above, two levels deep, and reads 256 KB per
  file for the rules. A script that `curl | sh`s another, a path held in a variable, a third level
  of nesting, or a danger past 256 KB is judged only on what is visible. Variables are expanded
  only from simple `VAR=value` lines in the same script. A prod marker on one line and a delete on
  another no longer combine (see above), so `ENV=prod` set elsewhere and used as
  `kubectl delete … -n "$ENV"` is caught only if the variable is assigned in that script.
- Scripts are read when the hook runs, not when the command runs. A script changed in between (by
  a parallel tool call, a background job, or a symlink swapped to another file) runs unjudged; the
  content hash in the cache key only makes an edit before the next call a fresh judgment. No agent
  hook can pin the file it approved, so treat allow for scripts as "Jev read this version", and
  keep `REFLEX_ALLOW` off where scripts can change under you. Symlinks are followed to their
  target; a FIFO or device is never opened.
- Rules and the read-only list are pattern matching, not a shell parser. They are designed to
  fail towards "ask Jev", not towards "pass", and the self-checks pin the known bypasses — but
  treat them as a strong filter, not a sandbox. Keep IAM, network controls, and least-privilege
  credentials: Reflex supplements them.
- Claude Code does not report a Bash exit code to hooks; Reflex records `ran` (exit 0) or
  `failed` from `PostToolUse` / `PostToolUseFailure`.
- Only shell tools are gated (`Bash`, pi/omp `bash`, opencode `bash`, Hermes `terminal`). File-edit
  tools, MCP tools, omp's `eval` and Hermes' `execute_code` go through each agent's own permissions.
- Codex and opencode hooks cannot open a prompt, so an `ask` blocks with a reason telling the agent
  to get your confirmation. Codex hooks cannot allow either (an allow falls through), so `allow`
  is a silent pass there. Codex passes the session directory as `cwd`, not a per-command
  `workdir`. Codex hooks must be trusted in `/hooks` before they run.
- Environment context comes from the agent's process environment. A command that switches
  profile inline (`AWS_PROFILE=prod aws …`) is still seen, because the command text is judged; a
  profile changed by a previous command in a persistent shell is not.
- Jev adds ~0.7 s in enforce mode to each command that reaches it. On one engineer's heavy
  infrastructure history, about one in five commands never needed the API; the rest are mostly
  inline scripts and multi-step remote commands.

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. The same pieces fit model routing
(a `choice` of small / medium / large before a request reaches the LLM gateway), LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
