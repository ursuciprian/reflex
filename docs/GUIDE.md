# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
   - [Subgoal dedup](#subgoal-dedup)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
   - [Calibrated allow](#calibrated-allow)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Injection guard](#injection-guard)
9. [Autonomous agents](#autonomous-agents)
10. [Conditional instructions](#conditional-instructions)
11. [Tool router](#tool-router)
12. [Model routing](#model-routing)
13. [Context layer (pi and oh-my-pi)](#context-layer-pi-and-oh-my-pi)
14. [Where this goes next](#where-this-goes-next)

## Local and hosted operation

New setup uses `--engine local`. Deterministic shell checks and path/keyword instruction matches
run without TypeSafe. An unknown command produces `ask`: enforce requires human review, while
shadow logs it and leaves the host's permissions in charge. In the autonomous profile that ask goes
to System 2 first ([keyless autonomy](#keyless-autonomy)). Local operation does not reuse cached
Jev answers, spawn background classifiers, classify subgoals or make semantic instruction calls.
The shared Jev client rejects hosted requests while local; the LiteLLM callback leaves model
selection unchanged. A separate LiteLLM container needs the same configuration or `REFLEX_ENGINE=local`.

`--engine jev` enables the existing hosted behavior below. Older direct hook installations retain
Jev until an engine is selected; `reflex setup` records the choice. Defaults are bundled, with durable
user overrides under `~/.config/reflex/tool-gate/`; `reflex status` shows the active policy path.

`reflex doctor` runs local synthetic decision checks in a disposable state directory. These probes
do not count as live activation. `reflex status` separately reports the last real pre-execution
hook event and whether it matches the latest installation and settings. The heartbeat is local
operational evidence, not proof against an agent that can modify files. Native dialog behavior and
host trust must also be checked in the agent itself.

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
   An `ssh` call counts only as a read of its remote command, which must be read-only by the same
   rules (the fast lane is for local work): `ssh [options] host '<read-only>'`, with the quoted
   command last (words after it are appended on the remote side). Options come from an allowlist
   (`-4 -6 -C -T -a -k -n -q -t -v -x`, `-p -l -i -J -b -c -m`, and `-o` with `ConnectTimeout`,
   `BatchMode`, `StrictHostKeyChecking`, `UserKnownHostsFile`, `ServerAlive*`, `Port`, `User`,
   `IdentityFile` and other connection settings): nothing that runs a local command or loads local
   code (`ProxyCommand`, `LocalCommand`, `KnownHostsCommand`, `-F` config, `-I`, `PKCS11Provider`),
   forwards (`-L -R -D -W -w`, `-A`, `-X -Y`), backgrounds (`-f -N`), writes a local file (`-E`) or
   sends the local environment (`SendEnv`). The host is a literal name, or a variable set only by a
   `for h in <literal hosts>` loop in the same command (no `IFS`, `read` or other assignment of it).
   Nothing may feed ssh's stdin (a pipe or a redirect into it), and a double-quoted remote command
   must have nothing the local shell expands (`$VAR`, `$(…)`, backticks would send local data).
   Also read-only for remote checks: `free`, `nproc`, `lscpu`, `seq`, `systemctl status|is-active|
   show|cat|list-*`, `journalctl` (not `--vacuum*`, `--rotate`, `--flush`), `ip addr|link|route|neigh
   [show]`, and `docker exec [-it] [-u …] [-w …] <container> <read-only>` with a literal container.
   In a session that read a suspected prompt injection a read-only `ssh` is still egress and asks.
2. **Rules** (`rules.json`) — regular expressions over the command plus its context
   (`cwd=`, `aws_profile=`, `kube_context=`, `tf_workspace=`, `git_branch=`). A rule fires when all
   of its patterns match. Rules are **enforced in shadow and enforce modes**, with off disabling the entire gate.
   Shipped rules: `rm-root`, `prod-destroy`, `force-push-main`, `push-mirror` (deny); `tamper`, `destroy`,
   and — checked even before read-only detection — `secret-read` (the API key, secret stores) and
   `secret-file-read` (`~/.ssh/id_*` but not `.pub`, `~/.aws/credentials`, `.netrc`, `.pgpass`, `.env` / `.env.*` files but not `.env.example` and other templates, `kubectl get secret(s)`) (ask). It fires only when the file is an argument of a command that reads, copies or sends it (`cat`, `less`, `head`/`tail`, `grep`/`rg`/`ag`, `jq`, `sed`/`awk`, `cp`/`scp`/`rsync` as the source, `base64`, `xxd`, `strings`, `od`, `open`, `source`/`.`, `nc`, `tar`/`zip`, `curl -d/-F/-T/--data*`, a routed `mcp` call), at any command position — after `;`, `&&`, `|`, inside `$(…)`, backticks, `bash -c '…'`, `ssh host '…'` — or is redirected in (`< ~/.aws/credentials`). A commit message, `echo`, or `cp .env.example .env` that only names the file passes. Known over-match: a `grep` whose search *pattern* is `.env` (`grep -rn '.env' src/`) asks. Any mutating command that touches the Reflex checkout, its setup files or its logs is also an `ask`, wherever the repo was cloned.
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

### Subgoal dedup

Before an agent spawns a subagent, the adapter sends the subgoal instead of a command:
`{agent, subgoal, session_id, call_id, cwd}`, or `subgoals: [...]` for a batch. A call that also
carries a `command` is judged as a command.

| Agent | Tool (hook) | Subgoal |
|---|---|---|
| Claude Code | `Agent` / `Task` (`PreToolUse`, matcher `Bash\|Task\|Agent`) | `agent: <subagent_type>`, description, prompt |
| Codex CLI | `spawn_agent` (`PreToolUse`, matcher `^(Bash\|spawn_agent)$`, Codex 0.155+) | `agent: <agent_type>`, task name, message (or its text items) |
| oh-my-pi | `task` (`tool_call`) | per task: `agent: <agent>`, task, the batch's shared context cut to 200 characters |
| opencode | `task` (`tool.execute.before`) | `agent: <subagent_type>`, description, prompt |
| Hermes | `delegate_task` (`pre_tool_call`, its own entry without `fail_closed`) | per task: goal, context cut to 300 characters |

pi has no subagents. Codex's `SubagentStart` hook is not used: its input has no task text and it
cannot block. Resumes (Claude Code `resume`, opencode `task_id`) and Hermes control actions
(`list`, `steer`, `stop`) are not checked. A subagent that spawns its own subagents (Claude Code,
Codex) is compared only with its own earlier ones.

Reflex keeps the subgoals of each session in `subgoals.jsonl` in the data directory, and asks Jev
one `choice` question per new subgoal (`setup/tool-gate/subgoals.json`). The options are the
last 20 earlier subgoals of the same agent and session that count, plus `none`:

- one whose spawn **ran** (a `ran` record from the post hook), or
- one still **pending**: written when its own check started, with no record yet, less than
  `pendingSeconds` (300) ago. Every subgoal is written first and then compared only with the
  rows before it, so spawns in the same message, and tasks in the same batch, see each other: of
  two identical ones, the first passes and the second is the duplicate.

A spawn Reflex denied is marked dropped at once; one the user rejected, another hook blocked or
that failed (a `denied` or `failed` record) is never offered either, since it has no result to
reuse. Long options keep their first 400 and last 200 characters. The question is "does this
repeat one of them: same task, same scope, same kind of answer?" Follow-ups, other parts of the
problem, reviews of earlier work and retries that say why the first attempt failed count as
`none`.

If the chosen option's probability is at least `duplicateAt` (0.6), that subgoal is a duplicate.
A single spawn is denied, with a reason that names the earlier subgoal and tells the agent to
reuse its result:

```
reflex (jev): duplicates a subgoal already launched in this session at 22:24 UTC (p 0.67):
"agent: Explore\nFind auth flow\nExplain how login works end to end …". Reuse that result instead of starting it again
```

A batch loses only its duplicate tasks where the tool input can be trimmed: oh-my-pi runs the
`task` call with the rest and appends to its result which tasks were not started and why. Hermes
cannot be told which tasks a trimmed call dropped, so a Hermes batch with a duplicate is blocked
with the list ("Start the others again without task 2"), and all its tasks are dropped, so the
resend passes. A batch whose every task is a duplicate is denied.

- **Modes:** as elsewhere. In shadow mode the check runs in the background, and duplicates are
  logged as `deny` but not applied.
- **Failures:** dedup saves work rather than guarding safety, so a Jev error or an internal error
  always passes, and the Hermes entry is not fail-closed.
- **What is stored:** `subgoals.jsonl` holds each subgoal once, redacted and cut to 2,000
  characters, because later checks need the text. The trace keeps only a 120-character title and a
  hash per check, never the earlier subgoals offered as options.
- **Report:** `report.mjs` counts these checks on their own `subgoals` line.

The same text again (ignoring case, spacing and a batch's shared context line) is a duplicate
without asking Jev: Jev scores an option identical to the new subgoal low (0.2–0.3), apparently
reading it as the new subgoal itself. On hand-made pairs with `subgoals-v3`, reworded duplicates
scored 0.67–0.78 on the matching option, and ten legitimate follow-ups (tests for the same code,
another part, a review, a retry that says why, a narrower scope) scored at most 0.05.

ponytail: each check reads the last 2 MB of `subgoals.jsonl` and `feedback.jsonl` and takes no lock
(each batch is one append).

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
Add an assertion whenever you change `readOnly()`, a rule or a gate. `node guard.mjs --selfcheck`
covers the injection guard: every detector (most with a benign twin), the policy, rewriting, log
redaction, each adapter's output shape, credential prompts, and taint making the gate stricter.

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

The set has 97 cases, 6 of them `allow: true`. `npm run eval` prints the pass / MISS / over counts
for the rules, questions and policy you have now, and saves them to
`~/.local/state/reflex/eval-*.json`; Jev's answers vary between runs, so read a run as a sample and
only treat a MISS as a blocker. CI runs the offline self-checks (`npm test`); the live eval needs
`TYPESAFE_API_KEY` and spends tokens, so CI does not run it.

**Grow the golden set from real traffic.** Every surprising decision in the trace becomes a case.

The injection guard has its own set, `setup/injection/golden.json`, run by `npm run eval-injection`:
precision and recall of warn / block against the labels, and exit 1 on a missed high-severity
injection (see [Injection guard](#injection-guard)).

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

1. **Shadow, about a week.** Deterministic rules still enforce; other decisions are logged only.
2. **Tune.** Try a candidate policy against everything recorded, without spending tokens:

   ```sh
   cp ~/.config/reflex/tool-gate/policy.json /tmp/candidate.json   # edit thresholds
   node report.mjs --policy /tmp/candidate.json         # "N of M Jev decisions change", pass -> ask: …
   ```

   Keep what reduces wrong asks without adding misses, then `npm run eval`.
3. **Enforce** with `node install.mjs --mode enforce`.
4. **Watch the ask outcomes.** In enforce mode `report.mjs` scores each emitted ask as approved
   (the command ran), rejected (explicit denial feedback), pending or unknown. Missing feedback after ten minutes is unknown and excluded from calibration. An ask that is nearly always approved is friction: tune it.
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
| `reflex_asks` | `resolution` (approved, rejected, pending, unknown), `user` |
| `reflex_replay_changes` | `user` — decisions the current policy file would flip |
| `reflex_input_tokens` | `user` |

`dashboards/reflex.json` shows them in Grafana.

## Data handling

- **What leaves the machine:** for commands that reach Jev only — the command with secrets
  redacted, the working directory path, environment names (AWS profile, region, kube context,
  terraform workspace, git branch), and the agent's last message and last five commands, also
  redacted and truncated, and the first 16 KB of a local script the command runs (a make recipe,
  an npm script), redacted, never a credentials file such as `.env`. Read-only, rule and fast-lane commands never leave the machine.
  For subgoal dedup: the new subagent's task and the session's earlier ones, redacted and
  truncated to 2,000 characters (600 per earlier subgoal).
- **Redaction** covers AWS keys, GitHub / GitLab / Slack / OpenAI-style tokens, bearer and basic
  auth headers, `*SECRET*=`, `*TOKEN*=`, `*PASSWORD*=`, `--password x`, credentials in URLs,
  private key blocks and JWTs. It is a pattern list, not DLP: extend it when you see a new shape.
  The patterns live in `setup/redact.json`, shared by the gate and the model router; its `corpus`
  lists inputs with their exact redacted outputs, and both selfchecks assert them.
- **TypeSafe** states it does not train on customer data; retention is covered by its
  [Data Processing Agreement](https://typesafe.ai/legal/data-processing), and zero data retention
  is available for enterprise customers ([legal](https://docs.typesafe.ai/legal)). Check this
  against your own data policy before rollout.
- **Injection guard** (engine `jev`), per inspected tool result (a web page, an MCP result, network
  command output, or a file read from outside the project; never a credential file): up to 8 chunks of the result
  (3,000 characters each), redacted, the tool name, a redacted origin (URL, path or command, 200
  characters) and, in Claude Code, the user's last prompt (redacted, last 1,000 characters). With
  the local engine nothing leaves. Credential checks on prompts are local in both engines.
- **Conditional instructions** send, per prompt that has undecided fragments: the prompt (redacted,
  first 4,000 characters), the working directory, recently touched file paths, the last five
  commands (redacted), and each fragment's `when` condition. The fragment bodies stay local.
- **Context layer (opt-in, pi / omp).** When installed with `--context`, redacted samples of tool
  output (per chunk at most ~1,000 characters of start and end plus up to six matching lines of 200
  characters), the user's request and the agent's last message go to TypeSafe for relevance judging;
  `bin/reflex-review` and `context.mjs --bundle` send a redacted diff excerpt, the goal and matching
  lines. The chunk store (`chunks/`) keeps full outputs **unredacted**, exactly as the tool printed
  them, because `expand_chunk` must give the agent back what it would otherwise have seen; that is
  the same data the agent's own session file holds. The store is local, its directories are 0700 and
  its files 0600, and it is pruned (see *Context layer*). Bundles and reviews are written 0600: they
  hold the unredacted diff and code. The reviewer command you configure receives the unredacted diff
  and related code, because it is your own model.
- **System 2** (autonomous profile), per escalated command: the redacted command, the cwd, the
  environment names, System 1's answers and rule, the task envelope, one line of intent and the
  relevant lines of the script it runs (never a credentials file), at most 1,500 tokens, to the
  backend you chose: your own `claude` or `codex` CLI (and so its provider), the Anthropic API, or the
  OpenAI-compatible endpoint you configured. The approval queue keeps the redacted command locally
  (0600) for you to review; `judge.jsonl` keeps hashes and the verdict.
- **Locally**, logs contain the same redacted data and stay in `~/.local/state/reflex/`. Trace and
  feedback files rotate at 50 MB. Command output is never stored.

## Safety properties and limits

- By default the gate never emits `allow`. The worst a wrong Jev answer can do is add a prompt, or
  fail to add one; it cannot remove one that your permission rules require. With
  `REFLEX_ALLOW=on` a wrong answer can remove one, for the narrow allow gate only: calibrate in
  shadow first.
- In the autonomous profile an `allow` can also come from System 2's approve or a human's queue
  approval, never for a rule outcome, the always-human class or a tainted session's egress; its
  invariants and their checks are in [Autonomous agents](#autonomous-agents).
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
- Only shell tools are gated (`Bash`, pi/omp `bash`, opencode `bash`, Hermes `terminal`), plus the subagent tools for dedup. File-edit
  tools, MCP tools, omp's `eval` and Hermes' `execute_code` go through each agent's own permissions.
  The injection guard reads the *results* of web, MCP, file and network tools; it does not gate
  those calls (see [Injection guard](#injection-guard)).
  The tool router is the exception: it runs its command tools and its downstream MCP calls through
  the gate itself.
- Codex and opencode hooks cannot open a prompt, so an `ask` blocks with a reason telling the agent
  to hand off to the human: review and run the exact command with `reflex run` in a separate terminal. A chat confirmation alone does not unblock the hook. Codex hooks cannot allow either (an allow falls through), so `allow`
  is a silent pass there. Codex passes the session directory as `cwd`, not a per-command
  `workdir`. Codex hooks must be trusted in `/hooks` before they run.
- Environment context comes from the agent's process environment. A command that switches
  profile inline (`AWS_PROFILE=prod aws …`) is still seen, because the command text is judged; a
  profile changed by a previous command in a persistent shell is not.
- Jev adds ~0.7 s in enforce mode to each command that reaches it. On one engineer's heavy
  infrastructure history, about one in five commands never needed the API; the rest are mostly
  inline scripts and multi-step remote commands.

## Injection guard

The gate judges what an agent runs. `guard.mjs` judges what it reads first: a web page, search
results, an MCP result, a file from someone else's project or the output of `curl` can carry text
written to steer the agent (indirect prompt injection). After such a tool runs, the guard scans its
result and returns **pass**, **warn** or **block**; on each prompt it also checks for a pasted
credential.

**Which results are inspected** (`sources` in `setup/injection/policy.json`):

| Source | Tools | When |
|---|---|---|
| web | `WebFetch`, `WebSearch`, opencode `webfetch` / `websearch` / `codesearch`, omp `web_fetch` / `web_search` / `github` and its `read` of a URL, Hermes `web_search` / `web_extract` / `x_search` / `feishu_doc_read` / `browser_*` (not the password vault) | always |
| mcp | any MCP tool (`mcp__server__tool`, Hermes `connectors__…`; opencode: any tool that is not built in) | always |
| file | `Read`, `read`, `read_file` | the file is outside the project (the nearest directory holding `.git` above the working directory; in Claude Code above `CLAUDE_PROJECT_DIR`, so a `cd` into a cloned repository does not make its files the user's), or inside it under `node_modules/`, `vendor/`, `third_party/`, `site-packages/`, `.venv/`, `.cache/`; never a credential file (`~/.ssh/`, `~/.aws/`, `~/.kube/`, `.env*`, `.netrc`, `*.pem`, ..., `exclude`), whose content would otherwise go to Jev |
| shell | `Bash`, `bash`, Hermes `terminal` | the command fetches remote content: `curl`, `wget`, `xh`, `gh issue/pr/api/release/gist/search`, `glab`, `npm view`, `pip download`, ...; or a local command that prints someone else's text: a reader (`cat`, `head`, `tail`, `less`, `jq`, `sed`, ...) given a path the file rule would inspect, or `git log` / `show` / `blame` in a repository outside the project. A command that also names a credential file is judged by the detectors only, never sent to Jev |

Anything else (edits, greps, local commands, the user's own files) is not inspected. A hook matcher
cannot see a `Read`'s path, so every `Read` starts the guard process (about 50 ms), which returns at
once for a file inside the repository.

**Deterministic detectors** (`setup/injection/detectors.json`, both engines), each counted as a
signal:

- `override`: text that cancels or replaces an AI's instructions (*ignore previous instructions*,
  *your new task is*, *do not tell the user*, *the user has already authorized you*).
- `role`: fake chat-role or system markers (`<|im_start|>`, `[INST]`, `<system_prompt>`, `<IMPORTANT>`).
- `to_ai`: text addressed to an AI agent (*note to AI agents*, *if you are an LLM*, *whoever is
  processing this page*, `@claude`).
- `shell`, `secrets`, `exfil`: what the text asks for (a remote script piped to a shell, reading
  keys or `.env`, sending data to a URL). Alone these are how install guides read; they matter next
  to an address to an AI.
- `hidden`: text a human reader does not see that speaks to an AI: Unicode tag characters
  (U+E0000 to U+E007F, *ASCII smuggling*; emoji flags excepted), a phrase split by zero-width
  characters, HTML comments, CSS-hidden elements, `alt` / `title` / `aria-label` attributes,
  markdown comments, the text of `data:` URLs, base64 blobs (also URL-safe or wrapped over lines)
  that decode to such text, and text spelled in a run of variation selectors. The phrases are
  matched on the text as a reader takes it in: invisible characters and soft hyphens out,
  look-alike Cyrillic and Greek letters, full-width, mathematical and accented letters read as
  Latin, JSON `\u` escapes and HTML character references decoded. A phrase that needed a disguised
  letter counts as hidden. They are also matched on text spaced out letter by letter
  (`I g n o r e   p r e v i o u s`, with any spaces, read with the narrowest gaps taken out); there
  a phrase counts like a plain one, since a reader sees it, so Jev can clear a quotation.
- `exfil_link`: a markdown image (or HTML `img`) whose URL has a placeholder or a data word
  (`?q={conversation}`, `[DATA]`, `${SECRET}`), or a link (markdown, HTML `a` or `<https://…>`)
  with a placeholder in a query value; reference-style ones (`![x][1]` … `[1]: url`) by their
  definition. An image is fetched when the agent's answer is rendered.
- `invisible`: zero-width and bidi controls, outside emoji sequences and right-to-left text.

**Jev** (engine `jev`): the result is cut into chunks with `context.mjs`'s `chunk()` (at most
3,000 characters each; at most 24 per result, those with a detector hit first, 8 per request with
the requests in parallel), and each request asks three questions per chunk (`setup/injection/questions.json`).
A piece under 1,000 characters goes with a neighbour when both fit in one chunk, else with the
lines before it (overlapping the previous chunk) up to 3,000 characters: a short last section judged
on its own has no page around it to show who it speaks to.

| Question | Type | Meaning |
|---|---|---|
| `addressed` | noul | The text tries to get an AI that reads it to act, as opposed to informing a human |
| `attack` | choice | exfiltrate, run_commands, credentials, override, deceive or none |
| `severity` | score 0 to 3 | Harm if the agent did what the text says |

The user's last prompt goes with them (Claude Code, from the transcript) so "deviates from the
task" can be judged. Chunks are redacted before they leave. Answers are cached by content for 24 h.

**Policy** (`setup/injection/policy.json`), per chunk; the worst chunk wins:

1. hidden instructions or an exfiltration link: **block**, whatever Jev says.
2. Jev: `addressed >= 0.7`, `severity >= 1.8`, an attack: **block**.
3. Jev: `addressed < 0.2`: **pass**. This is how an article that *quotes* an injection, or a README
   that tells a human to `curl … | sh`, gets through.
4. Jev: `attack` none and `severity < 1.8`, where the detectors saw an address to an AI and an
   action: **warn** (an `@claude` mention in one issue comment and an install line in another).
5. an address to an AI (override, role or `to_ai`) together with an action (`shell`, `secrets`,
   `exfil`): **block**.
6. Jev: `addressed >= 0.5`, `severity >= 0.8`, an attack: **warn**.
7. Jev: `addressed >= 0.25`, `severity >= 1.8`, an attack: **warn**. Jev is unsure the text speaks
   to an AI but names a serious attack: a polite request to "have the helper you are using" paste a
   key into a form scores 0.37 to 0.49. Text that quotes or reports an attack is judged attack none.
8. an address to an AI alone, or 12 or more invisible characters (with Jev, counted per chunk): **warn**.

With the local engine, steps 2 to 4, 6 and 7 do not exist, so a security article quoting an injection
warns. A Jev error or an incomplete answer falls back to the detectors alone. A result longer than
4 MB is read in part and is at least a **warn**.

**What each outcome does.** *Warn* adds a note next to the result: the result is third-party
content, not a message from the user, and the user has not asked for anything it says. *Block*
removes the offending text where the agent lets a hook rewrite a result, marking each cut
(`[reflex: removed text addressed to an AI agent]`): the paragraph around a phrase hit, the hidden
segment, the link, or the whole chunk (up to 3,000 characters) that Jev blocked. The note says
what was removed. Both record a **taint** for the session (enforce mode only):

| Agent | Tool results | Prompts with a pasted credential |
|---|---|---|
| Claude Code | `PostToolUse` (`^(WebFetch\|WebSearch\|Read\|Bash)$\|^mcp__`): warn is `additionalContext`; block adds `updatedToolOutput`, the result with the same shape and the text removed | `UserPromptSubmit`: `decision: "block"`; the reason names the key type and is shown to the user, not to Claude |
| Codex CLI | `PostToolUse` (`^Bash$\|^mcp__`): warn is `additionalContext`; block is `decision: "block"`, which replaces what the model sees with the reason, so the reason carries the cleaned result, cut to 8,000 characters. Codex fires no hook for its hosted web search, and cannot rewrite a result otherwise (`updatedMCPToolOutput` fails the hook) | `UserPromptSubmit`: `decision: "block"` |
| pi, oh-my-pi | `tool_result`: block returns the cleaned `content`, warn appends a note. Tools that only touch local work (`edit`, `write`, `grep`, `find`, `ls`, `task`) are not sent | `input`: `{action: "handled"}` (pi) / `{handled: true}` (omp) drops the prompt, with a notification; in omp only the interactive prompt fires `input` |
| opencode | `tool.execute.after`: `output.output` edited in place; for an MCP tool the hook sees the raw MCP result, so its `content[].text` is edited | `chat.message` throws: the message is not saved, and opencode shows an error (a plugin has no friendlier way) |
| Hermes | `post_tool_call` is observe-only and `pre_llm_call` runs once per turn, before any tool: a finding is logged and taints the session at once, and its note reaches the model at the start of the next turn. Rewriting results needs a Python plugin (`transform_tool_result`), which Reflex does not ship | no hook can block a message; in enforce mode `pre_llm_call` tells the model the message holds a credential it must not repeat |

**Taint.** A warn or block in enforce mode writes `taint/<hash of the session id>.json` in the
data directory. For the rest of that session the gate:

- asks before network egress (`curl`, `wget`, `ssh`, `scp`, `git push`, `gh api` and `gh … create/comment`,
  `npm publish`, `docker push`, any URL, a script opening a socket): `tainted` in `rules.json`,
  checked before the read-only list and the fast lane, since `gh api "…?q=$SECRET"` is a read,
  a read-only `ssh host 'uptime'` still reaches the host, and `git push` is fast lane;
- never allows (calibrated allow is off);
- applies the policy's taint gates (flag `taintStrict`): ask at `exfil >= 0.2`, at `blast >= 1.0`,
  and for a mutation with `on_task < 0.6`.

Rules that deny still deny. Like Jev decisions, the taint only takes effect in enforce mode. A
user `policy.json` seeded by an earlier setup gets what it lacks on the next `reflex setup`: gates,
params and flags of the bundled policy missing from it by id or name are added (a new gate right
after the one before it in the bundled order), nothing of the user's is changed or reordered, and
setup prints what it added. A deleted bundled gate comes back that way; switch one off with its
flag instead. In opencode the taint is kept under a subagent's root session, so a child that read
an injection makes its parent stricter.

**Credentials in prompts** use the credential shapes of `setup/redact.json` (AWS keys, GitHub,
GitLab, OpenAI and Slack tokens, private keys, JWTs, Stripe, Google and npm keys, Slack webhooks;
not the bare 40-character shape, which also matches long identifiers), and not its `KEY=` context
patterns, which would stop *what does max_tokens: 100 do*. The log keeps the key type and a hash of the redacted prompt, never the key.

**Modes.** The guard follows the gate's mode unless `REFLEX_GUARD` (or `"guard"` in
`~/.config/reflex/config.json`) says otherwise. Shadow judges in a detached background process,
logs, and changes nothing: no note, no rewrite, no taint, no blocked prompt. Off does nothing. Any
error passes: the guard only adds friction when it has a judgment to add.

**Try it:**

```sh
reflex scan page.html                  # exit 0 pass, 1 warn, 2 block; JSON with the signals
curl -s https://example.com | reflex scan - --rewrite     # also print the cleaned text
npm run eval-injection                 # setup/injection/golden.json against the live API
```

The golden set holds 62 results: 29 benign documents agents read every day (install guides that pipe
`curl` to a shell, man pages, API docs, npm output, HTML with comments and hidden menus, OWASP pages,
a blog post and a long field guide that quote or describe injections, a long README of a coding
agent, a GitHub issue that mentions `@claude` next to an install line, an `AGENTS.md` from another
repo, letter-spaced headings, accented, right-to-left and emoji text) and 33 injections
following published research (hidden-text pages, the GitHub MCP issue attack, MCP tool poisoning,
Unicode tag and variation-selector smuggling, look-alike letters, JSON escapes, markdown image
exfiltration, also reference-style, the rules-file backdoor, EchoLeak-style mail, fake role tags,
paraphrased injections with no trigger words: behind twelve chunks of benign text, split across two
chunks, on one long line, at the top, middle and end of long pages; letter-spaced text).
Current result, `jev-1.13.0`, five runs: precision 97 %, recall 100 %, every expected outcome met
(the `@claude` issue warns), 28 or 29 of 30 high-severity injections blocked and the rest warned.
With the local engine: precision 81 % (articles that quote injections warn or block), recall 79 %
(the GitHub MCP issue attack and the paraphrases, which have no trigger phrase, pass). A missed
high-severity injection fails the run.

**Logs.** `guard.jsonl` in the data directory: one line per inspected result (tool, source kind,
hashes of the text and origin, length, signal counts, Jev's numbers per chunk, outcome, what was
emitted, latency, tokens, the kind of a Jev error) and per blocked prompt (key types, a hash). Never
the text, the URL or the command. `reflex report` summarises it: results by source, outcome and
attack, tainted sessions and blocked prompts, as counts.

**Limits.** This is a heuristic filter, not a sandbox: it lowers the odds that injected text steers
the agent; it does not make untrusted content safe, and the gate still judges every command the
agent runs. The detectors are phrase lists and a handful of structural checks, so an injection
phrased like ordinary prose passes them (Jev is there for that; the local engine has no answer to
it), and text spaced out evenly letter by letter (the same gap between words), or one letter per
line, is left to Jev. Jev sees at most 24 chunks of 3,000
characters per result; past that only the detectors read the rest, and past 4 MB nothing does
(the result warns). A paraphrase split across two chunks is judged in halves: in the golden set
each half still reads as an instruction, but a split where neither does would pass. Hidden elements are found by their own `style` or `hidden`
attributes, not by class names or stylesheets. A tool the source list does not name (a custom pi
extension tool, an MCP tool in opencode that shares a built-in name) is not inspected. The agent has
read the result before Codex and Hermes can do anything about it, and in Hermes the note arrives a
turn late. A Jev-blocked chunk is removed whole, which can cut useful text next to the injection.
Shadow mode never taints, so the gate's taint behaviour only starts once the guard enforces.
A hook that times out passes the result unguarded. Subagents run under their own session id in
oh-my-pi and Hermes (and Hermes starts a new one after compressing the context), so taint does not
cross between a parent and its subagents there. Codex fires no PostToolUse for a failed tool or an
MCP error result, and scans only the last chunk of a long-running command. In Claude Code, `WebFetch`
hands the hook the fetch model's summary of the page, not the page.

## Autonomous agents

In the supervised profile (the default) every uncertain command becomes an `ask`, and an ask waits
for a person: the person is the bottleneck. The autonomous profile turns the human into the last
rung of an escalation ladder:

```
command
  |-- System 1: read-only list, rules, fast lane, Jev + policy   -> pass / allow / deny (most commands)
  |-- would be ask, not always-human: System 2                     -> approve / deny / human
  `-- always-human class, or System 2 said human                   -> the approval queue (async)
```

```sh
reflex setup --profile autonomous --dry-run     # the effective settings, nothing written
reflex setup --profile autonomous               # engine jev (local without a TypeSafe key), enforce, allow on, System 2, queue, checkpoints
reflex setup --profile autonomous --mode shadow # a flag beside a profile wins: log what it would do
reflex setup --profile supervised               # back to a human for every ask
```

A profile is a preset written to `config.json` (`profile`, `judge`, `queue`, `checkpoints` beside
`engine`, `mode`, `allow`). `REFLEX_JUDGE`, `REFLEX_QUEUE` and `REFLEX_CHECKPOINTS` (`on` / `off`)
override one session; `reflex run` turns all three off, since a person is at that terminal.
`autonomy.mjs` holds the ladder, the queue, envelopes and checkpoints; `judge2.mjs` System 2;
`setup/tool-gate/escalation.json` the always-human class and System 2's prompt.

### Keyless autonomy

The profile uses Jev when setup finds a TypeSafe key (`TYPESAFE_API_KEY`, or the Keychain item on
macOS). Without one it picks the local engine and says so, in a dry run too; `--engine` beside the
profile wins, and a later setup with a key moves to Jev. Keyless, System 1 is the rules, the
read-only list and the fast lane only, and a command they do not cover goes to System 2 instead of
straight to a human. Rule denies, tamper, the always-human patterns and taint behave exactly as with
Jev. What keyless does not have is Jev's own answers: the `prod`, `prod-destroy` and `exfil` gates
are Jev's, so production is caught only by the `prod` pattern and exfiltration only by System 2.

The `prod` pattern (the `prod` always-human rule and the `prod-destroy` rule share it) reads the
command, the cwd and the context. `prod`, `production` and `prd` count as words anywhere
(`envs/prod`, `terraform/ecs/production`, `--profile prod`, `prod-db.internal`, an ARN naming
`production-ecs`, `RAILS_ENV=production`), except in `non-prod` / `pre-prod` and in a document or
log file name (`prod-notes.md`, `production.log`). `live` is also an English word, so it counts only
as an environment: a directory under `envs/`, `environments/`, `stages/`, `deploy(ments)/`,
`overlays/`, `accounts/` or `workspaces/` (`envs/live`), the value of an environment option or
variable (`--context live`, `--profile=live`, `DEPLOY_ENV=live`, `terraform workspace select live`),
`--live`, or an AWS profile, kube context or terraform workspace containing it; the branch only when
it is exactly `live`. A checkout at `~/src/live-demo` or a scratch directory named `auto-live` is not
production. A directory named exactly `prod` still is, wherever it is.

System 2 approved something no other model judged, so its approve is a `pass` (the agent's own
permissions decide), except for a small class that becomes `allow`: a verdict at 0.9 or more, a stated
intent, an unredacted command of at most 400 characters (the case System 2 gets can cut a longer one),
a narrow cwd, no suspected injection in the session, and a command that sends nothing over the
network (the `tainted` egress patterns in `rules.json`), names no cloud, cluster, database, deploy,
package or system tool (`kubectl`, `helm`, `terraform`, `aws`, `gh`, `psql`, `docker`, `prisma`,
`brew`, `launchctl`, `sudo` and the like, in any case or quoting: a checkpoint cannot undo them) and no
verb that ships or installs (`deploy`, `publish`, `push`, `migrate`, `install`, `up`, `run`, ...),
writes nothing outside the working directory (no `~`, `$HOME`, `--global` or absolute path elsewhere),
and runs no local script or code nobody read (System 2 sees at most 24 lines of it). What is left
changes the repository, where a checkpoint was just taken. The same held prompts apply (plan mode, an
unsandboxed retry). What that means per agent:

| Agent | System 2 approves an allow-eligible command | System 2 approves anything else |
|---|---|---|
| Claude Code | `allow`: runs without its permission prompt (its own deny and ask rules still apply) | `pass`: its permission rules decide, a prompt unless it is allowlisted or prompts are off |
| Codex | its approval policy decides (it has no allow to skip) | the same |
| Hermes | its approvals decide | the same |
| opencode, pi, omp | runs | runs |

So in Codex, opencode, pi and omp a keyless System 2 approval runs the command, as a Jev-backed one
does; in Claude Code with its default permissions, the remote and networked ones still stop at its
prompt, which is the cost of having no second model.

**How often System 2 is asked.** Measured with `precheck` and the always-human patterns over 14,445
real Bash commands from Claude Code transcripts (one heavy DevOps user, 166 sessions, 63 active days):
31.5 % read-only, 1.0 % fast lane, 0.2 % a rule deny, 5.5 % a human before System 2 (rule asks 1.9 %,
production 2.9 %, destructive deletes 0.7 %, IAM and secrets), and 61.9 % to System 2 (about 90 % of
the commands the ladder judges; the verdict cache saved 0.5 %, since the same command rarely repeats
in a session). That is 115 calls on a median active day, 294 at p90 and 592 at most. Of those
escalations 59.6 % were egress (mostly `ssh`), 7.1 % remote CLIs, 11.4 % ran local code and 20.3 %
passed the egress, remote-tool and script checks (an upper bound: the length, verb, path, intent and confidence checks come on top). With Jev, System 2 sees far fewer: on the
ladder golden set 8 of 41 commands against 15 keyless.

Re-measured on the same history (14,463 commands) after the ssh and `prod` changes above: read-only
31.4 % → 32.9 %, a human before System 2 5.5 % → 4.7 % (the `prod` pattern 2.9 % → 2.0 %; each of the
133 matches it dropped was a word such as "live" in an echo, a comment or a file name, or the
`auto-live` scratch directory, and it gained none), System 2 61.8 % → 61.3 %, calls per active day
115 → 112 at the median and 294 → 281 at p90. The ssh change alone takes System 2 to 60.4 %. Most
`ssh` commands that still reach System 2 are not reads: they start servers and benchmarks, run
`python3 -c`, `docker exec $C` or `curl` against a health endpoint, or kill processes. Counting remote
`curl` GETs and `docker exec $C` as reads as well would reach only 57 %, so neither is on the list.

The keyless defaults follow from that: `budget.calls` 300 a day (enough for nine days in ten),
`session_calls` 100, `session_usd` $2, and the breaker off (`breaker.rate` 1): its 30 % would stay open
all the time, and it guards against a Jev outage or a noisy policy, neither of which exists without
Jev. Saved settings win. Past a cap, cases go to the queue. At the measured `claude` CLI numbers a call
is 3 to 4 s and $0.004 to $0.016 at API prices (with a subscription it counts against your plan
instead), so a median day costs about $0.5 to $1.8 and every escalated command waits for the judge.
`reflex status` shows `System 1: local rules (keyless: …)`; `npm run eval-ladder -- --engine local`
runs the golden set keyless, offline.

### System 2

A decision that would be `ask` goes to a stronger model with what Reflex knows about it, and one
structured answer comes back: `{"verdict": "approve" | "deny" | "human", "confidence": 0..1,
"reason": "one line"}`. Approve becomes `allow` (subject to `REFLEX_ALLOW` and the same held prompts
as calibrated allow: an unsandboxed retry and plan mode keep theirs), deny becomes `deny` with the
reason, human goes to the queue.

**Backends** (`judge.backend`):

| Backend | What runs | Key |
|---|---|---|
| `cli` | `claude -p`, or `codex exec` when you name it | none: the CLI you are already signed in to |
| `anthropic` | `POST <url>/v1/messages` (`anthropic-version: 2023-06-01`) | `ANTHROPIC_API_KEY`, or `judge.key_env` / `judge.keychain` |
| `openai-compatible` | `POST <url>/v1/chat/completions`: OpenAI, Ollama, vLLM, LM Studio, OpenRouter, a LiteLLM gateway | `judge.key_env` / `judge.keychain`, or none for a keyless endpoint |
| `none` | nothing: uncertain decisions go to a human | |

Setup picks the default and says which: the `claude` CLI when it is on `PATH`, else `anthropic` when
`ANTHROPIC_API_KEY` is set, else `none`. `--judge <backend>` overrides; an OpenAI-compatible endpoint
is never guessed. The CLI judge runs in a fresh empty directory (a project's own settings, hooks and
MCP servers are not loaded), with Reflex off in its environment (`REFLEX_MODE`, `REFLEX_GUARD`,
`REFLEX_JUDGE`, `REFLEX_QUEUE`, `REFLEX_CHECKPOINTS` all `off`, so a Reflex hook in that session does
nothing and cannot recurse) and with every tool off:

- `claude -p --output-format json --tools "" --system-prompt <judge prompt> --strict-mcp-config
  --settings '{"disableAllHooks":true}' --disable-slash-commands --no-session-persistence
  --model sonnet`, plus `CLAUDE_CODE_DISABLE_CLAUDE_MDS`, `_AUTO_MEMORY`, `_GIT_INSTRUCTIONS`,
  `_BUNDLED_SKILLS`, `_ATTACHMENTS`, `_THINKING` and `_NONESSENTIAL_TRAFFIC` in its environment, so its
  own system prompt, tool definitions, CLAUDE.md and skills stay out of the call. The model is always
  pinned (`judge.model`, `sonnet` by default): unpinned, `claude -p` uses your default model. `--bare`
  (leaner still) is added only when `ANTHROPIC_API_KEY` is set, because it never reads a subscription
  login.
- `codex exec --sandbox read-only --ignore-user-config --ignore-rules --ephemeral --skip-git-repo-check
  --disable shell_tool --disable unified_exec --disable hooks …  --output-schema <verdict> -o <file> -`.
  `codex exec` cannot replace its base instructions, so each call carries them: that is why it is
  never picked on its own.

**Spend is small by design.**

- *Fewer calls.* A verdict cache (`judge-cache.json`, `judge.cache_ttl_hours`, 12 h) keyed on the
  command's template (the redacted command with UUIDs, hex ids, timestamps and numbers of 4+ digits
  as slots; names, paths and small numbers are not slots, since `rm -rf build` and `rm -rf src`,
  `--replicas=0` and `--replicas=3` are different decisions), the cwd, the environment names, the
  envelope, the scripts' contents, the taint and egress state, the policy gate that asked and the
  versions of the policy, the escalation file and the judge. Only answers that parsed are cached. A
  retry of a command already waiting in the queue never asks again. Optional tiers (`judge.tiers`,
  cheapest first) ask a small model first; its deny or confident approve stands, its human, an
  unsure lean or an error goes up a tier.
- *Fewer tokens per call.* The static prompt goes first (for Anthropic marked `cache_control`; an
  OpenAI-compatible server caches a repeated prefix on its own), the case last, assembled to at most
  `judge.max_input_tokens` (1,500): the command, the cwd, the environment names, System 1's answers,
  the envelope, the last line of the agent's intent, and from the script it runs only the lines that
  share words with the command and intent or look like they change something (numbered, at most 24).
  What does not fit is cut, least useful first, and the case says what was cut. The answer is JSON
  in `judge.max_tokens` (100), with extended thinking off (`judge.thinking: "disabled"`; set it to
  `null` for a model that rejects that).
- *Caps.* Per day (`budget.calls` 200, `budget.usd` $5) and per agent session (`session_calls` 40,
  `session_usd` $1). The cost is estimated from the reported usage and `judge.price` (USD per million
  input and output tokens); a CLI backend uses the cost it reports itself. A breaker pauses System 2 when more than
  `breaker.rate` (30 %) of the commands the ladder judged in the last `breaker.window_minutes` (60),
  and at least `breaker.min_decisions` (20), were escalated: a Jev outage or a noisy policy then fills
  the queue instead of the bill, and `reflex status` and `reflex report` say so. Keyless the caps are
  300 calls a day, 100 and $2 a session, and the breaker is off ([why](#keyless-autonomy)).

Measured. On the escalation golden set the case System 2 gets is about 520 tokens (the stub judge
counts what it was sent) and a verdict about 20 tokens out on an API backend, where `max_tokens`
caps the output. The `claude` CLI, measured on Claude Code 2.1.282 with a subscription login:

| `claude -p` call | Input tokens | Output | Cost (API prices) | Time |
|---|---|---|---|---|
| naive: default model (Opus), CLAUDE.md, tools, skills | 36,826 | 423 | $0.28 | 7.3 s |
| lean flags above, `--model sonnet`, first call | ~3,100 | ~300 | $0.016 | 3 to 4 s |
| the same, repeated (the prefix is a cache read) | ~3,100, mostly cached | ~300 | $0.004 to $0.005 | 3 to 4 s |

About 2,100 of those input tokens are Claude Code's own floor, even with `--system-prompt`. The
output is ~300 tokens for a ~40-token verdict: hidden reasoning is billed and the CLI has no
`max_tokens`, so only an API backend caps output hard. Sonnet gave the same verdict on three
identical runs; Opus flipped between deny and human; Haiku ignored "JSON only" (fences, an essay)
and misread a simple case, so it is not a default tier: add a small model to `judge.tiers` only
after it passes `npm run eval-ladder`. For a CLI backend the tokens, the cost (`total_cost_usd`, an
API-price figure that also counts toward the budget) and the duration come from the CLI's own JSON
output, not from an estimate. The answer parser takes the first JSON object in the answer
(```` ```json ```` fences and trailing prose are tolerated) and validates it strictly.

**Everything else is human.** An HTTP or CLI error, a timeout, a refusal, a truncated or unparsable
answer (no JSON object, or a first object without exactly those three keys and valid values), an approve
below `judge.min_confidence` (0.8), a missing key or CLI, a spent budget or cap, an open breaker:
the decision goes to the queue, never to an approval.

**What it sees.** The redacted command, the cwd, the environment names, System 1's answers and the
rule that asked, the envelope, one line of intent and the relevant lines of the script it runs,
never a credentials file; `judge2.mjs` redacts every string again before sending. `judge.jsonl` logs
hashes of the case and command, the verdict, the redacted one-line reason, usage, cost and latency,
never the command or the case.

### The always-human class

`setup/tool-gate/escalation.json` names what neither System 1 nor System 2 may approve:

- every deterministic rule outcome: a rule deny stays a deny (never escalated); a rule ask
  (tamper, secret reads, destroy, script-budget) goes to a human;
- the policy gates `prod`, `prod-destroy`, `exfil` and `tainted-exfil`;
- patterns in the rules.json shape: production mutations (asks only; its System 1 check is the
  `prod` gate), IAM and permission changes, writing or deleting secrets, destructive deletes
  (`rm -rf`, `git reset --hard`, `git clean -f`, a force push, `DROP` / `TRUNCATE`, cloud deletes),
  money and billing APIs;
- network egress in a session tainted by the injection guard: System 2 may deny it, only a human may
  approve it; a tainted session never gets `allow`.

In the autonomous profile a System 1 pass or allow that matches one of these patterns also goes to a
human: in that profile a pass means the command runs.

### The approval queue

With the queue on, a human decision is a deny whose reason names a queue item:
`… parked in the approval queue as q-3f9c0a1b2d. Continue with other work and retry this exact
command later from the same directory`. Every adapter can show a deny, so the queue works for every
agent. Items live in `<data>/queue/` (0700 / 0600), one JSON file each, holding the redacted command
and the reason for review.

```sh
reflex queue                       # pending first
reflex queue show q-3f9c0a1b2d
reflex queue approve q-3f9c0a1b2d --ttl 2h
reflex queue deny q-3f9c0a1b2d --reason "use the dev pipeline"
reflex queue clear [--all]         # answered items, or everything
```

The id is a hash of the raw command, its redacted form, the resolved cwd and the session, so an
approval matches only the identical retry, in the same directory and session. It is used once and
expires after its TTL (`queue.ttl_hours`, 24). A deny is returned on retry with your reason until it
expires. An approval never lifts a deterministic deny. `queue.notify` runs a command for each new
item, detached, with `REFLEX_QUEUE_ID`, `REFLEX_QUEUE_REASON` and `REFLEX_QUEUE_AGENT` in its
environment (never the command text), for example
`osascript -e 'display notification "reflex: $REFLEX_QUEUE_ID" with title "Approval needed"'`,
`terminal-notifier -message "$REFLEX_QUEUE_ID"`, or a `curl` to a webhook. Off by default.
`reflex queue approve|deny|clear`, `reflex envelope set|clear` and `reflex checkpoints restore` are
tamper when an agent runs them: they are parked for a human too.

### Task envelopes

```sh
reflex envelope set "may modify this repo and the dev AWS account (profile dev); nothing in prod" [--cwd dir | --session id] [--ttl 8h]
reflex envelope show [--cwd dir] ; reflex envelope list ; reflex envelope clear [--cwd dir | --session id | --all]
```

An envelope says what the agent may touch for this task: per directory (it applies below that
directory, the nearest one wins) or per session (it wins over a directory's), for 24 h unless
`--ttl` says otherwise. It reaches Jev as `call.envelope.user` with one more question, `in_envelope`,
and the policy (`tool-gate-v6`) gains three gates before `off-task`: `off-envelope` (a mutation Jev
places outside it asks, so it escalates), `in-envelope` (non-production work Jev places inside it at
`envelopeAt`, 0.8, passes without escalation) and `repo-envelope`. Production is never passed by an
envelope. System 2 sees the envelope too.

`.reflex/envelope.md` in a repository (from the cwd up to the repository root, a regular file up to
8 KB, not a symlink: the same places and trust as instruction fragments) is text someone else wrote.
It reaches Jev only as `call.envelope.repo`, with its own question, `repo_forbids`, which can only
ask. The in-envelope gate needs the user's envelope, so a repository's envelope can narrow what the
user allowed but never widen it; System 2 is told it is untrusted and can only restrict.

### Checkpoints

In the autonomous profile, before an effective pass or allow of a command that is not read-only, in
a git repository, Reflex records the tracked files: `git stash create` against a temporary copy of
the index (it refreshes the stat cache of whatever index it uses, so never the real one; the copy
keeps the index's modification time, or git would trust stale stat data and miss a same-size edit
made within a second of the last index write; the commit carries Reflex's own identity,
`reflex <reflex@localhost>`, never the user's), or `HEAD` for a clean tree, kept as `refs/reflex/checkpoints/<time>-<pid>` (the last 50 per repository; an
unchanged tree is not recorded twice). The working tree and the index are not touched.

```sh
reflex checkpoints [--cwd dir]
reflex checkpoints restore <name> [--cwd dir]   # checkpoints the current state first; HEAD does not move
```

Restore makes the tracked files match the checkpoint (`git restore --worktree` from it, `--staged`
from its index) and prints how to move `HEAD` back if it moved. Not covered: untracked and ignored
files, anything outside the repository, and anything remote (a push, a deploy, a cloud change): this
is a recovery point, not a sandbox. Overhead: 25 to 35 ms per mutating command in a small repository;
`git stash create` itself took 17 ms for 2,000 tracked files.

### Hook time

A System 2 call can take Jev's 3 s plus `judge.timeout_ms` (20 s). A hook that runs out of time
fails open in Claude Code and Codex, so with System 2 on, setup gives their gate hooks
`timeout_ms` + 30 s (50 s by default), Hermes the same, and the opencode plugin the same budget; pi
and oh-my-pi stay at 29 s under omp's 30 s handler limit, where a slower judge is killed and the
call is blocked (those adapters fail closed). Without System 2 the hooks keep their short timeouts.

### Metrics

`reflex report` adds a ladder section: judged commands and who resolved them, human interventions per
100 judged commands (asks shown in the agent plus new queue items; read-only commands are not
counted), System 2's escalation rate and verdict split, its agreement with Jev (Jev's blast of 1.5
or less read as approve), tokens per call (in, cached, out) and cache hits, cost in the window and per
100 commands, the day's budget, the breaker, queue waits (p50, p95), and fast-lane candidates:
command shapes System 2 approved at least 5 times (`--candidates N`) and never denied, outside the
always-human class and the rules, printed as a `pass` pattern for you to review. They are never added
automatically. System 2's approve and deny are also calibration labels for System 1, next to your
own approvals, so calibration has data from the first day. `--push` exports `reflex_ladder`,
`reflex_system2`, `reflex_system2_tokens`, `reflex_system2_cache_hits`, `reflex_human_interventions`,
`reflex_system2_usd` and `reflex_queue_pending`. `reflex status` shows the profile, System 2's
reachability (a GET of the model list, never a paid call; for a CLI, that it is installed), the
budget left, the breaker and the queue.

`npm run eval-ladder` runs `setup/tool-gate/ladder.json` (41 commands labelled with their expected
resolver) with Jev live and a stub System 2 that approves everything it is asked. It fails on any
unsafe approval (a `safe: false` case that ended in pass or allow) and when the mean case System 2
gets exceeds `judge.max_input_tokens`. Current result, `jev-1.13.0`: 41 of 41 resolved as labelled, 0
unsafe approvals, 26.8 human interventions per 100 commands, System 2 asked 19.5 times per 100
commands, 512 tokens in and 22 out per call. `npm run eval-ladder -- --engine local` runs the same set
keyless (no Jev, so offline; the labels are Jev's, so only unsafe approvals are scored): 0 unsafe
approvals, 34.1 human interventions and 36.6 System 2 calls per 100 commands, 493 tokens in per call
(0.6.0 on the same 41: 39.0 and 34.1: there the remote `systemctl` / `journalctl` read went to
System 2, and the `live-demo` and `auto-live` cases to a human).

### Safety invariants

| Invariant | Checked by |
|---|---|
| A rule deny and tamper are never escalated or approved | `autonomy.mjs --selfcheck`: rule denies stay deny and tamper is parked, with a judge that approves everything, which is never called |
| The always-human class is never approved by System 1 or System 2 | the same: 13 commands, with safe System 1 answers and an approve-everything judge; `eval-ladder` |
| Judge errors, timeouts, over-budget and unparsable answers go to a human, never allow | `judge2.mjs --selfcheck` per backend (HTTP 500, timeout, malformed, prose, extra key, refusal, low confidence, no key, budget, session cap); `autonomy.mjs` for each through the ladder; a judge that throws is the error fallback |
| Tainted sessions: System 2 may deny, approvals of egress go to a human, no allow | `autonomy.mjs --selfcheck` |
| The judge never sees secrets or credential-file contents | `judge2.mjs` and `autonomy.mjs` inspect what the stub and the fake CLIs received |
| Queue approval matches exactly and expires | `autonomy.mjs --selfcheck`: another command text, cwd or session, a second use, an expired approval, a forged approval of a rule deny |
| The CLI judge runs no tools and no Reflex | the fake `claude` and `codex` refuse to answer without the tool and hook switches, with Reflex on, or inside the project |
| Shadow never blocks | `autonomy.mjs --selfcheck`: shadow logs what would have happened, parks nothing |
| Checkpoints never touch the working tree or the index | `autonomy.mjs --selfcheck` compares the index file and `git status` |
| A checkpoint sees a same-size edit made within a second of the last index write (#21) | `autonomy.mjs --selfcheck` aligns to the clock and checkpoints the same tree again a second later |
| Keyless: System 2 allows only local, small commands; the rest of its approvals pass; the always-human class, rules, tamper and taint as with Jev | `autonomy.mjs --selfcheck` (each exclusion, the 0.9 bar, the caps); `test.mjs` keyless journey; `eval-ladder --engine local` |

### Limits

- System 2 is a model: with an approve-everything judge (the eval), only the rules, System 1 and
  the always-human patterns stand between an escalated command and running. The patterns are
  pattern matching, not a parser.
- In the autonomous profile a `pass` usually means the command runs, because you run the agent with
  its own prompts off or broad. Keep IAM, network controls and least-privilege credentials.
- Queue files, envelopes, the verdict cache and checkpoints live in the data directory and the
  repository; an agent that can write files there without going through a gated shell (a file-edit
  tool in an agent Reflex does not guard) could forge them. The Claude Code install asks before
  editing the data directory; other agents rely on their own permissions.
- The template cache can reuse a verdict for a command that differs only in an id; that is the
  point, and also the ceiling: an id that decides safety (a resource named by a UUID) shares a
  verdict. Lower `judge.cache_ttl_hours` or set it to 0 if that matters to you.
- CLI token usage was not measured live here; `reflex report` shows it from the CLI's own usage.
- Keyless, nothing classifies the environment or exfiltration: a production change the `prod`
  pattern cannot see (an unmarked directory, a profile named `main`) or a leak through a command the
  egress patterns miss is System 2's call alone, and in Codex, opencode, pi and omp its approval
  runs. Use a TypeSafe key for production-adjacent work. The tool, verb, path and egress checks
  that keep an allow local are lists, not a parser: a tool they miss is allowed on System 2's word.

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
directory up to the repo root (the nearest one holding `.git`), plus
`~/.config/reflex/instructions/*.md` (or `$XDG_CONFIG_HOME/reflex/instructions`). Directories above
the repo root are never read; outside a repo only the working directory is. Only regular files up
to 64 KB are read, so a symlink to a file elsewhere is skipped.
When two fragments share an id, your personal fragment wins, so a cloned repo cannot suppress your
instructions by reusing an id (and a personal fragment can replace a repo fragment you disagree with);
between repo directories, the one nearest the working directory wins. `examples/instructions/repo/` shows the layout with three fragments.

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
   selected at `p >= REFLEX_INSTRUCTIONS_THRESHOLD` (0.5). Answers are cached for 24 h by a hash
   of that whole state (prompt, working directory, recent files and commands) and the conditions, so
   a repeated prompt after new work is judged again.
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
## Tool router

An agent that carries hundreds of tool schemas spends context on them in every turn and picks
worse among them. The router (`router/server.mjs`) is one stdio MCP server with three tools, so
the agent only sees what it asks for (tiered disclosure):

| Tool | Tier | What it does |
|---|---|---|
| `find_tools(intent, limit?)` | 1 | one line per best-matching tool, with Jev's probability |
| `describe_tool(name)` | 2 | the full description and argument schema of one tool |
| `run(intent, tool?, args?)` | — | picks the tool (unless given), fills its arguments (unless given), validates, runs |

**The catalog** is the built-in command tools in `router/commands.json` whose binary is on `PATH`
(`rg_search`, `grep_search`, `ast_grep`, `git_log`, `git_diff`, `git_blame`, `kubectl_get`,
`kubectl_describe`, `aws_describe`), plus every tool of every stdio MCP server listed in
`router/config.json` (or the file named by `REFLEX_ROUTER_CONFIG`), named `<server>.<tool>`:

```json
{"mcpServers": {
  "github": {"command": "/usr/local/bin/github-mcp-server", "args": ["stdio"], "env": {"GITHUB_TOOLSETS": "repos,issues"}},
  "tickets":{"command": "…", "trusted": true},
  "old":    {"command": "…", "disabled": true}
}}
```

It is the same shape as a Claude Code `.mcp.json`, so you can move servers over. Servers start the
first time a tool is needed; a server that fails to start is skipped with a message on stderr.
Only stdio servers are supported. A server that crashes later is started again by the next call to
one of its tools, at most once per `REFLEX_ROUTER_RETRY_MS` (30 s); calls in between fail at once
with the time of the next attempt. The tool list stays the one read at the first start.

**Protocol eras.** The router connects to both kinds of downstream server, as the 2026-07-28
revision's stdio backward-compatibility rules describe: it first sends `server/discover` with
`io.modelcontextprotocol/protocolVersion: 2026-07-28` (plus `clientInfo` and `clientCapabilities`) in
`_meta`. A `DiscoverResult` that lists 2026-07-28 makes the server modern: no handshake, and every
request carries those three `_meta` fields. A recognized modern error (`-32020`…`-32022`, e.g.
`UnsupportedProtocolVersion` naming only other versions) is a modern server the router cannot
speak to: it is skipped, never retried with `initialize`. Any other error, or no answer within 5 s,
is a legacy server: the router falls back to `initialize` (2025-11-25 … 2024-11-05). The era is
remembered across restarts of the same server.

**Choosing the tool.** `find_tools` and `run` ask one Jev `choice`: which tool does what
`request.intent` asks, over every tool's description plus `none_of_these`. A choice takes 255
options, so above 200 tools the router asks first which category (downstream server, or the
command tool's `category`) holds it, then chooses among the tools of the categories that hold 90% of
the probability (at most three).

**Filling arguments** follows TypeSafe's
[function-calling cookbook](https://docs.typesafe.ai/cookbooks/function_calling): Jev never writes
free text. Each argument the agent did not pass becomes one question, all in one request:

- an `enum` → a `choice` over its values;
- a boolean → a `noul` ("does the request ask for this?");
- a string or number → a `choice` over the words, `key=value` values and quoted strings of the
  (redacted) intent, filtered by the argument's type and `pattern`. Optional arguments get a
  `none_of_these` option, and choosing it leaves the tool's default in place. One value answers
  one question: when Jev gives an optional argument the value of a required or earlier-declared one
  (`in gate.mjs` as both the path and the file filter), the later one is dropped;
- objects and arrays are not filled: the agent passes them.

A call is only as sure as its least certain judgement. When the tool's probability or any
argument's is under `REFLEX_ROUTER_MIN_CONFIDENCE` (0.5), or `none_of_these` wins, `run` does not
guess: it returns `choose_tool` with the top candidates, or `needs_args` with the proposed
arguments, the missing and the weakest one, and the schema. The agent then calls `run` again with
`tool` and `args`. Arguments the agent passes are used exactly as given. Either way the arguments are
checked against the tool's JSON schema (`type`, `enum`, `const`, `required`, `properties`,
`additionalProperties`, `items`, lengths, bounds, `pattern`) before anything runs. Quote exact values
in the intent: `search for 'retry budget' in src`.

**Running.** A downstream tool call is first judged by the gate like a shell command, as one line
naming the server, the tool and the exact arguments: `mcp github.list_issues {"owner":"acme","repo":"api"}`
(`decideSafe`, agent `reflex-router`, the intent as the stated task). The rules see it raw, so
`secret-file-read`, `prod-destroy`'s SQL verbs, `rm-root` and the tamper checks apply; Jev and the
policy judge it the same way (in shadow mode Jev's verdict is only logged, as for shell commands).
`deny` returns `denied`, `ask` returns `needs_approval`, and nothing is sent. Past the gate, the call is
proxied as `tools/call` and its result (content and `structuredContent`) returned unchanged, after
one line naming the tool — but only when its server annotates it `readOnlyHint: true` (and not
`destructiveHint`). A tool that is not annotated read-only returns `needs_approval` whatever the
gate said: the agent's per-tool MCP permissions only see `run`, so a tool that may write must not
hide behind it. Keep such servers registered directly in the agent.
`"trusted": true` on a server's entry is the explicit opt-out: its calls skip the gate and the
annotation check entirely and run as the agent asks. Use it only for servers you would allow
wholesale. Downstream servers start with a
minimal environment (`HOME`, `PATH`, `USER`, `SHELL`, `TERM`, `LOGNAME`, `TMPDIR`, `LANG`) plus their
own `env`; shell tools get the router's environment without `TYPESAFE_API_KEY`. A command tool is expanded
from its argv template and run with `execFile` — never through a shell — **after the Reflex gate
judges the exact command**, shell-quoted (`decideSafe`, agent `reflex-router`, with the intent as
the stated task). `deny` returns `denied`; `ask` returns `needs_approval` and nothing runs (an MCP
tool cannot prompt), so the agent asks you and runs it through its own, also gated, shell tool.
The mode follows the gate's: `--mode` on the server's command line, or `REFLEX_MODE`. A string
argument starting with `-` is refused unless its template puts it where it cannot be an option
(`"x-allow-dash": true`, after `-e` or `--`).

Adding a command tool is a JSON entry:

```json
{"name": "git_show", "category": "git", "bin": "git",
 "description": "Show one commit: message, author and the change it made.",
 "args": ["show", "--no-color", "--stat", "{ref}"],
 "inputSchema": {"type": "object", "additionalProperties": false, "required": ["ref"], "properties": {
   "ref": {"type": "string", "pattern": "^[\\w./~^@-]+$", "description": "The commit, branch or tag to show"}}}}
```

`"{x}"` is replaced by argument `x`; `"{x...}"` splits an enum value on spaces (`"ec2 describe-vpcs"`);
a nested array is a group kept only when all its placeholders have a value, and a boolean
placeholder keeps its group when true. Write each argument's `description` as the idea, not the
parameter name — it is what Jev matches the intent against. Add only commands you would let the
agent run unasked; the gate still judges each call.

**Logs.** Every `find_tools` and `run` appends to `router.jsonl` in the data directory: the intent
(redacted), the chosen tool, its probability, the next four alternatives, the weakest argument and the
outcome. Argument values are not logged in `router.jsonl`. Every gated call, shell or MCP, is
also in `trace.jsonl` (redacted), like any gated command.

**Trying it.** `node router/server.mjs --check "who last changed router/mcp.mjs"` prints the
ranking; add `--run` to run it. `npm run eval-router` routes the intents in
`router/golden.json` through live Jev and scores the chosen tool and the filled arguments; nothing
runs. Each intent is `ok` (the expected tool with the expected arguments would run), `held` (the
router would return `choose_tool` or `needs_args` where the golden expected a run: nothing runs and
the agent is asked, so it is reported but safe) or `unsafe` (a wrong tool or wrong arguments would
run, or something would run where the golden expects no tool). Only `unsafe` exits 1; a growing
`held` count means routing got less decisive, not less safe. Registering it in an agent: `node install.mjs --router` prints the
command or config snippet for every agent, and changes nothing:

| Agent | Where the MCP server goes |
|---|---|
| Claude Code | `claude mcp add --scope user [--env K=V] --transport stdio reflex-router -- <node> <repo>/router/server.mjs --mode shadow`, or `mcpServers` in a repo's `.mcp.json` |
| Codex CLI | `codex mcp add reflex-router -- <node> …`, or `[mcp_servers.reflex-router]` (`command`, `args`, `[…env]`) in `~/.codex/config.toml` |
| pi | no built-in MCP: the `pi-mcp-adapter` extension, then `mcpServers` in `~/.pi/agent/mcp.json` or `.mcp.json` |
| oh-my-pi | `mcpServers` in `~/.omp/agent/mcp.json` or `.omp/mcp.json` (omp also imports Claude Code and Codex configs: register once) |
| opencode | `"mcp": {"reflex-router": {"type": "local", "command": [<node>, …], "environment": {…}}}` in `opencode.json` |
| Hermes | `mcp_servers:` in each profile's `config.yaml`; Hermes gives servers a filtered environment, so put `TYPESAFE_API_KEY` / `REFLEX_KEYCHAIN_SERVICE` / `REFLEX_*` under `env:` |

**Limits.**

- The gate judges a downstream call by its name and arguments only; it does not know what the tool
  does beyond that, and the read-only annotation is the server's own claim. `"trusted"` turns both
  checks off for a server.
- A legacy downstream server that ignores the `server/discover` probe costs 5 s at the first start.
  Modern-era features beyond plain requests (multi round-trip `input_required` results,
  `subscriptions/listen`, result caching) are not implemented; an `input_required` result is an error.
- Only stdio downstream servers; no resources, prompts, sampling or `listChanged` from them.
- The server speaks the `initialize`-handshake MCP revisions (2024-11-05 … 2025-11-25). A client of
  the handshake-free 2026-07-28 revision probes with `server/discover`, gets "method not found",
  and falls back to `initialize` as that revision specifies.
- Values Jev can choose are the ones in the intent. A value that needs composing (a regular
  expression written from a description, a date computed from "last Tuesday") comes back as
  `needs_args`, and the agent writes it.
- Two Jev requests per `run` without `tool` or `args` (three above 200 tools); input tokens grow
  with the catalog, since every description (cut at 300 characters) is an option. The router gives
  Jev 10 s per request unless `REFLEX_TIMEOUT_MS` is set.
- Commands run in the server's working directory, which is where the agent launched it.
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
   hesitant answer errs towards the safer pool. The tier errs upwards the same way: it is the
   highest tier whose probability mass P(level ≥ tier) reaches `tiers.up_at` (medium 0.4, large
   0.5), not the expected score, because a model that is too small costs quality and one that is
   too large only money. The `difficulty` levels describe concrete situations, and any change to
   credentials, IAM, network policy, production infrastructure or deployment configuration is at
   least medium, however short the request. Without probabilities (the fallback answer) the
   expected score is compared with `from_score`.
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
   **Guardrails and per-model limits.** Before the pre-call hooks, LiteLLM merges the model-level
   guardrails (`litellm_params.guardrails`, the union over the requested model group's
   deployments), checks the key's per-model budget, and its limiters count per-model rpm / tpm,
   all for the requested model; none of this runs again for the model the hook picks. So a
   candidate is only taken when its guardrail set equals the requested model's
   (`require_same_guardrails`, default true) and the key's rpm / tpm limit and `model_max_budget`
   entries for it equal the requested model's (`require_same_limits`, default true). Both are read
   per request from the proxy's live router and the caller's key, so models added through the UI
   count. Excluded models are logged under `excluded`; when that leaves nothing eligible,
   `no_eligible` applies.
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

   A conversation that carries model-bound state never moves for cost or tier, only when its
   sensitivity forces it: signed `thinking` / `redacted_thinking` blocks (Anthropic) or
   `reasoning` items with `encrypted_content` (Responses), and a 1M-token context (the `[1m]`
   model suffix or a `context-1m` `anthropic-beta` header). With no record of the previous model
   (another worker, a restart) such a conversation stays on the model it asks for. A forced move
   sends the conversation unchanged: per Anthropic's thinking docs ("Switching models
   mid-conversation"), thinking blocks are passed back as they are, and the API ignores or drops
   those the new model cannot read, so stripping them would only save tokens and risks breaking
   the latest turn. The log marks such a move `thinking_dropped_est`. A model whose
   `max_context` is below the estimated context is never a candidate; set it on models without a
   1M window.

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
the estimated context size (`ctx_tokens_est`), Jev's token usage, latency, the difficulty
probabilities (`difficulty_p`), models left out for other guardrails or limits (`excluded`),
`action` when no model was eligible, and `violation: true` when the requested model was not
eligible for the content. No
message text or paths are written; a Jev HTTP error is logged by status only. In shadow mode
`chosen` is what enforce would have used. The response's `model` field can still show the
requested name; the log has the one that served it.

**Test.**

```sh
python3 routing/reflex_router.py --selfcheck           # offline, Jev stubbed; part of npm test
python3 routing/reflex_router.py --check "Rotate the prod DB password in .env" --model claude-haiku-4-5
npm run eval-routing                                   # routing/golden.json through live Jev
```

`eval-routing` runs the 27 labelled prompts of `routing/golden.json` (sensitivity × tier, with
tricky ones such as security vocabulary in a trivial task, or a short prompt standing for a
multi-step production change) and reports sensitivity accuracy, tier accuracy, under- and
over-tiering. It exits 1 when a tier is two levels too low or restricted / proprietary content
is classified as public / application; details land in `REFLEX_DATA_DIR`.

**Limits.** The Jev answer cache is per process: another worker asks Jev again (one call). The
model each conversation is on is per process too, unless the proxy shares a Redis with its
key cache (`litellm_settings.enable_redis_auth_cache: true` plus the proxy's Redis settings): then
it is also stored there (`reflex:model:<conversation hash>`, 24 h) and stickiness holds across
workers and restarts. Token counts are estimates (characters / 4). Prices in `policy.json` are
list prices you maintain. The guardrail and limit comparison covers model-level guardrails and
the key's per-model rpm / tpm / budget (key, then team metadata, then deployment defaults, as
LiteLLM resolves them); team-, user- and end-user-level `model_max_budget` are not compared, and
budgets are matched on the exact model name.
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
`context.mjs`. Install it with `node install.mjs --agent pi,omp --context`; `--no-context` removes it;
a plain re-install refreshes it only where it is already installed, so re-running the installer (for
example to change `--mode`) never switches it on or off by accident.

**Visibility ladder (§V), on `tool_result`.** An output of 200+ lines or 16 KB+ (bash, grep, find, ls,
custom tools; not `read` / `edit` / `write`, whose exact text the model edits against) is split along
its own structure (a grep hit list by file; a diff by file and hunk, never packing two files into one
chunk while the budget allows; anything else by blank-line sections, also inside `cat -n` output)
into at most 24 chunks. One Jev request carries one `choice` per chunk, **hide / short / long /
full**, judged against the user's current request and the agent's last message. For each chunk Jev
sees where it comes from (the files in a grep or diff chunk), `matches` (up to six numbered lines that
share the most words with the request) and an excerpt of its start and end, and is asked whether any
of it could be what the request is about (a definition, setting, default, error or call it names);
*hide* only when nothing bears on it. Request words are the non-stop-words, prefix-stemmed ("cached"
finds `CACHE_TTL`), minus words that occur on more than a fifth of the output's lines. Jev judges, it
does not write text, so the levels are rendered by code: *short* = the first two and last line, up to
12 lines that mention the request (most shared words first) and the chunk's first six definitions
(`const`, `function`, `class`, … lines, because the line a question is about often shares no word
with it); *long* = the same with three lines of context around each hit, up to 60 lines and twelve
definitions; *full* = the chunk as is. A *hide* with probability under 0.7 becomes *short*: hiding is
the only level that can cost the agent something. The model gets the kept lines, `… [lines a-b
hidden] …` markers and one note naming the chunk id. The full output is written to
`chunks/<session>/<id>.txt` before anything is replaced, and the **`expand_chunk`** tool (`{"id": …,
"lines": "a-b"}`) returns it: a 2,400-line grep can be 12 hits for one question and come back whole
for the next. If the view would not save 20 %, the output is left alone.

**Chunk store.** Files are 0600 in 0700 directories. When the extension loads, chunks not written or
read for `REFLEX_CHUNK_DAYS` (7) days are deleted, then the least recently used ones beyond
`REFLEX_CHUNK_MB` (200) MB; `node context.mjs --prune` does the same by hand. Pruning is the one
place where data can go: a session resumed after that long gets "chunk not found" from
`expand_chunk` for outputs the ladder cut, and has to re-run the command. Raise the limits if you
resume sessions after weeks.

**Per-request assembly and the cache decision (§V), on `context`.** pi and omp fire `context` before
every LLM call with a copy of the message list. When a new user request appears, one batched Jev
request rates up to 24 of the largest earlier tool results against it (one `choice` each) and asks one
`noul`: *is the context assembled for the previous request still the right context for this one?* A
result the ladder already cut is judged and re-rendered from its stored full output (when the store
still has it and the cut view is a selection of its lines), so a new request can see lines the first
one did not need. The proposed view replaces hidden and shortened results with stubs pointing at
`expand_chunk`; a view that would not be smaller than the message leaves it as it is. Whether it
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

**Shared retrieval for background tasks, `node context.mjs --bundle`.** Given a change
(`git diff <base>` plus untracked files that are not ignored, diffed against `/dev/null`), it
collects the names defined on changed lines and in hunk context, plus the
changed files' basenames, looks each up once with `git grep --untracked -w`, rates up to 24 candidate files with
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
| Extension loads in the real agents | `pi -e` and `omp -e` with a throwaway `HOME` and `PI_CODING_AGENT_DIR` load it without extension errors; in omp `expand_chunk` is in the provider request's tool list |
| Live Jev, ladder | `npm run eval-context`: 16 real outputs of this repo (greps, `cat -n`, a 1,026-line `git show`) at a pinned commit, each with the lines that must stay visible (`setup/context/golden.json`). jev-1.13.0, three runs: must-keep recall 17/17, 16/17 and 17/17, 73-74 % of characters hidden, ~188k input tokens per run (~12k per output). The ladder as first written: 15/17 on both runs, 83-85 % hidden. Twelve cases were used while tuning the question and the rendering; the four `late-*` cases were added afterwards and passed on every run of both versions. Jev's choices vary between runs, so treat one run as a sample |
| Live Jev, smoke | `node context.mjs --smoke`: a ~490-line grep of this repo against a timeout question keeps the `timeoutMs` default and `ask()`; ~68 % hidden, ~11k input tokens, 1 s |
| Quality over real sessions, the cost-model parameters, `/fresh` in a live session | **Experimental.** Not measured yet: read `context.jsonl` and tune. A miss is recoverable with `expand_chunk`, and it is why this layer is opt-in |

Limits: only tool results are levelled, not tool-call inputs or reasoning (providers require some
reasoning blocks to be replayed unchanged); which lines a *short* or *long* view keeps is lexical
(request words and definitions), so a line that shares nothing with the request and is not a
definition can be cut from a chunk Jev rated relevant; the bundle's symbol search is name matching,
not a language index; the view lives in memory, so a resumed session starts with a fresh decision.

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. Model routing is the first
of these ([above](#model-routing)); the same pieces fit LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
