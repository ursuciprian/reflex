# Guide

## Contents

1. [How a command is decided](#how-a-command-is-decided)
2. [Testing](#testing)
3. [Rolling out: shadow, tune, enforce](#rolling-out-shadow-tune-enforce)
4. [Changing behaviour](#changing-behaviour)
5. [Metrics](#metrics)
6. [Data handling](#data-handling)
7. [Safety properties and limits](#safety-properties-and-limits)
8. [Tool router](#tool-router)
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
   Shipped rules: `rm-root`, `prod-destroy`, `force-push-main`, `push-mirror` (deny); `tamper`, `destroy`,
   and — checked even before read-only detection — `secret-read` (the API key, secret stores) and
   `secret-file-read` (`~/.ssh/id_*` but not `.pub`, `~/.aws/credentials`, `.netrc`, `.pgpass`, `.env` / `.env.*` files but not `.env.example` and other templates, `kubectl get secret(s)`) (ask). It matches the text, so a commit message or `echo` that names `.env` also asks. Any mutating command that touches the Reflex checkout, its setup files or its logs is also an `ask`, wherever the repo was cloned.
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
  The tool router is the exception: it runs its command tools and its downstream MCP calls through
  the gate itself.
- Codex and opencode hooks cannot open a prompt, so an `ask` blocks with a reason telling the agent
  to get your confirmation. Codex passes the session directory as `cwd`, not a per-command
  `workdir`. Codex hooks must be trusted in `/hooks` before they run.
- Environment context comes from the agent's process environment. A command that switches
  profile inline (`AWS_PROFILE=prod aws …`) is still seen, because the command text is judged; a
  profile changed by a previous command in a persistent shell is not.
- Jev adds ~0.7 s in enforce mode to each command that reaches it. On one engineer's heavy
  infrastructure history, about one in five commands never needed the API; the rest are mostly
  inline scripts and multi-step remote commands.

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
Only stdio servers are supported.

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
runs. Registering it in an agent: `node install.mjs --router` prints the
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
- A downstream server that crashes stays unavailable until the router restarts. Downstream servers
  must speak a handshake revision (2025-11-25 or earlier); a modern-only (2026-07-28) server fails
  to connect and is skipped.
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

## Where this goes next

Reflex is the tool-gating slice of a wider decision layer: one engine (typed questions, a trace,
a policy file, a replayable report) reused for other decisions. The same pieces fit model routing
(a `choice` of small / medium / large before a request reaches the LLM gateway), LLM evals (a
`score` per dimension with an uncertain band escalated to a stronger judge), reranking (a
comparable `score` per retrieved document) and confidence gating (policy thresholds per task,
calibrated from the feedback log). Each is a new `setup/<name>/` directory and an integration
point; the engine does not change.
