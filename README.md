# Reflex

A fast, auditable risk gate for the shell commands a coding agent wants to run.

Coding agents run hundreds of shell commands a day. Most are harmless; a few can delete a
production database, push over `main`, or post your credentials to a paste site. Allowlists
cannot tell `terraform apply` in a scratch directory from the same command in `envs/prod`.
Reflex can, because it judges what the command means in context — and it stays cheap and
fast because it only asks a model when plain code cannot decide.

Reflex runs as a **pre-execution hook** in the coding agents your team already uses, and asks
[TypeSafe](https://docs.typesafe.ai)'s **Jev** — a System One model that returns typed judgments
and probabilities in well under a second — instead of a large LLM.

| Agent | Hook point | `ask` becomes |
|---|---|---|
| Claude Code | `PreToolUse` hook on `Bash` | Claude Code's own permission prompt |
| Codex CLI | `PreToolUse` hook on `Bash` (`~/.codex/hooks.json`) | a block telling the agent to get your confirmation (Codex hooks cannot prompt) |
| pi, oh-my-pi | extension, `tool_call` event on `bash` | the agent's native confirm dialog; blocked when there is no UI |
| opencode | plugin, `tool.execute.before` on `bash` | a block telling the agent to get your confirmation (plugins cannot prompt) |
| Hermes | `pre_tool_call` shell hook on `terminal` | Hermes' own approval prompt, keyed per command |
| anything else | `bin/reflex-sh` as the shell (`reflex-sh -c "<cmd>"`) | a y/N prompt on the terminal; refused without one |

All of them call the same decision core with the same rules, questions, policy and logs.

**Model routing** (`routing/`): the same engine as a LiteLLM pre-call hook. One Jev call per request
judges how sensitive the conversation is and how hard the task is; `routing/policy.json` keeps
restricted content (secrets, env and infra config, credentials, proprietary research) on first-party
frontier models, sends easy public work to the cheapest model, and keeps a conversation on its model
when switching would cost more than it saves. Shadow by default. See [docs/GUIDE.md](docs/GUIDE.md#model-routing).
**Context layer (pi and oh-my-pi, opt-in, experimental).** The same Jev client also decides what the
model *sees*: a large tool output is cut, per request, to the chunks that matter (hide / short / long /
full; the full text is kept and returned by an `expand_chunk` tool); earlier outputs are re-levelled
when the request changes, but only when that beats keeping the provider's prompt cache; `/fresh <goal>`
restarts with only the relevant old context; and one retrieval pass over a git change feeds read-only
background tasks such as `bin/reflex-review`. See [docs/GUIDE.md](docs/GUIDE.md#context-layer-pi-and-oh-my-pi).

```
agent wants to run a command
   │
   ├─ read-only? (ls, git status, kubectl get, ssh host 'tail log' …) ─────────► pass, ~30 ms, no API call
   ├─ deterministic rules (rm -rf ~, prod deletes, force-push main …) ─────────► deny / ask, always enforced
   ├─ fast lane (go test, npm ci, git push origin feat/x …) ───────────────────► pass, no API call
   └─ Jev: 6 typed questions about the command, its environment and the
      agent's stated intent ──► policy thresholds ──► pass / ask / deny
```

**Tool router (optional).** `router/server.mjs` is an MCP server that puts three tools —
`find_tools`, `describe_tool`, `run` — in front of a whole catalog: built-in read-only shell tools
(ripgrep, git log/diff/blame, kubectl get, aws describe …) and every tool of the MCP servers you
list in `router/config.json`. Jev picks the tool and fills its arguments from the agent's intent,
and hands back candidates instead of guessing when it is unsure. Every call it makes, shell or
downstream MCP, goes through the gate first (unless you mark a server `"trusted"`). See [GUIDE → Tool router](docs/GUIDE.md#tool-router).

**The gate can only tighten.** It emits `ask` or `deny`, never `allow`, so your existing
permission rules stay authoritative and a model can never authorize anything on its own.

**Conditional instructions.** Reflex can also load agent instructions only when they apply. Put
fragments in `.reflex/instructions/*.md`, each with a `when:` condition such as *"the task touches
billing"* and optional `paths:` / `keywords:`. On every prompt, Reflex checks the paths and keywords
first, then asks Jev one yes/no question per remaining fragment, all in a single request (~0.7 s).
The fragments that apply are injected into that turn. The instructions that apply are added again
on every prompt, so compaction cannot drop them, and the rest stay out of the context. See
[GUIDE: conditional instructions](docs/GUIDE.md#conditional-instructions) and `examples/instructions/`.

## What Jev is asked

| Question | Type | Meaning |
|---|---|---|
| `mutates` | noul (probability) | Does it change state outside the working directory? |
| `blast` | score 0–3 | Worst plausible impact if it is wrong |
| `env` | choice | local / nonprod / production / unknown |
| `exfil` | noul | Does it send secrets or private data somewhere external? |
| `on_task` | noul | Does it match what the agent said it was doing? |
| `injection` | noul | Does the command text try to talk its way past review? |

The policy (`setup/tool-gate/policy.json`) turns those answers into a decision with ordered,
tunable gates — for example *deny production changes with blast ≥ 2.7*, *ask when data may
leave the machine*, *ask when a mutating command does not match the stated task*.

## Quick start

```sh
git clone https://github.com/ursuciprian/reflex.git && cd reflex
export TYPESAFE_API_KEY=...          # from https://console.typesafe.ai/keys — see docs/SETUP.md
npm test                             # offline self-checks, no API calls
node gate.mjs --check "terraform apply -auto-approve" --cwd ~/infra/envs/prod
npm run eval                         # 63 labelled commands through the real gate (~31k tokens)
node install.mjs --agent all         # hook into every supported agent found here, shadow mode
```

Shadow mode changes nothing the agent does: deterministic rules still apply, and Jev judges
every other mutating command in the background and logs what it *would* have done. After a
week, `node report.mjs` shows the decisions, and `node install.mjs --mode enforce` turns them on.

## Documentation

- [docs/SETUP.md](docs/SETUP.md) — TypeSafe account and key, install, verify, configure, uninstall
- [docs/GUIDE.md](docs/GUIDE.md) — how it works, testing, tuning, rollout, metrics, data handling, limits

## Files

| File | What it is |
|---|---|
| `gate.mjs` | The decision core and CLI: read-only detection, rules, redaction, Jev client, cache, logs, and the Claude Code / Codex / Hermes hook adapters |
| `instructions.mjs` | Conditional instructions: fragment discovery, path / keyword matching, one Jev request per prompt, and the Claude Code / Codex / Hermes prompt hooks |
| `eval-instructions.mjs` | Scores fragment selection against `examples/instructions/golden.json` with the live API |
| `examples/instructions/` | Example fragments (front end, billing, Terraform) in a fixture repo, and the golden set |
| `adapters/` | `pi.ts` (pi and oh-my-pi extension), `opencode.js` (opencode plugin); both carry the gate and the instructions |
| `adapters/` | `pi.ts` (pi and oh-my-pi extension), `pi-context.ts` (pi / oh-my-pi context layer), `opencode.js` (opencode plugin) |
| `context.mjs` | Context layer core: visibility ladder, chunk store, per-request assembly and cache decision, `/fresh` recall, retrieval bundles |
| `bin/reflex-sh` | Drop-in `bash -c` for agents without hooks |
| `bin/reflex-review` | Background cross-model review that consumes a retrieval bundle |
| `policy.mjs` | Policy evaluator: ordered gates over answers, no `eval`, no domain knowledge |
| `setup/tool-gate/` | `rules.json`, `questions.json`, `policy.json`, `golden.json` — all behaviour lives here |
| `eval.mjs` | Runs the golden set through the real gate; exits 1 on any missed risk |
| `report.mjs` | Summary, replay under a candidate policy, Prometheus Pushgateway export |
| `install.mjs` | Adds / removes Reflex (gate and instructions) in each agent's config (`--agent claude,codex,pi,omp,opencode,hermes,all`) |
| `install.mjs` | Adds / removes Reflex in each agent's config (`--agent claude,codex,pi,omp,opencode,hermes,all`); `--router` prints how to register the tool router in each agent |
| `router/server.mjs` | Tool router: stdio MCP server (`find_tools`, `describe_tool`, `run`), Jev tool selection and argument filling, schema validation, gated shell execution, downstream MCP proxy |
| `router/mcp.mjs` | Newline-delimited JSON-RPC over stdio, server and client side (no SDK) |
| `router/commands.json` | Built-in command tools: name, description, argument schema, argv template |
| `router/config.json` | Downstream stdio MCP servers whose tools join the catalog (`mcpServers`, same shape as `.mcp.json`) |
| `router/golden.json` | Labelled intents for `npm run eval-router` (tool and arguments chosen by real Jev; nothing runs) |
| `router/test/` | Fake downstream MCP server and stubbed Jev for `npm test` |
| `install.mjs` | Adds / removes Reflex in each agent's config (`--agent claude,codex,pi,omp,opencode,hermes,all`; `--context` / `--no-context` adds / removes the pi / omp context layer) |
| `dashboards/reflex.json` | Grafana dashboard for the pushed metrics |
| `routing/` | LiteLLM pre-call hook for security- and cost-aware model routing (`reflex_router.py`, `questions.json`, `policy.json`, an example LiteLLM config) |

Node 18+, no dependencies. The router needs Python 3.9+ (stdlib) inside a LiteLLM proxy.

## Cost and latency

- Read-only commands, rules and fast-lane commands never call the API.
- A Jev call takes ~0.7 s and ~1k input tokens. At TypeSafe's published price
  ($0.042 per million input tokens, output free) that is about 25,000 judged commands per dollar.
- In shadow mode nobody waits: the hook returns in ~30 ms and Jev runs in the background.
- Repeated identical commands in the same context are served from a 24 h answer cache.
