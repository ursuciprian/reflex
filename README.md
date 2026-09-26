<h1 align="center"><img src="assets/wordmark.svg" alt="Reflex" width="320"></h1>

<p align="center">
  <a href="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml"><img src="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://www.npmjs.com/package/@ursuciprian/reflex"><img src="https://img.shields.io/npm/v/@ursuciprian/reflex" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="license: MIT"></a>
</p>

Pre-execution risk checks for coding agents. Reflex hooks into Claude Code, Codex CLI, pi,
oh-my-pi, opencode and Hermes, and decides for every shell command the agent wants to run whether
it can run, needs your confirmation, or is blocked. It also checks what the agent reads: web pages,
search results, MCP results, files from outside the project and network command output are scanned
for prompt injection before the agent acts on them.

Start locally without an account or API key. Deterministic rules handle known dangerous cases;
uncertain commands ask for review in enforce mode. Optional hosted classification uses
[TypeSafe Jev](https://docs.typesafe.ai), a small model that returns typed answers in under a
second, and a policy file you can edit turns those answers into a decision.

## Features

- Blocks destructive commands such as `rm -rf ~`, deletes against production, and force pushes to
  `main`, in shadow and enforce modes. Off disables the gate.
- Judges the rest in context: working directory, AWS profile, kube context, Terraform workspace,
  git branch, and what the agent said it was doing.
- Reads local scripts, make targets and package scripts before they run.
- Injection guard: finds text in tool results that is written to steer the agent (hidden Unicode,
  instructions in HTML comments or hidden elements, text addressed to an AI, markdown image
  exfiltration, encoded payloads). It warns the agent, or removes the text where the agent allows a
  hook to rewrite results, and makes the gate stricter for the rest of that session. In enforce
  mode it also blocks prompts that contain a pasted credential.
- Redacts secrets before anything leaves the machine or is logged.
- Shadow mode by default: deterministic rules enforce; other decisions are logged only.
- Local engine by default for new setups: no API key and no hosted classification.
- Experimental `--engine laya`: Jev's questions answered by a [Laya](https://huggingface.co/convaiinnovations/laya)
  checkpoint on this machine, nothing sent anywhere. Measured far below Jev on every golden set, so
  not recommended for enforcement ([GUIDE](docs/GUIDE.md#laya-local-system-1)).
- `reflex doctor` checks installation; `reflex status` shows configuration and observed hook events.
- Autonomous profile: uncertain commands go to a stronger model (System 2) before a human, and a
  human decides asynchronously through an approval queue, with task envelopes and git checkpoints.
- Optional: allow clearly safe commands without a prompt, deny duplicate subagent spawns, inject
  instructions only when they apply, route requests to models by sensitivity (LiteLLM), and trim
  large tool outputs (pi, oh-my-pi).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash
```

Or with a package runner:

```sh
npx @ursuciprian/reflex setup
pnpm dlx @ursuciprian/reflex setup
bunx @ursuciprian/reflex setup
yarn dlx @ursuciprian/reflex setup    # yarn 2+
```

Requirements: Node.js 18+ on macOS or Linux (including WSL). Native Windows is not supported yet.
To enable hosted classification, run `reflex setup --engine jev` with a
[TypeSafe API key](https://console.typesafe.ai/keys). macOS setup can store it in Keychain.

The installer copies the package to `~/.local/share/reflex`, links the `reflex` command into
`~/.local/bin`, and adds hooks to every supported agent it finds, in shadow mode. Pass options
after `bash -s --` or `setup`:

```sh
curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash -s -- --agents claude,codex
npx @ursuciprian/reflex setup --mode enforce
npx @ursuciprian/reflex setup --dry-run   # preview configuration changes
```

See [docs/SETUP.md](docs/SETUP.md) for all options, per-agent notes and uninstalling.

## Usage

```sh
reflex check "terraform apply -auto-approve" --cwd ~/infra/envs/prod   # judge one command
reflex scan page.html                                                  # check text for prompt injection
reflex report                                                          # decisions so far
reflex replay claude --since 7d                                        # what it would have done with past sessions
reflex doctor                                                          # local checks; no API calls
reflex status                                                          # configured vs observed hooks
reflex run "command" --cwd /path/to/work                                 # human terminal handoff
reflex setup --mode enforce                                            # start enforcing
reflex setup --profile autonomous                                      # System 2 and the approval queue
reflex queue                                                           # what waits for a human
reflex uninstall
```

A typical rollout: install in shadow mode, use your agents for a week, read `reflex report`,
adjust the user policy shown by `reflex status` if needed, then switch to enforce. Settings and
policy survive upgrades and uninstall. `reflex run` always enforces, asks on its controlling
terminal when needed, and refuses deterministic denies; it does not grant an agent permission.

## How it works

```
command
  |-- read-only (ls, git status, kubectl get, ...)          -> pass, no API call
  |-- rule match (rm -rf ~, prod delete, force push main)   -> deny or ask
  |-- rule match inside a script it runs                    -> deny or ask
  |-- known safe (go test, npm ci, git push origin feat/x)  -> pass, no API call
  `-- uncertain -> local: ask; Jev: questions + policy       -> pass, ask or deny
```

With the Jev engine enabled, Jev is asked:

| Question | Type | Meaning |
|---|---|---|
| `mutates` | probability | Changes state outside the working directory |
| `blast` | score 0 to 3 | Worst plausible impact if the command is wrong |
| `env` | choice | local, nonprod, production or unknown |
| `exfil` | probability | Sends secrets or private data somewhere external |
| `on_task` | probability | Matches what the agent said it was doing |
| `injection` | probability | Text in the command tries to influence the review |

Bundled defaults live in `setup/tool-gate/`. User overrides live in
`~/.config/reflex/tool-gate/` (or `$XDG_CONFIG_HOME/reflex/tool-gate/`); setup seeds `policy.json`
without replacing edits. Every decision is logged
with those versions to `~/.local/state/reflex/`.

By default Reflex only adds friction: it emits `ask` or `deny` and leaves `pass` to the agent's own
permission settings. In enforce mode, `--allow on` also lets it approve commands it judges clearly safe; see
[docs/GUIDE.md](docs/GUIDE.md#calibrated-allow).

## Autonomous agents

By default every uncertain command becomes a question for a person, so the person is the
bottleneck. The autonomous profile makes the human the last rung of a ladder instead of the first:

```
command
  |-- System 1: rules, read-only list, fast lane, Jev + policy     -> resolves most commands
  |-- would ask? System 2: a stronger model with the full context  -> approve, deny or human
  `-- human: the always-human class and what System 2 hands up     -> the approval queue
```

```sh
reflex setup --profile autonomous          # Jev (local without a key), enforce, calibrated allow, System 2, queue, checkpoints
reflex setup --profile autonomous --dry-run  # no TypeSafe key? it says so and goes keyless
reflex envelope set "may modify this repo and the dev AWS account (profile dev); nothing in prod"
reflex queue                               # list what waits; reflex queue approve <id> | deny <id>
reflex checkpoints                         # recovery points taken before mutations
```

- **System 2** is picked at setup, and setup says which: the `claude` CLI when it is installed
  (you are already signed in, so no extra key; it runs with its own system prompt replaced, no
  tools, hooks, MCP servers or CLAUDE.md, and a pinned model, about 3k input tokens and a few tenths
  of a cent a call), else the Anthropic Messages API when `ANTHROPIC_API_KEY`
  is set, else none. `codex exec` works when you name it (`--judge cli --judge-cli codex`), and so
  does any OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, LM Studio, OpenRouter, or a LiteLLM
  gateway): `--judge openai-compatible --judge-url URL --judge-model M`. An error, a timeout, an
  unreadable answer or a spent budget goes to a human, never to an approval.
- **Spend is small by design**: a case of at most 1,500 tokens (the static prompt first, so provider
  prompt caching can apply), a JSON verdict of about 100 tokens with no extended thinking, a verdict
  cache so a retry or the same command with another id never asks twice, optional cheaper tiers
  before the frontier model, daily and per-session caps, and a breaker that pauses System 2 when
  more than 30 % of the last hour's commands escalated.
- **Keyless**: without a TypeSafe key the profile uses the local engine, and what the local rules do
  not cover goes to System 2 instead of a human. With no second model behind it, System 2 alone
  allows only short commands whose effects stay in the working directory (no network, no cloud,
  cluster, database, deploy or install tool, no script it could not read in full, nothing under
  `~`); its other approvals leave the decision to the agent's own permissions. Measured on real
  history, System 2 then sees most non-read-only commands, so the daily cap is 300 calls
  ([GUIDE](docs/GUIDE.md#keyless-autonomy)).
- **Always human**: production changes, IAM and permission changes, writing secrets, destructive
  deletes, money and billing APIs, network egress after a suspected prompt injection, and anything a
  deterministic rule decided. Neither System 1 nor System 2 can approve these.
- **The approval queue** works with every agent: the agent gets a refusal that names a queue item
  and moves on to other work; once you approve it, the identical command in the same directory and
  session runs on the next try, once.
- **Task envelopes** tell Jev and System 2 what this task may touch, so work inside it resolves
  without escalation. A `.reflex/envelope.md` in a repository can only narrow that, never widen it.
- **Checkpoints**: before a mutating command runs in a git repository, the tracked files are
  recorded under `refs/reflex/checkpoints/` without touching the working tree or the index.
  This is not a sandbox: untracked files, other directories and remote systems are not covered.

`reflex report` shows human interventions per 100 commands, how often System 2 was asked and what it
said, how often it agreed with Jev, tokens per call, cache hits, cost per 100 commands and how long
queue items waited, and proposes fast-lane rules for commands System 2 keeps approving (you add them
by hand). See
[GUIDE: autonomous agents](docs/GUIDE.md#autonomous-agents).

## Supported agents

| Agent | Hook | How `ask` is shown |
|---|---|---|
| Claude Code | `PreToolUse` | Claude Code permission prompt |
| Codex CLI | `PreToolUse` | Blocked; human uses `reflex run` in their own terminal |
| pi, oh-my-pi | extension `tool_call` | Native confirm dialog |
| opencode | plugin `tool.execute.before` | Blocked; human uses `reflex run` in their own terminal |
| Hermes | `pre_tool_call` | Hermes approval prompt |
| Other | `bin/reflex-sh` as the shell | y/N on the terminal |

The injection guard reads tool results and prompts through each agent's own hooks, so what it can do
differs:

| Agent | Tool results | Prompts with a pasted credential |
|---|---|---|
| Claude Code | `PostToolUse` on web, MCP, `Read` and `Bash`: warn adds a note, block rewrites the result | `UserPromptSubmit`: blocked, reason shown |
| Codex CLI | `PostToolUse` on `Bash` and MCP tools: warn adds a note, block replaces the result with the reason and the cleaned text; web search is not hookable | `UserPromptSubmit`: blocked, reason shown |
| pi, oh-my-pi | extension `tool_result`: block rewrites the result, warn appends a note | extension `input`: dropped with a notification |
| opencode | plugin `tool.execute.after`: block rewrites the result, warn appends a note | `chat.message`: stopped with an error |
| Hermes | `post_tool_call` is observe-only: logged, and the note reaches the model on the next turn | cannot block; the model is told not to repeat it |
| Other | not covered | not covered |

The guard is a heuristic filter, not a sandbox: see [GUIDE: injection guard](docs/GUIDE.md#injection-guard).

Coverage is agent shell tools and the optional router's own calls. Installing an MCP server does
not intercept every tool in a client. Doctor cannot prove host trust or verify a native approval
dialog; run a harmless command in a fresh agent session and check status. Plain chat confirmation
does not unblock a Codex or opencode hook. See [setup](docs/SETUP.md) for manual steps and limits.

## Cost and latency

- Local mode never calls TypeSafe. Read-only, rule and known-safe commands need no API in either engine.
- A Jev call takes about 0.7 s and 1k input tokens, roughly 25,000 judged commands per dollar at
  TypeSafe's published price.
- With Jev in shadow mode the hook returns in about 30 ms and classification runs in the background.
- Identical commands in the same context are cached for 24 hours.

## Documentation

- [docs/SETUP.md](docs/SETUP.md): installation, configuration, per-agent setup, uninstalling
- [docs/GUIDE.md](docs/GUIDE.md): design, testing, tuning, rollout, metrics, data handling, limits
- [SECURITY.md](SECURITY.md): reporting vulnerabilities, known limits
- [CONTRIBUTING.md](CONTRIBUTING.md): development, tests, repository layout
- [CHANGELOG.md](CHANGELOG.md)

## Development

```sh
git clone https://github.com/ursuciprian/reflex.git && cd reflex
npm test                        # offline self-checks
npm run eval                    # golden set against the live API (needs a key)
npm run eval-injection          # injection golden set against the live API
node install.mjs --agent all    # hook this checkout into your agents
```

No runtime dependencies. The LiteLLM routing hook needs Python 3.9+.

## License

[MIT](LICENSE)
