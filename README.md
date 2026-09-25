<h1 align="center"><img src="assets/wordmark.svg" alt="Reflex" width="320"></h1>

<p align="center">
  <a href="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml"><img src="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://www.npmjs.com/package/@ursuciprian/reflex"><img src="https://img.shields.io/npm/v/@ursuciprian/reflex" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="license: MIT"></a>
</p>

Pre-execution risk checks for coding agents. Reflex hooks into Claude Code, Codex CLI, pi,
oh-my-pi, opencode and Hermes, and decides for every shell command the agent wants to run whether
it can run, needs your confirmation, or is blocked.

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
- Redacts secrets before anything leaves the machine or is logged.
- Shadow mode by default: deterministic rules enforce; other decisions are logged only.
- Local engine by default for new setups: no API key and no hosted classification.
- `reflex doctor` checks installation; `reflex status` shows configuration and observed hook events.
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
reflex report                                                          # decisions so far
reflex doctor                                                          # local checks; no API calls
reflex status                                                          # configured vs observed hooks
reflex run "command" --cwd /path/to/work                                 # human terminal handoff
reflex setup --mode enforce                                            # start enforcing
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

## Supported agents

| Agent | Hook | How `ask` is shown |
|---|---|---|
| Claude Code | `PreToolUse` | Claude Code permission prompt |
| Codex CLI | `PreToolUse` | Blocked; human uses `reflex run` in their own terminal |
| pi, oh-my-pi | extension `tool_call` | Native confirm dialog |
| opencode | plugin `tool.execute.before` | Blocked; human uses `reflex run` in their own terminal |
| Hermes | `pre_tool_call` | Hermes approval prompt |
| Other | `bin/reflex-sh` as the shell | y/N on the terminal |

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
node install.mjs --agent all    # hook this checkout into your agents
```

No runtime dependencies. The LiteLLM routing hook needs Python 3.9+.

## License

[MIT](LICENSE)
