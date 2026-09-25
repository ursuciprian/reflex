<h1 align="center"><img src="assets/wordmark.svg" alt="Reflex" width="320"></h1>

<p align="center">
  <a href="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml"><img src="https://github.com/ursuciprian/reflex/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://www.npmjs.com/package/@ursuciprian/reflex"><img src="https://img.shields.io/npm/v/@ursuciprian/reflex" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="license: MIT"></a>
</p>

Pre-execution risk checks for coding agents. Reflex hooks into Claude Code, Codex CLI, pi,
oh-my-pi, opencode and Hermes, and decides for every shell command the agent wants to run whether
it can run, needs your confirmation, or is blocked.

Deterministic rules handle the known dangerous cases. Everything else is classified by
[TypeSafe Jev](https://docs.typesafe.ai), a small model that returns typed answers in under a
second, and a policy file you can edit turns those answers into a decision.

## Features

- Blocks destructive commands such as `rm -rf ~`, deletes against production, and force pushes to
  `main`, in every mode.
- Judges the rest in context: working directory, AWS profile, kube context, Terraform workspace,
  git branch, and what the agent said it was doing.
- Reads local scripts, make targets and package scripts before they run.
- Redacts secrets before anything leaves the machine or is logged.
- Shadow mode by default: nothing changes until you have reviewed what it would have done.
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

Requirements: Node.js 18+ and a [TypeSafe API key](https://console.typesafe.ai/keys). On macOS the
installer offers to store the key in the Keychain; elsewhere, set `TYPESAFE_API_KEY`.

The installer copies the package to `~/.local/share/reflex`, links the `reflex` command into
`~/.local/bin`, and adds hooks to every supported agent it finds, in shadow mode. Pass options
after `bash -s --` or `setup`:

```sh
curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash -s -- --agents claude,codex
npx @ursuciprian/reflex setup --mode enforce
```

See [docs/SETUP.md](docs/SETUP.md) for all options, per-agent notes and uninstalling.

## Usage

```sh
reflex check "terraform apply -auto-approve" --cwd ~/infra/envs/prod   # judge one command
reflex report                                                          # decisions so far
reflex setup --mode enforce                                            # start enforcing
reflex uninstall
```

A typical rollout: install in shadow mode, use your agents for a week, read `reflex report`,
adjust thresholds in `setup/tool-gate/policy.json` if needed, then switch to enforce.

## How it works

```
command
  |-- read-only (ls, git status, kubectl get, ...)          -> pass, no API call
  |-- rule match (rm -rf ~, prod delete, force push main)   -> deny or ask
  |-- rule match inside a script it runs                    -> deny or ask
  |-- known safe (go test, npm ci, git push origin feat/x)  -> pass, no API call
  `-- Jev: six typed questions -> policy thresholds         -> pass, ask or deny
```

Jev is asked:

| Question | Type | Meaning |
|---|---|---|
| `mutates` | probability | Changes state outside the working directory |
| `blast` | score 0 to 3 | Worst plausible impact if the command is wrong |
| `env` | choice | local, nonprod, production or unknown |
| `exfil` | probability | Sends secrets or private data somewhere external |
| `on_task` | probability | Matches what the agent said it was doing |
| `injection` | probability | Text in the command tries to influence the review |

Rules, questions and policy live in `setup/tool-gate/` as versioned JSON. Every decision is logged
with those versions to `~/.local/state/reflex/`.

By default Reflex only adds friction: it emits `ask` or `deny` and leaves `pass` to the agent's own
permission settings. In enforce mode, `--allow on` also lets it approve commands it judges clearly safe; see
[docs/GUIDE.md](docs/GUIDE.md#calibrated-allow).

## Supported agents

| Agent | Hook | How `ask` is shown |
|---|---|---|
| Claude Code | `PreToolUse` | Claude Code permission prompt |
| Codex CLI | `PreToolUse` | Blocked with a request to confirm (Codex hooks cannot prompt) |
| pi, oh-my-pi | extension `tool_call` | Native confirm dialog |
| opencode | plugin `tool.execute.before` | Blocked with a request to confirm (plugins cannot prompt) |
| Hermes | `pre_tool_call` | Hermes approval prompt |
| Other | `bin/reflex-sh` as the shell | y/N on the terminal |

## Cost and latency

- Read-only, rule and known-safe commands never call the API.
- A Jev call takes about 0.7 s and 1k input tokens, roughly 25,000 judged commands per dollar at
  TypeSafe's published price.
- In shadow mode the hook returns in about 30 ms and the judgment runs in the background.
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
