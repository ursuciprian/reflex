# Contributing

Changes land through a pull request against `main`; nothing is pushed to `main` directly.

## Before you open a PR

```sh
npm test          # offline self-checks: no network, no API key, a few seconds
```

`npm test` runs the self-checks of every component (`policy`, `gate`, `instructions`, `install`,
`context`, `router`, the LiteLLM router) and is what CI runs on every PR.

The `eval` scripts are different: they call the live Jev API and cost tokens.

```sh
npm run eval              # setup/tool-gate/golden.json: 90 labelled commands
npm run eval-router       # router/golden.json: tool and argument choice, nothing is executed
npm run eval-routing      # routing/golden.json: model choice for 27 prompts
npm run eval-context      # setup/context/golden.json: what the visibility ladder keeps visible
npm run eval-instructions # examples/instructions/golden.json: which fragments load
```

They need `TYPESAFE_API_KEY`, they are non-deterministic (Jev's answers vary run to run), and they
are not run in CI. Run the one matching what you touched and paste the summary in the PR.

## Behaviour lives in JSON, not in code

`setup/tool-gate/` holds the rules, the questions, the policy thresholds, the subgoal rules and the
golden set; `setup/redact.json` the secret patterns; `routing/` and `router/` the routing and tool
catalogues. Most changes that alter a decision are a JSON edit, not a code edit.

When you change rules, questions, policy or redaction:

1. Add a case to `setup/tool-gate/golden.json` for the behaviour you want, before changing anything.
   `expect` is the outcome we want, not what the current policy does; `allow: true` marks a command
   that should be allow-eligible, `allow: false` one that must never be auto-allowed.
2. Run `npm run eval`. A `MISS` (a risky command judged too softly) fails the run and blocks the PR;
   an `over` (stricter than wanted) is friction to fix when it is common.
3. A surprising decision you see in a trace, in your own use or in an issue, becomes a golden case.

## Invariants a reviewer will hold you to

- **The gate can only tighten.** Nothing new may emit `allow` outside the calibrated allow gate, and
  that gate stays as narrow as the checks in `gate.mjs` make it: unseen code, unsandboxed retries,
  plan mode, commands without a stated intent, redacted commands and code Jev did not see never
  allow.
- **Errors fail towards `ask`.** In enforce mode every failure path — Jev down, timeout, unreadable
  setup file, incomplete answer, adapter crash — ends in the policy fallback, never in a pass.
- **Nothing unread is allowed.** A script a command runs is inspected before the command is judged;
  code the judge never saw is never allow-eligible.
- **Judged data is redacted first, and the redaction is shared.** `setup/redact.json` is read by
  both `gate.mjs` and `routing/reflex_router.py`; its `corpus` is asserted by both self-checks, so
  add a pattern *and* a corpus line together. Patterns must mean the same in JavaScript and Python.
- **A new agent integration is a new adapter, not a new decision path.** It calls the same core with
  the same rules, questions, policy and logs, and documents in the README table what `ask` and
  `allow` mean on a hook that cannot prompt.

## House rules

- No dependencies. Node 18+ stdlib for the `.mjs`, Python 3.9+ stdlib for the LiteLLM hook (a real
  dependency would have to be argued for in the PR).
- `npm test` stays offline, keyless and under a minute; it may use a throwaway `HOME` and a fake Jev
  server on localhost, never the network.
- Comments name the limitation instead of hiding it (what a pattern does not cover, what is
  heuristic). Match that style.
- The docs are three files with different jobs: README (what it is, install), `docs/SETUP.md`
  (install, configure, verify), `docs/GUIDE.md` (how it works, test, tune, limits). Update all three
  when a flag, a default or a limit changes.
- Do not rewrite git history: `setup/context/golden.json` pins commit `b41c8c1`, and
  `npm run eval-context` breaks if it stops existing.
- Keep the working tree free of generated state: logs, cache, chunk stores and bundles go under
  `~/.local/state/reflex` (`REFLEX_DATA_DIR`), never in the repo.

## Repository layout

| File | What it is |
|---|---|
| `gate.mjs` | The decision core and CLI: read-only detection, rules, redaction, Jev client, cache, logs, and the Claude Code / Codex / Hermes hook adapters |
| `instructions.mjs` | Conditional instructions: fragment discovery, path / keyword matching, one Jev request per prompt, and the Claude Code / Codex / Hermes prompt hooks |
| `eval-instructions.mjs` | Scores fragment selection against `examples/instructions/golden.json` with the live API |
| `examples/instructions/` | Example fragments (front end, billing, Terraform) in a fixture repo, and the golden set |
| `adapters/` | `pi.ts` (pi and oh-my-pi extension), `pi-context.ts` (pi / oh-my-pi context layer), `opencode.js` (opencode plugin) |
| `context.mjs` | Context layer core: visibility ladder, chunk store, per-request assembly and cache decision, `/fresh` recall, retrieval bundles |
| `bin/reflex` | The CLI: `setup` (what `curl` / `npx` / `pnpm dlx` / `bunx` run), `check`, `report`, `install`, `uninstall`, `test`, `eval`, `version` |
| `bin/reflex-sh` | Drop-in `bash -c` for agents without hooks |
| `bin/reflex-review` | Background cross-model review that consumes a retrieval bundle |
| `policy.mjs` | Policy evaluator: ordered gates over answers, no `eval`, no domain knowledge |
| `setup/tool-gate/` | `rules.json`, `questions.json`, `policy.json`, `golden.json`, `subgoals.json`: all behaviour lives here; `fixtures/` holds the scripts the golden set runs |
| `setup/redact.json` | The credential shapes and `KEY=` / `--password` patterns redacted before anything is judged or logged; shared by the gate and the model router, with a corpus both self-checks assert |
| `eval.mjs` | Runs the golden set through the real gate; exits 1 on any missed risk |
| `router/server.mjs` | Tool router: stdio MCP server (`find_tools`, `describe_tool`, `run`), Jev tool selection and argument filling, schema validation, gated shell execution, downstream MCP proxy |
| `router/mcp.mjs` | Newline-delimited JSON-RPC over stdio, server and client side (no SDK) |
| `router/commands.json` | Built-in command tools: name, description, argument schema, argv template |
| `router/config.json` | Downstream stdio MCP servers whose tools join the catalog (`mcpServers`, same shape as `.mcp.json`) |
| `router/golden.json` | Labelled intents for `npm run eval-router` (tool and arguments chosen by real Jev; nothing runs) |
| `router/test/` | Fake downstream MCP server and stubbed Jev for `npm test` |
| `install.mjs` | Adds / removes Reflex in each agent's config (`--agent claude,codex,pi,omp,opencode,hermes,all`; `--mode`, `--allow`, `--keychain`; `--context` / `--no-context` adds / removes the pi / omp context layer; `--router` prints how to register the tool router in each agent) |
| `install.sh` | The `curl` installer: fetches the package from npm and runs `reflex setup` |
| `report.mjs` | Summary, replay under a candidate policy, allow calibration from your approvals, Prometheus Pushgateway export |
| `dashboards/reflex.json` | Grafana dashboard for the pushed metrics |
| `routing/` | LiteLLM pre-call hook for security- and cost-aware model routing (`reflex_router.py`, `questions.json`, `policy.json`, `golden.json`, an example LiteLLM config) |
