# Changelog

All notable changes to Reflex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local setup without a TypeSafe account or key; explicit `--engine local|jev` and a setup preview.
- `reflex status` and `reflex doctor`, including JSON output, synthetic hook checks and separate
  evidence of real hook events.
- Durable user policy and settings that survive upgrades and uninstall.
- `reflex run` for a human terminal handoff where an agent cannot display an approval dialog.
- An isolated full-suite runner and onboarding/adapter integration checks; macOS CI coverage.

### Fixed

- Shadow mode descriptions now explain that deterministic rules still enforce.
- Codex and opencode no longer suggest that chat confirmation can unblock their hooks.
- Missing execution feedback is unknown, not rejection; pi records explicit declined approvals.
- Invalid engine/configuration cannot silently enable hosted classification.

## [0.2.0] - 2026-09-25

### Added

- The gate: read-only detection, deterministic rules, fast-lane commands, and six typed Jev questions
  (`mutates`, `blast`, `env`, `exfil`, `on_task`, `injection`) turned into pass / ask / deny by an
  ordered policy in `setup/tool-gate/policy.json`. Hooks for Claude Code, Codex CLI, pi, oh-my-pi,
  opencode and Hermes, plus `bin/reflex-sh` for agents without a hook system.
- Script inspection: the local script, make target or package script a command runs is read and
  judged before the command is; code Reflex cannot read (`npx` packages, imported modules,
  `NODE_OPTIONS`, …) is marked unseen and never allowed.
- Calibrated allow (`REFLEX_ALLOW`), opt-in: a command Jev judges clearly safe skips the prompt the
  agent's own permissions would require.
- Subgoal dedup: a subagent spawn that repeats a subgoal already launched in the session is denied
  with a reason naming the earlier one.
- Conditional instructions: `.reflex/instructions/*.md` fragments with a `when:` condition, selected
  per prompt by path, keyword and one Jev request.
- Tool router (`router/server.mjs`): a stdio MCP server with `find_tools`, `describe_tool` and `run`
  in front of built-in read-only shell commands and your own MCP servers; every call it makes goes
  through the gate.
- Model routing (`routing/reflex_router.py`): a LiteLLM pre-call hook that keeps restricted content on
  first-party frontier models and sends easy public work to the cheapest model that does the task.
- Context layer (`context.mjs`, `adapters/pi-context.ts`, opt-in, experimental): per-request chunk
  visibility, `expand_chunk`, `/fresh <goal>` restart with recall, retrieval bundles and
  `bin/reflex-review`.
- Golden sets and live evals for each layer (90 gate commands, 15 router intents, 27 routing prompts,
  16 context outputs, 20 instruction prompts); offline self-checks for every component.
- `report.mjs`: decision summary, replay under a candidate policy, allow calibration, Prometheus
  Pushgateway export, and `dashboards/reflex.json` for Grafana.
- Install with `curl -fsSL …/install.sh | bash` or `npx` / `pnpm dlx` / `bunx` / `yarn dlx
  @ursuciprian/reflex setup`: the package is copied to `~/.local/share/reflex`, the `reflex` command
  linked, the TypeSafe key optionally stored in the macOS Keychain, and every supported agent hooked
  in shadow mode, with `--mode enforce` and `--allow` to tighten later. `--keychain` records where
  the key lives; `reflex uninstall` removes everything.
- `publish.yml` publishes a `v*` tag to npm with provenance (`NPM_TOKEN` secret); `ci.yml` runs the offline self-checks on every pull request (Node 18 and 22, Python 3.9
  and 3.12).
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, this changelog and issue templates.

[0.2.0]: https://github.com/ursuciprian/reflex/releases/tag/v0.2.0
