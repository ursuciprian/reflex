# Changelog

All notable changes to Reflex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `LICENSE` (MIT) and the matching `license` field in `package.json`.
- `install.sh --registry npm|gh`: the default install path now pulls `@ursuciprian/reflex` from the
  public npm registry, which needs no token; `--registry gh` keeps the GitHub Packages path and its
  `read:packages` token.
- `.github/workflows/ci.yml`: the offline self-checks (`npm test`) run on every pull request, on
  Node 18 and 22 against Python 3.9 and 3.12.
- `SECURITY.md`, `CONTRIBUTING.md`, this file, and issue templates for a surprising gate decision,
  a bug and a feature request.

### Changed

- `publish.yml` publishes a tag to both registries: npmjs (needs the `NPM_TOKEN` repository secret)
  and GitHub Packages.
- README and `docs/SETUP.md` install through `curl` from the public repository instead of `gh api`,
  so a stranger without the GitHub CLI can install Reflex.
- Documentation defects fixed: duplicated and contradicting rows in the README file table and in
  SETUP's agent table, `GUIDE`'s stale golden-set count (65 → 90 cases), an unresolved section
  placeholder in the context-layer section, and the context-layer variables listed in the model
  routing table.

## [0.2.0] - 2026-09-25

### Added

- The gate: read-only detection, deterministic rules, fast-lane commands, and six typed Jev questions
  (`mutates`, `blast`, `env`, `exfil`, `on_task`, `injection`) turned into pass / ask / deny by an
  ordered policy in `setup/tool-gate/policy.json`. Hooks for Claude Code, Codex CLI, pi, oh-my-pi,
  opencode and Hermes, plus `bin/reflex-sh` for agents without a hook system.
- Script inspection: the local script, make target, package script or `npx` package a command runs is
  read and judged before the command is.
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
- `install.sh` / `install.mjs`: one command installs the package and wires up every supported agent
  found on the machine, in shadow mode, with `--mode enforce` and `--allow` to tighten later.

[Unreleased]: https://github.com/ursuciprian/reflex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ursuciprian/reflex/releases/tag/v0.2.0
