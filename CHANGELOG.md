# Changelog

All notable changes to Reflex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Autonomous profile (`reflex setup --profile autonomous`; `supervised` stays the default): an
  escalation ladder in which Jev resolves the confident majority, an uncertain decision goes to a
  stronger model (System 2, `judge2.mjs`), and a human decides asynchronously through an approval
  queue. Profiles are presets in `config.json`; flags beside a profile win; `--dry-run` prints the
  effective settings.
- System 2 backends: `cli` (the `claude` CLI already installed and signed in, run with no tools,
  hooks, MCP servers, CLAUDE.md or Reflex; `codex exec` when named), `anthropic` (Messages API),
  `openai-compatible` (OpenAI, Ollama, vLLM, LM Studio, OpenRouter, a LiteLLM gateway) and `none`.
  Setup picks `claude`, else `anthropic` with `ANTHROPIC_API_KEY`, else `none`, and says which.
  The CLI judge pins its model (`sonnet`) and adds `--bare` only with an API key; measured at about
  3,100 input tokens a call against 36,826 for a naive `claude -p`. Verdicts: the first JSON object in
  the answer, validated strictly; any error, timeout, refusal, invalid answer or spent budget goes to a human.
- Low System 2 spend: a verdict cache keyed on the command's template (ids as slots), no re-ask while
  a command waits in the queue, optional cheaper tiers (`judge.tiers`), a case capped at 1,500 tokens
  with the static prompt first (Anthropic `cache_control`), 100-token JSON verdicts without extended
  thinking, per-day and per-session caps on calls and estimated cost, and a breaker that pauses
  System 2 when more than 30 % of the last hour's commands escalated.
- Always-human class (`setup/tool-gate/escalation.json`, `escalation-v1`): rule outcomes, the `prod`,
  `prod-destroy`, `exfil` and `tainted-exfil` gates, and patterns for production mutations, IAM and
  permission changes, secrets writes, destructive deletes and money APIs; tainted egress needs a human
  to approve. Neither System 1 nor System 2 can approve them.
- `reflex queue` (list, show, approve, deny, clear) with an optional notification command; an approval
  matches the identical command, cwd and session, once, within its TTL.
- `reflex envelope` (set, show, list, clear): a task envelope per directory or session, fed to Jev
  (`in_envelope`, questions `tool-gate-q7`) and System 2; policy `tool-gate-v6` gains the
  `repo-envelope`, `off-envelope` and `in-envelope` gates. `.reflex/envelope.md` in a repository can
  only narrow (`repo_forbids`).
- `reflex checkpoints` (list, restore): recovery points under `refs/reflex/checkpoints/` before a
  mutating command in a git repository, without touching the working tree or the index.
- `reflex report`: human interventions per 100 commands, System 2's escalation rate, verdicts,
  agreement with Jev, tokens per call, cache hits, cost per 100 commands, queue waits, fast-lane
  candidates from repeated System 2 approvals (never added automatically); System 2 verdicts become
  calibration labels. `reflex status` shows the profile, System 2's reachability without a paid
  call, the budget, the breaker and the queue.
- `npm run eval-ladder`: 33 commands labelled with their expected resolver, Jev live and an
  approve-everything stub System 2; fails on an unsafe approval or an oversized case.

### Fixed

- Claude Code: the installer wrote `Write(path)` permission rules, which Claude Code ignores (and
  warns about); only `Edit(path)` rules are written now, and old `Write(...)` entries are removed.

## [0.4.0] - 2026-09-25

### Fixed

- A fresh install through the `curl` installer now starts with the local engine like `npx` / `pnpm dlx`
  / `bunx`; it used Jev (and asked for a key) because the package was already in place. Settings
  from 0.2.0 still keep Jev.

## [0.3.0] - 2026-09-25

### Added

- Logo, wordmark and social preview image (`assets/`); the README opens with the wordmark.

- Injection guard (`guard.mjs`, `setup/injection/`): tool results from the web, MCP servers, files
  outside the project and network commands are scanned for prompt injection (deterministic
  detectors in both engines; with Jev, one request of three typed questions per chunk) and a policy
  turns the result into pass, warn or block. Warn adds a note for the agent; block removes the
  offending text where the agent lets a hook rewrite results (Claude Code `updatedToolOutput`, pi and
  oh-my-pi `tool_result`, opencode `tool.execute.after`) and sends the strongest signal available
  elsewhere (Codex `decision: block`, Hermes a note on the next turn).
- Taint: after a warn or block in enforce mode, the gate is stricter for the rest of that session
  (network egress asks, calibrated allow is off, lower ask thresholds via the policy flag
  `taintStrict`). New `tainted` rules in `rules.json` (`rules-v10`) and taint gates in
  `tool-gate-v5`; `reflex setup` adds the gates, params and flags a user `policy.json` from an
  earlier setup lacks, and says which, without changing or reordering the user's own.
- Credentials pasted into a prompt are blocked in enforce mode (Claude Code, Codex, pi, oh-my-pi,
  opencode), named by key type and never logged; `setup/redact.json` gains `names`.
- `reflex report` summarises the guard: results by source, outcome and attack, tainted sessions and
  blocked credential prompts, as counts.
- `reflex scan <file|->` checks text by hand; `npm run eval-injection` runs a 53-case golden set
  (precision, recall, exit 1 on a missed high-severity injection); `reflex doctor` probes each
  installed guard hook; `REFLEX_GUARD` / `"guard"` set the guard's mode on its own.
- Local setup without a TypeSafe account or key; explicit `--engine local|jev` and a setup preview.
- `reflex status` and `reflex doctor`, including JSON output, synthetic hook checks and separate
  evidence of real hook events.
- Durable user policy and settings that survive upgrades and uninstall.
- `reflex run` for a human terminal handoff where an agent cannot display an approval dialog.
- An isolated full-suite runner and onboarding/adapter integration checks; macOS CI coverage.

### Changed

- With System 2 on, the gate hooks get the judge's timeout plus 30 s (Claude Code, Codex, Hermes,
  opencode; pi and oh-my-pi up to 29 s), since a hook timeout lets the command through.
- Rules `rules-v11`: `reflex queue approve|deny|clear`, `reflex envelope set|clear` and
  `reflex checkpoints restore` are tamper; `reflex status`, `queue list|show`, `envelope show` and
  `checkpoints list` are fast lane.

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

[Unreleased]: https://github.com/ursuciprian/reflex/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ursuciprian/reflex/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ursuciprian/reflex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ursuciprian/reflex/releases/tag/v0.2.0
