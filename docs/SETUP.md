# Setup

About ten minutes. You need Node 18+ and at least one supported agent: Claude Code, Codex CLI,
pi, oh-my-pi (omp), opencode or Hermes.

## 1. Get a TypeSafe API key

Reflex calls TypeSafe's System One API with the Jev model. From the
[official quick start](https://docs.typesafe.ai/introduction/quickstart):

1. Sign in to the TypeSafe console: <https://console.typesafe.ai/playground>
2. Create an API key on the keys page: <https://console.typesafe.ai/keys>
3. Check it works:

   ```sh
   export TYPESAFE_API_KEY=...   # paste the key; do not commit it anywhere
   curl -s -X POST https://api.typesafe.ai/v1/systemone \
     -H "Authorization: Bearer $TYPESAFE_API_KEY" -H "Content-Type: application/json" \
     -d '{"state": "rm -rf build/", "model": "jev-1.13.0",
          "questions": {"destructive": {"type": "noul", "instructions": "Does this shell command delete data?"}}}'
   ```

   You should get `{"model": "...", "answers": {"destructive": {"type": "noul", "noul": 0.9...}}, "usage": {...}}`.
   `401` means the key is wrong; `429` / `529` mean rate-limited or overloaded (retry shortly).

Reference: [HTTP API](https://docs.typesafe.ai/api), [models and limits](https://docs.typesafe.ai/models)
(currently `jev-1.13.0`, 64k tokens per request, 1,200 requests/minute),
[legal / data processing](https://docs.typesafe.ai/legal).

### Where to keep the key

Hooks and plugins inherit the environment the agent was started with. Either:

- **Environment** — `export TYPESAFE_API_KEY=...` in the shell profile you start Claude Code from
  (or load it from your password manager there); or
- **macOS Keychain** (no key in any file):

  ```sh
  security add-generic-password -s typesafe-api-key -a "$USER" -w   # prompts for the key
  ```

  Reflex reads the item named in `REFLEX_KEYCHAIN_SERVICE` (default `typesafe-api-key`).

Never put the key in `settings.json`, the repo, or shell history.

## 2. Get Reflex and check it

```sh
git clone https://github.com/ursuciprian/reflex.git ~/src/reflex
cd ~/src/reflex
npm test                                   # offline: policy + gate self-checks
node gate.mjs --check "git push --force origin main"                       # a rule, no API call
node gate.mjs --check "aws iam attach-role-policy --role-name ci --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
npm run eval                               # the golden set through the live API
```

`--check` prints the decision, the rule that fired, where it came from (`read-only`, `rule`,
`fast-lane`, `jev`, `fallback`) and Jev's raw answers. If a Jev call fails it prints the error and
the policy's fallback decision (`ask`).

## 3. Install the hooks (shadow mode)

```sh
node install.mjs --agent all                 # every supported agent found on this machine
node install.mjs --agent claude,codex        # or pick
```

Every file it edits is backed up next to itself first (`*.bak-<timestamp>`). Re-running replaces
Reflex's own entries only; other hooks and plugins are left alone. The hook commands use the
absolute path of the Node that ran `install.mjs`; pass `--node /path/to/node` to pin another.

| Agent | What `install.mjs` does | After installing |
|---|---|---|
| Claude Code | `~/.claude/settings.json`: `PreToolUse` hook on `Bash` (`gate.mjs --claude`), `PostToolUse` / `PostToolUseFailure` / `PermissionDenied` hooks (`--claude-post`), a `UserPromptSubmit` hook for conditional instructions (`instructions.mjs --claude`), and permission rules that make Claude Code ask before editing the Reflex checkout, its logs, your personal instruction fragments (`~/.config/reflex`) or its own settings | restart sessions |
| Codex CLI | `~/.codex/hooks.json`: `PreToolUse` + `PostToolUse` on `^Bash$`, and `UserPromptSubmit` (`instructions.mjs --codex`) | open Codex, run `/hooks` and **trust** the Reflex hooks — untrusted hooks do not run |
| pi | `~/.pi/agent/extensions/reflex.ts` (gate on `tool_call`, instructions on `before_agent_start`) | restart pi |
| oh-my-pi | `~/.omp/agent/extensions/reflex.ts` (same file) | restart omp |
| opencode | `~/.config/opencode/plugins/reflex.js` (gate on `tool.execute.before`, instructions on `chat.message` + `experimental.chat.system.transform`) | restart opencode |
| Hermes | prints a `hooks:` block with `pre_tool_call`, `post_tool_call` and `pre_llm_call` (Hermes config is YAML, so you paste it) | add it to each profile's `config.yaml`, then `hermes hooks list` to accept it |

The instruction hooks do nothing until you add fragments (`.reflex/instructions/*.md` in a repo, or
`~/.config/reflex/instructions/`); see [GUIDE: conditional instructions](GUIDE.md#conditional-instructions).

For an agent with no hook system, point its shell setting at `bin/reflex-sh`: it behaves like
`bash`, but judges every `-c` command first. Set `REFLEX_AGENT=<name>` so the logs say which agent
it was.

## 4. Verify in a real session

In a new agent session ask it to run something harmless but mutating, e.g.
`npm install left-pad` in a scratch directory. Then:

```sh
node report.mjs            # should show 1 judged command, source "jev", mode "shadow"
node report.mjs --list pass
```

Logs live in `~/.local/state/reflex/` (`trace.jsonl`, `feedback.jsonl`, `instructions.jsonl`, `cache.json`).

A quick check that a rule blocks in each agent, even in shadow mode: in an empty scratch
directory ask the agent to run `git push --force origin main`. It must be refused with
`reflex (rule): force push or delete of main/master`.

## 5. Switch to enforce (after the shadow period)

```sh
node install.mjs --agent all --mode enforce     # or --mode off to disable everything, rules included
```

`REFLEX_MODE` in the environment overrides the installed mode for one session, e.g.
`REFLEX_MODE=enforce claude` to try enforce without changing the install.

## Configuration

All optional.

| Variable | Default | Meaning |
|---|---|---|
| `TYPESAFE_API_KEY` | — | API key (or use the Keychain item) |
| `REFLEX_MODE` | installed `--mode`, else `shadow` | `off` · `shadow` (rules enforce, Jev logs only) · `enforce` |
| `REFLEX_MODEL` | `jev-1.13.0` | Pinned model; `jev-latest` follows TypeSafe's current version |
| `REFLEX_TIMEOUT_MS` | `3000` | Budget for one Jev call, retry included; on timeout the policy fallback applies |
| `REFLEX_SETUP_DIR` | `./setup/tool-gate` | Directory with rules / questions / policy / golden |
| `REFLEX_DATA_DIR` | `~/.local/state/reflex` | Trace, feedback, cache, eval results |
| `REFLEX_KEYCHAIN_SERVICE` | `typesafe-api-key` | macOS Keychain item holding the key |
| `REFLEX_API_URL` | TypeSafe System One endpoint | Override for a proxy |
| `REFLEX_INSTRUCTIONS_THRESHOLD` | `0.5` | Jev probability at which a conditional instruction fragment is injected |
| `REFLEX_INSTRUCTIONS_MAX_CHARS` | `6000` | Most fragment text injected per prompt; whole fragments are dropped, never cut |
| `XDG_CONFIG_HOME` | `~/.config` | Personal fragments are read from `$XDG_CONFIG_HOME/reflex/instructions/` |

## Optional: Grafana

Push a snapshot of the metrics to a Prometheus Pushgateway, e.g. every five minutes from cron:

```sh
*/5 * * * * cd ~/src/reflex && /usr/local/bin/node report.mjs --push http://localhost:9091 >/dev/null
```

Import `dashboards/reflex.json` into Grafana (it asks for the Prometheus data source) or drop it
into a provisioned dashboards folder. Metrics carry a `user` label, so one Pushgateway can serve a
team.

## Uninstall

```sh
node install.mjs --agent all --uninstall
rm -rf ~/.local/state/reflex        # optional: the logs
```
