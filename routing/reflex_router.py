#!/usr/bin/env python3
"""Reflex routing: a LiteLLM pre-call hook that picks the model for a request by how sensitive its
content is and how hard it is, with one Jev call.

  litellm_settings: {callbacks: ["reflex_router.proxy_handler_instance"]}   (this file next to config.yaml)
  python3 routing/reflex_router.py --selfcheck          offline tests, Jev stubbed
  python3 routing/reflex_router.py --check "<prompt>" [--model claude-opus-5]   one live decision
  python3 routing/reflex_router.py --smoke              live Jev over a small labelled prompt set

Order: family of the requested model -> secret shapes / sensitive paths (a floor) -> cache -> Jev
-> policy (sensitivity pool, models the caller's key may use, difficulty tier, cheapest; none
eligible: policy no_eligible) -> stickiness (large contexts stay put).
REFLEX_ROUTING_MODE: off | shadow (default: decide in the background, log, keep the requested model)
| enforce (wait up to the latency budget, rewrite data["model"]). Stdlib only; litellm is imported
to subclass its CustomLogger and, inside the proxy, for its key-access check.
"""
import asyncio
import functools
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # the selfcheck and the CLI run without litellm
    CustomLogger = object

HERE = Path(__file__).resolve().parent
ENV = os.environ
CONFIG = {
    "api": ENV.get("REFLEX_API_URL", "https://api.typesafe.ai/v1/systemone"),
    "model": ENV.get("REFLEX_MODEL", "jev-1.13.0"),
    "mode": ENV.get("REFLEX_ROUTING_MODE", "shadow"),
    "policy": ENV.get("REFLEX_ROUTING_POLICY", str(HERE / "policy.json")),
    "questions": ENV.get("REFLEX_ROUTING_QUESTIONS", str(HERE / "questions.json")),
    "redact": ENV.get("REFLEX_REDACT", str(HERE.parent / "setup" / "redact.json")),
    "data": ENV.get("REFLEX_DATA_DIR", str(Path(ENV.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "reflex")),
    "keychain": ENV.get("REFLEX_KEYCHAIN_SERVICE", "typesafe-api-key"),
}
# The request types that carry a conversation. Embeddings, images, files etc. are never routed.
ROUTED = {"completion", "acompletion", "text_completion", "atext_completion",
          "anthropic_messages", "aanthropic_messages", "responses", "aresponses"}
# python.org builds on macOS ship without a CA bundle; certifi (a LiteLLM dependency) fills the gap.
try:
    import certifi
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = None
ROTATE_BYTES = 50 * 1024 * 1024
MAX_CHARS = 1_000_000          # text scanned per request; beyond this the tail is what matters


def load(path):
    return json.loads(Path(path).read_text())


def sha(v):
    return hashlib.sha256((v if isinstance(v, str) else json.dumps(v, sort_keys=True)).encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------------------------
# Redaction: the patterns in setup/redact.json, shared with gate.mjs; both selfchecks run its corpus.
# re.ASCII makes \w, \b and case folding match JavaScript's. Loaded on first use, so a missing file
# fails routing (the request keeps its model), never the proxy's start.
@functools.cache
def redaction():
    spec = load(CONFIG["redact"])
    return ([re.compile(p, re.ASCII) for p in spec["shapes"]],
            [(re.compile(c["pattern"], re.ASCII | (re.I if "i" in c["flags"] else 0)), re.sub(r"\$(\d+)", r"\\g<\1>", c["replace"]))
             for c in spec["context"]], spec["corpus"])


def redact(s):
    shapes, context, _ = redaction()
    out = str(s or "")
    for rx in shapes:
        out = rx.sub("<redacted>", out)
    for rx, repl in context:
        out = rx.sub(repl, out)
    return out


def has_secret(s):
    # Shapes only: the keyword patterns also match prose like "max_tokens: 100".
    return any(rx.search(s) for rx in redaction()[0])


# ---------------------------------------------------------------------------------------------
# What a request is about. One reader for the three shapes a coding agent sends: chat completions
# (messages), Anthropic messages (system + messages with blocks) and Responses (instructions + input).
SKIP_KEYS = {"type", "role", "id", "tool_use_id", "call_id", "data", "image_url", "source", "signature",
             "cache_control", "file_data", "image"}
REMINDER = re.compile(r"<system-reminder>[\s\S]*?</system-reminder>")
PATH_RE = re.compile(r"(?<![\w:/.])[~.\w-]*(?:/[\w.@-]+)+/?|(?<![\w/.])\.env(?:\.[\w-]+)?\b|\b[\w-]+\.(?:pem|key|tfvars|tfstate|p12)\b")
# The agent's working directory, as Claude Code ("Primary working directory: /x") and Codex
# ("<cwd>/x</cwd>") state it. Paths under it are the repo; everything else is outside.
CWD_RE = re.compile(r"(?:working directory:\s*|<cwd>\s*)(/[^\s<]+)", re.I)


def text_of(x):
    """Every string a model would read, minus binary payloads and bookkeeping keys."""
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return "\n".join(filter(None, (text_of(v) for v in x)))
    if isinstance(x, dict):
        return "\n".join(filter(None, (text_of(v) for k, v in x.items() if k not in SKIP_KEYS)))
    return ""


def user_text(content):
    """What a person typed: text parts only, so a tool result sent as a user turn does not count."""
    if isinstance(content, str):
        return REMINDER.sub("", content).strip()
    if isinstance(content, list):
        return REMINDER.sub("", "\n".join(p.get("text", "") for p in content
                                          if isinstance(p, dict) and p.get("type") in ("text", "input_text"))).strip()
    return ""


def features(data):
    items = data.get("messages") or data.get("input") or []
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    items = [m for m in items if isinstance(m, dict)]
    system = text_of(data.get("system")) or text_of(data.get("instructions")) or \
        "\n".join(text_of(m.get("content")) for m in items if m.get("role") in ("system", "developer"))
    users = [m for m in items if m.get("role") == "user"]
    last = next((t for m in reversed(users) if (t := user_text(m.get("content")))), "")
    tools = [t.get("name") or (t.get("function") or {}).get("name") or t.get("type")
             for t in data.get("tools") or [] if isinstance(t, dict)]
    convo = text_of(items)
    whole = (system + "\n" + convo)[-MAX_CHARS:]
    paths = sorted({p for p in PATH_RE.findall(whole) if len(p) > 3})
    first = user_text(users[0].get("content")) if users else last
    cwd = CWD_RE.search(whole)
    return {
        "last": last, "system": system, "tools": [t for t in tools if t], "paths": paths,
        "cwd": cwd.group(1).rstrip("/") if cwd else None,
        "turn": len(users), "secret": has_secret(whole),
        # An estimate, labelled _est wherever it appears. ponytail: chars / 4; a tokenizer per model
        # family if the switch maths ever needs better than that.
        "ctx_tokens_est": (len(system) + len(convo) + len(json.dumps(data.get("tools") or []))) // 4,
        # LiteLLM sets litellm_session_id from x-*-session-id headers and Anthropic metadata.user_id;
        # otherwise the first user message and system prompt identify the conversation.
        "conv": str(data.get("litellm_session_id") or sha([system[:2000], first[:2000]])),
        "pinned": bool(data.get("previous_response_id")),   # server-side context lives with the old model
    }


def path_view(p, f, policy):
    """What Jev sees of a path. policy paths_to_jev: full | shape | shape_outside_repo (default).
    A shape is the file name plus flags, so the directory layout outside the repo stays local."""
    mode = policy.get("paths_to_jev", "shape_outside_repo")
    if mode == "full":
        return p
    cwd = f.get("cwd")
    rel = "." if p.rstrip("/") == cwd else p[len(cwd) + 1:] if cwd and p.startswith(cwd + "/") else p
    inside = not rel.startswith(("/", "~")) and ".." not in rel.split("/")
    if inside and mode == "shape_outside_repo":
        return rel
    flags = ([] if inside else ["outside repo"]) + \
        (["sensitive"] if any(re.search(rx, p, re.I) for rx in policy["sensitivity"]["restricted_paths"]) else [])
    return ".../" + p.rstrip("/").rsplit("/", 1)[-1] + (f" [{', '.join(flags)}]" if flags else "")


def jev_state(f, spec, policy):
    paths = list(dict.fromkeys(redact(path_view(p, f, policy)) for p in f["paths"][:200]))
    return {spec["item_key"]: {"message": redact(f["last"])[-2000:], "system_summary": redact(f["system"][:400]),
                               "system_chars": len(f["system"]), "tools": f["tools"][:60],
                               "paths": paths[:40], "turn": f["turn"]},
            spec["context_key"]: spec["context"]}


# ---------------------------------------------------------------------------------------------
# Jev. Same key lookup as gate.mjs: TYPESAFE_API_KEY, else the macOS Keychain item.
def api_key():
    if ENV.get("TYPESAFE_API_KEY"):
        return ENV["TYPESAFE_API_KEY"].strip()
    if sys.platform == "darwin":
        r = subprocess.run(["security", "find-generic-password", "-s", CONFIG["keychain"], "-w"],
                           capture_output=True, text=True, timeout=1.5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    raise RuntimeError(f'no API key: set TYPESAFE_API_KEY or keychain item "{CONFIG["keychain"]}"')


def ask(state, questions, timeout_s):
    """One Jev call -> (answers, usage). Raises on any failure; the caller falls back."""
    t0 = time.monotonic()
    body = json.dumps({"state": state, "model": CONFIG["model"], "questions": questions}).encode()
    for attempt in (0, 1):
        req = urllib.request.Request(CONFIG["api"], body, {"Authorization": f"Bearer {api_key()}",
                                                           "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=max(0.1, timeout_s - (time.monotonic() - t0)), context=TLS) as r:
                payload = json.load(r)
            return payload.get("answers") or {}, payload.get("usage") or {}
        except urllib.error.HTTPError as e:
            # 429 rate limited, 529 overloaded: one quick retry if the budget allows
            if e.code in (429, 529) and attempt == 0 and time.monotonic() - t0 < timeout_s / 2:
                time.sleep(0.25)
                continue
            # The status only: an error body may quote the request, and this text reaches the log.
            raise RuntimeError(f"HTTP {e.code}") from None


# ---------------------------------------------------------------------------------------------
# Policy: pure functions over answers, request features and policy.json.
def family_of(model, policy):
    """The family whose models (or aliases, such as a gateway's own auto router) include `model`.
    A model the policy does not list is never routed, so a newer model is not quietly swapped for a
    listed one."""
    return next((name for name, fam in policy["families"].items()
                 if resolve(model, fam) or model in fam.get("aliases", [])), None)


def resolve(model, fam):
    """claude-haiku-4-5-20251001 and claude-opus-5[1m] are the policy's claude-haiku-4-5 and claude-opus-5."""
    hits = [m for m in fam["models"] if model == m or model.startswith(m)]
    return max(hits, key=len) if hits else None


def classify(answers, f, policy):
    """answers + deterministic floors -> (sensitivity, tier, needs_tools, why)."""
    s, t = policy["sensitivity"], policy["tiers"]
    order = s["order"]
    sa = answers["sensitivity"]
    sens, why = sa["choice"], []
    p = sa.get("probabilities") or {}
    if order.index(sens) < order.index("restricted") and \
            p.get("restricted", 0) + p.get("proprietary", 0) >= s["restricted_at"]:
        sens, why = "restricted", why + ["restricted probability"]
    floor = "restricted" if f["secret"] else next(
        ("restricted" for path in f["paths"] for rx in s["restricted_paths"] if re.search(rx, path, re.I)), None)
    if floor and order.index(sens) < order.index(floor):
        sens, why = floor, why + ["secret in conversation" if f["secret"] else "sensitive path"]
    score = answers["difficulty"]["score"]
    tier = max((name for name, at in t["from_score"].items() if score >= at), key=t["order"].index, default=t["order"][0])
    tools = bool(f["tools"]) and answers["needs_tools"]["noul"] >= policy["needs_tools_at"]
    return sens, tier, tools, why


def eligible(fam, sens, tools, policy, ctx_est=0):
    """Models whose tags the sensitivity requires, with tools when needed, and a context window
    (max_context, optional) that fits the estimated context."""
    need = policy["sensitivity"]["pools"][sens]["require"]
    return [m for m, i in fam["models"].items() if all(i.get(k) for k in need) and (not tools or i.get("tools", True))
            and ctx_est <= i.get("max_context", float("inf"))]


def pick(fam, pool, tier, policy):
    """Cheapest model at or above the tier; if none reaches it, the strongest eligible one."""
    rank = policy["tiers"]["order"].index
    ok = [m for m in pool if rank(fam["models"][m]["tier"]) >= rank(tier)]
    if ok:
        return min(ok, key=lambda m: (rank(fam["models"][m]["tier"]), fam["models"][m]["price_in"]))
    return max(pool, key=lambda m: (rank(fam["models"][m]["tier"]), -fam["models"][m]["price_in"])) if pool else None


def stay_or_switch(prev, new, pool, f, fam, policy):
    """Paper §II.A: a route change makes the new model reprocess the whole context. Returns (model, why)."""
    if not prev or prev == new:
        return new, None
    p = resolve(prev, fam)
    if p is None or p not in pool:
        return new, "previous model not eligible for this content"
    rank = policy["tiers"]["order"].index
    if rank(fam["models"][new]["tier"]) > rank(fam["models"][p]["tier"]):
        return new, "harder turn: moving up a tier"
    if f["pinned"]:
        return prev, "sticky: server-side context (previous_response_id)"
    st, ctx = policy["stickiness"], f["ctx_tokens_est"]
    old_in, new_in = fam["models"][p]["price_in"] / 1e6, fam["models"][new]["price_in"] / 1e6
    saving = (ctx * st["cache_read_factor"] + st["turn_tokens"]) * (old_in - new_in) * st["remaining_turns"]
    rebuild = ctx * new_in
    if saving > rebuild:
        return new, f"switch: saves ${saving:.4f} over {st['remaining_turns']} turns, rebuild ${rebuild:.4f}"
    return prev, f"sticky: rebuild ${rebuild:.4f} >= saving ${saving:.4f} ({ctx} context tokens, est.)"


# ---------------------------------------------------------------------------------------------
STICKY_TTL_S = 24 * 3600


def key_lists(model, key):
    """The key's own model list: the check outside a proxy."""
    allowed = list(getattr(key, "models", None) or [])
    return not allowed or model in allowed or "all-proxy-models" in allowed


async def may_call(model, key):
    """Whether the caller's key may use `model`. LiteLLM authorises the requested model before the
    pre-call hooks and never re-checks after them, so a rewrite gets LiteLLM's own check here: the
    one it runs for a key's model-group alias (key and team models, wildcards, access groups, team
    members, projects)."""
    if key is None:
        return True
    try:
        from litellm.proxy.auth.auth_checks import can_key_call_resolved_model
        from litellm.proxy.proxy_server import llm_router
    except ImportError:     # outside a proxy (CLI, selfcheck)
        return key_lists(model, key)
    try:
        await can_key_call_resolved_model(model=model, llm_model_list=llm_router.model_list if llm_router else None,
                                          valid_token=key, llm_router=llm_router)
        return True
    except Exception:
        return False


class ReflexRouter(CustomLogger):
    def __init__(self, ask_fn=ask, mode=None, may_call_fn=may_call):
        if CustomLogger is not object:
            super().__init__()
        self.ask, self.mode, self.may_call = ask_fn, mode, may_call_fn
        # ponytail: per-process dicts. The Jev cache stays per process (a miss costs one Jev call). The
        # model each conversation is on also goes to LiteLLM's Redis when the proxy shares one (see
        # prev_model), so stickiness survives a request landing on another worker.
        self.cache, self.convs, self.tasks = {}, {}, set()

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        mode = self.mode or CONFIG["mode"]
        if mode == "off" or call_type not in ROUTED or not isinstance(data.get("model"), str):
            return data
        try:
            f, requested = features(data), data["model"]
        except Exception as e:     # a routing bug never breaks a request
            print(f"reflex routing: {type(e).__name__}: {e}", file=sys.stderr)
            return data
        redis = getattr(cache, "redis_cache", None)
        if mode != "enforce":
            # Shadow: nobody waits. The decision runs after the request is on its way.
            task = asyncio.get_running_loop().create_task(self.decide(f, requested, user_api_key_dict, redis))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return data
        d = await self.decide(f, requested, user_api_key_dict, redis, apply=True)
        if d.get("block"):
            return d["block"]       # a string: LiteLLM rejects the request with it (HTTP 400)
        data["model"] = d["applied"]
        return data

    async def decide(self, f, requested, key=None, redis=None, apply=False):
        t0 = time.monotonic()
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": "enforce" if apply else "shadow",
               "conv": sha(f["conv"]), "turn": f["turn"], "ctx_tokens_est": f["ctx_tokens_est"], "requested": requested,
               "chosen": requested, "applied": requested, "source": None, "reason": None, "error": None}
        try:
            policy, spec = load(CONFIG["policy"]), load(CONFIG["questions"])
            rec["policy_version"], rec["qset"] = policy["version"], spec["version"]
            fam_name = family_of(requested, policy)
            if fam_name is None:
                rec.update(source="skip", reason="model not in any routing family")
                return rec
            fam = policy["families"][fam_name]
            answers, rec["source"] = await self.answers(f, spec, policy, rec)
            sens, tier, tools, why = classify(answers, f, policy)
            req = resolve(requested, fam)
            # Eligible for the content, and callable with this key (the requested model already passed).
            pool = [m for m in eligible(fam, sens, tools, policy, f["ctx_tokens_est"])
                    if m == requested or await self.may_call(m, key)]
            chosen = pick(fam, pool, tier, policy)
            rec.update(family=fam_name, sensitivity=sens, tier=tier, needs_tools=tools, floors=why or None,
                       answers={k: a.get("choice", a.get("score", a.get("noul"))) for k, a in answers.items()},
                       violation=(req is not None and req not in pool) or None)
            if chosen is None:
                ne = policy.get("no_eligible", {})
                fb, action = ne.get("model"), ne.get("action", "block")
                if action == "keep":
                    rec.update(action="keep", reason=f"no model in {fam_name} is eligible for {sens}; kept")
                    return rec
                if action == "fallback_model" and fb and await self.may_call(fb, key):
                    chosen, reason = fb, f"no model in {fam_name} is eligible for {sens}: fallback_model"
                else:
                    rec.update(action="block", reason=f"no model in {fam_name} this key may use is eligible for {sens}")
                    if apply:
                        rec.update(applied=None, block=f"Reflex routing blocked this request: no model this key may use in "
                                   f"'{fam_name}' is cleared for {sens} content (policy {policy['version']}).")
                    return rec
            else:
                prev = await self.prev_model(f["conv"], redis)
                chosen, sticky = stay_or_switch(prev, chosen, pool, f, fam, policy)
                reason = sticky or f"{sens}/{tier}: cheapest eligible"
            if req is not None and resolve(chosen, fam) == req:
                chosen = requested      # same model: keep the requested name (claude-opus-5[1m], a dated id)
            rec.update(chosen=chosen, reason=reason)
            if apply:
                rec["applied"] = chosen
            return rec
        except Exception as e:
            rec.update(source="error", error=f"{type(e).__name__}: {e}"[:200], reason="internal error; kept")
            return rec
        finally:
            rec["latency_s"] = round(time.monotonic() - t0, 3)
            await self.remember(f["conv"], rec["applied"], redis)
            log(rec)

    async def prev_model(self, conv, redis):
        if redis is not None:
            try:
                if v := await redis.async_get_cache(f"reflex:model:{sha(conv)}"):
                    return v
            except Exception:
                pass
        return self.convs.get(conv)

    async def remember(self, conv, model, redis):
        self.convs[conv] = model
        while len(self.convs) > 5000:
            self.convs.pop(next(iter(self.convs)))
        if redis is not None and model:
            try:
                await redis.async_set_cache(f"reflex:model:{sha(conv)}", model, ttl=STICKY_TTL_S)
            except Exception:
                pass

    async def answers(self, f, spec, policy, rec):
        state = jev_state(f, spec, policy)
        key = sha([state, spec["version"], CONFIG["model"]])
        rec["state_sha"] = key
        hit = self.cache.get(key)
        if hit and time.time() - hit[0] < policy["cache_ttl_s"]:
            return hit[1], "cache"
        try:
            answers, rec["usage"] = await asyncio.wait_for(
                asyncio.to_thread(self.ask, state, spec["questions"], policy["latency_budget_ms"] / 1000),
                policy["latency_budget_ms"] / 1000)
            missing = [q for q in spec["questions"] if not isinstance(answers.get(q), dict) or
                       answers[q].get("choice", answers[q].get("score", answers[q].get("noul"))) is None]
            if missing:
                raise RuntimeError(f"incomplete answer: missing {', '.join(missing)}")
        except Exception as e:
            fb = policy["fallback"]
            rec["error"] = f"{type(e).__name__}: {e}"[:200]
            return {"sensitivity": {"choice": fb["sensitivity"]}, "difficulty": {"score": fb["difficulty"]},
                    "needs_tools": {"noul": 1.0}}, "fallback"
        self.cache[key] = (time.time(), answers)
        while len(self.cache) > 2000:
            self.cache.pop(next(iter(self.cache)))
        return answers, "jev"


def log(rec):
    """routing.jsonl: hashes, labels and numbers only, never message text or paths."""
    try:
        d = Path(CONFIG["data"])
        d.mkdir(parents=True, exist_ok=True)
        p = d / "routing.jsonl"
        if p.exists() and p.stat().st_size > ROTATE_BYTES:
            p.rename(d / f"routing.{int(time.time() * 1000)}.jsonl")
        with p.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError as e:
        print(f"reflex routing: cannot log ({e})", file=sys.stderr)


proxy_handler_instance = ReflexRouter()


# ---------------------------------------------------------------------------------------------
def selfcheck():
    import tempfile
    from types import SimpleNamespace

    async def listed(model, key):
        return key_lists(model, key)
    Router = functools.partial(ReflexRouter, may_call_fn=listed)    # same result with or without litellm
    fails = []

    def ok(c, m):
        if not c:
            fails.append(m)
            print("FAIL", m, file=sys.stderr)

    # redaction: setup/redact.json's corpus, the exact outputs gate.mjs's selfcheck also asserts
    for c in redaction()[2]:
        ok(redact(c["in"]) == c["out"], f"redact corpus: {c['in'][:40]!r} -> {redact(c['in'])!r}")
    ok(has_secret("key AKIAABCDEFGHIJKLMNOP") and not has_secret("max_tokens: 100, password field"), "secret shapes only")

    # the three request shapes
    chat = {"model": "claude-opus-5", "messages": [
        {"role": "system", "content": "You are a coding agent."},
        {"role": "user", "content": "Fix the flaky test in src/app/test_api.py"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": [{"type": "text", "text": "<system-reminder>noise</system-reminder>and bump deps"}]}],
        "tools": [{"type": "function", "function": {"name": "Bash"}}]}
    f = features(chat)
    ok(f["last"] == "and bump deps" and f["system"].startswith("You are") and f["tools"] == ["Bash"], "chat shape")
    ok("src/app/test_api.py" in f["paths"] and f["turn"] == 2 and not f["secret"], "chat paths / turns")
    anth = {"model": "claude-sonnet-5", "system": [{"type": "text", "text": "Claude Code"}], "tools": [{"name": "Read"}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "Read the config"}]},
                         {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "Read", "input": {"file_path": "/repo/.env"}}]},
                         {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "AWS_KEY=AKIAABCDEFGHIJKLMNOP"}]}]}
    f = features(anth)
    ok(f["last"] == "Read the config" and f["system"] == "Claude Code", "anthropic: tool result is not the user's message")
    ok("/repo/.env" in f["paths"] and f["secret"], "anthropic: paths and secrets from tool traffic")
    resp = {"model": "gpt-5.6-terra", "instructions": "codex", "input": [{"role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "previous_response_id": "resp_1"}
    f = features(resp)
    ok(f["last"] == "hi" and f["system"] == "codex" and f["pinned"], "responses shape")
    ok(features({"model": "x", "input": "just text"})["last"] == "just text", "responses string input")
    ok(features(chat)["conv"] == features({**chat, "messages": chat["messages"][:2]})["conv"], "conversation id stable across turns")
    ok(features({**chat, "litellm_session_id": "s1"})["conv"] == "s1", "session id from LiteLLM wins")

    # what Jev sees of paths
    policy = load(CONFIG["policy"])
    cc = {"model": "claude-opus-5", "system": "You are Claude Code.\nPrimary working directory: /Users/me/src/app\n",
          "messages": [{"role": "user", "content": "compare /Users/me/src/app/lib/db.py, src/x.go, "
                        "/Users/me/infra/envs/prod/rds.tf, ~/.aws/credentials and ../other/secret.txt from /Users/me/src/app"}]}
    f = features(cc)
    seen = jev_state(f, {"item_key": "r", "context_key": "c", "context": ""}, policy)["r"]["paths"]
    ok(f["cwd"] == "/Users/me/src/app", f"cwd from the system prompt ({f['cwd']})")
    ok("lib/db.py" in seen and "src/x.go" in seen and "." in seen, f"repo paths kept, relative ({seen})")
    ok(".../rds.tf [outside repo, sensitive]" in seen and ".../credentials [outside repo, sensitive]" in seen
       and ".../secret.txt [outside repo, sensitive]" in seen, f"outside paths as shapes ({seen})")
    ok(not any("/Users/me" in p or "infra" in p for p in seen), "no layout outside the repo reaches Jev")
    ok(features({"model": "gpt-5.6-sol", "input": [{"role": "user", "content": "<cwd>/w/r</cwd> hi"}]})["cwd"] == "/w/r", "codex cwd")
    ok(path_view("/Users/me/infra/main.tf", f, {**policy, "paths_to_jev": "full"}) == "/Users/me/infra/main.tf", "full paths option")
    ok(path_view("src/x.go", f, {**policy, "paths_to_jev": "shape"}) == ".../x.go", "shape option")

    # policy
    fam = policy["families"]["claude"]
    fam["models"]["cheap-3p"] = {"tier": "small", "price_in": 0.1, "first_party": False, "frontier": False, "tools": False}
    A = lambda s, d, t=0.9, probs=None: {"sensitivity": {"choice": s, "probabilities": probs or {}},
                                         "difficulty": {"score": d}, "needs_tools": {"noul": t}}
    F = lambda **kw: {"secret": False, "paths": [], "tools": ["Bash"], "ctx_tokens_est": 1000, "pinned": False, **kw}

    def route(ans, feats=None):
        sens, tier, tools, _ = classify(ans, feats or F(), policy)
        return pick(fam, eligible(fam, sens, tools, policy), tier, policy)
    ok(route(A("public", 0.1, 0.1)) == "cheap-3p", "public small, no tools: cheapest, third party ok")
    ok(route(A("public", 0.1, 0.9)) == "claude-haiku-4-5", "needs tools excludes a model without tools")
    ok(route(A("application", 0.1, 0.1)) == "claude-haiku-4-5", "application: first party only")
    ok(route(A("restricted", 0.1)) == "claude-sonnet-5", "restricted: first-party frontier, cheapest")
    ok(route(A("proprietary", 1.8)) == "claude-opus-5", "large tier")
    ok(route(A("public", 1.0)) == "claude-sonnet-5", "medium tier")
    ok(route(A("public", 0.1, 0.1, {"restricted": 0.2, "proprietary": 0.1})) == "claude-sonnet-5", "restricted probability bumps")
    ok(route(A("public", 0.1, 0.1), F(secret=True)) == "claude-sonnet-5", "secret shape floors to restricted")
    ok(route(A("public", 0.1, 0.1), F(paths=["infra/envs/prod/main.tf"])) == "claude-sonnet-5", "sensitive path floors")
    ok(route(A("public", 0.1, 0.1), F(tools=[])) == "cheap-3p", "no tools offered: needs_tools ignored")
    ok(family_of("claude-haiku-4-5-20251001", policy) == "claude" and family_of("spark-vllm", policy) is None, "families")
    ok(family_of("gpt-6-astra", policy) is None and family_of("claude-fable-6", policy) is None, "unlisted models are not routed")
    ok(family_of("auto", policy) == "chatgpt" and family_of("claude-auto", policy) == "claude", "aliases")
    ok(route(A("public", 0.1, 0.1), F(ctx_tokens_est=300_000, tools=[])) == "cheap-3p", "max_context absent: no limit")
    big = lambda: pick(fam, eligible(fam, "application", True, policy, 300_000), "small", policy)
    ok(big() == "claude-sonnet-5", "a context over max_context skips the model")
    ok(resolve("claude-opus-5[1m]", fam) == "claude-opus-5" and resolve("claude-haiku-4-5-20251001", fam) == "claude-haiku-4-5", "resolve")

    # stickiness
    pool = eligible(fam, "application", True, policy)
    sw = lambda prev, new, **kw: stay_or_switch(prev, new, pool, F(**kw), fam, policy)[0]
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=150_000) == "claude-opus-5", "large context stays")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=2_000) == "claude-haiku-4-5", "small context switches down")
    ok(sw("claude-haiku-4-5", "claude-opus-5", ctx_tokens_est=150_000) == "claude-opus-5", "harder turn moves up")
    ok(stay_or_switch("claude-haiku-4-5", "claude-sonnet-5", eligible(fam, "restricted", True, policy), F(ctx_tokens_est=150_000), fam, policy)[0]
       == "claude-sonnet-5", "sensitivity forces a switch at any size")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=100, pinned=True) == "claude-opus-5", "previous_response_id pins")

    # the hook, Jev stubbed
    with tempfile.TemporaryDirectory() as tmp:
        CONFIG["data"] = tmp
        calls = []

        def stub(answers):
            def fn(state, questions, timeout_s):
                calls.append(state)
                if answers is None:
                    raise TimeoutError("stub")
                return answers, {"input_tokens": 400}
            return fn
        key = SimpleNamespace(models=[])

        async def run():
            h = Router(stub(A("public", 0.1, 0.9)), mode="enforce")
            d = await h.async_pre_call_hook(key, None, {**chat, "messages": chat["messages"][:2]}, "acompletion")
            ok(d["model"] == "claude-haiku-4-5", f"enforce rewrites the model ({d['model']})")
            await h.async_pre_call_hook(key, None, {**chat, "messages": chat["messages"][:2]}, "acompletion")
            ok(len(calls) == 1, "second identical request is a cache hit")
            d = await h.async_pre_call_hook(key, None, {"model": "spark-vllm", "messages": chat["messages"]}, "acompletion")
            ok(d["model"] == "spark-vllm" and len(calls) == 1, "unrouted family: untouched, no Jev call")
            d = await h.async_pre_call_hook(key, None, {"model": "x", "input": ["a"]}, "aembedding")
            ok(d["model"] == "x", "embeddings are never routed")
            d = await h.async_pre_call_hook(SimpleNamespace(models=["claude-opus-5"]), None, dict(chat, litellm_session_id="k"), "acompletion")
            ok(d["model"] == "claude-opus-5", "a model the key may not use is never chosen")

            h = Router(stub(None), mode="enforce")
            d = await h.async_pre_call_hook(key, None, dict(chat), "acompletion")
            ok(d["model"] == "claude-sonnet-5", "Jev error: fallback restricted + medium")

            h = Router(stub(A("public", 0.1, 0.9)), mode="shadow")
            d = await h.async_pre_call_hook(key, None, dict(chat, litellm_session_id="shadow-1"), "acompletion")
            ok(d["model"] == "claude-opus-5", "shadow keeps the requested model")
            await asyncio.gather(*h.tasks)
        asyncio.run(run())
        lines = [json.loads(x) for x in (Path(tmp) / "routing.jsonl").read_text().splitlines()]
        shadow = lines[-1]
        ok(shadow["mode"] == "shadow" and shadow["chosen"] == "claude-haiku-4-5" and shadow["applied"] == "claude-opus-5",
           "shadow logs what enforce would do")
        ok(lines[-2]["source"] == "fallback" and "stub" in lines[-2]["error"], "fallback logged with its error")
        raw = (Path(tmp) / "routing.jsonl").read_text()
        ok("flaky" not in raw and "test_api.py" not in raw and "AKIA" not in raw, "log carries no content or paths")

        class Redis:        # the part of LiteLLM's RedisCache the router uses
            def __init__(self):
                self.kv = {}

            async def async_get_cache(self, k):
                return self.kv.get(k)

            async def async_set_cache(self, k, v, ttl=None):
                self.kv[k] = v
        shared = SimpleNamespace(redis_cache=Redis())

        async def run2():
            haiku_only = SimpleNamespace(models=["claude-haiku-4-5"])
            secret = {"model": "claude-haiku-4-5", "messages": [{"role": "user", "content": "why does AKIAABCDEFGHIJKLMNOP fail"}]}
            pol, orig = load(CONFIG["policy"]), CONFIG["policy"]

            def use_policy(name, **no_eligible):
                pf = Path(tmp) / f"policy-{name}.json"
                pf.write_text(json.dumps({**pol, "no_eligible": no_eligible}))
                CONFIG["policy"] = str(pf)

            async def enforce(k, data, answers=A("public", 0.1, 0.1)):
                return await Router(stub(answers), mode="enforce").async_pre_call_hook(k, None, dict(data), "anthropic_messages")
            use_policy("block", action="block")
            d = await enforce(haiku_only, secret)
            ok(isinstance(d, str) and "blocked" in d, f"no eligible model: block ({d})")
            h = Router(stub(A("public", 0.1, 0.1)), mode="shadow")
            d = await h.async_pre_call_hook(haiku_only, None, dict(secret), "anthropic_messages")
            await asyncio.gather(*h.tasks)
            ok(d["model"] == "claude-haiku-4-5", "shadow never blocks")
            use_policy("keep", action="keep")
            ok((await enforce(haiku_only, secret))["model"] == "claude-haiku-4-5", "no eligible model: keep")
            use_policy("fb", action="fallback_model", model="spark-vllm")
            ok((await enforce(SimpleNamespace(models=["claude-haiku-4-5", "spark-vllm"]), secret))["model"] == "spark-vllm",
               "no eligible model: fallback_model")
            ok(isinstance(await enforce(haiku_only, secret), str), "fallback_model the key may not call: blocked")
            CONFIG["policy"] = orig

            d = await enforce(key, dict(chat, model="claude-opus-5[1m]"), A("public", 1.8, 0.9))
            ok(d["model"] == "claude-opus-5[1m]", f"same model keeps the requested name ({d['model']})")

            # stickiness through a shared Redis: a second worker sees the model the first one chose
            conv = dict(chat, litellm_session_id="w", messages=chat["messages"] + [{"role": "assistant", "content": "x" * 600_000}])

            async def worker(answers, cache):
                h = Router(stub(answers), mode="enforce")
                return (await h.async_pre_call_hook(key, cache, dict(conv), "acompletion"))["model"]
            ok(await worker(A("public", 1.8, 0.9), shared) == "claude-opus-5", "worker 1: large task")
            ok(await worker(A("public", 0.1, 0.9), shared) == "claude-opus-5", "worker 2 keeps it (shared Redis)")
            ok(await worker(A("public", 0.1, 0.9), None) == "claude-haiku-4-5", "without Redis, per process")
        asyncio.run(run2())
        recs = [json.loads(x) for x in (Path(tmp) / "routing.jsonl").read_text().splitlines()]
        ok(any(r.get("action") == "block" and r["mode"] == "shadow" and r["applied"] == "claude-haiku-4-5" for r in recs),
           "shadow logs the block it would make")
        ok(all("ctx_tokens" not in r for r in recs), "token counts are labelled as estimates")
    print("routing selfcheck FAILED" if fails else "routing selfcheck OK")
    return not fails


# A labelled sample for --smoke: (prompt, requested model, expected sensitivity, expected tier).
SAMPLES = [
    ("What does the -p flag of mkdir do?", "claude-opus-5", "public", "small"),
    ("Rename the variable usr to user in src/models/user.py", "claude-opus-5", "application", "small"),
    ("Write unit tests for the pagination helper in api/pagination.go", "claude-opus-5", "application", "medium"),
    ("Rotate the prod RDS master password in terraform/envs/prod/rds.tf and put the new value in .env", "claude-haiku-4-5", "restricted", "medium"),
    ("Here are my AWS keys AKIAABCDEFGHIJKLMNOP, why does aws sts get-caller-identity fail?", "claude-haiku-4-5", "restricted", "small"),
    ("Summarise our unreleased jev-2 eval results in research/evals/jev2-results.md for the board", "claude-haiku-4-5", "proprietary", "medium"),
    ("Design the migration of our three EKS clusters to a single multi-tenant cluster with zero downtime, "
     "including IAM, network policy and rollback plan", "claude-haiku-4-5", "restricted", "large"),
    ("Give this conversation a five word title", "claude-sonnet-5", "public", "small"),
    ("Explain how Python's asyncio.gather handles exceptions", "gpt-5.6-sol", "public", "small"),
    ("Find the race condition that makes the Go worker pool in internal/pool/pool.go deadlock under load", "gpt-5.6-luna", "application", "large"),
]


async def smoke():
    h = ReflexRouter(mode="enforce")
    hits = {"sensitivity": 0, "tier": 0}
    tools = [{"name": n} for n in ("Bash", "Read", "Edit", "Grep")]
    print(f"{'requested':16} {'chosen':16} {'sens':12} {'want':12} {'tier':7} {'want':7} {'src':8} lat_s")
    for prompt, model, want_s, want_t in SAMPLES:
        d = await h.decide(features({"model": model, "tools": tools, "messages": [{"role": "user", "content": prompt}]}), model, apply=True)
        hits["sensitivity"] += d.get("sensitivity") == want_s
        hits["tier"] += d.get("tier") == want_t
        print(f"{model:16} {d['chosen']:16} {d.get('sensitivity', '-'):12} {want_s:12} {d.get('tier', '-'):7} {want_t:7} "
              f"{d['source']:8} {d['latency_s']}{'  ' + d['error'] if d['error'] else ''}")
    n = len(SAMPLES)
    print(f"sensitivity {hits['sensitivity']}/{n}, tier {hits['tier']}/{n}")


if __name__ == "__main__":
    args = sys.argv[1:]
    opt = lambda n, d=None: args[args.index(n) + 1] if n in args else d
    if "--selfcheck" in args:
        sys.exit(0 if selfcheck() else 1)
    elif "--smoke" in args:
        asyncio.run(smoke())
    elif "--check" in args:
        model = opt("--model", "claude-opus-5")
        f = features({"model": model, "messages": [{"role": "user", "content": opt("--check")}]})
        print(json.dumps(asyncio.run(ReflexRouter().decide(f, model, apply=True)), indent=1))
    else:
        print(__doc__)
