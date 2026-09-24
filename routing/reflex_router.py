#!/usr/bin/env python3
"""Reflex routing: a LiteLLM pre-call hook that picks the model for a request by how sensitive its
content is and how hard it is, with one Jev call.

  litellm_settings: {callbacks: ["reflex_router.proxy_handler_instance"]}   (this file next to config.yaml)
  python3 routing/reflex_router.py --selfcheck          offline tests, Jev stubbed
  python3 routing/reflex_router.py --check "<prompt>" [--model claude-opus-5]   one live decision
  python3 routing/reflex_router.py --smoke              live Jev over a small labelled prompt set

Order: family of the requested model -> secret shapes / sensitive paths (a floor) -> cache -> Jev
-> policy (sensitivity pool, difficulty tier, cheapest) -> stickiness (large contexts stay put).
REFLEX_ROUTING_MODE: off | shadow (default: decide in the background, log, keep the requested model)
| enforce (wait up to the latency budget, rewrite data["model"]). Stdlib only; litellm is imported
only to subclass its CustomLogger.
"""
import asyncio
import fnmatch
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
# Redaction: a port of redact() in gate.mjs. Keep the two lists in sync.
# ponytail: a pattern list, not a DLP engine; add a pattern when a new credential shape shows up.
SECRET_SHAPES = [re.compile(p) for p in [
    r"\b(AKIA|ASIA)[A-Z0-9]{16}\b",
    r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
    r"\b(sk-[A-Za-z0-9_-]{16,}|xox[abpr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{16,})\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"\b[rs]k_(live|test)_[A-Za-z0-9]{10,}\b", r"\bAIza[0-9A-Za-z_-]{35}\b", r"\bnpm_[A-Za-z0-9]{36}\b",
    r"hooks\.slack\.com/services/\S+",
    # a bare 40-char AWS-style secret: mixed case, so git SHAs (lowercase hex) are left alone
    r"(?<![A-Za-z0-9/+])(?=[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+]))(?=[A-Za-z0-9/+]*[A-Z])(?=[A-Za-z0-9/+]*[a-z])[A-Za-z0-9/+]{40}",
]]
SECRET_CONTEXT = [(re.compile(p, f), r) for p, f, r in [
    (r"(authorization:\s*(bearer|basic|token)\s+)\S+", re.I, r"\1<redacted>"),
    (r"((cookie|x-[\w-]*(auth|token|key)[\w-]*):\s*)[^'\"\n]+", re.I, r"\1<redacted>"),
    (r"(\b[\w.-]*(secret|token|passw(or)?d|api[_-]?key|access[_-]?key|credential)[\w.-]*\"?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)", re.I, r"\1<redacted>"),
    (r"(--?(password|passwd|token|secret|api-key)[= ]\s*)(\"[^\"]*\"|'[^']*'|\S+)", re.I, r"\1<redacted>"),
    (r"((\s-u|--user)\s+[^\s:]+:)\S+", 0, r"\1<redacted>"),
    (r"(\b(mysql|mariadb)\b[^|;&]*\s-p)(\S+)", 0, r"\1<redacted>"),
    (r"(\bsshpass\s+-p\s*)\S+", 0, r"\1<redacted>"),
    (r"(://[^\s:@/]+:)\S+@", 0, r"\1<redacted>@"),
]]


def redact(s):
    out = str(s or "")
    for rx in SECRET_SHAPES:
        out = rx.sub("<redacted>", out)
    for rx, repl in SECRET_CONTEXT:
        out = rx.sub(repl, out)
    return out


def has_secret(s):
    # Shapes only: the keyword patterns also match prose like "max_tokens: 100".
    return any(rx.search(s) for rx in SECRET_SHAPES)


# ---------------------------------------------------------------------------------------------
# What a request is about. One reader for the three shapes a coding agent sends: chat completions
# (messages), Anthropic messages (system + messages with blocks) and Responses (instructions + input).
SKIP_KEYS = {"type", "role", "id", "tool_use_id", "call_id", "data", "image_url", "source", "signature",
             "cache_control", "file_data", "image"}
REMINDER = re.compile(r"<system-reminder>[\s\S]*?</system-reminder>")
PATH_RE = re.compile(r"(?<![\w:/.])[~.\w-]*(?:/[\w.@-]+)+/?|(?<![\w/.])\.env(?:\.[\w-]+)?\b|\b[\w-]+\.(?:pem|key|tfvars|tfstate|p12)\b")


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
    return {
        "last": last, "system": system, "tools": [t for t in tools if t], "paths": paths,
        "turn": len(users), "secret": has_secret(whole),
        # ponytail: chars / 4 as tokens; a tokenizer per model family if the switch maths needs it
        "ctx_tokens": (len(system) + len(convo) + len(json.dumps(data.get("tools") or []))) // 4,
        # LiteLLM sets litellm_session_id from x-*-session-id headers and Anthropic metadata.user_id;
        # otherwise the first user message and system prompt identify the conversation.
        "conv": str(data.get("litellm_session_id") or sha([system[:2000], first[:2000]])),
        "pinned": bool(data.get("previous_response_id")),   # server-side context lives with the old model
    }


def jev_state(f, spec):
    return {spec["item_key"]: {"message": redact(f["last"])[-2000:], "system_summary": redact(f["system"][:400]),
                               "system_chars": len(f["system"]), "tools": f["tools"][:60],
                               "paths": [redact(p) for p in f["paths"][:40]], "turn": f["turn"]},
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
            raise RuntimeError(f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}") from None


# ---------------------------------------------------------------------------------------------
# Policy: pure functions over answers, request features and policy.json.
def family_of(model, policy):
    return next((name for name, fam in policy["families"].items()
                 if any(fnmatch.fnmatchcase(model, g) for g in fam["match"])), None)


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


def eligible(fam, sens, tools, policy):
    need = policy["sensitivity"]["pools"][sens]["require"]
    return [m for m, i in fam["models"].items() if all(i.get(k) for k in need) and (not tools or i.get("tools", True))]


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
    st, ctx = policy["stickiness"], f["ctx_tokens"]
    old_in, new_in = fam["models"][p]["price_in"] / 1e6, fam["models"][new]["price_in"] / 1e6
    saving = (ctx * st["cache_read_factor"] + st["turn_tokens"]) * (old_in - new_in) * st["remaining_turns"]
    rebuild = ctx * new_in
    if saving > rebuild:
        return new, f"switch: saves ${saving:.4f} over {st['remaining_turns']} turns, rebuild ${rebuild:.4f}"
    return prev, f"sticky: rebuild ${rebuild:.4f} >= saving ${saving:.4f} ({ctx} context tokens)"


# ---------------------------------------------------------------------------------------------
class ReflexRouter(CustomLogger):
    def __init__(self, ask_fn=ask, mode=None):
        if CustomLogger is not object:
            super().__init__()
        self.ask, self.mode = ask_fn, mode
        # ponytail: in-process dicts; LiteLLM with several workers needs the passed DualCache (Redis) instead
        self.cache, self.convs, self.tasks = {}, {}, set()

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        mode = self.mode or CONFIG["mode"]
        if mode == "off" or call_type not in ROUTED or not isinstance(data.get("model"), str):
            return data
        try:
            f, requested = features(data), data["model"]
            allowed = list(getattr(user_api_key_dict, "models", None) or [])
        except Exception as e:     # a routing bug never breaks a request
            print(f"reflex routing: {e}", file=sys.stderr)
            return data
        if mode != "enforce":
            # Shadow: nobody waits. The decision runs after the request is on its way.
            task = asyncio.get_running_loop().create_task(self.decide(f, requested, allowed, apply=False))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return data
        d = await self.decide(f, requested, allowed, apply=True)
        data["model"] = d["applied"]
        return data

    async def decide(self, f, requested, allowed=(), apply=False):
        t0 = time.monotonic()
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": "enforce" if apply else "shadow",
               "conv": sha(f["conv"]), "turn": f["turn"], "ctx_tokens": f["ctx_tokens"], "requested": requested,
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
            pool = eligible(fam, sens, tools, policy)
            chosen = pick(fam, pool, tier, policy)
            rec.update(family=fam_name, sensitivity=sens, tier=tier, needs_tools=tools, floors=why or None,
                       answers={k: a.get("choice", a.get("score", a.get("noul"))) for k, a in answers.items()})
            if chosen is None:
                rec.update(reason=f"no model in {fam_name} is eligible for {sens}; kept", violation=True)
                return rec
            prev = self.convs.get(f["conv"])
            chosen, sticky = stay_or_switch(prev, chosen, pool, f, fam, policy)
            if allowed and chosen not in allowed and "all-proxy-models" not in allowed:
                rec.update(reason=f"{chosen} not allowed for this key; kept")
                return rec
            req = resolve(requested, fam)
            rec.update(chosen=chosen, violation=req not in pool or None,
                       reason=sticky or f"{sens}/{tier}: cheapest eligible")
            if apply:
                rec["applied"] = chosen
            return rec
        except Exception as e:
            rec.update(source="error", error=f"{type(e).__name__}: {e}"[:200], reason="internal error; kept")
            return rec
        finally:
            self.convs[f["conv"]] = rec["applied"]
            while len(self.convs) > 5000:
                self.convs.pop(next(iter(self.convs)))
            rec["latency_s"] = round(time.monotonic() - t0, 3)
            log(rec)

    async def answers(self, f, spec, policy, rec):
        state = jev_state(f, spec)
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
    fails = []

    def ok(c, m):
        if not c:
            fails.append(m)
            print("FAIL", m, file=sys.stderr)

    # redaction: same cases as gate.mjs
    r = redact("curl -H 'Authorization: Bearer abc.def' https://u:hunter2@x.io AWS_SECRET_ACCESS_KEY=wJalr/K7 "
               "--password s3cr3t AKIAABCDEFGHIJKLMNOP ghp_" + "a" * 36)
    for s in ["abc.def", "hunter2", "wJalr", "s3cr3t", "AKIAABCDEFGHIJKLMNOP", "ghp_aaaa"]:
        ok(s not in r, f"redact {s}")
    ok(redact("git show 3f5e8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f").endswith("3f5e8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f"), "git SHA kept")
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

    # policy
    policy = load(CONFIG["policy"])
    fam = policy["families"]["claude"]
    fam["models"]["cheap-3p"] = {"tier": "small", "price_in": 0.1, "first_party": False, "frontier": False, "tools": False}
    A = lambda s, d, t=0.9, probs=None: {"sensitivity": {"choice": s, "probabilities": probs or {}},
                                         "difficulty": {"score": d}, "needs_tools": {"noul": t}}
    F = lambda **kw: {"secret": False, "paths": [], "tools": ["Bash"], "ctx_tokens": 1000, "pinned": False, **kw}

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
    ok(resolve("claude-opus-5[1m]", fam) == "claude-opus-5" and resolve("claude-haiku-4-5-20251001", fam) == "claude-haiku-4-5", "resolve")

    # stickiness
    pool = eligible(fam, "application", True, policy)
    sw = lambda prev, new, **kw: stay_or_switch(prev, new, pool, F(**kw), fam, policy)[0]
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens=150_000) == "claude-opus-5", "large context stays")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens=2_000) == "claude-haiku-4-5", "small context switches down")
    ok(sw("claude-haiku-4-5", "claude-opus-5", ctx_tokens=150_000) == "claude-opus-5", "harder turn moves up")
    ok(stay_or_switch("claude-haiku-4-5", "claude-sonnet-5", eligible(fam, "restricted", True, policy), F(ctx_tokens=150_000), fam, policy)[0]
       == "claude-sonnet-5", "sensitivity forces a switch at any size")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens=100, pinned=True) == "claude-opus-5", "previous_response_id pins")

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
            h = ReflexRouter(stub(A("public", 0.1, 0.9)), mode="enforce")
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

            h = ReflexRouter(stub(None), mode="enforce")
            d = await h.async_pre_call_hook(key, None, dict(chat), "acompletion")
            ok(d["model"] == "claude-sonnet-5", "Jev error: fallback restricted + medium")

            h = ReflexRouter(stub(A("public", 0.1, 0.9)), mode="shadow")
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
