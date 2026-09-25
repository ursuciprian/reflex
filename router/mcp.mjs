// Minimal MCP over stdio: newline-delimited JSON-RPC 2.0, both ends. No SDK.
// https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
import {spawn} from "node:child_process";

// Legacy (initialize-handshake) revisions, newest first.
export const VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
// Modern (per-request _meta, no handshake) revisions this client speaks.
export const MODERN = ["2026-07-28"];
const CLIENT = {name: "reflex-router", version: "0.1.0"};
const M = "io.modelcontextprotocol/";
// Recognized modern errors (2026-07-28 schema): header mismatch, missing client capability, unsupported version.
const MODERN_ERRORS = new Set([-32020, -32021, -32022]);

// How long server/discover may go unanswered before a server counts as legacy (the spec only says
// "a reasonable timeout"). Legacy servers normally answer the unknown method with an error at once;
// only one that stays silent costs the full wait, once per start (a restart of a known legacy
// server skips the probe). 1 s is safe because a modern server that is still starting and misses
// the window refuses the fallback initialize, and connect() then probes again with the full timeout.
export const PROBE_MS = Number(process.env.REFLEX_ROUTER_PROBE_MS ?? 1000);

const BASE_ENV = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "TMPDIR", "LANG", "LC_ALL"];

/** Calls onMessage(obj | Error) once per line of `stream`. */
export function lines(stream, onMessage) {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", chunk => {
    buf += chunk;
    for (let i; (i = buf.indexOf("\n")) > -1;) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (e) { msg = e; }
      onMessage(msg);
    }
  });
}

class PeerError extends Error { constructor(name, e) { super(`${name}: ${e.message} (${e.code})`); this.code = e.code; this.data = e.data; } }

/**
 * Spawn a stdio MCP server and hold a session with it. Dual-era, per the 2026-07-28 stdio
 * backward-compatibility rules: probe with server/discover carrying our modern version in _meta.
 * A DiscoverResult, or a recognized modern error, means a modern server: every request then carries
 * the version, client info and capabilities in _meta. Any other error, or no answer within
 * `probeMs`, means a legacy server: fall back to the initialize handshake.
 */
export async function connect({command, args = [], env = {}, cwd}, {timeoutMs = 30000, probeMs = PROBE_MS, name = command, era} = {}) {
  // Like the MCP SDKs: a server gets a minimal environment plus its own `env`, never the caller's
  // credentials (TYPESAFE_API_KEY, AWS_*, GITHUB_TOKEN ...).
  const base = Object.fromEntries(BASE_ENV.filter(k => process.env[k] != null).map(k => [k, process.env[k]]));
  const child = spawn(command, args, {cwd, env: {...base, ...env}, stdio: ["pipe", "pipe", "inherit"]});
  const pending = new Map();
  let next = 1, dead = null, modern = null;   // modern: the negotiated modern version, or null for legacy
  const fail = err => { dead ??= err; for (const p of pending.values()) p.reject(err); pending.clear(); };
  child.on("error", fail);
  child.on("exit", code => fail(new Error(`${name} exited (${code})`)));
  child.stdin.on("error", () => {});   // EPIPE after the child died: the exit handler reports it
  const send = obj => child.stdin.write(JSON.stringify(obj) + "\n");
  lines(child.stdout, msg => {
    if (msg instanceof Error || !msg || typeof msg !== "object") return;
    if (msg.method && msg.id != null)   // a request from a legacy server (ping, roots, sampling): only ping is supported
      return send(msg.method === "ping" ? {jsonrpc: "2.0", id: msg.id, result: {}}
                                        : {jsonrpc: "2.0", id: msg.id, error: {code: -32601, message: "not supported by reflex-router"}});
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) return p.reject(new PeerError(name, msg.error));
    // A modern result states its type; absent means complete (older servers). ponytail: no
    // input_required (multi round-trip) support; such a result is an error to the caller.
    const type = msg.result?.resultType ?? "complete";
    if (type !== "complete") return p.reject(new Error(`${name}: unsupported resultType ${type}`));
    p.resolve(msg.result);
  });
  const request = (method, params, ms = timeoutMs, version = modern) => new Promise((resolve, reject) => {
    if (dead) return reject(dead);
    const id = next++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${name}: ${method} timed out`)); }, ms);
    pending.set(id, {resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); }});
    if (version) params = {...params, _meta: {...params?._meta, [`${M}protocolVersion`]: version,
                                              [`${M}clientInfo`]: CLIENT, [`${M}clientCapabilities`]: {}}};
    send({jsonrpc: "2.0", id, method, ...(params ? {params} : {})});
  });
  let init;
  const tools = [], seen = new Set();
  try {   // a server that hangs or fails during setup is not left running
    // The era is a property of the server: a restart of a known legacy server skips the probe.
    const probe = ms => request("server/discover", undefined, ms, MODERN[0]).then(r => ({era: "modern", ...r}), e => {
      if (!(e instanceof PeerError && MODERN_ERRORS.has(e.code))) return null;   // anything else: legacy
      if (e.code !== -32022) throw e;
      return {era: "modern", supportedVersions: e.data?.supported ?? []};       // modern, other versions: never initialize
    });
    init = era === "legacy" ? null : await probe(probeMs);
    if (!init) {
      if (dead) throw dead;
      // A short probe must not cost a slow-starting modern server its connection: when the
      // fallback initialize is refused by a server that is still running, the probe missed
      // the window, so probe once more with the full timeout before giving up.
      init = await request("initialize", {protocolVersion: VERSIONS[0], capabilities: {}, clientInfo: CLIENT})
        .then(r => ({era: "legacy", ...r}), async e => {
          if (!(e instanceof PeerError) || era === "legacy" || dead) throw e;
          const late = await probe(timeoutMs);
          if (!late) throw e;
          return late;
        });
    }
    if (init.era === "modern") {
      modern = MODERN.find(v => init.supportedVersions?.includes(v));
      if (!modern) throw new Error(`${name}: no common protocol version (server: ${init.supportedVersions?.join(", ") || "none"}; reflex-router: ${MODERN.join(", ")})`);
      init.protocolVersion = modern;
    } else if (init.era === "legacy") {
      if (!VERSIONS.includes(init?.protocolVersion)) throw new Error(`${name}: unsupported protocol version ${init?.protocolVersion}`);
      send({jsonrpc: "2.0", method: "notifications/initialized"});
    }
    let cursor;
    do {   // tools/list is paginated; a server repeating a cursor would loop forever
      const page = await request("tools/list", cursor ? {cursor} : undefined);
      tools.push(...(page?.tools ?? []));
      cursor = page?.nextCursor;
      if (seen.has(cursor)) break;
      seen.add(cursor);
    } while (cursor);
  } catch (e) { child.kill(); throw e; }
  return {init, tools, request: (m, p) => request(m, p), get dead() { return dead; }, pid: child.pid,
          close: () => { child.stdin.end(); setTimeout(() => child.kill(), 2000).unref(); }};
}

/**
 * connect(), and reconnect lazily: a request after the server died starts it again, at most once
 * per `retryMs`; in between, requests fail fast. `tools` is always the live server's list: a
 * restarted server may have been upgraded, so its tools/list is re-read, and `onRestart(tools)` is
 * told about it.
 */
export async function reconnecting(spec, opts = {}) {
  const {retryMs = 30000, name = spec.command, onRestart = () => {}} = opts;
  let c = await connect(spec, opts), last = 0, starting = null;
  return {
    get init() { return c.init; }, get tools() { return c.tools; }, get pid() { return c.pid; },
    async request(method, params) {
      if (c.dead) {
        const wait = last + retryMs - Date.now();
        if (!starting && wait > 0) throw new Error(`${name} is down (${c.dead.message}); next restart attempt in ${Math.ceil(wait / 1000)} s`);
        starting ??= (last = Date.now(), connect(spec, {...opts, era: c.init.era}).then(n => { c = n; onRestart(n.tools); }).finally(() => { starting = null; }));
        await starting;
      }
      return c.request(method, params);
    },
    close: () => c.close(),
  };
}
