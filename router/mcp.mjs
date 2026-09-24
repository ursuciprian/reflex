// Minimal MCP over stdio: newline-delimited JSON-RPC 2.0, both ends. No SDK.
// https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio
import {spawn} from "node:child_process";

// Legacy (initialize-handshake) revisions, newest first. ponytail: the 2026-07-28 per-request-_meta
// era is not implemented; a dual-era client probes with server/discover, gets -32601 and falls back
// to initialize, as that spec requires. Add server/discover when clients stop speaking the old era.
export const VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

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

/** Spawn a stdio MCP server and hold an initialized session with it. */
export async function connect({command, args = [], env = {}, cwd}, {timeoutMs = 30000, name = command} = {}) {
  const child = spawn(command, args, {cwd, env: {...process.env, ...env}, stdio: ["pipe", "pipe", "inherit"]});
  const pending = new Map();
  let next = 1, dead = null;
  const fail = err => { dead = err; for (const p of pending.values()) p.reject(err); pending.clear(); };
  child.on("error", fail);
  child.on("exit", code => fail(new Error(`${name} exited (${code})`)));
  child.stdin.on("error", () => {});   // EPIPE after the child died: the exit handler reports it
  const send = obj => child.stdin.write(JSON.stringify(obj) + "\n");
  lines(child.stdout, msg => {
    if (msg instanceof Error) return;
    if (msg.method && msg.id != null)   // a request from the server (ping, roots, sampling): only ping is supported
      return send(msg.method === "ping" ? {jsonrpc: "2.0", id: msg.id, result: {}}
                                        : {jsonrpc: "2.0", id: msg.id, error: {code: -32601, message: "not supported by reflex-router"}});
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    msg.error ? p.reject(new Error(`${name}: ${msg.error.message} (${msg.error.code})`)) : p.resolve(msg.result);
  });
  const request = (method, params) => new Promise((resolve, reject) => {
    if (dead) return reject(dead);
    const id = next++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${name}: ${method} timed out`)); }, timeoutMs);
    pending.set(id, {resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); }});
    send({jsonrpc: "2.0", id, method, ...(params ? {params} : {})});
  });
  const init = await request("initialize", {protocolVersion: VERSIONS[0], capabilities: {},
                                            clientInfo: {name: "reflex-router", version: "0.1.0"}});
  send({jsonrpc: "2.0", method: "notifications/initialized"});
  const tools = [];
  let cursor;
  do {   // tools/list is paginated
    const page = await request("tools/list", cursor ? {cursor} : undefined);
    tools.push(...(page.tools ?? []));
    cursor = page.nextCursor;
  } while (cursor);
  return {init, tools, request, close: () => { child.stdin.end(); setTimeout(() => child.kill(), 2000).unref(); }};
}
