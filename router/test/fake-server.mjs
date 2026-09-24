// A fake downstream MCP server for the router self-checks: three tools, served over two pages; echo is
// annotated read-only, add and crash are not. echo also reports whether the router leaked
// TYPESAFE_API_KEY to it and which protocol era the call came in; crash exits the process.
//   node fake-server.mjs [legacy|silent|modern|future|slow] [marker]
//   legacy  initialize handshake (2025-11-25); server/discover is an unknown method (the default)
//   silent  legacy, but unknown pre-initialize requests get no answer at all
//   modern  2026-07-28 only: server/discover, per-request _meta, initialize rejected
//   future  like modern, but only speaks a later revision (2099-01-01)
//   slow    like modern, but reads nothing for its first 600 ms (a server still starting up)
// With a marker file that exists at start, a fourth tool, upgraded, is listed (a server upgraded
// between two starts).
import {existsSync} from "node:fs";
import {lines} from "../mcp.mjs";

const ERA = process.argv[2] ?? "legacy", M = "io.modelcontextprotocol/";
const MODERN = ["modern", "future", "slow"].includes(ERA), VERSION = ERA === "future" ? "2099-01-01" : "2026-07-28";
const TOOLS = [
  {name: "echo", description: "Echo a text back.", annotations: {readOnlyHint: true},
   inputSchema: {type: "object", required: ["text"], properties: {text: {type: "string", description: "The text to echo"}}}},
  {name: "add", description: "Add two numbers.",
   inputSchema: {type: "object", required: ["a", "b"], properties: {a: {type: "number", description: "The first number"},
                                                                    b: {type: "number", description: "The second number"}}}},
  {name: "crash", description: "Exit the server process.", inputSchema: {type: "object"}},
];
if (process.argv[3] && existsSync(process.argv[3])) TOOLS.push({name: "upgraded", description: "Added in a later version.", inputSchema: {type: "object"}});
const send = o => process.stdout.write(JSON.stringify(o) + "\n");
const handle = m => {
  if (m instanceof Error || m.id == null) return;
  const r = result => send({jsonrpc: "2.0", id: m.id, result: MODERN ? {resultType: "complete", ...result} : result});
  const err = (code, message, data) => send({jsonrpc: "2.0", id: m.id, error: {code, message, ...(data ? {data} : {})}});
  if (MODERN) {
    if (m.method === "initialize") return err(-32601, `initialize is not supported: this server speaks MCP ${VERSION}`);
    const meta = m.params?._meta ?? {};
    if (!meta[`${M}protocolVersion`] || !meta[`${M}clientCapabilities`]) return err(-32602, "missing _meta protocol fields");
    if (meta[`${M}protocolVersion`] !== VERSION)
      return err(-32022, "Unsupported protocol version", {supported: [VERSION], requested: meta[`${M}protocolVersion`]});
    if (m.method === "server/discover")
      return r({supportedVersions: [VERSION], capabilities: {tools: {}}, _meta: {[`${M}serverInfo`]: {name: "fake", version: "1"}}});
  } else if (m.method === "initialize") {
    return r({protocolVersion: m.params.protocolVersion, capabilities: {tools: {}}, serverInfo: {name: "fake", version: "1"}});
  } else if (m.method === "server/discover" && ERA === "silent") return;
  if (m.method === "tools/list") return r(m.params?.cursor ? {tools: TOOLS.slice(1)} : {tools: [TOOLS[0]], nextCursor: "p2"});
  if (m.method === "tools/call") {
    const a = m.params.arguments;
    if (m.params.name === "echo") return r({content: [{type: "text", text: `echo: ${a.text} key=${process.env.TYPESAFE_API_KEY ? "leaked" : "absent"} era=${m.params._meta ? "modern" : "legacy"}`}]});
    if (m.params.name === "add") return r({content: [{type: "text", text: String(a.a + a.b)}], structuredContent: {sum: a.a + a.b}});
    if (m.params.name === "crash") process.exit(3);
  }
  err(-32601, "no");
};
// slow: every message waits until 600 ms after start, in order, as if read only then
const up = Date.now() + (ERA === "slow" ? 600 : 0);
lines(process.stdin, m => Date.now() >= up ? handle(m) : setTimeout(() => handle(m), up - Date.now()));
process.stdin.on("end", () => setTimeout(() => process.exit(0), Math.max(0, up - Date.now())));
