// A fake downstream MCP server for the router self-checks: two tools, served over two pages; echo is
// annotated read-only, add is not. echo also reports whether the router leaked TYPESAFE_API_KEY to it.
import {lines} from "../mcp.mjs";

const TOOLS = [
  {name: "echo", description: "Echo a text back.", annotations: {readOnlyHint: true},
   inputSchema: {type: "object", required: ["text"], properties: {text: {type: "string", description: "The text to echo"}}}},
  {name: "add", description: "Add two numbers.",
   inputSchema: {type: "object", required: ["a", "b"], properties: {a: {type: "number", description: "The first number"},
                                                                    b: {type: "number", description: "The second number"}}}},
];
const send = o => process.stdout.write(JSON.stringify(o) + "\n");
lines(process.stdin, m => {
  if (m instanceof Error || m.id == null) return;
  const r = result => send({jsonrpc: "2.0", id: m.id, result});
  if (m.method === "initialize") return r({protocolVersion: m.params.protocolVersion, capabilities: {tools: {}}, serverInfo: {name: "fake", version: "1"}});
  if (m.method === "tools/list") return r(m.params?.cursor ? {tools: [TOOLS[1]]} : {tools: [TOOLS[0]], nextCursor: "p2"});
  if (m.method === "tools/call") {
    const a = m.params.arguments;
    if (m.params.name === "echo") return r({content: [{type: "text", text: `echo: ${a.text} key=${process.env.TYPESAFE_API_KEY ? "leaked" : "absent"}`}]});
    if (m.params.name === "add") return r({content: [{type: "text", text: String(a.a + a.b)}], structuredContent: {sum: a.a + a.b}});
  }
  send({jsonrpc: "2.0", id: m.id, error: {code: -32601, message: "no"}});
});
process.stdin.on("end", () => process.exit(0));
