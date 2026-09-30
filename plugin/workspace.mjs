// The workspace judge: a keyless System 1 rung for commands whose whole effect is provably confined
// to the current git working tree and reversible. It turns "not covered, ask a human" into a pass
// when a recovery point can be taken first (gate.mjs finish() takes the checkpoint before the command
// runs, reusing autonomy.mjs). It is the last rung in precheckAs, after the rules, the tamper and
// secret checks, the local-script scan and the fast lanes, so nothing it passes was already flagged.
//
// It only ever passes; it never asks or denies (an unrecognised command falls through unchanged), so
// it can only reduce human prompts, never add a MISS. Everything irreversible or outside the tree
// (production, remotes, deploys, pushes, deletes outside the tree, cloud or MCP mutations, secrets,
// network egress that carries data, process/service/system changes, code nobody read) is left to the
// next rung: it is not recognised here.
//
// Pure: it imports only read-only helpers from the gate and the repo-root lookup. Confinement is by
// path: every write target must resolve inside the working tree and not be a protected path, the
// .git internals, .reflex, or the Reflex checkout (those already asked earlier). Inline interpreter
// code (python3 -c, python3 - <<EOF, node -e) is read conservatively: an allowlist of stdlib modules
// and read-only APIs, no subprocess, network, exec/eval or writes outside the tree.
import {lstatSync, readFileSync, readlinkSync, realpathSync} from "node:fs";
import {basename, dirname, isAbsolute, join, resolve} from "node:path";
import {homedir} from "node:os";
import {prodTier, protectedWrite} from "./gate.mjs";
import {pipelines, readOnly} from "./readonly.mjs";
import {maskQuotes, shellWords, stripDataHeredocs} from "./shell.mjs";
import {repoRoot} from "./team.mjs";

const MAX = 16 * 1024;   // a command longer than this is not read; it asks
const WS = /[ \t]+/;

// A path token resolved against cwd; ~ and $HOME are the home directory. null when it cannot be
// resolved to a real path (an expansion other than ~/$HOME, a glob, a URL): unknown, so not confined.
function resolvePath(tok, cwd) {
  let t = tok.replace(/^["']|["']$/g, "");
  if (!t || t.includes("://")) return null;
  if (/[*?\[\]{}]/.test(t)) return null;                       // a glob: what it expands to is unknown
  if (t === "~" || t.startsWith("~/")) t = t === "~" ? homedir() : join(homedir(), t.slice(2));
  else if (/\$|`/.test(t)) return null;                         // a variable or substitution: unknown
  return isAbsolute(t) ? resolve(t) : resolve(cwd, t);
}
// The real path of `p`, following symlinks along the way out (a link in the tree that points
// elsewhere) including a dangling one whose target does not exist yet, so a write cannot escape the
// tree through one. Resolved component by component from the root down; readlink handles a link whose
// target is missing (realpathSync cannot). Depth-limited against a link cycle.
function realOf(p, depth = 0) {
  if (depth > 40) return p;
  try { return realpathSync.native(p); } catch { /* p or an ancestor does not exist, or a link dangles */ }
  const parent = realOf(dirname(p), depth + 1), self = join(parent, basename(p));
  try {
    if (lstatSync(self).isSymbolicLink()) {
      const t = readlinkSync(self);
      return realOf(isAbsolute(t) ? t : join(parent, t), depth + 1);
    }
  } catch { /* self does not exist: a plain new file under a real parent */ }
  return self;
}
// Is `abs` inside the working tree `root` and not a place a human must see? .git and .reflex
// internals, and a protected path, already ask earlier for a shell command; here we exclude them too
// so an inline write or a resolved cp/mv target cannot reach them. Both the literal and the
// symlink-resolved path must stay inside the tree.
function insideTree(abs, cwd, root) {
  if (abs === null) return false;
  const realRoot = realOf(root);
  for (const p of new Set([abs, realOf(abs)])) {
    if (p !== root && !p.startsWith(root + "/") && p !== realRoot && !p.startsWith(realRoot + "/")) return false;
    const rel = "/" + (p.startsWith(root + "/") ? p.slice(root.length + 1) : p.startsWith(realRoot + "/") ? p.slice(realRoot.length + 1) : "");
    if (/(^|\/)\.git(\/|$)/.test(rel) || /(^|\/)\.reflex(\/|$)/.test(rel)) return false;
  }
  if (protectedWrite([abs], cwd)) return false;                    // CI, prod infra, agent settings, startup files
  return true;
}

// The write targets of a command, from its pipelines' redirect targets and the path operands of the
// recognised local-write programs. Returns {targets: [abs...], ok} where ok is false when the command
// contains a write this cannot pin to a path (then it is not confined and falls through).
const FLAG = /^-/;
// Programs that only create or write files, and how to read their path operands. All operands are
// write targets except where noted; a source that is only read is not a write target but must still
// be readable (checked as "not a secret" via the shell rules that ran earlier).
const WRITE_PROGRAMS = {
  mkdir: "operands", touch: "operands", tee: "operands", truncate: "operands",
  cp: "last-and-first", mv: "operands", ln: "reject",              // ln can point outside the tree: not handled here
};
// sed -i / -I / --in-place writes the files it edits; without the in-place flag sed is read-only, so
// we require the same command minus in-place to be read-only (its script is safe) and its operands in-tree.
const SED_INPLACE = /(^|\s)(-i|-I|--in-place)(\b|=|\s|$)/;

const progOf = seg => shellWords(seg.core)?.[0]?.raw?.replace(/^.*\//, "") ?? "";
function localWrites(seg, cwd) {
  const words = shellWords(seg.core);
  if (!words) return {ok: false};
  const argv = words.map(w => w.raw);
  const name = argv[0]?.replace(/^.*\//, "");
  const targets = [...seg.targets];   // redirect targets of the segment
  if (name === "sed") {
    if (!SED_INPLACE.test(seg.core)) return {ok: true, targets};   // read-only sed writes nothing of its own
    // The macOS `-i ''` empty backup suffix is already dropped by the caller's empty-quote fallback,
    // so here -i is a bare flag (possibly clustered, or with an attached suffix `-i.bak`). Strip it and
    // keep any other cluster flags; the rest must parse as a read-only sed, so its script is safe.
    const stripped = seg.core
      .replace(/(^|\s)--in-place(=\S*)?(?=\s|$)/g, "$1")
      .replace(/(^|\s)(-[a-zA-Z]*)[iI]([a-zA-Z]*)\S*(?=\s|$)/g, (m, sp, pre, post) => { const f = (pre.slice(1) + post); return f ? `${sp}-${f}` : sp; });
    if (!readOnly(stripped)) return {ok: false};
    // every non-flag operand is a file it edits (the sed script also lands here but resolves in-tree,
    // so it never wrongly rejects; a script naming a real outside path would, which is the safe side)
    const operands = argv.slice(1).filter(a => !FLAG.test(a) && a && !/^['"]*$/.test(a));
    return {ok: true, targets: [...targets, ...operands]};
  }
  const kind = WRITE_PROGRAMS[name];
  if (kind === "reject") return {ok: false};
  const operands = argv.slice(1).filter(a => !FLAG.test(a));
  if (kind === "operands" || kind === "last-and-first") return {ok: true, targets: [...targets, ...operands]};
  return {ok: true, targets};   // only redirect targets count; the reader part is checked separately
}
const WRITER = new Set(["sed", "mkdir", "touch", "tee", "truncate", "cp", "mv"]);

// ---------------------------------------------------------------------------------------------
// Network reads. A curl or wget that only fetches (GET, no body, no upload) and writes nothing
// outside the tree, and is not piped into an interpreter. A read prints to stdout by default.
const CURL_WRITE = /(^|\s)(-[a-zA-Z]*[dFT]|--data\b|--data-\S+|--form\b|--form-\S+|--upload-file\b|-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|-o\b|-O\b|--output\b|--remote-name\b)/i;
const WGET_WRITE = /(^|\s)(--post-\S+|--method[=\s]+(?!GET)\S+|--body-\S+|-O\b|--output-document\b|-P\b|--directory-prefix\b)/i;
// A pipe into a shell or interpreter runs whatever came down the pipe: never confined.
const PIPE_TO_RUNNER = /\|\s*(sudo\s+)?(env\s+\S+\s+)?(\/\S+\/)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(\/\S+\/)?(python[\d.]*|node|deno|bun|ruby|perl|php|osascript|Rscript)\b/;

function networkReadOk(seg, cwd, root) {
  const name = shellWords(seg.core)?.[0]?.raw?.replace(/^.*\//, "");
  if (name === "curl") {
    if (CURL_WRITE.test(seg.core)) {
      // an output file is allowed only inside the tree
      const m = [...seg.core.matchAll(/(?:-o|--output)\s+(\S+)/g)].map(x => x[1]);
      if (CURL_WRITE.test(seg.core.replace(/(?:-o|--output)\s+\S+/g, ""))) return false;   // a body/upload/mutating method
      if (!m.length || !m.every(t => insideTree(resolvePath(t, cwd), cwd, root))) return false;
    }
    return true;
  }
  if (name === "wget") {
    if (WGET_WRITE.test(seg.core)) {
      const m = [...seg.core.matchAll(/(?:-O|--output-document)\s+(\S+)/g)].map(x => x[1]);
      if (WGET_WRITE.test(seg.core.replace(/(?:-O|--output-document)\s+\S+/g, "").replace(/(?:-P|--directory-prefix)\s+\S+/g, ""))) return false;
      const dirs = [...seg.core.matchAll(/(?:-P|--directory-prefix)\s+(\S+)/g)].map(x => x[1]);
      if (![...m, ...dirs].length || ![...m, ...dirs].every(t => insideTree(resolvePath(t, cwd), cwd, root))) return false;
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Inline interpreter code (python3 -c / python3 - <<EOF / node -e). Allowed only when it reads and
// computes, or writes inside the tree, using nothing that can run a subprocess, open a socket, fetch
// over the network, or evaluate more code. Conservative by construction: any token not on the safe
// lists, or any path literal that resolves outside the tree, means "not confined" and it falls
// through. ponytail: static, literal analysis; a path built at runtime from a variable is not seen,
// which is why no subprocess/network/exec/os-mutation API is allowed and every absolute string
// literal is checked, so the only writers left (open, pathlib) can reach outside only through a
// literal this catches.
const PY_BAD = [
  "subprocess", "os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
  "os.rename", "os.replace", "os.chmod", "os.chown", "os.link", "os.symlink", "os.mkfifo", "os.exec",
  "os.spawn", "os.fork", "os.kill", "os.setuid", "os.setgid", "os.putenv", "os.startfile", "os.walk",
  "shutil", "socket", "urllib", "requests", "httpx", "http.client", "ftplib", "smtplib", "telnetlib",
  "asyncio", "multiprocessing", "ctypes", "cffi", "pty", "pexpect", "signal", "resource", "mmap",
  "importlib", "__import__", "eval", "exec", "compile", "globals", "builtins", "getattr", "setattr",
  "input(", "breakpoint", "code.interact", "pdb", "webbrowser", "platform.popen", "commands.",
  "pickle.load", "marshal", "os.environ[", "sys.argv", "open(0", "os.dup", "os.pipe", "os.fdopen",
];
// Node member accesses that reach a subprocess, the network, more code, or a destructive fs call.
const NODE_BAD = [
  "child_process", "process.binding", "worker_threads", "cluster", "vm.", "module.", "inspector",
  "fetch(", "import(", "eval(", "Function(", "createRequire", "globalThis", "constructor.constructor",
  "process.env", "process.argv", "process.dlopen", "os.homedir", "os.userInfo", "os.networkInterfaces",
  "fs.unlink", "fs.rm", "fs.rename", "fs.chmod", "fs.chown", "fs.symlink", "fs.link", "fs.rmdir",
  "fs.truncate", "fs.cp(", "fs.copyFile", "fs.open", ".spawn", ".exec", "require.resolve",
];
// The only modules a node -e snippet may require (read, in-tree write, compute); node: prefix allowed.
const NODE_MODULES = new Set(["fs", "path", "os", "util", "crypto", "stream", "buffer", "zlib", "url",
  "assert", "string_decoder", "querystring", "events", "readline"]);
// Modules a python snippet may import (read-only or in-tree write only).
const PY_MODULES = new Set(["json", "re", "sys", "math", "cmath", "pathlib", "collections", "itertools",
  "functools", "datetime", "time", "textwrap", "string", "hashlib", "base64", "binascii", "struct",
  "decimal", "fractions", "statistics", "random", "csv", "io", "typing", "dataclasses", "enum",
  "operator", "bisect", "heapq", "copy", "pprint", "unicodedata", "difflib", "html", "xml", "ast",
  "tomllib", "configparser", "gzip", "zlib", "yaml", "os", "os.path"]);

// Every path-looking string literal in the code must resolve inside the tree (an absolute one that
// escapes, or ~ / $HOME, is a write or read outside: not confined). Relative literals are inside cwd.
function pathLiteralsConfined(code, cwd, root) {
  for (const m of code.matchAll(/(['"])((?:[^'"\\]|\\.)*)\1/g)) {
    const s = m[2].replace(/\\(.)/g, "$1");   // undo escapes so \x2e etc do not hide a target
    // absolute, home, env-interpolated, or a relative path that climbs out with .. must be checked;
    // a plain relative literal resolves inside cwd (inside the tree)
    if (!s || (!s.startsWith("/") && !s.startsWith("~") && !s.startsWith("$") && !/(^|\/)\.\.(\/|$)/.test(s))) continue;
    if (s.startsWith("$")) return false;                    // an env-interpolated path: unknown
    const abs = resolvePath(s, cwd);
    if (abs === null || (abs !== root && !abs.startsWith(root + "/"))) return false;
  }
  return true;
}
function pyOk(code, cwd, root) {
  const flat = code.replace(/#[^\n]*/g, "");                 // drop comments
  if (PY_BAD.some(b => flat.includes(b))) return false;
  for (const m of flat.matchAll(/(?:^|\n)\s*(?:import\s+([\w.]+(?:\s*,\s*[\w.]+)*)|from\s+([\w.]+)\s+import)/g)) {
    const mods = (m[1] ? m[1].split(",") : [m[2]]).map(s => s.trim().split(".")[0]);
    if (!mods.every(x => PY_MODULES.has(x) || PY_MODULES.has(x + ""))) return false;
  }
  return pathLiteralsConfined(flat, cwd, root);
}
function nodeOk(code, cwd, root) {
  const flat = code.replace(/\/\/[^\n]*/g, "");
  if (NODE_BAD.some(b => flat.includes(b))) return false;
  // every require/import must be a clean allowlisted string literal; an obfuscated or computed target
  // (require(x), a broken literal, dynamic import()) is not, so any occurrence that does not parse to
  // an allowlisted module rejects. Count total occurrences against clean ones.
  if (/\bimport\s*\(/.test(flat)) return false;
  const ok = re => { let n = 0; for (const m of flat.matchAll(re)) { if (!NODE_MODULES.has(m[2].replace(/^node:/, "").split("/")[0])) return -1; n++; } return n; };
  const reqClean = ok(/\brequire\s*\(\s*(['"])([^'"]+)\1\s*\)/g);
  if (reqClean < 0 || reqClean !== (flat.match(/\brequire\s*\(/g) ?? []).length) return false;
  const impClean = ok(/\bfrom\s+(['"])([^'"]+)\1/g);
  if (impClean < 0 || impClean !== (flat.match(/\bfrom\s+['"]/g) ?? []).length) return false;
  // fs/os reach outside only through the APIs above (blocked) or writes, whose paths are literals here.
  return pathLiteralsConfined(flat, cwd, root);
}

// The inline code a segment runs, or null. Handles `-c "..."` / `-e "..."` and a single stdin heredoc.
function inlineCode(seg, whole) {
  const words = shellWords(seg.core);
  if (!words) return null;
  const name = words[0]?.raw?.replace(/^.*\//, "");
  const lang = /^python[\d.]*$/.test(name) ? "py" : name === "node" ? "node" : null;
  if (!lang) return null;
  // -c / -e with the code as the next word
  const flag = words.findIndex(w => ["-c", "-e", "--eval"].includes(w.raw));
  if (flag > -1 && words[flag + 1]) {
    // nothing after the code word except flags we do not accept -> only the interpreter, the flag and the code
    return {lang, code: words[flag + 1].value};
  }
  // stdin heredoc: `python3 - <<'EOF' ... EOF` or `python3 <<EOF ... EOF`, and nothing else runs
  const hd = /<<-?\s*(['"]?)([A-Za-z_]\w*)\1\s*\n([\s\S]*?)\n[ \t]*\2[ \t]*$/.exec(whole);
  if (hd && /^(cd\s+\S+\s*(&&|;)\s*)*(\S*\/)?(python[\d.]*|node)\b[^\n]*\s-\s*<<|(\S*\/)?(python[\d.]*|node)\s*<</.test(whole.replace(/\n[\s\S]*/, "\n")))
    return {lang, code: hd[3]};
  return null;
}

// ---------------------------------------------------------------------------------------------
/**
 * A workspace pass, or null. `deps` is unused (kept for symmetry with tools.mjs); everything is
 * imported. Only pass; never ask or deny.
 */
export function workspaceJudge(command, cwd, env = {}) {
  if (typeof command !== "string" || !command.trim() || command.length > MAX) return null;
  if (typeof cwd !== "string" || !cwd) return null;
  const root = repoRoot(cwd);
  if (!root) return null;                                     // must be inside a git working tree
  const c = command.replace(/\\\n/g, "");
  if (prodTier(command, cwd, env).prod) return null;          // production is never confined-reversible
  if (PIPE_TO_RUNNER.test(maskQuotes(c, " "))) return null;   // curl | bash and friends

  // pipelines() returns null when the text hides what runs. Empty quotes alone (the macOS `sed -i ''`
  // form) also make it bail though nothing is hidden; when there is no expansion, heredoc or
  // substitution, drop the empty quotes and retry (they are only an empty argument for our purposes).
  let ps = pipelines(c);
  if (ps === null && !/[$`]|<<|<\(|>\(/.test(maskQuotes(c, " "))) ps = pipelines(c.replace(/''|""/g, " "));
  const targets = [];
  if (ps === null) {
    // The text hides what runs ($, a heredoc, a substitution). The one confined case is a single
    // interpreter fed by a stdin heredoc, with the rest of the line only a leading cd inside the tree.
    const seg = {core: stripDataHeredocs(c, true).replace(/\\\n/g, "").trim(), targets: []};
    const inline = inlineCode(seg, c);
    if (!inline) return null;
    const ok = inline.lang === "py" ? pyOk(inline.code, cwd, root) : nodeOk(inline.code, cwd, root);
    if (!ok) return null;
    // a leading `cd DIR` in the heredoc line must stay inside the tree
    const cd = /(^|;|&&)\s*cd\s+(\S+)/.exec(maskQuotes(c.split("<<")[0], " "));
    if (cd && !insideTree(resolvePath(cd[2], cwd), cwd, root)) return null;
    return pass("inline interpreter code confined to the working tree");
  }
  if (!ps.length) return null;

  let sawWrite = false;
  for (const seg of ps) {
    const name = progOf(seg);
    // an interpreter with inline code (its literal writes are checked inside the analyzer)
    const inline = inlineCode(seg, c);
    if (inline) {
      if (!(inline.lang === "py" ? pyOk(inline.code, cwd, root) : nodeOk(inline.code, cwd, root))) return null;
      targets.push(...seg.targets); sawWrite = true; continue;
    }
    // a network read (curl/wget GET), writing nothing outside the tree
    if (["curl", "wget"].includes(name)) { if (!networkReadOk(seg, cwd, root)) return null; targets.push(...seg.targets); sawWrite = true; continue; }
    // a recognised local writer (mkdir/touch/cp/mv/tee/truncate/sed -i, plus redirects)
    if (WRITER.has(name)) {
      const lw = localWrites(seg, cwd);
      if (!lw.ok) return null;
      const bare = seg.core.replace(SED_INPLACE, " ");
      if (!(readOnly(bare) || WRITER.has(name))) return null;   // the reader part must be safe
      targets.push(...lw.targets); sawWrite = true; continue;
    }
    // a plain read-only step, possibly with a redirect into the tree (grep x f > out, cat a >> b)
    if (seg.inert) { targets.push(...seg.targets); if (seg.targets.length) sawWrite = true; continue; }
    return null;                                               // an unknown program: not confined
  }
  if (!sawWrite) return null;                                  // a pure read would have passed the read-only rung
  for (const t of targets) if (!insideTree(resolvePath(String(t).replace(/^>+\s*/, ""), cwd), cwd, root)) return null;
  return pass("writes confined to the working tree");
}

// npm/pnpm/yarn install in the repo: writes node_modules and the lockfile inside the tree. Allowed
// only when this package.json declares no install lifecycle script (the local attack surface the task
// calls out) and nothing is fetched from a URL, git or file spec. ponytail: a dependency's own
// postinstall still runs; that is the documented ceiling. Not part of workspaceJudge's path proof, so
// it is a separate check gate.mjs calls in the same rung.
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepack", "preprepare", "postprepare"];
export function npmInstallOk(command, cwd) {
  if (typeof command !== "string" || typeof cwd !== "string" || !cwd) return false;
  const root = repoRoot(cwd);
  if (!root) return false;
  const words = shellWords(command.replace(/\\\n/g, ""));
  if (!words) return false;
  const argv = words.map(w => w.raw);
  const pm = argv[0]?.replace(/^.*\//, "");
  if (!["npm", "pnpm", "yarn"].includes(pm)) return false;
  const sub = argv[1];
  const isInstall = (pm === "yarn" && (sub === undefined || sub === "install")) ||
    ((pm === "npm" || pm === "pnpm") && ["install", "i", "ci", "add"].includes(sub));
  if (!isInstall) return false;
  const rest = argv.slice(pm === "yarn" && sub === "install" ? 2 : 2).filter(a => !FLAG.test(a));
  // a package fetched from a URL, git or a file spec runs its own code from an unknown source
  if (rest.some(a => /(:\/\/|^git\+|^git@|^file:|\.tgz$|\.tar\.gz$|^https?:)/.test(a))) return false;
  // a global or relocated install writes outside the tree; --unsafe-perm / *-scripts re-enable scripts
  if (/(^|\s)(-g|--global|--location[=\s]global|--prefix|-C|--install-links|--unsafe-perm|--foreground-scripts|--allow-scripts)\b/.test(command)) return false;
  const pj = join(cwd, "package.json");
  try {
    const scripts = JSON.parse(readFileSync(pj, "utf8")).scripts ?? {};
    if (LIFECYCLE.some(s => scripts[s])) return false;
  } catch { return false; }   // no readable package.json in cwd: not confined
  return true;
}

// Allow-eligible: with a checkpoint taken first (gate.mjs), a confined reversible command may run
// without the agent's prompt. allowSetting/holdAllow decide whether the allow stands (REFLEX_ALLOW,
// enforce mode, not plan mode, not an unsandboxed retry); supervised keeps it a plain pass.
const pass = rule => ({outcome: "allow", source: "workspace", id: "workspace", rule});

export const WORKSPACE_DEFAULT = true;

