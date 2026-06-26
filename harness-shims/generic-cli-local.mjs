#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Hypervisor Generic CLI Local Harness

Usage:
  node harness-shims/generic-cli-local.mjs --provider ollama --model qwen --cd <workspace>

Options:
  --provider <PROVIDER>       Local OpenAI-compatible provider. Use ollama for this harness.
  --model <MODEL>             Local model mounted by Hypervisor.
  --cd <DIR>                  Workspace root admitted by the Hypervisor Daemon.
  --harness-label <LABEL>     Optional display label for the configured CLI harness.
  --model-endpoint <URL>      OpenAI-compatible base URL (default IOI_HYPERVISOR_MODEL_UPSTREAM or :11434/v1).
  --once <PROMPT>             Run a single prompt in non-interactive mode.
  --help                      Show this help.
`);
  process.exit(0);
}

const options = parseOptions(args);
const provider = options.provider ?? "ollama";
const model = options.model ?? "qwen";
const workspace = options.cd ?? process.cwd();
const harnessLabel = options["harness-label"] ?? "Generic CLI Harness";
const modelEndpoint = (
  options["model-endpoint"] ??
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM ??
  "http://127.0.0.1:11434/v1"
).replace(/\/+$/, "");

if (provider !== "ollama") {
  console.error(`Unsupported provider for this generic harness: ${provider}`);
  process.exit(2);
}

if (!isSafeToken(model) || !isSafeLabel(harnessLabel)) {
  console.error("Model and harness labels must be shell-token safe.");
  process.exit(2);
}

if (options.once) {
  // Non-interactive single-shot: drive the model, write files, exit.
  const ok = await runIntent(String(options.once));
  process.exit(ok ? 0 : 1);
}

console.log(
  `Hypervisor Generic CLI Local Harness ready: label=${harnessLabel} provider=${provider} model=${model} workspace=${workspace}`,
);
console.log("Type /exit to close this generic harness session.");

let busy = false;
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  for (const line of chunk.split(/\r?\n/)) {
    const input = line.trim();
    if (!input) continue;
    if (input === "/exit" || input === "exit") process.exit(0);
    if (busy) continue;
    // Each non-command line is a task intent: drive the model and edit the
    // workspace, rather than echoing the input back.
    busy = true;
    await runIntent(input);
    busy = false;
  }
});

// Drive the local model for a file manifest and write the files into the
// admitted workspace. Returns true on success. Honest error (no faked work)
// when the model route is unreachable.
async function runIntent(intent) {
  console.log(`[generic-cli:${model}] planning: ${truncate(intent, 160)}`);
  let manifest;
  try {
    manifest = await requestFileManifest(intent);
    // Small local models occasionally return prose/empty with no parseable file. Retry once with a
    // more directive instruction so a single flaky turn doesn't silently produce nothing.
    if (!manifest.files.length) {
      console.log(`[generic-cli:${model}] no files parsed; retrying with a stricter instruction`);
      manifest = await requestFileManifest(intent, true);
    }
  } catch (error) {
    console.error(
      `[generic-cli:${model}] no model route: ${truncate(String(error), 200)} ` +
        `(endpoint=${modelEndpoint}). Start a local model (Ollama with a Qwen ` +
        `model) or set IOI_HYPERVISOR_MODEL_UPSTREAM.`,
    );
    emitResult({ ok: false, error: "no_model_route", files_written: [] });
    return false;
  }
  const written = [];
  for (const file of manifest.files) {
    const safe = safeWorkspacePath(workspace, file.path);
    if (!safe) {
      console.error(`[generic-cli:${model}] refused unsafe path: ${file.path}`);
      continue;
    }
    await mkdir(path.dirname(safe), { recursive: true });
    await writeFile(safe, file.content, "utf8");
    written.push(file.path);
    console.log(
      `[generic-cli:${model}] wrote ${file.path} (${Buffer.byteLength(
        file.content,
      )} bytes)`,
    );
  }
  if (manifest.summary) {
    console.log(`[generic-cli:${model}] ${manifest.summary}`);
  }
  emitResult({
    ok: true,
    summary: manifest.summary,
    files_written: written,
  });
  return true;
}

async function requestFileManifest(intent, strict = false) {
  const system =
    "You are a coding harness operating inside an isolated workspace. Given a " +
    "task, respond with ONLY a JSON object of the form " +
    '{"summary": string, "files": [{"path": string, "content": string}]}. ' +
    "Each path is relative to the workspace root and MUST include a file extension " +
    "(e.g. main.py, index.html, styles.css, README.md). Emit complete file contents. " +
    "Do not include any prose outside the JSON object." +
    (strict ? " You MUST return at least one file with non-empty content." : "");
  const response = await fetch(`${modelEndpoint}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model,
      stream: false,
      messages: [
        { role: "system", content: system },
        { role: "user", content: intent },
      ],
    }),
  });
  if (!response.ok) {
    throw new Error(`upstream responded ${response.status}`);
  }
  const payload = await response.json();
  const content = payload?.choices?.[0]?.message?.content ?? "";
  return parseManifest(content, intent);
}

// Parse the model response into {summary, files[]}. Small local models are
// inconsistent: some emit the requested JSON manifest, many emit fenced code
// blocks, and some emit raw code. We accept all three so DIVERSE tasks (python,
// sql, css, bash, …) reliably produce files — not just the JSON-friendly ones.
function parseManifest(content, intent = "") {
  const text = String(content).trim();
  // 1) Preferred: a JSON manifest (fenced ```json or the first {...}).
  const fromJson = tryJsonManifest(text, intent);
  if (fromJson && fromJson.files.length) return fromJson;
  // 2) Fenced code blocks → one file each, filename inferred from the fence
  //    language / an inline filename hint / the task.
  const blocks = [...text.matchAll(/```([A-Za-z0-9_.+-]*)\r?\n([\s\S]*?)```/g)];
  if (blocks.length) {
    const files = blocks.map((m, i) => ({
      path: inferFilename(m[1] || "", m[2], intent, i, blocks.length),
      content: `${m[2].replace(/\s+$/, "")}\n`,
    }));
    return { summary: fromJson?.summary || leadingProse(text) || "Generated files from the agent response.", files: dedupePaths(files) };
  }
  // 3) No fence + not JSON → the whole reply is the file; infer its name from the task.
  if (text) {
    return { summary: "Generated a file from the agent response.", files: [{ path: inferFilename("", text, intent, 0, 1), content: `${text}\n` }] };
  }
  throw new Error("model response did not contain files");
}

function tryJsonManifest(text, intent = "") {
  try {
    const fenced = text.match(/```(?:json)\s*([\s\S]*?)```/i);
    const jsonText = fenced ? fenced[1] : sliceFirstJsonObject(text);
    let parsed;
    try { parsed = JSON.parse(jsonText); } catch { parsed = JSON.parse(escapeControlCharsInStrings(jsonText)); }
    const files = Array.isArray(parsed.files) ? parsed.files : [];
    return {
      summary: typeof parsed.summary === "string" ? parsed.summary : "",
      files: files
        .filter((file) => file && typeof file.path === "string" && file.path.trim())
        // Models sometimes emit an extension-less path (e.g. "styles"); give it one.
        .map((file) => ({ path: ensureExtension(file.path.trim(), String(file.content ?? ""), intent), content: String(file.content ?? "") })),
    };
  } catch {
    return null;
  }
}

// Ensure a manifest path has a sensible extension (infer from content/language/intent if missing).
function ensureExtension(p, content, intent) {
  const base = p.split("/").pop() || p;
  if (/\.[A-Za-z0-9]{1,6}$/.test(base)) return p; // already has an extension
  const ext = EXT_FOR[langFromIntent(String(intent).toLowerCase(), content)] || "txt";
  return `${p}.${ext}`;
}

const EXT_FOR = { python: "py", py: "py", javascript: "js", js: "js", node: "js", typescript: "ts", ts: "ts", html: "html", xml: "html", css: "css", scss: "css", json: "json", jsonc: "json", bash: "sh", sh: "sh", shell: "sh", zsh: "sh", sql: "sql", markdown: "md", md: "md", java: "java", go: "go", golang: "go", ruby: "rb", rb: "rb", rust: "rs", rs: "rs", c: "c", cpp: "cpp", "c++": "cpp", yaml: "yaml", yml: "yaml", toml: "toml", text: "txt", "": "" };

function langFromIntent(it, body) {
  if (/\bpython\b|\.py\b|fibonacci|binary search tree/.test(it)) return "python";
  if (/\btypescript\b|\.ts\b/.test(it)) return "typescript";
  if (/\bjavascript\b|\bjs\b|node|debounce/.test(it)) return "javascript";
  if (/\bbash\b|\bshell\b|\.sh\b|backs? up|tarball/.test(it)) return "bash";
  if (/\bsql\b|schema|database|\btable\b/.test(it)) return "sql";
  if (/\bcss\b|stylesheet|theme|styles?/.test(it)) return "css";
  if (/readme|markdown|\bdoc/.test(it)) return "markdown";
  if (/\bjson\b|config/.test(it)) return "json";
  if (/\bhtml\b|website|web ?page|\bform\b|landing/.test(it)) return "html";
  // sniff the body as a last resort.
  if (/^\s*(def |import |print\(|class .*:)/m.test(body)) return "python";
  if (/<!doctype|<html/i.test(body)) return "html";
  if (/^\s*(CREATE TABLE|INSERT INTO|SELECT )/im.test(body)) return "sql";
  if (/^\s*(function |const |let |var |=>|export )/m.test(body)) return "javascript";
  if (/^\s*#!\s*\/.*sh\b/m.test(body)) return "bash";
  if (/^\s*[#*-]\s|^#{1,6}\s/m.test(body)) return "markdown";
  return "text";
}

function inferFilename(lang, body, intent, idx, total) {
  const it = String(intent || "").toLowerCase();
  // an explicit filename in the body (e.g. a "# fibonacci.py" header) or the task.
  const hint = (body.match(/(?:^|[\s#/*"'`(])([A-Za-z0-9._-]+\.(?:py|js|ts|html|css|json|sh|sql|md|java|go|rb|rs|c|cpp|ya?ml|toml|txt))\b/) ||
    it.match(/\b([a-z0-9._-]+\.(?:py|js|ts|html|css|json|sh|sql|md|java|go|rb|rs|c|cpp|ya?ml|toml|txt))\b/) || [])[1];
  if (hint) return hint;
  const ext = EXT_FOR[String(lang).toLowerCase()] || EXT_FOR[langFromIntent(it, body)] || "txt";
  const base = /readme/.test(it) ? "README"
    : /schema|database/.test(it) ? "schema"
    : /config/.test(it) ? "config"
    : ext === "css" ? "styles"
    : ext === "html" ? "index"
    : ext === "sql" ? "schema"
    : ext === "md" ? "README"
    : "main";
  return total > 1 ? `${base}${idx > 0 ? idx + 1 : ""}.${ext}` : `${base}.${ext}`;
}

function dedupePaths(files) {
  const seen = new Set();
  return files.map((f) => {
    let p = f.path;
    if (seen.has(p)) { const dot = p.lastIndexOf("."); p = dot > 0 ? `${p.slice(0, dot)}-${seen.size}${p.slice(dot)}` : `${p}-${seen.size}`; }
    seen.add(p);
    return { ...f, path: p };
  });
}

function leadingProse(text) {
  const before = text.split("```")[0].trim();
  return before && before.length < 200 ? before : "";
}

// Escape raw control characters (newlines/tabs/etc.) that appear INSIDE JSON
// string literals — the #1 way small local models produce not-quite-valid JSON
// when emitting multi-line file content. Structure outside strings is untouched.
function escapeControlCharsInStrings(text) {
  let out = "";
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const ch = text[index];
    const code = text.charCodeAt(index);
    if (!inString) {
      if (ch === '"') inString = true;
      out += ch;
      continue;
    }
    if (escaped) {
      out += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      out += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      out += ch;
      inString = false;
      continue;
    }
    if (code < 0x20) {
      if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else out += `\\u${code.toString(16).padStart(4, "0")}`;
      continue;
    }
    out += ch;
  }
  return out;
}

function sliceFirstJsonObject(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    throw new Error("model response did not contain a JSON object");
  }
  return text.slice(start, end + 1);
}

// Only ever write inside the admitted workspace root; reject traversal/escape.
function safeWorkspacePath(root, relative) {
  if (typeof relative !== "string" || !relative.trim()) return null;
  const normalizedRoot = path.resolve(root);
  const resolved = path.resolve(normalizedRoot, relative);
  if (
    resolved !== normalizedRoot &&
    !resolved.startsWith(normalizedRoot + path.sep)
  ) {
    return null;
  }
  return resolved;
}

// Machine-readable result line the spawn executor parses out of stdout.
function emitResult(result) {
  console.log(`__HYPERVISOR_HARNESS_RESULT__ ${JSON.stringify(result)}`);
}

function truncate(value, max) {
  const text = String(value);
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function parseOptions(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = "true";
      continue;
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function isSafeToken(value) {
  return /^[A-Za-z0-9._:/@+-]+$/.test(String(value ?? ""));
}

function isSafeLabel(value) {
  return /^[A-Za-z0-9._:/@+ -]+$/.test(String(value ?? ""));
}
