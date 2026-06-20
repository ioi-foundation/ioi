#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Hypervisor Generic CLI Local Harness

Usage:
  node packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs --provider ollama --model qwen --cd <workspace>

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

async function requestFileManifest(intent) {
  const system =
    "You are a coding harness operating inside an isolated workspace. Given a " +
    "task, respond with ONLY a JSON object of the form " +
    '{"summary": string, "files": [{"path": string, "content": string}]}. ' +
    "Each path is relative to the workspace root. Emit complete file contents. " +
    "Do not include any prose outside the JSON object.";
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
  return parseManifest(content);
}

function parseManifest(content) {
  const text = String(content).trim();
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const jsonText = fenced ? fenced[1] : sliceFirstJsonObject(text);
  const parsed = JSON.parse(jsonText);
  const files = Array.isArray(parsed.files) ? parsed.files : [];
  return {
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
    files: files
      .filter((file) => file && typeof file.path === "string")
      .map((file) => ({
        path: file.path,
        content: String(file.content ?? ""),
      })),
  };
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
