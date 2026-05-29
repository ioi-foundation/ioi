import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";

export const repoRoot = resolve(process.cwd());

export function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

export function readText(path) {
  return readFileSync(path, "utf8");
}

export function readJson(path) {
  return JSON.parse(readText(path));
}

export function maybeReadJson(path) {
  try {
    return readJson(path);
  } catch {
    return null;
  }
}

export function writeJson(path, body) {
  ensureDir(dirname(path));
  writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
}

export function writeJsonl(path, rows) {
  ensureDir(dirname(path));
  writeFileSync(path, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
}

export function writeMarkdown(path, body) {
  ensureDir(dirname(path));
  writeFileSync(path, `${Array.isArray(body) ? body.join("\n") : body}\n`);
}

export function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

export function rel(path) {
  return relative(repoRoot, path);
}

export function cleanDir(path) {
  rmSync(path, { recursive: true, force: true });
  ensureDir(path);
}

export function listDirectories(path) {
  if (!existsSync(path)) return [];
  return readdirSync(path)
    .map((name) => {
      const fullPath = `${path}/${name}`;
      try {
        const stat = statSync(fullPath);
        return stat.isDirectory() ? { name, path: fullPath, mtimeMs: stat.mtimeMs } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((left, right) => left.mtimeMs - right.mtimeMs);
}

export function newestDirectory(path, beforeNames = new Set()) {
  return listDirectories(path)
    .filter((entry) => !beforeNames.has(entry.name))
    .at(-1)?.path ?? null;
}

export function runCommand(command, args, options = {}) {
  const startedAt = Date.now();
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: { ...process.env, ...(options.env ?? {}) },
    encoding: "utf8",
    timeout: options.timeoutMs ?? 120_000,
    maxBuffer: options.maxBuffer ?? 10 * 1024 * 1024,
  });
  return {
    command,
    args,
    cwd: options.cwd ?? repoRoot,
    status: result.status,
    signal: result.signal,
    error: result.error ? String(result.error.message ?? result.error) : null,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    durationMs: Date.now() - startedAt,
    ok: result.status === 0,
  };
}

export function runCommandAsync(command, args, options = {}) {
  const startedAt = Date.now();
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repoRoot,
      env: { ...process.env, ...(options.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      child.kill("SIGTERM");
      setTimeout(() => {
        if (!settled) child.kill("SIGKILL");
      }, 1000).unref();
    }, options.timeoutMs ?? 120_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > (options.maxBuffer ?? 10 * 1024 * 1024)) {
        stdout = stdout.slice(-(options.maxBuffer ?? 10 * 1024 * 1024));
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (stderr.length > (options.maxBuffer ?? 10 * 1024 * 1024)) {
        stderr = stderr.slice(-(options.maxBuffer ?? 10 * 1024 * 1024));
      }
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({
        command,
        args,
        cwd: options.cwd ?? repoRoot,
        status: null,
        signal: null,
        error: String(error?.message ?? error),
        stdout,
        stderr,
        durationMs: Date.now() - startedAt,
        ok: false,
      });
    });
    child.on("close", (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({
        command,
        args,
        cwd: options.cwd ?? repoRoot,
        status,
        signal,
        error: null,
        stdout,
        stderr,
        durationMs: Date.now() - startedAt,
        ok: status === 0,
      });
    });
  });
}

export function parseMaybeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function parseSseEvents(text) {
  const rows = [];
  const normalized = String(text ?? "").replace(/\r\n/g, "\n");
  for (const block of normalized.split(/\n\n+/)) {
    const dataLines = block
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trimStart());
    if (!dataLines.length) continue;
    const data = dataLines.join("\n");
    const parsed = parseMaybeJson(data);
    rows.push(parsed ?? { raw: data });
  }
  const directJson = parseMaybeJson(normalized);
  if (!rows.length && Array.isArray(directJson)) return directJson;
  if (!rows.length && Array.isArray(directJson?.events)) return directJson.events;
  return rows;
}

export async function requestJson(endpoint, method, path, body, transcript = []) {
  const startedAt = Date.now();
  const response = await fetch(`${endpoint}${path}`, {
    method,
    headers: body
      ? { "content-type": "application/json", accept: "application/json, text/event-stream" }
      : { accept: "application/json, text/event-stream" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  const parsed = contentType.includes("text/event-stream")
    ? { events: parseSseEvents(text), rawText: text }
    : parseMaybeJson(text) ?? { rawText: text };
  const entry = {
    method,
    path,
    status: response.status,
    ok: response.ok,
    durationMs: Date.now() - startedAt,
    request: body ?? null,
    response: parsed,
  };
  transcript.push(entry);
  if (!response.ok) {
    const error = new Error(`${method} ${path} failed with ${response.status}`);
    error.entry = entry;
    throw error;
  }
  return parsed;
}

export function assertCheck(condition, label, details = {}) {
  return {
    label,
    passed: Boolean(condition),
    details,
  };
}

export function summarizeChecks(checks) {
  return {
    passed: checks.every((check) => check.passed),
    total: checks.length,
    failed: checks.filter((check) => !check.passed).map((check) => check.label),
  };
}

export function commandEvidence(commandResult) {
  const parsedJson = parseMaybeJson(commandResult.stdout);
  return {
    command: commandResult.command,
    args: commandResult.args,
    status: commandResult.status,
    signal: commandResult.signal,
    ok: commandResult.ok,
    durationMs: commandResult.durationMs,
    stdoutPreview: commandResult.stdout.slice(0, 12_000),
    stderrPreview: commandResult.stderr.slice(0, 12_000),
    parsedJson,
  };
}

export function pgrep(pattern) {
  const result = runCommand("pgrep", ["-af", pattern], { timeoutMs: 10_000 });
  return {
    pattern,
    status: result.status,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
    matches: result.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  };
}

export function cleanupProof(patterns) {
  return {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.cleanup.v1",
    generatedAt: new Date().toISOString(),
    probes: patterns.map((pattern) => pgrep(pattern)),
  };
}
