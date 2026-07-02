// Shared driver library for external harness adapters (OpenCode / DeepSeek TUI).
//
// A driver speaks the daemon's Lane A host-spawn protocol (same as generic-cli-local):
//   - prints a line containing "ready:" once it can accept work
//   - reads one task per stdin line ("/exit" closes)
//   - streams NORMALIZED HarnessAdapterEvent records to stdout as
//       __HYPERVISOR_ADAPTER_EVENT__ {json}
//   - finishes each task with the machine-readable result line
//       __HYPERVISOR_HARNESS_RESULT__ {json}   (carries implementation_result)
//
// Doctrine: the driver NEVER fabricates work. files_written is a real before/after
// workspace snapshot diff; events are mapped from the adapter CLI's actual output;
// a missing binary / dead model route is an honest error result, not a fake success.

import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const ADAPTER_EVENT_SENTINEL = "__HYPERVISOR_ADAPTER_EVENT__";
export const RESULT_SENTINEL = "__HYPERVISOR_HARNESS_RESULT__";
export const ADAPTER_EVENT_SCHEMA = "ioi.hypervisor.harness-adapter-event.v1";
export const IMPLEMENTATION_RESULT_SCHEMA = "ioi.hypervisor.implementation-result.v1";

const SNAPSHOT_IGNORED = new Set([".git", "node_modules", ".opencode", ".deepseek", ".cache"]);

let eventSeq = 0;

export function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) { options[key] = next; i++; }
      else options[key] = true;
    }
  }
  return options;
}

export function emitEvent(harness, kind, payload) {
  eventSeq += 1;
  const event = {
    schema_version: ADAPTER_EVENT_SCHEMA,
    event_id: `hae_${Date.now().toString(16)}_${eventSeq}`,
    harness,
    kind,
    at: new Date().toISOString(),
    payload: payload ?? {},
  };
  console.log(`${ADAPTER_EVENT_SENTINEL} ${JSON.stringify(event)}`);
  return event;
}

export function emitResult(result) {
  console.log(`${RESULT_SENTINEL} ${JSON.stringify(result)}`);
}

// Real workspace snapshot (relative path -> mtimeMs:size). Diffing two snapshots is the
// honest files_written source — whatever the adapter truly changed, however it changed it.
export function snapshotWorkspace(root) {
  const out = new Map();
  const walk = (dir, rel) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (SNAPSHOT_IGNORED.has(entry.name)) continue;
      const abs = path.join(dir, entry.name);
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(abs, relPath);
      else if (entry.isFile()) {
        try { const s = statSync(abs); out.set(relPath, `${s.mtimeMs}:${s.size}`); } catch { /* raced */ }
      }
    }
  };
  walk(root, "");
  return out;
}

export function diffSnapshots(before, after) {
  const written = [];
  for (const [rel, sig] of after) {
    if (before.get(rel) !== sig) written.push(rel);
  }
  return written.sort();
}

export function writeTempConfig(prefix, filename, content) {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  const file = path.join(dir, filename);
  writeFileSync(file, content);
  return file;
}

// Run the adapter CLI child, stream its stdout lines through mapLine (which emits
// normalized events), and resolve with the honest outcome.
export function runAdapterChild({ harness, command, args, env, cwd, timeoutMs, mapLine }) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let settled = false;
    let stdoutBuf = "";
    let stderrTail = [];
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill("SIGKILL"); } catch { /* gone */ }
        resolve({ exitCode: null, timedOut: true, stderrTail });
      }
    }, timeoutMs);
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode: null, timedOut: false, spawnError: error.message, stderrTail });
    });
    child.stdout.on("data", (chunk) => {
      stdoutBuf += chunk.toString();
      let idx;
      while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
        const line = stdoutBuf.slice(0, idx);
        stdoutBuf = stdoutBuf.slice(idx + 1);
        if (line.trim()) {
          try { mapLine(line); } catch { emitEvent(harness, "adapter_raw", { line: line.slice(0, 400) }); }
        }
      }
    });
    child.stderr.on("data", (chunk) => {
      for (const line of chunk.toString().split(/\r?\n/)) {
        if (!line.trim()) continue;
        stderrTail.push(line.slice(0, 300));
        if (stderrTail.length > 20) stderrTail.shift();
      }
    });
    child.on("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (stdoutBuf.trim()) { try { mapLine(stdoutBuf); } catch { /* tail fragment */ } }
      resolve({ exitCode: code, timedOut: false, stderrTail });
    });
  });
}

export function truncate(value, max) {
  const text = String(value ?? "");
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

// The task delivered to the adapter. Relative paths only: small local models mangle long
// absolute paths when echoing them into tool calls; the OS sandbox (daemon-side bwrap) is the
// hard boundary, this instruction just keeps the model on the happy path.
export function scopedTask(_workspace, intent) {
  return `You are already inside the admitted project workspace directory. Create or edit files using RELATIVE paths only (for example ./notes.txt) — never absolute paths. ${intent}`;
}

// Shared driver main loop: ready line -> one task per stdin line -> /exit. A stdin EOF while a
// task is running defers the exit until the task's honest result has been emitted.
export async function driverMain({ harness, label, runTask }) {
  console.log(`Hypervisor ${label} adapter driver ready: harness=${harness}`);
  let busy = false;
  let stdinEnded = false;
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", async (chunk) => {
    for (const line of chunk.split(/\r?\n/)) {
      const input = line.trim();
      if (!input) continue;
      if (input === "/exit" || input === "exit") process.exit(0);
      if (busy) continue;
      busy = true;
      try {
        await runTask(input);
      } catch (error) {
        emitResult({ ok: false, files_written: [], summary: "", error: `driver_failure: ${truncate(error.message, 200)}` });
      }
      busy = false;
      if (stdinEnded) process.exit(0);
    }
  });
  process.stdin.on("end", () => {
    stdinEnded = true;
    if (!busy) process.exit(0);
  });
}
