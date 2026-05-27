#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const AUTOPILOT_CAMPAIGN_PROCESS_PATTERN =
  "[n]pm run dev:desktop|[l]aunch-autopilot-ide-fork|scripts/[i]oi-local-runtime-daemon\\.mjs|ide/builds/VSCode-linux-x64/[a]utopilot|[i]oi-runtime-bridge|[s]tartRuntimeDaemonService|packages/runtime-daemon/src/[i]ndex.mjs";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parentPid(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const endOfCommand = stat.lastIndexOf(")");
    const rest = stat.slice(endOfCommand + 2).trim().split(/\s+/);
    const ppid = Number(rest[1]);
    return Number.isFinite(ppid) ? ppid : null;
  } catch {
    return null;
  }
}

function ancestorPids(pid = process.pid) {
  const protectedPids = new Set([pid]);
  let current = pid;
  for (let depth = 0; depth < 32; depth += 1) {
    const ppid = parentPid(current);
    if (!ppid || ppid <= 1 || protectedPids.has(ppid)) break;
    protectedPids.add(ppid);
    current = ppid;
  }
  return protectedPids;
}

export function listAutopilotCampaignProcesses(pattern = AUTOPILOT_CAMPAIGN_PROCESS_PATTERN) {
  const protectedPids = ancestorPids();
  try {
    const raw = execFileSync("pgrep", ["-af", pattern], { encoding: "utf8" });
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [pid, ...rest] = line.split(/\s+/);
        return { pid: Number(pid), command: rest.join(" ") };
      })
      .filter((entry) => Number.isFinite(entry.pid) && !protectedPids.has(entry.pid));
  } catch {
    return [];
  }
}

function killProcesses(processes, signal) {
  for (const processInfo of processes) {
    try {
      process.kill(processInfo.pid, signal);
    } catch {
      // The process may have already exited between pgrep and kill.
    }
  }
}

export async function cleanupAutopilotCampaignProcesses({
  outputDir = null,
  phase = "manual",
  pattern = AUTOPILOT_CAMPAIGN_PROCESS_PATTERN,
  graceMs = 2000,
} = {}) {
  const before = listAutopilotCampaignProcesses(pattern);
  killProcesses(before, "SIGTERM");
  await sleep(graceMs);
  const stubborn = listAutopilotCampaignProcesses(pattern);
  killProcesses(stubborn, "SIGKILL");
  await sleep(250);
  const after = listAutopilotCampaignProcesses(pattern);
  const proof = {
    schemaVersion: "ioi.autopilot.gui-chat-ux-campaign.process-cleanup.v1",
    phase,
    pattern,
    before,
    stubborn,
    after,
    cleaned: before.length,
    ok: after.length === 0,
    timestamp: new Date().toISOString(),
  };
  if (outputDir) {
    mkdirSync(outputDir, { recursive: true });
    writeFileSync(join(outputDir, `process-cleanup-${phase}.json`), `${JSON.stringify(proof, null, 2)}\n`);
  }
  return proof;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2] ?? "list";
  const outputDirArgIndex = process.argv.indexOf("--output-dir");
  const phaseArgIndex = process.argv.indexOf("--phase");
  const outputDir =
    outputDirArgIndex >= 0 ? process.argv[outputDirArgIndex + 1] : null;
  const phase = phaseArgIndex >= 0 ? process.argv[phaseArgIndex + 1] : command;
  if (command === "list") {
    const processes = listAutopilotCampaignProcesses();
    process.stdout.write(`${JSON.stringify({ processes }, null, 2)}\n`);
    process.exit(0);
  }
  if (command === "cleanup") {
    const proof = await cleanupAutopilotCampaignProcesses({
      outputDir: outputDir && existsSync(outputDir) ? outputDir : outputDir,
      phase,
    });
    process.stdout.write(`${JSON.stringify(proof, null, 2)}\n`);
    process.exit(proof.ok ? 0 : 1);
  }
  process.stderr.write(`Unknown command: ${command}\n`);
  process.exit(2);
}
