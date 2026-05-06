#!/usr/bin/env node
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultOutputRoot = path.join(repoRoot, "docs/evidence/model-mounting-closeout");
const schemaVersion = "ioi.model-mounting.closeout.v1";
const closeoutRequiredStatuses = new Set(["passed"]);
const nonClosingAllowedStatuses = new Set(["passed", "skipped", "blocked"]);

const deterministicGates = [
  {
    id: "guide-lint",
    command: "npm run check:model-mounting-guide",
    required: true,
    category: "guide",
  },
  {
    id: "model-mounting-contract",
    command: "npm run test:model-mounting",
    required: true,
    category: "deterministic",
  },
  {
    id: "daemon-runtime-api",
    command: "npm run test:daemon-runtime-api",
    required: true,
    category: "deterministic",
  },
  {
    id: "agent-sdk",
    command: "npm test --workspace=@ioi/agent-sdk",
    required: true,
    category: "deterministic",
  },
  {
    id: "model-backends",
    command: "npm run test:model-backends",
    required: true,
    category: "deterministic",
  },
  {
    id: "model-mounting-workflows",
    command: "npm run test:model-mounting-workflows",
    required: true,
    category: "deterministic",
  },
  {
    id: "model-mounting-gui-contract",
    command: "npm run test:model-mounting-gui",
    required: true,
    category: "deterministic",
  },
  {
    id: "model-mounting-e2e",
    command: "npm run validate:model-mounting:e2e",
    required: true,
    category: "evidence",
    evidencePattern: /docs\/evidence\/model-mounting-e2e\/[^\s]+\/result\.json/g,
  },
  {
    id: "mounts-gui",
    command: "npm run validate:model-mounts-gui:run",
    required: true,
    category: "gui",
    evidencePattern: /docs\/evidence\/model-mounts-gui-validation\/[^\s]+\/result\.json/g,
  },
  {
    id: "autopilot-gui-harness",
    command: "AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000",
    required: true,
    category: "gui",
    evidencePattern: /docs\/evidence\/autopilot-gui-harness-validation\/[^\s]+\/result\.json/g,
  },
  {
    id: "autopilot-tsc",
    command: "npx tsc -p apps/autopilot/tsconfig.json --noEmit",
    required: true,
    category: "build",
  },
  {
    id: "autopilot-build",
    command: "npm run build --workspace=apps/autopilot",
    required: true,
    category: "build",
  },
  {
    id: "agent-ide-build",
    command: "npm run build --workspace=@ioi/agent-ide",
    required: true,
    category: "build",
  },
  {
    id: "cli-check",
    command: "cargo check -p ioi-cli --bin cli",
    required: true,
    category: "build",
  },
  {
    id: "cli-build",
    command: "cargo build -p ioi-cli --bin cli",
    required: true,
    category: "build",
  },
  {
    id: "diff-check",
    command: "git diff --check",
    required: true,
    category: "hygiene",
  },
];

const liveGates = [
  {
    id: "lm-studio-live",
    command: "IOI_LIVE_LM_STUDIO=1 npm run test:lm-studio-live",
    required: true,
    category: "live",
    env: "IOI_LIVE_LM_STUDIO",
    evidencePattern: /docs\/evidence\/model-mounting-live\/lm-studio\/[^\s]+\/result\.json/g,
  },
  {
    id: "llama-cpp-live",
    command: "IOI_LIVE_LLAMA_CPP=1 npm run test:llama-cpp-live",
    required: true,
    category: "live",
    env: "IOI_LIVE_LLAMA_CPP",
    evidencePattern: /docs\/evidence\/model-mounting-live\/llama-cpp\/[^\s]+\/result\.json/g,
  },
  {
    id: "model-backends-live",
    command:
      "OLLAMA_HOST=${OLLAMA_HOST:-http://127.0.0.1:11434} IOI_PROVIDER_HTTP_TIMEOUT_MS=${IOI_PROVIDER_HTTP_TIMEOUT_MS:-120000} IOI_LIVE_MODEL_BACKENDS=1 npm run test:model-backends:live",
    required: true,
    category: "live",
    env: "IOI_LIVE_MODEL_BACKENDS",
    evidencePattern: /docs\/evidence\/model-mounting-live\/model-backends\/[^\s]+\/result\.json/g,
  },
  {
    id: "model-catalog-live",
    command: "IOI_LIVE_MODEL_CATALOG=1 npm run test:model-catalog-live",
    required: true,
    category: "live",
    env: "IOI_LIVE_MODEL_CATALOG",
    evidencePattern: /docs\/evidence\/model-mounting-live\/model-catalog\/[^\s]+\/result\.json/g,
  },
  {
    id: "model-catalog-oauth-live",
    command: "IOI_LIVE_MODEL_CATALOG_OAUTH=1 npm run test:model-catalog-oauth-live",
    required: true,
    category: "live",
    env: "IOI_LIVE_MODEL_CATALOG_OAUTH",
    evidencePattern: /docs\/evidence\/model-mounting-live\/model-catalog-oauth\/[^\s]+\/result\.json/g,
  },
  {
    id: "wallet-live",
    command: "IOI_REMOTE_WALLET=1 npm run test:wallet-live",
    required: true,
    category: "live",
    env: "IOI_REMOTE_WALLET",
    evidencePattern: /docs\/evidence\/model-mounting-live\/wallet\/[^\s]+\/result\.json/g,
  },
  {
    id: "agentgres-live",
    command: "IOI_REMOTE_AGENTGRES=1 npm run test:agentgres-live",
    required: true,
    category: "live",
    env: "IOI_REMOTE_AGENTGRES",
    evidencePattern: /docs\/evidence\/model-mounting-live\/agentgres\/[^\s]+\/result\.json/g,
  },
];

const fixtureFallbackGates = [
  {
    id: "model-catalog-oauth-fixture",
    command: "IOI_LIVE_MODEL_CATALOG_OAUTH=1 IOI_MODEL_CATALOG_OAUTH_FIXTURE=1 npm run test:model-catalog-oauth-live",
    required: true,
    category: "fixture-fallback",
    evidencePattern: /docs\/evidence\/model-mounting-live\/model-catalog-oauth\/[^\s]+\/result\.json/g,
  },
];

function timestamp() {
  return new Date().toISOString().replaceAll(":", "-").replace(/\.\d{3}Z$/, "Z");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function parseArgs(argv) {
  const options = {
    outputRoot: defaultOutputRoot,
    allowLiveSkips: false,
    skipDeterministic: false,
    skipLive: false,
    skipGui: false,
    dryRun: false,
    timeoutMs: 30 * 60 * 1000,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--output-root") {
      options.outputRoot = path.resolve(argv[++index]);
    } else if (arg === "--allow-live-skips") {
      options.allowLiveSkips = true;
    } else if (arg === "--skip-deterministic") {
      options.skipDeterministic = true;
    } else if (arg === "--skip-live") {
      options.skipLive = true;
      options.allowLiveSkips = true;
    } else if (arg === "--skip-gui") {
      options.skipGui = true;
    } else if (arg === "--dry-run") {
      options.dryRun = true;
      options.allowLiveSkips = true;
    } else if (arg === "--timeout-ms") {
      options.timeoutMs = Number(argv[++index] ?? options.timeoutMs);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

function redactText(text) {
  return String(text ?? "")
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]{12,}/gi, "Bearer [REDACTED]")
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, "sk-[REDACTED]")
    .replace(/(access_token|refresh_token|authorization_code|client_secret)=([^&\s]+)/gi, "$1=[REDACTED]")
    .replace(/"(access_token|refresh_token|authorization_code|client_secret)"\s*:\s*"[^"]+"/gi, "\"$1\":\"[REDACTED]\"");
}

function shellResultStatus(result) {
  if (result.error) return "failed";
  if (result.status === 0) return "passed";
  return "failed";
}

function runShell(command, { timeoutMs }) {
  const startedAt = new Date().toISOString();
  const result = childProcess.spawnSync("bash", ["-lc", command], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: timeoutMs,
    env: process.env,
    maxBuffer: 128 * 1024 * 1024,
  });
  const finishedAt = new Date().toISOString();
  return {
    command,
    startedAt,
    finishedAt,
    durationMs: Date.parse(finishedAt) - Date.parse(startedAt),
    exitCode: result.status,
    signal: result.signal,
    error: result.error?.message ?? null,
    status: shellResultStatus(result),
    stdout: redactText(result.stdout),
    stderr: redactText(result.stderr),
  };
}

function normalizeEvidencePath(candidate) {
  if (!candidate) return null;
  const absolute = path.isAbsolute(candidate) ? candidate : path.join(repoRoot, candidate);
  return fs.existsSync(absolute) ? path.relative(repoRoot, absolute) : null;
}

function evidenceFromOutput(output, pattern) {
  if (!pattern) return [];
  const matches = new Set();
  for (const match of String(output ?? "").matchAll(pattern)) {
    const normalized = normalizeEvidencePath(match[0]);
    if (normalized) matches.add(normalized);
  }
  return [...matches];
}

function readJsonIfPresent(relativePath) {
  if (!relativePath) return null;
  const absolute = path.join(repoRoot, relativePath);
  if (!fs.existsSync(absolute)) return null;
  try {
    return JSON.parse(fs.readFileSync(absolute, "utf8"));
  } catch {
    return null;
  }
}

function deriveEvidenceStatus(evidencePaths, commandStatus) {
  const loaded = evidencePaths
    .map((relativePath) => ({ relativePath, json: readJsonIfPresent(relativePath) }))
    .filter((entry) => entry.json);
  const statuses = loaded
    .map((entry) => entry.json.status ?? entry.json.result?.status ?? (entry.json.passed === true ? "passed" : null))
    .filter(Boolean);
  if (statuses.includes("failed")) return "failed";
  if (statuses.includes("blocked")) return "blocked";
  if (statuses.includes("skipped")) return "skipped";
  if (statuses.includes("passed")) return "passed";
  return commandStatus;
}

function deriveCloseoutEvidenceStatus(gate, evidencePaths, evidenceStatus) {
  if (evidenceStatus !== "passed") return evidenceStatus;

  if (["wallet-live", "agentgres-live"].includes(gate.id)) {
    for (const relativePath of evidencePaths) {
      const json = readJsonIfPresent(relativePath);
      const remoteMode = json?.result?.remoteMode ?? json?.details?.remoteMode ?? null;
      if (remoteMode === "deterministic_fake_remote") return "blocked";
    }
    return evidenceStatus;
  }

  if (gate.id !== "model-backends-live") return evidenceStatus;

  const requiredBackendKinds = new Set(["ollama", "vllm"]);
  const checked = [];
  for (const relativePath of evidencePaths) {
    const json = readJsonIfPresent(relativePath);
    if (Array.isArray(json?.result?.checked)) checked.push(...json.result.checked);
  }

  for (const kind of requiredBackendKinds) {
    const backend = checked.find((entry) => entry.kind === kind);
    if (!backend || ["absent", "blocked"].includes(backend.status)) return "blocked";
  }

  return evidenceStatus;
}

function gateSkippedReason(evidencePaths) {
  for (const relativePath of evidencePaths) {
    const json = readJsonIfPresent(relativePath);
    const reason = json?.reason ?? json?.result?.reason ?? json?.nextLiveStep ?? json?.result?.nextLiveStep;
    if (reason) return reason;
  }
  return null;
}

function gateEntry(gate, result, options) {
  const output = `${result.stdout}\n${result.stderr}`;
  const evidencePaths = evidenceFromOutput(output, gate.evidencePattern);
  const evidenceStatus = deriveEvidenceStatus(evidencePaths, result.status);
  const closeoutEvidenceStatus = deriveCloseoutEvidenceStatus(gate, evidencePaths, evidenceStatus);
  const closingStatus =
    gate.required && !closeoutRequiredStatuses.has(closeoutEvidenceStatus) ? "not_closing" : result.status;
  const allowedStatuses = options.allowLiveSkips ? nonClosingAllowedStatuses : closeoutRequiredStatuses;
  const acceptableForMode = !gate.required || allowedStatuses.has(closeoutEvidenceStatus);

  return {
    id: gate.id,
    category: gate.category,
    required: gate.required,
    command: gate.command,
    env: gate.env ?? null,
    status: result.status,
    evidenceStatus,
    closeoutEvidenceStatus,
    closingStatus,
    acceptableForMode,
    evidencePaths,
    blocker: acceptableForMode
      ? null
      : gateSkippedReason(evidencePaths) ?? `Gate ${gate.id} ended with ${closeoutEvidenceStatus}.`,
    exitCode: result.exitCode,
    signal: result.signal,
    error: result.error,
    durationMs: result.durationMs,
    stdoutHash: `sha256:${sha256Hex(result.stdout)}`,
    stderrHash: `sha256:${sha256Hex(result.stderr)}`,
  };
}

function skippedGateEntry(gate, reason) {
  return {
    id: gate.id,
    category: gate.category,
    required: gate.required,
    command: gate.command,
    env: gate.env ?? null,
    status: "skipped",
    evidenceStatus: "skipped",
    closingStatus: "not_closing",
    acceptableForMode: true,
    evidencePaths: [],
    blocker: reason,
    exitCode: null,
    signal: null,
    error: null,
    durationMs: 0,
    stdoutHash: null,
    stderrHash: null,
  };
}

function scanFilesForSecretShapes(roots) {
  const patterns = [
    /sk-[A-Za-z0-9_-]{20,}/,
    /Bearer\s+[A-Za-z0-9._~+/-]{20,}/i,
    /"(access_token|refresh_token|authorization_code|client_secret)"\s*:\s*"(?!\[REDACTED\]|redacted|vault:\/\/|sha256:)[^"]{8,}"/i,
  ];
  const findings = [];
  const visited = new Set();

  function visit(absolute) {
    if (!fs.existsSync(absolute)) return;
    const stat = fs.statSync(absolute);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(absolute)) {
        visit(path.join(absolute, entry));
      }
      return;
    }
    if (!stat.isFile() || stat.size > 8 * 1024 * 1024) return;
    const relativePath = path.relative(repoRoot, absolute);
    if (visited.has(relativePath)) return;
    visited.add(relativePath);
    const content = fs.readFileSync(absolute, "utf8");
    const lines = content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (patterns.some((pattern) => pattern.test(line))) {
        findings.push({ path: relativePath, line: index + 1, hash: `sha256:${sha256Hex(line)}` });
      }
    }
  }

  for (const root of roots) {
    visit(path.isAbsolute(root) ? root : path.join(repoRoot, root));
  }

  return { passed: findings.length === 0, findings };
}

function guideLintResult() {
  const result = runShell("npm run check:model-mounting-guide", { timeoutMs: 60_000 });
  return gateEntry(
    { id: "guide-lint-direct", category: "guide", required: true, command: result.command },
    result,
    { allowLiveSkips: false },
  );
}

function writeManifest(manifest, outputRoot) {
  const runDir = path.join(outputRoot, timestamp());
  fs.mkdirSync(runDir, { recursive: true });
  const resultPath = path.join(runDir, "result.json");
  fs.writeFileSync(resultPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return path.relative(repoRoot, resultPath);
}

function selectedGates(options) {
  const gates = [];
  if (!options.skipDeterministic) {
    gates.push(...deterministicGates.filter((gate) => !(options.skipGui && gate.category === "gui")));
  }
  if (!options.skipLive) {
    gates.push(...liveGates);
  }
  gates.push(...fixtureFallbackGates);
  return gates;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = {
    schemaVersion,
    generatedAt: new Date().toISOString(),
    status: "running",
    mode: {
      allowLiveSkips: options.allowLiveSkips,
      skipDeterministic: options.skipDeterministic,
      skipLive: options.skipLive,
      skipGui: options.skipGui,
      dryRun: options.dryRun,
    },
    closeoutStandard: {
      deterministicFixtureParityIsEnough: false,
      requiredLiveProductParity: true,
      requiredEvidenceRoot: "docs/evidence/model-mounting-closeout",
    },
    gates: [],
    secretScan: null,
    blockers: [],
  };

  const gates = selectedGates(options);
  if (options.dryRun) {
    manifest.gates = gates.map((gate) => skippedGateEntry(gate, "dry_run"));
  } else {
    for (const gate of gates) {
      const result = runShell(gate.command, { timeoutMs: options.timeoutMs });
      const entry = gateEntry(gate, result, options);
      manifest.gates.push(entry);
      if (entry.status === "failed" || !entry.acceptableForMode) {
        // Continue through all gates so the manifest captures the whole closeout state.
        manifest.blockers.push(entry.blocker ?? `${entry.id} failed.`);
      }
    }
  }

  const evidenceRoots = [
    "docs/evidence/model-mounting-closeout",
    "docs/evidence/model-mounting-e2e",
    "docs/evidence/model-mounts-gui-validation",
    "docs/evidence/model-mounting-live",
  ];
  manifest.secretScan = scanFilesForSecretShapes(evidenceRoots);
  if (!manifest.secretScan.passed) {
    manifest.blockers.push("Secret-shape scan found unredacted material in evidence.");
  }

  const directGuideLint = guideLintResult();
  manifest.guideLint = directGuideLint;
  if (directGuideLint.status !== "passed") {
    manifest.blockers.push("Master guide lint failed.");
  }

  const failedGates = manifest.gates.filter((gate) => gate.status === "failed");
  const nonClosingGates = manifest.gates.filter((gate) => gate.required && gate.closingStatus !== "passed");
  manifest.summary = {
    gateCount: manifest.gates.length,
    passedCount: manifest.gates.filter((gate) => gate.evidenceStatus === "passed").length,
    failedCount: failedGates.length,
    nonClosingCount: nonClosingGates.length,
    blockerCount: manifest.blockers.length,
  };
  manifest.status =
    manifest.blockers.length === 0 && failedGates.length === 0 && (options.allowLiveSkips || nonClosingGates.length === 0)
      ? "passed"
      : "failed";

  const resultPath = writeManifest(manifest, options.outputRoot);
  console.log(`[model-mounting-closeout] ${manifest.status}: ${resultPath}`);
  if (manifest.status !== "passed") {
    for (const blocker of manifest.blockers) {
      console.error(`[model-mounting-closeout] blocker: ${blocker}`);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
