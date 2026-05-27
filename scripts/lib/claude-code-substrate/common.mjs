import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

export const repoRoot = resolve(process.cwd());

export function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
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

export function writeMarkdown(path, lines) {
  ensureDir(dirname(path));
  writeFileSync(path, `${Array.isArray(lines) ? lines.join("\n") : lines}\n`);
}

export function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

export function existingRelative(path) {
  return existsSync(path) ? relative(repoRoot, path) : "";
}

export function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) continue;
    const [key, inlineValue] = arg.slice(2).split("=", 2);
    args[key] = inlineValue ?? argv[index + 1] ?? true;
    if (inlineValue === undefined && argv[index + 1] && !argv[index + 1].startsWith("--")) {
      index += 1;
    }
  }
  return args;
}

export function proofEnvelope({ proofId, stage, rowIds, evidenceKind, outputPath, checks, productDecision = "", artifacts = {}, passed = true }) {
  return {
    schemaVersion: "ioi.autopilot.claude-code-substrate-absorption.proof.v1",
    generatedAt: new Date().toISOString(),
    proofId,
    stage,
    rowIds,
    evidenceKind,
    outputPath: relative(repoRoot, outputPath),
    passed,
    productDecision,
    artifacts,
    checks,
  };
}

