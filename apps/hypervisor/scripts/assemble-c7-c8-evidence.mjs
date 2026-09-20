#!/usr/bin/env node
// The live CLI over lib/c7-c8-evidence.mjs (R-211, 2026-09-20): this file reads the host — the
// driver's artifact directory, the daemon's durable families, git, the daemon binary and the
// substrate log — and hands what it read to `assembleRunEvidence`, which is the assembler itself.
// Its arguments, outputs and refusals are unchanged from the inline form it replaced.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { normalizeCertifiedSourceBasisForLifecycle } from "./lib/certified-daemon-source-basis.mjs";
import { assembleRunEvidence } from "./lib/c7-c8-evidence.mjs";

const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null; };
const artifacts = path.resolve(arg("--artifacts") || "");
const dataDir = path.resolve(arg("--data-dir") || "");
const repo = path.resolve(arg("--repo") || process.cwd());
const environment = arg("--environment");
const historicalSourcePath = arg("--source-basis-certificate");
const output = path.resolve(arg("--output") || path.join(artifacts, "run-evidence.json"));
if (!artifacts || !dataDir || !environment) {
  console.error("usage: assemble-c7-c8-evidence --artifacts <dir> --data-dir <dir> --environment <env> [--repo <repo>] [--source-basis-certificate <historical-certificate.json>] [--output <json>]");
  process.exit(2);
}
const read = (name) => JSON.parse(fs.readFileSync(path.join(artifacts, name), "utf8"));
const records = (family) => {
  const dir = path.join(dataDir, family);
  return fs.existsSync(dir) ? fs.readdirSync(dir).filter((name) => name.endsWith(".json")).map((name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"))) : [];
};
const shaFile = (file) => `sha256:${crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`;

const sourceBasisDocument = historicalSourcePath
  ? JSON.parse(fs.readFileSync(path.resolve(historicalSourcePath), "utf8"))
  : null;
const historicalSource = historicalSourcePath
  ? normalizeCertifiedSourceBasisForLifecycle(sourceBasisDocument)
  : null;
const status = historicalSource
  ? historicalSource.dirty_state_declaration
  : execFileSync("git", ["status", "--short"], { cwd: repo, encoding: "utf8" }).trim();
const source = historicalSource
  ? { ...historicalSource, dirty_state_declaration: status }
  : {
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim(),
    dirty_state_declaration: status,
    publication_eligible: true,
    daemon_binary_sha256: shaFile(path.join(repo, "target/debug/hypervisor-daemon")),
  };
const muxlog = fs.readFileSync(path.join(dataDir, "substrate/muxlog.bin"));

const evidence = assembleRunEvidence({
  artifacts: {
    challenge: read("c7-challenge.json"),
    proposalAdmission: read("c7-proposal-admission.json"),
    cast: read("c7-cast.json"),
    start: read("c7-start.json"),
    logs: read("c7-logs.json"),
    deleted: read("c7-delete.json"),
    reconcile: fs.existsSync(path.join(artifacts, "c7-reconcile.json")) ? read("c7-reconcile.json") : null,
    whoami: read("c7-whoami.json"),
    receipts: read("c7-receipts.json").receipts || [],
    reconciliation: read("c7-reconciliation.json"),
    operations: read("c7-operations.json").operations || [],
  },
  records: {
    deployments: records("akash-deployments"),
    leases: records("akash-leases"),
    endpoints: records("akash-endpoints"),
    capabilityLeases: records("capability-leases"),
  },
  environment,
  source,
  substrateAnchor: { bytes: muxlog.length, prefix_sha256: `sha256:${crypto.createHash("sha256").update(muxlog).digest("hex")}` },
});
fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ ok: evidence.ok, output, environment, final_net_cost_usd: evidence.settlement.final_net_cost_usd }));
