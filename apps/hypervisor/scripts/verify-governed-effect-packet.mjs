#!/usr/bin/env node
//
// The packet builder is only trustworthy if its disclosure scan can actually
// refuse, and if its claim matrix cannot quietly promote a rung nothing
// supports. This gate builds a packet from the retained, already-accepted
// evidence into a temp dir, asserts both, and publishes nothing.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanDisclosure, claimToEvidenceMatrix } from "./build-governed-effect-packet.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../../..");
const home = process.env.HOME;
const evidenceRoot = process.env.IOI_U1_CAMPAIGN_EVIDENCE_ROOT || path.join(home, ".ioi/hypervisor/evidence/u1");
const admissionDir = path.join(evidenceRoot, "campaign-o-aes-phl-14d24907/c8-v3-registry-admission");
const bundleDir = path.join(admissionDir, "portable-bundle");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-packet-gate-"));
const findings = [];

try {
  for (const required of [bundleDir, admissionDir]) {
    if (!fs.existsSync(required)) throw new Error(`retained evidence is absent: ${required}`);
  }
  const output = path.join(temp, "public-evidence");
  const built = spawnSync(process.execPath, [
    path.join(here, "build-governed-effect-packet.mjs"),
    "--bundle", bundleDir, "--admission", admissionDir, "--output", output,
  ], { cwd: repo, encoding: "utf8" });
  if (built.status !== 0) throw new Error(`packet build failed: ${built.stderr || built.stdout}`);

  const files = fs.readdirSync(output).sort();
  if (!files.includes("claim-nonclaim-manifest.json") || !files.includes("manifest.sha256")) {
    findings.push("packet is missing its claim matrix or checksum manifest");
  }

  // 1. Every emitted byte survives the scan.
  for (const name of files) {
    const failures = scanDisclosure(fs.readFileSync(path.join(output, name), "utf8"), "");
    if (failures.length > 0) findings.push(`emitted packet file leaks: ${name} -> ${failures.join(",")}`);
  }

  // 2. The scan can refuse. Each planted leak must be caught for its own reason.
  const planted = [
    ["bearer_session", "session ioi_sess_deadbeefcafe1234 retained"],
    ["absolute_home_path", 'path "/home/operator/.config/thing"'],
    ["internal_data_dir_layout", "read from .ioi/hypervisor/data/principals"],
    ["registry_credential_ref", "registry connector://conn_98d89041141110ce"],
    ["operator_email", "contact operator@example.com"],
    ["private_key_pem", "-----BEGIN PRIVATE KEY-----"],
    ["provider_account_locator", "provider-account://pacc_18cd245812ad55b9"],
    ["wallet_fixture_path", "/tmp/ioi-wallet-network-pa-123/ca.pem"],
  ];
  for (const [code, sample] of planted) {
    const caught = scanDisclosure(sample, "");
    if (!caught.includes(code)) findings.push(`planted ${code} was not refused (observed ${caught.join(",") || "nothing"})`);
  }
  const canary = "ioi-packet-canary-abc123";
  if (!scanDisclosure(`harmless text ${canary}`, canary).includes("seeded_canary")) {
    findings.push("a seeded canary passed the scan");
  }

  // 3. The claim matrix cannot promote a rung nothing supports.
  const emptyMatrix = claimToEvidenceMatrix({ claims: { claims: [] }, acceptance: null, capstoneRun: false });
  const wronglyDemonstrated = emptyMatrix.rungs.filter((r) => r.status === "demonstrated" && !r.evidence);
  if (wronglyDemonstrated.length > 0) findings.push(`rung demonstrated with no evidence: ${wronglyDemonstrated.map((r) => r.rung).join(",")}`);
  const manifestBacked = emptyMatrix.rungs.filter((r) => [1, 2, 3, 4, 5, 9].includes(r.rung));
  if (manifestBacked.some((r) => r.status !== "not_demonstrated")) {
    findings.push("a certificate-backed rung stayed demonstrated with an empty claim manifest");
  }
  const rejected = claimToEvidenceMatrix({ claims: { claims: [] }, acceptance: { decision: "rejected" }, capstoneRun: false });
  if (rejected.rungs.find((r) => r.rung === 8).status !== "not_demonstrated") {
    findings.push("a rejected acceptance receipt still lit the relying-party rung");
  }

  // 4. The real matrix must be honest about what has NOT run.
  const real = JSON.parse(fs.readFileSync(path.join(output, "claim-nonclaim-manifest.json"), "utf8"));
  if (real.integrated_capstone.status !== "not_demonstrated") findings.push("packet claims an integrated capstone that has not run");
  if (real.rungs.find((r) => r.rung === 10).status !== "not_demonstrated") findings.push("packet claims external witnessing");
  if (real.rungs.length !== 10) findings.push(`claim matrix has ${real.rungs.length} rungs, expected 10`);

  const verdict = findings.length === 0 ? "PASS" : "FAIL";
  console[verdict === "PASS" ? "log" : "error"](JSON.stringify({
    check: "check:governed-effect-packet", verdict,
    packet_files: files.length,
    disclosure_patterns_proved_refusable: planted.length + 1,
    rungs: real.rungs.map((r) => ({ rung: r.rung, status: r.status })),
    integrated_capstone: real.integrated_capstone.status,
    published: false,
    findings,
  }, null, 2));
  process.exit(verdict === "PASS" ? 0 : 1);
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
