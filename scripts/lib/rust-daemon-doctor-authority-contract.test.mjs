// Ported JS-daemon contract → Rust hypervisor-daemon: the `/v1/doctor` redacted
// runtime-readiness report and the `/v1/authority-evidence` summary projection.
//
// Origin: scripts/lib/live-runtime-daemon-contract.test.mjs (the JS daemon contract,
// "local daemon doctor reports redacted runtime readiness…" + "local daemon exposes
// compact authority evidence summaries…"). This re-homes that coverage onto the Rust
// true-north daemon so the JS daemon can be retired. Where the Rust projection expresses
// the same guarantee with a different shape BY DESIGN, we assert the equivalent guarantee
// (noted inline) rather than the legacy JS field.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let savedOpenAi;
let savedHosted;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-doctor-"));
  savedOpenAi = process.env.OPENAI_API_KEY;
  savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  process.env.OPENAI_API_KEY = "sk-doctor-secret-do-not-print";
  process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = "https://doctor-secret.example";
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  if (savedOpenAi === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = savedOpenAi;
  if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
  try {
    fs.rmSync(stateDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

const fetchJson = async (url) => {
  const response = await fetch(url);
  assert.ok(response.ok, `${url} -> ${response.status}`);
  return response.json();
};

test("Rust /v1/doctor reports a redacted runtime-readiness report (no secret leakage)", async () => {
  const report = await fetchJson(`${daemon.endpoint}/v1/doctor`);

  assert.equal(report.schemaVersion, "ioi.agent-runtime.doctor.v1");
  assert.equal(report.object, "ioi.agent_runtime_doctor_report");
  assert.equal(report.readiness, "ready");
  assert.ok(["pass", "degraded"].includes(report.status), `status: ${report.status}`);
  assert.deepEqual(report.blockers, []);

  // Redaction posture.
  assert.equal(report.redaction.secretValuesIncluded, false);
  assert.equal(report.redaction.endpointValuesHashed, true);

  // Workflow activation consumes the doctor report.
  assert.equal(report.workflow.doctorNodeType, "runtime_doctor");
  assert.equal(report.workflow.activationConsumesDoctorReport, true);

  // The public-API check passes; no REQUIRED check is failing.
  assert.ok(report.checks.some((check) => check.id === "daemon.public_api" && check.status === "pass"));
  assert.ok(report.checks.every((check) => !check.required || check.status === "pass"));

  // Provider key is surfaced as configured + hashed, never in the clear.
  const openAiKey = report.providerKeys.find((key) => key.name === "OPENAI_API_KEY");
  assert.equal(openAiKey.configured, true);
  assert.equal(openAiKey.valueRedacted, true);
  assert.match(openAiKey.valueHash, /^[a-f0-9]{64}$/);

  // The hosted-endpoint env var is surfaced (configured + hashed) via providerKeys — the
  // Rust projection expresses "hosted endpoint configured" here + via the node `status`,
  // and deliberately leaves the runtime node's `endpoint` null (so it is never hashed back
  // into a value). Assert the equivalent guarantee.
  const hostedKey = report.providerKeys.find((key) => key.name === "IOI_AGENT_SDK_HOSTED_ENDPOINT");
  assert.equal(hostedKey.configured, true);
  assert.match(hostedKey.valueHash, /^[a-f0-9]{64}$/);
  const hostedNode = report.runtimeNodes.find((node) => node.id === "hosted-provider");
  assert.equal(hostedNode.endpointConfigured, false, "hosted node endpoint is intentionally null in the Rust projection");
  assert.equal(hostedNode.status, "available", "configured hosted endpoint flips the node status to available");

  // No secret or endpoint value leaks into the serialized report.
  const serialized = JSON.stringify(report);
  assert.ok(!serialized.includes("sk-doctor-secret-do-not-print"), "no secret value leaked");
  assert.ok(!serialized.includes("doctor-secret.example"), "no endpoint value leaked");
});

test("Rust /v1/authority-evidence projects the compact snake_case summary contract", async () => {
  const evidence = await fetchJson(`${daemon.endpoint}/v1/authority-evidence`);

  // Canonical snake_case envelope — NOT the camelCase variant.
  assert.equal(evidence.schema_version, "ioi.authority-evidence-summary-list.v1");
  assert.equal(Object.hasOwn(evidence, "schemaVersion"), false);
  assert.equal(Object.hasOwn(evidence, "rowCount"), false);
  assert.equal(typeof evidence.row_count, "number");
  assert.ok(Array.isArray(evidence.items));

  // A fresh daemon has no capability-preflight rows yet; the projection is honest (empty),
  // not fabricated. (The populated-rows case requires seeding the runtime event log and is
  // covered by the deeper lifecycle port.)
  assert.equal(evidence.row_count, 0);
  assert.deepEqual(evidence.items, []);
});
