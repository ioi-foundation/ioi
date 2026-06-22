// Lane B (Phase 5) foothold gate — a Rust-native DETERMINISTIC/offline decision
// step against the provisioned workspace, emitting the SAME canonical session
// surface as Lane A, without replacing it. Fully verifiable offline (no model,
// no harness, no container): the only substrate is the wallet grant.
//
//   POST /v1/hypervisor/sessions/:id/execute  { lane: "native_local", intent }
//     - no grant  → 403 execution_authority_required (wallet-gated like Lane A)
//     - with a bound grant → executed: a REAL deterministic artifact in the
//       workspace, a REAL changed_file_groups diff, a REAL terminal transcript,
//       an Agentgres receipt, and an admitted capability_lease_ref.
//   The decision is DETERMINISTIC (sha256-seeded) → reproducible across runs.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { mintApprovalGrant } from "./mint-approval-grant.mjs";
import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let daemon;
let stateDir;
let sessionsRoot;
let priorSessions;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-laneb-state-"));
  sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-laneb-ws-"));
  priorSessions = process.env.IOI_HYPERVISOR_SESSIONS_ROOT;
  process.env.IOI_HYPERVISOR_SESSIONS_ROOT = sessionsRoot;
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  if (priorSessions === undefined) delete process.env.IOI_HYPERVISOR_SESSIONS_ROOT;
  else process.env.IOI_HYPERVISOR_SESSIONS_ROOT = priorSessions;
  for (const dir of [stateDir, sessionsRoot]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

function parseSse(text) {
  const frames = [];
  for (const block of text.split("\n\n")) {
    let event = null;
    let data = null;
    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) event = line.slice("event: ".length);
      else if (line.startsWith("data: ")) data = line.slice("data: ".length);
    }
    if (event && data) frames.push({ event, data: JSON.parse(data) });
  }
  return frames;
}

async function createSession(sessionRef) {
  const create = await fetch(`${daemon.endpoint}/v1/hypervisor/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_ref: sessionRef }),
  });
  assert.equal(create.status, 202);
  return (await create.json()).environment_status.components.workspace_content.workspace_root;
}

async function executeNativeLocal(sessionRef, body) {
  const response = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lane: "native_local", ...body }),
    },
  );
  return { status: response.status, body: await response.json() };
}

const INTENT = "create a website that explains post-quantum computers";

test("Lane B: native_local execution is wallet-gated (no grant → 403 challenge)", async () => {
  const sessionRef = "session:laneb-gate";
  await createSession(sessionRef);
  const challenge = await executeNativeLocal(sessionRef, { intent: INTENT });
  assert.equal(challenge.status, 403);
  assert.equal(challenge.body.reason, "execution_authority_required");
  assert.ok(challenge.body.approval.policy_hash && challenge.body.approval.request_hash);
  // Gated before any work — no fabricated output.
  assert.deepEqual(challenge.body.changed_file_groups, []);
  assert.deepEqual(challenge.body.terminal_events, []);
});

test("Lane B: a bound grant runs a deterministic, offline step with the real canonical surface", async () => {
  const sessionRef = "session:laneb-run";
  const workspaceRoot = await createSession(sessionRef);

  const challenge = await executeNativeLocal(sessionRef, { intent: INTENT });
  assert.equal(challenge.status, 403);
  const grant = mintApprovalGrant({
    policyHash: challenge.body.approval.policy_hash,
    requestHash: challenge.body.approval.request_hash,
  });

  const result = await executeNativeLocal(sessionRef, { intent: INTENT, wallet_approval_grant: grant });
  assert.equal(result.status, 200);
  assert.equal(result.body.decision, "executed");
  assert.equal(result.body.lane, "native_local_decision_step");
  assert.equal(result.body.deterministic, true);

  // Real file written by the Rust-native step.
  assert.deepEqual(result.body.files_written, ["lane-b-native-local/decision-step.md"]);
  const artifact = path.join(workspaceRoot, "lane-b-native-local/decision-step.md");
  assert.ok(fs.existsSync(artifact), "the deterministic artifact exists on disk");
  const contents = fs.readFileSync(artifact, "utf8");
  assert.match(contents, /native local model response\. input_hash=[0-9a-f]{12}/, "deterministic native-local content");

  // Real diff surfaces it.
  const diffNames = (result.body.changed_file_groups ?? []).flatMap((g) => g.files.map((f) => f.name));
  assert.ok(diffNames.includes("decision-step.md"), `diff includes the artifact: ${JSON.stringify(diffNames)}`);

  // Real transcript + admitted authority + receipt.
  assert.ok(result.body.terminal_events.some((e) => /\[lane-b:native_local\]/.test(String(e.text))), "real Lane B transcript");
  assert.ok(String(result.body.capability_lease_ref).startsWith("wallet.network://grant/approval/"), "admitted capability lease");
  assert.ok((result.body.latest_receipt_refs ?? []).some((r) => r.startsWith("receipt://hypervisor/session-lane-b/")), "Lane B receipt");

  // Determinism: the artifact content is reproducible for the same intent.
  const digest = contents.match(/input_hash=([0-9a-f]{12})/)[1];
  fs.rmSync(artifact);
  const rerun = await executeNativeLocal(sessionRef, { intent: INTENT, wallet_approval_grant: grant });
  assert.equal(rerun.status, 200);
  assert.match(fs.readFileSync(artifact, "utf8"), new RegExp(`input_hash=${digest}`), "same intent → same deterministic output");

  // The events SSE surfaces the real transcript as terminal_chunk.
  const events = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/events`,
    { headers: { accept: "text/event-stream" } },
  );
  const frames = parseSse(await events.text());
  assert.ok(frames.some((f) => f.event === "terminal_chunk"), "events surface the real Lane B transcript");
});
