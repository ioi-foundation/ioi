// Hypervisor session execution — Lane A, Cut #2/#3 EQUIPPED gate.
//
// The execute endpoint is wallet-gated (Cut #3): consequential effects
// (workspace_write + command_exec) require a wallet capability grant bound to
// daemon-derived policy_hash + request_hash. This gate proves, on an equipped
// box (local Ollama model + node + the generic-cli-local shim):
//
//   NEGATIVES (must block BEFORE any spawn — no files, no transcript):
//     - no grant                → 403 execution_authority_required (exposes hashes)
//     - wrong policy_hash        → 403
//     - expired grant            → 403
//     - wrong request_hash       → 403
//
//   POSITIVE (gated real loop):
//     - challenge → mint a valid wallet grant → execute → the harness drives the
//       local model, writes a REAL index.html, the diff/transcript are real, and
//       the receipts carry the admitted capability_lease_ref + authority scopes.
//
// HONEST SKIP when Ollama/model/node/shim are absent. The offline fail-closed
// contract is covered by hypervisor-session-execution-cut1.test.mjs.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { mintApprovalGrant } from "./mint-approval-grant.mjs";
import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MODEL_ENDPOINT = process.env.IOI_HYPERVISOR_MODEL_UPSTREAM ?? "http://127.0.0.1:11434/v1";
const PQC_INTENT =
  "Create a small static website that explains what post-quantum computers are. " +
  "Include an index.html file with a paragraph about post-quantum cryptography.";

function tagsUrl() {
  return `${MODEL_ENDPOINT.replace(/\/v1\/?$/, "")}/api/tags`;
}

async function detectEquipment() {
  const shim = path.resolve(repoRoot, "packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs");
  if (!fs.existsSync(shim)) return { ok: false, reason: "generic-cli-local shim missing" };
  try {
    const response = await fetch(tagsUrl(), { signal: AbortSignal.timeout(3000) });
    if (!response.ok) return { ok: false, reason: `ollama tags ${response.status}` };
    const body = await response.json();
    const models = (body.models ?? []).map((model) => model.name).filter(Boolean);
    if (models.length === 0) return { ok: false, reason: "no local models cached" };
    const preferred = process.env.IOI_HYPERVISOR_MODEL;
    const model =
      (preferred && models.includes(preferred) && preferred) ||
      models.find((name) => /^qwen2\.5/.test(name)) ||
      models.find((name) => /qwen/i.test(name)) ||
      models[0];
    return { ok: true, model };
  } catch (error) {
    return { ok: false, reason: `ollama unreachable: ${String(error)}` };
  }
}

const equipment = await detectEquipment();
const SKIP = equipment.ok ? false : `not equipped (${equipment.reason}) — offline path covered by the cut1 gate`;

let daemon;
let stateDir;
let sessionsRoot;
let prev;

beforeEach(async () => {
  if (SKIP) return;
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-equip-state-"));
  sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-equip-ws-"));
  prev = {
    upstream: process.env.IOI_HYPERVISOR_MODEL_UPSTREAM,
    model: process.env.IOI_HYPERVISOR_MODEL,
    sessions: process.env.IOI_HYPERVISOR_SESSIONS_ROOT,
  };
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = MODEL_ENDPOINT;
  process.env.IOI_HYPERVISOR_MODEL = equipment.model;
  process.env.IOI_HYPERVISOR_SESSIONS_ROOT = sessionsRoot;
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  if (SKIP) return;
  await daemon?.close();
  for (const [key, value] of [
    ["IOI_HYPERVISOR_MODEL_UPSTREAM", prev.upstream],
    ["IOI_HYPERVISOR_MODEL", prev.model],
    ["IOI_HYPERVISOR_SESSIONS_ROOT", prev.sessions],
  ]) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
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
    body: JSON.stringify({ project_ref: "project:pqc", session_ref: sessionRef }),
  });
  assert.equal(create.status, 202);
  const created = await create.json();
  return created.environment_status.components.workspace_content.workspace_root;
}

async function execute(sessionRef, body) {
  const response = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
  );
  return { status: response.status, body: await response.json() };
}

test("Equipped gate — execution authority blocks every unauthorized grant BEFORE spawn", { timeout: 120000 }, async (t) => {
  if (SKIP) {
    t.skip(SKIP);
    return;
  }
  const sessionRef = "session:authz-neg";
  const workspaceRoot = await createSession(sessionRef);

  // No grant → 403 challenge exposing the daemon-derived hashes.
  const challenge = await execute(sessionRef, { intent: PQC_INTENT });
  assert.equal(challenge.status, 403, "no grant is rejected");
  assert.equal(challenge.body.decision, "blocked");
  assert.equal(challenge.body.reason, "execution_authority_required");
  assert.ok(challenge.body.required_scopes.includes("workspace_write"), "workspace_write scope required");
  assert.ok(challenge.body.required_scopes.includes("command_exec"), "command_exec scope required");
  const policyHash = challenge.body.approval.policy_hash;
  const requestHash = challenge.body.approval.request_hash;
  assert.ok(policyHash && requestHash, "challenge exposes policy_hash + request_hash to mint against");
  assert.deepEqual(challenge.body.changed_file_groups, [], "no fabricated work on the challenge");

  // Wrong policy_hash (correct request_hash) → blocked.
  const wrongPolicy = await execute(sessionRef, {
    intent: PQC_INTENT,
    wallet_approval_grant: mintApprovalGrant({ policyHash: "22".repeat(32), requestHash }),
  });
  assert.equal(wrongPolicy.status, 403, "a grant bound to a different policy_hash is rejected");

  // Wrong request_hash (correct policy_hash) → blocked.
  const wrongRequest = await execute(sessionRef, {
    intent: PQC_INTENT,
    wallet_approval_grant: mintApprovalGrant({ policyHash, requestHash: "11".repeat(32) }),
  });
  assert.equal(wrongRequest.status, 403, "a grant bound to a different request_hash is rejected");

  // Expired grant (correct hashes) → blocked.
  const expired = await execute(sessionRef, {
    intent: PQC_INTENT,
    wallet_approval_grant: mintApprovalGrant({ policyHash, requestHash, expiresAt: 1000 }),
  });
  assert.equal(expired.status, 403, "an expired grant is rejected");

  // Every rejection blocked BEFORE spawn — the workspace stayed empty.
  assert.equal(fs.existsSync(path.join(workspaceRoot, "index.html")), false, "no file was written under a blocked grant");
});

test("Equipped gate — a valid wallet grant authorizes the real Lane A loop", { timeout: 240000 }, async (t) => {
  if (SKIP) {
    t.skip(SKIP);
    return;
  }
  const sessionRef = "session:authz-pos";
  const workspaceRoot = await createSession(sessionRef);

  // Challenge for the daemon-derived hashes, then mint a valid bound grant.
  const challenge = await execute(sessionRef, { intent: PQC_INTENT });
  assert.equal(challenge.status, 403);
  const grant = mintApprovalGrant({
    policyHash: challenge.body.approval.policy_hash,
    requestHash: challenge.body.approval.request_hash,
  });

  const result = await execute(sessionRef, { intent: PQC_INTENT, wallet_approval_grant: grant });
  assert.equal(result.status, 200, `gated execute returns 200 (got ${result.status})`);
  assert.equal(result.body.decision, "executed", `decision executed (error=${JSON.stringify(result.body.error)})`);
  assert.equal(result.body.exit_status, "success");
  assert.equal(result.body.model, equipment.model);

  // Admitted authority surfaced on the result.
  assert.ok(
    String(result.body.capability_lease_ref).startsWith("wallet.network://grant/approval/"),
    `capability_lease_ref is an admitted wallet grant ref: ${result.body.capability_lease_ref}`,
  );
  assert.ok(result.body.authority_scope_refs.includes("workspace_write"), "workspace_write authorized");
  assert.ok(result.body.authority_scope_refs.includes("command_exec"), "command_exec authorized");

  // Real file writes.
  assert.ok(result.body.files_written.includes("index.html"), `files_written includes index.html: ${JSON.stringify(result.body.files_written)}`);
  const indexPath = path.join(workspaceRoot, "index.html");
  assert.ok(fs.existsSync(indexPath), "index.html exists on disk");
  assert.match(fs.readFileSync(indexPath, "utf8"), /quantum/i, "index.html mentions quantum");

  // Real diff + real transcript.
  const diffNames = (result.body.changed_file_groups ?? []).flatMap((group) => group.files.map((file) => file.name));
  assert.ok(diffNames.includes("index.html"), `diff includes index.html: ${JSON.stringify(diffNames)}`);
  assert.ok(result.body.terminal_events.length > 0, "real transcript present");
  assert.ok(
    result.body.terminal_events.some((event) => /generic-cli/.test(String(event.text))),
    "transcript carries real harness output",
  );

  // The execute receipt carries the admitted capability lease.
  const execReceiptRef = (result.body.latest_receipt_refs ?? []).find((ref) =>
    String(ref).startsWith("receipt://hypervisor/session-execute/"),
  );
  assert.ok(execReceiptRef, "execute receipt present");

  // A REAL wallet-gated preview port was opened, exposing the served site.
  const previewPort = (result.body.environment_ports ?? [])[0];
  assert.ok(previewPort, "a preview port was exposed for the served site");
  assert.equal(previewPort.exposure_state, "open");
  assert.equal(
    previewPort.capability_lease_ref,
    result.body.capability_lease_ref,
    "the preview port carries the admitted capability lease (port_exposure is gated)",
  );
  assert.match(String(previewPort.url), /^http:\/\/127\.0\.0\.1:\d+\/$/, `preview url: ${previewPort.url}`);
  assert.ok(result.body.authority_scope_refs.includes("port_exposure"), "port_exposure scope admitted");

  // The served preview returns the REAL index.html bytes over the real listener.
  const preview = await fetch(previewPort.url);
  assert.equal(preview.status, 200, "preview listener serves 200");
  assert.match(await preview.text(), /quantum/i, "served preview is the real index.html");

  // The events SSE surfaces the real transcript (terminal_chunk) + the port.
  const events = await fetch(
    `${daemon.endpoint}/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/events`,
    { headers: { accept: "text/event-stream" } },
  );
  const frames = parseSse(await events.text());
  assert.ok(frames.some((frame) => frame.event === "terminal_chunk"), "events surface real terminal_chunk frames");
  const envStatus = frames.find((frame) => frame.event === "environment_status")?.data;
  assert.ok(
    (envStatus?.ports ?? []).some((p) => p.url === previewPort.url && p.capability_lease_ref),
    "environment_status surfaces the wallet-gated preview port",
  );
});
