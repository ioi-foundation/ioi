// Cockpit session-flow EQUIPPED smoke — drives the APP client functions
// (the exact ones the migrated cockpit launchNewSession + composer call) against
// the live Rust daemon, proving the cockpit code path is reachable end to end:
//
//   requestHypervisorSessionCreate  → POST /v1/hypervisor/sessions (real workspace)
//   requestHypervisorSessionExecute → POST /sessions/:id/execute → 403 wallet
//     challenge → mint a bound grant → retry → executed with a real index.html,
//     real diff, real transcript, served preview port + capability_lease_ref.
//
// This is the node code-path equivalent of "click Launch in the cockpit and see
// real terminal/diff/preview from Rust". HONEST SKIP when Ollama/model/node are
// absent.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  readHypervisorExecutionAuthorityChallenge,
  requestHypervisorSessionCreate,
  requestHypervisorSessionExecute,
} from "../../apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts";
import { mintApprovalGrant } from "./mint-approval-grant.mjs";
import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MODEL_ENDPOINT = process.env.IOI_HYPERVISOR_MODEL_UPSTREAM ?? "http://127.0.0.1:11434/v1";
const PQC_INTENT =
  "Create a small static website that explains what post-quantum computers are. " +
  "Include an index.html file with a paragraph about post-quantum cryptography.";

async function detectEquipment() {
  const shim = path.resolve(repoRoot, "packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs");
  if (!fs.existsSync(shim)) return { ok: false, reason: "shim missing" };
  try {
    const response = await fetch(`${MODEL_ENDPOINT.replace(/\/v1\/?$/, "")}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (!response.ok) return { ok: false, reason: `ollama ${response.status}` };
    const models = ((await response.json()).models ?? []).map((m) => m.name);
    if (models.length === 0) return { ok: false, reason: "no models" };
    const model = models.find((n) => /^qwen2\.5/.test(n)) ?? models.find((n) => /qwen/i.test(n)) ?? models[0];
    return { ok: true, model };
  } catch (error) {
    return { ok: false, reason: String(error) };
  }
}

test("Cockpit equipped smoke: app client launches a real Rust session + runs the gated loop", { timeout: 240000 }, async (t) => {
  const equipment = await detectEquipment();
  if (!equipment.ok) {
    t.skip(`not equipped (${equipment.reason})`);
    return;
  }
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-cockpit-state-"));
  const sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-cockpit-ws-"));
  const prev = {
    upstream: process.env.IOI_HYPERVISOR_MODEL_UPSTREAM,
    model: process.env.IOI_HYPERVISOR_MODEL,
    sessions: process.env.IOI_HYPERVISOR_SESSIONS_ROOT,
  };
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = MODEL_ENDPOINT;
  process.env.IOI_HYPERVISOR_MODEL = equipment.model;
  process.env.IOI_HYPERVISOR_SESSIONS_ROOT = sessionsRoot;
  const daemon = await startRustHypervisorDaemon({ stateDir });
  const endpoint = daemon.endpoint;
  try {
    // 1) launchNewSession → requestHypervisorSessionCreate provisions a real session.
    const created = await requestHypervisorSessionCreate(
      { project_ref: "project:pqc", session_ref: "session:cockpit-smoke", workspace_mount_policy: "public_trunk" },
      { endpoint },
    );
    assert.equal(created.session_ref, "session:cockpit-smoke");
    const workspaceRoot = created.environment_status.components.workspace_content.workspace_root;
    assert.ok(fs.existsSync(workspaceRoot), "the cockpit launch provisioned a real workspace");

    // 2) composer execute without a grant → the daemon returns the wallet challenge.
    const challengeResponse = await requestHypervisorSessionExecute(
      created.session_ref,
      { intent: PQC_INTENT },
      { endpoint },
    );
    const challenge = readHypervisorExecutionAuthorityChallenge(challengeResponse);
    assert.ok(challenge, "the cockpit receives the 403 wallet challenge");
    assert.ok(challenge.required_scopes.includes("port_exposure"), "the challenge requires port_exposure");

    // 3) the dev/e2e wallet path mints a grant bound to the daemon-derived hashes.
    const grant = mintApprovalGrant({ policyHash: challenge.policy_hash, requestHash: challenge.request_hash });
    const executed = await requestHypervisorSessionExecute(
      created.session_ref,
      { intent: PQC_INTENT, wallet_approval_grant: grant },
      { endpoint },
    );
    assert.equal(executed.status, 200, `gated execute returns 200 (got ${executed.status})`);
    assert.equal(executed.body.decision, "executed");

    // 4) real terminal/diff/preview reach the cockpit through the result.
    assert.ok(Array.isArray(executed.body.files_written) && executed.body.files_written.includes("index.html"));
    assert.match(fs.readFileSync(path.join(workspaceRoot, "index.html"), "utf8"), /quantum/i);
    const diffNames = (executed.body.changed_file_groups ?? []).flatMap((g) => g.files.map((f) => f.name));
    assert.ok(diffNames.includes("index.html"), "real diff reaches the cockpit");
    assert.ok((executed.body.terminal_events ?? []).length > 0, "real transcript reaches the cockpit");
    const previewPort = (executed.body.environment_ports ?? [])[0];
    assert.ok(previewPort && previewPort.capability_lease_ref, "a wallet-gated preview port reaches the cockpit");
    const preview = await fetch(previewPort.url);
    assert.equal(preview.status, 200);
    assert.match(await preview.text(), /quantum/i, "the cockpit preview URL serves the real site");
  } finally {
    await daemon.close();
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
  }
});
