// Phase 5 (browser consolidation) EQUIPPED gate — the daemon-hosted canonical
// handle_step drives the REAL BrowserDriver (Chromium). A wallet-gated step@v1 with a
// `browser_navigate` directive deterministically dispatches a constrained
// browser__navigate that launches Chromium and loads a benign local file:// page.
//
// This is NOT offline: it needs the chromiumoxide Chromium cached under
// ./ioi-data/browser_cache (the daemon launches it). The test SKIPS HONESTLY when that
// cache is absent. The daemon's tokio worker stack must be large enough for the deep
// browser async chain (the daemon configures 32 MiB by default).

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { mintApprovalGrant } from "./mint-approval-grant.mjs";
import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function chromiumCached() {
  try {
    const cacheDir = path.join(repoRoot, "ioi-data", "browser_cache");
    return fs.readdirSync(cacheDir).some((entry) => entry.startsWith("linux-"));
  } catch {
    return false;
  }
}

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-p5br-"));
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  try {
    fs.rmSync(stateDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

async function postRuntimeHost(body) {
  const response = await fetch(`${daemon.endpoint}/v1/hypervisor/runtime-host/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function grantedRun(request) {
  const challenge = await postRuntimeHost(request);
  assert.equal(challenge.status, 403, `step is wallet-gated (got ${challenge.status})`);
  const grant = mintApprovalGrant({
    policyHash: challenge.body.approval.policy_hash,
    requestHash: challenge.body.approval.request_hash,
  });
  return postRuntimeHost({ ...request, wallet_approval_grant: grant });
}

test(
  "Phase 5 (browser): a browser_navigate directive REALLY launches Chromium and navigates to a local page via the BrowserDriver",
  { skip: chromiumCached() ? false : "chromiumoxide Chromium not cached (./ioi-data/browser_cache)" },
  async () => {
    // A benign local HTML page (no PII) — file:// is local processing, so the egress
    // firewall inspects and allows it.
    const page = path.join(stateDir, "p5-browser-page.html");
    fs.writeFileSync(
      page,
      "<!doctype html><html><head><title>Phase5 Browser</title></head><body><h1>phase-5-browser-marker</h1></body></html>",
    );
    const url = `file://${page}`;

    const run = await grantedRun({
      session_ref: "session:p5-browser",
      goal: "open the local page in the browser",
      step: true,
      browser_navigate: { url },
    });
    assert.equal(run.status, 200);
    const body = run.body;

    assert.equal(body.step.ran, true, `step ran (error=${JSON.stringify(body.step.error)})`);
    assert.equal(body.step.error, null);
    const action = body.step.events.find((event) => event.kind === "AgentActionResult");
    assert.ok(action, `step produced an AgentActionResult: ${JSON.stringify(body.step.events.map((e) => e.kind))}`);
    assert.equal(action.tool_name, "browser__navigate", "the executed tool was the constrained browser navigation");
    assert.equal(action.error_class, null, "Chromium navigated to the page without error");

    // The egress firewall inspected the URL (PiiDecisionReceipt) and ALLOWED it — no
    // interception, because a benign local page carries no PII.
    assert.ok(
      body.step.events.some((event) => event.kind.startsWith("PiiDecisionReceipt")),
      "the egress firewall inspected the navigated URL",
    );
    assert.ok(
      !body.step.events.some((event) => event.kind === "FirewallInterception"),
      "no firewall interception — the benign local navigation was policy- and egress-allowed",
    );
  },
);
