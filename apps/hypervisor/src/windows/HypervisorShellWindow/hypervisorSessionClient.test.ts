import assert from "node:assert/strict";
import test from "node:test";

import {
  readHypervisorExecutionAuthorityChallenge,
  requestHypervisorSessionCreate,
  requestHypervisorSessionExecute,
} from "./hypervisorSessionOperationsModel.ts";

function fetchStub(handler: (url: string, init: { method?: string; body?: string }) => { ok?: boolean; status: number; text: string }) {
  return async (url: string, init: { method?: string; body?: string } = {}) => {
    const result = handler(url, init);
    return {
      ok: result.ok ?? (result.status >= 200 && result.status < 300),
      status: result.status,
      text: async () => result.text,
    };
  };
}

test("requestHypervisorSessionCreate POSTs /v1/hypervisor/sessions and returns the daemon session_ref", async () => {
  let seenUrl = "";
  let seenBody: Record<string, unknown> = {};
  const fetchImpl = fetchStub((url, init) => {
    seenUrl = url;
    seenBody = JSON.parse(init.body ?? "{}");
    return {
      status: 202,
      text: JSON.stringify({
        schema_version: "ioi.hypervisor.session_create_projection.v1",
        session_ref: "session:hyp-abc",
        environment_ref: "environment:hyp-abc",
        environment_status: { schema_version: "ioi.hypervisor.environment_status.v1" },
        workspace_initializer: { schema_version: "ioi.hypervisor.workspace_initializer.v1" },
        receipt_ref: "receipt://hypervisor/session-provision/hyp-abc",
        runtimeTruthSource: "daemon-runtime",
      }),
    };
  });
  const result = await requestHypervisorSessionCreate(
    { project_ref: "project:x", session_ref: "session:hyp-abc", workspace_mount_policy: "public_trunk" },
    { endpoint: "http://127.0.0.1:8765/", fetchImpl },
  );
  assert.equal(seenUrl, "http://127.0.0.1:8765/v1/hypervisor/sessions");
  assert.equal(seenBody.project_ref, "project:x");
  assert.equal(result.session_ref, "session:hyp-abc");
});

test("requestHypervisorSessionCreate throws on a non-ok daemon response", async () => {
  const fetchImpl = fetchStub(() => ({ status: 500, text: "boom" }));
  await assert.rejects(
    () => requestHypervisorSessionCreate({ project_ref: "p" }, { endpoint: "http://d", fetchImpl }),
    /session create failed \(500\)/,
  );
});

test("execute returns the 403 wallet challenge so the caller can mint a bound grant", async () => {
  const fetchImpl = fetchStub((url) => {
    assert.match(url, /\/v1\/hypervisor\/sessions\/session%3Ahyp-abc\/execute$/);
    return {
      status: 403,
      text: JSON.stringify({
        decision: "blocked",
        reason: "execution_authority_required",
        required_scopes: ["command_exec", "port_exposure", "workspace_write"],
        approval: { policy_hash: "sha256:aa", request_hash: "sha256:bb" },
        changed_file_groups: [],
        terminal_events: [],
      }),
    };
  });
  const response = await requestHypervisorSessionExecute(
    "session:hyp-abc",
    { intent: "build a site" },
    { endpoint: "http://127.0.0.1:8765", fetchImpl },
  );
  assert.equal(response.status, 403);
  const challenge = readHypervisorExecutionAuthorityChallenge(response);
  assert.ok(challenge, "a challenge is parsed from the 403");
  assert.equal(challenge?.policy_hash, "sha256:aa");
  assert.equal(challenge?.request_hash, "sha256:bb");
  assert.ok(challenge?.required_scopes.includes("port_exposure"));
});

test("execute returns {status,body} for an executed run; no challenge on 200", async () => {
  const fetchImpl = fetchStub(() => ({
    status: 200,
    text: JSON.stringify({ decision: "executed", files_written: ["index.html"], capability_lease_ref: "wallet.network://grant/approval/x" }),
  }));
  const response = await requestHypervisorSessionExecute(
    "session:hyp-abc",
    { intent: "x", wallet_approval_grant: { signed: true } },
    { endpoint: "http://d", fetchImpl },
  );
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, "executed");
  assert.equal(readHypervisorExecutionAuthorityChallenge(response), null);
});
