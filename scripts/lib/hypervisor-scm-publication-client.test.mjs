import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import { readFile } from "node:fs/promises";

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

test("Publish PR admits a repository binding and submits the registered publication contract", async (t) => {
  const requests = [];
  const connector = {
    connector_id: "scm_local",
    remote_url: "file:///tmp/ioi-publication-test.git",
    auth_posture: "local-none",
    kind: "git",
    created_at: "2026-08-06T00:00:00Z",
  };
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : null;
    requests.push({ method: request.method, url: request.url, body });
    // The publish client resolves its publication owner from whoami before touching connectors.
    // This stub had no whoami route, so tenant_refs came back empty and the client refused with
    // "authenticated principal has no publication owner tenant" long before reaching the assertion
    // below. The daemon's own whoami does carry tenant_refs (resolve_principal_tenant_refs), so
    // answering here matches the real contract rather than papering over it.
    if (request.method === "GET" && request.url === "/v1/hypervisor/auth/whoami") {
      return json(response, 200, {
        ok: true,
        principal: {
          principal_ref: "user://publication-test",
          tenant_refs: ["org://publication-test"],
        },
      });
    }
    if (request.method === "GET" && request.url === "/v1/hypervisor/scm-connectors") {
      return json(response, 200, { ok: true, connectors: [connector] });
    }
    if (request.method === "GET" && request.url === "/v1/hypervisor/scm-destination-bindings") {
      return json(response, 200, { ok: true, destination_bindings: [] });
    }
    if (request.method === "POST" && request.url === "/v1/hypervisor/scm-destination-bindings") {
      return json(response, 200, { ok: true, destination_binding: body });
    }
    if (request.method === "POST" && request.url === "/v1/hypervisor/environments/env-contract/scm/publish") {
      return json(response, 428, {
        ok: false,
        approval: {
          policy_hash: `sha256:${"ab".repeat(32)}`,
          request_hash: `sha256:${"cd".repeat(32)}`,
        },
      });
    }
    if (request.method === "POST" && request.url?.startsWith("/v1/hypervisor/agent-run-transcripts/")) {
      return json(response, 200, { ok: true });
    }
    return json(response, 404, { ok: false });
  });
  const port = await listen(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  process.env.IOI_HYPERVISOR_DAEMON_URL = `http://127.0.0.1:${port}`;
  delete process.env.IOI_WALLET_TEST_SIGNER;
  const runsModule = await import(`../../apps/hypervisor/scripts/ioi-agent-runs.mjs?contract=${Date.now()}`);
  const run = runsModule.registerAgentRun({ envId: "env-contract" });
  run.publicationProposalRef = "proposal://local/hypervisor/test";
  run.publicationSourceBranch = "main";
  run.prompt = "Publish exact files";

  const result = await runsModule.publishRunViaConnector(run.id, connector.connector_id);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "awaiting_wallet_authority");

  const binding = requests.find((entry) => entry.method === "POST" && entry.url === "/v1/hypervisor/scm-destination-bindings");
  assert.ok(binding);
  assert.equal(binding.body.connector_ref, "connector://scm_local");
  assert.equal(binding.body.remote_url, connector.remote_url);
  assert.match(binding.body.destination_binding_ref, /^scm-destination-binding:\/\/local\/scm_local\/revision\//u);

  const challenge = requests.find((entry) => entry.method === "POST" && entry.url === "/v1/hypervisor/environments/env-contract/scm/publish");
  assert.ok(challenge);
  assert.deepEqual(Object.keys(challenge.body).sort(), [
    "destination_binding_ref",
    // The client now carries a caller idempotency key on publish, so a retried publish cannot open
    // a second pull request. This list predates that and was pinning the older payload shape.
    "idempotency_key",
    "open_review_request",
    "proposal_ref",
    "target_ref_name",
    "title",
    "work_run_ref",
  ]);
  assert.equal(challenge.body.proposal_ref, run.publicationProposalRef);
  assert.equal(challenge.body.destination_binding_ref, binding.body.destination_binding_ref);
  assert.equal(challenge.body.open_review_request, true);
  assert.equal("connector_id" in challenge.body, false);
  assert.equal("remote_url" in challenge.body, false);
});

test("SCM-facing product copy and projections retain the truthfulness repairs", async () => {
  const [serve, environment] = await Promise.all([
    readFile(new URL("../../apps/hypervisor/scripts/serve-product-ui.mjs", import.meta.url), "utf8"),
    readFile(
      new URL(
        "../../crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs",
        import.meta.url,
      ),
      "utf8",
    ),
  ]);
  assert.match(serve, /\/v1\/hypervisor\/scm-publication-effects/u);
  assert.doesNotMatch(serve, /String\(e\.kind\s*\|\|\s*""\)\.includes\("publish"\)/u);
  assert.match(serve, /This connection has no webhook and supplies no live provider workflow events/u);
  assert.match(environment, /local-pr-draft:\/\//u);
  assert.doesNotMatch(environment, /agentgres:\/\/pull-request-draft/u);
  assert.match(environment, /pull-request draft record cannot be persisted/u);
});
