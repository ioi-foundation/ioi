import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { mintApprovalGrant } from "../../../../scripts/lib/mint-approval-grant.mjs";

const hashBytes = (text) => [...createHash("sha256").update(text).digest()];

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const same = (left, right) => canonicalJson(left) === canonicalJson(right);

function signer(seed, principalRef, version = 1) {
  const probe = mintApprovalGrant({
    seed,
    policyHash: `sha256:${"11".repeat(32)}`,
    requestHash: `sha256:${"22".repeat(32)}`,
  });
  const bindingHash = hashBytes(`wallet.network principal binding ${principalRef} v${version}`);
  const approvalAuthority = {
    schema_version: 1,
    authority_id: probe.authority_id,
    public_key: probe.approver_public_key,
    signature_suite: probe.approver_suite,
    expires_at: Date.now() + 60 * 60 * 1000,
    revoked: false,
    scope_allowlist: ["room_participation.*"],
  };
  return {
    seed,
    principalRef,
    coordinates: {
      binding_ref: `wallet.network://principal-authority-binding/${Buffer.from(bindingHash).toString("hex")}`,
      binding_version: version,
      binding_hash: bindingHash,
    },
    approvalAuthority,
    snapshotHash: [...createHash("sha256").update(canonicalJson(approvalAuthority)).digest()],
  };
}

export async function startPrincipalAuthorityResolver(bindings) {
  const state = new Map(bindings.map(({ principalRef, seed }) => [principalRef, signer(seed, principalRef)]));
  let tamper = null;
  const server = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== "/v1/authority/principal-bindings/resolve") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "not_found" } }));
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "invalid_json" } }));
      return;
    }
    const binding = state.get(body.principal_ref);
    if (!binding || body.authority_kind !== "approval" || typeof body.required_scope !== "string") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "principal_authority_binding_not_found" } }));
      return;
    }
    if (!body.required_scope.startsWith("room_participation.")) {
      response.writeHead(403, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "principal_authority_scope_denied" } }));
      return;
    }
    if (body.expected_coordinates && !same(body.expected_coordinates, binding.coordinates)) {
      response.writeHead(409, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "principal_authority_binding_coordinates_stale" } }));
      return;
    }
    const resolvedAt = Date.now();
    const resolution = {
      schema_version: 1,
      principal_ref: binding.principalRef,
      authority_kind: "approval",
      coordinates: binding.coordinates,
      required_scope: body.required_scope,
      matched_scope: "room_participation.*",
      approval_authority: structuredClone(binding.approvalAuthority),
      authority_id: binding.approvalAuthority.authority_id,
      authority_public_key: binding.approvalAuthority.public_key,
      authority_signature_suite: binding.approvalAuthority.signature_suite,
      approval_authority_snapshot_hash: binding.snapshotHash,
      resolved_at_ms: resolvedAt,
      mutation_audit_event_id: hashBytes(`audit id ${binding.principalRef} ${binding.coordinates.binding_version}`),
      mutation_audit_event_hash: hashBytes(`audit hash ${binding.principalRef} ${binding.coordinates.binding_version}`),
    };
    if (tamper === "scope") {
      resolution.required_scope = "room_participation.reject";
      resolution.matched_scope = "room_participation.reject";
      resolution.approval_authority.scope_allowlist = ["room_participation.reject"];
    } else if (tamper === "snapshot") {
      resolution.approval_authority.revoked = true;
    } else if (tamper === "expiry") {
      resolution.approval_authority.expires_at += 1;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ request_id: body.request_id, resolved_at_ms: resolvedAt, resolution }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    mint(principalRef, policyHash, requestHash) {
      const binding = state.get(principalRef);
      if (!binding) throw new Error(`no signer for ${principalRef}`);
      return mintApprovalGrant({ seed: binding.seed, policyHash, requestHash });
    },
    rotate(principalRef, seed) {
      const previous = state.get(principalRef);
      state.set(principalRef, signer(seed || previous.seed, principalRef, previous.coordinates.binding_version + 1));
      return previous;
    },
    restore(principalRef, binding) { state.set(principalRef, binding); },
    setTamper(value) { tamper = value; },
    async stop() { await new Promise((resolve) => server.close(resolve)); },
  };
}
