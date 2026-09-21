// M01.10 — THE PURE ORACLE FOR CANONICAL MCP NON-TOOL PRIMITIVE NORMALIZATION.
//
// Canon: every exposed MCP primitive resolves to an EXISTING canonical owner with exact session,
// invocation and context bindings, produces the same admitted semantics as the native path, and fails
// TYPED-UNAVAILABLE rather than inventing truth when normalization is impossible.
//
// Everything in this file is a pure function of its arguments. It reads no files, starts no process and
// knows no paths, so the unit's mutation battery can load a mutated copy of it and score the oracle
// itself — the gate that drives a live daemon is the caller, not this.
//
// THE ONE CLAIM THIS FILE EXISTS TO POLICE: a protocol object is not authority. A resource URI is not a
// capability, a prompt is not a trusted instruction, an elicitation answer is not an approval, an MCP task
// is not a run identity, and an App descriptor is not host or runtime truth. Every decision this estate
// emits says so in two constant members, and a decision that says otherwise is refused here rather than
// explained.

export const DECISION_SCHEMA_VERSION = "ioi.runtime.mcp-normalization-decision.v1";
export const DECISION_CONTRACT_ID =
  "schema://ioi/components/hypervisor/mcp-primitive-normalization-decision/v1";

/** The eleven members every decision carries, positive or negative. */
export const REQUIRED_DECISION_MEMBERS = Object.freeze([
  "schema_version",
  "status",
  "primitive",
  "canonical_owner",
  "canonical_backing_ref",
  "normalization_decision",
  "authority_granted",
  "receipt_identity_granted",
  "source_protocol_version",
  "policy_lease_posture",
  "reason",
]);

/** The closed primitive vocabulary. A primitive outside it is `mcp.unknown`, never a nearby neighbour. */
export const PRIMITIVES = Object.freeze([
  "mcp.tool",
  "mcp.resource",
  "mcp.prompt",
  "mcp.elicitation",
  "mcp.task",
  "mcp.app",
  "mcp.serve",
  "mcp.gateway",
  "mcp.sampling",
  "mcp.roots",
  "mcp.logging",
  "mcp.notification",
  "mcp.unknown",
]);

/** The five ACC-1 N5 primitives: the ones whose normalization would be a grant if it were careless. */
export const NON_TOOL_PRIMITIVES = Object.freeze([
  "mcp.resource",
  "mcp.prompt",
  "mcp.elicitation",
  "mcp.task",
  "mcp.app",
]);

/**
 * The canonical owner each primitive resolves to, or — where it resolves to nothing today — the owner that
 * would have to exist for it to be served. This table is canon's and the daemon's; the gate checks that the
 * Rust side says exactly the same thing, because two tables that drift are how a refusal starts naming an
 * owner that was retired.
 */
export const OWNERS_BY_PRIMITIVE = Object.freeze({
  "mcp.tool": "RuntimeToolContract",
  "mcp.resource": "PolicyBoundDataView|ArtifactRef|MemoryProjection+ContextLease",
  "mcp.prompt": "tainted-import:SkillManifest|ioi.ai-owned-profile|invocation",
  "mcp.elicitation": "typed-user-input-request",
  "mcp.task": "HarnessInvocation.external-handle",
  "mcp.app": "sandboxed-extension_application-descriptor-and-surface",
  "mcp.serve": "RuntimeMcpServe",
  "mcp.gateway": "HypervisorMCPGatewayProfile",
  "mcp.sampling": "ModelRoute+HarnessInvocation",
  "mcp.roots": "WorkspaceRootProjection",
  "mcp.logging": "RuntimeObservability",
  "mcp.notification": "RuntimeEventStream",
  "mcp.unknown": "none",
});

/**
 * Which primitives this tree can normalize today, and which are a NAMED ABSENCE. An absence with an owner
 * is a boundary; an absence without one is a wall, and the difference is the whole product of a refusal.
 */
export const NORMALIZED_TODAY = Object.freeze(["mcp.tool", "mcp.app"]);

/** Why each non-tool primitive other than the App is still typed unavailable, named by its blocker. */
export const ABSENCE_OWNERS = Object.freeze({
  "mcp.resource":
    "ContextLease is the ioi.ai orchestration application's record over the generic System-record seam (R-192, R-202) and the seam knows no application vocabulary; ArtifactRef has no producer (R-205) and MemoryProjection has no registered contract",
  "mcp.prompt":
    "M04.3's SkillManifest is the owner, and the inert provenance-bearing import record a normalized prompt would produce does not exist",
  "mcp.elicitation": "no typed-user-input record family exists",
  "mcp.task": "no HarnessInvocation record family exists",
});

/** Route segment → primitive, as a table. A substring chain decided this before M01.10. */
export const ROUTE_PRIMITIVES = Object.freeze([
  ["/resources", "mcp.resource"],
  ["/prompts", "mcp.prompt"],
  ["/elicitation-requests", "mcp.elicitation"],
  ["/external-task-bindings", "mcp.task"],
  ["/apps", "mcp.app"],
  ["/serve", "mcp.serve"],
]);

/** Server-initiated MCP method → primitive, for the stdio client's refusal. */
export const CLIENT_METHOD_PRIMITIVES = Object.freeze({
  "sampling/createMessage": "mcp.sampling",
  "elicitation/create": "mcp.elicitation",
  "roots/list": "mcp.roots",
  "logging/setLevel": "mcp.logging",
});

/** The JSON-RPC error code the client answers an unimplemented server-initiated request with. */
export const TYPED_UNAVAILABLE_CODE = -32001;

export function classifyRoute(routePath) {
  for (const [segment, primitive] of ROUTE_PRIMITIVES) {
    if (String(routePath).includes(segment)) return primitive;
  }
  return "mcp.unknown";
}

export function classifyClientMethod(method) {
  const named = CLIENT_METHOD_PRIMITIVES[method];
  if (named) return named;
  if (String(method).startsWith("notifications/")) return "mcp.notification";
  return "mcp.unknown";
}

/**
 * THE ORACLE. Every finding is a defect in the decision handed in; an empty array is the claim that this
 * decision makes no claim it is not entitled to.
 */
export function decisionFindings(decision, { where = "decision" } = {}) {
  const findings = [];
  if (!decision || typeof decision !== "object" || Array.isArray(decision)) {
    return [`${where}: the decision is not an object`];
  }
  for (const member of REQUIRED_DECISION_MEMBERS) {
    if (!(member in decision)) findings.push(`${where}: the member ${member} is absent`);
  }
  if (decision.schema_version !== DECISION_SCHEMA_VERSION) {
    findings.push(`${where}: schema_version reads ${decision.schema_version}`);
  }
  if (!PRIMITIVES.includes(decision.primitive)) {
    findings.push(`${where}: ${decision.primitive} is outside the closed primitive vocabulary`);
  }
  const status = decision.normalization_decision;
  if (status !== "normalized" && status !== "typed_unavailable") {
    findings.push(`${where}: normalization_decision reads ${status}, which is not a status`);
  }
  if (decision.status !== status) {
    findings.push(`${where}: status ${decision.status} disagrees with the decision ${status}`);
  }
  // The two constants. A protocol projection never becomes authority by describing one, and never writes a
  // receipt; both are false in BOTH branches, which is why they are checked outside the branch.
  if (decision.authority_granted !== false) {
    findings.push(`${where}: the decision claims authority_granted`);
  }
  if (decision.receipt_identity_granted !== false) {
    findings.push(`${where}: the decision claims receipt_identity_granted`);
  }
  if (typeof decision.canonical_owner !== "string" || decision.canonical_owner.length === 0) {
    findings.push(`${where}: the decision names no canonical owner`);
  } else if (
    OWNERS_BY_PRIMITIVE[decision.primitive] &&
    decision.canonical_owner !== OWNERS_BY_PRIMITIVE[decision.primitive] &&
    // The gateway and the registry answer for a primitive under their own owner name, which the table
    // carries for the primitive rather than for the route; only a NAMED owner is admitted either way.
    !Object.values(OWNERS_BY_PRIMITIVE).includes(decision.canonical_owner) &&
    decision.canonical_owner !== "RuntimeToolContractRegistry"
  ) {
    findings.push(
      `${where}: ${decision.primitive} names the owner ${decision.canonical_owner}, which is in no table`,
    );
  }
  if (status === "normalized") {
    if (typeof decision.canonical_backing_ref !== "string" || !/^[a-z][a-z0-9+.-]*:\/\//.test(decision.canonical_backing_ref)) {
      findings.push(`${where}: a normalized decision names no admitted backing record`);
    }
  } else if (status === "typed_unavailable") {
    if (decision.canonical_backing_ref !== null) {
      findings.push(`${where}: a typed-unavailable decision carries a backing ref`);
    }
    if (decision.policy_lease_posture !== "not_minted") {
      findings.push(`${where}: a typed-unavailable decision reports the lease posture ${decision.policy_lease_posture}`);
    }
    if (Array.isArray(decision.receipt_refs) && decision.receipt_refs.length > 0) {
      findings.push(`${where}: a typed-unavailable decision carries receipts`);
    }
  }
  if (typeof decision.source_protocol_version !== "string" || decision.source_protocol_version.length === 0) {
    findings.push(`${where}: the decision names no source protocol revision`);
  }
  return findings;
}

/**
 * The stdio client's answer to a server-initiated primitive. Silence is the defect this checks for: before
 * M01.10 the client dropped the message, which a server cannot distinguish from a hang.
 */
export function refusalFindings(response, { method } = {}) {
  const findings = [];
  if (!response || typeof response !== "object") return ["the client answered nothing"];
  if (response.jsonrpc !== "2.0") findings.push("the refusal is not JSON-RPC 2.0");
  if (response.id === undefined || response.id === null) findings.push("the refusal answers no request id");
  if (response.result !== undefined) findings.push("the refusal carries a result");
  const error = response.error;
  if (!error || typeof error !== "object") return [...findings, "the refusal carries no error object"];
  if (error.code !== TYPED_UNAVAILABLE_CODE) {
    findings.push(`the refusal code is ${error.code}, not the estate's typed-unavailable ${TYPED_UNAVAILABLE_CODE}`);
  }
  findings.push(...decisionFindings(error.data, { where: "the refusal's decision" }));
  if (method && error.data && error.data.primitive !== classifyClientMethod(method)) {
    findings.push(
      `the refusal classifies ${method} as ${error.data?.primitive}, not ${classifyClientMethod(method)}`,
    );
  }
  return findings;
}

/**
 * A catalog entry for a primitive nothing normalizes must not advertise a workflow binding or an authority
 * scope. A scope no plane can grant reads to an author as "ask for this", and a workflow node type with no
 * executor is a binding that fails at run time instead of at read time.
 */
export function catalogEntryFindings(entry, primitive) {
  const findings = [];
  if (!entry || typeof entry !== "object") return ["the catalog entry is not an object"];
  const normalizable = NORMALIZED_TODAY.includes(primitive);
  const scopes = entry.authority_scope_requirements;
  if (!Array.isArray(scopes)) {
    findings.push(`${primitive}: authority_scope_requirements is not a list`);
  } else if (!normalizable && scopes.length > 0) {
    findings.push(
      `${primitive}: the catalog requires the scope ${scopes.join(", ")} for a primitive no owner normalizes`,
    );
  }
  if (!normalizable) {
    if (entry.invocable !== false) {
      findings.push(`${primitive}: the catalog entry does not declare itself non-invocable`);
    }
    if (entry.workflow_node_type !== null) {
      findings.push(
        `${primitive}: the catalog advertises the workflow node type ${entry.workflow_node_type}, which no executor serves`,
      );
    }
    if (entry.workflow_node_id !== null) {
      findings.push(`${primitive}: the catalog advertises a workflow node id for an unservable primitive`);
    }
    findings.push(...decisionFindings(entry.normalization, { where: `${primitive} catalog entry` }));
    if (entry.normalization && entry.normalization.normalization_decision !== "typed_unavailable") {
      findings.push(`${primitive}: the catalog entry claims a normalization this tree does not have`);
    }
  }
  return findings;
}

/**
 * The App positive. The descriptor is a PROJECTION of an admitted extension_application registration: every
 * projected member equals the registration's, and the four grant members are false. A projection that
 * derives a member the registration does not carry is the defect this looks for.
 */
export const APP_PROJECTED_MEMBERS = Object.freeze([
  "display_name",
  "canonical_route",
  "surface_class",
  "surface_origin",
  "surface_creation_method",
  "effect_boundary",
  "declared_object_contract_refs",
  "declared_action_contract_refs",
  "supported_placements",
  "launch_modes",
]);

export const APP_GRANT_MEMBERS = Object.freeze([
  "host_mutation",
  "runtime_ownership",
  "authority",
  "receipt_identity",
]);

export function appDescriptorFindings(descriptor, registration) {
  const findings = [];
  if (!descriptor || typeof descriptor !== "object") return ["the App descriptor is not an object"];
  if (!registration || typeof registration !== "object") return ["there is no admitted registration to project"];
  for (const member of APP_PROJECTED_MEMBERS) {
    const projected = JSON.stringify(descriptor[member] ?? null);
    const admitted = JSON.stringify(registration[member] ?? null);
    if (projected !== admitted) {
      findings.push(`the descriptor's ${member} reads ${projected}, the admitted registration's ${admitted}`);
    }
  }
  if (descriptor.surface_ref !== registration.surface_ref) {
    findings.push("the descriptor is bound to a different surface than the registration it claims");
  }
  const grants = descriptor.grants;
  if (!grants || typeof grants !== "object") {
    findings.push("the descriptor does not say what it does not grant");
  } else {
    for (const member of APP_GRANT_MEMBERS) {
      if (grants[member] !== false) findings.push(`the App descriptor grants ${member}`);
    }
  }
  return findings;
}

/**
 * A source pin measures CODE, never the prose that explains it. A negative pin that reads comments goes red
 * on the sentence documenting why the thing is absent, which is the most misleading possible false positive:
 * it fires exactly when the defect has been fixed and written up. Whole-line comments are dropped; string
 * literals are left intact, so a pin can still look for a ref or a route.
 */
export function codeOnly(source) {
  return String(source)
    .split("\n")
    .filter((line) => !/^\s*\/\//u.test(line))
    .join("\n");
}

/**
 * The Rust table and this one must agree. The daemon carries its own copy because a route cannot import
 * from a gate; the cost of that copy is this check, and paying it here is cheaper than a refusal in
 * production naming an owner this estate retired two units ago.
 */
export function tableParityFindings(rustSource) {
  const findings = [];
  // The subject is what the daemon SERVES, so the module's own test block is cut away first: a test that
  // asserts "this owner is never a GoalRun" must not be read as the daemon naming one.
  const served = String(rustSource).split("#[cfg(test)]")[0];
  const table = codeOnly(served);
  for (const [segment, primitive] of ROUTE_PRIMITIVES) {
    const row = new RegExp(`"${segment.replace(/[/-]/g, "\\$&")}"\\s*,\\s*\\n?\\s*"${primitive.replace(".", "\\.")}"`);
    if (!row.test(table)) findings.push(`the daemon's table has no row mapping ${segment} to ${primitive}`);
  }
  for (const primitive of NON_TOOL_PRIMITIVES) {
    const owner = OWNERS_BY_PRIMITIVE[primitive];
    if (!table.includes(owner)) {
      findings.push(`the daemon does not name ${primitive}'s owner ${owner}`);
    }
  }
  // R-192: goal pursuit is the ioi.ai application's composition. The daemon's own wire bytes may not name a
  // Hypervisor GoalRun as any primitive's canonical owner.
  if (/GoalRun/.test(table)) {
    findings.push("the daemon's primitive table still names a GoalRun as a canonical owner (R-192)");
  }
  return findings;
}
