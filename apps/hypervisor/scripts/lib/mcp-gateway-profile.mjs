// M01.11 — THE PURE ORACLE FOR THE SUBJECT-SCOPED OUTWARD HYPERVISOR MCP GATEWAY.
//
// Canon: one immutable versioned `HypervisorMCPGatewayProfile` binds ONE subject and ONE use to exact
// requirement and exposure-manifest hashes, and an external model or harness receives only what that
// profile admitted. A profile grants no authority by itself.
//
// Everything here is a pure function of its arguments — no files, no processes, no paths — so the unit's
// mutation battery can load a mutated copy and score the oracle itself. The gate that drives a real daemon
// is the caller.
//
// THE CLAIM THIS FILE POLICES: an outward surface may only ever NARROW. Lifecycle state reduces; a changed
// declared body is a successor; a successor that adds anything repeats admission; and a call reaches the
// same final invoker as the native path or it is not the same call.

export const PROFILE_V1_VERSION = "ioi.hypervisor-mcp-gateway-profile.v1";
export const PROFILE_V2_VERSION = "ioi.hypervisor-mcp-gateway-profile.v2";
export const REQUIREMENT_VERSION = "ioi.mcp-gateway-requirement.v1";

export const PROFILE_V1_CONTRACT =
  "schema://ioi/components/connectors-tools/hypervisor-mcp-gateway-profile/v1";
export const PROFILE_V2_CONTRACT =
  "schema://ioi/components/connectors-tools/hypervisor-mcp-gateway-profile/v2";
export const REQUIREMENT_CONTRACT =
  "schema://ioi/components/connectors-tools/mcp-gateway-requirement-envelope/v1";

/** The seven v1 kinds, unchanged by the successor. */
export const V1_PROFILE_KINDS = Object.freeze([
  "discovery_readonly",
  "project_session",
  "connector_preview",
  "operator_proposal",
  "effectful_approved",
  "foundry_eval_training",
  "receipts_replay_proof",
]);

/** The one kind v2 adds, and the reason it is not a widening of `foundry_eval_training`. */
export const V2_ONLY_KIND = "capability_construction_eval";
export const V2_PROFILE_KINDS = Object.freeze([...V1_PROFILE_KINDS, V2_ONLY_KIND]);

/**
 * The lifecycle projections that BIND the content hash rather than entering it. If one of these joined the
 * preimage, revoking a profile would mint a new identity for an unchanged body and break every consumer's
 * pin on an event that took nothing away from them.
 */
export const EXCLUDED_FROM_CONTENT_HASH = Object.freeze([
  "profile_content_hash",
  "status",
  "revocation_ref",
  "quarantine_advisory_refs",
  "last_use_ref",
  "admission_decision_ref",
  "admission_receipt_ref",
  "receipt_refs",
]);

/**
 * The canonical risk ladder from foundations/canonical-enums.md, lowest to highest. `physical_action` is a
 * PEER top-tier class OUTSIDE the monotonic ladder — it carries its own safety envelope — so it is never
 * reached by rising through the ladder, and a successor that introduces it widens whatever came before.
 */
export const RISK_LADDER = Object.freeze([
  "read",
  "draft",
  "local_write",
  "write_reversible",
  "external_message",
  "commerce",
  "funds",
  "credential_access",
  "policy_widening",
  "secret_export",
  "identity_change",
  "system_destructive",
]);
export const PEER_RISK_CLASS = "physical_action";

/** The identity schemes. One object, one spelling (ADR 0055). */
export const PROFILE_ID_PATTERN = /^mcp-gateway:\/\/[^\s?#\\]{1,160}$/u;
export const PROFILE_REVISION_PATTERN =
  /^mcp-gateway:\/\/[^\s?#\\]{1,160}\/revision\/sha256:[0-9a-f]{64}$/u;
export const REQUIREMENT_REVISION_PATTERN =
  /^mcp-gateway-requirement:\/\/[^\s?#\\]{1,160}\/revision\/sha256:[0-9a-f]{64}$/u;

/** The lifecycle states a PATCH may move a profile to. Every one of them reduces. */
export const REDUCING_STATES = Object.freeze(["suspended", "quarantined", "expired", "revoked"]);

const asSet = (value) =>
  new Set(Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : []);
const strAt = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");

export function riskRank(riskClass) {
  const index = RISK_LADDER.indexOf(riskClass);
  return index < 0 ? null : index;
}

export function exposedToolNames(profile) {
  return asSet((profile?.exposed_tools ?? []).map((tool) => strAt(tool, "mcp_tool_name")));
}

export function exposedResourceUris(profile) {
  return asSet((profile?.exposed_resources ?? []).map((item) => strAt(item, "mcp_resource_uri")));
}

/**
 * The highest risk class any exposed tool carries. `null` means the profile exposes no tool at all, which
 * is a real posture and not a ceiling of zero.
 */
export function exposedRiskCeiling(profile) {
  let best = null;
  let peer = null;
  for (const tool of profile?.exposed_tools ?? []) {
    for (const key of ["risk_class", "effect_class"]) {
      const value = strAt(tool, key);
      if (value === PEER_RISK_CLASS) peer = value;
      else {
        const rank = riskRank(value);
        if (rank !== null && (best === null || rank > riskRank(best))) best = value;
      }
    }
  }
  return peer ?? best;
}

/** The declared body: what the admitted revision froze, with the lifecycle projections removed. */
export function declaredBody(profile) {
  const body = { ...(profile ?? {}) };
  for (const excluded of EXCLUDED_FROM_CONTENT_HASH) delete body[excluded];
  return body;
}

/**
 * WHAT A SUCCESSOR ADDED. Every finding is a widening, and a widening successor must carry its own fresh
 * admission rather than inheriting its predecessor's. An empty result is a narrowing or an unchanged
 * exposure, which may land under the same admission.
 *
 * This is the JS side of the rule the daemon enforces in Rust. The two are compared row for row by the
 * gate, because a narrowing rule that disagrees with itself across the wire is worse than one rule.
 */
export function wideningFindings(previous, next) {
  const findings = [];
  const added = (what, before, after) => {
    const gained = [...after].filter((entry) => !before.has(entry));
    if (gained.length) findings.push(`${what} gains ${gained.join(", ")}`);
  };
  added("the exposed tool set", exposedToolNames(previous), exposedToolNames(next));
  added("the exposed resource set", exposedResourceUris(previous), exposedResourceUris(next));
  for (const [what, key] of [
    ["the authority scope set", "authority_scope_refs"],
    ["the project set", "project_refs"],
    ["the session set", "session_refs"],
    ["the invocation scope set", "invocation_scope_refs"],
    ["the surface set", "surface_refs"],
    ["the extension application set", "extension_application_refs"],
  ]) {
    added(what, asSet(previous?.[key]), asSet(next?.[key]));
  }
  // A different subject is not a wider profile; it is a different profile wearing this one's name.
  if (strAt(previous, "subject_ref") !== strAt(next, "subject_ref")) {
    findings.push("the subject changes, which is a different profile rather than a wider one");
  }
  const before = exposedRiskCeiling(previous);
  const after = exposedRiskCeiling(next);
  if (after === PEER_RISK_CLASS) {
    findings.push(
      "the exposure reaches the physical-action class, which is outside the ladder and never inherited",
    );
  } else if (after !== null && before === null) {
    findings.push(`the exposure gains a risk ceiling of ${after}`);
  } else if (after !== null && before !== null && riskRank(after) > riskRank(before)) {
    findings.push(`the risk ceiling rises from ${before} to ${after}`);
  }
  if (strAt(next, "expires_at") > strAt(previous, "expires_at")) {
    findings.push(
      `the expiry extends from ${strAt(previous, "expires_at")} to ${strAt(next, "expires_at")}`,
    );
  }
  return findings;
}

/**
 * The CURRENT revision of one family: the revision no other revision names as its predecessor. Derived
 * from the chain, never taken by position — a record directory has no order, and a head taken by position
 * is a bug that reproduces on some runs and not others. Two heads is a FORK and answers with none.
 */
export function currentRevision(records, gatewayProfileId) {
  const family = (records ?? []).filter(
    (record) => strAt(record, "gateway_profile_id") === gatewayProfileId,
  );
  if (!family.length) return null;
  const superseded = new Set(
    family
      .map((record) => strAt(record, "predecessor_profile_revision_ref"))
      .filter((entry) => entry.length > 0),
  );
  const heads = family.filter(
    (record) => !superseded.has(strAt(record, "profile_revision_ref")),
  );
  return heads.length === 1 ? heads[0] : null;
}

/** Effective status. Expiry is DERIVED: a stored `active` on a past expiry is a claim the clock denies. */
export function effectiveStatus(profile, now) {
  const stored = strAt(profile, "status");
  if (stored !== "active") return stored;
  return strAt(profile, "expires_at") <= now ? "expired" : "active";
}

/**
 * THE PROFILE ORACLE. Every finding is a claim the profile is not entitled to make.
 */
export function profileFindings(profile, { where = "profile" } = {}) {
  const findings = [];
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    return [`${where}: the profile is not an object`];
  }
  const version = strAt(profile, "schema_version");
  const kinds =
    version === PROFILE_V2_VERSION
      ? V2_PROFILE_KINDS
      : version === PROFILE_V1_VERSION
        ? V1_PROFILE_KINDS
        : null;
  if (kinds === null) {
    findings.push(`${where}: ${version} is not a gateway profile version this estate reads`);
  } else if (!kinds.includes(strAt(profile, "profile_kind"))) {
    findings.push(
      `${where}: ${strAt(profile, "profile_kind")} is outside the ${version} closed kind set`,
    );
  }
  // VERSIONS DO NOT FALL BACK. The v2-only kind in a v1 document is refused, not ignored — ignoring it
  // would admit the builder surface as whatever the v1 reader defaulted to.
  if (version === PROFILE_V1_VERSION && strAt(profile, "profile_kind") === V2_ONLY_KIND) {
    findings.push(`${where}: a v1 document carries the v2-only kind ${V2_ONLY_KIND}`);
  }
  if (!PROFILE_ID_PATTERN.test(strAt(profile, "gateway_profile_id"))) {
    findings.push(`${where}: the profile id is not on the canonical mcp-gateway:// scheme`);
  }
  if (!PROFILE_REVISION_PATTERN.test(strAt(profile, "profile_revision_ref"))) {
    findings.push(`${where}: the revision ref is not a canonical content-addressed revision`);
  }
  // The revision belongs to its OWN family. A revision under another family's id is how one profile's
  // narrowing gets filed as another's, and both documents look correct in isolation.
  const id = strAt(profile, "gateway_profile_id");
  const revision = strAt(profile, "profile_revision_ref");
  if (id && revision && !revision.startsWith(`${id}/revision/`)) {
    findings.push(`${where}: the revision ref belongs to another profile family`);
  }
  if (profile.issued_after_required_admission !== true) {
    findings.push(`${where}: the profile does not claim to have been issued after its admission`);
  }
  for (const key of ["admission_decision_ref", "admission_receipt_ref"]) {
    if (!strAt(profile, key)) findings.push(`${where}: the profile names no ${key}`);
  }
  if (strAt(profile, "status") === "revoked" && !strAt(profile, "revocation_ref")) {
    findings.push(
      `${where}: a revoked profile names no revocation ref, and the content hash does not move on revocation`,
    );
  }
  if (strAt(profile, "admission_basis") === "room_guest" && !strAt(profile, "room_admission_decision_ref")) {
    findings.push(`${where}: a room guest names no room admission decision`);
  }
  if (
    strAt(profile, "admission_basis") === "registered_worker_invocation" &&
    !strAt(profile, "worker_registration_ref")
  ) {
    findings.push(`${where}: a registered-worker invocation names no worker registration`);
  }
  if (strAt(profile, "audience") === "local_harness") {
    for (const key of ["candidate_public_key_ref", "local_agent_pairing_session_ref"]) {
      if (!strAt(profile, key)) findings.push(`${where}: a paired local harness names no ${key}`);
    }
  }
  if (strAt(profile, "pairing_execution_posture") === "prompt_only") {
    if (strAt(profile, "pairing_contribution_lane") !== "proposal_only") {
      findings.push(`${where}: a prompt-only posture carries an instrumented contribution lane`);
    }
    if (profile.prompt_only_proposal !== true) {
      findings.push(`${where}: a prompt-only posture is not marked proposal-only`);
    }
  }
  // A discovery-only profile that exposed an approval-requiring or effectful tool is a contradiction
  // admitted in writing.
  if (strAt(profile, "profile_kind") === "discovery_readonly") {
    for (const tool of profile.exposed_tools ?? []) {
      if (tool?.approval_required === true) {
        findings.push(`${where}: a read-only discovery profile exposes an approval-requiring tool`);
      }
      if (!["read", "draft"].includes(strAt(tool, "effect_class"))) {
        findings.push(
          `${where}: a read-only discovery profile exposes the effect class ${strAt(tool, "effect_class")}`,
        );
      }
    }
  }
  // The source-neutral builder: bound to ONE invocation, and reading no first-party training corpus. The
  // contract cannot express the second half (the portable keyword set admits no negation), so it is here.
  if (strAt(profile, "profile_kind") === V2_ONLY_KIND) {
    if (!(profile.invocation_scope_refs ?? []).length) {
      findings.push(
        `${where}: the source-neutral builder names no invocation scope, so it is scoped to every invocation its subject can reach`,
      );
    }
    for (const tool of profile.exposed_tools ?? []) {
      for (const scope of tool?.authority_scopes_required ?? []) {
        if (/^scope:(foundry|training|dataset-factory)\./u.test(scope)) {
          findings.push(
            `${where}: the source-neutral builder requires ${scope}, which is a training scope and belongs to foundry_eval_training`,
          );
        }
      }
    }
  }
  const names = [...(profile.exposed_tools ?? [])].map((tool) => strAt(tool, "mcp_tool_name"));
  if (new Set(names).size !== names.length) {
    findings.push(`${where}: two exposed tools share one wire name`);
  }
  for (const resource of profile.exposed_resources ?? []) {
    if (!strAt(resource, "required_context_lease_ref")) {
      findings.push(
        `${where}: an exposed resource names no context lease — a resource URI is not access, and the lease is what makes it access`,
      );
    }
  }
  return findings;
}

/**
 * A LIFECYCLE CHANGE MAY ONLY REDUCE, and may not move the content hash. The second half is the one that
 * catches a lifecycle route quietly editing the declared body, which is the in-place privilege edit canon
 * forbids.
 */
export function lifecycleFindings(before, after) {
  const findings = [];
  const target = strAt(after, "status");
  if (!REDUCING_STATES.includes(target)) {
    findings.push(`a lifecycle change to ${target} is not a reduction`);
  }
  if (JSON.stringify(declaredBody(before)) !== JSON.stringify(declaredBody(after))) {
    findings.push("a lifecycle change edited the declared body");
  }
  if (strAt(before, "profile_content_hash") !== strAt(after, "profile_content_hash")) {
    findings.push("a lifecycle change moved the content hash");
  }
  if (target === "revoked" && !strAt(after, "revocation_ref")) {
    findings.push("a revoked profile names no revocation ref");
  }
  return findings;
}

/**
 * RESOLVING A REQUIREMENT ISSUES NOTHING. Every finding is the resolver claiming more than an evaluation.
 */
export function resolutionFindings(answer) {
  const findings = [];
  if (!answer || typeof answer !== "object") return ["the resolver answered nothing"];
  if (answer.profile_issued !== false) findings.push("the resolver claims a profile was issued");
  if (answer.authority_granted !== false) findings.push("the resolver claims authority was granted");
  if (!REQUIREMENT_REVISION_PATTERN.test(strAt(answer, "requirement_revision_ref"))) {
    findings.push("the resolver answers for no exact immutable requirement revision");
  }
  if (typeof answer.resolvable !== "boolean") findings.push("the resolver returns no verdict");
  if (answer.resolvable === false && !(answer.exceeded ?? []).length) {
    findings.push("the resolver refuses without naming which member of the ceiling was exceeded");
  }
  if (answer.resolvable === true && (answer.exceeded ?? []).length) {
    findings.push("the resolver resolves while naming exceeded members");
  }
  return findings;
}

/**
 * THE CALL REACHES THE SAME FINAL INVOKER. Everything the gateway adds is a narrowing; a gateway answer
 * that claims authority, or that reports a final invoker other than the native one, is the second spine.
 */
export function callFindings(answer) {
  const findings = [];
  if (!answer || typeof answer !== "object") return ["the gateway answered nothing"];
  if (answer.authority_granted !== false) findings.push("the gateway call claims authority");
  if (strAt(answer, "final_invoker") !== "RuntimeAgentService.handle_action_execution") {
    findings.push(
      `the gateway call reports the final invoker ${strAt(answer, "final_invoker")}, which is not the native path's`,
    );
  }
  if (!PROFILE_REVISION_PATTERN.test(strAt(answer, "profile_revision_ref"))) {
    findings.push("the gateway call names no exact profile revision");
  }
  if (!strAt(answer, "exposure_manifest_hash")) {
    findings.push("the gateway call names no exposure manifest hash, so nothing binds what it served");
  }
  if (!("native_answer" in answer)) {
    findings.push("the gateway call carries no native answer, so it did not delegate");
  }
  return findings;
}

/**
 * NATIVE-VERSUS-MCP PARITY. The two answers are the same admitted fact or they are not the same call.
 * Compared on the members that decide admission, not on the whole body: the gateway answer legitimately
 * adds its own narrowing record, and requiring byte equality would make the check fail for the one reason
 * that is correct.
 */
export const PARITY_MEMBERS = Object.freeze([
  "status",
  "final_invoker",
  "contract",
  "runtime_tool_contract_admission_receipt_ref",
]);

export function parityFindings(nativeAnswer, gatewayAnswer) {
  const findings = [];
  const throughGateway = gatewayAnswer?.native_answer;
  if (!throughGateway) return ["the gateway answer carries no native answer to compare"];
  for (const member of PARITY_MEMBERS) {
    const a = JSON.stringify(nativeAnswer?.[member] ?? null);
    const b = JSON.stringify(throughGateway?.[member] ?? null);
    if (a !== b) findings.push(`${member} differs: native ${a.slice(0, 80)} ≠ gateway ${b.slice(0, 80)}`);
  }
  return findings;
}

/**
 * The daemon's Rust table and this one must agree. The daemon carries its own copy because a route cannot
 * import from a gate; the cost of that copy is this check.
 */
export function codeOnly(source) {
  return String(source)
    .split("\n")
    .filter((line) => !/^\s*\/\//u.test(line))
    .join("\n");
}

export function sourceParityFindings(rustSource) {
  const findings = [];
  const served = codeOnly(String(rustSource).split("#[cfg(test)]")[0]);
  for (const entry of RISK_LADDER) {
    if (!new RegExp(`"${entry}"`, "u").test(served)) {
      findings.push(`the daemon's risk ladder omits ${entry}`);
    }
  }
  for (const excluded of EXCLUDED_FROM_CONTENT_HASH) {
    if (!new RegExp(`"${excluded}"`, "u").test(served)) {
      findings.push(`the daemon's content-hash exclusion set omits ${excluded}`);
    }
  }
  // The daemon does NOT hardcode the identity scheme, and that is the correct state rather than a gap: the
  // registered contracts own the pattern, the daemon validates against them, and a second copy of the
  // pattern in Rust would be a second definition of one object's identity. What the daemon must not do is
  // carry the RETIRED underscored spelling, which is a negative and is checkable.
  if (/mcp_gateway:\/\//u.test(served)) {
    findings.push("the daemon still carries the retired underscored ref scheme");
  }
  for (const contract of [PROFILE_V1_CONTRACT, PROFILE_V2_CONTRACT, REQUIREMENT_CONTRACT]) {
    if (!served.includes(contract)) {
      findings.push(`the daemon validates against no ${contract.split("/").slice(-2).join("/")} contract`);
    }
  }
  if (!/validate_architecture_contract\(/u.test(served)) {
    findings.push("the daemon names the contracts but validates against none of them");
  }
  return findings;
}
