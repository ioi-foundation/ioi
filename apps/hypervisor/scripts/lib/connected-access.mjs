// M08.16 — THE SHARED CONNECTED-ACCESS PROJECTION.
//
// Canon: embedded product settings, the Hypervisor Connections cockpit and an advanced wallet view expose
// the SAME owner-backed connect, inspect, reauthorize, disconnect and receipt lifecycle over ONE daemon;
// they distinguish provider REACHABILITY from delegated AUTHORITY; and they show exact dependents without
// rendering secrets. Every presentation uses the same M03.16 operations and state.
//
// This file is the reason that is possible. It is pure — no files, no processes, no fetch — and it is the
// ONLY place a posture, a next action or a dependent set is derived. A view that computes any of those
// locally has become a second source of truth about authority, and the three views would then disagree in
// exactly the situations that matter: mid-reauthorization, after a provider revocation, across a restart.
//
// THE DISTINCTION THIS FILE EXISTS TO HOLD. "The provider answered" and "we hold delegated authority" are
// different facts with different owners. Reachability lives on the connection record — its status, its last
// verification, the scopes the PROVIDER returned. Authority lives on the capability lease, which this file
// never derives and never infers. `provider_granted_scopes` is the sharpest trap in the estate: it reads
// like a grant, canon says in as many words that it is not one, and the surface that renders it beside a
// "connected" badge has shipped the conflation this unit exists to refuse.

/** The connection family's material members, in the daemon's own order. A projection that drops one is
 *  hiding state; a projection that adds one is deriving. */
export const CONNECTION_MEMBERS = Object.freeze([
  "schema_version",
  "connection_ref",
  "connection_version",
  "predecessor_ref",
  "owner_ref",
  "principal_ref",
  "connector_ref",
  "provider_profile_ref",
  "provider_account_subject_hash",
  "provider_tenant_subject_hash",
  "provider_granted_scopes",
  "credential_binding_ref",
  "credential_custody_profile_ref",
  "permitted_audience_classes",
  "connection_revocation_epoch",
  "reauthorization_required_at",
  "last_provider_verification",
  "status",
  "successor_ref",
  "ceremony_ref",
  "receipt_refs",
]);

/** The seven declared statuses. `superseded` is declared and never emitted by the daemon today, which a
 *  view must not quietly drop: a dead state in a closed set is a fact about the plane, not a typo. */
export const CONNECTION_STATUSES = Object.freeze([
  "pending_authorization",
  "active",
  "reauthorization_required",
  "degraded",
  "provider_revoked",
  "disconnected",
  "superseded",
]);

/** Statuses under which the credential fence still admits a use. */
export const LIVE_STATUSES = Object.freeze(["active"]);

/** The provider verification's own vocabulary — REACHABILITY, and nothing else. */
export const VERIFICATION_STATUSES = Object.freeze(["current", "degraded", "unknown", "provider_revoked"]);

/**
 * Which members carry REACHABILITY and which carry the fence. Neither list carries AUTHORITY, because the
 * connection record does not have any: authority is the capability lease's, and this file will not infer
 * one from a connection however healthy it looks.
 */
export const REACHABILITY_MEMBERS = Object.freeze([
  "last_provider_verification",
  "provider_granted_scopes",
]);
export const FENCE_MEMBERS = Object.freeze([
  "connection_revocation_epoch",
  "credential_binding_ref",
  "credential_custody_profile_ref",
  "permitted_audience_classes",
  "reauthorization_required_at",
]);
export const AUTHORITY_MEMBERS = Object.freeze([]);

/** The lifecycle verbs every view must offer identically. */
export const LIFECYCLE_VERBS = Object.freeze([
  "connect",
  "inspect",
  "verify",
  "reauthorize",
  "disconnect",
]);

/** The four things the unit requires be kept DISTINCT. Conflating any two is the defect. */
export const DISTINCT_SUBJECTS = Object.freeze([
  "connection",
  "grant",
  "product_system_integration",
  "provider_account",
]);

/** Members no rendered surface may carry, in any view, ever. */
export const NEVER_RENDERED = Object.freeze([
  "sealed_client_secret",
  "sealed_refresh_token",
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "authorization_code",
  "code_verifier",
  "cookie",
]);

const strAt = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const listAt = (value, key) => (Array.isArray(value?.[key]) ? value[key] : []);

/**
 * THE READOUT. One connection as every view renders it: the daemon's own members, plus exactly three
 * DERIVED facts that are derived HERE and nowhere else — the effective posture, the required next action,
 * and whether a use would be fenced. Each carries `derived_from` so a reader can tell a projection from a
 * claim.
 */
export function projectConnection(connection, { now = new Date().toISOString() } = {}) {
  const projected = {};
  for (const member of CONNECTION_MEMBERS) {
    projected[member] = connection?.[member] ?? null;
  }
  const status = strAt(connection, "status");
  const verification = connection?.last_provider_verification ?? null;
  const reachability = strAt(verification, "status") || "unknown";
  const deadline = strAt(connection, "reauthorization_required_at");
  const overdue = deadline !== "" && deadline <= now;

  // POSTURE is the connection's own status, narrowed by facts the record cannot state about itself: a
  // deadline the clock has passed, and a provider that stopped answering. It never widens.
  let posture = status;
  if (status === "active" && overdue) posture = "reauthorization_required";
  if (status === "active" && reachability === "provider_revoked") posture = "provider_revoked";
  if (status === "active" && reachability === "degraded") posture = "degraded";

  projected.effective_posture = posture;
  projected.provider_reachability = reachability;
  projected.use_is_fenced = !LIVE_STATUSES.includes(posture);
  projected.required_next_action = requiredNextAction({ ...connection, status: posture }, { now });
  projected.derived_from = {
    effective_posture: ["status", "reauthorization_required_at", "last_provider_verification.status"],
    provider_reachability: ["last_provider_verification.status"],
    use_is_fenced: ["status"],
    required_next_action: ["status", "reauthorization_required_at", "successor_ref"],
  };
  // SAID ON THE WIRE, not left to a reader's care: what this record is not.
  projected.authority_granted = false;
  projected.provider_granted_scopes_are_not_authority = true;
  return projected;
}

/**
 * What the operator must do next, or null when nothing is owed. Derived rather than stored, because a
 * stored next action is a claim that goes stale exactly when the connection changes — which is the only
 * time anyone reads it.
 */
export function requiredNextAction(connection, { now = new Date().toISOString() } = {}) {
  const status = strAt(connection, "status");
  const deadline = strAt(connection, "reauthorization_required_at");
  if (status === "pending_authorization") return "complete_the_authorization_ceremony";
  if (status === "provider_revoked") return "reconnect_the_provider_account";
  if (status === "disconnected") return "reconnect_if_this_access_is_still_wanted";
  if (status === "superseded") return "read_the_successor_version";
  if (status === "reauthorization_required") return "reauthorize";
  if (status === "degraded") return "verify_the_provider_connection";
  if (status === "active" && deadline !== "" && deadline <= now) return "reauthorize";
  return null;
}

/**
 * THE PROJECTION ORACLE. Every finding is a view claiming something the daemon did not say.
 */
export function projectionFindings(projected, connection, { where = "view" } = {}) {
  const findings = [];
  if (!projected || typeof projected !== "object") return [`${where}: the projection is not an object`];
  for (const member of CONNECTION_MEMBERS) {
    if (!(member in projected)) {
      findings.push(`${where}: the projection drops ${member}, which hides state rather than narrowing it`);
      continue;
    }
    const rendered = JSON.stringify(projected[member]);
    const admitted = JSON.stringify(connection?.[member] ?? null);
    if (rendered !== admitted) {
      findings.push(`${where}: ${member} reads ${rendered.slice(0, 60)}, the admitted record's ${admitted.slice(0, 60)}`);
    }
  }
  if (!CONNECTION_STATUSES.includes(projected.effective_posture)) {
    findings.push(`${where}: the posture ${projected.effective_posture} is outside the declared status set`);
  }
  if (!VERIFICATION_STATUSES.includes(projected.provider_reachability)) {
    findings.push(`${where}: the reachability ${projected.provider_reachability} is outside the verification vocabulary`);
  }
  // A POSTURE MAY ONLY NARROW. An admitted record that is not active can never project as active.
  if (projected.effective_posture === "active" && strAt(connection, "status") !== "active") {
    findings.push(`${where}: a ${strAt(connection, "status")} connection projects as active, which widens`);
  }
  if (projected.use_is_fenced !== !LIVE_STATUSES.includes(projected.effective_posture)) {
    findings.push(`${where}: the fence verdict disagrees with the posture it was derived from`);
  }
  if (projected.authority_granted !== false) {
    findings.push(`${where}: the projection claims authority, which no connection record carries`);
  }
  if (projected.provider_granted_scopes_are_not_authority !== true) {
    findings.push(`${where}: the projection does not say that provider-granted scopes are not authority`);
  }
  if (!projected.derived_from || typeof projected.derived_from !== "object") {
    findings.push(`${where}: the projection does not say which members each derived fact came from`);
  }
  return findings;
}

/**
 * REACHABILITY IS NOT AUTHORITY. Given what a view renders for one connection and the leases the daemon
 * holds for it, every finding is the view treating one as the other.
 */
export function conflationFindings(rendered, { leases = [], connection = null, where = "view" } = {}) {
  const findings = [];
  const text = typeof rendered === "string" ? rendered : JSON.stringify(rendered ?? "");
  const posture = strAt(connection, "status");
  // The literal word "connected" beside a record that is not active is the defect this unit names first.
  if (/\bconnected\b/iu.test(text) && posture !== "" && posture !== "active") {
    findings.push(`${where}: renders "connected" for a connection whose admitted status is ${posture}`);
  }
  // A view may say authorized only where a lease says so. The connection never does.
  if (/\bauthoriz(ed|ation granted)\b/iu.test(text) && leases.length === 0) {
    findings.push(`${where}: renders an authorization claim with no capability lease behind it`);
  }
  // Provider-granted scopes rendered under an authority heading is the conflation canon names by hand.
  if (/authority|granted authority|permissions granted/iu.test(text) && /provider_granted_scopes/u.test(text)) {
    findings.push(`${where}: presents provider-granted scopes as authority`);
  }
  return findings;
}

/**
 * THE FOUR SUBJECTS STAY DISTINCT. A view that offers one action for two of them has merged lifecycles the
 * daemon keeps apart — and the merge is invisible until a disconnect silently deletes an integration, or a
 * grant revocation is read as a provider disconnect.
 */
export function distinctnessFindings(actions, { where = "view" } = {}) {
  const findings = [];
  const offered = Array.isArray(actions) ? actions : [];
  for (const action of offered) {
    const subjects = DISTINCT_SUBJECTS.filter((subject) => (action?.affects ?? []).includes(subject));
    if (subjects.length > 1) {
      findings.push(`${where}: the action ${strAt(action, "id")} affects ${subjects.join(" and ")} at once`);
    }
    if (subjects.length === 0) {
      findings.push(`${where}: the action ${strAt(action, "id")} names no subject it affects`);
    }
  }
  const covered = new Set(offered.flatMap((action) => action?.affects ?? []));
  for (const verb of LIFECYCLE_VERBS) {
    if (!offered.some((action) => strAt(action, "id") === verb)) {
      findings.push(`${where}: the lifecycle verb ${verb} is not offered`);
    }
  }
  return { findings, covered: [...covered] };
}

/**
 * NO SECRET REACHES A SURFACE. Checked over what was RENDERED, not over what the view intended to render:
 * a hand-picked field list is a promise, and this is the measurement.
 */
export function secretFindings(rendered, { where = "view" } = {}) {
  const findings = [];
  const text = typeof rendered === "string" ? rendered : JSON.stringify(rendered ?? "");
  for (const member of NEVER_RENDERED) {
    if (text.includes(member)) {
      findings.push(`${where}: the rendered surface carries the member name ${member}`);
    }
  }
  return findings;
}

/**
 * DEPENDENTS ARE EXACT. The daemon derives them on read; a view must show what it was given and must not
 * present a dependent of a DIFFERENT connection version as this one's. Reconnect creates a successor
 * version, so a set keyed on the connector rather than on the connection ref will look right and be wrong.
 */
export function dependentFindings(dependents, connection, { where = "view" } = {}) {
  const findings = [];
  const connectionRef = strAt(connection, "connection_ref");
  const entries = Array.isArray(dependents) ? dependents : [];
  for (const entry of entries) {
    const bound = strAt(entry, "connection_ref");
    if (bound !== "" && bound !== connectionRef) {
      findings.push(`${where}: a dependent bound to ${bound} is rendered under ${connectionRef}`);
    }
    if (!strAt(entry, "kind")) {
      findings.push(`${where}: a dependent names no kind, so a reader cannot tell a grant from a session`);
    }
  }
  return findings;
}

/**
 * THE THREE VIEWS AGREE. Compared on the members that decide what an operator does next — not on the whole
 * rendering, because each view legitimately renders different chrome, and requiring byte equality would
 * fail for the one reason that is correct.
 */
export const PARITY_MEMBERS = Object.freeze([
  "connection_ref",
  "connection_version",
  "status",
  "effective_posture",
  "provider_reachability",
  "connection_revocation_epoch",
  "provider_granted_scopes",
  "required_next_action",
  "use_is_fenced",
  "authority_granted",
]);

export function viewParityFindings(views, { where = "views" } = {}) {
  const findings = [];
  const names = Object.keys(views ?? {});
  if (names.length < 2) return [`${where}: parity needs at least two views, got ${names.length}`];
  const [first, ...rest] = names;
  for (const member of PARITY_MEMBERS) {
    const baseline = JSON.stringify(views[first]?.[member] ?? null);
    for (const other of rest) {
      const value = JSON.stringify(views[other]?.[member] ?? null);
      if (value !== baseline) {
        findings.push(`${where}: ${member} differs — ${first} ${baseline.slice(0, 50)} ≠ ${other} ${value.slice(0, 50)}`);
      }
    }
  }
  return findings;
}

/** A source pin reads CODE, never the prose explaining it. */
export function codeOnly(source) {
  return String(source)
    .split("\n")
    .filter((line) => !/^\s*(\/\/|#)/u.test(line))
    .join("\n");
}
