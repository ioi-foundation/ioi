// provider-connection-offline-verifier — M03.16's OFFLINE verifier. A relying party holding only the
// records (a ProviderConnectionCeremony, the versions of a ProviderConnectionBinding, a connector's
// auth profile) re-derives every commitment the daemon served and checks the version chain, with
// no daemon, no provider and no secret. The driven gate uses these functions as its oracles and the
// SDK exports them, so the API path and the SDK path verify the same bytes the same way.
//
// Nothing here trusts a member it can recompute: the content hashes, the provider profile
// revision and the account subject commitment are all recomputed from their material.
import crypto from "node:crypto";

export const CEREMONY_DOMAIN = "ioi.wallet.provider-connection-ceremony-content-commitment-jcs-sha256.v1";
export const BINDING_DOMAIN = "ioi.wallet.provider-connection-binding-content-commitment-jcs-sha256.v1";
export const CEREMONY_MATERIAL = ["schema_version", "ceremony_ref", "owner_ref", "principal_ref", "connector_ref", "provider_profile_ref", "redirect", "state", "nonce", "proof", "requested_scopes", "declared_account_subject", "credential_custody_profile_ref", "permitted_audience_classes", "product_session_origin", "issued_at", "expires_at", "status", "completion", "refusal", "receipt_refs"];
export const BINDING_MATERIAL = ["schema_version", "connection_ref", "connection_version", "predecessor_ref", "owner_ref", "principal_ref", "connector_ref", "provider_profile_ref", "provider_account_subject_hash", "provider_tenant_subject_hash", "provider_granted_scopes", "credential_binding_ref", "credential_custody_profile_ref", "permitted_audience_classes", "connection_revocation_epoch", "reauthorization_required_at", "last_provider_verification", "status", "successor_ref", "ceremony_ref", "receipt_refs"];
export const LIVE_STATUSES = new Set(["active", "reauthorization_required", "degraded"]);

/** RFC 8785 canonical JSON for the value shapes these records carry (objects, arrays, strings, integers, booleans, null). */
export function jcs(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
}

export const sha256 = (text) => crypto.createHash("sha256").update(text).digest("hex");

function commitment(record, domain, material) {
  const missing = material.filter((field) => !(field in record));
  if (missing.length) throw new Error(`commitment material missing: ${missing.join(", ")}`);
  const flat = { domain };
  for (const field of material) flat[field] = record[field];
  return `sha256:${sha256(jcs(flat))}`;
}

export const deriveCeremonyHash = (record) => commitment(record, CEREMONY_DOMAIN, CEREMONY_MATERIAL);
export const deriveBindingHash = (record) => commitment(record, BINDING_DOMAIN, BINDING_MATERIAL);

/** The provider profile REVISION: content-addressed over the connector's auth profile with every sealed member excluded. */
export function deriveProviderProfileRef(connector) {
  const profile = Object.fromEntries(Object.entries(connector.auth_profile ?? {}).filter(([key]) => !key.startsWith("sealed_")));
  return `provider-profile://${connector.connector_id}@sha256:${sha256(jcs(profile))}`;
}

/** The account (or tenant) subject commitment: the provider profile revision and the subject, never the identifier alone. */
export const deriveSubjectHash = (providerProfileRef, subject) => `sha256:${sha256(jcs({ provider_profile_ref: providerProfileRef, subject }))}`;
export const deriveTenantHash = (providerProfileRef, tenant) => deriveSubjectHash(providerProfileRef, `tenant:${tenant}`);

/** The S256 PKCE challenge a verifier commits to. */
export const pkceChallenge = (verifier) => crypto.createHash("sha256").update(verifier).digest("base64url");

/**
 * Verify a ceremony record offline. Returns the list of findings (empty = verified).
 */
export function verifyCeremony(record, { connector = null, now = Date.now() } = {}) {
  const findings = [];
  if (record.content_hash !== deriveCeremonyHash(record)) findings.push("content_hash does not commit the record as served");
  if (connector && record.provider_profile_ref !== deriveProviderProfileRef(connector)) findings.push("provider_profile_ref does not match the connector's auth profile revision");
  if (record.proof?.code_challenge_method !== "S256" || !record.proof?.code_challenge) findings.push("proof is not an S256 challenge");
  if (!(record.requested_scopes?.length > 0)) findings.push("requested_scopes is empty");
  if (Date.parse(record.expires_at) <= Date.parse(record.issued_at)) findings.push("expires_at is not after issued_at");
  if (record.status === "completed") {
    for (const member of ["connection_ref", "provider_account_subject_hash", "evidence_ref", "completed_at"]) if (!record.completion?.[member]) findings.push(`completed without completion.${member}`);
    const widened = (record.completion?.provider_granted_scopes ?? []).filter((scope) => !record.requested_scopes.includes(scope));
    if (widened.length) findings.push(`completion granted scopes never requested: ${widened.join(", ")}`);
  }
  if (record.status === "refused" && !record.refusal?.code) findings.push("refused without a code");
  if (record.status === "issued" && Date.parse(record.expires_at) < now) findings.push("an issued ceremony past its expiry is stale");
  return findings;
}

/**
 * Verify a connection's version chain offline: each version commits itself, names its predecessor
 * exactly, moves version and epoch monotonically, never changes the account it binds, and a live
 * head is what the latest version says it is.
 */
export function verifyConnectionChain(versions, { connector = null, subject = null } = {}) {
  const findings = [];
  if (!versions?.length) return ["no versions"];
  const sorted = [...versions].sort((a, b) => a.connection_version - b.connection_version);
  let previous = null;
  for (const version of sorted) {
    const at = `@${version.connection_version}`;
    if (version.content_hash !== deriveBindingHash(version)) findings.push(`${at}: content_hash does not commit the version as served`);
    if (connector && version.provider_profile_ref !== deriveProviderProfileRef(connector)) findings.push(`${at}: provider_profile_ref does not match the connector`);
    if (subject !== null && version.provider_account_subject_hash !== deriveSubjectHash(version.provider_profile_ref, subject)) findings.push(`${at}: provider_account_subject_hash does not commit the expected subject`);
    if (!/^credential:\/\/.+@[0-9]+$/u.test(version.credential_binding_ref)) findings.push(`${at}: credential_binding_ref is not versioned`);
    if (version.status === "active" && !(version.provider_granted_scopes?.length > 0)) findings.push(`${at}: active without granted scopes`);
    if (["current", "degraded", "provider_revoked"].includes(version.last_provider_verification?.status) && !version.last_provider_verification?.evidence_ref) findings.push(`${at}: verification claimed without evidence`);
    if (previous === null) {
      if (version.connection_version !== 1 || version.predecessor_ref !== null) findings.push(`${at}: the first version is not version 1 without a predecessor`);
    } else {
      if (version.connection_version !== previous.connection_version + 1) findings.push(`${at}: version does not follow ${previous.connection_version}`);
      if (version.predecessor_ref !== `${previous.connection_ref}@${previous.connection_version}`) findings.push(`${at}: predecessor_ref does not name @${previous.connection_version}`);
      if (version.connection_revocation_epoch < previous.connection_revocation_epoch) findings.push(`${at}: the epoch went backwards`);
      if (version.provider_account_subject_hash !== previous.provider_account_subject_hash) findings.push(`${at}: the bound account changed across versions`);
      if (version.provider_tenant_subject_hash !== previous.provider_tenant_subject_hash) findings.push(`${at}: the bound tenant changed across versions`);
      if ((previous.status === "disconnected" || previous.status === "provider_revoked") && version.status === "active" && version.credential_binding_ref === previous.credential_binding_ref) findings.push(`${at}: a reconnect reused the predecessor's credential binding`);
      if (previous.status === "disconnected" && version.connection_revocation_epoch === previous.connection_revocation_epoch - 1) findings.push(`${at}: the epoch was rolled back`);
    }
    if (version.connection_ref !== sorted[0].connection_ref) findings.push(`${at}: a different connection family`);
    previous = version;
  }
  return findings;
}

/** Whether a credential record's coordinates are those a live head admits — the fence, computed offline. */
export function credentialIsFenced(credential, head, now = Date.now()) {
  if (!credential?.connection_ref) return { fenced: false, cause: "legacy credential without a connection" };
  if (!head) return { fenced: true, cause: "connection_absent" };
  if (head.status !== "active") return { fenced: true, cause: `connection_${head.status}` };
  if (credential.credential_binding_ref !== head.credential_binding_ref) return { fenced: true, cause: "connection_credential_superseded" };
  if (credential.connection_revocation_epoch !== head.connection_revocation_epoch) return { fenced: true, cause: "connection_epoch_advanced" };
  if (head.reauthorization_required_at && Date.parse(head.reauthorization_required_at) < now) return { fenced: true, cause: "connection_reauthorization_required" };
  return { fenced: false, cause: null };
}
