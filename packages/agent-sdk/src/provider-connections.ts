/**
 * M03.16 — external-account connections (wallet.network's ProviderConnectionCeremony and
 * ProviderConnectionBinding as the daemon serves them under /v1/hypervisor/auth/connections).
 *
 * Connected is not authorized: none of these calls mints action authority. The client is a thin
 * path over the same routes the API and the product UI use; the verifier functions below let a
 * relying party holding only the records re-derive every commitment offline — the same derivations
 * the registered fixtures pin and the daemon's gate re-derives.
 */
import { createHash } from "node:crypto";

export interface ProviderConnectionStartInput {
  owner_ref: string;
  idempotency_key: string;
  connector_id: string;
  redirect_uri: string;
  requested_scopes?: string[];
  declared_account_subject?: string | null;
  credential_custody_profile_ref?: string;
  permitted_audience_classes?: Array<"connector" | "final_invoker">;
  product_session_origin?: string;
}

export interface ProviderConnectionCompleteInput {
  owner_ref: string;
  idempotency_key: string;
  state: string;
  code: string;
  redirect_uri?: string;
}

export interface ProviderConnectionTransitionInput {
  owner_ref: string;
  idempotency_key: string;
  expected_head: string;
  reason?: string;
}

export interface ProviderConnectionReauthorizeInput {
  owner_ref: string;
  idempotency_key: string;
  redirect_uri: string;
  requested_scopes?: string[];
}

export interface ProviderConnectionCeremony {
  schema_version: "ioi.wallet.provider-connection-ceremony.v1";
  ceremony_ref: string;
  owner_ref: string;
  principal_ref: string;
  connector_ref: string;
  provider_profile_ref: string;
  redirect: { origin: string; uri: string };
  state: string;
  nonce: string;
  proof: { kind: "pkce_s256" | "profile_equivalent"; code_challenge: string; code_challenge_method: "S256" };
  requested_scopes: string[];
  declared_account_subject: string | null;
  credential_custody_profile_ref: string;
  permitted_audience_classes: string[];
  product_session_origin: string;
  issued_at: string;
  expires_at: string;
  status: "issued" | "completed" | "expired" | "refused";
  completion: {
    completed_at: string | null;
    connection_ref: string | null;
    provider_account_subject_hash: string | null;
    provider_tenant_subject_hash: string | null;
    provider_granted_scopes: string[];
    evidence_ref: string | null;
  };
  refusal: { code: string | null; refused_at: string | null };
  receipt_refs: string[];
  content_hash: string;
  admitted_at: string;
}

export interface ProviderConnectionBinding {
  schema_version: "ioi.wallet.provider-connection-binding.v1";
  connection_ref: string;
  connection_version: number;
  predecessor_ref: string | null;
  owner_ref: string;
  principal_ref: string;
  connector_ref: string;
  provider_profile_ref: string;
  provider_account_subject_hash: string;
  provider_tenant_subject_hash: string | null;
  provider_granted_scopes: string[];
  credential_binding_ref: string;
  credential_custody_profile_ref: string;
  permitted_audience_classes: string[];
  connection_revocation_epoch: number;
  reauthorization_required_at: string | null;
  last_provider_verification: { observed_at: string | null; evidence_ref: string | null; status: "current" | "degraded" | "unknown" | "provider_revoked" };
  status: "pending_authorization" | "active" | "reauthorization_required" | "degraded" | "provider_revoked" | "disconnected" | "superseded";
  successor_ref: string | null;
  ceremony_ref: string;
  receipt_refs: string[];
  content_hash: string;
  admitted_at: string;
}

export interface ProviderConnectionStartResult {
  ok: boolean;
  authorize_url?: string;
  state?: string;
  provider_connection_ceremony_record?: ProviderConnectionCeremony;
  [key: string]: unknown;
}

export interface ProviderConnectionCompleteResult {
  ok: boolean;
  connected?: boolean;
  connection_id?: string;
  connection?: ProviderConnectionBinding;
  connection_head?: string;
  ceremony?: ProviderConnectionCeremony;
  [key: string]: unknown;
}

export interface ProviderConnectionView {
  ok: boolean;
  current: ProviderConnectionBinding | null;
  versions: ProviderConnectionBinding[];
  head: string | null;
}

export interface ProviderConnectionSummary {
  connection_id: string;
  connection_ref: string;
  connection_version: number;
  status: ProviderConnectionBinding["status"];
  connection_revocation_epoch: number;
  reauthorization_required_at: string | null;
  connector_ref: string;
}

export interface ProviderConnectionListResult {
  ok: boolean;
  connections: ProviderConnectionSummary[];
}

export interface ProviderConnectionDependentsResult {
  ok: boolean;
  connection_ref: string;
  connection_version: number | null;
  dependents: { lease_grants: unknown[]; connector_sessions: unknown[]; obligations: unknown[] };
}

export interface ProviderConnectionTransitionResult {
  ok: boolean;
  provider_connection_binding_record?: ProviderConnectionBinding;
  expected_head_for_successor?: string;
  obligations?: unknown[];
  [key: string]: unknown;
}

export const PROVIDER_CONNECTION_ROUTES = {
  start: "/v1/hypervisor/auth/connections/authorization/start",
  complete: "/v1/hypervisor/auth/connections/authorization/complete",
  list: "/v1/hypervisor/auth/connections",
  get: (id: string) => `/v1/hypervisor/auth/connections/${encodeURIComponent(id)}`,
  dependents: (id: string) => `/v1/hypervisor/auth/connections/${encodeURIComponent(id)}/dependents`,
  verify: (id: string) => `/v1/hypervisor/auth/connections/${encodeURIComponent(id)}/verify`,
  reauthorize: (id: string) => `/v1/hypervisor/auth/connections/${encodeURIComponent(id)}/reauthorize`,
  disconnect: (id: string) => `/v1/hypervisor/auth/connections/${encodeURIComponent(id)}/disconnect`,
} as const;

// ------------------------------------------------------------------ the offline derivations

export const PROVIDER_CONNECTION_CEREMONY_DOMAIN = "ioi.wallet.provider-connection-ceremony-content-commitment-jcs-sha256.v1";
export const PROVIDER_CONNECTION_BINDING_DOMAIN = "ioi.wallet.provider-connection-binding-content-commitment-jcs-sha256.v1";
const CEREMONY_MATERIAL = ["schema_version", "ceremony_ref", "owner_ref", "principal_ref", "connector_ref", "provider_profile_ref", "redirect", "state", "nonce", "proof", "requested_scopes", "declared_account_subject", "credential_custody_profile_ref", "permitted_audience_classes", "product_session_origin", "issued_at", "expires_at", "status", "completion", "refusal", "receipt_refs"] as const;
const BINDING_MATERIAL = ["schema_version", "connection_ref", "connection_version", "predecessor_ref", "owner_ref", "principal_ref", "connector_ref", "provider_profile_ref", "provider_account_subject_hash", "provider_tenant_subject_hash", "provider_granted_scopes", "credential_binding_ref", "credential_custody_profile_ref", "permitted_audience_classes", "connection_revocation_epoch", "reauthorization_required_at", "last_provider_verification", "status", "successor_ref", "ceremony_ref", "receipt_refs"] as const;

/** RFC 8785 canonical JSON for the value shapes these records carry. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

function commitment(record: Record<string, unknown>, domain: string, material: readonly string[]): string {
  const flat: Record<string, unknown> = { domain };
  for (const field of material) {
    if (!(field in record)) throw new Error(`commitment material missing: ${field}`);
    flat[field] = record[field];
  }
  return `sha256:${sha256(canonicalJson(flat))}`;
}

export const deriveProviderConnectionCeremonyHash = (record: ProviderConnectionCeremony | Record<string, unknown>): string =>
  commitment(record as Record<string, unknown>, PROVIDER_CONNECTION_CEREMONY_DOMAIN, CEREMONY_MATERIAL);
export const deriveProviderConnectionBindingHash = (record: ProviderConnectionBinding | Record<string, unknown>): string =>
  commitment(record as Record<string, unknown>, PROVIDER_CONNECTION_BINDING_DOMAIN, BINDING_MATERIAL);

/** The provider profile REVISION: content-addressed over a connector's auth profile with every sealed member excluded. */
export function deriveProviderProfileRef(connector: { connector_id: string; auth_profile?: Record<string, unknown> | null }): string {
  const profile = Object.fromEntries(Object.entries(connector.auth_profile ?? {}).filter(([key]) => !key.startsWith("sealed_")));
  return `provider-profile://${connector.connector_id}@sha256:${sha256(canonicalJson(profile))}`;
}

/** The account subject commitment: the provider profile revision and the subject, never the identifier alone. */
export const deriveProviderAccountSubjectHash = (providerProfileRef: string, subject: string): string =>
  `sha256:${sha256(canonicalJson({ provider_profile_ref: providerProfileRef, subject }))}`;

/**
 * Verify a connection's version chain offline: every version commits itself, names its predecessor
 * exactly, moves version and epoch monotonically and never changes the account it binds.
 */
export function verifyProviderConnectionChain(versions: ProviderConnectionBinding[]): string[] {
  const findings: string[] = [];
  if (!versions?.length) return ["no versions"];
  const sorted = [...versions].sort((a, b) => a.connection_version - b.connection_version);
  let previous: ProviderConnectionBinding | null = null;
  for (const version of sorted) {
    const at = `@${version.connection_version}`;
    if (version.content_hash !== deriveProviderConnectionBindingHash(version)) findings.push(`${at}: content_hash does not commit the version as served`);
    if (version.status === "active" && !(version.provider_granted_scopes?.length > 0)) findings.push(`${at}: active without granted scopes`);
    if (previous === null) {
      if (version.connection_version !== 1 || version.predecessor_ref !== null) findings.push(`${at}: the first version is not version 1 without a predecessor`);
    } else {
      if (version.connection_version !== previous.connection_version + 1) findings.push(`${at}: version does not follow ${previous.connection_version}`);
      if (version.predecessor_ref !== `${previous.connection_ref}@${previous.connection_version}`) findings.push(`${at}: predecessor_ref does not name @${previous.connection_version}`);
      if (version.connection_revocation_epoch < previous.connection_revocation_epoch) findings.push(`${at}: the epoch went backwards`);
      if (version.provider_account_subject_hash !== previous.provider_account_subject_hash) findings.push(`${at}: the bound account changed across versions`);
    }
    previous = version;
  }
  return findings;
}

/** The fence, computed offline: whether a credential's coordinates are those a live head admits. */
export function providerCredentialIsFenced(
  credential: { connection_ref?: string; credential_binding_ref?: string; connection_revocation_epoch?: number },
  head: ProviderConnectionBinding | null,
  now: number = Date.now(),
): { fenced: boolean; cause: string | null } {
  if (!credential?.connection_ref) return { fenced: false, cause: "legacy credential without a connection" };
  if (!head) return { fenced: true, cause: "connection_absent" };
  if (head.status !== "active") return { fenced: true, cause: `connection_${head.status}` };
  if (credential.credential_binding_ref !== head.credential_binding_ref) return { fenced: true, cause: "connection_credential_superseded" };
  if (credential.connection_revocation_epoch !== head.connection_revocation_epoch) return { fenced: true, cause: "connection_epoch_advanced" };
  if (head.reauthorization_required_at && Date.parse(head.reauthorization_required_at) < now) return { fenced: true, cause: "connection_reauthorization_required" };
  return { fenced: false, cause: null };
}
