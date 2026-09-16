/**
 * Collaboration composed over an orchestration (R-172 slice S3; M11.1; ACC-13 clauses 1, 2, 3, N1).
 *
 * WHAT THIS IS. The ioi.ai application's composition of four typed records over the agent SDK's
 * `Orchestration` (a coordinating thread, delegations as subagents, reservations, and records under
 * a bounded System through the generic record seam): CollaborationTerms v3 whose activation is
 * DERIVED from exact-root acceptances; an OrchestrationDiscovery projection that is refused until
 * the terms are active; an OrchestrationParticipationRequest signed by a party OUTSIDE the host
 * System, verified against the key that party accepted the terms with, refused when it originates
 * inside the host's own system_id, and decided as a successor revision of the same record; and a
 * least-disclosing ParticipantStateBundle the host signs and anyone verifies offline.
 *
 * WHAT THIS IS NOT. Not a plane. Nothing here is served by the daemon for the collaboration; every
 * fact is a record under the System, every derivation is re-computable from the record, and the
 * composer holds no state but the orchestration handle and the host's signer. No lease, roster or
 * membership object exists; an accepted participation IS its accepted revision.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

import { canonicalJson, type Orchestration, type SystemRecordAdmitResult, type SystemRecordChainResult } from "@ioi/agent-sdk";

// ---- contracts ----------------------------------------------------------------------------------

export const COLLABORATION_CONTRACTS = {
  terms: "schema://ioi/foundations/objects/collaboration-terms-envelope/v3",
  discovery: "schema://ioi/applications/ioi-ai/orchestration-discovery/v1",
  participation: "schema://ioi/applications/ioi-ai/orchestration-participation-request/v2",
  bundle: "schema://ioi/applications/ioi-ai/participant-state-bundle/v4",
} as const;

export const COLLABORATION_DOMAINS = {
  termsAcceptance: "ioi.collaboration-terms-acceptance-jcs-sha256.v1",
  discoveryStateRoot: "ioi.orchestration-discovery-state-root-jcs-sha256.v1",
  participationRequestHash: "ioi.orchestration-participation-request-hash-jcs-sha256.v1",
  participationDecision: "ioi.orchestration-participation-decision-jcs-sha256.v1",
  bundleRoot: "ioi.participant-state-bundle-root-jcs-sha256.v1",
} as const;

/** The members each root commits, exactly as the registered invariants list them (the unit test pins the two against each other). */
export const DISCOVERY_ROOT_MEMBERS = [
  "discovery_id", "orchestration_ref", "publication_version", "published_by_ref", "public_goal_ref", "public_objective",
  "public_category_refs", "coordination_topology", "admission_owner_ref", "participation_channel_ref", "collaboration_terms_ref",
  "collaboration_terms_root", "semantic_and_action_profile_refs", "required_capability_and_worker_profile_refs",
  "eligibility_and_affiliation_policy_refs", "visibility_and_privacy_policy_refs", "public_frontier_and_context_projection_refs",
  "budget_quote_and_capacity_refs", "verifier_and_acceptance_posture_refs", "settlement_dispute_and_contribution_policy_refs",
  "license_retention_and_export_policy_refs", "excluded_context_classes", "private_context_included", "published_at", "valid_until",
] as const;
export const PARTICIPATION_REQUEST_HASH_MEMBERS = [
  "participation_request_id", "orchestration_ref", "discovery_ref", "coordination_topology", "admission_owner_ref", "requested_by_ref",
  "requester_system_ref", "collaboration_terms_ref", "collaboration_terms_root", "terms_response", "counterterms_ref", "capability_offer_refs",
  "eligibility_evidence_refs", "requested_role_frontier_and_visibility_refs", "privacy_custody_and_context_policy_refs",
  "private_context_included", "requested_at",
] as const;
export const BUNDLE_ROOT_MEMBERS = [
  "participant_state_bundle_id", "orchestration_ref", "participation_ref", "participant_and_home_domain_refs", "coordination_topology",
  "bundle_reason", "source_admission_watermark_ref", "released_or_reassigned_claim_refs", "preserved_contribution_attempt_finding_and_result_refs",
  "preserved_receipt_acceptance_settlement_and_dispute_refs", "portable_artifact_and_view_refs", "lineage_and_supersession_refs",
  "export_license_retention_and_recall_policy_refs", "excluded_context_classes", "released_future_access_refs", "revocation_or_supersession_refs",
  "revocation_effect", "bundle_artifact_ref", "hosted_database_access_required", "issued_at",
] as const;

export const DISCOVERY_EXCLUDED_CONTEXT_CLASSES = [
  "raw_secret", "protected_plaintext", "unauthorized_connector_payload", "unrelated_private_memory", "private_orchestration_state", "non_opted_in_training_trace",
] as const;
export const BUNDLE_EXCLUDED_CONTEXT_CLASSES = [...DISCOVERY_EXCLUDED_CONTEXT_CLASSES, "revoked_restricted_view"] as const;

export const BUNDLE_REF_SLOTS = [
  "released_or_reassigned_claim_refs", "preserved_contribution_attempt_finding_and_result_refs", "preserved_receipt_acceptance_settlement_and_dispute_refs",
  "portable_artifact_and_view_refs", "lineage_and_supersession_refs", "export_license_retention_and_recall_policy_refs", "released_future_access_refs",
  "revocation_or_supersession_refs",
] as const;
export type BundleRefSlot = (typeof BUNDLE_REF_SLOTS)[number];

// ---- shapes -------------------------------------------------------------------------------------

export interface SignatureEnvelope {
  key_suite: "ed25519";
  signer_ref: string;
  signer_public_key: string;
  signed_material_hash: string;
  signature: string;
}

export interface TermsAcceptance {
  party_ref: string;
  terms_body_root: string;
  accepted_at: string;
  signature: SignatureEnvelope;
}

export interface TermsActivation {
  rule: "unanimous_required_parties";
  status_when_activated: "active";
  accepted_root: string;
  accepted_party_refs: string[];
  acceptance_receipt_refs: string[];
  activated_at: string;
}

export interface CollaborationTermsRecord {
  schema_version: "ioi.collaboration-terms.v3";
  collaboration_terms_id: string;
  version: string;
  predecessor_terms_ref: string | null;
  terms_body_hash_profile: "ioi.collaboration-terms-body.v1";
  terms_body_root: string;
  scope: { collaboration_ref: string | null; orchestration_ref: string | null };
  proposed_by_ref: string;
  status: "draft" | "proposed" | "active" | "suspended" | "superseded" | "expired" | "terminated" | "revoked";
  party_roles: Array<{ party_ref: string; role: string; acceptance_required: boolean }> | null;
  required_party_refs: string[];
  acceptances: TermsAcceptance[];
  activation: TermsActivation | null;
  system_binding?: Record<string, unknown>;
}

export type TermsProposal = Omit<CollaborationTermsRecord, "schema_version" | "status" | "acceptances" | "activation" | "system_binding" | "scope"> & {
  scope?: { collaboration_ref?: string | null; orchestration_ref?: string | null };
};

export interface DiscoveryDraft {
  discovery_id: string;
  publication_version: string;
  public_goal_ref: string;
  public_objective: string;
  public_category_refs: string[];
  coordination_topology: "hosted_admission" | "federated_admission";
  admission_owner_ref: string;
  participation_channel_ref: string;
  collaboration_terms_ref: string;
  semantic_and_action_profile_refs?: string[];
  required_capability_and_worker_profile_refs?: string[];
  eligibility_and_affiliation_policy_refs?: string[];
  visibility_and_privacy_policy_refs?: string[];
  public_frontier_and_context_projection_refs?: string[];
  budget_quote_and_capacity_refs?: string[];
  verifier_and_acceptance_posture_refs?: string[];
  settlement_dispute_and_contribution_policy_refs?: string[];
  license_retention_and_export_policy_refs?: string[];
  published_at?: string;
  valid_until?: string | null;
}

export interface ParticipationRequestDraft {
  participation_request_id: string;
  orchestration_ref: string;
  discovery_ref: string;
  coordination_topology: "hosted_admission" | "federated_admission";
  admission_owner_ref: string;
  requester_system_ref: string;
  collaboration_terms_ref: string;
  collaboration_terms_root: string;
  terms_response: "accept" | "counteroffer" | "decline";
  counterterms_ref?: string | null;
  capability_offer_refs?: string[];
  eligibility_evidence_refs?: string[];
  requested_role_frontier_and_visibility_refs?: string[];
  privacy_custody_and_context_policy_refs?: string[];
  requested_at?: string;
}

export interface ParticipationDecision {
  status: "accepted" | "refused";
  decided_by_ref: string;
  decided_at: string;
  receipt_ref: string;
  reason_code: string;
  /** Under federated_admission: the terms party (role coordinator) whose key of record co-signs; null under hosted_admission. */
  adjudicator_ref: string | null;
  federation_signature: SignatureEnvelope | null;
}

export interface ParticipationExit {
  /** An exit exists only on an accepted participation; the status stays accepted, the exit is a fact on top of it. */
  status_at_exit: "accepted";
  bundle_ref: string;
  exited_at: string;
  reason_code: string;
  /** The seam's receipt of the accepted revision the exit leaves from. */
  receipt_ref: string;
}

export interface ParticipationRequestRecord extends Required<Omit<ParticipationRequestDraft, "counterterms_ref">> {
  schema_version: "ioi.applications.ioi-ai.orchestration-participation-request.v2";
  requested_by_ref: string;
  counterterms_ref: string | null;
  private_context_included: false;
  request_hash: string;
  signature: SignatureEnvelope;
  decision: ParticipationDecision | null;
  exit: ParticipationExit | null;
  status: "submitted" | "accepted" | "refused" | "withdrawn" | "expired";
  system_binding?: Record<string, unknown>;
}

export interface BundleCandidateRef {
  slot: BundleRefSlot;
  ref: string;
  /** The context class of what the ref reaches; a ref whose class is excluded never enters the bundle. */
  context_class: string;
}

export interface BundleDraft {
  participant_state_bundle_id: string;
  participation_request_id: string;
  participant_and_home_domain_refs: string[];
  bundle_reason: "checkpoint" | "voluntary_retirement" | "participation_expiry" | "revocation" | "quarantine" | "orchestration_close";
  source_admission_watermark_ref: string;
  candidate_refs: BundleCandidateRef[];
  revocation_effect?: "none" | "future_access_only" | "restricted_view_keys_revoked" | "erroneous_export_superseded";
  bundle_artifact_ref: string;
  issued_at?: string;
}

export interface Signer {
  signer_ref: string;
  privateKey: KeyObject;
  publicKeyHex: string;
}

// ---- refusals -----------------------------------------------------------------------------------

export class CollaborationRefusal extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;
  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "CollaborationRefusal";
    this.code = code;
    this.details = details;
  }
}

// ---- pure derivations ---------------------------------------------------------------------------

const sha256 = (text: string): string => `sha256:${createHash("sha256").update(text).digest("hex")}`;

function materialRoot(domain: string, record: Record<string, unknown>, members: readonly string[]): string {
  const material: Record<string, unknown> = { domain };
  for (const member of members) material[member] = record[member] === undefined ? null : record[member];
  return sha256(canonicalJson(material));
}

export function deriveTermsAcceptanceMaterialHash(input: { collaboration_terms_id: string; terms_body_root: string; party_ref: string; accepted_at: string }): string {
  return sha256(canonicalJson({ domain: COLLABORATION_DOMAINS.termsAcceptance, ...input }));
}

export function deriveDiscoveryStateRoot(discovery: Record<string, unknown>): string {
  return materialRoot(COLLABORATION_DOMAINS.discoveryStateRoot, discovery, DISCOVERY_ROOT_MEMBERS);
}

export function deriveParticipationRequestHash(request: Record<string, unknown>): string {
  return materialRoot(COLLABORATION_DOMAINS.participationRequestHash, request, PARTICIPATION_REQUEST_HASH_MEMBERS);
}

export function deriveBundleRoot(bundle: Record<string, unknown>): string {
  return materialRoot(COLLABORATION_DOMAINS.bundleRoot, bundle, BUNDLE_ROOT_MEMBERS);
}

/** The material a federated decision is co-signed over: the request it decides, its hash, the verdict, the time and the declared admission owner. */
export function deriveParticipationDecisionMaterialHash(input: { participation_request_id: string; request_hash: string; status: "accepted" | "refused"; decided_at: string; admission_owner_ref: string }): string {
  return sha256(canonicalJson({ domain: COLLABORATION_DOMAINS.participationDecision, ...input }));
}

/** Offline verification of a decision revision: the admission owner decided; under federated_admission the adjudicator's co-signature verifies against the given key of record. */
export function verifyParticipationDecision(record: ParticipationRequestRecord, adjudicatorPublicKeyHex?: string): { ok: boolean; findings: string[] } {
  const findings: string[] = [];
  const decision = record.decision;
  if (!decision) return { ok: false, findings: ["no decision on the record"] };
  if (decision.decided_by_ref !== record.admission_owner_ref) findings.push("the decision is not the admission owner's");
  if (record.status !== decision.status) findings.push("the record's status contradicts the decision");
  if (record.coordination_topology === "federated_admission") {
    if (!decision.adjudicator_ref || !decision.federation_signature) findings.push("a federated decision carries no adjudicator co-signature");
    else {
      const material = deriveParticipationDecisionMaterialHash({ participation_request_id: record.participation_request_id, request_hash: record.request_hash, status: decision.status, decided_at: decision.decided_at, admission_owner_ref: record.admission_owner_ref });
      if (decision.federation_signature.signer_ref !== decision.adjudicator_ref) findings.push("the co-signature is not the adjudicator's");
      if (!verifySignatureEnvelope(decision.federation_signature, material, adjudicatorPublicKeyHex)) findings.push("the adjudicator's co-signature does not verify over the decision material");
    }
  } else if (decision.adjudicator_ref !== null || decision.federation_signature !== null) {
    findings.push("a hosted decision carries an adjudicator");
  }
  return { ok: findings.length === 0, findings };
}

/**
 * Activation is a projection of the acceptances: non-null exactly when every required party has an
 * acceptance over the terms' own root. `acceptance_receipt_refs` are the seam receipts of the
 * revisions that carried those acceptances, supplied by the caller who admitted them.
 */
export function deriveTermsActivation(
  terms: Pick<CollaborationTermsRecord, "terms_body_root" | "required_party_refs" | "acceptances">,
  acceptanceReceiptRefs: string[],
  activatedAt: string,
): TermsActivation | null {
  const exact = terms.acceptances.filter((a) => a.terms_body_root === terms.terms_body_root);
  const accepted = [...new Set(exact.map((a) => a.party_ref))].sort();
  const missing = terms.required_party_refs.filter((p) => !accepted.includes(p));
  if (missing.length > 0) return null;
  return {
    rule: "unanimous_required_parties",
    status_when_activated: "active",
    accepted_root: terms.terms_body_root,
    accepted_party_refs: accepted,
    acceptance_receipt_refs: [...acceptanceReceiptRefs],
    activated_at: activatedAt,
  };
}

// ---- ed25519 ------------------------------------------------------------------------------------

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function signerFromSeed(signerRef: string, seedHex: string): Signer {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  return { signer_ref: signerRef, privateKey, publicKeyHex: rawPublicKeyHex(privateKey) };
}

export function generateSigner(signerRef: string): Signer {
  const { privateKey } = generateKeyPairSync("ed25519");
  return { signer_ref: signerRef, privateKey, publicKeyHex: rawPublicKeyHex(privateKey) };
}

function rawPublicKeyHex(privateKey: KeyObject): string {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32).toString("hex");
}

/** Sign the material hash string itself (UTF-8 bytes of `sha256:…`), the estate's receipt convention. */
export function signMaterialHash(signer: Signer, materialHash: string): SignatureEnvelope {
  return {
    key_suite: "ed25519",
    signer_ref: signer.signer_ref,
    signer_public_key: signer.publicKeyHex,
    signed_material_hash: materialHash,
    signature: edSign(null, Buffer.from(materialHash, "utf8"), signer.privateKey).toString("hex"),
  };
}

export function verifySignatureEnvelope(envelope: SignatureEnvelope, expectedMaterialHash: string, expectedPublicKeyHex?: string): boolean {
  if (envelope.key_suite !== "ed25519" || envelope.signed_material_hash !== expectedMaterialHash) return false;
  if (expectedPublicKeyHex !== undefined && envelope.signer_public_key !== expectedPublicKeyHex) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(envelope.signer_public_key, "hex")]), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(expectedMaterialHash, "utf8"), key, Buffer.from(envelope.signature, "hex"));
  } catch {
    return false;
  }
}

// ---- the external party's side (pure) -----------------------------------------------------------

export function buildParticipationRequest(draft: ParticipationRequestDraft, requester: Signer, now = new Date().toISOString()): ParticipationRequestRecord {
  const body: Omit<ParticipationRequestRecord, "request_hash" | "signature"> = {
    schema_version: "ioi.applications.ioi-ai.orchestration-participation-request.v2",
    participation_request_id: draft.participation_request_id,
    orchestration_ref: draft.orchestration_ref,
    discovery_ref: draft.discovery_ref,
    coordination_topology: draft.coordination_topology,
    admission_owner_ref: draft.admission_owner_ref,
    requested_by_ref: requester.signer_ref,
    requester_system_ref: draft.requester_system_ref,
    collaboration_terms_ref: draft.collaboration_terms_ref,
    collaboration_terms_root: draft.collaboration_terms_root,
    terms_response: draft.terms_response,
    counterterms_ref: draft.counterterms_ref ?? null,
    capability_offer_refs: draft.capability_offer_refs ?? [],
    eligibility_evidence_refs: draft.eligibility_evidence_refs ?? [],
    requested_role_frontier_and_visibility_refs: draft.requested_role_frontier_and_visibility_refs ?? [],
    privacy_custody_and_context_policy_refs: draft.privacy_custody_and_context_policy_refs ?? [],
    private_context_included: false,
    requested_at: draft.requested_at ?? now,
    decision: null,
    exit: null,
    status: "submitted",
  };
  const request_hash = deriveParticipationRequestHash(body as unknown as Record<string, unknown>);
  return { ...body, request_hash, signature: signMaterialHash(requester, request_hash) };
}

/** Offline verification of a bundle against nothing but the bundle and the host's declared key. */
export function verifyStateBundle(bundle: Record<string, unknown>, hostPublicKeyHex: string): { ok: boolean; findings: string[] } {
  const findings: string[] = [];
  if (bundle.hosted_database_access_required !== false) findings.push("hosted_database_access_required is not false");
  const excluded = Array.isArray(bundle.excluded_context_classes) ? (bundle.excluded_context_classes as string[]) : [];
  for (const cls of BUNDLE_EXCLUDED_CONTEXT_CLASSES) if (!excluded.includes(cls)) findings.push(`excluded context class missing: ${cls}`);
  const root = deriveBundleRoot(bundle);
  if (bundle.bundle_root !== root) findings.push("bundle_root does not recompute");
  const signature = bundle.signature as SignatureEnvelope | undefined;
  if (!signature || !verifySignatureEnvelope(signature, root, hostPublicKeyHex)) findings.push("host signature does not verify over the bundle root");
  else if (signature.signer_ref !== (bundle.system_binding as { system_id?: string } | undefined)?.system_id) findings.push("signer is not the host System");
  return { ok: findings.length === 0, findings };
}

// ---- the host application's composer ------------------------------------------------------------

export class Collaboration {
  readonly orchestration: Orchestration;
  readonly host: Signer;
  private readonly now: () => string;

  constructor(orchestration: Orchestration, host: Signer, options: { now?: () => string } = {}) {
    this.orchestration = orchestration;
    this.host = host;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  // -- terms (ACC-13 clause 1) --------------------------------------------------------------------

  async proposeTerms(proposal: TermsProposal): Promise<SystemRecordAdmitResult> {
    const record: Omit<CollaborationTermsRecord, "system_binding"> = {
      ...proposal,
      schema_version: "ioi.collaboration-terms.v3",
      scope: { collaboration_ref: proposal.scope?.collaboration_ref ?? null, orchestration_ref: proposal.scope?.orchestration_ref ?? this.orchestration.scope_ref },
      status: "proposed",
      acceptances: [],
      activation: null,
    };
    return this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.terms, object_id: record.collaboration_terms_id, record: record as unknown as Record<string, unknown>, expected_head: null });
  }

  async terms(termsId: string): Promise<SystemRecordChainResult> {
    return this.orchestration.recordChain(COLLABORATION_CONTRACTS.terms, termsId);
  }

  /** One party's exact-root acceptance, appended as a revision; activation is re-derived from the acceptances on record. */
  async acceptTerms(termsId: string, party: Signer): Promise<{ admitted: SystemRecordAdmitResult; activated: boolean }> {
    const chain = await this.terms(termsId);
    const current = stripBinding(chain.current) as CollaborationTermsRecord | null;
    if (!current) throw new CollaborationRefusal("collaboration_terms_absent", `no terms record ${termsId}`);
    if (current.status !== "proposed") {
      throw new CollaborationRefusal("collaboration_terms_not_open_for_acceptance", `${termsId} is ${current.status}; an active or closed bargain takes no further acceptance`);
    }
    if (!current.required_party_refs.includes(party.signer_ref)) {
      throw new CollaborationRefusal("collaboration_terms_party_not_required", `${party.signer_ref} is not a required party of ${termsId}`, { required_party_refs: current.required_party_refs });
    }
    if (current.acceptances.some((a) => a.party_ref === party.signer_ref)) {
      throw new CollaborationRefusal("collaboration_terms_already_accepted_by_party", `${party.signer_ref} already accepted ${termsId}`);
    }
    const accepted_at = this.now();
    const acceptance: TermsAcceptance = {
      party_ref: party.signer_ref,
      terms_body_root: current.terms_body_root,
      accepted_at,
      signature: signMaterialHash(party, deriveTermsAcceptanceMaterialHash({ collaboration_terms_id: termsId, terms_body_root: current.terms_body_root, party_ref: party.signer_ref, accepted_at })),
    };
    const acceptances = [...current.acceptances, acceptance];
    const priorReceipts = (chain.admissions ?? []).map((a) => a.receipt_ref).filter((r): r is string => typeof r === "string");
    const activation = deriveTermsActivation({ ...current, acceptances }, priorReceipts, accepted_at);
    const next: CollaborationTermsRecord = { ...current, acceptances, activation, status: activation ? "active" : current.status };
    const admitted = await this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.terms, object_id: termsId, record: next as unknown as Record<string, unknown>, expected_head: chain.head });
    return { admitted, activated: activation !== null };
  }

  private async requireActiveTerms(termsRef: string, expectedRoot?: string): Promise<CollaborationTermsRecord> {
    const chain = await this.terms(termsRef);
    const current = stripBinding(chain.current) as CollaborationTermsRecord | null;
    if (!current) throw new CollaborationRefusal("collaboration_terms_absent", `no terms record ${termsRef}`);
    if (current.status !== "active" || !current.activation || current.activation.accepted_root !== current.terms_body_root) {
      throw new CollaborationRefusal("collaboration_terms_not_active", `nothing crosses before every required party has accepted the exact terms root; ${termsRef} is ${current.status}`, {
        status: current.status,
        required_party_refs: current.required_party_refs,
        accepted_party_refs: current.acceptances.map((a) => a.party_ref),
      });
    }
    if (expectedRoot !== undefined && expectedRoot !== current.terms_body_root) {
      throw new CollaborationRefusal("collaboration_terms_root_mismatch", `the named root is not the active terms root`, { named: expectedRoot, active: current.terms_body_root });
    }
    return current;
  }

  // -- discovery (ACC-13 clause 2) ----------------------------------------------------------------

  async publishDiscovery(draft: DiscoveryDraft): Promise<SystemRecordAdmitResult> {
    const terms = await this.requireActiveTerms(draft.collaboration_terms_ref);
    const body: Record<string, unknown> = {
      schema_version: "ioi.applications.ioi-ai.orchestration-discovery.v1",
      discovery_id: draft.discovery_id,
      orchestration_ref: this.orchestration.scope_ref,
      publication_version: draft.publication_version,
      published_by_ref: this.host.signer_ref,
      public_goal_ref: draft.public_goal_ref,
      public_objective: draft.public_objective,
      public_category_refs: draft.public_category_refs,
      coordination_topology: draft.coordination_topology,
      admission_owner_ref: draft.admission_owner_ref,
      participation_channel_ref: draft.participation_channel_ref,
      collaboration_terms_ref: draft.collaboration_terms_ref,
      collaboration_terms_root: terms.terms_body_root,
      semantic_and_action_profile_refs: draft.semantic_and_action_profile_refs ?? [],
      required_capability_and_worker_profile_refs: draft.required_capability_and_worker_profile_refs ?? [],
      eligibility_and_affiliation_policy_refs: draft.eligibility_and_affiliation_policy_refs ?? [],
      visibility_and_privacy_policy_refs: draft.visibility_and_privacy_policy_refs ?? [],
      public_frontier_and_context_projection_refs: draft.public_frontier_and_context_projection_refs ?? [],
      budget_quote_and_capacity_refs: draft.budget_quote_and_capacity_refs ?? [],
      verifier_and_acceptance_posture_refs: draft.verifier_and_acceptance_posture_refs ?? [],
      settlement_dispute_and_contribution_policy_refs: draft.settlement_dispute_and_contribution_policy_refs ?? [],
      license_retention_and_export_policy_refs: draft.license_retention_and_export_policy_refs ?? [],
      excluded_context_classes: [...DISCOVERY_EXCLUDED_CONTEXT_CLASSES],
      private_context_included: false,
      published_at: draft.published_at ?? this.now(),
      updated_at: null,
      valid_until: draft.valid_until ?? null,
      status: "discoverable",
    };
    const discovery_state_root = deriveDiscoveryStateRoot(body);
    const record = { ...body, discovery_state_root, signature: signMaterialHash(this.host, discovery_state_root) };
    return this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.discovery, object_id: draft.discovery_id, record, expected_head: null });
  }

  async discovery(discoveryId: string): Promise<SystemRecordChainResult> {
    return this.orchestration.recordChain(COLLABORATION_CONTRACTS.discovery, discoveryId);
  }

  // -- participation (ACC-13 clause 3, N1) ---------------------------------------------------------

  /**
   * The host admits an external party's signed request. The signature is verified against the key
   * that party ACCEPTED THE TERMS with — the only key of record — never against the key the request
   * declares for itself. A request from inside the host's own system_id is refused: work inside the
   * System is a delegation, not a crossing.
   */
  async admitParticipation(request: ParticipationRequestRecord): Promise<SystemRecordAdmitResult> {
    const systemId = this.orchestration.system_id;
    if (request.requester_system_ref === systemId || request.requested_by_ref === systemId) {
      throw new CollaborationRefusal("same_system_participation_refused", "no AIIP path is used inside one system_id; delegate a subagent of the coordinating thread instead", { requester_system_ref: request.requester_system_ref, system_id: systemId });
    }
    if (request.orchestration_ref !== this.orchestration.scope_ref) {
      throw new CollaborationRefusal("participation_orchestration_mismatch", "the request names another orchestration", { named: request.orchestration_ref, this: this.orchestration.scope_ref });
    }
    if (request.status !== "submitted" || request.decision !== null || request.exit !== null) {
      throw new CollaborationRefusal("participation_not_a_submission", "a request is admitted as submitted with no decision and no exit; both are the host's revisions");
    }
    if (request.coordination_topology === "hosted_admission" && request.admission_owner_ref !== systemId) {
      throw new CollaborationRefusal("hosted_admission_owner_not_the_host", "under hosted_admission the admission owner is the host System itself", { admission_owner_ref: request.admission_owner_ref, system_id: systemId });
    }
    if (request.coordination_topology === "federated_admission" && !request.admission_owner_ref.startsWith("policy://")) {
      throw new CollaborationRefusal("federated_admission_owner_not_a_policy", "under federated_admission the admission owner is the declared federation policy path", { admission_owner_ref: request.admission_owner_ref });
    }
    const terms = await this.requireActiveTerms(request.collaboration_terms_ref, request.collaboration_terms_root);
    const acceptance = terms.acceptances.find((a) => a.party_ref === request.requested_by_ref);
    if (!acceptance) {
      throw new CollaborationRefusal("participation_signer_unknown", `${request.requested_by_ref} has no acceptance on the active terms, so no key of record`, { required_party_refs: terms.required_party_refs });
    }
    const expectedHash = deriveParticipationRequestHash(request as unknown as Record<string, unknown>);
    if (request.request_hash !== expectedHash) {
      throw new CollaborationRefusal("participation_request_hash_mismatch", "the request body does not recompute to its hash", { declared: request.request_hash, recomputed: expectedHash });
    }
    if (request.signature.signer_ref !== request.requested_by_ref || !verifySignatureEnvelope(request.signature, expectedHash, acceptance.signature.signer_public_key)) {
      throw new CollaborationRefusal("participation_signature_invalid", "the request is not signed by the requesting party's key of record over its hash");
    }
    const discovery = await this.discovery(request.discovery_ref);
    const published = stripBinding(discovery.current);
    if (!published || published.status !== "discoverable" || published.collaboration_terms_root !== terms.terms_body_root) {
      throw new CollaborationRefusal("discovery_not_discoverable", "the request answers no discoverable projection of this orchestration under the active terms", { status: published?.status ?? null });
    }
    if (published.coordination_topology !== request.coordination_topology || published.admission_owner_ref !== request.admission_owner_ref) {
      throw new CollaborationRefusal("participation_mode_mismatch", "the request's topology and admission owner are the projection's declared mode, never the requester's choice", { declared: { topology: published.coordination_topology, owner: published.admission_owner_ref }, requested: { topology: request.coordination_topology, owner: request.admission_owner_ref } });
    }
    return this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.participation, object_id: request.participation_request_id, record: request as unknown as Record<string, unknown>, expected_head: null });
  }

  async participation(requestId: string): Promise<SystemRecordChainResult> {
    return this.orchestration.recordChain(COLLABORATION_CONTRACTS.participation, requestId);
  }

  /**
   * The decision is a successor revision citing the seam receipt of the submission it answers, made
   * by the admission owner the projection declared. Under `federated_admission` the owner is a policy
   * path and the decision is CO-SIGNED by the adjudicator: a party of the active terms with role
   * `coordinator`, signing with the key it accepted the terms with. A hosted decision takes no
   * adjudicator; a federated one is unreachable without one, and without terms acceptance.
   */
  async decideParticipation(requestId: string, decision: { accept: boolean; reason_code: string; adjudicator?: Signer }): Promise<SystemRecordAdmitResult> {
    const chain = await this.participation(requestId);
    const current = stripBinding(chain.current) as ParticipationRequestRecord | null;
    if (!current) throw new CollaborationRefusal("participation_absent", `no participation record ${requestId}`);
    if (current.status !== "submitted" || current.decision !== null) {
      throw new CollaborationRefusal("participation_already_decided", `${requestId} is ${current.status}`);
    }
    const submission = (chain.admissions ?? [])[0];
    const receipt = typeof submission?.receipt_ref === "string" ? submission.receipt_ref : null;
    if (!receipt) throw new CollaborationRefusal("participation_receipt_unknown", "the submission's seam receipt is not on the chain");
    const status = decision.accept ? "accepted" : "refused";
    const decided_at = this.now();
    let adjudicator_ref: string | null = null;
    let federation_signature: SignatureEnvelope | null = null;
    if (current.coordination_topology === "federated_admission") {
      if (!decision.adjudicator) {
        throw new CollaborationRefusal("federated_decision_requires_adjudicator", "under federated_admission the host does not decide alone: the declared adjudicator co-signs the decision", { admission_owner_ref: current.admission_owner_ref });
      }
      const terms = await this.requireActiveTerms(current.collaboration_terms_ref, current.collaboration_terms_root);
      const role = (terms.party_roles ?? []).find((r) => r.party_ref === decision.adjudicator?.signer_ref);
      const acceptance = terms.acceptances.find((a) => a.party_ref === decision.adjudicator?.signer_ref);
      if (!role || role.role !== "coordinator" || !acceptance) {
        throw new CollaborationRefusal("federation_adjudicator_not_a_party", "the adjudicator is a party of the active terms with role coordinator that accepted them; federated admission is unreachable without terms acceptance", { adjudicator_ref: decision.adjudicator.signer_ref });
      }
      if (acceptance.signature.signer_public_key !== decision.adjudicator.publicKeyHex) {
        throw new CollaborationRefusal("federation_adjudicator_key_mismatch", "the adjudicator signs with the key it accepted the terms with, and with no other");
      }
      adjudicator_ref = decision.adjudicator.signer_ref;
      federation_signature = signMaterialHash(decision.adjudicator, deriveParticipationDecisionMaterialHash({ participation_request_id: requestId, request_hash: current.request_hash, status, decided_at, admission_owner_ref: current.admission_owner_ref }));
    } else if (decision.adjudicator) {
      throw new CollaborationRefusal("hosted_decision_takes_no_adjudicator", "under hosted_admission the host System decides; there is no adjudicator to co-sign");
    }
    const next: ParticipationRequestRecord = {
      ...current,
      status,
      decision: { status, decided_by_ref: current.admission_owner_ref, decided_at, receipt_ref: receipt, reason_code: decision.reason_code, adjudicator_ref, federation_signature },
    };
    return this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.participation, object_id: requestId, record: next as unknown as Record<string, unknown>, expected_head: chain.head });
  }

  /**
   * Portable exit (ACC-13 clause 6): the state bundle is produced first, then the exit is a third
   * revision of the participation citing it and the receipt of the accepted revision it leaves
   * from. The status stays `accepted` — acceptance is history, the exit is a fact on top of it —
   * and nothing else moves: the orchestration continues.
   */
  async exitParticipation(requestId: string, input: { reason_code: string; bundle: Omit<BundleDraft, "participation_request_id" | "bundle_reason"> }): Promise<{ bundle: SystemRecordAdmitResult; excluded: BundleCandidateRef[]; exit: SystemRecordAdmitResult }> {
    const before = await this.participation(requestId);
    const current = stripBinding(before.current) as ParticipationRequestRecord | null;
    if (!current || current.status !== "accepted" || current.exit !== null) {
      throw new CollaborationRefusal("participation_not_accepted", "only an accepted participation exits; a submission is withdrawn and an exited one has left", { status: current?.status ?? null });
    }
    const acceptedRevision = (before.admissions ?? [])[before.admissions.length - 1];
    const receipt = typeof acceptedRevision?.receipt_ref === "string" ? acceptedRevision.receipt_ref : null;
    if (!receipt) throw new CollaborationRefusal("participation_receipt_unknown", "the accepted revision's seam receipt is not on the chain");
    const produced = await this.produceStateBundle({ ...input.bundle, participation_request_id: requestId, bundle_reason: "voluntary_retirement" });
    const bundleId = String(produced.admitted.record.participant_state_bundle_id);
    const next: ParticipationRequestRecord = {
      ...current,
      exit: { status_at_exit: "accepted", bundle_ref: bundleId, exited_at: this.now(), reason_code: input.reason_code, receipt_ref: receipt },
    };
    const exit = await this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.participation, object_id: requestId, record: next as unknown as Record<string, unknown>, expected_head: before.head });
    return { bundle: produced.admitted, excluded: produced.excluded, exit };
  }

  // -- the least-disclosing bundle (ACC-13 clause 3) ----------------------------------------------

  async produceStateBundle(draft: BundleDraft): Promise<{ admitted: SystemRecordAdmitResult; excluded: BundleCandidateRef[] }> {
    const chain = await this.participation(draft.participation_request_id);
    const participation = stripBinding(chain.current) as ParticipationRequestRecord | null;
    if (!participation || participation.status !== "accepted" || participation.exit !== null) {
      throw new CollaborationRefusal("participation_not_accepted", "a state bundle is produced for an accepted participation that has not left", { status: participation?.status ?? null, exited: participation?.exit !== null && participation?.exit !== undefined });
    }
    const excludedClasses = [...BUNDLE_EXCLUDED_CONTEXT_CLASSES];
    const slots = {} as Record<BundleRefSlot, string[]>;
    for (const slot of BUNDLE_REF_SLOTS) slots[slot] = [];
    const excluded: BundleCandidateRef[] = [];
    for (const candidate of draft.candidate_refs) {
      if (excludedClasses.includes(candidate.context_class as (typeof excludedClasses)[number])) excluded.push(candidate);
      else slots[candidate.slot].push(candidate.ref);
    }
    const body: Record<string, unknown> = {
      schema_version: "ioi.applications.ioi-ai.participant-state-bundle.v4",
      participant_state_bundle_id: draft.participant_state_bundle_id,
      orchestration_ref: this.orchestration.scope_ref,
      participation_ref: draft.participation_request_id,
      participant_and_home_domain_refs: draft.participant_and_home_domain_refs,
      coordination_topology: participation.coordination_topology,
      bundle_reason: draft.bundle_reason,
      source_admission_watermark_ref: draft.source_admission_watermark_ref,
      ...slots,
      excluded_context_classes: excludedClasses,
      revocation_effect: draft.revocation_effect ?? "none",
      bundle_artifact_ref: draft.bundle_artifact_ref,
      hosted_database_access_required: false,
      issued_at: draft.issued_at ?? this.now(),
      status: "exported",
    };
    const bundle_root = deriveBundleRoot(body);
    const record = { ...body, bundle_root, signature: signMaterialHash(this.host, bundle_root) };
    const admitted = await this.orchestration.record({ contract_id: COLLABORATION_CONTRACTS.bundle, object_id: draft.participant_state_bundle_id, record, expected_head: null });
    return { admitted, excluded };
  }

  async bundle(bundleId: string): Promise<SystemRecordChainResult> {
    return this.orchestration.recordChain(COLLABORATION_CONTRACTS.bundle, bundleId);
  }
}

/** The seam derives the binding on every admission; a revision never re-authors it. */
function stripBinding(record: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!record) return null;
  const { system_binding: _binding, ...rest } = record;
  return rest;
}
