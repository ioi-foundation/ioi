//! Room participation plane — build step 3, first pair (#74): `RoomParticipationRequest` +
//! `RoomParticipantLease` over the hosted OutcomeRoom aggregate (canonical owner:
//! docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md; envelopes:
//! common-objects-and-envelopes.md §RoomParticipationRequestEnvelope /
//! §RoomParticipantLeaseEnvelope). Participation is a LEASE, not ambient membership: a typed
//! admission request carries identity, affiliation, eligibility evidence, and requested scopes;
//! the hosted admission owner admits a bounded lease or rejects without granting context or
//! power. A lease record grants NOTHING by itself — context/authority/budget powers stay
//! declared refs to their own governed planes.
//!
//! Step-3 contract (honest scope):
//! - HOSTED admission only; `federated_admission`, AIIP signatures, and
//!   `room_discovery_ref` are named gaps (build steps 7-8) — declared, never faked.
//! - Request intake admits as `submitted` and grants nothing. Governed evaluate/reject/withdraw/
//!   admit operations resolve the accountable host/participant through wallet.network's versioned,
//!   revocable principal-authority binding contract. Every decision pins the complete signed grant,
//!   authority snapshot/hash, operation scope match, and immutable binding coordinates; missing or
//!   invalid resolver configuration refuses typed before mutation.
//! - Lease lifecycle machinery covers suspend/resume, sleep/wake, wait/activate,
//!   quarantine/release_quarantine, retire, revoke for already-admitted/replayed leases, but its
//!   online and boot decisions share the same full-tuple authority verification. `invited`/`joining` (invite flow),
//!   `retiring` (claim-release orchestration, arrives with WorkClaimLease), and `expire`
//!   (TTL/clock) are named gaps. Revocation ends FUTURE participation only: it appends the
//!   revocation receipt, never erases lineage.
//! - OutcomeRoom backlinks (`participation_request_refs`, `participant_lease_refs`) are bound
//!   EXCLUSIVELY through the room-owned `bind_room_backlink` seam (including its room-locked
//!   entrypoint for cross-plane transactions) — this plane never writes a room record.
//! - Every admitted mutation is an intent transaction on the shared durable core (#73). Ungated
//!   submit replay reconstructs the ONLY valid successor (record AND receipt) byte-exactly.
//!   Governed replay re-resolves the exact stored coordinates and byte-compares the full tuple;
//!   copied receipt fields alone never cross that boundary.
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::outcome_room_routes::{
    self as rooms, build_room_receipt_at, check_expected_revision, is_canonical_receipt_tail,
    is_rfc3339, record_output_hash, reject_sensitive_keys, s, str_opt_bounded, verr,
    vocab_required, VErr,
};
use super::{iso_now, DaemonState};

// ============================ CANONICAL REFERENCE GRAMMAR ========================================
// The room plane's `ref_scheme_ok` is `scheme://`-only; the participation envelopes use the
// RICHER canon grammar (#74 review finding 4): `scheme://tail` with EXACT canonical scheme names
// (underscores/hyphens as the envelope writes them), non-URI PREFIX forms (`harness_profile:`,
// `agent_harness_adapter:`, `prim:`), and — for `home_domain_ref` — the `agentgres://domain/…`
// path form. Aliasing hyphenated schemes (the earlier bug: canonical `model_route://` refused
// while noncanonical `model-route://` persisted) is replaced by validating the declared forms
// verbatim. Mirrors the WorkResult grammar.
const REF_MAX: usize = 300;
const LIST_MAX: usize = 64;

fn pref_ok(v: &str, schemes: &[&str], prefixes: &[&str]) -> bool {
    if prefixes
        .iter()
        .any(|p| v.starts_with(p) && v.len() > p.len())
    {
        return true;
    }
    match v.split_once("://") {
        Some((scheme, tail)) if !tail.is_empty() => schemes.contains(&scheme),
        _ => false,
    }
}

fn pscheme_err(key: &str, schemes: &[&str], prefixes: &[&str]) -> VErr {
    let mut allowed: Vec<String> = schemes.iter().map(|s| format!("{s}://")).collect();
    allowed.extend(prefixes.iter().map(|p| format!("{p}*")));
    verr("room_participation_ref_scheme_invalid", format!("`{key}` must be a canonical ref [{}] — a raw string or noncanonical alias is never a ref", allowed.join("|")))
}

fn preq(
    body: &Value,
    key: &str,
    schemes: &[&str],
    prefixes: &[&str],
    req_code: &str,
) -> Result<String, VErr> {
    match str_opt_bounded(body, key, REF_MAX)? {
        Some(v) if pref_ok(&v, schemes, prefixes) => Ok(v),
        Some(_) => Err(pscheme_err(key, schemes, prefixes)),
        None => Err(verr(
            req_code,
            format!("`{key}` is required (a canonical ref)"),
        )),
    }
}

fn pscalar(
    body: &Value,
    key: &str,
    schemes: &[&str],
    prefixes: &[&str],
) -> Result<Option<String>, VErr> {
    match str_opt_bounded(body, key, REF_MAX)? {
        None => Ok(None),
        Some(v) if pref_ok(&v, schemes, prefixes) => Ok(Some(v)),
        Some(_) => Err(pscheme_err(key, schemes, prefixes)),
    }
}

fn plist(
    body: &Value,
    key: &str,
    schemes: &[&str],
    prefixes: &[&str],
) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > LIST_MAX {
                return Err(verr(
                    "room_participation_field_too_long",
                    format!("`{key}` exceeds the bounded list length ({LIST_MAX})"),
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it.as_str() {
                    Some(t) if t.len() <= REF_MAX && pref_ok(t, schemes, prefixes) => {
                        out.push(t.to_string())
                    }
                    _ => return Err(pscheme_err(key, schemes, prefixes)),
                }
            }
            Ok(out)
        }
        Some(_) => Err(verr(
            "room_participation_field_type_invalid",
            format!("`{key}` must be an array of canonical refs"),
        )),
    }
}

/// `home_domain_ref` has one path-qualified form in canon: `agentgres://domain/<id>`.
/// Generic scheme validation is deliberately insufficient because `agentgres://artifact/...`
/// (or any other non-domain tail) names a different object class.
fn home_domain_ref_ok(value: &str) -> bool {
    pref_ok(value, &["domain", "system"], &[])
        || value
            .strip_prefix("agentgres://domain/")
            .is_some_and(|tail| !tail.is_empty())
}

fn home_domain_ref_required(body: &Value) -> Result<String, VErr> {
    match str_opt_bounded(body, "home_domain_ref", REF_MAX)? {
        Some(value) if home_domain_ref_ok(&value) => Ok(value),
        Some(_) => Err(verr(
            "room_participation_ref_scheme_invalid",
            "`home_domain_ref` must be domain://..., system://..., or the canonical path-qualified agentgres://domain/... ref",
        )),
        None => Err(verr(
            "participant_lease_home_domain_required",
            "`home_domain_ref` is required (domain://..., system://..., or agentgres://domain/...)",
        )),
    }
}

const REQUEST_SCHEMA: &str = "ioi.hypervisor.room-participation-request.v1";
const LEASE_SCHEMA: &str = "ioi.hypervisor.room-participant-lease.v1";
const REQUEST_RECEIPT_SCHEMA: &str = "ioi.hypervisor.room-participation-request-receipt.v1";
pub(crate) const REQUEST_DIR: &str = "room-participation-requests";
pub(crate) const LEASE_DIR: &str = "room-participant-leases";
const RECEIPT_DIR: &str = "room-participation-receipts";
const SUBMIT_INTENT_DIR: &str = "room-participation-submit-intents";

// Receipt assurance notes — shared by finalizers AND replay validators, so a reconstructed
// receipt is byte-identical to the finalized one.
const SUBMIT_NOTE: &str = "admission of a typed participation request — a receipt is not eligibility, admission, or authority; the hosted owner's decision is its own receipted transition";
const REQUEST_TRANSITION_NOTE: &str = "an admitted participation-request transition — receipted, optimistically concurrent, and honest about being admission (not verification)";
const ADMIT_NOTE: &str = "an admitted participation decision — the request's terminal admission and the bounded participant lease land in one crash-convergent finalization; the lease grants nothing beyond its own declared refs";
const LEASE_TRANSITION_NOTE: &str = "an admitted participant-lease transition — receipted, optimistically concurrent; revocation ends FUTURE participation and never erases contribution lineage";
const DECISION_RECEIPT_SCHEMA: &str = "ioi.hypervisor.room-participation-decision-receipt.v1";

// ================================ DECISION AUTHORITY (#74 review finding 1) ======================
// Hosted participation DECISIONS are governed operations, not open daemon endpoints. Comparing a
// caller-supplied `admission_owner_ref` to the room host is NOT authorization; nor is verifying a
// grant's signature and DAEMON-DERIVED policy/request hashes. A trusted resolver must also bind
// the required host/participant identity to the grant signer. The production wallet.network
// resolver supplies the complete frozen authority snapshot, operation scope match, and immutable
// binding coordinates; this plane verifies and retains that whole tuple. Authority is split by operation:
//   - HOST-bound (the room's host domain must authorize): request evaluate/reject, admit, and
//     the administrative lease transitions suspend/resume/quarantine/release_quarantine/revoke.
//   - PARTICIPANT-bound (the record's own principal must authorize): request withdraw and the
//     self-state lease transitions sleep/wake/wait/activate/retire.
// The request hash binds the exact {subject, op, revision, required authority}; without a valid
// resolver result no decision receipt is emitted and every governed operation refuses with ZERO mutation.
#[cfg(test)]
use ioi_types::app::{
    ApprovalAuthority, ApprovalGrant, PrincipalAuthorityBindingCoordinates,
    PrincipalAuthorityKind, PrincipalAuthorityResolutionV1,
};
use super::governed_authority::{self as governed, AuthorityContract, Governance};

const ROOM_AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "room_participation",
    policy_domain: "hypervisor.room-participation.decision.policy.v1",
    request_domain: "hypervisor.room-participation.decision.request.v1",
    resolution_domain: "hypervisor.room-participation.authority-resolution.v1",
    code_prefix: "room_participation",
    host_label: "host_admission",
    participant_label: "participant_self",
};

/// Governance class of a gated operation.
#[derive(Clone, Copy, PartialEq)]
enum Gov {
    Host,
    Participant,
}
impl From<Gov> for Governance {
    fn from(value: Gov) -> Self {
        match value {
            Gov::Host => Governance::Host,
            Gov::Participant => Governance::Participant,
        }
    }
}

fn decision_authority_posture() -> Value {
    governed::decision_authority_posture(ROOM_AUTHORITY)
}

/// Request lifecycle governance: withdraw is the participant's own; evaluate/reject are the host's.
fn request_op_gov(op: &str) -> Gov {
    match op {
        "withdraw" => Gov::Participant,
        _ => Gov::Host,
    }
}
/// Lease lifecycle governance: self-state is the participant's; discipline is the host's.
fn lease_op_gov(op: &str) -> Gov {
    match op {
        "sleep" | "wake" | "wait" | "activate" | "retire" => Gov::Participant,
        _ => Gov::Host,
    }
}

fn decision_policy_hash(gov: Gov, room_ref: &str, required_authority: &str, op: &str) -> String {
    governed::decision_policy_hash(
        ROOM_AUTHORITY,
        gov.into(),
        room_ref,
        required_authority,
        op,
    )
}
fn decision_request_hash(
    gov: Gov,
    subject_ref: &str,
    op: &str,
    revision: u64,
    required_authority: &str,
) -> String {
    governed::decision_request_hash(
        ROOM_AUTHORITY,
        gov.into(),
        subject_ref,
        op,
        revision,
        required_authority,
    )
}

/// The proven authority for one gated decision — sealed into the receipt so a replay reconstructs
/// it byte-exactly.
#[derive(Clone, Debug, PartialEq)]
struct DecisionAuthority {
    acting_authority_id: Value,
    grant_ref: String,
    policy_hash: String,
    request_hash: String,
    wallet_approval_grant: Value,
    authority_binding: Value,
}

type VerifiedAuthorityResolution = governed::VerifiedAuthorityResolution;

/// Verify a wallet grant against the daemon-derived policy/request hashes AND the complete frozen
/// authority snapshot obtained from wallet.network. Kept separate so foreign-signer and snapshot
/// mismatch refusal remain directly testable without a network fixture.
#[allow(clippy::too_many_arguments)]
fn authorize_decision_for_resolution(
    body: &Value,
    gov: Gov,
    room_ref: &str,
    required_authority: &str,
    verified_resolution: &VerifiedAuthorityResolution,
    subject_ref: &str,
    op: &str,
    revision: u64,
) -> Result<DecisionAuthority, (StatusCode, Json<Value>)> {
    governed::authorize_decision_for_resolution(
        ROOM_AUTHORITY,
        body,
        gov.into(),
        room_ref,
        required_authority,
        verified_resolution,
        subject_ref,
        op,
        revision,
    )
    .map(|authorized| DecisionAuthority {
        acting_authority_id: authorized.evidence.acting_authority_id,
        grant_ref: authorized.evidence.grant_ref,
        policy_hash: authorized.evidence.policy_hash,
        request_hash: authorized.evidence.request_hash,
        wallet_approval_grant: authorized.evidence.wallet_approval_grant,
        authority_binding: authorized.evidence.authority_binding,
    })
}

/// Resolve the required identity binding before considering any grant. Resolver absence/refusal
/// is typed with ZERO mutation. The hashes remain in every challenge so an external wallet can
/// sign exactly what the daemon derived.
#[allow(clippy::too_many_arguments)]
async fn authorize_decision(
    body: &Value,
    gov: Gov,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
) -> Result<DecisionAuthority, (StatusCode, Json<Value>)> {
    governed::authorize_decision(
        ROOM_AUTHORITY,
        body,
        gov.into(),
        room_ref,
        required_authority,
        subject_ref,
        op,
        revision,
    )
    .await
    .map(|authorized| DecisionAuthority {
        acting_authority_id: authorized.evidence.acting_authority_id,
        grant_ref: authorized.evidence.grant_ref,
        policy_hash: authorized.evidence.policy_hash,
        request_hash: authorized.evidence.request_hash,
        wallet_approval_grant: authorized.evidence.wallet_approval_grant,
        authority_binding: authorized.evidence.authority_binding,
    })
}

/// Build a decision receipt: the portable base + the sealed authority binding (actor = the
/// acting authority, `authority_grant_id` = the verified grant ref, `policy_hash` and
/// `input_hash` = the daemon-derived decision hashes). Finalizers AND replay validators call
/// THIS, so a reconstructed decision receipt is byte-identical.
#[allow(clippy::too_many_arguments)]
fn build_decision_receipt(
    id_tail: &str,
    receipt_type: &str,
    subject_ref: &str,
    op: &str,
    bound_facts: Value,
    boundary_refs: Vec<Value>,
    output_hash: String,
    excludes: &[&str],
    note: &str,
    now: &str,
    auth: &DecisionAuthority,
) -> Value {
    let mut r = build_room_receipt_at(
        id_tail,
        DECISION_RECEIPT_SCHEMA,
        receipt_type,
        subject_ref,
        op,
        bound_facts,
        boundary_refs,
        output_hash,
        excludes,
        "admitted_not_verified",
        note,
        now,
    );
    if let Some(obj) = r.as_object_mut() {
        obj.insert("actor_id".into(), auth.acting_authority_id.clone());
        obj.insert("authority_grant_id".into(), json!(auth.grant_ref));
        obj.insert("policy_hash".into(), json!(auth.policy_hash));
        obj.insert("input_hash".into(), json!(auth.request_hash));
        obj.insert(
            "wallet_approval_grant".into(),
            auth.wallet_approval_grant.clone(),
        );
        obj.insert(
            "principal_authority_binding".into(),
            auth.authority_binding.clone(),
        );
    }
    r
}

/// Recover receipt fields for STRUCTURAL byte-exact reconstruction only. These copied fields are
/// not authority: without the original signed grant plus a trusted expected-signer resolution,
/// they must never authorize boot replay.
#[allow(dead_code)]
fn sealed_authority(receipt: &Value) -> DecisionAuthority {
    DecisionAuthority {
        acting_authority_id: receipt.get("actor_id").cloned().unwrap_or(Value::Null),
        grant_ref: receipt
            .get("authority_grant_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        policy_hash: receipt
            .get("policy_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        request_hash: receipt
            .get("input_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        wallet_approval_grant: receipt
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
        authority_binding: receipt
            .get("principal_authority_binding")
            .cloned()
            .unwrap_or(Value::Null),
    }
}

async fn reauthorize_sealed_receipt(
    receipt: &Value,
    gov: Gov,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    revision: u64,
) -> Result<(), String> {
    governed::reauthorize_sealed_receipt(
        ROOM_AUTHORITY,
        receipt,
        gov.into(),
        room_ref,
        required_authority,
        subject_ref,
        op,
        revision,
    )
    .await
}

/// Canonical vocabularies (envelopes, verbatim).
const REQUEST_STATUSES: &[&str] = &[
    "draft",
    "submitted",
    "evaluating",
    "admitted",
    "rejected",
    "withdrawn",
    "expired",
];
const LEASE_STATUSES: &[&str] = &[
    "invited",
    "joining",
    "active",
    "sleeping",
    "waiting",
    "suspended",
    "quarantined",
    "retiring",
    "retired",
    "revoked",
];
const ADMITTED_ROLES: &[&str] = &[
    "conductor",
    "implementer",
    "reviewer",
    "verifier",
    "operator",
    "researcher",
    "specialist",
    "synthesizer",
    "resource_provider",
    "integrity_challenger",
    "memory_curator",
];
/// Request lifecycle: name → (allowed from-statuses, to-status). `admit` is NOT here — it mints
/// a lease and runs through its own endpoint + finalization.
const REQUEST_TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("evaluate", &["submitted"], "evaluating"),
    ("reject", &["submitted", "evaluating"], "rejected"),
    ("withdraw", &["submitted", "evaluating"], "withdrawn"),
];
const UNAVAILABLE_REQUEST_TRANSITIONS: &[(&str, &str)] = &[
    (
        "expire",
        "TTL/clock authority (a later build step) — expiry is never faked by a wall-clock guess",
    ),
    (
        "admit",
        "the admit endpoint (it mints the participant lease in one finalization)",
    ),
];
/// Lease lifecycle: name → (allowed from-statuses, to-status). Terminal: retired, revoked.
const LEASE_TRANSITIONS: &[(&str, &[&str], &str)] = &[
    ("suspend", &["active", "sleeping", "waiting"], "suspended"),
    ("resume", &["suspended"], "active"),
    ("sleep", &["active", "waiting"], "sleeping"),
    ("wake", &["sleeping"], "active"),
    ("wait", &["active"], "waiting"),
    ("activate", &["waiting"], "active"),
    (
        "quarantine",
        &["active", "sleeping", "waiting", "suspended"],
        "quarantined",
    ),
    ("release_quarantine", &["quarantined"], "active"),
    (
        "retire",
        &["active", "sleeping", "waiting", "suspended"],
        "retired",
    ),
    (
        "revoke",
        &["active", "sleeping", "waiting", "suspended", "quarantined"],
        "revoked",
    ),
];
const UNAVAILABLE_LEASE_TRANSITIONS: &[(&str, &str)] = &[
    ("invite", "the invite flow (invited/joining statuses) — a later leg of this plane"),
    ("join", "the invite flow (invited/joining statuses) — a later leg of this plane"),
    ("begin_retirement", "claim-release orchestration (`retiring`) — arrives with WorkClaimLease (build step 3, #76)"),
    ("expire", "TTL/clock authority (a later build step) — expiry is never faked by a wall-clock guess"),
];

/// CREATION hash scope: the admission receipt binds the DECLARED shape — plane-owned mutable
/// fields are excluded so later receipted transitions never invalidate it.
const REQUEST_CREATE_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "updated_at",
    "revision",
    "status",
    "status_history",
    "admission_and_replay_refs",
    "admission_decision_ref",
    "participant_lease_ref",
    "request_hash",
];
const LEASE_CREATE_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "updated_at",
    "revision",
    "status",
    "status_history",
    "admission_and_replay_refs",
    "future_access_revocation_refs",
    "exit_and_claim_release_refs",
];
/// TRANSITION hash scope: the receipt hashes the transition's OUTPUT — only the circular
/// receipt-bearing fields are excluded.
const TRAIL_EXCLUDES: &[&str] = &[
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "status_history",
];

const HISTORY_MAX: usize = 100;

/// Serializes every PARTICIPATION-scope critical section. LOCK ORDERING (fixed, documented):
/// PARTICIPATION_LOCK is acquired BEFORE the room plane's ROOM_MUTATION_LOCK; callers either hold
/// both across a cross-plane finalizer or use the room-owned locking seam after taking this lock.
/// No path ever takes them in the reverse order, and no .await runs under either lock.
pub(crate) static PARTICIPATION_LOCK: Mutex<()> = Mutex::new(());

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn is_canonical_request_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "rpr")
}
fn is_canonical_lease_tail(tail: &str) -> bool {
    is_canonical_receipt_tail(tail, "rpl")
}

// ================================ STRICT STORAGE ACCESS ==========================================

/// Persist a MUTABLE plane record through the shared typed durable writer (#73).
fn persist_atomic(
    data_dir: &str,
    family: &str,
    record_id: &str,
    record: &Value,
) -> Result<(), super::durable_fs::PersistFailure> {
    super::durable_fs::persist_record_durable(data_dir, family, record_id, record)
}

/// The shared no-clobber receipt commit mapped onto this plane's wire codes.
fn persist_receipt(data_dir: &str, tail: &str, receipt: &Value) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure;
    super::durable_fs::persist_receipt_no_clobber(data_dir, RECEIPT_DIR, tail, receipt).map_err(
        |f| match f {
            CommitFailure::KeyInvalid(m) => verr("room_participation_receipt_key_invalid", m),
            CommitFailure::NotCommitted(m) => verr("room_participation_receipt_persist_failed", m),
            CommitFailure::SlotUnreadable(m) => {
                verr("room_participation_receipt_slot_unreadable", m)
            }
            CommitFailure::Conflict(m) => verr("room_participation_receipt_conflict", m),
            CommitFailure::DurabilityUnconfirmed(m) => {
                verr("room_participation_receipt_durability_unconfirmed", m)
            }
            CommitFailure::Swapped(m) => verr("room_participation_receipt_swapped", m),
        },
    )
}

/// Strict slot read keyed by a CANONICAL stem (validated BEFORE any filesystem access), through
/// the shared pinned no-follow primitives. Ok(None) = definitively absent; Err = unreadable /
/// non-JSON occupant. Callers must preserve the distinction between definitive absence and an
/// occupied-but-unreadable slot; uncertainty is never mapped to not-found.
fn read_slot_strict(
    data_dir: &str,
    family: &str,
    stem: &str,
    canonical: fn(&str) -> bool,
) -> Result<Option<Value>, String> {
    if !canonical(stem) {
        return Err(format!(
            "non-canonical stem '{stem}' — refused before any filesystem access"
        ));
    }
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("family '{family}' unavailable ({e})")),
    };
    match super::durable_fs::read_slot_strict(&dir, &format!("{stem}.json")) {
        Ok(None) => Ok(None),
        Ok(Some((_f, bytes))) => serde_json::from_slice::<Value>(&bytes)
            .map(Some)
            .map_err(|e| format!("slot '{stem}' holds non-JSON content ({e})")),
        Err(e) => Err(format!(
            "slot '{stem}' is occupied but not readable as a regular file ({e})"
        )),
    }
}

/// Scan a plane family as (canonical-stem, value) pairs through the pinned fd (#72 round 21
/// finding 3 discipline): a scan failure is a TYPED error, never a false-empty registry; the
/// file STEM is the trusted storage key and content identity must agree with it.
fn scan_family(
    data_dir: &str,
    family: &str,
    id_field: &str,
    id_prefix: &str,
    canonical: fn(&str) -> bool,
) -> Result<Vec<(String, Value)>, String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("family '{family}' directory could not be pinned ({e}) — refusing to report a false-empty registry")),
    };
    let names = super::durable_fs::enumerate_pinned(&dir).map_err(|e| format!("family '{family}' could not be enumerated ({e}) — refusing to report a false-empty registry"))?;
    scan_family_entries(&dir, names, family, id_field, id_prefix, canonical)
}

/// The read half of `scan_family`, split so the vanished-after-enumeration contract can be
/// exercised deterministically while retaining the same pinned directory descriptor in
/// production and tests.
fn scan_family_entries(
    dir: &std::fs::File,
    names: Vec<String>,
    family: &str,
    id_field: &str,
    id_prefix: &str,
    canonical: fn(&str) -> bool,
) -> Result<Vec<(String, Value)>, String> {
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical(stem) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&dir, &name) {
            Ok(Some((_f, bytes))) => bytes,
            Ok(None) => {
                return Err(format!(
                    "canonical slot '{name}' vanished after enumeration — refusing to report a false-empty registry"
                ))
            }
            Err(e) => {
                return Err(format!(
                    "canonical slot '{name}' is not readable as a regular file ({e}) — refusing to report a false-empty registry"
                ))
            }
        };
        let value = serde_json::from_slice::<Value>(&bytes).map_err(|e| {
            format!(
                "canonical slot '{name}' holds malformed JSON ({e}) — refusing to report a false-empty registry"
            )
        })?;
        let expected_id = format!("{id_prefix}{stem}");
        if value.get(id_field).and_then(Value::as_str) != Some(expected_id.as_str()) {
            return Err(format!(
                "canonical slot '{name}' has an identity that does not match its storage key — refusing to report a false-empty registry"
            ));
        }
        validate_registry_record(family, stem, &value).map_err(|why| {
            format!(
                "canonical slot '{name}' is malformed ({why}) — refusing to report a false-empty registry"
            )
        })?;
        out.push((stem.to_string(), value));
    }
    Ok(out)
}

/// Storage-level canonical validation for records discovered under a canonical filename. This is
/// deliberately narrower than authorization: it proves that registry state has a typed envelope,
/// canonical identity/status, and (when present) a deterministically sealed transaction intent.
fn validate_registry_record(family: &str, tail: &str, record: &Value) -> Result<(), String> {
    if !record.is_object() {
        return Err("record is not a JSON object".into());
    }
    let (schema, statuses, id_field, expected_id) = if family == REQUEST_DIR {
        (
            REQUEST_SCHEMA,
            REQUEST_STATUSES,
            "participation_request_id",
            format!("participation-request://{tail}"),
        )
    } else if family == LEASE_DIR {
        (
            LEASE_SCHEMA,
            LEASE_STATUSES,
            "participant_lease_id",
            format!("participant-lease://{tail}"),
        )
    } else {
        return Ok(());
    };
    if record.get("schema_version").and_then(Value::as_str) != Some(schema) {
        return Err("schema_version is absent or noncanonical".into());
    }
    if record.get(id_field).and_then(Value::as_str) != Some(expected_id.as_str()) {
        return Err("record identity does not bind to the storage key".into());
    }
    let status = record.get("status").and_then(Value::as_str).unwrap_or("");
    if !statuses.contains(&status) {
        return Err("status is absent or outside the canonical vocabulary".into());
    }
    if record.get("revision").and_then(Value::as_u64).is_none() {
        return Err("revision is absent or not an unsigned integer".into());
    }
    if !record
        .get("outcome_room_ref")
        .and_then(Value::as_str)
        .is_some_and(|value| pref_ok(value, &["outcome-room"], &[]))
    {
        return Err("outcome_room_ref is absent or noncanonical".into());
    }

    if family == REQUEST_DIR {
        if !record
            .get("requested_by_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| pref_ok(value, &["worker", "service", "org", "domain"], &[]))
        {
            return Err("requested_by_ref is absent or noncanonical".into());
        }
        if status == "admitted"
            && !record
                .get("participant_lease_ref")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("participant-lease://"))
                .is_some_and(is_canonical_lease_tail)
        {
            return Err("admitted request has no canonical participant_lease_ref".into());
        }
        if record.get("admit_intent").is_some() && record.get("transition_intent").is_some() {
            return Err("request carries two pending intents".into());
        }
        if let Some(intent) = record.get("admit_intent") {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("admit_intent");
            validate_admit_intent(intent, &prior, tail)
                .map_err(|why| format!("admit_intent is not canonical: {why}"))?;
        } else if let Some(intent) = record.get("transition_intent") {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("transition_intent");
            validate_transition_intent(
                intent,
                &prior,
                tail,
                "participation_request_id",
                "participation-request://",
                REQUEST_TRANSITIONS,
                "rqt",
                REQUEST_TRANSITION_NOTE,
                is_canonical_request_tail,
            )
            .map_err(|why| format!("transition_intent is not canonical: {why}"))?;
        }
    } else {
        if !record
            .get("participant_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| pref_ok(value, &["worker", "service", "org", "domain"], &[]))
        {
            return Err("participant_ref is absent or noncanonical".into());
        }
        if !record
            .get("join_request_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| pref_ok(value, &["participation-request"], &[]))
        {
            return Err("join_request_ref is absent or noncanonical".into());
        }
        if let Some(intent) = record.get("transition_intent") {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("transition_intent");
            validate_transition_intent(
                intent,
                &prior,
                tail,
                "participant_lease_id",
                "participant-lease://",
                LEASE_TRANSITIONS,
                "rlt",
                LEASE_TRANSITION_NOTE,
                is_canonical_lease_tail,
            )
            .map_err(|why| format!("transition_intent is not canonical: {why}"))?;
        }
    }
    Ok(())
}

fn load_request(data_dir: &str, tail: &str) -> Result<Option<Value>, String> {
    let id = format!("participation-request://{tail}");
    match read_slot_strict(data_dir, REQUEST_DIR, tail, is_canonical_request_tail)? {
        None => Ok(None),
        Some(record)
            if record
                .get("participation_request_id")
                .and_then(Value::as_str)
                == Some(id.as_str()) =>
        {
            validate_registry_record(REQUEST_DIR, tail, &record)?;
            Ok(Some(record))
        }
        Some(_) => Err(format!(
            "request slot '{tail}' has an identity that does not match its storage key"
        )),
    }
}

fn load_lease(data_dir: &str, tail: &str) -> Result<Option<Value>, String> {
    let id = format!("participant-lease://{tail}");
    match read_slot_strict(data_dir, LEASE_DIR, tail, is_canonical_lease_tail)? {
        None => Ok(None),
        Some(record)
            if record.get("participant_lease_id").and_then(Value::as_str) == Some(id.as_str()) =>
        {
            validate_registry_record(LEASE_DIR, tail, &record)?;
            Ok(Some(record))
        }
        Some(_) => Err(format!(
            "lease slot '{tail}' has an identity that does not match its storage key"
        )),
    }
}

/// Strict participant-lease resolver for later room object planes. The participant plane owns
/// both the storage-key check and the envelope validation; callers never read lease files
/// directly. `Ok(None)` means definitively absent, while unreadable/mismatched state is `Err`.
pub(crate) fn resolve_participant_lease_strict(
    data_dir: &str,
    lease_ref: &str,
) -> Result<Option<Value>, String> {
    let tail = lease_ref
        .strip_prefix("participant-lease://")
        .ok_or_else(|| "participant lease ref must be participant-lease://rpl_<hex>".to_string())?;
    load_lease(data_dir, tail)
}

/// Construct the only participant-owned current-claim successor. The claim plane may coordinate
/// the transaction, but it never authors participant bytes itself. Binding requires an active
/// lease with no current claim; release requires the exact current claim and preserves lineage.
pub(crate) fn participant_current_claim_successor(
    prior: &Value,
    claim_ref: &str,
    receipt_ref: &str,
    now: &str,
    bind: bool,
) -> Result<Value, VErr> {
    if !claim_ref
        .strip_prefix("work-claim://wcl_")
        .is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
        })
    {
        return Err(verr(
            "participant_lease_current_claim_ref_invalid",
            "current claim must be canonical work-claim://wcl_<64 lowercase hex>",
        ));
    }
    if pending_intent(prior).is_some() {
        return Err(verr(
            "participant_lease_mutation_in_flight",
            "the participant lease carries a pending participation intent",
        ));
    }
    let current = prior
        .get("current_claim_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    if bind {
        if s(prior, "status", "") != "active" {
            return Err(verr(
                "participant_lease_not_active",
                "only an active participant lease may bind a current work claim",
            ));
        }
        if !current.is_empty() {
            return Err(verr(
                "participant_lease_current_claim_conflict",
                format!("participant already holds current claim '{current}'"),
            ));
        }
    } else if current != claim_ref {
        return Err(verr(
            "participant_lease_current_claim_mismatch",
            format!("participant current claim is '{current}', not '{claim_ref}'"),
        ));
    }
    let mut final_lease = prior.clone();
    let prior_revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Some(object) = final_lease.as_object_mut() {
        object.insert(
            "current_claim_ref".into(),
            if bind { json!(claim_ref) } else { Value::Null },
        );
        object.insert("revision".into(), json!(prior_revision + 1));
        object.insert("updated_at".into(), json!(now));
        let mut trail = object
            .get("admission_and_replay_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        trail.push(json!(receipt_ref));
        object.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let op = if bind { "bind_current_claim" } else { "release_current_claim" };
        let mut history = object
            .get("status_history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        history.push(json!({
            "op": op,
            "at": now,
            "receipt_ref": receipt_ref,
            "revision": prior_revision + 1,
            "work_claim_ref": claim_ref,
        }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        object.insert("status_history".into(), Value::Array(history));
        if !bind {
            let mut releases = object
                .get("exit_and_claim_release_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            releases.push(json!(receipt_ref));
            object.insert("exit_and_claim_release_refs".into(), Value::Array(releases));
        }
    }
    Ok(final_lease)
}

/// Persist an exact participant-owned current-claim successor while the caller holds
/// `PARTICIPATION_LOCK`. Existing final bytes are idempotent; any foreign successor refuses.
pub(crate) fn persist_participant_claim_successor_locked(
    data_dir: &str,
    lease_ref: &str,
    prior: &Value,
    final_lease: &Value,
) -> Result<(), VErr> {
    let tail = lease_ref
        .strip_prefix("participant-lease://")
        .ok_or_else(|| verr("participant_lease_ref_invalid", "lease ref must be canonical"))?;
    let current = load_lease(data_dir, tail)
        .map_err(|message| verr("participant_lease_registry_unreadable", message))?
        .ok_or_else(|| verr("participant_lease_not_found", format!("no participant lease '{lease_ref}'")))?;
    if current == *final_lease {
        return Ok(());
    }
    if current != *prior {
        return Err(verr(
            "participant_lease_current_claim_conflict",
            "participant lease no longer equals the sealed prior or successor",
        ));
    }
    persist_atomic(data_dir, LEASE_DIR, tail, final_lease).map_err(|failure| {
        if failure.visible() {
            verr(
                "participant_lease_claim_stamp_pending_convergence",
                failure.detail(),
            )
        } else {
            verr("participant_lease_claim_stamp_persist_failed", failure.detail())
        }
    })
}

/// Which durable intent (if any) is pending on a plane record — EVERY mutator refuses while one
/// is in flight. Governed intents are quarantined until replay has verifiable identity-bound
/// authority; they are never auto-applied from sealed receipt fields.
fn pending_intent(record: &Value) -> Option<(&'static str, &'static str)> {
    if record.get("admit_intent").is_some() {
        return Some(("admit_intent", "room_participation_admit_in_flight"));
    }
    if record.get("transition_intent").is_some() {
        return Some((
            "transition_intent",
            "room_participation_transition_in_flight",
        ));
    }
    None
}

// ================================ DECLARATION VALIDATORS =========================================

/// Validate + canonicalize the participation-request DECLARATION (the caller-owned shape) —
/// used by creation AND by replay reconstruction, so a hollow or drifted envelope can never
/// converge (#72 round 16 discipline). Returns the canonical declaration record.
fn validate_request_create(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    // Plane-owned scalars refuse typed.
    for (key, code, why) in [
        ("status", "room_participation_status_plane_owned", "a typed request admits as `submitted`; decisions are receipted transitions"),
        ("participant_lease_ref", "room_participation_field_plane_owned", "the lease ref is minted by an admitted decision"),
        ("admission_decision_ref", "room_participation_field_plane_owned", "the decision ref is minted by an admitted decision"),
        ("request_hash", "room_participation_field_plane_owned", "the request hash is computed by this plane"),
        ("revision", "room_participation_field_plane_owned", "`revision` is minted by this plane"),
        ("admission_receipt_ref", "room_participation_field_plane_owned", "receipts are minted by this plane"),
        ("signature", "room_participation_signature_unavailable", "AIIP-signed requests are the federated/discovery leg (build steps 7-8) — a named gap, never faked"),
        ("room_discovery_ref", "room_participation_discovery_unavailable", "OutcomeRoomDiscoveryEnvelope is the AIIP discovery leg (build step 7) — a named gap, never faked"),
    ] {
        if body.get(key).map(|v| !v.is_null()).unwrap_or(false) {
            return Err(verr(code, why));
        }
    }
    let outcome_room_ref = preq(
        body,
        "outcome_room_ref",
        &["outcome-room"],
        &[],
        "room_participation_room_required",
    )?;
    let requested_by = preq(
        body,
        "requested_by_ref",
        &["worker", "service", "org", "domain"],
        &[],
        "room_participation_requested_by_required",
    )?;
    let topology = vocab_required(
        body,
        "coordination_topology",
        &["hosted_admission", "federated_admission"],
        "room_participation_topology_invalid",
    )?;
    if topology == "federated_admission" {
        return Err(verr("room_participation_federated_unavailable", "`federated_admission` participation needs the AIIP leg (build steps 7-8) — hosted_admission is the step-3 contract"));
    }
    let admission_owner = preq(
        body,
        "admission_owner_ref",
        &["domain", "policy"],
        &[],
        "room_participation_admission_owner_required",
    )?;
    // The canon pins `private_context_included: false` — a request NEVER carries raw context.
    match body.get("private_context_included") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Err(verr("room_participation_private_context_rejected", "`private_context_included` must be false — a participation request never carries raw private context")),
        Some(_) => return Err(verr("room_participation_private_context_rejected", "`private_context_included` must be the boolean false")),
    }
    let record = json!({
        "outcome_room_ref": outcome_room_ref,
        "requested_by_ref": requested_by,
        "operator_and_home_domain_refs": plist(body, "operator_and_home_domain_refs", &["user", "wallet", "org", "domain", "system"], &[])?,
        "worker_composition_and_dependency_refs": plist(body, "worker_composition_and_dependency_refs", &["package", "worker", "model_route", "runtime", "provider"], &["harness_profile:"])?,
        "capability_offer_refs": plist(body, "capability_offer_refs", &["capability-offer", "ai", "package"], &[])?,
        "affiliation_and_independent_operation_evidence_refs": plist(body, "affiliation_and_independent_operation_evidence_refs", &["evidence", "receipt", "org", "certification_claim"], &[])?,
        "supported_semantic_and_action_profile_refs": plist(body, "supported_semantic_and_action_profile_refs", &["ontology", "semantic-profile", "ontology-mapping", "ontology-action", "action_schema"], &[])?,
        "eligibility_evidence_refs": plist(body, "eligibility_evidence_refs", &["evidence", "receipt", "benchmark", "conformance_profile", "certification_claim"], &[])?,
        "requested_role_frontier_and_visibility_refs": plist(body, "requested_role_frontier_and_visibility_refs", &["frontier", "policy", "restricted_view"], &[])?,
        "privacy_custody_and_context_policy_refs": plist(body, "privacy_custody_and_context_policy_refs", &["privacy_posture", "custody", "policy"], &[])?,
        "proposed_quote_and_budget_refs": plist(body, "proposed_quote_and_budget_refs", &["quote", "goal-budget", "order"], &[])?,
        "accepted_verifier_settlement_dispute_and_contribution_policy_refs": plist(body, "accepted_verifier_settlement_dispute_and_contribution_policy_refs", &["verifier_path", "policy", "settlement-intent", "dispute"], &[])?,
        "requested_participant_state_export_policy_ref": pscalar(body, "requested_participant_state_export_policy_ref", &["policy"], &[])?,
        "coordination_topology": topology,
        "admission_owner_ref": admission_owner,
        "private_context_included": false,
        "room_discovery_ref": Value::Null,
        "signature": Value::Null,
    });
    Ok(record)
}

/// Seal a validated declaration into the COMPLETE submitted request — creation and replay
/// reconstruction both call THIS, so a replay byte-compares against the only valid shape.
fn seal_request(declaration: &Value, tail: &str, receipt_ref: &str, now: &str) -> Value {
    let mut record = declaration.clone();
    let obj = record.as_object_mut().expect("declaration is an object");
    obj.insert("schema_version".into(), json!(REQUEST_SCHEMA));
    obj.insert(
        "participation_request_id".into(),
        json!(format!("participation-request://{tail}")),
    );
    obj.insert("status".into(), json!("submitted"));
    obj.insert("revision".into(), json!(1));
    obj.insert("status_history".into(), json!([]));
    obj.insert("created_at".into(), json!(now));
    obj.insert("updated_at".into(), json!(now));
    obj.insert("admission_receipt_ref".into(), json!(receipt_ref));
    obj.insert("admission_and_replay_refs".into(), json!([receipt_ref]));
    obj.insert("admission_decision_ref".into(), Value::Null);
    obj.insert("participant_lease_ref".into(), Value::Null);
    obj.insert("runtimeTruthSource".into(), json!("daemon-runtime"));
    // request_hash binds the DECLARED shape (computed over the sealed record minus plane-owned
    // mutables — the same scope the admission receipt hashes).
    let h = record_output_hash(&record, REQUEST_CREATE_EXCLUDES);
    record
        .as_object_mut()
        .expect("object")
        .insert("request_hash".into(), json!(h));
    record
}

/// Validate + canonicalize the host's ADMIT parameters — used by the admit endpoint AND by
/// replay reconstruction.
fn validate_admit_params(body: &Value) -> Result<Value, VErr> {
    reject_sensitive_keys(body, "")?;
    let admitted_role = vocab_required(
        body,
        "admitted_role",
        ADMITTED_ROLES,
        "participant_lease_role_invalid",
    )?;
    let operator_ref = preq(
        body,
        "operator_ref",
        &["user", "org", "wallet", "domain"],
        &[],
        "participant_lease_operator_required",
    )?;
    // `agentgres` is path-qualified here: only agentgres://domain/… is a home domain.
    let home_domain_ref = home_domain_ref_required(body)?;
    // TTL is DECLARED but not enforced — there is no clock/expiry authority yet (#74 review
    // finding 3). Rather than store a bound we cannot honor, a non-null `ttl_seconds` is REFUSED
    // as a named gap: a receipted expiry transition + bounded maximum arrive with clock authority.
    match body.get("ttl_seconds") {
        None | Some(Value::Null) => {}
        Some(_) => {
            return Err(verr(
                "participant_lease_ttl_unavailable",
                "`ttl_seconds` is not enforceable yet — lease expiry needs clock/expiry authority (a later build step). Omit it (null); a bounded, receipted TTL arrives with that authority, never a stored-but-unenforced deadline",
            ))
        }
    }
    let ttl = Value::Null;
    Ok(json!({
        "admitted_role": admitted_role,
        "operator_ref": operator_ref,
        "home_domain_ref": home_domain_ref,
        "visibility_scope_ref": pscalar(body, "visibility_scope_ref", &["policy", "restricted_view"], &[])?,
        "context_and_authority_lease_refs": plist(body, "context_and_authority_lease_refs", &["context_lease", "grant", "authority"], &[])?,
        "runtime_resource_and_budget_lease_refs": plist(body, "runtime_resource_and_budget_lease_refs", &["lease", "resource-lease", "budget"], &[])?,
        "ttl_seconds": ttl,
    }))
}

/// Build the COMPLETE bounded lease from the (pre-admit) request + validated admit params —
/// the admit finalizer and the replay validator both call THIS.
fn build_lease(
    request: &Value,
    params: &Value,
    lease_tail: &str,
    lease_receipt_ref: &str,
    now: &str,
) -> Value {
    let mut identity_refs: Vec<Value> = request
        .get("affiliation_and_independent_operation_evidence_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    identity_refs.extend(
        request
            .get("eligibility_evidence_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    );
    let mut record = json!({
        "schema_version": LEASE_SCHEMA,
        "participant_lease_id": format!("participant-lease://{lease_tail}"),
        "outcome_room_ref": request.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "participant_ref": request.get("requested_by_ref").cloned().unwrap_or(Value::Null),
        "admitted_role": params.get("admitted_role").cloned().unwrap_or(Value::Null),
        "operator_ref": params.get("operator_ref").cloned().unwrap_or(Value::Null),
        "home_domain_ref": params.get("home_domain_ref").cloned().unwrap_or(Value::Null),
        "worker_and_runtime_refs": request.get("worker_composition_and_dependency_refs").cloned().unwrap_or(json!([])),
        "capability_advertisement_refs": request.get("capability_offer_refs").cloned().unwrap_or(json!([])),
        "tool_connector_and_capability_dependency_refs": [],
        "join_request_ref": request.get("participation_request_id").cloned().unwrap_or(Value::Null),
        "identity_and_eligibility_evidence_refs": identity_refs,
        "admission_decision_ref": lease_receipt_ref,
        "visibility_scope_ref": params.get("visibility_scope_ref").cloned().unwrap_or(Value::Null),
        "context_and_authority_lease_refs": params.get("context_and_authority_lease_refs").cloned().unwrap_or(json!([])),
        "runtime_resource_and_budget_lease_refs": params.get("runtime_resource_and_budget_lease_refs").cloned().unwrap_or(json!([])),
        "current_claim_ref": Value::Null,
        "heartbeat_ref": Value::Null,
        "next_wake_condition_ref": Value::Null,
        "quiet_hours_or_backoff_ref": Value::Null,
        "last_contribution_ref": Value::Null,
        "exit_and_claim_release_refs": [],
        "portable_participant_state_bundle_ref": Value::Null,
        "future_access_revocation_refs": [],
        "ttl_seconds": params.get("ttl_seconds").cloned().unwrap_or(Value::Null),
        "status": "active",
        "revision": 1,
        "status_history": [],
        "created_at": now,
        "updated_at": now,
        "admission_receipt_ref": lease_receipt_ref,
        "admission_and_replay_refs": [lease_receipt_ref],
        "runtimeTruthSource": "daemon-runtime"
    });
    let _ = &mut record;
    record
}

/// Apply a lease transition deterministically — finalizer AND replay validator call THIS.
/// Revocation appends the revocation receipt to `future_access_revocation_refs` (future access
/// ends; lineage is never erased).
fn apply_transition(
    record: &Value,
    intent_field: &str,
    op: &str,
    to_status: &str,
    receipt_ref: &Value,
    now: &Value,
    extra_revocation: bool,
) -> Value {
    let prior_rev = record.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let from = s(record, "status", "");
    let mut updated = record.clone();
    if let Some(obj) = updated.as_object_mut() {
        obj.remove(intent_field);
        obj.insert("status".into(), json!(to_status));
        obj.insert("revision".into(), json!(prior_rev + 1));
        obj.insert("updated_at".into(), now.clone());
        let mut trail: Vec<Value> = obj
            .get("admission_and_replay_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        trail.push(receipt_ref.clone());
        obj.insert("admission_and_replay_refs".into(), Value::Array(trail));
        let mut history: Vec<Value> = obj
            .get("status_history")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        history.push(json!({ "op": op, "from": from, "at": now, "receipt_ref": receipt_ref, "revision": prior_rev + 1 }));
        if history.len() > HISTORY_MAX {
            let drop_n = history.len() - HISTORY_MAX;
            history.drain(0..drop_n);
        }
        obj.insert("status_history".into(), Value::Array(history));
        if extra_revocation {
            let mut revs: Vec<Value> = obj
                .get("future_access_revocation_refs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            revs.push(receipt_ref.clone());
            obj.insert("future_access_revocation_refs".into(), Value::Array(revs));
        }
    }
    updated
}

// ================================ FINALIZERS =====================================================

/// Duplicate-live guard: at most ONE live (non-terminal) request per (room, principal), and at
/// most ONE live lease per (room, participant). Scans are TYPED — an unreadable registry
/// refuses rather than admitting a duplicate over unknown truth.
fn live_request_exists(data_dir: &str, room_ref: &str, principal: &str) -> Result<bool, VErr> {
    let requests = scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    )
    .map_err(|e| verr("room_participation_registry_unreadable", e))?;
    // A submit intent reserves the same uniqueness key before its request becomes visible. Scan
    // and canonically reconstruct EVERY intent first so an unrelated malformed slot cannot be
    // hidden by an early positive match.
    let submit_intents = scan_intent_family(data_dir)
        .map_err(|e| verr("room_participation_registry_unreadable", e))?;
    let mut pending_requests = Vec::with_capacity(submit_intents.len());
    for (tail, intent) in submit_intents {
        let (final_request, _, _) = validate_submit_intent(&intent, &tail).map_err(|why| {
            verr(
                "room_participation_registry_unreadable",
                format!("submit intent '{tail}' is not canonical ({why})"),
            )
        })?;
        pending_requests.push(final_request);
    }
    let completed_live = requests.iter().any(|(_, r)| {
        s(r, "outcome_room_ref", "") == room_ref
            && s(r, "requested_by_ref", "") == principal
            && matches!(
                s(r, "status", "").as_str(),
                "draft" | "submitted" | "evaluating"
            )
    });
    let pending_live = pending_requests.iter().any(|request| {
        s(request, "outcome_room_ref", "") == room_ref
            && s(request, "requested_by_ref", "") == principal
    });
    Ok(completed_live || pending_live)
}

/// Parse the room-owned lease reservation ledger without the projection helper's permissive
/// defaults. Uniqueness is a write-side decision, so a missing/wrong-type/duplicate/noncanonical
/// entry or a release with no prior bind makes the reservation truth unknown.
fn strict_room_lease_refs(
    room: &Value,
) -> Result<
    (
        std::collections::HashSet<String>,
        std::collections::HashSet<String>,
    ),
    String,
> {
    fn parse(
        room: &Value,
        field: &str,
        required: bool,
    ) -> Result<std::collections::HashSet<String>, String> {
        let Some(value) = room.get(field) else {
            return if required {
                Err(format!("room field '{field}' is absent"))
            } else {
                Ok(std::collections::HashSet::new())
            };
        };
        if value.is_null() && !required {
            return Ok(std::collections::HashSet::new());
        }
        let Some(values) = value.as_array() else {
            return Err(format!("room field '{field}' is not an array"));
        };
        let mut out = std::collections::HashSet::with_capacity(values.len());
        for value in values {
            let Some(lease_ref) = value.as_str() else {
                return Err(format!(
                    "room field '{field}' contains a non-string lease ref"
                ));
            };
            let Some(tail) = lease_ref.strip_prefix("participant-lease://") else {
                return Err(format!(
                    "room field '{field}' contains noncanonical ref '{lease_ref}'"
                ));
            };
            if !is_canonical_lease_tail(tail) {
                return Err(format!(
                    "room field '{field}' contains noncanonical ref '{lease_ref}'"
                ));
            }
            if !out.insert(lease_ref.to_string()) {
                return Err(format!(
                    "room field '{field}' contains duplicate ref '{lease_ref}'"
                ));
            }
        }
        Ok(out)
    }

    let bound = parse(room, "participant_lease_refs", true)?;
    let released = parse(room, "released_participant_lease_refs", false)?;
    if !released.is_subset(&bound) {
        return Err(
            "released_participant_lease_refs is not a subset of participant_lease_refs".into(),
        );
    }
    Ok((bound, released))
}

fn live_lease_exists(data_dir: &str, room_ref: &str, participant: &str) -> Result<bool, VErr> {
    let leases = scan_family(
        data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    )
    .map_err(|e| verr("participant_lease_registry_unreadable", e))?;
    // Admission reserves its final lease while the request still carries `admit_intent`. Include
    // those canonically validated reservations, not only visible lease records, or two request
    // records can race into the same (room, participant) lease key.
    let requests = scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    )
    .map_err(|e| verr("participant_lease_registry_unreadable", e))?;
    let mut reserved_leases: Vec<(String, Value)> = Vec::new();
    for (tail, request) in &requests {
        if let Some(intent) = request.get("admit_intent") {
            let mut prior = request.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("admit_intent");
            validate_admit_intent(intent, &prior, tail).map_err(|why| {
                verr(
                    "participant_lease_registry_unreadable",
                    format!("request '{tail}' carries a noncanonical admit reservation ({why})"),
                )
            })?;
            reserved_leases.push((
                tail.clone(),
                intent.get("final_lease").cloned().unwrap_or(Value::Null),
            ));
        }
    }
    let completed_live = leases.iter().any(|(_, lease)| {
        s(lease, "outcome_room_ref", "") == room_ref
            && s(lease, "participant_ref", "") == participant
            && !matches!(s(lease, "status", "").as_str(), "retired" | "revoked")
    });
    let reserved_live = reserved_leases.iter().any(|(_, lease)| {
        s(lease, "outcome_room_ref", "") == room_ref
            && s(lease, "participant_ref", "") == participant
            && !matches!(s(lease, "status", "").as_str(), "retired" | "revoked")
    });
    // The room backlink is the room plane's exact live reservation set. A terminal lease remains
    // reserved until its `participant_lease_released` backlink lands; conversely, an orphaned or
    // mismatched live backlink is registry uncertainty, not permission to mint another lease.
    let room = match rooms::resolve_room_strict(data_dir, room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            return Err(verr(
                "room_participation_room_not_found",
                format!("room '{room_ref}' does not resolve while checking lease uniqueness"),
            ))
        }
        Err(message) => {
            return Err(verr(
                "room_participation_room_unreadable",
                format!(
                "room '{room_ref}' cannot be resolved while checking lease uniqueness ({message})"
            ),
            ))
        }
    };
    let (bound_backlinks, released_backlinks) = strict_room_lease_refs(&room).map_err(|why| {
        verr(
            "participant_lease_registry_unreadable",
            format!("room '{room_ref}' has malformed lease reservations ({why})"),
        )
    })?;
    let live_backlinks: Vec<String> = bound_backlinks
        .difference(&released_backlinks)
        .cloned()
        .collect();
    let mut backlink_live_for_participant = false;
    for lease_ref in &live_backlinks {
        let Some(lease_tail) = lease_ref.strip_prefix("participant-lease://") else {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("room '{room_ref}' has a noncanonical live lease backlink '{lease_ref}'"),
            ));
        };
        if !is_canonical_lease_tail(lease_tail) {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("room '{room_ref}' has a noncanonical live lease backlink '{lease_ref}'"),
            ));
        }
        let bound = leases
            .iter()
            .find(|(_, lease)| s(lease, "participant_lease_id", "") == *lease_ref)
            .map(|(_, lease)| lease)
            .or_else(|| {
                reserved_leases
                    .iter()
                    .find(|(_, lease)| s(lease, "participant_lease_id", "") == *lease_ref)
                    .map(|(_, lease)| lease)
            });
        let Some(bound) = bound else {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("room '{room_ref}' reserves live lease '{lease_ref}', but no canonical completed or pending lease binds that ref"),
            ));
        };
        if s(bound, "outcome_room_ref", "") != room_ref {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("room '{room_ref}' live backlink '{lease_ref}' resolves to a lease bound to another room"),
            ));
        }
        if s(bound, "participant_ref", "") == participant {
            backlink_live_for_participant = true;
        }
    }

    // A completed admitted request is the durable lineage anchor for its lease. Its ref must
    // resolve and agree on room, participant, and join request even after room release; missing
    // lineage is an inconsistent registry and therefore typed-unreadable.
    for (request_tail, request) in requests {
        if s(&request, "status", "") != "admitted" {
            continue;
        }
        let lease_ref = s(&request, "participant_lease_ref", "");
        let Some(lease_tail) = lease_ref.strip_prefix("participant-lease://") else {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("admitted request '{request_tail}' has no canonical participant_lease_ref"),
            ));
        };
        if !is_canonical_lease_tail(lease_tail) {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("admitted request '{request_tail}' has no canonical participant_lease_ref"),
            ));
        }
        let Some((_, lease)) = leases
            .iter()
            .find(|(_, lease)| s(lease, "participant_lease_id", "") == lease_ref)
        else {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("admitted request '{request_tail}' references missing lease '{lease_ref}'"),
            ));
        };
        let request_id = format!("participation-request://{request_tail}");
        if s(lease, "outcome_room_ref", "") != s(&request, "outcome_room_ref", "")
            || s(lease, "participant_ref", "") != s(&request, "requested_by_ref", "")
            || s(lease, "join_request_ref", "") != request_id
        {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("admitted request '{request_tail}' and lease '{lease_ref}' do not bind the same room, participant, and join lineage"),
            ));
        }
        if s(&request, "outcome_room_ref", "") == room_ref {
            if !bound_backlinks.contains(&lease_ref) {
                return Err(verr(
                    "participant_lease_registry_unreadable",
                    format!("admitted request '{request_tail}' and lease '{lease_ref}' have no room backlink reservation"),
                ));
            }
            let terminal = matches!(s(lease, "status", "").as_str(), "retired" | "revoked");
            if released_backlinks.contains(&lease_ref) && !terminal {
                return Err(verr(
                    "participant_lease_registry_unreadable",
                    format!("room '{room_ref}' releases nonterminal lease '{lease_ref}'"),
                ));
            }
        }
    }

    Ok(completed_live || reserved_live || backlink_live_for_participant)
}

/// Durably consume a submit intent through a pinned family descriptor. A checked directory fsync
/// makes rollback of a pre-linearization intent survive a crash instead of resurrecting an
/// impossible submission on the next boot.
fn consume_submit_intent(data_dir: &str, tail: &str) -> Result<(), String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, SUBMIT_INTENT_DIR) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "submit-intent family could not be pinned for consumption ({e})"
            ))
        }
    };
    match super::durable_fs::unlink_at(&dir, format!("{tail}.json")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("submit intent could not be unlinked ({e})")),
    }
    dir.sync_all()
        .map_err(|e| format!("submit-intent directory sync failed after unlink ({e})"))
}

/// Preflight submission-owned targets before either its durable intent or room reservation. The
/// returned flags distinguish exact crash-replay occupants from absent targets for safe rollback.
fn preflight_submit_targets(
    data_dir: &str,
    tail: &str,
    final_request: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(bool, bool), VErr> {
    let request_preexisting =
        match read_slot_strict(data_dir, REQUEST_DIR, tail, is_canonical_request_tail) {
            Ok(None) => false,
            Ok(Some(existing)) if existing == *final_request => true,
            Ok(Some(_)) => {
                return Err(verr(
                    "room_participation_request_conflict",
                    format!(
                        "request slot '{tail}' holds a different record — the room was not mutated"
                    ),
                ))
            }
            Err(e) => {
                return Err(verr(
                    "room_participation_registry_unreadable",
                    format!(
                    "request slot '{tail}' cannot be certified ({e}) — the room was not mutated"
                ),
                ))
            }
        };
    let receipt_preexisting = match read_slot_strict(
        data_dir,
        RECEIPT_DIR,
        receipt_id,
        |candidate| is_canonical_receipt_tail(candidate, "rqr"),
    ) {
        Ok(None) => false,
        Ok(Some(existing)) if existing == *receipt => true,
        Ok(Some(_)) => {
            return Err(verr(
                "room_participation_receipt_conflict",
                format!("receipt slot '{receipt_id}' holds different append-only evidence — the room was not mutated"),
            ))
        }
        Err(e) => {
            return Err(verr(
                "room_participation_receipt_slot_unreadable",
                format!("receipt slot '{receipt_id}' cannot be certified ({e}) — the room was not mutated"),
            ))
        }
    };
    Ok((request_preexisting, receipt_preexisting))
}

/// SUBMIT finalization: durable internal intent → room backlink reservation (through the
/// room-owned seam; `already_bound` = converged replay) → append-only receipt → terminal
/// request → consume the intent. The caller holds the room lock from OPEN validation through
/// reservation, so close cannot win after admission evidence starts to land. Any post-
/// linearization failure retains the intent and a restart converges this same submission.
fn finalize_submit(
    data_dir: &str,
    tail: &str,
    final_request: &Value,
    receipt_id: &str,
    receipt: &Value,
    room_scope: &std::sync::MutexGuard<'_, ()>,
) -> Result<(), VErr> {
    preflight_submit_targets(data_dir, tail, final_request, receipt_id, receipt)?;
    let intent = json!({
        "kind": "submit",
        "request_tail": tail,
        "request_ref": final_request.get("participation_request_id").cloned().unwrap_or(Value::Null),
        "room_ref": final_request.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "final_request": final_request,
        "final_request_hash": record_output_hash(final_request, &[]),
        "receipt_id": receipt_id,
        "receipt": receipt,
        "receipt_hash": record_output_hash(receipt, &[]),
        "at": final_request.get("updated_at").cloned().unwrap_or(Value::Null),
    });
    if let Err(f) = persist_atomic(data_dir, SUBMIT_INTENT_DIR, tail, &intent) {
        if f.visible() {
            return Err(verr("room_participation_submit_pending_convergence", format!("the submit intent is {} — a restart converges this same submission; do not re-submit", f.detail())));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the submit intent did not commit ({}) — nothing was admitted",
                f.detail()
            ),
        ));
    }
    complete_submit(
        data_dir,
        tail,
        final_request,
        receipt_id,
        receipt,
        room_scope,
    )
}

/// The convergent tail of a submission — called by the finalizer AND (after validation) by the
/// boot completer, so both paths produce the identical durable outcome. `room_scope` proves that
/// room-open validation and room reservation share one room-scoped critical section.
fn complete_submit(
    data_dir: &str,
    tail: &str,
    final_request: &Value,
    receipt_id: &str,
    receipt: &Value,
    _room_scope: &std::sync::MutexGuard<'_, ()>,
) -> Result<(), VErr> {
    // Preflight every participation-owned target BEFORE reserving the room. The participation
    // mutex excludes in-daemon writers until commit, so a foreign/unreadable target cannot strand
    // a room backlink. Byte-identical occupants are valid crash replay.
    let (request_preexisting, receipt_preexisting) =
        preflight_submit_targets(data_dir, tail, final_request, receipt_id, receipt)?;
    let room_ref = s(final_request, "outcome_room_ref", "");
    let request_id = s(final_request, "participation_request_id", "");
    match rooms::bind_room_backlink_room_locked(
        data_dir,
        &room_ref,
        "participation_request_bound",
        &request_id,
    ) {
        Ok(_) => {}
        // Idempotent replay: the ref landed before a crash — converged, not a conflict.
        Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
        Err((code, msg)) if code == "outcome_room_not_open" || code == "outcome_room_not_found" => {
            // Before the room reservation there is no admitted evidence to preserve. Consume the
            // impossible intent durably so a closed room cannot leave permanent retry state.
            // Legacy exact artifacts from the old receipt-first order cannot be rolled back.
            if !request_preexisting && !receipt_preexisting {
                consume_submit_intent(data_dir, tail).map_err(|why| {
                    verr(
                        "room_participation_submit_pending_convergence",
                        format!("{msg}; no submission evidence was written, but the pre-linearization intent could not be consumed ({why})"),
                    )
                })?;
                let mapped = if code == "outcome_room_not_found" {
                    "room_participation_room_not_found"
                } else {
                    "room_participation_room_not_open"
                };
                return Err(verr(
                    mapped,
                    format!("{msg}; the pre-linearization submit intent was rolled back durably and no submission evidence was written"),
                ));
            }
            return Err(verr(
                "room_participation_submit_pending_convergence",
                format!("{msg}; legacy submission artifacts already exist, so append-only evidence forbids rollback and the intent is retained for manual repair"),
            ));
        }
        Err((code, msg)) => {
            return Err(verr(&code, format!("{msg}; the DURABLE submit intent is retained — a restart converges this same submission")));
        }
    }
    persist_receipt(data_dir, receipt_id, receipt).map_err(|(code, msg)| {
        let ecode = if code == "room_participation_receipt_conflict" || code == "room_participation_receipt_slot_unreadable" || code == "room_participation_receipt_swapped" { code } else { "room_participation_submit_pending_convergence".to_string() };
        (ecode, format!("the room reservation is durable, but the submission receipt is not durably committed ({msg}); the DURABLE intent is retained — a restart converges this same submission"))
    })?;
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, tail, final_request) {
        if f.visible() {
            return Err(verr("room_participation_submit_pending_convergence", format!("the terminal request write is {} — the intent is retained; a restart re-verifies and completes", f.detail())));
        }
        return Err(verr("room_participation_submit_pending_convergence", format!("the terminal request write did not commit ({}) — the intent is retained; a restart completes it", f.detail())));
    }
    consume_submit_intent(data_dir, tail).map_err(|why| {
        verr(
            "room_participation_submit_pending_convergence",
            format!("the submission is durable, but its replay intent could not be consumed ({why}); a restart consumes the same byte-identical intent"),
        )
    })?;
    Ok(())
}

/// Single-record transition finalization (request or lease): seal the intent ON the record →
/// receipt (append-only) → terminal record with the intent consumed. Receipt failure retains
/// the intent (visible/unconfirmed evidence is never rolled back "as absent"); current boot
/// policy quarantines that governed intent rather than replaying unverifiable authority.
fn finalize_record_transition(
    data_dir: &str,
    family: &str,
    tail: &str,
    prior: &Value,
    updated: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    let mut carrying = prior.clone();
    carrying.as_object_mut().expect("object").insert(
        "transition_intent".into(),
        json!({
            "op": receipt.get("op").cloned().unwrap_or(Value::Null),
            "final_record": updated,
            "final_record_hash": record_output_hash(updated, &[]),
            "receipt_id": receipt_id,
            "receipt": receipt,
            "receipt_hash": record_output_hash(receipt, &[]),
            "at": updated.get("updated_at").cloned().unwrap_or(Value::Null),
        }),
    );
    if let Err(f) = persist_atomic(data_dir, family, tail, &carrying) {
        if f.visible() {
            return Err(verr("room_participation_transition_pending_convergence", format!("the transition intent is {} — the visible state may already carry it; governed replay remains quarantined until its authority can be reverified", f.detail())));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the transition intent did not commit ({}) — nothing changed",
                f.detail()
            ),
        ));
    }
    match persist_receipt(data_dir, receipt_id, receipt) {
        Ok(()) => {}
        Err((code, msg)) if code == "room_participation_receipt_durability_unconfirmed" => {
            return Err(verr("room_participation_transition_pending_convergence", format!("{msg}; the DURABLE intent is retained with the record still showing its PRIOR state, but boot will not apply it without replay-verifiable identity-bound authority")));
        }
        Err((code, msg))
            if code == "room_participation_receipt_conflict"
                || code == "room_participation_receipt_slot_unreadable"
                || code == "room_participation_receipt_swapped" =>
        {
            // Roll the intent back exactly — append-only evidence is never overwritten.
            return match persist_atomic(data_dir, family, tail, prior) {
                Ok(()) => Err(verr(
                    &code,
                    format!("{msg}; the intent was rolled back EXACTLY — nothing changed"),
                )),
                Err(_) => Err(verr(
                    &code,
                    format!(
                        "{msg} AND the intent rollback did not commit — manual repair required"
                    ),
                )),
            };
        }
        Err((_code, msg)) => {
            return match persist_atomic(data_dir, family, tail, prior) {
                Ok(()) => Err(verr("room_participation_receipt_persist_failed", format!("transition receipt persist did not commit ({msg}); the intent was rolled back EXACTLY — nothing changed"))),
                Err(_) => Err(verr("room_participation_transition_pending_convergence", format!("transition receipt persist did not commit ({msg}) AND the intent rollback did not commit — the governed intent is quarantined for authenticated repair"))),
            };
        }
    }
    if let Err(f) = persist_atomic(data_dir, family, tail, updated) {
        return Err(verr("room_participation_transition_pending_convergence", format!("the terminal transition write is {}; the DURABLE intent and receipt are retained, but boot will not apply them without replay-verifiable identity-bound authority", f.detail())));
    }
    Ok(())
}

/// Compound participant terminalization: persist the participation transition intent first,
/// embed the exact separately authorized work-claim intent in it, then materialize that work
/// intent before the participant can become terminal. Any crash therefore leaves at least one
/// authenticated durable predecessor from which both successors can be reconstructed.
#[allow(clippy::too_many_arguments)]
fn finalize_record_transition_with_work_claim(
    data_dir: &str,
    family: &str,
    tail: &str,
    plan: &RecordTransitionPlan,
    work_intent_tail: &str,
    work_intent: &Value,
) -> Result<(), VErr> {
    let mut carrying = plan.prior.clone();
    carrying.as_object_mut().expect("object").insert(
        "transition_intent".into(),
        json!({
            "op": plan.receipt.get("op").cloned().unwrap_or(Value::Null),
            "final_record": plan.updated,
            "final_record_hash": record_output_hash(&plan.updated, &[]),
            "receipt_id": plan.receipt_id,
            "receipt": plan.receipt,
            "receipt_hash": record_output_hash(&plan.receipt, &[]),
            "at": plan.updated.get("updated_at").cloned().unwrap_or(Value::Null),
            "coupled_work_claim_intent_tail": work_intent_tail,
            "coupled_work_claim_intent": work_intent,
            "coupled_work_claim_intent_hash": record_output_hash(work_intent, &[]),
        }),
    );
    persist_atomic(data_dir, family, tail, &carrying).map_err(|failure| {
        let code = if failure.visible() {
            "room_participation_transition_pending_convergence"
        } else {
            "room_participation_persist_failed"
        };
        verr(
            code,
            format!(
                "the compound participant/work-claim intent is {}; no untracked terminal participant was admitted",
                failure.detail()
            ),
        )
    })?;

    super::work_frontier_claim_routes::persist_embedded_intent_locked(
        data_dir,
        work_intent_tail,
        work_intent,
    )
    .map_err(|(_, message)| {
        verr(
            "participant_lease_claim_release_pending_convergence",
            format!("the participation intent is durable but its embedded work-claim intent is pending ({message})"),
        )
    })?;

    persist_receipt(data_dir, &plan.receipt_id, &plan.receipt).map_err(|(_, message)| {
        verr(
            "room_participation_transition_pending_convergence",
            format!("the compound intents are durable but the participation receipt is pending ({message})"),
        )
    })?;
    persist_atomic(data_dir, family, tail, &plan.updated).map_err(|failure| {
        verr(
            "room_participation_transition_pending_convergence",
            format!("the compound intents and receipt are durable but the terminal participant write is {}", failure.detail()),
        )
    })?;
    Ok(())
}

/// Certify that every participation-owned admission target is either absent or already contains
/// the exact sealed value. This runs BEFORE the room backlink linearizes admission, so a foreign
/// or unreadable receipt/lease occupant cannot reserve a phantom live lease and permanently block
/// room close. `PARTICIPATION_LOCK` excludes all in-daemon writers across this preflight + commit.
fn preflight_admit_targets(data_dir: &str, admit: &Value) -> Result<(), VErr> {
    let lease_tail = admit
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("");
    let final_lease = admit.get("final_lease").cloned().unwrap_or(Value::Null);
    let expected_lease_id = format!("participant-lease://{lease_tail}");
    if final_lease
        .get("participant_lease_id")
        .and_then(Value::as_str)
        != Some(expected_lease_id.as_str())
    {
        return Err(verr(
            "participant_lease_conflict",
            "the sealed lease identity does not bind to its target slot — the room was not mutated",
        ));
    }
    match read_slot_strict(data_dir, LEASE_DIR, lease_tail, is_canonical_lease_tail) {
        Ok(None) => {}
        Ok(Some(existing)) if existing == final_lease => {}
        Ok(Some(_)) => {
            return Err(verr(
                "participant_lease_conflict",
                format!("the lease slot '{lease_tail}' holds different state — the room was not mutated"),
            ))
        }
        Err(e) => {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("the lease slot '{lease_tail}' cannot be certified ({e}) — the room was not mutated"),
            ))
        }
    }

    for (field, prefix) in [("lease_receipt", "rlr"), ("request_receipt", "rqt")] {
        let id_field = format!("{field}_id");
        let receipt_id = admit
            .get(id_field.as_str())
            .and_then(Value::as_str)
            .unwrap_or("");
        let expected = admit.get(field).cloned().unwrap_or(Value::Null);
        let canonical: fn(&str) -> bool = match prefix {
            "rlr" => |tail| is_canonical_receipt_tail(tail, "rlr"),
            _ => |tail| is_canonical_receipt_tail(tail, "rqt"),
        };
        match read_slot_strict(data_dir, RECEIPT_DIR, receipt_id, canonical) {
            Ok(None) => {}
            Ok(Some(existing)) if existing == expected => {}
            Ok(Some(_)) => {
                return Err(verr(
                    "room_participation_receipt_conflict",
                    format!("receipt slot '{receipt_id}' holds different append-only evidence — the room was not mutated"),
                ))
            }
            Err(e) => {
                return Err(verr(
                    "room_participation_receipt_slot_unreadable",
                    format!("receipt slot '{receipt_id}' cannot be certified ({e}) — the room was not mutated"),
                ))
            }
        }
    }
    Ok(())
}

/// ADMIT finalization under the room-scoped lock: seal the admit intent ON the request → reserve
/// the room slot through its own intent transaction → lease receipt → request receipt → lease
/// record → terminal request. The room transition is the linearization point: before it, the
/// held room lock excludes close; after it, a pending room intent or live lease ref excludes
/// close. Participation decision evidence is therefore never persisted for a closed room.
#[allow(clippy::too_many_arguments)]
fn finalize_admit(
    data_dir: &str,
    request_tail: &str,
    prior_request: &Value,
    admit: &Value,
    room_scope: &std::sync::MutexGuard<'_, ()>,
) -> Result<(), VErr> {
    // Conflict-atomicity: refuse deterministic target conflicts before either the request intent
    // or the room reservation exists.
    preflight_admit_targets(data_dir, admit)?;
    let mut carrying = prior_request.clone();
    carrying
        .as_object_mut()
        .expect("object")
        .insert("admit_intent".into(), admit.clone());
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, request_tail, &carrying) {
        if f.visible() {
            return Err(verr(
                "room_participation_admit_pending_convergence",
                format!(
                    "the admit intent is {} — governed replay is quarantined until its authority can be reverified",
                    f.detail()
                ),
            ));
        }
        return Err(verr(
            "room_participation_persist_failed",
            format!(
                "the admit intent did not commit ({}) — nothing changed",
                f.detail()
            ),
        ));
    }
    complete_admit(data_dir, request_tail, prior_request, admit, room_scope)
}

/// The room-locked tail of an already-authorized admission. Both the online handler and the
/// post-readiness replay pass call this only after wallet.network has authenticated and pinned the
/// complete identity-bound authority tuple. `room_scope` proves room-open validation and
/// reservation cannot race a close.
fn complete_admit(
    data_dir: &str,
    request_tail: &str,
    prior_request: &Value,
    admit: &Value,
    _room_scope: &std::sync::MutexGuard<'_, ()>,
) -> Result<(), VErr> {
    let final_request = admit.get("final_request").cloned().unwrap_or(Value::Null);
    let final_lease = admit.get("final_lease").cloned().unwrap_or(Value::Null);
    let lease_tail = admit
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let lease_receipt_id = admit
        .get("lease_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let lease_receipt = admit.get("lease_receipt").cloned().unwrap_or(Value::Null);
    let request_receipt_id = admit
        .get("request_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let request_receipt = admit.get("request_receipt").cloned().unwrap_or(Value::Null);
    let pend = |msg: String| -> VErr {
        verr("room_participation_admit_pending_convergence", format!("{msg}; the DURABLE admit intent is retained, but boot will not apply it without replay-verifiable identity-bound authority"))
    };
    // Re-check at the linearization boundary. The normal finalizer already preflighted before
    // sealing its intent; this second check protects a resumed/future proof-bearing replay and
    // detects out-of-band target swaps before the room is mutated.
    preflight_admit_targets(data_dir, admit)?;
    // ROOM FIRST. Its durable intent is the cross-plane reservation that keeps close from
    // winning after admission evidence starts to land.
    let room_ref = s(&final_lease, "outcome_room_ref", "");
    let lease_id = s(&final_lease, "participant_lease_id", "");
    match rooms::bind_room_backlink_room_locked(
        data_dir,
        &room_ref,
        "participant_lease_bound",
        &lease_id,
    ) {
        Ok(_) => {}
        Err((code, _)) if code == "outcome_room_backlink_already_bound" => {}
        Err((code, msg)) if code == "outcome_room_not_open" || code == "outcome_room_not_found" => {
            // A request-intent write can be visible-but-unconfirmed before the room reservation.
            // If close wins after that refusal and NO admission artifact exists, restore the
            // exact prior request instead of retaining a permanently impossible intent. Legacy
            // receipts/lease occupants make rollback unsafe and remain held for manual repair.
            let lease_absent = matches!(
                read_slot_strict(data_dir, LEASE_DIR, &lease_tail, is_canonical_lease_tail),
                Ok(None)
            );
            let lease_receipt_absent = matches!(
                read_slot_strict(data_dir, RECEIPT_DIR, &lease_receipt_id, |tail| {
                    is_canonical_receipt_tail(tail, "rlr")
                }),
                Ok(None)
            );
            let request_receipt_absent = matches!(
                read_slot_strict(data_dir, RECEIPT_DIR, &request_receipt_id, |tail| {
                    is_canonical_receipt_tail(tail, "rqt")
                }),
                Ok(None)
            );
            if lease_absent && lease_receipt_absent && request_receipt_absent {
                return match persist_atomic(data_dir, REQUEST_DIR, request_tail, prior_request) {
                    Ok(()) => Err(verr(
                        "room_participation_room_not_open",
                        format!("room '{room_ref}' is no longer open; the pre-linearization admit intent was rolled back EXACTLY and no admission evidence was written"),
                    )),
                    Err(f) => Err(pend(format!("room '{room_ref}' is no longer open and exact rollback of the pre-linearization intent is {}", f.detail()))),
                };
            }
            return Err(verr(
                "room_participation_admit_pending_convergence",
                format!("{msg}; legacy admission artifacts already exist, so append-only evidence forbids rollback and the intent is retained for manual repair"),
            ));
        }
        Err((_code, msg)) => return Err(pend(msg)),
    }
    persist_receipt(data_dir, &lease_receipt_id, &lease_receipt).map_err(|(code, msg)| {
        if code == "room_participation_receipt_conflict"
            || code == "room_participation_receipt_slot_unreadable"
            || code == "room_participation_receipt_swapped"
        {
            (code, msg)
        } else {
            pend(msg)
        }
    })?;
    persist_receipt(data_dir, &request_receipt_id, &request_receipt).map_err(|(code, msg)| {
        if code == "room_participation_receipt_conflict"
            || code == "room_participation_receipt_slot_unreadable"
            || code == "room_participation_receipt_swapped"
        {
            (code, msg)
        } else {
            pend(msg)
        }
    })?;
    // The lease slot is append-only in spirit: an existing occupant must BE this sealed lease.
    match read_slot_strict(data_dir, LEASE_DIR, &lease_tail, is_canonical_lease_tail) {
        Ok(Some(existing)) => {
            if serde_json::to_vec(&existing).unwrap_or_default()
                != serde_json::to_vec(&final_lease).unwrap_or_default()
            {
                return Err(verr("participant_lease_conflict", format!("the lease slot '{lease_tail}' already holds DIFFERENT state — refused, never overwritten; the admit intent is retained for manual repair")));
            }
        }
        Ok(None) => {
            if let Err(f) = persist_atomic(data_dir, LEASE_DIR, &lease_tail, &final_lease) {
                return Err(pend(format!("the lease record write is {}", f.detail())));
            }
        }
        Err(e) => {
            return Err(verr(
                "participant_lease_registry_unreadable",
                format!("{e} — the admit intent is retained; never admitted over unknown truth"),
            ))
        }
    }
    if let Err(f) = persist_atomic(data_dir, REQUEST_DIR, request_tail, &final_request) {
        return Err(pend(format!(
            "the terminal request write is {}",
            f.detail()
        )));
    }
    let _ = prior_request;
    Ok(())
}

// ================================ REPLAY VALIDATORS ==============================================

/// Plane-owned + identity fields stripped from a sealed request to recover the ORIGINAL
/// declaration for reconstruction.
const REQUEST_PLANE_OWNED: &[&str] = &[
    "schema_version",
    "participation_request_id",
    "status",
    "revision",
    "status_history",
    "created_at",
    "updated_at",
    "admission_receipt_ref",
    "admission_and_replay_refs",
    "admission_decision_ref",
    "participant_lease_ref",
    "request_hash",
    "runtimeTruthSource",
];

/// Reconstruct the ONLY valid submitted request + EXACT receipt from a sealed submit intent;
/// byte-compare both. The TRUSTED key is the intent's filename stem.
fn validate_submit_intent(
    intent: &Value,
    request_tail: &str,
) -> Result<(Value, String, Value), String> {
    if !is_canonical_request_tail(request_tail) {
        return Err("non-canonical request tail (storage key)".into());
    }
    let final_request = intent.get("final_request").cloned().unwrap_or(Value::Null);
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if intent.get("final_request_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_request, &[]).as_str())
    {
        return Err("final-request seal".into());
    }
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if !is_canonical_receipt_tail(&receipt_id, "rqr") {
        return Err("non-canonical submission receipt tail".into());
    }
    let request_id = format!("participation-request://{request_tail}");
    if intent.get("request_tail").and_then(Value::as_str) != Some(request_tail)
        || intent.get("request_ref").and_then(Value::as_str) != Some(request_id.as_str())
        || final_request
            .get("participation_request_id")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(request_id.as_str())
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
    {
        return Err("request identity does not bind to the storage key".into());
    }
    let now = final_request
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now) || final_request.get("created_at") != final_request.get("updated_at") {
        return Err("submission timestamps invalid".into());
    }
    // Reconstruct THROUGH the declaration validator + sealer.
    let mut declaration = final_request.clone();
    if let Some(obj) = declaration.as_object_mut() {
        for k in REQUEST_PLANE_OWNED {
            obj.remove(*k);
        }
    }
    let validated = validate_request_create(&declaration)
        .map_err(|(_, m)| format!("sealed declaration does not validate: {m}"))?;
    let receipt_ref = format!("receipt://{receipt_id}");
    let expected = seal_request(
        &validated,
        request_tail,
        &receipt_ref,
        now.as_str().unwrap_or(""),
    );
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&final_request).unwrap_or_default()
    {
        return Err("not the canonical sealed request".into());
    }
    let room_ref = s(&final_request, "outcome_room_ref", "");
    let expected_receipt = build_room_receipt_at(
        &receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "submitted",
        json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&final_request, "requested_by_ref", ""), "status_at_submission": "submitted" }),
        vec![json!(request_id), json!(room_ref)],
        record_output_hash(&expected, REQUEST_CREATE_EXCLUDES),
        REQUEST_CREATE_EXCLUDES,
        "admitted_not_verified",
        SUBMIT_NOTE,
        now.as_str().unwrap_or(""),
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical submission receipt".into());
    }
    Ok((final_request, receipt_id, receipt))
}

/// Reconstruct the ONLY valid single-record transition successor + EXACT receipt; byte-compare.
/// This is structural validation only; production replay remains quarantined until intents retain
/// a re-verifiable signed grant and the daemon can resolve the expected signer.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn validate_transition_intent(
    intent: &Value,
    prior: &Value,
    tail: &str,
    id_field: &str,
    id_prefix: &str,
    transitions: &[(&str, &[&str], &str)],
    receipt_prefix: &str,
    note: &str,
    canonical: fn(&str) -> bool,
) -> Result<(Value, String, Value), String> {
    if !canonical(tail) {
        return Err("non-canonical storage key".into());
    }
    let final_record = intent.get("final_record").cloned().unwrap_or(Value::Null);
    let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
    let receipt_id = intent
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if intent.get("final_record_hash").and_then(Value::as_str)
        != Some(record_output_hash(&final_record, &[]).as_str())
    {
        return Err("final-record seal".into());
    }
    if intent.get("receipt_hash").and_then(Value::as_str)
        != Some(record_output_hash(&receipt, &[]).as_str())
    {
        return Err("receipt seal".into());
    }
    if !is_canonical_receipt_tail(&receipt_id, receipt_prefix) {
        return Err("non-canonical transition receipt tail".into());
    }
    let record_id = format!("{id_prefix}{tail}");
    if prior.get(id_field).and_then(Value::as_str) != Some(record_id.as_str())
        || final_record.get(id_field).and_then(Value::as_str) != Some(record_id.as_str())
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(record_id.as_str())
        || receipt
            .pointer("/attested_boundary_fact_refs/0")
            .and_then(Value::as_str)
            != Some(record_id.as_str())
    {
        return Err("record identity does not bind to the storage key".into());
    }
    let now = final_record
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now) {
        return Err("transition updated_at not RFC3339".into());
    }
    let op = receipt.get("op").and_then(Value::as_str).unwrap_or("");
    let Some((_, allowed_from, to_status)) = transitions.iter().find(|(t, _, _)| *t == op) else {
        return Err("unknown transition op".into());
    };
    let from = prior.get("status").and_then(Value::as_str).unwrap_or("");
    if !allowed_from.contains(&from) {
        return Err("transition not admitted from prior status".into());
    }
    let prior_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    if receipt_ref.as_str() != Some(format!("receipt://{receipt_id}").as_str()) {
        return Err("receipt ref vs intent tail".into());
    }
    let expected = apply_transition(
        prior,
        "transition_intent",
        op,
        to_status,
        &receipt_ref,
        &now,
        op == "revoke",
    );
    if serde_json::to_vec(&expected).unwrap_or_default()
        != serde_json::to_vec(&final_record).unwrap_or_default()
    {
        return Err("not the deterministic successor".into());
    }
    // Reconstruct the decision receipt with the SEALED authority (#74 finding 1): the byte
    // compare requires the sealed receipt to carry a consistent actor/grant/policy binding AND
    // an output hash that still binds the reconstructed record.
    let expected_receipt = build_decision_receipt(
        &receipt_id,
        "RoomParticipationDecisionReceipt",
        &record_id,
        op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": prior_rev, "revision_after": prior_rev + 1, "outcome_room_ref": final_record.get("outcome_room_ref").cloned().unwrap_or(Value::Null) }),
        vec![
            json!(record_id),
            final_record
                .get("outcome_room_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ],
        record_output_hash(&expected, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        note,
        now.as_str().unwrap_or(""),
        &sealed_authority(&receipt),
    );
    if serde_json::to_vec(&expected_receipt).unwrap_or_default()
        != serde_json::to_vec(&receipt).unwrap_or_default()
    {
        return Err("not the canonical transition receipt".into());
    }
    Ok((final_record, receipt_id, receipt))
}

/// Reconstruct the ONLY valid admit outcome (terminal request + lease + BOTH receipts) from a
/// sealed admit intent; byte-compare all four. The TRUSTED key is the request record's stem.
fn validate_admit_intent(
    intent: &Value,
    prior_request: &Value,
    request_tail: &str,
) -> Result<(), String> {
    if !is_canonical_request_tail(request_tail) {
        return Err("non-canonical request tail (storage key)".into());
    }
    let final_request = intent.get("final_request").cloned().unwrap_or(Value::Null);
    let final_lease = intent.get("final_lease").cloned().unwrap_or(Value::Null);
    let params = intent.get("admit_params").cloned().unwrap_or(Value::Null);
    let lease_tail = intent
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_receipt_id = intent
        .get("lease_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_receipt = intent.get("lease_receipt").cloned().unwrap_or(Value::Null);
    let request_receipt_id = intent
        .get("request_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let request_receipt = intent
        .get("request_receipt")
        .cloned()
        .unwrap_or(Value::Null);
    for (field, sealed) in [
        ("final_request_hash", &final_request),
        ("final_lease_hash", &final_lease),
        ("lease_receipt_hash", &lease_receipt),
        ("request_receipt_hash", &request_receipt),
    ] {
        if intent.get(field).and_then(Value::as_str)
            != Some(record_output_hash(sealed, &[]).as_str())
        {
            return Err(format!("{field} seal"));
        }
    }
    if !is_canonical_lease_tail(lease_tail) {
        return Err("non-canonical lease tail".into());
    }
    if !is_canonical_receipt_tail(lease_receipt_id, "rlr")
        || !is_canonical_receipt_tail(request_receipt_id, "rqt")
    {
        return Err("non-canonical admit receipt tail".into());
    }
    let request_id = format!("participation-request://{request_tail}");
    let lease_id = format!("participant-lease://{lease_tail}");
    if prior_request
        .get("participation_request_id")
        .and_then(Value::as_str)
        != Some(request_id.as_str())
        || final_request
            .get("participation_request_id")
            .and_then(Value::as_str)
            != Some(request_id.as_str())
        || final_lease
            .get("participant_lease_id")
            .and_then(Value::as_str)
            != Some(lease_id.as_str())
    {
        return Err("identity does not bind to the storage keys".into());
    }
    let from = prior_request
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(from, "submitted" | "evaluating") {
        return Err("admit not admitted from prior status".into());
    }
    let now = final_request
        .get("updated_at")
        .cloned()
        .unwrap_or(Value::Null);
    if !is_rfc3339(&now)
        || final_lease.get("updated_at") != Some(&now)
        || final_lease.get("created_at") != Some(&now)
    {
        return Err("admit timestamps invalid".into());
    }
    let now_str = now.as_str().unwrap_or("");
    // Reconstruct the lease THROUGH the admit-params validator + lease constructor.
    let validated_params = validate_admit_params(&params)
        .map_err(|(_, m)| format!("sealed admit params do not validate: {m}"))?;
    if serde_json::to_vec(&validated_params).unwrap_or_default()
        != serde_json::to_vec(&params).unwrap_or_default()
    {
        return Err("admit params are not canonical".into());
    }
    let lease_receipt_ref = format!("receipt://{lease_receipt_id}");
    let expected_lease = build_lease(
        prior_request,
        &params,
        lease_tail,
        &lease_receipt_ref,
        now_str,
    );
    if serde_json::to_vec(&expected_lease).unwrap_or_default()
        != serde_json::to_vec(&final_lease).unwrap_or_default()
    {
        return Err("not the canonical lease".into());
    }
    // Reconstruct the terminal request successor.
    let prior_rev = prior_request
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let request_receipt_ref = json!(format!("receipt://{request_receipt_id}"));
    let mut expected_request = apply_transition(
        prior_request,
        "admit_intent",
        "admit",
        "admitted",
        &request_receipt_ref,
        &now,
        false,
    );
    if let Some(obj) = expected_request.as_object_mut() {
        obj.insert("participant_lease_ref".into(), json!(lease_id));
        obj.insert("admission_decision_ref".into(), request_receipt_ref.clone());
    }
    if serde_json::to_vec(&expected_request).unwrap_or_default()
        != serde_json::to_vec(&final_request).unwrap_or_default()
    {
        return Err("not the deterministic admitted request".into());
    }
    // Reconstruct BOTH decision receipts exactly, with the SEALED host authority (#74 finding 1).
    let room_ref = s(&final_lease, "outcome_room_ref", "");
    let expected_lease_receipt = build_decision_receipt(
        lease_receipt_id,
        "RoomParticipationDecisionReceipt",
        &lease_id,
        "admitted",
        json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": s(&final_lease, "admitted_role", ""), "join_request_ref": request_id, "status_at_admission": "active" }),
        vec![json!(lease_id), json!(room_ref), json!(request_id)],
        record_output_hash(&expected_lease, LEASE_CREATE_EXCLUDES),
        LEASE_CREATE_EXCLUDES,
        ADMIT_NOTE,
        now_str,
        &sealed_authority(&lease_receipt),
    );
    if serde_json::to_vec(&expected_lease_receipt).unwrap_or_default()
        != serde_json::to_vec(&lease_receipt).unwrap_or_default()
    {
        return Err("not the canonical lease receipt".into());
    }
    // BOTH admit receipts must carry the SAME sealed authority (one host decision, two receipts).
    for field in [
        "actor_id",
        "authority_grant_id",
        "policy_hash",
        "input_hash",
    ] {
        if lease_receipt.get(field) != request_receipt.get(field) {
            return Err("admit receipts carry inconsistent authority".into());
        }
    }
    let expected_request_receipt = build_decision_receipt(
        request_receipt_id,
        "RoomParticipationDecisionReceipt",
        &request_id,
        "admit",
        json!({ "transition": "admit", "from": from, "to": "admitted", "participant_lease_ref": lease_id, "revision_before": prior_rev, "revision_after": prior_rev + 1, "outcome_room_ref": room_ref }),
        vec![json!(request_id), json!(lease_id)],
        record_output_hash(&expected_request, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        ADMIT_NOTE,
        now_str,
        &sealed_authority(&request_receipt),
    );
    if serde_json::to_vec(&expected_request_receipt).unwrap_or_default()
        != serde_json::to_vec(&request_receipt).unwrap_or_default()
    {
        return Err("not the canonical admit receipt".into());
    }
    Ok(())
}

/// Safe cleanup for the old closed-room failure lane. This does NOT replay a governed decision:
/// after structural validation, it only removes an unlinearized intent when the room is gone or
/// closed, the proposed lease was never reserved, and every admission target is definitively
/// absent. Any evidence, unreadable slot, live room, or pending room mutation leaves the intent
/// quarantined for manual repair.
fn rollback_impossible_unlinearized_admit(
    data_dir: &str,
    request_tail: &str,
    prior_request: &Value,
    admit: &Value,
    _room_scope: &std::sync::MutexGuard<'_, ()>,
) -> Result<bool, VErr> {
    let room_ref = s(prior_request, "outcome_room_ref", "");
    let final_lease = admit.get("final_lease").cloned().unwrap_or(Value::Null);
    if s(&final_lease, "outcome_room_ref", "") != room_ref {
        return Ok(false);
    }
    let lease_tail = admit
        .get("lease_tail")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_id = format!("participant-lease://{lease_tail}");
    if s(&final_lease, "participant_lease_id", "") != lease_id {
        return Ok(false);
    }
    match rooms::resolve_room_strict(data_dir, &room_ref) {
        Ok(Some(room)) => {
            if rooms::pending_intent(&room).is_some() || s(&room, "status", "") == "open" {
                return Ok(false);
            }
            if room
                .get("participant_lease_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(lease_id.as_str()))
                })
            {
                return Ok(false);
            }
        }
        Ok(None) => {}
        Err(message) => {
            return Err(verr(
                "room_participation_room_unreadable",
                format!("room '{room_ref}' is not definitively absent or closed ({message}); the admit intent remains quarantined"),
            ))
        }
    }

    let lease_absent = matches!(
        read_slot_strict(data_dir, LEASE_DIR, lease_tail, is_canonical_lease_tail),
        Ok(None)
    );
    let lease_receipt_id = admit
        .get("lease_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let lease_receipt_absent = matches!(
        read_slot_strict(data_dir, RECEIPT_DIR, lease_receipt_id, |tail| {
            is_canonical_receipt_tail(tail, "rlr")
        }),
        Ok(None)
    );
    let request_receipt_id = admit
        .get("request_receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let request_receipt_absent = matches!(
        read_slot_strict(data_dir, RECEIPT_DIR, request_receipt_id, |tail| {
            is_canonical_receipt_tail(tail, "rqt")
        }),
        Ok(None)
    );
    if !(lease_absent && lease_receipt_absent && request_receipt_absent) {
        return Ok(false);
    }
    persist_atomic(data_dir, REQUEST_DIR, request_tail, prior_request).map_err(|failure| {
        verr(
            "room_participation_admit_pending_convergence",
            format!(
                "the impossible pre-linearization admit intent could not be rolled back exactly ({})",
                failure.detail()
            ),
        )
    })?;
    Ok(true)
}

// ================================ BOOT COMPLETER =================================================

/// Synchronous boot completer for the participation plane. Ungoverned submit intents are
/// canonically reconstructed and converged without network I/O. Governed admit/request/lease
/// decision intents retain their complete signed grant, root-signed binding proof, and authority
/// tuple, but remain quarantined here so resolver latency cannot delay listener readiness. The
/// post-readiness bounded completer re-resolves them. This pass only performs exact rollback of a
/// closed, definitively unlinearized admission and already-terminal non-decision room release.
pub(crate) fn complete_participation_intents(data_dir: &str) {
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // (1) Submit intents — internal family; the file STEM is the trusted request tail.
    let submit_intents = match scan_intent_family(data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: submit-intent scan failed ({e}) — retrying next boot, nothing converged");
            return;
        }
    };
    for (tail, intent) in submit_intents {
        match validate_submit_intent(&intent, &tail) {
            Ok((final_request, receipt_id, receipt)) => {
                // A request already at this identity must BE the sealed one.
                match read_slot_strict(data_dir, REQUEST_DIR, &tail, is_canonical_request_tail) {
                    Ok(Some(existing)) => {
                        // The existing record may have moved PAST submission (later receipted
                        // transitions); the sealed shape must match its admission lineage.
                        if existing.get("admission_receipt_ref")
                            != final_request.get("admission_receipt_ref")
                        {
                            eprintln!("participation completer: request '{tail}' exists with a DIFFERENT admission lineage — intent retained for manual repair");
                            continue;
                        }
                        if let Err(why) = consume_submit_intent(data_dir, &tail) {
                            eprintln!("participation completer: submit '{tail}' is already terminal but its replay intent could not be consumed ({why}) — retrying next boot");
                        }
                    }
                    Ok(None) => {
                        // Fixed order: participation lock (held by this completer) → room lock.
                        // A pending close may converge before the next boot; a completed close
                        // causes exact pre-linearization rollback with zero false evidence.
                        let room_scope = rooms::ROOM_MUTATION_LOCK
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        if let Err((code, msg)) = complete_submit(
                            data_dir,
                            &tail,
                            &final_request,
                            &receipt_id,
                            &receipt,
                            &room_scope,
                        ) {
                            eprintln!("participation completer: submit '{tail}' not converged ({code}: {msg}) — retrying next boot");
                        }
                    }
                    Err(e) => {
                        eprintln!("participation completer: request slot '{tail}' cannot be inspected ({e}) — refused, intent retained");
                    }
                }
            }
            Err(why) => {
                eprintln!("participation completer: submit intent '{tail}' fails canonical validation ({why}) — left in place for manual repair");
            }
        }
    }
    // (2) Request records carrying transition/admit intents.
    let requests = match scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: request scan failed ({e}) — retrying next boot");
            return;
        }
    };
    for (tail, record) in requests {
        if let Some(admit) = record.get("admit_intent").cloned() {
            let mut prior = record.clone();
            prior
                .as_object_mut()
                .expect("object")
                .remove("admit_intent");
            match validate_admit_intent(&admit, &prior, &tail) {
                Ok(()) => {
                    let room_scope = rooms::ROOM_MUTATION_LOCK
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    match rollback_impossible_unlinearized_admit(
                        data_dir,
                        &tail,
                        &prior,
                        &admit,
                        &room_scope,
                    ) {
                        Ok(true) => eprintln!("participation completer: admit '{tail}' targeted a closed/missing room before linearization — rolled back exactly with zero admission evidence"),
                        Ok(false) => eprintln!("participation completer: admit '{tail}' is QUARANTINED for bounded post-readiness authority re-resolution; no decision was applied"),
                        Err((code, msg)) => eprintln!("participation completer: admit '{tail}' cleanup is pending ({code}: {msg}) — no decision was applied"),
                    }
                }
                Err(why) => {
                    eprintln!("participation completer: admit intent on '{tail}' fails canonical validation ({why}) — left in place for manual repair");
                }
            }
        } else if record.get("transition_intent").is_some() {
            eprintln!("participation completer: request transition '{tail}' is QUARANTINED for bounded post-readiness authority re-resolution; no decision was applied");
        }
    }
    // (3) Lease records carrying transition intents.
    let leases = match scan_family(
        data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("participation completer: lease scan failed ({e}) — retrying next boot");
            return;
        }
    };
    for (tail, record) in leases {
        if record.get("transition_intent").is_some() {
            eprintln!("participation completer: lease transition '{tail}' is QUARANTINED for bounded post-readiness authority re-resolution; no decision was applied or released");
        } else if matches!(s(&record, "status", "").as_str(), "revoked" | "retired") {
            // Crash-convergence for the room-release step (#74 finding 3): a lease that reached
            // a terminal state but whose room slot was not released (crash between the terminal
            // lease write and the release bind) is released now — idempotent, so an
            // already-released lease is a no-op.
            if let Err((code, msg)) = ensure_lease_released(data_dir, &record) {
                eprintln!("participation completer: terminal lease '{tail}' room release is pending ({code}: {msg}) — retrying next boot");
            }
        }
    }
}

fn replay_host_authority(data_dir: &str, room_ref: &str) -> Result<String, String> {
    match rooms::resolve_room_strict(data_dir, room_ref) {
        Ok(Some(room)) => {
            let host = s(&room, "host_domain_ref", "");
            if host.is_empty() {
                Err(format!("room '{room_ref}' has no canonical host authority"))
            } else {
                Ok(host)
            }
        }
        Ok(None) => Err(format!("room '{room_ref}' no longer resolves")),
        Err(error) => Err(format!("room '{room_ref}' is unreadable: {error}")),
    }
}

async fn complete_live_transition_intent(
    data_dir: &str,
    family: &str,
    tail: &str,
    carrying: &Value,
    prior: &Value,
) -> Result<(), String> {
    let intent = carrying
        .get("transition_intent")
        .ok_or_else(|| "transition intent vanished".to_string())?;
    let coupled_work = match (
        intent
            .get("coupled_work_claim_intent_tail")
            .and_then(Value::as_str),
        intent.get("coupled_work_claim_intent"),
    ) {
        (None, None) => None,
        (Some(work_tail), Some(work_intent))
            if intent
                .get("coupled_work_claim_intent_hash")
                .and_then(Value::as_str)
                == Some(record_output_hash(work_intent, &[]).as_str()) =>
        {
            Some((work_tail.to_string(), work_intent.clone()))
        }
        _ => return Err("transition intent carries an incomplete or mismatched work-claim intent".into()),
    };
    let is_request = family == REQUEST_DIR;
    let (final_record, receipt_id, receipt) = validate_transition_intent(
        intent,
        prior,
        tail,
        if is_request {
            "participation_request_id"
        } else {
            "participant_lease_id"
        },
        if is_request {
            "participation-request://"
        } else {
            "participant-lease://"
        },
        if is_request {
            REQUEST_TRANSITIONS
        } else {
            LEASE_TRANSITIONS
        },
        if is_request { "rqt" } else { "rlt" },
        if is_request {
            REQUEST_TRANSITION_NOTE
        } else {
            LEASE_TRANSITION_NOTE
        },
        if is_request {
            is_canonical_request_tail
        } else {
            is_canonical_lease_tail
        },
    )?;
    let op = receipt
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "transition receipt has no operation".to_string())?;
    let gov = if is_request {
        request_op_gov(op)
    } else {
        lease_op_gov(op)
    };
    let room_ref = s(prior, "outcome_room_ref", "");
    let required_authority = match gov {
        Gov::Host => replay_host_authority(data_dir, &room_ref)?,
        Gov::Participant if is_request => s(prior, "requested_by_ref", ""),
        Gov::Participant => s(prior, "participant_ref", ""),
    };
    let subject_ref = if is_request {
        s(prior, "participation_request_id", "")
    } else {
        s(prior, "participant_lease_id", "")
    };
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    reauthorize_sealed_receipt(
        &receipt,
        gov,
        &room_ref,
        &required_authority,
        &subject_ref,
        op,
        revision,
    )
    .await?;

    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let current = if is_request {
        load_request(data_dir, tail)
    } else {
        load_lease(data_dir, tail)
    }
    .map_err(|error| format!("transition slot became unreadable: {error}"))?
    .ok_or_else(|| "transition slot vanished before convergence".to_string())?;
    if current != *carrying {
        return Err("transition slot changed after authority re-resolution".into());
    }
    if let Some((work_tail, work_intent)) = coupled_work {
        let _frontier_guard = super::work_frontier_claim_routes::FRONTIER_CLAIM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _room_guard = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        super::work_frontier_claim_routes::persist_embedded_intent_locked(
            data_dir,
            &work_tail,
            &work_intent,
        )
        .map_err(|error| error.1)?;
        persist_receipt(data_dir, &receipt_id, &receipt)
            .map_err(|(code, message)| format!("{code}: {message}"))?;
        persist_atomic(data_dir, family, tail, &final_record)
            .map_err(|failure| format!("terminal transition write is {}", failure.detail()))?;
        // The independently reauthorizing work completer owns claim/frontier/stamp convergence
        // and the final room-slot release. Persisting it before this terminal write closes the
        // crash window without widening participation authority into work-claim authority.
        return Ok(());
    }
    persist_receipt(data_dir, &receipt_id, &receipt)
        .map_err(|(code, message)| format!("{code}: {message}"))?;
    persist_atomic(data_dir, family, tail, &final_record)
        .map_err(|failure| format!("terminal transition write is {}", failure.detail()))?;
    if !is_request
        && matches!(
            s(&final_record, "status", "").as_str(),
            "revoked" | "retired"
        )
    {
        ensure_lease_released(data_dir, &final_record).map_err(|error| error.1)?;
    }
    Ok(())
}

async fn complete_live_admit_intent(
    data_dir: &str,
    tail: &str,
    carrying: &Value,
    prior: &Value,
    admit: &Value,
) -> Result<(), String> {
    validate_admit_intent(admit, prior, tail)?;
    let request_receipt = admit
        .get("request_receipt")
        .ok_or_else(|| "admit intent has no request receipt".to_string())?;
    let lease_receipt = admit
        .get("lease_receipt")
        .ok_or_else(|| "admit intent has no lease receipt".to_string())?;
    if sealed_authority(request_receipt) != sealed_authority(lease_receipt) {
        return Err("admit receipts do not retain the same complete authority tuple".into());
    }
    let room_ref = s(prior, "outcome_room_ref", "");
    let host = replay_host_authority(data_dir, &room_ref)?;
    reauthorize_sealed_receipt(
        request_receipt,
        Gov::Host,
        &room_ref,
        &host,
        &s(prior, "participation_request_id", ""),
        "admit",
        prior.get("revision").and_then(Value::as_u64).unwrap_or(0),
    )
    .await?;

    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let room_scope = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let current = load_request(data_dir, tail)
        .map_err(|error| format!("admit slot became unreadable: {error}"))?
        .ok_or_else(|| "admit slot vanished before convergence".to_string())?;
    if current != *carrying {
        return Err("admit slot changed after authority re-resolution".into());
    }
    complete_admit(data_dir, tail, prior, admit, &room_scope).map_err(|error| error.1)
}

/// Production boot pass for governed intents. The synchronous completer first converges the
/// ungated submission and release tails; this pass then re-resolves every retained decision
/// against its exact immutable coordinates and byte-compares the complete authority tuple before
/// applying the already sealed successor. Resolver absence/refusal leaves the intent untouched.
pub(crate) async fn complete_governed_participation_intents(data_dir: &str, max_intents: usize) {
    if max_intents == 0 {
        return;
    }
    let mut attempted = 0usize;
    let requests = match scan_family(
        data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    ) {
        Ok(records) => records,
        Err(error) => {
            eprintln!("participation governed completer: request scan failed ({error})");
            return;
        }
    };
    for (tail, carrying) in requests {
        if attempted >= max_intents {
            break;
        }
        let mut prior = carrying.clone();
        if let Some(admit) = prior
            .as_object_mut()
            .and_then(|object| object.remove("admit_intent"))
        {
            attempted += 1;
            if let Err(error) =
                complete_live_admit_intent(data_dir, &tail, &carrying, &prior, &admit).await
            {
                eprintln!("participation governed completer: admit '{tail}' retained ({error})");
            }
            continue;
        }
        if prior
            .as_object_mut()
            .and_then(|object| object.remove("transition_intent"))
            .is_some()
        {
            attempted += 1;
            if let Err(error) =
                complete_live_transition_intent(data_dir, REQUEST_DIR, &tail, &carrying, &prior)
                    .await
            {
                eprintln!("participation governed completer: request transition '{tail}' retained ({error})");
            }
        }
    }

    let leases = match scan_family(
        data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    ) {
        Ok(records) => records,
        Err(error) => {
            eprintln!("participation governed completer: lease scan failed ({error})");
            return;
        }
    };
    for (tail, carrying) in leases {
        if attempted >= max_intents {
            break;
        }
        let mut prior = carrying.clone();
        if prior
            .as_object_mut()
            .and_then(|object| object.remove("transition_intent"))
            .is_some()
        {
            attempted += 1;
            if let Err(error) =
                complete_live_transition_intent(data_dir, LEASE_DIR, &tail, &carrying, &prior).await
            {
                eprintln!("participation governed completer: lease transition '{tail}' retained ({error})");
            }
        }
    }
}

fn scan_intent_family(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, SUBMIT_INTENT_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("intent family could not be pinned ({e})")),
    };
    let names = super::durable_fs::enumerate_pinned(&dir)
        .map_err(|e| format!("intent family could not be enumerated ({e})"))?;
    scan_intent_entries(&dir, names)
}

fn scan_intent_entries(
    dir: &std::fs::File,
    names: Vec<String>,
) -> Result<Vec<(String, Value)>, String> {
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !is_canonical_request_tail(stem) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&dir, &name) {
            Ok(Some((_f, bytes))) => bytes,
            Ok(None) => {
                return Err(format!(
                    "canonical submit-intent slot '{name}' vanished after enumeration"
                ))
            }
            Err(e) => {
                return Err(format!(
                    "canonical submit-intent slot '{name}' is not readable as a regular file ({e})"
                ))
            }
        };
        let value = serde_json::from_slice::<Value>(&bytes).map_err(|e| {
            format!("canonical submit-intent slot '{name}' holds malformed JSON ({e})")
        })?;
        validate_submit_intent(&value, stem).map_err(|why| {
            format!("canonical submit-intent slot '{name}' is not canonical ({why})")
        })?;
        out.push((stem.to_string(), value));
    }
    Ok(out)
}

// ================================ HANDLERS =======================================================

fn http_err(status: StatusCode, (code, msg): VErr) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": msg } })),
    )
}

fn classify(e: VErr) -> (StatusCode, Json<Value>) {
    let status = if e.0.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if e.0.ends_with("_conflict")
        || e.0.ends_with("_in_flight")
        || e.0.ends_with("_already_bound")
        || e.0.ends_with("_duplicate")
    {
        StatusCode::CONFLICT
    } else if e.0.ends_with("_persist_failed")
        || e.0.ends_with("_pending_convergence")
        || e.0.ends_with("_durability_unconfirmed")
        || e.0.ends_with("_unreadable")
        || e.0.ends_with("_swapped")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    http_err(status, e)
}

/// POST /v1/hypervisor/room-participation-requests — a typed admission request; admits as
/// `submitted` with a receipt, bound into the room through the room-owned seam.
pub(crate) async fn handle_participation_request_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let declaration = match validate_request_create(&body) {
        Ok(d) => d,
        Err(e) => return classify(e),
    };
    let room_ref = s(&declaration, "outcome_room_ref", "");
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Fixed lock order: participation → room. Hold the room lock from exact status/intent
    // validation through the room-first submit finalizer so close cannot win in between.
    let room_scope = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let room = match rooms::resolve_room_strict(&st.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            return classify(verr(
                "room_participation_room_not_found",
                format!("no admitted room '{room_ref}' — participation binds only to a live hosted room"),
            ))
        }
        Err(message) if message.starts_with("non-canonical room stem") => {
            return classify(verr(
                "room_participation_room_not_found",
                format!("no admitted room '{room_ref}' — participation binds only to a canonical hosted room"),
            ))
        }
        Err(message) => {
            return classify(verr(
                "room_participation_room_unreadable",
                format!("room '{room_ref}' cannot be resolved strictly ({message})"),
            ))
        }
    };
    if let Some((field, code)) = rooms::pending_intent(&room) {
        return classify(verr(
            code,
            format!("a durable {field} is pending on room '{room_ref}' — a restart converges it before request submission"),
        ));
    }
    if s(&room, "status", "") != "open" {
        return classify(verr(
            "room_participation_room_not_open",
            format!(
                "room '{room_ref}' is '{}' — requests bind only to an OPEN room",
                s(&room, "status", "?")
            ),
        ));
    }
    if s(&room, "host_domain_ref", "") != s(&declaration, "admission_owner_ref", "") {
        return classify(verr("room_participation_admission_owner_mismatch", format!("`admission_owner_ref` must equal the room's host domain '{}' — the hosted owner is not negotiable per request", s(&room, "host_domain_ref", "?"))));
    }
    match live_request_exists(&st.data_dir, &room_ref, &s(&declaration, "requested_by_ref", "")) {
        Ok(true) => return classify(verr("room_participation_request_duplicate", "a live (submitted/evaluating) request by this principal already exists for this room — withdraw it or await the decision")),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    match live_lease_exists(
        &st.data_dir,
        &room_ref,
        &s(&declaration, "requested_by_ref", ""),
    ) {
        Ok(true) => return classify(verr(
            "room_participation_request_duplicate",
            "this principal already holds a live lease in this room — one participant, one lease",
        )),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    let now = iso_now();
    let tail = format!("rpr_{:x}", nanos());
    let receipt_id = format!("rqr_{:x}", nanos());
    let receipt_ref = format!("receipt://{receipt_id}");
    let record = seal_request(&declaration, &tail, &receipt_ref, &now);
    let request_id = s(&record, "participation_request_id", "");
    let receipt = build_room_receipt_at(
        &receipt_id,
        REQUEST_RECEIPT_SCHEMA,
        "RoomParticipationRequestReceipt",
        &request_id,
        "submitted",
        json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
        vec![json!(request_id), json!(room_ref)],
        record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
        REQUEST_CREATE_EXCLUDES,
        "admitted_not_verified",
        SUBMIT_NOTE,
        &now,
    );
    if let Err(e) = finalize_submit(
        &st.data_dir,
        &tail,
        &record,
        &receipt_id,
        &receipt,
        &room_scope,
    ) {
        return classify(e);
    }
    (
        StatusCode::CREATED,
        Json(json!({ "participation_request": record, "participation_request_receipt": receipt })),
    )
}

/// GET /v1/hypervisor/room-participation-requests[?room=outcome-room://…]
pub(crate) async fn handle_participation_requests_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    match scan_family(
        &st.data_dir,
        REQUEST_DIR,
        "participation_request_id",
        "participation-request://",
        is_canonical_request_tail,
    ) {
        Ok(items) => {
            let mut rows: Vec<Value> = items
                .into_iter()
                .map(|(_, r)| r)
                .filter(|r| {
                    q.get("room")
                        .map(|room| s(r, "outcome_room_ref", "") == *room)
                        .unwrap_or(true)
                })
                .collect();
            rows.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
            (
                StatusCode::OK,
                Json(
                    json!({ "schema_version": REQUEST_SCHEMA, "participation_requests": rows, "request_statuses": REQUEST_STATUSES, "request_transitions": REQUEST_TRANSITIONS.iter().map(|(t, from, to)| json!({ "transition": t, "from": from, "to": to, "available": false, "unavailable_code": "room_participation_authority_binding_unavailable" })).collect::<Vec<_>>(), "admit_available": false, "decision_authority_posture": decision_authority_posture(), "runtimeTruthSource": "daemon-runtime" }),
                ),
            )
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("room_participation_registry_unreadable", e),
        ),
    }
}

/// GET /v1/hypervisor/room-participation-requests/:id
pub(crate) async fn handle_participation_request_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_request(&st.data_dir, &id) {
        Ok(Some(r)) => (StatusCode::OK, Json(json!({ "participation_request": r }))),
        Ok(None) => http_err(
            StatusCode::NOT_FOUND,
            verr(
                "room_participation_request_not_found",
                format!("no participation request '{id}'"),
            ),
        ),
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("room_participation_registry_unreadable", e),
        ),
    }
}

/// POST /v1/hypervisor/room-participation-requests/:id/transition
pub(crate) async fn handle_participation_request_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return classify(e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return classify(verr(
                "room_participation_transition_invalid",
                format!(
                    "`transition` is required — request lifecycle: [{}]",
                    REQUEST_TRANSITIONS
                        .iter()
                        .map(|(t, _, _)| *t)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            ))
        }
        Err(e) => return classify(e),
    };
    if let Some((_, why)) = UNAVAILABLE_REQUEST_TRANSITIONS
        .iter()
        .find(|(t, _)| *t == transition)
    {
        return classify(verr(
            "room_participation_transition_unavailable",
            format!("transition '{transition}' needs {why}"),
        ));
    }
    let Some((_, allowed_from, to_status)) = REQUEST_TRANSITIONS
        .iter()
        .find(|(t, _, _)| *t == transition)
    else {
        return classify(verr(
            "room_participation_transition_invalid",
            format!(
                "unknown transition '{transition}' — request lifecycle: [{}]",
                REQUEST_TRANSITIONS
                    .iter()
                    .map(|(t, _, _)| *t)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // AUTHORITY (#74 review finding 1): the decision is gated BEFORE any mutation. evaluate/reject
    // are host-governed; withdraw is the participant's own.
    let prior = match load_request(&st.data_dir, &id) {
        Ok(Some(prior)) => prior,
        Ok(None) => {
            return classify(verr(
                "room_participation_request_not_found",
                format!("no participation request '{id}'"),
            ))
        }
        Err(e) => return classify(verr("room_participation_registry_unreadable", e)),
    };
    let gov = request_op_gov(&transition);
    let room_ref = s(&prior, "outcome_room_ref", "");
    let subject_ref = s(&prior, "participation_request_id", "");
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let required_authority = match gov {
        Gov::Host => match rooms::resolve_room_host(&st.data_dir, &room_ref) {
            Some(h) => h,
            None => return classify(verr("room_participation_room_not_found", format!("the request's room '{room_ref}' no longer resolves — its host authority cannot be established"))),
        },
        Gov::Participant => s(&prior, "requested_by_ref", ""),
    };
    drop(_guard);
    let auth = match authorize_decision(
        &body,
        gov,
        &room_ref,
        &required_authority,
        &subject_ref,
        &transition,
        revision,
    )
    .await
    {
        Ok(a) => a,
        Err(challenge) => return challenge,
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    match transition_record(
        &st.data_dir,
        REQUEST_DIR,
        &id,
        &body,
        transition.as_str(),
        allowed_from,
        to_status,
        "participation-request://",
        "rqt",
        REQUEST_TRANSITION_NOTE,
        "room_participation",
        &auth,
    ) {
        Ok((record, receipt)) => (
            StatusCode::OK,
            Json(
                json!({ "participation_request": record, "participation_request_receipt": receipt }),
            ),
        ),
        Err(e) => classify(e),
    }
}

/// The shared single-record transition core (request + lease).
#[allow(clippy::too_many_arguments)]
fn transition_record(
    data_dir: &str,
    family: &str,
    tail: &str,
    body: &Value,
    op: &str,
    allowed_from: &[&str],
    to_status: &str,
    id_prefix: &str,
    receipt_prefix: &str,
    note: &str,
    code_ns: &str,
    auth: &DecisionAuthority,
) -> Result<(Value, Value), VErr> {
    transition_record_with_terminal_release(
        data_dir,
        family,
        tail,
        body,
        op,
        allowed_from,
        to_status,
        id_prefix,
        receipt_prefix,
        note,
        code_ns,
        auth,
        true,
    )
}

struct RecordTransitionPlan {
    prior: Value,
    updated: Value,
    receipt_id: String,
    receipt: Value,
}

#[allow(clippy::too_many_arguments)]
fn plan_record_transition(
    data_dir: &str,
    family: &str,
    tail: &str,
    body: &Value,
    op: &str,
    allowed_from: &[&str],
    to_status: &str,
    id_prefix: &str,
    receipt_prefix: &str,
    note: &str,
    code_ns: &str,
    auth: &DecisionAuthority,
) -> Result<RecordTransitionPlan, VErr> {
    let (loader, nf_code, unreadable_code): (
        fn(&str, &str) -> Result<Option<Value>, String>,
        &str,
        &str,
    ) = if family == REQUEST_DIR {
        (
            load_request,
            "room_participation_request_not_found",
            "room_participation_registry_unreadable",
        )
    } else {
        (
            load_lease,
            "participant_lease_not_found",
            "participant_lease_registry_unreadable",
        )
    };
    let prior = match loader(data_dir, tail) {
        Ok(Some(prior)) => prior,
        Ok(None) => return Err(verr(nf_code, format!("no record '{tail}'"))),
        Err(error) => return Err(verr(unreadable_code, error)),
    };
    if let Some((field, code)) = pending_intent(&prior) {
        return Err(verr(code, format!("a durable {field} is pending on this record — governed replay is quarantined until its authority can be reverified")));
    }
    if family == LEASE_DIR {
        let room_ref = s(&prior, "outcome_room_ref", "");
        match rooms::resolve_open_room(data_dir, &room_ref) {
            Some(room) if s(&room, "status", "") == "open" => {}
            _ => return Err(verr("participant_lease_room_not_open", format!("the lease's room '{room_ref}' is not open — no lease transition is admitted once the room has left `open`"))),
        }
    }
    let from = s(&prior, "status", "");
    if !allowed_from.contains(&from.as_str()) {
        return Err(verr(
            &format!("{code_ns}_transition_invalid"),
            format!(
                "transition '{op}' is not admitted from status '{from}' (allowed from: [{}])",
                allowed_from.join("|")
            ),
        ));
    }
    let current_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    check_expected_revision(body, current_rev)
        .map_err(|(_, message)| verr(&format!("{code_ns}_revision_conflict"), message))?;
    let now = iso_now();
    let receipt_id = format!("{receipt_prefix}_{:x}", nanos());
    let record_id = format!("{id_prefix}{tail}");
    let receipt_ref = json!(format!("receipt://{receipt_id}"));
    let updated = apply_transition(
        &prior,
        "transition_intent",
        op,
        to_status,
        &receipt_ref,
        &json!(now),
        op == "revoke",
    );
    let receipt = build_decision_receipt(
        &receipt_id,
        "RoomParticipationDecisionReceipt",
        &record_id,
        op,
        json!({ "transition": op, "from": from, "to": to_status, "revision_before": current_rev, "revision_after": current_rev + 1, "outcome_room_ref": updated.get("outcome_room_ref").cloned().unwrap_or(Value::Null) }),
        vec![
            json!(record_id),
            updated
                .get("outcome_room_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ],
        record_output_hash(&updated, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        note,
        &now,
        auth,
    );
    Ok(RecordTransitionPlan {
        prior,
        updated,
        receipt_id,
        receipt,
    })
}

#[allow(clippy::too_many_arguments)]
fn transition_record_with_terminal_release(
    data_dir: &str,
    family: &str,
    tail: &str,
    body: &Value,
    op: &str,
    allowed_from: &[&str],
    to_status: &str,
    id_prefix: &str,
    receipt_prefix: &str,
    note: &str,
    code_ns: &str,
    auth: &DecisionAuthority,
    release_terminal_room_slot: bool,
) -> Result<(Value, Value), VErr> {
    let plan = plan_record_transition(
        data_dir,
        family,
        tail,
        body,
        op,
        allowed_from,
        to_status,
        id_prefix,
        receipt_prefix,
        note,
        code_ns,
        auth,
    )?;
    finalize_record_transition(
        data_dir,
        family,
        tail,
        &plan.prior,
        &plan.updated,
        &plan.receipt_id,
        &plan.receipt,
    )?;
    // A lease reaching a TERMINAL state (revoked/retired) releases its room slot (#74 review
    // finding 2), through the room-owned seam — the room's live-lease set shrinks by one, so a
    // room with no remaining live participants can close. Idempotent + crash-convergent (the
    // completer re-drives it). The lease transition may already be durable, but the HTTP
    // operation is not complete until this second plane converges: return typed pending rather
    // than falsely reporting 200.
    if release_terminal_room_slot
        && family == LEASE_DIR
        && matches!(to_status, "revoked" | "retired")
    {
        ensure_lease_released(data_dir, &plan.updated)?;
    }
    Ok((plan.updated, plan.receipt))
}

/// Release a terminal lease's room slot through the room-owned seam (#74 finding 2). Idempotent:
/// an already-released ref converges. Any incomplete cross-plane release is surfaced as typed
/// pending convergence; the boot completer retries it.
fn ensure_lease_released(data_dir: &str, lease: &Value) -> Result<(), VErr> {
    let room_ref = s(lease, "outcome_room_ref", "");
    let lease_id = s(lease, "participant_lease_id", "");
    if room_ref.is_empty() || lease_id.is_empty() {
        return Err(verr(
            "participant_lease_release_pending_convergence",
            "the terminal lease is missing its room or lease identity — its room slot cannot be released automatically",
        ));
    }
    if lease
        .get("current_claim_ref")
        .is_some_and(|claim| !claim.is_null())
    {
        return Err(verr(
            "participant_lease_claim_release_pending_convergence",
            format!(
                "terminal lease '{lease_id}' still carries current claim '{}'; the claim must converge before its room slot can be released",
                s(lease, "current_claim_ref", "")
            ),
        ));
    }
    match rooms::bind_room_backlink(data_dir, &room_ref, "participant_lease_released", &lease_id) {
        Ok(_) => Ok(()),
        Err((code, _)) if code == "outcome_room_backlink_already_bound" => Ok(()),
        Err((code, msg)) => Err(verr(
            "participant_lease_release_pending_convergence",
            format!("terminal lease '{lease_id}' is durable but its room release is incomplete ({code}: {msg}); restart convergence will retry the same release"),
        )),
    }
}

/// POST /v1/hypervisor/room-participation-requests/:id/admit — the hosted owner's admitted
/// decision: terminal request + bounded ACTIVE lease + room backlink in ONE finalization.
pub(crate) async fn handle_participation_request_admit(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let params = match validate_admit_params(&body) {
        Ok(p) => p,
        Err(e) => return classify(e),
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Fixed lock order: participation → room. Hold the room lock from exact status/intent
    // validation through the room-first admission finalizer so close cannot win in between.
    let room_scope = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let prior = match load_request(&st.data_dir, &id) {
        Ok(Some(prior)) => prior,
        Ok(None) => {
            return classify(verr(
                "room_participation_request_not_found",
                format!("no participation request '{id}'"),
            ))
        }
        Err(e) => return classify(verr("room_participation_registry_unreadable", e)),
    };
    if let Some((field, code)) = pending_intent(&prior) {
        return classify(verr(
            code,
            format!("a durable {field} is pending on this record — governed replay is quarantined until its authority can be reverified"),
        ));
    }
    let from = s(&prior, "status", "");
    if !matches!(from.as_str(), "submitted" | "evaluating") {
        return classify(verr(
            "room_participation_transition_invalid",
            format!(
                "admit is not admitted from status '{from}' (allowed from: [submitted|evaluating])"
            ),
        ));
    }
    let current_rev = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Err((_, m)) = check_expected_revision(&body, current_rev) {
        return classify(verr("room_participation_revision_conflict", m));
    }
    let room_ref = s(&prior, "outcome_room_ref", "");
    match live_lease_exists(&st.data_dir, &room_ref, &s(&prior, "requested_by_ref", "")) {
        Ok(true) => return classify(verr("participant_lease_duplicate", "this principal already holds a live lease in this room — one participant, one lease; revoke or retire the existing lease first")),
        Ok(false) => {}
        Err(e) => return classify(e),
    }
    // Exact missing/pending/closed distinctions while the room scope is held. This check and
    // the room-first backlink transaction below are one critical section.
    let room = match rooms::resolve_room_strict(&st.data_dir, &room_ref) {
        Ok(Some(room)) => room,
        Ok(None) => {
            return classify(verr(
                "room_participation_room_not_found",
                format!("room '{room_ref}' does not resolve — admission refuses"),
            ))
        }
        Err(message) => {
            return classify(verr(
                "room_participation_room_unreadable",
                format!("room '{room_ref}' cannot be resolved strictly ({message})"),
            ))
        }
    };
    if let Some((field, code)) = rooms::pending_intent(&room) {
        return classify(verr(
            code,
            format!("a durable {field} is pending on room '{room_ref}' — admission waits for room convergence"),
        ));
    }
    if s(&room, "status", "") != "open" {
        return classify(verr(
            "room_participation_room_not_open",
            format!(
                "room '{room_ref}' is '{}' — admission is admitted only while the room is open",
                s(&room, "status", "?")
            ),
        ));
    };
    // AUTHORITY (#74 review finding 1): admission is a HOST decision — the room's host domain
    // must authorize it, bound to THIS request + revision. Gated BEFORE the lease is minted.
    let request_id = s(&prior, "participation_request_id", "");
    let host_authority = s(&room, "host_domain_ref", "");
    drop(room_scope);
    drop(_guard);
    let auth = match authorize_decision(
        &body,
        Gov::Host,
        &room_ref,
        &host_authority,
        &request_id,
        "admit",
        current_rev,
    )
    .await
    {
        Ok(a) => a,
        Err(challenge) => return challenge,
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let room_scope = rooms::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    match load_request(&st.data_dir, &id) {
        Ok(Some(current)) if current == prior => {}
        Ok(Some(_)) => {
            return classify(verr(
                "room_participation_revision_conflict",
                "the request changed while wallet.network resolved authority; retry against the current revision",
            ))
        }
        Ok(None) => {
            return classify(verr(
                "room_participation_request_not_found",
                format!("no participation request '{id}'"),
            ))
        }
        Err(error) => return classify(verr("room_participation_registry_unreadable", error)),
    }
    match live_lease_exists(&st.data_dir, &room_ref, &s(&prior, "requested_by_ref", "")) {
        Ok(true) => return classify(verr(
            "participant_lease_duplicate",
            "this principal already holds a live lease in this room — one participant, one lease",
        )),
        Ok(false) => {}
        Err(error) => return classify(error),
    }
    match rooms::resolve_room_strict(&st.data_dir, &room_ref) {
        Ok(Some(current_room))
            if s(&current_room, "status", "") == "open"
                && rooms::pending_intent(&current_room).is_none()
                && s(&current_room, "host_domain_ref", "") == host_authority => {}
        Ok(Some(_)) => {
            return classify(verr(
                "room_participation_room_not_open",
                format!("room '{room_ref}' changed while authority resolved; admission refuses"),
            ))
        }
        Ok(None) => {
            return classify(verr(
                "room_participation_room_not_found",
                format!("room '{room_ref}' does not resolve"),
            ))
        }
        Err(error) => return classify(verr("room_participation_room_unreadable", error)),
    }
    let now = iso_now();
    let lease_tail = format!("rpl_{:x}", nanos());
    let lease_receipt_id = format!("rlr_{:x}", nanos());
    let request_receipt_id = format!("rqt_{:x}", nanos());
    let lease_receipt_ref = format!("receipt://{lease_receipt_id}");
    let request_receipt_ref = json!(format!("receipt://{request_receipt_id}"));
    let lease_id = format!("participant-lease://{lease_tail}");
    let final_lease = build_lease(&prior, &params, &lease_tail, &lease_receipt_ref, &now);
    let now_v = json!(now);
    let mut final_request = apply_transition(
        &prior,
        "admit_intent",
        "admit",
        "admitted",
        &request_receipt_ref,
        &now_v,
        false,
    );
    if let Some(obj) = final_request.as_object_mut() {
        obj.insert("participant_lease_ref".into(), json!(lease_id));
        obj.insert("admission_decision_ref".into(), request_receipt_ref.clone());
    }
    let lease_receipt = build_decision_receipt(
        &lease_receipt_id,
        "RoomParticipationDecisionReceipt",
        &lease_id,
        "admitted",
        json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": s(&final_lease, "admitted_role", ""), "join_request_ref": request_id, "status_at_admission": "active" }),
        vec![json!(lease_id), json!(room_ref), json!(request_id)],
        record_output_hash(&final_lease, LEASE_CREATE_EXCLUDES),
        LEASE_CREATE_EXCLUDES,
        ADMIT_NOTE,
        &now,
        &auth,
    );
    let request_receipt = build_decision_receipt(
        &request_receipt_id,
        "RoomParticipationDecisionReceipt",
        &request_id,
        "admit",
        json!({ "transition": "admit", "from": from, "to": "admitted", "participant_lease_ref": lease_id, "revision_before": current_rev, "revision_after": current_rev + 1, "outcome_room_ref": room_ref }),
        vec![json!(request_id), json!(lease_id)],
        record_output_hash(&final_request, TRAIL_EXCLUDES),
        TRAIL_EXCLUDES,
        ADMIT_NOTE,
        &now,
        &auth,
    );
    let admit = json!({
        "kind": "admit",
        "lease_tail": lease_tail,
        "admit_params": params,
        "final_request": final_request,
        "final_request_hash": record_output_hash(&final_request, &[]),
        "final_lease": final_lease,
        "final_lease_hash": record_output_hash(&final_lease, &[]),
        "lease_receipt_id": lease_receipt_id,
        "lease_receipt": lease_receipt,
        "lease_receipt_hash": record_output_hash(&lease_receipt, &[]),
        "request_receipt_id": request_receipt_id,
        "request_receipt": request_receipt,
        "request_receipt_hash": record_output_hash(&request_receipt, &[]),
        "at": now,
    });
    if let Err(e) = finalize_admit(&st.data_dir, &id, &prior, &admit, &room_scope) {
        return classify(e);
    }
    (
        StatusCode::OK,
        Json(
            json!({ "participation_request": final_request, "participant_lease": final_lease, "participant_lease_receipt": lease_receipt, "participation_request_receipt": request_receipt }),
        ),
    )
}

/// GET /v1/hypervisor/room-participant-leases[?room=…]
pub(crate) async fn handle_participant_leases_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    match scan_family(
        &st.data_dir,
        LEASE_DIR,
        "participant_lease_id",
        "participant-lease://",
        is_canonical_lease_tail,
    ) {
        Ok(items) => {
            let mut rows: Vec<Value> = items
                .into_iter()
                .map(|(_, r)| r)
                .filter(|r| {
                    q.get("room")
                        .map(|room| s(r, "outcome_room_ref", "") == *room)
                        .unwrap_or(true)
                })
                .collect();
            rows.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
            (
                StatusCode::OK,
                Json(
                    json!({ "schema_version": LEASE_SCHEMA, "participant_leases": rows, "lease_statuses": LEASE_STATUSES, "lease_transitions": LEASE_TRANSITIONS.iter().map(|(t, from, to)| json!({ "transition": t, "from": from, "to": to, "available": false, "unavailable_code": "room_participation_authority_binding_unavailable" })).collect::<Vec<_>>(), "decision_authority_posture": decision_authority_posture(), "admitted_roles": ADMITTED_ROLES, "runtimeTruthSource": "daemon-runtime" }),
                ),
            )
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("participant_lease_registry_unreadable", e),
        ),
    }
}

/// GET /v1/hypervisor/room-participant-leases/:id
pub(crate) async fn handle_participant_lease_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_lease(&st.data_dir, &id) {
        Ok(Some(r)) => (StatusCode::OK, Json(json!({ "participant_lease": r }))),
        Ok(None) => http_err(
            StatusCode::NOT_FOUND,
            verr(
                "participant_lease_not_found",
                format!("no participant lease '{id}'"),
            ),
        ),
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            verr("participant_lease_registry_unreadable", e),
        ),
    }
}

/// POST /v1/hypervisor/room-participant-leases/:id/transition
pub(crate) async fn handle_participant_lease_transition(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = reject_sensitive_keys(&body, "") {
        return classify(e);
    }
    let transition = match str_opt_bounded(&body, "transition", 40) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return classify(verr(
                "participant_lease_transition_invalid",
                format!(
                    "`transition` is required — lease lifecycle: [{}]",
                    LEASE_TRANSITIONS
                        .iter()
                        .map(|(t, _, _)| *t)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            ))
        }
        Err(e) => return classify(e),
    };
    if let Some((_, why)) = UNAVAILABLE_LEASE_TRANSITIONS
        .iter()
        .find(|(t, _)| *t == transition)
    {
        return classify(verr(
            "participant_lease_transition_unavailable",
            format!("transition '{transition}' needs {why} — a named gap, never faked"),
        ));
    }
    let Some((_, allowed_from, to_status)) =
        LEASE_TRANSITIONS.iter().find(|(t, _, _)| *t == transition)
    else {
        return classify(verr(
            "participant_lease_transition_invalid",
            format!(
                "unknown transition '{transition}' — lease lifecycle: [{}]",
                LEASE_TRANSITIONS
                    .iter()
                    .map(|(t, _, _)| *t)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // AUTHORITY (#74 review finding 1): administrative transitions (suspend/resume/quarantine/
    // release_quarantine/revoke) are host-governed; self-state (sleep/wake/wait/activate/retire)
    // is the participant's own. Gated BEFORE any mutation.
    let prior = match load_lease(&st.data_dir, &id) {
        Ok(Some(prior)) => prior,
        Ok(None) => {
            return classify(verr(
                "participant_lease_not_found",
                format!("no participant lease '{id}'"),
            ))
        }
        Err(e) => return classify(verr("participant_lease_registry_unreadable", e)),
    };
    let gov = lease_op_gov(&transition);
    let room_ref = s(&prior, "outcome_room_ref", "");
    let subject_ref = s(&prior, "participant_lease_id", "");
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let required_authority = match gov {
        Gov::Host => match rooms::resolve_room_host(&st.data_dir, &room_ref) {
            Some(h) => h,
            None => return classify(verr("participant_lease_room_not_open", format!("the lease's room '{room_ref}' no longer resolves — its host authority cannot be established"))),
        },
        Gov::Participant => s(&prior, "participant_ref", ""),
    };
    drop(_guard);
    let auth = match authorize_decision(
        &body,
        gov,
        &room_ref,
        &required_authority,
        &subject_ref,
        &transition,
        revision,
    )
    .await
    {
        Ok(a) => a,
        Err(challenge) => return challenge,
    };
    // Terminal participation is a compound governed operation when a current work claim exists.
    // Resolve BOTH grants before reacquiring synchronous locks; the work-claim grant has its own
    // scope and exact claim revision and is never inferred from room-participation authority.
    let prepared_claim = if matches!(transition.as_str(), "retire" | "revoke") {
        match super::work_frontier_claim_routes::prepare_participant_terminal_claim(
            &st.data_dir,
            &prior,
            &transition,
            &body,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(response) => return response,
        }
    } else {
        None
    };
    let _guard = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(prepared) = prepared_claim {
        let plan = match plan_record_transition(
            &st.data_dir,
            LEASE_DIR,
            &id,
            &body,
            transition.as_str(),
            allowed_from,
            to_status,
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &auth,
        ) {
            Ok(plan) => plan,
            Err(error) => return classify(error),
        };
        let _frontier_guard = super::work_frontier_claim_routes::FRONTIER_CLAIM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _room_guard = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (work_intent_tail, work_intent) =
            match super::work_frontier_claim_routes::build_participant_terminal_claim_intent_locked(
                &st.data_dir,
                prepared,
                &plan.updated,
            ) {
                Ok(value) => value,
                Err(error) => return classify(error),
            };
        if let Err(error) = finalize_record_transition_with_work_claim(
            &st.data_dir,
            LEASE_DIR,
            &id,
            &plan,
            &work_intent_tail,
            &work_intent,
        ) {
            return classify(error);
        }
        if let Err(error) =
            super::work_frontier_claim_routes::complete_embedded_intent_locked(
                &st.data_dir,
                &work_intent_tail,
                &work_intent,
            )
        {
            return classify(error);
        }
        return (
            StatusCode::OK,
            Json(json!({
                "participant_lease": work_intent.get("final_participant").cloned().unwrap_or(Value::Null),
                "participant_lease_receipt": plan.receipt,
                "released_work_claim": work_intent.get("final_claim").cloned().unwrap_or(Value::Null),
                "frontier_item": work_intent.get("final_frontier").cloned().unwrap_or(Value::Null),
                "work_claim_receipt": work_intent.get("receipt").cloned().unwrap_or(Value::Null),
            })),
        );
    }
    match transition_record_with_terminal_release(
        &st.data_dir,
        LEASE_DIR,
        &id,
        &body,
        transition.as_str(),
        allowed_from,
        to_status,
        "participant-lease://",
        "rlt",
        LEASE_TRANSITION_NOTE,
        "participant_lease",
        &auth,
        false,
    ) {
        Ok((record, receipt)) => {
            let response = json!({
                "participant_lease": record,
                "participant_lease_receipt": receipt,
            });
            if matches!(transition.as_str(), "retire" | "revoke") {
                if let Err(error) = ensure_lease_released(&st.data_dir, &record) {
                    return classify(error);
                }
            }
            (StatusCode::OK, Json(response))
        }
        Err(e) => classify(e),
    }
}

// ====================================== TESTS ====================================================

#[cfg(test)]
mod participation_tests {
    use super::*;

    // Existing transaction tests use terse Option-style fixtures. Production callers use the
    // strict Result-returning point loaders above; these wrappers keep fixture setup readable
    // without collapsing errors anywhere on the daemon surface.
    fn load_request(data_dir: &str, tail: &str) -> Option<Value> {
        super::load_request(data_dir, tail).expect("test request slot must be readable")
    }

    fn load_lease(data_dir: &str, tail: &str) -> Option<Value> {
        super::load_lease(data_dir, tail).expect("test lease slot must be readable")
    }

    fn scan_requests(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
        scan_family(
            data_dir,
            REQUEST_DIR,
            "participation_request_id",
            "participation-request://",
            is_canonical_request_tail,
        )
    }

    fn scan_leases(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
        scan_family(
            data_dir,
            LEASE_DIR,
            "participant_lease_id",
            "participant-lease://",
            is_canonical_lease_tail,
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ioi-participation-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fixed decision authority for lower-seam transaction/structural-validation tests. It is
    /// intentionally NOT authorization: production online gates refuse it, and boot quarantines
    /// governed intents whose authority cannot be reverified against an expected signer.
    fn ta() -> DecisionAuthority {
        DecisionAuthority {
            acting_authority_id: json!("wallet://acct_test_authority"),
            grant_ref: "wallet.network://grant/approval/testgranthash".to_string(),
            policy_hash: "sha256:testpolicyhash".to_string(),
            request_hash: "sha256:testrequesthash".to_string(),
            wallet_approval_grant: Value::Null,
            authority_binding: Value::Null,
        }
    }

    /// Mint the same real Ed25519 ApprovalGrant used by the live fixture, with caller-selected
    /// signer seed and exact daemon-derived hashes. This lets the unit test distinguish
    /// same-hashes/different-signer from the older, weaker different-hashes case.
    fn signed_grant(seed_byte: u8, policy_hash: &str, request_hash: &str) -> Value {
        use ioi_api::crypto::{SerializableKey, SigningKeyPair};
        use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
        use ioi_types::app::action::ApprovalGrant;
        use ioi_types::app::{account_id_from_key_material, SignatureSuite};

        fn hash32(value: &str) -> [u8; 32] {
            let bytes = hex::decode(value.trim_start_matches("sha256:"))
                .expect("decision hash is canonical hex");
            bytes.try_into().expect("decision hash is 32 bytes")
        }

        let private_key = Ed25519PrivateKey::from_bytes(&[seed_byte; 32]).unwrap();
        let keypair = Ed25519KeyPair::from_private_key(&private_key).unwrap();
        let approver_public_key = keypair.public_key().to_bytes();
        let authority_id =
            account_id_from_key_material(SignatureSuite::ED25519, &approver_public_key).unwrap();
        let mut grant = ApprovalGrant {
            schema_version: 1,
            authority_id,
            request_hash: hash32(request_hash),
            policy_hash: hash32(policy_hash),
            audience: [3u8; 32],
            nonce: [4u8; 32],
            counter: 1,
            expires_at: 1_850_000_000_000,
            max_usages: Some(1),
            window_id: None,
            pii_action: None,
            scoped_exception: None,
            review_request_hash: None,
            approver_public_key,
            approver_sig: Vec::new(),
            approver_suite: SignatureSuite::ED25519,
        };
        let signing_bytes = grant.signing_bytes().unwrap();
        grant.approver_sig = keypair.sign(&signing_bytes).unwrap().to_bytes().to_vec();
        serde_json::to_value(grant).unwrap()
    }

    /// A minimal OPEN hosted room the seam accepts (content id == stem, open, no intents).
    fn plant_room(data_dir: &str, tail: &str) {
        let room = json!({
            "schema_version": "ioi.hypervisor.outcome-room.v1",
            "outcome_room_id": format!("outcome-room://{tail}"),
            "status": "open", "revision": 1, "host_domain_ref": "domain://acme-host",
            "participation_request_refs": [], "participant_lease_refs": [],
            "member_goal_run_refs": [], "status_history": [],
            "admission_receipt_ref": "receipt://orr_0", "admission_and_replay_refs": ["receipt://orr_0"],
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        });
        super::super::durable_fs::persist_record_durable(data_dir, rooms::ROOM_DIR, tail, &room)
            .unwrap();
    }

    fn declaration_body(room_tail: &str) -> Value {
        json!({
            "outcome_room_ref": format!("outcome-room://{room_tail}"),
            "requested_by_ref": "worker://independent-alloy-lab",
            "coordination_topology": "hosted_admission",
            "admission_owner_ref": "domain://acme-host",
            "operator_and_home_domain_refs": ["org://alloy-lab", "domain://alloy-lab.example"],
            "capability_offer_refs": ["capability-offer://fatigue-sim"],
            "eligibility_evidence_refs": ["evidence://fatigue-benchmarks"],
            "accepted_verifier_settlement_dispute_and_contribution_policy_refs": ["policy://contribution-v1"]
        })
    }

    fn canonical_submit_intent(
        room_tail: &str,
        request_tail: &str,
        receipt_tail: &str,
        now: &str,
    ) -> (Value, Value) {
        let declaration = validate_request_create(&declaration_body(room_tail)).unwrap();
        let receipt_ref = format!("receipt://{receipt_tail}");
        let request = seal_request(&declaration, request_tail, &receipt_ref, now);
        let request_id = s(&request, "participation_request_id", "");
        let room_ref = s(&request, "outcome_room_ref", "");
        let receipt = build_room_receipt_at(
            receipt_tail,
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&request, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!(room_ref)],
            record_output_hash(&request, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let intent = json!({
            "kind": "submit",
            "request_tail": request_tail,
            "request_ref": request.get("participation_request_id").cloned().unwrap_or(Value::Null),
            "room_ref": request.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
            "final_request": request,
            "final_request_hash": record_output_hash(&request, &[]),
            "receipt_id": receipt_tail,
            "receipt": receipt,
            "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        (request, intent)
    }

    #[test]
    fn strict_loaders_and_scans_refuse_canonical_slot_corruption() {
        use std::os::unix::fs::symlink;

        // Definitive absence remains distinguishable from an occupied-but-unreadable point slot.
        let absent = temp_dir("strict-absent");
        let absent_data = absent.to_str().unwrap();
        assert!(super::load_request(absent_data, "rpr_a0")
            .unwrap()
            .is_none());
        assert!(super::load_lease(absent_data, "rpl_a0").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&absent);

        // REQUEST: malformed JSON, unreadable canonical occupant, and identity relocation each
        // make both the point loader and the registry scan fail closed.
        let malformed_request = temp_dir("strict-request-malformed");
        let malformed_request_data = malformed_request.to_str().unwrap();
        std::fs::create_dir_all(malformed_request.join(REQUEST_DIR)).unwrap();
        std::fs::write(
            malformed_request.join(REQUEST_DIR).join("rpr_a1.json"),
            b"{not-json",
        )
        .unwrap();
        assert!(super::load_request(malformed_request_data, "rpr_a1").is_err());
        assert!(scan_requests(malformed_request_data)
            .unwrap_err()
            .contains("malformed JSON"));
        let _ = std::fs::remove_dir_all(&malformed_request);

        let unreadable_request = temp_dir("strict-request-unreadable");
        let unreadable_request_data = unreadable_request.to_str().unwrap();
        std::fs::create_dir_all(unreadable_request.join(REQUEST_DIR)).unwrap();
        std::fs::write(unreadable_request.join("request-decoy.json"), b"{}").unwrap();
        symlink(
            unreadable_request.join("request-decoy.json"),
            unreadable_request.join(REQUEST_DIR).join("rpr_a2.json"),
        )
        .unwrap();
        assert!(super::load_request(unreadable_request_data, "rpr_a2").is_err());
        assert!(scan_requests(unreadable_request_data)
            .unwrap_err()
            .contains("not readable as a regular file"));
        let _ = std::fs::remove_dir_all(&unreadable_request);

        let mismatched_request = temp_dir("strict-request-identity");
        let mismatched_request_data = mismatched_request.to_str().unwrap();
        let (foreign_request, _) =
            canonical_submit_intent("or_a3", "rpr_a4", "rqr_a4", "2026-02-01T00:00:00Z");
        persist_atomic(
            mismatched_request_data,
            REQUEST_DIR,
            "rpr_a3",
            &foreign_request,
        )
        .unwrap();
        assert!(super::load_request(mismatched_request_data, "rpr_a3").is_err());
        assert!(scan_requests(mismatched_request_data)
            .unwrap_err()
            .contains("identity that does not match"));
        let _ = std::fs::remove_dir_all(&mismatched_request);

        // LEASE: the same three canonical-slot failure classes are never skipped.
        let malformed_lease = temp_dir("strict-lease-malformed");
        let malformed_lease_data = malformed_lease.to_str().unwrap();
        std::fs::create_dir_all(malformed_lease.join(LEASE_DIR)).unwrap();
        std::fs::write(malformed_lease.join(LEASE_DIR).join("rpl_b1.json"), b"[").unwrap();
        assert!(super::load_lease(malformed_lease_data, "rpl_b1").is_err());
        assert!(scan_leases(malformed_lease_data)
            .unwrap_err()
            .contains("malformed JSON"));
        let _ = std::fs::remove_dir_all(&malformed_lease);

        let unreadable_lease = temp_dir("strict-lease-unreadable");
        let unreadable_lease_data = unreadable_lease.to_str().unwrap();
        std::fs::create_dir_all(unreadable_lease.join(LEASE_DIR)).unwrap();
        std::fs::write(unreadable_lease.join("lease-decoy.json"), b"{}").unwrap();
        symlink(
            unreadable_lease.join("lease-decoy.json"),
            unreadable_lease.join(LEASE_DIR).join("rpl_b2.json"),
        )
        .unwrap();
        assert!(super::load_lease(unreadable_lease_data, "rpl_b2").is_err());
        assert!(scan_leases(unreadable_lease_data)
            .unwrap_err()
            .contains("not readable as a regular file"));
        let _ = std::fs::remove_dir_all(&unreadable_lease);

        let mismatched_lease = temp_dir("strict-lease-identity");
        let mismatched_lease_data = mismatched_lease.to_str().unwrap();
        let (request, _) =
            canonical_submit_intent("or_b3", "rpr_b3", "rqr_b3", "2026-02-01T00:00:00Z");
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer",
            "operator_ref": "org://alloy-lab",
            "home_domain_ref": "domain://alloy-lab.example",
        }))
        .unwrap();
        let foreign_lease = build_lease(
            &request,
            &params,
            "rpl_b4",
            "receipt://rlr_b4",
            "2026-02-02T00:00:00Z",
        );
        persist_atomic(mismatched_lease_data, LEASE_DIR, "rpl_b3", &foreign_lease).unwrap();
        assert!(super::load_lease(mismatched_lease_data, "rpl_b3").is_err());
        assert!(scan_leases(mismatched_lease_data)
            .unwrap_err()
            .contains("identity that does not match"));
        let _ = std::fs::remove_dir_all(&mismatched_lease);

        // SUBMIT INTENT: canonical filenames with malformed, unreadable, or relocated content
        // make the internal scan fail instead of disappearing from the uniqueness union.
        let malformed_intent = temp_dir("strict-intent-malformed");
        let malformed_intent_data = malformed_intent.to_str().unwrap();
        std::fs::create_dir_all(malformed_intent.join(SUBMIT_INTENT_DIR)).unwrap();
        std::fs::write(
            malformed_intent.join(SUBMIT_INTENT_DIR).join("rpr_c1.json"),
            b"null trailing",
        )
        .unwrap();
        assert!(scan_intent_family(malformed_intent_data)
            .unwrap_err()
            .contains("malformed JSON"));
        let _ = std::fs::remove_dir_all(&malformed_intent);

        let unreadable_intent = temp_dir("strict-intent-unreadable");
        let unreadable_intent_data = unreadable_intent.to_str().unwrap();
        std::fs::create_dir_all(unreadable_intent.join(SUBMIT_INTENT_DIR)).unwrap();
        std::fs::write(unreadable_intent.join("intent-decoy.json"), b"{}").unwrap();
        symlink(
            unreadable_intent.join("intent-decoy.json"),
            unreadable_intent
                .join(SUBMIT_INTENT_DIR)
                .join("rpr_c2.json"),
        )
        .unwrap();
        assert!(scan_intent_family(unreadable_intent_data)
            .unwrap_err()
            .contains("not readable as a regular file"));
        let _ = std::fs::remove_dir_all(&unreadable_intent);

        let mismatched_intent = temp_dir("strict-intent-identity");
        let mismatched_intent_data = mismatched_intent.to_str().unwrap();
        let (_, foreign_intent) =
            canonical_submit_intent("or_c3", "rpr_c4", "rqr_c4", "2026-02-01T00:00:00Z");
        persist_atomic(
            mismatched_intent_data,
            SUBMIT_INTENT_DIR,
            "rpr_c3",
            &foreign_intent,
        )
        .unwrap();
        assert!(scan_intent_family(mismatched_intent_data)
            .unwrap_err()
            .contains("not canonical"));
        let _ = std::fs::remove_dir_all(&mismatched_intent);
    }

    #[test]
    fn canonical_scans_refuse_slots_that_vanish_after_enumeration() {
        // REQUEST: pin + enumerate, then remove the canonical name before the strict read.
        let request_dir = temp_dir("vanished-request");
        let request_data = request_dir.to_str().unwrap();
        let (request, _) =
            canonical_submit_intent("or_d1", "rpr_d1", "rqr_d1", "2026-02-01T00:00:00Z");
        persist_atomic(request_data, REQUEST_DIR, "rpr_d1", &request).unwrap();
        let pinned =
            super::super::durable_fs::open_family_dir_pinned(request_data, REQUEST_DIR).unwrap();
        let names = super::super::durable_fs::enumerate_pinned(&pinned).unwrap();
        std::fs::remove_file(request_dir.join(REQUEST_DIR).join("rpr_d1.json")).unwrap();
        assert!(scan_family_entries(
            &pinned,
            names,
            REQUEST_DIR,
            "participation_request_id",
            "participation-request://",
            is_canonical_request_tail,
        )
        .unwrap_err()
        .contains("vanished after enumeration"));
        let _ = std::fs::remove_dir_all(&request_dir);

        // LEASE: exercise the identical window through the shared entry scanner.
        let lease_dir = temp_dir("vanished-lease");
        let lease_data = lease_dir.to_str().unwrap();
        let (request, _) =
            canonical_submit_intent("or_d2", "rpr_d2", "rqr_d2", "2026-02-01T00:00:00Z");
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer",
            "operator_ref": "org://alloy-lab",
            "home_domain_ref": "domain://alloy-lab.example",
        }))
        .unwrap();
        let lease = build_lease(
            &request,
            &params,
            "rpl_d2",
            "receipt://rlr_d2",
            "2026-02-02T00:00:00Z",
        );
        persist_atomic(lease_data, LEASE_DIR, "rpl_d2", &lease).unwrap();
        let pinned =
            super::super::durable_fs::open_family_dir_pinned(lease_data, LEASE_DIR).unwrap();
        let names = super::super::durable_fs::enumerate_pinned(&pinned).unwrap();
        std::fs::remove_file(lease_dir.join(LEASE_DIR).join("rpl_d2.json")).unwrap();
        assert!(scan_family_entries(
            &pinned,
            names,
            LEASE_DIR,
            "participant_lease_id",
            "participant-lease://",
            is_canonical_lease_tail,
        )
        .unwrap_err()
        .contains("vanished after enumeration"));
        let _ = std::fs::remove_dir_all(&lease_dir);

        // SUBMIT INTENT: the internal family has the same pinned-enumeration guarantee.
        let intent_dir = temp_dir("vanished-intent");
        let intent_data = intent_dir.to_str().unwrap();
        let (_, intent) =
            canonical_submit_intent("or_d3", "rpr_d3", "rqr_d3", "2026-02-01T00:00:00Z");
        persist_atomic(intent_data, SUBMIT_INTENT_DIR, "rpr_d3", &intent).unwrap();
        let pinned =
            super::super::durable_fs::open_family_dir_pinned(intent_data, SUBMIT_INTENT_DIR)
                .unwrap();
        let names = super::super::durable_fs::enumerate_pinned(&pinned).unwrap();
        std::fs::remove_file(intent_dir.join(SUBMIT_INTENT_DIR).join("rpr_d3.json")).unwrap();
        assert!(scan_intent_entries(&pinned, names)
            .unwrap_err()
            .contains("vanished after enumeration"));
        let _ = std::fs::remove_dir_all(&intent_dir);
    }

    #[test]
    fn pending_submit_and_admit_intents_reserve_uniqueness_keys() {
        // `draft` is canonical but not emitted by this hosted cut. If one is durably present,
        // conservatively treat it as live instead of validating it and then declaring absence.
        let draft_dir = temp_dir("draft-request-unique");
        let draft_data = draft_dir.to_str().unwrap();
        plant_room(draft_data, "or_e0");
        let (mut draft, _) =
            canonical_submit_intent("or_e0", "rpr_e0", "rqr_e0", "2026-02-01T00:00:00Z");
        draft["status"] = json!("draft");
        persist_atomic(draft_data, REQUEST_DIR, "rpr_e0", &draft).unwrap();
        assert!(live_request_exists(
            draft_data,
            "outcome-room://or_e0",
            "worker://independent-alloy-lab",
        )
        .unwrap());
        let _ = std::fs::remove_dir_all(&draft_dir);

        let submit_dir = temp_dir("pending-submit-unique");
        let submit_data = submit_dir.to_str().unwrap();
        plant_room(submit_data, "or_e1");
        let (_, intent) =
            canonical_submit_intent("or_e1", "rpr_e1", "rqr_e1", "2026-02-01T00:00:00Z");
        persist_atomic(submit_data, SUBMIT_INTENT_DIR, "rpr_e1", &intent).unwrap();
        assert!(load_request(submit_data, "rpr_e1").is_none());
        assert!(live_request_exists(
            submit_data,
            "outcome-room://or_e1",
            "worker://independent-alloy-lab",
        )
        .unwrap());
        let _ = std::fs::remove_dir_all(&submit_dir);

        let admit_dir = temp_dir("pending-admit-unique");
        let admit_data = admit_dir.to_str().unwrap();
        plant_room(admit_data, "or_e2");
        submit(
            admit_data,
            "or_e2",
            "rpr_e2",
            "rqr_e2",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(admit_data, "rpr_e2").unwrap();
        let admit =
            canonical_admit_intent(&prior, "rpl_e2", "rlr_e2", "rqt_e2", "2026-02-02T00:00:00Z");
        let mut carrying = prior;
        carrying["admit_intent"] = admit;
        persist_atomic(admit_data, REQUEST_DIR, "rpr_e2", &carrying).unwrap();
        assert!(load_lease(admit_data, "rpl_e2").is_none());
        assert!(live_lease_exists(
            admit_data,
            "outcome-room://or_e2",
            "worker://independent-alloy-lab",
        )
        .unwrap());
        let _ = std::fs::remove_dir_all(&admit_dir);
    }

    #[test]
    fn room_backlink_remains_a_lease_reservation_until_exact_release() {
        let dir = temp_dir("lease-backlink-unique");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_f1");
        submit(
            data_dir,
            "or_f1",
            "rpr_f1",
            "rqr_f1",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_f1").unwrap();
        let admit =
            canonical_admit_intent(&prior, "rpl_f1", "rlr_f1", "rqt_f1", "2026-02-02T00:00:00Z");
        let room_scope = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        finalize_admit(data_dir, "rpr_f1", &prior, &admit, &room_scope).unwrap();
        drop(room_scope);

        let lease = load_lease(data_dir, "rpl_f1").unwrap();
        let terminal = apply_transition(
            &lease,
            "transition_intent",
            "revoke",
            "revoked",
            &json!("receipt://rlt_f1"),
            &json!("2026-02-03T00:00:00Z"),
            true,
        );
        persist_atomic(data_dir, LEASE_DIR, "rpl_f1", &terminal).unwrap();
        assert!(live_lease_exists(
            data_dir,
            "outcome-room://or_f1",
            "worker://independent-alloy-lab",
        )
        .unwrap());

        rooms::bind_room_backlink(
            data_dir,
            "outcome-room://or_f1",
            "participant_lease_released",
            "participant-lease://rpl_f1",
        )
        .unwrap();
        assert!(!live_lease_exists(
            data_dir,
            "outcome-room://or_f1",
            "worker://independent-alloy-lab",
        )
        .unwrap());
    }

    #[test]
    fn orphaned_or_malformed_room_lease_reservations_fail_typed() {
        let orphan = temp_dir("orphan-backlink");
        let orphan_data = orphan.to_str().unwrap();
        plant_room(orphan_data, "or_f2");
        rooms::bind_room_backlink(
            orphan_data,
            "outcome-room://or_f2",
            "participant_lease_bound",
            "participant-lease://rpl_f2",
        )
        .unwrap();
        let orphan_err = live_lease_exists(
            orphan_data,
            "outcome-room://or_f2",
            "worker://independent-alloy-lab",
        )
        .unwrap_err();
        assert_eq!(orphan_err.0, "participant_lease_registry_unreadable");
        let _ = std::fs::remove_dir_all(&orphan);

        let malformed = temp_dir("malformed-room-backlink");
        let malformed_data = malformed.to_str().unwrap();
        plant_room(malformed_data, "or_f3");
        let mut room = rooms::resolve_room(malformed_data, "outcome-room://or_f3").unwrap();
        room["participant_lease_refs"] = json!([Value::Null]);
        persist_atomic(malformed_data, rooms::ROOM_DIR, "or_f3", &room).unwrap();
        let malformed_err = live_lease_exists(
            malformed_data,
            "outcome-room://or_f3",
            "worker://independent-alloy-lab",
        )
        .unwrap_err();
        assert_eq!(malformed_err.0, "participant_lease_registry_unreadable");
        let _ = std::fs::remove_dir_all(&malformed);
    }

    /// Drive the SUBMIT flow exactly as the handler does (validate → seal → receipt → finalize).
    fn submit(
        data_dir: &str,
        room_tail: &str,
        req_tail: &str,
        receipt_tail: &str,
        now: &str,
    ) -> (Value, Value) {
        let declaration = validate_request_create(&declaration_body(room_tail)).unwrap();
        let receipt_ref = format!("receipt://{receipt_tail}");
        let record = seal_request(&declaration, req_tail, &receipt_ref, now);
        let request_id = s(&record, "participation_request_id", "");
        let room_ref = s(&record, "outcome_room_ref", "");
        let receipt = build_room_receipt_at(
            receipt_tail,
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!(room_ref)],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let _participation = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let room_scope = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        finalize_submit(
            data_dir,
            req_tail,
            &record,
            receipt_tail,
            &receipt,
            &room_scope,
        )
        .unwrap();
        (record, receipt)
    }

    /// Build the exact sealed admission intent the HTTP handler would produce after authority
    /// succeeds. Internal transaction/race/recovery tests use this because the online surface is
    /// correctly typed-unavailable until identity→wallet authority binding exists.
    fn canonical_admit_intent(
        prior: &Value,
        lease_tail: &str,
        lease_receipt_id: &str,
        request_receipt_id: &str,
        now: &str,
    ) -> Value {
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer",
            "operator_ref": "org://alloy-lab",
            "home_domain_ref": "domain://alloy-lab.example",
        }))
        .unwrap();
        let lease_id = format!("participant-lease://{lease_tail}");
        let lease_receipt_ref = format!("receipt://{lease_receipt_id}");
        let request_receipt_ref = json!(format!("receipt://{request_receipt_id}"));
        let final_lease = build_lease(prior, &params, lease_tail, &lease_receipt_ref, now);
        let current_rev = prior.get("revision").and_then(Value::as_u64).unwrap();
        let from = s(prior, "status", "");
        let request_id = s(prior, "participation_request_id", "");
        let room_ref = s(prior, "outcome_room_ref", "");
        let mut final_request = apply_transition(
            prior,
            "admit_intent",
            "admit",
            "admitted",
            &request_receipt_ref,
            &json!(now),
            false,
        );
        if let Some(obj) = final_request.as_object_mut() {
            obj.insert("participant_lease_ref".into(), json!(lease_id));
            obj.insert("admission_decision_ref".into(), request_receipt_ref);
        }
        let lease_receipt = build_decision_receipt(
            lease_receipt_id,
            "RoomParticipationDecisionReceipt",
            &lease_id,
            "admitted",
            json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": s(&final_lease, "admitted_role", ""), "join_request_ref": request_id, "status_at_admission": "active" }),
            vec![json!(lease_id), json!(room_ref), json!(request_id)],
            record_output_hash(&final_lease, LEASE_CREATE_EXCLUDES),
            LEASE_CREATE_EXCLUDES,
            ADMIT_NOTE,
            now,
            &ta(),
        );
        let request_receipt = build_decision_receipt(
            request_receipt_id,
            "RoomParticipationDecisionReceipt",
            &request_id,
            "admit",
            json!({ "transition": "admit", "from": from, "to": "admitted", "participant_lease_ref": lease_id, "revision_before": current_rev, "revision_after": current_rev + 1, "outcome_room_ref": room_ref }),
            vec![json!(request_id), json!(lease_id)],
            record_output_hash(&final_request, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            ADMIT_NOTE,
            now,
            &ta(),
        );
        json!({
            "kind": "admit",
            "lease_tail": lease_tail,
            "admit_params": params,
            "final_request": final_request,
            "final_request_hash": record_output_hash(&final_request, &[]),
            "final_lease": final_lease,
            "final_lease_hash": record_output_hash(&final_lease, &[]),
            "lease_receipt_id": lease_receipt_id,
            "lease_receipt": lease_receipt,
            "lease_receipt_hash": record_output_hash(&lease_receipt, &[]),
            "request_receipt_id": request_receipt_id,
            "request_receipt": request_receipt,
            "request_receipt_hash": record_output_hash(&request_receipt, &[]),
            "at": now,
        })
    }

    fn plant_bound_active_lease(
        data_dir: &str,
        room_tail: &str,
        request_tail: &str,
        submit_receipt_tail: &str,
        lease_tail: &str,
    ) -> Value {
        plant_room(data_dir, room_tail);
        submit(
            data_dir,
            room_tail,
            request_tail,
            submit_receipt_tail,
            "2026-02-01T00:00:00Z",
        );
        let request = load_request(data_dir, request_tail).unwrap();
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer",
            "operator_ref": "org://alloy-lab",
            "home_domain_ref": "domain://alloy-lab.example",
        }))
        .unwrap();
        let lease = build_lease(
            &request,
            &params,
            lease_tail,
            &format!("receipt://rlr_{}", lease_tail.trim_start_matches("rpl_")),
            "2026-02-02T00:00:00Z",
        );
        persist_atomic(data_dir, LEASE_DIR, lease_tail, &lease).unwrap();
        rooms::bind_room_backlink(
            data_dir,
            &format!("outcome-room://{room_tail}"),
            "participant_lease_bound",
            &format!("participant-lease://{lease_tail}"),
        )
        .unwrap();
        lease
    }

    #[test]
    fn submit_finalizes_and_binds_the_room_through_the_seam() {
        let dir = temp_dir("submit");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_a1");
        let (record, _receipt) = submit(
            data_dir,
            "or_a1",
            "rpr_a1",
            "rqr_a1",
            "2026-02-01T00:00:00Z",
        );
        let _ = record;
        // Wait: request tail must be canonical rpr_<hex> — a1 is hex. Room bound?
        let stored = load_request(data_dir, "rpr_a1").expect("request stored");
        assert_eq!(stored["status"], json!("submitted"));
        assert_eq!(stored["revision"], json!(1));
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_a1").unwrap();
        assert_eq!(
            room["participation_request_refs"],
            json!(["participation-request://rpr_a1"]),
            "the room backlink landed through the seam"
        );
        assert_eq!(
            room["revision"],
            json!(2),
            "the backlink was a receipted room transition"
        );
        assert!(
            std::fs::read(dir.join(RECEIPT_DIR).join("rqr_a1.json")).is_ok(),
            "the submission receipt is durable"
        );
        assert!(
            !dir.join(SUBMIT_INTENT_DIR).join("rpr_a1.json").exists(),
            "the submit intent was consumed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn submit_completer_converges_a_crashed_submission_and_refuses_tamper() {
        let dir = temp_dir("submit-replay");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_b2");
        // Seal the intent EXACTLY as finalize_submit would. Let the room-first reservation land,
        // then "crash" before the submission receipt/request; replay must finish byte-exactly.
        let declaration = validate_request_create(&declaration_body("or_b2")).unwrap();
        let now = "2026-02-01T00:00:00Z";
        let record = seal_request(&declaration, "rpr_b2", "receipt://rqr_b2", now);
        let request_id = s(&record, "participation_request_id", "");
        let receipt = build_room_receipt_at(
            "rqr_b2",
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": "outcome-room://or_b2", "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!("outcome-room://or_b2")],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let intent = json!({
            "kind": "submit", "request_tail": "rpr_b2", "request_ref": request_id,
            "room_ref": "outcome-room://or_b2",
            "final_request": record, "final_request_hash": record_output_hash(&record, &[]),
            "receipt_id": "rqr_b2", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_b2", &intent).unwrap();
        rooms::bind_room_backlink(
            data_dir,
            "outcome-room://or_b2",
            "participation_request_bound",
            "participation-request://rpr_b2",
        )
        .unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_b2").is_some(),
            "the completer converged the crashed submission"
        );
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_b2").unwrap();
        assert_eq!(
            room["participation_request_refs"],
            json!(["participation-request://rpr_b2"])
        );
        assert!(
            !dir.join(SUBMIT_INTENT_DIR).join("rpr_b2.json").exists(),
            "intent consumed after convergence"
        );
        // Idempotent second boot.
        complete_participation_intents(data_dir);
        // TAMPERED intent: an escalated requested_by inside a re-sealed intent must be refused —
        // reconstruction through the declaration validator + sealer catches it even with hashes fixed.
        let mut forged = record.clone();
        forged
            .as_object_mut()
            .unwrap()
            .insert("requested_by_ref".into(), json!("org://insider"));
        let forged_intent = json!({
            "kind": "submit", "request_tail": "rpr_b3", "request_ref": "participation-request://rpr_b3",
            "room_ref": "outcome-room://or_b2",
            "final_request": forged, "final_request_hash": record_output_hash(&forged, &[]),
            "receipt_id": "rqr_b3", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_b3", &forged_intent).unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_b3").is_none(),
            "a tampered submission never converges"
        );
        assert!(
            dir.join(SUBMIT_INTENT_DIR).join("rpr_b3.json").exists(),
            "the tampered intent is retained for manual repair"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn closed_room_submit_replay_consumes_intent_without_false_evidence() {
        // Regression for receipt-first submission: if a crash leaves only the internal intent
        // and close wins before replay, boot rolls the pre-linearization intent back durably.
        let dir = temp_dir("closed-submit-replay");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_b8");
        let declaration = validate_request_create(&declaration_body("or_b8")).unwrap();
        let now = "2026-02-01T00:00:00Z";
        let record = seal_request(&declaration, "rpr_b8", "receipt://rqr_b8", now);
        let request_id = s(&record, "participation_request_id", "");
        let receipt = build_room_receipt_at(
            "rqr_b8",
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": "outcome-room://or_b8", "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!("outcome-room://or_b8")],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let intent = json!({
            "kind": "submit", "request_tail": "rpr_b8", "request_ref": request_id,
            "room_ref": "outcome-room://or_b8",
            "final_request": record, "final_request_hash": record_output_hash(&record, &[]),
            "receipt_id": "rqr_b8", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": now,
        });
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_b8", &intent).unwrap();
        let mut closed = rooms::resolve_room(data_dir, "outcome-room://or_b8").unwrap();
        closed["status"] = json!("closed");
        persist_atomic(data_dir, rooms::ROOM_DIR, "or_b8", &closed).unwrap();
        let room_before = serde_json::to_vec(&closed).unwrap();

        complete_participation_intents(data_dir);

        assert!(load_request(data_dir, "rpr_b8").is_none());
        assert!(!dir.join(RECEIPT_DIR).join("rqr_b8.json").exists());
        assert!(
            !dir.join(SUBMIT_INTENT_DIR).join("rpr_b8.json").exists(),
            "the impossible pre-linearization intent is consumed"
        );
        assert_eq!(
            serde_json::to_vec(&rooms::resolve_room(data_dir, "outcome-room://or_b8").unwrap())
                .unwrap(),
            room_before,
            "the closed room is byte-unchanged and gains no false request backlink"
        );
        // Repeated boot is a no-op: rollback is itself crash-durable.
        complete_participation_intents(data_dir);
        assert!(load_request(data_dir, "rpr_b8").is_none());
        assert!(!dir.join(RECEIPT_DIR).join("rqr_b8.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_room_never_consumes_submit_or_admit_recovery_intents() {
        use std::os::unix::fs::symlink;

        // SUBMIT: construct the exact intent, then make the room slot a symlink before its
        // room-first reservation. Strict uncertainty retains the recovery anchor.
        let submit_dir = temp_dir("unreadable-room-submit");
        let submit_data = submit_dir.to_str().unwrap();
        plant_room(submit_data, "or_bc");
        let declaration = validate_request_create(&declaration_body("or_bc")).unwrap();
        let now = "2026-02-01T00:00:00Z";
        let record = seal_request(&declaration, "rpr_bc", "receipt://rqr_bc", now);
        let request_id = s(&record, "participation_request_id", "");
        let receipt = build_room_receipt_at(
            "rqr_bc",
            REQUEST_RECEIPT_SCHEMA,
            "RoomParticipationRequestReceipt",
            &request_id,
            "submitted",
            json!({ "outcome_room_ref": "outcome-room://or_bc", "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
            vec![json!(request_id), json!("outcome-room://or_bc")],
            record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
            REQUEST_CREATE_EXCLUDES,
            "admitted_not_verified",
            SUBMIT_NOTE,
            now,
        );
        let room_path = submit_dir.join(rooms::ROOM_DIR).join("or_bc.json");
        let room_backup = submit_dir.join("or_bc-room-backup.json");
        std::fs::rename(&room_path, &room_backup).unwrap();
        symlink(&room_backup, &room_path).unwrap();
        let room_scope = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (code, _) = finalize_submit(
            submit_data,
            "rpr_bc",
            &record,
            "rqr_bc",
            &receipt,
            &room_scope,
        )
        .unwrap_err();
        drop(room_scope);
        assert_eq!(code, "outcome_room_registry_unreadable");
        let submit_intent_path = submit_dir.join(SUBMIT_INTENT_DIR).join("rpr_bc.json");
        assert!(submit_intent_path.exists());
        complete_participation_intents(submit_data);
        assert!(submit_intent_path.exists());
        assert!(load_request(submit_data, "rpr_bc").is_none());
        assert!(!submit_dir.join(RECEIPT_DIR).join("rqr_bc.json").exists());
        let _ = std::fs::remove_dir_all(&submit_dir);

        // ADMIT: a structurally valid legacy intent is likewise retained when the room is not
        // strictly readable; cleanup is allowed only for proven absence or a valid closed room.
        let admit_dir = temp_dir("unreadable-room-admit");
        let admit_data = admit_dir.to_str().unwrap();
        plant_room(admit_data, "or_cd");
        submit(
            admit_data,
            "or_cd",
            "rpr_cd",
            "rqr_cd",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(admit_data, "rpr_cd").unwrap();
        let admit =
            canonical_admit_intent(&prior, "rpl_cd", "rlr_cd", "rqt_cd", "2026-02-02T00:00:00Z");
        let mut carrying = prior;
        carrying["admit_intent"] = admit;
        persist_atomic(admit_data, REQUEST_DIR, "rpr_cd", &carrying).unwrap();
        let admit_before = serde_json::to_vec(&carrying).unwrap();
        let room_path = admit_dir.join(rooms::ROOM_DIR).join("or_cd.json");
        let room_backup = admit_dir.join("or_cd-room-backup.json");
        std::fs::rename(&room_path, &room_backup).unwrap();
        symlink(&room_backup, &room_path).unwrap();
        complete_participation_intents(admit_data);
        assert_eq!(
            serde_json::to_vec(&load_request(admit_data, "rpr_cd").unwrap()).unwrap(),
            admit_before
        );
        assert!(load_lease(admit_data, "rpl_cd").is_none());
        assert!(!admit_dir.join(RECEIPT_DIR).join("rlr_cd.json").exists());
        assert!(!admit_dir.join(RECEIPT_DIR).join("rqt_cd.json").exists());
        let _ = std::fs::remove_dir_all(&admit_dir);
    }

    #[test]
    fn close_vs_submit_race_serializes_open_validation_and_room_reservation() {
        // Both operations enter the same room critical section. Close-first leaves zero submit
        // artifacts; submit-first lands the complete transaction before close may proceed.
        for round in 0..12u8 {
            let dir = temp_dir(&format!("close-submit-race-{round:x}"));
            let data_dir = dir.to_str().unwrap().to_string();
            let room_tail = format!("or_b{round:x}");
            let request_tail = format!("rpr_b{round:x}");
            let receipt_tail = format!("rqr_b{round:x}");
            let room_ref = format!("outcome-room://{room_tail}");
            plant_room(&data_dir, &room_tail);
            let declaration = validate_request_create(&declaration_body(&room_tail)).unwrap();
            let now = "2026-02-01T00:00:00Z";
            let record = seal_request(
                &declaration,
                &request_tail,
                &format!("receipt://{receipt_tail}"),
                now,
            );
            let request_id = s(&record, "participation_request_id", "");
            let receipt = build_room_receipt_at(
                &receipt_tail,
                REQUEST_RECEIPT_SCHEMA,
                "RoomParticipationRequestReceipt",
                &request_id,
                "submitted",
                json!({ "outcome_room_ref": room_ref, "requested_by_ref": s(&record, "requested_by_ref", ""), "status_at_submission": "submitted" }),
                vec![json!(request_id), json!(room_ref)],
                record_output_hash(&record, REQUEST_CREATE_EXCLUDES),
                REQUEST_CREATE_EXCLUDES,
                "admitted_not_verified",
                SUBMIT_NOTE,
                now,
            );
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let submit_data = data_dir.clone();
            let submit_room_ref = room_ref.clone();
            let submit_request_tail = request_tail.clone();
            let submit_receipt_tail = receipt_tail.clone();
            let submit_barrier = Arc::clone(&barrier);
            let submit_thread = std::thread::spawn(move || {
                submit_barrier.wait();
                let _participation = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
                let room_scope = rooms::ROOM_MUTATION_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let room = rooms::resolve_room(&submit_data, &submit_room_ref).unwrap();
                if s(&room, "status", "") != "open" || rooms::pending_intent(&room).is_some() {
                    return false;
                }
                finalize_submit(
                    &submit_data,
                    &submit_request_tail,
                    &record,
                    &submit_receipt_tail,
                    &receipt,
                    &room_scope,
                )
                .is_ok()
            });

            let close_data = data_dir.clone();
            let close_room_tail = room_tail.clone();
            let close_room_ref = room_ref.clone();
            let close_barrier = Arc::clone(&barrier);
            let close_thread = std::thread::spawn(move || {
                close_barrier.wait();
                let _room_scope = rooms::ROOM_MUTATION_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let mut room = rooms::resolve_room(&close_data, &close_room_ref).unwrap();
                if s(&room, "status", "") != "open" || rooms::pending_intent(&room).is_some() {
                    return false;
                }
                room["status"] = json!("closed");
                persist_atomic(&close_data, rooms::ROOM_DIR, &close_room_tail, &room).unwrap();
                true
            });

            let submitted = submit_thread.join().unwrap();
            let closed = close_thread.join().unwrap();
            assert!(
                closed,
                "close either wins first or follows a complete submission"
            );
            let room = rooms::resolve_room(&data_dir, &room_ref).unwrap();
            assert_eq!(s(&room, "status", ""), "closed");
            assert!(!dir
                .join(SUBMIT_INTENT_DIR)
                .join(format!("{request_tail}.json"))
                .exists());
            if submitted {
                assert!(load_request(&data_dir, &request_tail).is_some());
                assert!(dir
                    .join(RECEIPT_DIR)
                    .join(format!("{receipt_tail}.json"))
                    .exists());
                assert!(room["participation_request_refs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(
                        |value| value == &json!(format!("participation-request://{request_tail}"))
                    ));
            } else {
                assert!(load_request(&data_dir, &request_tail).is_none());
                assert!(!dir
                    .join(RECEIPT_DIR)
                    .join(format!("{receipt_tail}.json"))
                    .exists());
                assert_eq!(room["participation_request_refs"], json!([]));
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn admit_mints_the_lease_binds_the_room_and_guards_duplicates() {
        let dir = temp_dir("admit");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_c3");
        submit(
            data_dir,
            "or_c3",
            "rpr_c3",
            "rqr_c3",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_c3").unwrap();
        let params = validate_admit_params(&json!({
            "admitted_role": "implementer", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example"
        })).unwrap();
        let now = "2026-02-02T00:00:00Z";
        let final_lease = build_lease(&prior, &params, "rpl_c3", "receipt://rlr_c3", now);
        let request_receipt_ref = json!("receipt://rqt_c3");
        let now_v = json!(now);
        let mut final_request = apply_transition(
            &prior,
            "admit_intent",
            "admit",
            "admitted",
            &request_receipt_ref,
            &now_v,
            false,
        );
        final_request.as_object_mut().unwrap().insert(
            "participant_lease_ref".into(),
            json!("participant-lease://rpl_c3"),
        );
        final_request
            .as_object_mut()
            .unwrap()
            .insert("admission_decision_ref".into(), request_receipt_ref.clone());
        let request_id = s(&prior, "participation_request_id", "");
        let room_ref = s(&prior, "outcome_room_ref", "");
        let current_rev = prior["revision"].as_u64().unwrap();
        let lease_receipt = build_decision_receipt(
            "rlr_c3",
            "RoomParticipationDecisionReceipt",
            "participant-lease://rpl_c3",
            "admitted",
            json!({ "outcome_room_ref": room_ref, "participant_ref": s(&final_lease, "participant_ref", ""), "admitted_role": "implementer", "join_request_ref": request_id, "status_at_admission": "active" }),
            vec![
                json!("participant-lease://rpl_c3"),
                json!(room_ref),
                json!(request_id),
            ],
            record_output_hash(&final_lease, LEASE_CREATE_EXCLUDES),
            LEASE_CREATE_EXCLUDES,
            ADMIT_NOTE,
            now,
            &ta(),
        );
        let request_receipt = build_decision_receipt(
            "rqt_c3",
            "RoomParticipationDecisionReceipt",
            &request_id,
            "admit",
            json!({ "transition": "admit", "from": "submitted", "to": "admitted", "participant_lease_ref": "participant-lease://rpl_c3", "revision_before": current_rev, "revision_after": current_rev + 1, "outcome_room_ref": room_ref }),
            vec![json!(request_id), json!("participant-lease://rpl_c3")],
            record_output_hash(&final_request, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            ADMIT_NOTE,
            now,
            &ta(),
        );
        let admit = json!({
            "kind": "admit", "lease_tail": "rpl_c3", "admit_params": params,
            "final_request": final_request, "final_request_hash": record_output_hash(&final_request, &[]),
            "final_lease": final_lease, "final_lease_hash": record_output_hash(&final_lease, &[]),
            "lease_receipt_id": "rlr_c3", "lease_receipt": lease_receipt, "lease_receipt_hash": record_output_hash(&lease_receipt, &[]),
            "request_receipt_id": "rqt_c3", "request_receipt": request_receipt, "request_receipt_hash": record_output_hash(&request_receipt, &[]),
            "at": now,
        });
        // The sealed admit intent must validate through canonical reconstruction…
        validate_admit_intent(&admit, &prior, "rpr_c3").expect("canonical admit validates");
        let room_scope = rooms::ROOM_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        finalize_admit(data_dir, "rpr_c3", &prior, &admit, &room_scope).unwrap();
        let lease = load_lease(data_dir, "rpl_c3").expect("lease minted");
        assert_eq!(lease["status"], json!("active"));
        assert_eq!(lease["admitted_role"], json!("implementer"));
        assert_eq!(lease["join_request_ref"], json!(request_id));
        let req = load_request(data_dir, "rpr_c3").unwrap();
        assert_eq!(req["status"], json!("admitted"));
        assert_eq!(
            req["participant_lease_ref"],
            json!("participant-lease://rpl_c3")
        );
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_c3").unwrap();
        assert_eq!(
            room["participant_lease_refs"],
            json!(["participant-lease://rpl_c3"]),
            "the lease backlink landed through the seam"
        );
        // Duplicate-live guard: the same principal cannot get a second live lease or request.
        assert!(live_lease_exists(
            data_dir,
            "outcome-room://or_c3",
            "worker://independent-alloy-lab"
        )
        .unwrap());
        // …and a ROLE-ESCALATED forged lease inside the sealed intent is refused.
        let mut escalated = admit.clone();
        let mut bad_lease = escalated["final_lease"].clone();
        bad_lease
            .as_object_mut()
            .unwrap()
            .insert("admitted_role".into(), json!("conductor"));
        escalated
            .as_object_mut()
            .unwrap()
            .insert("final_lease".into(), bad_lease.clone());
        escalated.as_object_mut().unwrap().insert(
            "final_lease_hash".into(),
            json!(record_output_hash(&bad_lease, &[])),
        );
        assert!(
            validate_admit_intent(&escalated, &prior, "rpr_c3").is_err(),
            "a role-escalated sealed lease never validates"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admit_preflights_all_targets_before_room_linearization() {
        use std::os::unix::fs::symlink;

        for (round, target, expected_code) in [
            (0u8, "lease_receipt", "room_participation_receipt_conflict"),
            (1, "request_receipt", "room_participation_receipt_conflict"),
            (2, "lease", "participant_lease_conflict"),
            (
                3,
                "unreadable_request_receipt",
                "room_participation_receipt_slot_unreadable",
            ),
        ] {
            let suffix = format!("d{round:x}");
            let room_tail = format!("or_{suffix}");
            let request_tail = format!("rpr_{suffix}");
            let submit_receipt = format!("rqr_{suffix}");
            let lease_tail = format!("rpl_{suffix}");
            let lease_receipt = format!("rlr_{suffix}");
            let request_receipt = format!("rqt_{suffix}");
            let dir = temp_dir(&format!("admit-preflight-{target}"));
            let data_dir = dir.to_str().unwrap();
            plant_room(data_dir, &room_tail);
            submit(
                data_dir,
                &room_tail,
                &request_tail,
                &submit_receipt,
                "2026-02-01T00:00:00Z",
            );
            let prior = load_request(data_dir, &request_tail).unwrap();
            let admit = canonical_admit_intent(
                &prior,
                &lease_tail,
                &lease_receipt,
                &request_receipt,
                "2026-02-02T00:00:00Z",
            );
            let room_ref = format!("outcome-room://{room_tail}");
            let room_before =
                serde_json::to_vec(&rooms::resolve_room(data_dir, &room_ref).unwrap()).unwrap();
            match target {
                "lease_receipt" => persist_atomic(
                    data_dir,
                    RECEIPT_DIR,
                    &lease_receipt,
                    &json!({ "foreign": true }),
                )
                .unwrap(),
                "request_receipt" => persist_atomic(
                    data_dir,
                    RECEIPT_DIR,
                    &request_receipt,
                    &json!({ "foreign": true }),
                )
                .unwrap(),
                "lease" => persist_atomic(
                    data_dir,
                    LEASE_DIR,
                    &lease_tail,
                    &json!({
                        "participant_lease_id": format!("participant-lease://{lease_tail}"),
                        "status": "foreign",
                    }),
                )
                .unwrap(),
                "unreadable_request_receipt" => {
                    let decoy = dir.join("foreign-receipt.json");
                    std::fs::write(&decoy, b"{}").unwrap();
                    symlink(
                        &decoy,
                        dir.join(RECEIPT_DIR)
                            .join(format!("{request_receipt}.json")),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }

            let room_scope = rooms::ROOM_MUTATION_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (code, _) =
                finalize_admit(data_dir, &request_tail, &prior, &admit, &room_scope).unwrap_err();
            drop(room_scope);
            assert_eq!(code, expected_code, "target={target}");
            assert_eq!(
                serde_json::to_vec(&load_request(data_dir, &request_tail).unwrap()).unwrap(),
                serde_json::to_vec(&prior).unwrap(),
                "preflight conflict never leaves an admit intent ({target})"
            );
            assert_eq!(
                serde_json::to_vec(&rooms::resolve_room(data_dir, &room_ref).unwrap()).unwrap(),
                room_before,
                "preflight conflict never reserves a phantom room lease ({target})"
            );
            assert!(
                rooms::resolve_room(data_dir, &room_ref).unwrap()["participant_lease_refs"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn closed_room_admit_replay_rolls_back_without_false_evidence() {
        // Regression for the live failure: a closed room must be rejected BEFORE either decision
        // receipt. A pre-linearization request intent (for example, a visible-unconfirmed write)
        // is restored exactly instead of becoming permanently stuck.
        let dir = temp_dir("closed-admit");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_c8");
        submit(
            data_dir,
            "or_c8",
            "rpr_c8",
            "rqr_c8",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_c8").unwrap();
        let admit =
            canonical_admit_intent(&prior, "rpl_c8", "rlr_c8", "rqt_c8", "2026-02-02T00:00:00Z");
        let mut closed = rooms::resolve_room(data_dir, "outcome-room://or_c8").unwrap();
        closed["status"] = json!("closed");
        persist_atomic(data_dir, rooms::ROOM_DIR, "or_c8", &closed).unwrap();
        let room_before = serde_json::to_vec(&closed).unwrap();
        let mut carrying = prior.clone();
        carrying["admit_intent"] = admit;
        persist_atomic(data_dir, REQUEST_DIR, "rpr_c8", &carrying).unwrap();

        complete_participation_intents(data_dir);

        let after_request = load_request(data_dir, "rpr_c8").unwrap();
        assert_eq!(
            serde_json::to_vec(&after_request).unwrap(),
            serde_json::to_vec(&prior).unwrap(),
            "the impossible pre-linearization intent is rolled back exactly"
        );
        assert!(load_lease(data_dir, "rpl_c8").is_none());
        assert!(!dir.join(RECEIPT_DIR).join("rlr_c8.json").exists());
        assert!(!dir.join(RECEIPT_DIR).join("rqt_c8.json").exists());
        assert_eq!(
            serde_json::to_vec(&rooms::resolve_room(data_dir, "outcome-room://or_c8").unwrap())
                .unwrap(),
            room_before,
            "the closed room is byte-unchanged and gains no false lease backlink"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governed_admit_and_request_replays_are_quarantined_without_identity_binding() {
        let dir = temp_dir("governed-replay-quarantine");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_ca");
        submit(
            data_dir,
            "or_ca",
            "rpr_ca",
            "rqr_ca",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_ca").unwrap();

        // A fully self-consistent legacy admit intent carrying arbitrary sealed authority fields
        // must not mint a lease on an open room.
        let admit =
            canonical_admit_intent(&prior, "rpl_ca", "rlr_ca", "rqt_ca", "2026-02-02T00:00:00Z");
        let mut carrying_admit = prior.clone();
        carrying_admit["admit_intent"] = admit;
        persist_atomic(data_dir, REQUEST_DIR, "rpr_ca", &carrying_admit).unwrap();
        let admit_before = serde_json::to_vec(&carrying_admit).unwrap();
        complete_participation_intents(data_dir);
        assert_eq!(
            serde_json::to_vec(&load_request(data_dir, "rpr_ca").unwrap()).unwrap(),
            admit_before
        );
        assert!(load_lease(data_dir, "rpl_ca").is_none());
        assert!(!dir.join(RECEIPT_DIR).join("rlr_ca.json").exists());
        assert!(!dir.join(RECEIPT_DIR).join("rqt_ca.json").exists());
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_ca").unwrap();
        assert_eq!(room["participant_lease_refs"], json!([]));

        // The request-transition branch is independently quarantined. Its sealed receipt is
        // structurally canonical but its copied actor/grant fields are not authorization.
        persist_atomic(data_dir, REQUEST_DIR, "rpr_ca", &prior).unwrap();
        let now = json!("2026-02-03T00:00:00Z");
        let updated = apply_transition(
            &prior,
            "transition_intent",
            "evaluate",
            "evaluating",
            &json!("receipt://rqt_cb"),
            &now,
            false,
        );
        let receipt = build_decision_receipt(
            "rqt_cb",
            "RoomParticipationDecisionReceipt",
            "participation-request://rpr_ca",
            "evaluate",
            json!({ "transition": "evaluate", "from": "submitted", "to": "evaluating", "revision_before": 1, "revision_after": 2, "outcome_room_ref": "outcome-room://or_ca" }),
            vec![
                json!("participation-request://rpr_ca"),
                json!("outcome-room://or_ca"),
            ],
            record_output_hash(&updated, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            REQUEST_TRANSITION_NOTE,
            "2026-02-03T00:00:00Z",
            &ta(),
        );
        let mut carrying_transition = prior.clone();
        carrying_transition["transition_intent"] = json!({
            "op": "evaluate",
            "final_record": updated,
            "final_record_hash": record_output_hash(&updated, &[]),
            "receipt_id": "rqt_cb",
            "receipt": receipt,
            "receipt_hash": record_output_hash(&receipt, &[]),
            "at": "2026-02-03T00:00:00Z",
        });
        persist_atomic(data_dir, REQUEST_DIR, "rpr_ca", &carrying_transition).unwrap();
        let transition_before = serde_json::to_vec(&carrying_transition).unwrap();
        complete_participation_intents(data_dir);
        assert_eq!(
            serde_json::to_vec(&load_request(data_dir, "rpr_ca").unwrap()).unwrap(),
            transition_before
        );
        assert!(!dir.join(RECEIPT_DIR).join("rqt_cb.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn close_vs_admit_race_has_one_room_scoped_winner() {
        // Exercise both critical sections concurrently. Legal outcomes are exclusively:
        // close wins with zero admission artifacts, OR admission reserves the room and close is
        // blocked by the live-lease set. Closed + admission evidence is forbidden.
        for round in 0..12u8 {
            let dir = temp_dir(&format!("close-admit-race-{round:x}"));
            let data_dir = dir.to_str().unwrap().to_string();
            let room_tail = format!("or_a{round:x}");
            let request_tail = format!("rpr_a{round:x}");
            let submit_receipt = format!("rqr_a{round:x}");
            let lease_tail = format!("rpl_a{round:x}");
            let lease_receipt = format!("rlr_a{round:x}");
            let request_receipt = format!("rqt_a{round:x}");
            plant_room(&data_dir, &room_tail);
            submit(
                &data_dir,
                &room_tail,
                &request_tail,
                &submit_receipt,
                "2026-02-01T00:00:00Z",
            );
            let prior = load_request(&data_dir, &request_tail).unwrap();
            let admit = canonical_admit_intent(
                &prior,
                &lease_tail,
                &lease_receipt,
                &request_receipt,
                "2026-02-02T00:00:00Z",
            );
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let admit_data = data_dir.clone();
            let admit_room_ref = format!("outcome-room://{room_tail}");
            let admit_request_tail = request_tail.clone();
            let admit_barrier = Arc::clone(&barrier);
            let admit_thread = std::thread::spawn(move || {
                admit_barrier.wait();
                let _participation = PARTICIPATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
                let room_scope = rooms::ROOM_MUTATION_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let room = rooms::resolve_room(&admit_data, &admit_room_ref).unwrap();
                if s(&room, "status", "") != "open" || rooms::pending_intent(&room).is_some() {
                    return false;
                }
                finalize_admit(
                    &admit_data,
                    &admit_request_tail,
                    &prior,
                    &admit,
                    &room_scope,
                )
                .is_ok()
            });

            let close_data = data_dir.clone();
            let close_room_tail = room_tail.clone();
            let close_room_ref = format!("outcome-room://{room_tail}");
            let close_barrier = Arc::clone(&barrier);
            let close_thread = std::thread::spawn(move || {
                close_barrier.wait();
                let _room_scope = rooms::ROOM_MUTATION_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let mut room = rooms::resolve_room(&close_data, &close_room_ref).unwrap();
                if s(&room, "status", "") != "open"
                    || rooms::pending_intent(&room).is_some()
                    || !rooms::live_lease_refs(&room).is_empty()
                {
                    return false;
                }
                room["status"] = json!("closed");
                persist_atomic(&close_data, rooms::ROOM_DIR, &close_room_tail, &room).unwrap();
                true
            });

            let admitted = admit_thread.join().unwrap();
            let closed = close_thread.join().unwrap();
            assert_ne!(
                admitted, closed,
                "exactly one room-scoped operation must win"
            );
            let room =
                rooms::resolve_room(&data_dir, &format!("outcome-room://{room_tail}")).unwrap();
            if admitted {
                assert_eq!(s(&room, "status", ""), "open");
                assert_eq!(
                    rooms::live_lease_refs(&room),
                    vec![format!("participant-lease://{lease_tail}")]
                );
                assert_eq!(
                    s(
                        &load_request(&data_dir, &request_tail).unwrap(),
                        "status",
                        ""
                    ),
                    "admitted"
                );
            } else {
                assert_eq!(s(&room, "status", ""), "closed");
                assert!(load_lease(&data_dir, &lease_tail).is_none());
                assert!(!dir
                    .join(RECEIPT_DIR)
                    .join(format!("{lease_receipt}.json"))
                    .exists());
                assert!(!dir
                    .join(RECEIPT_DIR)
                    .join(format!("{request_receipt}.json"))
                    .exists());
                let request = load_request(&data_dir, &request_tail).unwrap();
                assert_eq!(s(&request, "status", ""), "submitted");
                assert!(request.get("admit_intent").is_none());
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn lease_transitions_walk_receipted_and_revoke_appends_revocation() {
        let dir = temp_dir("lease-walk");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_d4");
        submit(
            data_dir,
            "or_d4",
            "rpr_d4",
            "rqr_d4",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_d4").unwrap();
        let params = validate_admit_params(&json!({ "admitted_role": "reviewer", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example" })).unwrap();
        let now = "2026-02-02T00:00:00Z";
        let final_lease = build_lease(&prior, &params, "rpl_d4", "receipt://rlr_d4", now);
        persist_atomic(data_dir, LEASE_DIR, "rpl_d4", &final_lease).unwrap();
        rooms::bind_room_backlink(
            data_dir,
            "outcome-room://or_d4",
            "participant_lease_bound",
            "participant-lease://rpl_d4",
        )
        .unwrap();
        // suspend → resume → revoke, each optimistically concurrent and receipted.
        let (l1, r1) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 1 }),
            "suspend",
            &["active", "sleeping", "waiting"],
            "suspended",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        )
        .unwrap();
        assert_eq!(l1["status"], json!("suspended"));
        assert_eq!(r1["op"], json!("suspend"));
        // Stale revision: byte-unchanged refusal.
        let stale = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 1 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        );
        assert_eq!(stale.unwrap_err().0, "participant_lease_revision_conflict");
        let (l2, _) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 2 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        )
        .unwrap();
        assert_eq!(l2["status"], json!("active"));
        let (l3, r3) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 3 }),
            "revoke",
            &["active", "sleeping", "waiting", "suspended", "quarantined"],
            "revoked",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        )
        .unwrap();
        assert_eq!(l3["status"], json!("revoked"));
        assert_eq!(
            l3["future_access_revocation_refs"],
            json!([r3["receipt_ref"]]),
            "revocation appends its receipt — future access ends, lineage stays"
        );
        // Terminal: no further transitions.
        let dead = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_d4",
            &json!({ "expected_revision": 4 }),
            "resume",
            &["suspended"],
            "active",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        );
        assert_eq!(dead.unwrap_err().0, "participant_lease_transition_invalid");
        // The lease no longer counts as live.
        assert!(!live_lease_exists(
            data_dir,
            "outcome-room://or_d4",
            "worker://independent-alloy-lab"
        )
        .unwrap());
        // Receipts: 3 transition receipts exist (suspend/resume/revoke).
        let receipts = std::fs::read_dir(dir.join(RECEIPT_DIR)).unwrap().count();
        assert!(
            receipts >= 4,
            "submission + three transition receipts are durable (found {receipts})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lease_transition_intent_is_quarantined_without_replayable_authority() {
        let dir = temp_dir("lease-replay");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_e5");
        submit(
            data_dir,
            "or_e5",
            "rpr_e5",
            "rqr_e5",
            "2026-02-01T00:00:00Z",
        );
        let prior_req = load_request(data_dir, "rpr_e5").unwrap();
        let params = validate_admit_params(&json!({ "admitted_role": "verifier", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example" })).unwrap();
        let lease = build_lease(
            &prior_req,
            &params,
            "rpl_e5",
            "receipt://rlr_e5",
            "2026-02-02T00:00:00Z",
        );
        // Seal a canonical suspend intent ON the lease record, as finalize would, then "crash".
        let now = json!("2026-02-03T00:00:00Z");
        let receipt_ref = json!("receipt://rlt_e5");
        let updated = apply_transition(
            &lease,
            "transition_intent",
            "suspend",
            "suspended",
            &receipt_ref,
            &now,
            false,
        );
        let receipt = build_decision_receipt(
            "rlt_e5",
            "RoomParticipationDecisionReceipt",
            "participant-lease://rpl_e5",
            "suspend",
            json!({ "transition": "suspend", "from": "active", "to": "suspended", "revision_before": 1, "revision_after": 2, "outcome_room_ref": "outcome-room://or_e5" }),
            vec![
                json!("participant-lease://rpl_e5"),
                json!("outcome-room://or_e5"),
            ],
            record_output_hash(&updated, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            LEASE_TRANSITION_NOTE,
            "2026-02-03T00:00:00Z",
            &ta(),
        );
        let mut carrying = lease.clone();
        carrying.as_object_mut().unwrap().insert("transition_intent".into(), json!({
            "op": "suspend", "final_record": updated, "final_record_hash": record_output_hash(&updated, &[]),
            "receipt_id": "rlt_e5", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": "2026-02-03T00:00:00Z",
        }));
        persist_atomic(data_dir, LEASE_DIR, "rpl_e5", &carrying).unwrap();
        let before = serde_json::to_vec(&carrying).unwrap();
        complete_participation_intents(data_dir);
        let after = load_lease(data_dir, "rpl_e5").unwrap();
        assert_eq!(serde_json::to_vec(&after).unwrap(), before);
        assert_eq!(s(&after, "status", ""), "active");
        assert!(after.get("transition_intent").is_some());
        assert!(!dir.join(RECEIPT_DIR).join("rlt_e5.json").exists());

        // This intent is structurally canonical and would pass the old sealed-field replay
        // validator. That is deliberately insufficient: `ta()` is not a re-verifiable signed
        // grant bound to an expected participant/host identity, so production boot applies zero.
        assert!(validate_transition_intent(
            after.get("transition_intent").unwrap(),
            &lease,
            "rpl_e5",
            "participant_lease_id",
            "participant-lease://",
            LEASE_TRANSITIONS,
            "rlt",
            LEASE_TRANSITION_NOTE,
            is_canonical_lease_tail,
        )
        .is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn already_terminal_lease_releases_in_one_boot_pass() {
        let dir = temp_dir("one-boot-release");
        let data_dir = dir.to_str().unwrap();
        let lease = plant_bound_active_lease(data_dir, "or_e8", "rpr_e8", "rqr_e8", "rpl_e8");
        let now = json!("2026-02-03T00:00:00Z");
        let receipt_ref = json!("receipt://rlt_e8");
        let updated = apply_transition(
            &lease,
            "transition_intent",
            "revoke",
            "revoked",
            &receipt_ref,
            &now,
            true,
        );
        let receipt = build_decision_receipt(
            "rlt_e8",
            "RoomParticipationDecisionReceipt",
            "participant-lease://rpl_e8",
            "revoke",
            json!({ "transition": "revoke", "from": "active", "to": "revoked", "revision_before": 1, "revision_after": 2, "outcome_room_ref": "outcome-room://or_e8" }),
            vec![
                json!("participant-lease://rpl_e8"),
                json!("outcome-room://or_e8"),
            ],
            record_output_hash(&updated, TRAIL_EXCLUDES),
            TRAIL_EXCLUDES,
            LEASE_TRANSITION_NOTE,
            "2026-02-03T00:00:00Z",
            &ta(),
        );
        // Model the crash boundary AFTER the governed transition and its receipt are durable but
        // BEFORE the non-decision room-release tail. Boot may finish release without replaying an
        // untrusted decision intent.
        persist_receipt(data_dir, "rlt_e8", &receipt).unwrap();
        persist_atomic(data_dir, LEASE_DIR, "rpl_e8", &updated).unwrap();

        complete_participation_intents(data_dir);

        let terminal = load_lease(data_dir, "rpl_e8").unwrap();
        assert_eq!(s(&terminal, "status", ""), "revoked");
        assert!(terminal.get("transition_intent").is_none());
        let room = rooms::resolve_open_room(data_dir, "outcome-room://or_e8").unwrap();
        assert!(
            room["released_participant_lease_refs"]
                .as_array()
                .unwrap()
                .contains(&json!("participant-lease://rpl_e8")),
            "one boot pass releases an already-durable terminal lease"
        );
        assert!(rooms::live_lease_refs(&room).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminal_release_failure_is_typed_pending_then_one_boot_converges() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("release-pending");
        let data_dir = dir.to_str().unwrap();
        plant_bound_active_lease(data_dir, "or_e9", "rpr_e9", "rqr_e9", "rpl_e9");
        // Break only the room-receipt family after the lease has been bound. The terminal lease
        // receipt/record can commit; the cross-plane release cannot, and must not return success.
        let receipt_dir = dir.join("outcome-room-registry-receipts");
        let receipt_backup = dir.join("outcome-room-registry-receipts-backup");
        let decoy = dir.join("decoy-room-receipts");
        std::fs::rename(&receipt_dir, &receipt_backup).unwrap();
        std::fs::create_dir_all(&decoy).unwrap();
        symlink(&decoy, &receipt_dir).unwrap();

        let (code, _) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_e9",
            &json!({ "expected_revision": 1 }),
            "revoke",
            &["active", "sleeping", "waiting", "suspended", "quarantined"],
            "revoked",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        )
        .unwrap_err();
        assert_eq!(code, "participant_lease_release_pending_convergence");
        assert_eq!(
            s(&load_lease(data_dir, "rpl_e9").unwrap(), "status", ""),
            "revoked",
            "the lease transition is durable even though the compound operation is pending"
        );
        let unreleased = rooms::resolve_open_room(data_dir, "outcome-room://or_e9").unwrap();
        assert!(!rooms::live_lease_refs(&unreleased).is_empty());

        std::fs::remove_file(&receipt_dir).unwrap();
        std::fs::rename(&receipt_backup, &receipt_dir).unwrap();
        complete_participation_intents(data_dir);

        let released = rooms::resolve_open_room(data_dir, "outcome-room://or_e9").unwrap();
        assert!(rooms::live_lease_refs(&released).is_empty());
        assert!(released["released_participant_lease_refs"]
            .as_array()
            .unwrap()
            .contains(&json!("participant-lease://rpl_e9")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creation_declaration_is_fail_closed() {
        // Vocabulary, plane-owned fields, topology, and private-context guards refuse typed.
        let body = declaration_body("or_ff");
        assert!(validate_request_create(&body).is_ok());
        for (mutation, expected_code) in [
            (
                json!({ "status": "admitted" }),
                "room_participation_status_plane_owned",
            ),
            (
                json!({ "participant_lease_ref": "participant-lease://x" }),
                "room_participation_field_plane_owned",
            ),
            (
                json!({ "request_hash": "sha256:forged" }),
                "room_participation_field_plane_owned",
            ),
            (
                json!({ "signature": "sig" }),
                "room_participation_signature_unavailable",
            ),
            (
                json!({ "room_discovery_ref": "room-discovery://x" }),
                "room_participation_discovery_unavailable",
            ),
            (
                json!({ "coordination_topology": "federated_admission" }),
                "room_participation_federated_unavailable",
            ),
            (
                json!({ "coordination_topology": "mesh" }),
                "room_participation_topology_invalid",
            ),
            (
                json!({ "private_context_included": true }),
                "room_participation_private_context_rejected",
            ),
            (
                json!({ "requested_by_ref": "user://someone" }),
                "room_participation_ref_scheme_invalid",
            ),
            (
                json!({ "capability_offer_refs": ["not-a-ref"] }),
                "room_participation_ref_scheme_invalid",
            ),
            (
                json!({ "notes": { "api_key": "SENTINEL" } }),
                "outcome_room_plaintext_secret_rejected",
            ),
        ] {
            let mut b = body.clone();
            for (k, v) in mutation.as_object().unwrap() {
                b.as_object_mut().unwrap().insert(k.clone(), v.clone());
            }
            let (code, _) = validate_request_create(&b).unwrap_err();
            assert_eq!(code, expected_code, "mutation {mutation} → wrong code");
        }
        // Admit params: role vocabulary is canonical.
        let (code, _) = validate_admit_params(&json!({ "admitted_role": "root", "operator_ref": "org://x", "home_domain_ref": "domain://x" })).unwrap_err();
        assert_eq!(code, "participant_lease_role_invalid");
        let _ = code;
    }

    #[test]
    fn reference_grammar_accepts_canonical_forms_and_refuses_aliases() {
        // #74 review finding 4: EXACT canonical scheme names + prefix forms; the earlier bug
        // (canonical `model_route://` refused while noncanonical `model-route://` persisted) is
        // gone. Table-driven over every declared form.
        let accept = [
            (
                "worker_composition_and_dependency_refs",
                json!([
                    "model_route://m",
                    "harness_profile:codex",
                    "package://p",
                    "worker://w",
                    "runtime://r",
                    "provider://pr"
                ]),
            ),
            (
                "capability_offer_refs",
                json!(["capability-offer://c", "ai://a", "package://p"]),
            ),
            (
                "affiliation_and_independent_operation_evidence_refs",
                json!([
                    "certification_claim://cc",
                    "evidence://e",
                    "receipt://r",
                    "org://o"
                ]),
            ),
            (
                "supported_semantic_and_action_profile_refs",
                json!([
                    "ontology://o",
                    "semantic-profile://s",
                    "ontology-mapping://m",
                    "ontology-action://a",
                    "action_schema://sc"
                ]),
            ),
            (
                "eligibility_evidence_refs",
                json!([
                    "conformance_profile://c",
                    "certification_claim://cc",
                    "benchmark://b"
                ]),
            ),
            (
                "requested_role_frontier_and_visibility_refs",
                json!(["restricted_view://rv", "frontier://f", "policy://p"]),
            ),
            (
                "privacy_custody_and_context_policy_refs",
                json!(["privacy_posture://pp", "custody://c", "policy://p"]),
            ),
            (
                "accepted_verifier_settlement_dispute_and_contribution_policy_refs",
                json!([
                    "verifier_path://v",
                    "settlement-intent://s",
                    "dispute://d",
                    "policy://p"
                ]),
            ),
        ];
        for (field, val) in accept {
            let mut b = declaration_body("or_ff");
            b.as_object_mut().unwrap().insert(field.into(), val.clone());
            assert!(
                validate_request_create(&b).is_ok(),
                "canonical {field} {val} must be accepted"
            );
        }
        // Noncanonical aliases + raw strings are refused (a representative set).
        let refuse = [
            (
                "worker_composition_and_dependency_refs",
                json!(["model-route://m"]),
            ), // hyphen alias
            (
                "worker_composition_and_dependency_refs",
                json!(["harness-profile://h"]),
            ), // wrong form
            (
                "affiliation_and_independent_operation_evidence_refs",
                json!(["certification-claim://c"]),
            ),
            (
                "requested_role_frontier_and_visibility_refs",
                json!(["restricted-view://v"]),
            ),
            (
                "privacy_custody_and_context_policy_refs",
                json!(["privacy-posture://p"]),
            ),
            (
                "accepted_verifier_settlement_dispute_and_contribution_policy_refs",
                json!(["verifier-path://v"]),
            ),
            ("capability_offer_refs", json!(["capability_offer://c"])), // underscore where canon has hyphen
            ("capability_offer_refs", json!(["raw-string"])),
        ];
        for (field, val) in refuse {
            let mut b = declaration_body("or_ff");
            b.as_object_mut().unwrap().insert(field.into(), val.clone());
            let (code, _) = validate_request_create(&b).unwrap_err();
            assert_eq!(
                code, "room_participation_ref_scheme_invalid",
                "noncanonical {field} {val} must be refused"
            );
        }
        // Admit params: home_domain_ref accepts ONLY the field-specific Agentgres domain path.
        assert!(validate_admit_params(&json!({ "admitted_role": "implementer", "operator_ref": "org://o", "home_domain_ref": "agentgres://domain/acme" })).is_ok());
        for invalid in [
            "agentgres://not-domain",
            "agentgres://domain",
            "agentgres://domain/",
            "agentgres://artifact/x",
        ] {
            let (code, _) = validate_admit_params(&json!({
                "admitted_role": "implementer",
                "operator_ref": "org://o",
                "home_domain_ref": invalid,
            }))
            .unwrap_err();
            assert_eq!(
                code, "room_participation_ref_scheme_invalid",
                "non-domain Agentgres ref '{invalid}' must be refused"
            );
        }
        let (code, _) = validate_admit_params(&json!({ "admitted_role": "implementer", "operator_ref": "org://o", "home_domain_ref": "domain://d", "ttl_seconds": 3600 })).unwrap_err();
        assert_eq!(
            code, "participant_lease_ttl_unavailable",
            "a non-null TTL is refused until expiry authority exists (#74 finding 3)"
        );
        let (code, _) = validate_admit_params(&json!({ "admitted_role": "implementer", "operator_ref": "org://o", "home_domain_ref": "domain://d", "ttl_seconds": 0 })).unwrap_err();
        assert_eq!(
            code, "participant_lease_ttl_unavailable",
            "even ttl 0 is refused — TTL is unavailable, not merely invalid"
        );
    }

    #[test]
    fn decision_authority_requires_identity_binding_and_refuses_same_hash_foreign_signer() {
        let dir = temp_dir("authority-binding");
        let policy_hash = decision_policy_hash(
            Gov::Host,
            "outcome-room://or_z1",
            "domain://acme-host",
            "admit",
        );
        let request_hash = decision_request_hash(
            Gov::Host,
            "participation-request://rpr_z1",
            "admit",
            1,
            "domain://acme-host",
        );
        let bound_grant = signed_grant(7, &policy_hash, &request_hash);
        let foreign_grant = signed_grant(8, &policy_hash, &request_hash);
        let parsed: ApprovalGrant = serde_json::from_value(bound_grant.clone()).unwrap();
        let authority = ApprovalAuthority {
            schema_version: 1,
            authority_id: parsed.authority_id,
            public_key: parsed.approver_public_key.clone(),
            signature_suite: parsed.approver_suite,
            expires_at: parsed.expires_at,
            revoked: false,
            scope_allowlist: vec!["room_participation.admit".to_string()],
        };
        let binding_hash = [17u8; 32];
        let resolution = PrincipalAuthorityResolutionV1 {
            schema_version: 1,
            principal_ref: "domain://acme-host".to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            coordinates: PrincipalAuthorityBindingCoordinates {
                binding_ref: format!(
                    "wallet.network://principal-authority-binding/{}",
                    hex::encode(binding_hash)
                ),
                binding_version: 1,
                binding_hash,
            },
            required_scope: "room_participation.admit".to_string(),
            matched_scope: "room_participation.admit".to_string(),
            approval_authority_snapshot_hash: authority.artifact_hash().unwrap(),
            authority_id: authority.authority_id,
            authority_public_key: authority.public_key.clone(),
            authority_signature_suite: authority.signature_suite,
            approval_authority: authority,
            resolved_at_ms: parsed.expires_at - 1,
            mutation_audit_event_id: [18u8; 32],
            mutation_audit_event_hash: [19u8; 32],
        };
        let verified_resolution = VerifiedAuthorityResolution {
            authority_binding: json!({ "test_only": "signer-binding-unit-test" }),
            resolution,
        };
        assert!(authorize_decision_for_resolution(
            &json!({ "wallet_approval_grant": bound_grant }),
            Gov::Host,
            "outcome-room://or_z1",
            "domain://acme-host",
            &verified_resolution,
            "participation-request://rpr_z1",
            "admit",
            1,
        )
        .is_ok());
        let (foreign_status, foreign_body) = authorize_decision_for_resolution(
            &json!({ "wallet_approval_grant": foreign_grant.clone() }),
            Gov::Host,
            "outcome-room://or_z1",
            "domain://acme-host",
            &verified_resolution,
            "participation-request://rpr_z1",
            "admit",
            1,
        )
        .unwrap_err();
        assert_eq!(foreign_status, StatusCode::FORBIDDEN);
        assert_eq!(
            foreign_body.0["error"]["code"],
            json!("room_participation_host_authority_required")
        );
        // Spoofing the expected authority_id onto the foreign key invalidates the grant's own
        // signature/key binding and is also refused.
        let mut spoofed = foreign_grant;
        spoofed["authority_id"] = json!(verified_resolution.resolution.authority_id);
        assert!(authorize_decision_for_resolution(
            &json!({ "wallet_approval_grant": spoofed }),
            Gov::Host,
            "outcome-room://or_z1",
            "domain://acme-host",
            &verified_resolution,
            "participation-request://rpr_z1",
            "admit",
            1,
        )
        .is_err());
        // The request hash BINDS the revision — a grant for rev 1 cannot authorize rev 2 (replay).
        let rh1 = decision_request_hash(
            Gov::Host,
            "participation-request://rpr_z1",
            "admit",
            1,
            "domain://acme-host",
        );
        let rh2 = decision_request_hash(
            Gov::Host,
            "participation-request://rpr_z1",
            "admit",
            2,
            "domain://acme-host",
        );
        assert_ne!(
            rh1, rh2,
            "the request hash is revision-bound — replay after the record moves is refused"
        );
        // And it binds the operation + required authority (host vs participant differ).
        assert_ne!(
            decision_policy_hash(
                Gov::Host,
                "outcome-room://or_z1",
                "domain://acme-host",
                "admit"
            ),
            decision_policy_hash(
                Gov::Participant,
                "outcome-room://or_z1",
                "worker://w",
                "withdraw"
            ),
            "host and participant governance derive distinct policies"
        );
        // Governance split: withdraw is the participant's; evaluate/reject/admit are the host's.
        assert!(request_op_gov("withdraw") == Gov::Participant);
        assert!(request_op_gov("evaluate") == Gov::Host && request_op_gov("reject") == Gov::Host);
        assert!(
            lease_op_gov("revoke") == Gov::Host
                && lease_op_gov("suspend") == Gov::Host
                && lease_op_gov("quarantine") == Gov::Host
        );
        assert!(
            lease_op_gov("sleep") == Gov::Participant
                && lease_op_gov("retire") == Gov::Participant
                && lease_op_gov("wake") == Gov::Participant
        );
        // The decision receipt binds actor + grant + policy + request hash.
        let r = build_decision_receipt(
            "rlt_z1",
            "RoomParticipationDecisionReceipt",
            "participant-lease://rpl_z1",
            "revoke",
            json!({}),
            vec![json!("participant-lease://rpl_z1")],
            "sha256:x".into(),
            TRAIL_EXCLUDES,
            LEASE_TRANSITION_NOTE,
            "2026-01-01T00:00:00Z",
            &ta(),
        );
        assert_eq!(r["actor_id"], json!("wallet://acct_test_authority"));
        assert_eq!(
            r["authority_grant_id"],
            json!("wallet.network://grant/approval/testgranthash")
        );
        assert_eq!(r["policy_hash"], json!("sha256:testpolicyhash"));
        assert_eq!(r["input_hash"], json!("sha256:testrequesthash"));
        assert_eq!(r["schema_version"], json!(DECISION_RECEIPT_SCHEMA));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn room_close_interlock_blocks_while_a_lease_is_live_then_releases() {
        // #74 review finding 2: a room may not close while it has a live participant lease; a
        // revoke/retire RELEASES the slot (idempotent) and then close is admitted. Lease
        // transitions also refuse once the room is not open. Driven through the real seams.
        use super::super::outcome_room_routes as orr;
        let dir = temp_dir("close-interlock");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_c7");
        // Admit a lease (bind through the seam so the room counts it live).
        submit(
            data_dir,
            "or_c7",
            "rpr_c7",
            "rqr_c7",
            "2026-02-01T00:00:00Z",
        );
        let prior = load_request(data_dir, "rpr_c7").unwrap();
        let params = validate_admit_params(&json!({ "admitted_role": "implementer", "operator_ref": "org://alloy-lab", "home_domain_ref": "domain://alloy-lab.example" })).unwrap();
        let now = "2026-02-02T00:00:00Z";
        let lease = build_lease(&prior, &params, "rpl_c7", "receipt://rlr_c7", now);
        persist_atomic(data_dir, LEASE_DIR, "rpl_c7", &lease).unwrap();
        orr::bind_room_backlink(
            data_dir,
            "outcome-room://or_c7",
            "participant_lease_bound",
            "participant-lease://rpl_c7",
        )
        .unwrap();
        // Close is BLOCKED while the lease is live.
        let live = orr::live_lease_refs(
            &orr::resolve_open_room(data_dir, "outcome-room://or_c7").unwrap(),
        );
        assert_eq!(
            live,
            vec!["participant-lease://rpl_c7".to_string()],
            "the room counts the lease live"
        );
        // Revoke the lease (host op) via the real transition core → releases the room slot.
        let (revoked, _r) = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_c7",
            &json!({ "expected_revision": 1 }),
            "revoke",
            &["active", "sleeping", "waiting", "suspended", "quarantined"],
            "revoked",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        )
        .unwrap();
        assert_eq!(revoked["status"], json!("revoked"));
        let after = orr::resolve_open_room(data_dir, "outcome-room://or_c7").unwrap();
        assert!(
            orr::live_lease_refs(&after).is_empty(),
            "the revoke released the room slot — no live leases remain"
        );
        // A further transition on the revoked lease refuses (terminal), and even a fresh op is
        // refused once the room is closed. Close the room directly (all leases released).
        let mut closed = after.clone();
        closed
            .as_object_mut()
            .unwrap()
            .insert("status".into(), json!("closed"));
        super::super::durable_fs::persist_record_durable(data_dir, orr::ROOM_DIR, "or_c7", &closed)
            .unwrap();
        let denied = transition_record(
            data_dir,
            LEASE_DIR,
            "rpl_c7",
            &json!({ "expected_revision": 2 }),
            "suspend",
            &["active", "sleeping", "waiting"],
            "suspended",
            "participant-lease://",
            "rlt",
            LEASE_TRANSITION_NOTE,
            "participant_lease",
            &ta(),
        );
        assert_eq!(
            denied.unwrap_err().0,
            "participant_lease_room_not_open",
            "no lease transition is admitted once the room is not open"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_key_binding_refuses_a_relocated_intent() {
        // An intent whose sealed request claims a DIFFERENT id than its filename stem is refused.
        let dir = temp_dir("rebind");
        let data_dir = dir.to_str().unwrap();
        plant_room(data_dir, "or_f6");
        let declaration = validate_request_create(&declaration_body("or_f6")).unwrap();
        let record = seal_request(
            &declaration,
            "rpr_f6",
            "receipt://rqr_f6",
            "2026-02-01T00:00:00Z",
        );
        let receipt = json!({ "receipt_ref": "receipt://rqr_f6" });
        let intent = json!({
            "kind": "submit", "request_tail": "rpr_f6", "request_ref": "participation-request://rpr_f6",
            "room_ref": "outcome-room://or_f6",
            "final_request": record, "final_request_hash": record_output_hash(&record, &[]),
            "receipt_id": "rqr_f6", "receipt": receipt, "receipt_hash": record_output_hash(&receipt, &[]),
            "at": "2026-02-01T00:00:00Z",
        });
        // Stored under a DIFFERENT stem: refused before any write.
        persist_atomic(data_dir, SUBMIT_INTENT_DIR, "rpr_f7", &intent).unwrap();
        complete_participation_intents(data_dir);
        assert!(
            load_request(data_dir, "rpr_f6").is_none(),
            "nothing admitted at the claimed id"
        );
        assert!(
            load_request(data_dir, "rpr_f7").is_none(),
            "nothing admitted at the stem id"
        );
        assert!(
            dir.join(SUBMIT_INTENT_DIR).join("rpr_f7.json").exists(),
            "intent retained"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
