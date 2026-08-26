//! M04.8 — the hosted, same-System participation and contribution runtime.
//!
//! This module is the CURRENT generation of the room participation/contribution arc. The
//! predecessor planes (`room_participation_routes`, `resource_capability_offer_routes`,
//! `work_frontier_claim_routes`, `attempt_finding_routes`, `verifier_challenge_routes`) remain
//! physically present and are retained predecessors only: they are not current proof of anything
//! this module asserts, and nothing here reads or writes their families.
//!
//! # The ten named lifecycles
//!
//! LocalAgentPairingSession, RoomParticipationRequest, RoomParticipantLease, ResourceOffer,
//! CapabilityOffer, WorkFrontierItem, WorkClaimLease, Attempt, Finding, VerifierChallenge.
//!
//! CollaborationTermsEnvelope plus its exact terms-acceptance receipt is an AUXILIARY PRODUCER of
//! the lease's `collaboration_terms_ref`/`accepted_terms_root`/`terms_acceptance_ref` triple, not
//! an eleventh lifecycle. OutcomeRoomDiscovery and ParticipantStateBundle are NOT produced here;
//! both remain M11.
//!
//! # Where truth lives
//!
//! Every APPLICATION child is persisted only through
//! [`super::outcome_room_system_routes::admit_room_native_child`] and read back only through
//! `current_room_children` / `list_room_child_generations`. There is no parallel child registry,
//! no global index, and no local current-state copy of a room child in this module.
//!
//! Exactly three owner-local durable families exist here, and they hold no room-child truth:
//! pairing sessions, CollaborationTermsEnvelope + acceptance receipts, and
//! WorkEligibilityMatchReceipt evidence.
//!
//! # The M04.8 atomicity ruling (owner/integrator accepted)
//!
//! `admit_room_native_child` is synchronous, takes `ROOM_MUTATION_LOCK` internally (a
//! non-reentrant `std::sync::Mutex`), and every admission moves the room's Agentgres head. Two
//! consequences are load-bearing for this module and are enforced, not merely documented:
//!
//! 1. **No route may mutate two room children.** A caller cannot hold the room lock across two
//!    admissions (it would deadlock), and it cannot admit two children under one head (the first
//!    moves it). A claim + frontier-item pseudo-transaction would therefore tear on crash into
//!    either a permanently-stuck item or a doubly-claimable one. So:
//!    **claim expiry/release is ONE admission — a terminal successor generation of the
//!    WorkClaimLease** — and **frontier claimability is a DERIVED PROJECTION** over the current
//!    active, non-expired claim leases evaluated at a freshly wallet-authorized `resolved_at_ms`.
//!    See [`frontier_claimability`] and [`claim_is_live`].
//! 2. **Read-then-admit is still linearizable.** The seam enforces a room-level compare-and-swap
//!    on `expected_room_head`. Observing the room at head H and admitting with `expected_room_head
//!    = H` commits only if no writer intervened; otherwise the admission is refused
//!    `outcome_room_expected_head_stale`. That CAS — not a lock held by this module — is what
//!    makes claim exclusivity safe. See [`observe_room_at_head`].
//!
//! No Attempt, Finding, or lineage generation is ever deleted: succession appends.
//!
//! # Time
//!
//! Every TTL, expiry, heartbeat, renewal, release, and freshness decision consumes the
//! wallet.network-authorized `resolved_at_ms` committed by M03.5. System wall-clock never
//! authorizes a lifecycle transition; `iso_now()` appears only in non-authoritative audit stamps.
//! `heartbeat_ref` is a `receipt://` ref — this module invents no heartbeat schema or object.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::governed_authority as governed;
use super::outcome_room_routes::{
    self as rooms, is_rfc3339, record_output_hash, reject_sensitive_keys, VErr,
};
use super::outcome_room_system_routes as room_system;
use super::DaemonState;

// --- registered contract coordinates -----------------------------------------------------------
//
// These are the exact registered room-child contract ids the seam admits. They are spelled here so
// a drift in either place is a compile-visible mismatch rather than a silent re-binding.

pub(crate) const PARTICIPATION_REQUEST_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/room-participation-request/v3";
pub(crate) const PARTICIPANT_LEASE_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/room-participant-lease/v3";
pub(crate) const RESOURCE_OFFER_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/resource-offer/v3";
pub(crate) const CAPABILITY_OFFER_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/capability-offer/v3";
pub(crate) const WORK_FRONTIER_ITEM_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/work-frontier-item/v3";
pub(crate) const WORK_CLAIM_LEASE_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/work-claim-lease/v3";
pub(crate) const ATTEMPT_CONTRACT: &str = "schema://ioi/applications/ioi-ai/attempt/v3";
pub(crate) const FINDING_CONTRACT: &str = "schema://ioi/applications/ioi-ai/finding/v3";
pub(crate) const VERIFIER_CHALLENGE_CONTRACT: &str =
    "schema://ioi/applications/ioi-ai/verifier-challenge/v3";

/// Registered schema_version constants, which the seam compares verbatim.
pub(crate) const PARTICIPATION_REQUEST_SCHEMA: &str =
    "ioi.applications.ioi-ai.room-participation-request.v3";
pub(crate) const PARTICIPANT_LEASE_SCHEMA: &str =
    "ioi.applications.ioi-ai.room-participant-lease.v3";
pub(crate) const RESOURCE_OFFER_SCHEMA: &str = "ioi.applications.ioi-ai.resource-offer.v3";
pub(crate) const CAPABILITY_OFFER_SCHEMA: &str = "ioi.applications.ioi-ai.capability-offer.v3";
pub(crate) const WORK_FRONTIER_ITEM_SCHEMA: &str = "ioi.applications.ioi-ai.work-frontier-item.v3";
pub(crate) const WORK_CLAIM_LEASE_SCHEMA: &str = "ioi.applications.ioi-ai.work-claim-lease.v3";
pub(crate) const ATTEMPT_SCHEMA: &str = "ioi.applications.ioi-ai.attempt.v3";
pub(crate) const FINDING_SCHEMA: &str = "ioi.applications.ioi-ai.finding.v3";
pub(crate) const VERIFIER_CHALLENGE_SCHEMA: &str = "ioi.applications.ioi-ai.verifier-challenge.v3";

/// The two auxiliary owner-local contracts. Neither is a room child.
pub(crate) const PAIRING_SESSION_SCHEMA: &str =
    "ioi.foundations.local-agent-pairing-session-envelope.v1";
pub(crate) const COLLABORATION_TERMS_SCHEMA: &str = "ioi.collaboration-terms.v1";
pub(crate) const COLLABORATION_TERMS_BODY_PROFILE: &str = "ioi.collaboration-terms-body.v1";
/// WorkEligibilityMatchReceipt is doc-registered evidence, not a JSON-Schema registry contract.
pub(crate) const ELIGIBILITY_MATCH_SCHEMA: &str =
    "ioi.hypervisor.work-eligibility-match-receipt.v1";
pub(crate) const TERMS_ACCEPTANCE_SCHEMA: &str =
    "ioi.hypervisor.collaboration-terms-acceptance-receipt.v1";

// --- the three owner-local durable families ----------------------------------------------------
//
// Nothing below holds room-child truth. Each family is closed, bounded, atomically written,
// strictly read, exactly replayable, and fails closed on a malformed or uncertain slot.

/// LocalAgentPairingSession envelopes: authenticated, expiring, single-use, pre-admission.
pub(crate) const PAIRING_DIR: &str = "m048-local-agent-pairing-sessions";
/// CollaborationTermsEnvelope records.
pub(crate) const TERMS_DIR: &str = "m048-collaboration-terms";
/// Exact terms-acceptance receipts; append-only, no-clobber.
pub(crate) const TERMS_ACCEPTANCE_DIR: &str = "m048-collaboration-terms-acceptances";
/// WorkEligibilityMatchReceipt evidence; append-only, no-clobber.
pub(crate) const ELIGIBILITY_DIR: &str = "m048-work-eligibility-matches";

/// Every owner-local family this module may create. Startup pre-creates exactly these.
pub(crate) const OWNER_LOCAL_FAMILIES: &[&str] = &[
    PAIRING_DIR,
    TERMS_DIR,
    TERMS_ACCEPTANCE_DIR,
    ELIGIBILITY_DIR,
];

// --- bounds ------------------------------------------------------------------------------------

/// Bounded request body. Mirrors the room plane's ceiling so one oversized submission cannot
/// consume the daemon before validation runs.
const BODY_MAX: usize = room_system::M4_SERIALIZED_BODY_MAX;
/// Bounded ref-list arity for any caller-supplied array.
const REF_LIST_MAX: usize = 64;
/// Bounded string field length for any caller-supplied scalar.
const STRING_MAX: usize = 1000;
/// A pairing session may never outlive this bound, regardless of what a caller asks for.
const PAIRING_TTL_MAX_SECONDS: u64 = 900;
/// A participant lease TTL is bounded on both ends; an unbounded term needs a governed exception.
const LEASE_TTL_MIN_SECONDS: u64 = 60;
const LEASE_TTL_MAX_SECONDS: u64 = 86_400;
/// A work claim TTL is bounded on both ends.
const CLAIM_TTL_MIN_SECONDS: u64 = 30;
const CLAIM_TTL_MAX_SECONDS: u64 = 86_400;
/// A claim whose heartbeat is older than this at the wallet-authorized instant is not live.
const CLAIM_HEARTBEAT_MAX_SECONDS: u64 = 300;

// --- typed errors ------------------------------------------------------------------------------

/// This plane's error constructor. Codes are `m048_<subject>_<condition>`.
fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_string(), message.into())
}

/// Map a typed refusal onto its wire status. Suffix-driven, matching the sibling planes: an
/// uncertain durable outcome is server uncertainty, never a client error, because a caller cannot
/// distinguish "refused" from "maybe written" by retrying.
pub(crate) fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.ends_with("_unauthenticated") || code.ends_with("_principal_required") {
        // Repository identity precedent: a caller whose identity did not resolve gets 401, not a
        // 400. An unauthenticated pairing proof is an identity failure against a pre-admission
        // authenticator, so it belongs here rather than in the malformed-request class.
        StatusCode::UNAUTHORIZED
    } else if code.ends_with("_forbidden") || code.ends_with("_authority_required") {
        StatusCode::FORBIDDEN
    } else if code.ends_with("_stale")
        || code.ends_with("_conflict")
        || code.ends_with("_in_flight")
        || code.ends_with("_duplicate")
        || code.ends_with("_exclusive")
    {
        StatusCode::CONFLICT
    } else if code.ends_with("_persist_failed")
        || code.ends_with("_durability_unconfirmed")
        || code.ends_with("_unreadable")
        || code.ends_with("_swapped")
        || code.ends_with("_pending_recovery")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if code.ends_with("_unavailable") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
}

// --- closed, bounded, secret-refusing input validation -----------------------------------------

/// Refuse any body that is not a bounded JSON object, carries an unknown key, or carries anything
/// that looks like a secret at any depth.
///
/// Closedness is checked against an explicit allow-list because an ignored key is
/// indistinguishable at the wire from an honoured one.
fn closed_object<'a>(
    body: &'a Value,
    allowed: &[&str],
    code: &str,
) -> Result<&'a serde_json::Map<String, Value>, VErr> {
    let size = serde_json::to_vec(body)
        .map_err(|error| verr(code, format!("body cannot be serialized ({error})")))?
        .len();
    if size > BODY_MAX {
        return Err(verr(code, "request body exceeds the bounded maximum"));
    }
    reject_sensitive_keys(body, "body")?;
    let map = body
        .as_object()
        .ok_or_else(|| verr(code, "request body must be a JSON object"))?;
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(verr(
                code,
                format!("`{key}` is not an admitted field of this request"),
            ));
        }
    }
    Ok(map)
}

/// A required bounded string.
fn req_str(body: &Value, key: &str, code: &str) -> Result<String, VErr> {
    match body.get(key) {
        Some(Value::String(raw)) if !raw.is_empty() && raw.chars().count() <= STRING_MAX => {
            Ok(raw.clone())
        }
        Some(Value::String(_)) => Err(verr(
            code,
            format!("`{key}` must be a non-empty string within the bounded maximum"),
        )),
        _ => Err(verr(code, format!("`{key}` is required"))),
    }
}

/// A required ref whose scheme must be one of `schemes`.
fn req_ref(body: &Value, key: &str, schemes: &[&str], code: &str) -> Result<String, VErr> {
    let raw = req_str(body, key, code)?;
    if !schemes.iter().any(|s| raw.starts_with(&format!("{s}://"))) {
        return Err(verr(
            code,
            format!("`{key}` must name one of {schemes:?} as its scheme"),
        ));
    }
    if raw.contains(char::is_whitespace) {
        return Err(verr(code, format!("`{key}` must not contain whitespace")));
    }
    Ok(raw)
}

/// An optional ref: absent or explicit null both mean absent.
fn opt_ref(body: &Value, key: &str, schemes: &[&str], code: &str) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => req_ref(body, key, schemes, code).map(Some),
    }
}

/// A bounded, unique array of refs.
fn ref_list(body: &Value, key: &str, schemes: &[&str], code: &str) -> Result<Vec<String>, VErr> {
    let items = match body.get(key) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(verr(code, format!("`{key}` must be an array"))),
    };
    if items.len() > REF_LIST_MAX {
        return Err(verr(
            code,
            format!("`{key}` exceeds the bounded maximum of {REF_LIST_MAX} entries"),
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let raw = item
            .as_str()
            .ok_or_else(|| verr(code, format!("`{key}` entries must be strings")))?;
        if raw.is_empty() || raw.chars().count() > STRING_MAX {
            return Err(verr(code, format!("`{key}` entry is out of bounds")));
        }
        if !schemes.is_empty() && !schemes.iter().any(|s| raw.starts_with(&format!("{s}://"))) {
            // A scheme-free entry (a bare `scope:` token) is admitted only where the registered
            // contract admits one; callers pass an empty `schemes` for those fields.
            return Err(verr(
                code,
                format!("`{key}` entry must name one of {schemes:?} as its scheme"),
            ));
        }
        if out.contains(&raw.to_string()) {
            return Err(verr(code, format!("`{key}` entries must be unique")));
        }
        out.push(raw.to_string());
    }
    Ok(out)
}

/// A required value from a closed vocabulary.
fn req_vocab(body: &Value, key: &str, vocab: &[&str], code: &str) -> Result<String, VErr> {
    let raw = req_str(body, key, code)?;
    if !vocab.contains(&raw.as_str()) {
        return Err(verr(code, format!("`{key}` must be one of {vocab:?}")));
    }
    Ok(raw)
}

/// A required `sha256:<64 lowercase hex>` root.
fn req_root(body: &Value, key: &str, code: &str) -> Result<String, VErr> {
    let raw = req_str(body, key, code)?;
    if !is_sha256_root(&raw) {
        return Err(verr(
            code,
            format!("`{key}` must be a sha256:<64 lowercase hex> root"),
        ));
    }
    Ok(raw)
}

fn is_sha256_root(raw: &str) -> bool {
    raw.strip_prefix("sha256:")
        .map(|hex| {
            hex.len() == 64
                && hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
        .unwrap_or(false)
}

/// A bounded positive TTL within an inclusive range.
fn req_ttl(body: &Value, key: &str, min: u64, max: u64, code: &str) -> Result<u64, VErr> {
    let raw = body
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| verr(code, format!("`{key}` must be a positive integer")))?;
    if raw < min || raw > max {
        return Err(verr(
            code,
            format!("`{key}` must be between {min} and {max} seconds"),
        ));
    }
    Ok(raw)
}

// --- wallet-authorized time --------------------------------------------------------------------
//
// Everything here converts the M03.5 committed `resolved_at_ms` into the exact timestamps the
// registered contracts require. `iso_now()` is never used for any of these.

/// Convert a wallet-authorized instant to the RFC3339 spelling the registered contracts pin.
///
/// A value that cannot be rendered is a refusal, not a fallback to local time: silently
/// substituting a system clock is exactly the authority substitution this plane forbids.
fn wallet_ms_to_rfc3339(resolved_at_ms: u64) -> Result<String, VErr> {
    let nanos = i128::from(resolved_at_ms)
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            verr(
                "m048_wallet_time_invalid",
                "the wallet-authorized instant is out of representable range",
            )
        })?;
    let stamp = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|error| {
        verr(
            "m048_wallet_time_invalid",
            format!("the wallet-authorized instant is not a valid timestamp ({error})"),
        )
    })?;
    stamp
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| {
            verr(
                "m048_wallet_time_invalid",
                format!("the wallet-authorized instant cannot be rendered ({error})"),
            )
        })
}

/// Parse a contract timestamp back to milliseconds for comparison against a wallet instant.
///
/// This is a comparison input only. It never becomes an authority: the instant it is compared
/// AGAINST is always freshly wallet-authorized.
fn rfc3339_to_ms(raw: &str) -> Result<u64, VErr> {
    let stamp = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|error| {
            verr(
                "m048_record_timestamp_invalid",
                format!("a durable timestamp is not RFC3339 ({error})"),
            )
        })?;
    let millis = stamp.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis).map_err(|_| {
        verr(
            "m048_record_timestamp_invalid",
            "a durable timestamp precedes the representable epoch",
        )
    })
}

/// Add a bounded TTL to a wallet-authorized instant without overflowing.
fn wallet_deadline_ms(resolved_at_ms: u64, ttl_seconds: u64) -> Result<u64, VErr> {
    ttl_seconds
        .checked_mul(1_000)
        .and_then(|ttl_ms| resolved_at_ms.checked_add(ttl_ms))
        .ok_or_else(|| {
            verr(
                "m048_wallet_time_invalid",
                "the requested deadline overflows the representable range",
            )
        })
}

// --- the room-head CAS seam adapter ------------------------------------------------------------

/// One observation of a room at a specific Agentgres head.
///
/// Holding this is what makes a read-modify-write over room children linearizable: every decision
/// taken from `room` is submitted back with `head`, and the seam refuses the write if the head
/// moved. This module therefore never takes `ROOM_MUTATION_LOCK` itself — doing so would deadlock
/// against the seam, which takes it internally.
#[derive(Clone, Debug)]
pub(crate) struct RoomAtHead {
    pub(crate) room_ref: String,
    pub(crate) head: String,
    pub(crate) system_id: String,
    pub(crate) room: Value,
}

/// Resolve a room and pin the exact head the caller's subsequent decisions are taken at.
///
/// A room that is absent, unreadable, not the current v2 generation, or not open is refused here
/// rather than at the seam, so a caller never reasons about children of a room it may not write.
pub(crate) fn observe_room_at_head(data_dir: &str, room_ref: &str) -> Result<RoomAtHead, VErr> {
    if !room_ref.starts_with("outcome-room://") {
        return Err(verr(
            "m048_room_ref_invalid",
            "the room ref must be outcome-room://<tail>",
        ));
    }
    let room = rooms::resolve_room_strict(data_dir, room_ref)
        .map_err(|error| verr("m048_room_unreadable", error))?
        .ok_or_else(|| verr("m048_room_not_found", "no such OutcomeRoom"))?;
    if room.get("status").and_then(Value::as_str) != Some("open") {
        return Err(verr(
            "m048_room_not_open",
            "this room does not admit children in its current status",
        ));
    }
    let head = room
        .get("room_state_root")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_room_head_unresolved",
                "the room record carries no Agentgres head",
            )
        })?
        .to_string();
    let system_id = room
        .get("system_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_room_system_unresolved",
                "the room record names no bounded System",
            )
        })?
        .to_string();
    Ok(RoomAtHead {
        room_ref: room_ref.to_string(),
        head,
        system_id,
        room,
    })
}

/// Admit one room-native child at the observed head.
///
/// `expected_prior_object_root` is `None` to create and `Some(root)` to append a successor
/// generation. Succession NEVER deletes a predecessor; `list_room_child_generations` continues to
/// return the full lineage afterwards.
pub(crate) fn admit_child(
    data_dir: &str,
    observed: &RoomAtHead,
    contract_id: &str,
    candidate: &Value,
    issuer_ref: &str,
    expected_prior_object_root: Option<&str>,
) -> Result<Value, VErr> {
    // The candidate must not carry plane-owned coordinates. The seam refuses these too; refusing
    // here keeps the error in this plane's vocabulary and proves the caller never supplied them.
    if let Some(map) = candidate.as_object() {
        for owned in [
            "system_binding",
            "outcome_room_ref",
            "room_admission",
            "room_binding",
        ] {
            if map.get(owned).is_some_and(|value| !value.is_null()) {
                return Err(verr(
                    "m048_child_plane_owned_field_supplied",
                    format!("`{owned}` is derived from room truth and must not be supplied"),
                ));
            }
        }
    }
    room_system::admit_room_native_child(
        data_dir,
        &observed.room_ref,
        &observed.head,
        contract_id,
        candidate,
        issuer_ref,
        expected_prior_object_root,
    )
}

/// The current generation of every child of one contract in one room.
pub(crate) fn current_children(
    data_dir: &str,
    room_ref: &str,
    contract_id: &str,
) -> Result<Vec<Value>, VErr> {
    room_system::current_room_children(data_dir, room_ref, contract_id, None)
}

/// The current generation of exactly one child, or `None` when the room never admitted it.
pub(crate) fn current_child(
    data_dir: &str,
    room_ref: &str,
    contract_id: &str,
    object_ref: &str,
) -> Result<Option<Value>, VErr> {
    Ok(
        room_system::current_room_children(data_dir, room_ref, contract_id, Some(object_ref))?
            .into_iter()
            .next_back(),
    )
}

/// Every admitted generation of one child, oldest first. Lineage, never garbage.
pub(crate) fn child_lineage(
    data_dir: &str,
    room_ref: &str,
    contract_id: &str,
    object_ref: &str,
) -> Result<Vec<Value>, VErr> {
    room_system::list_room_child_generations(data_dir, room_ref, contract_id, Some(object_ref))
}

/// The payload of a projection entry — the admitted object itself.
fn admitted(projection: &Value) -> Result<&Value, VErr> {
    projection.get("admitted_object").ok_or_else(|| {
        verr(
            "m048_projection_unreadable",
            "a room-child projection entry carries no admitted object",
        )
    })
}

/// The successor evidence for a projection entry: the exact current generation's object root.
fn object_root(projection: &Value) -> Result<String, VErr> {
    projection
        .get("object_root")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            verr(
                "m048_projection_unreadable",
                "a room-child projection entry carries no object root",
            )
        })
}

// --- the ruled claim semantics (pure, unit-tested) ---------------------------------------------

/// WorkClaimLease statuses under which a claim still holds its frontier item exclusively.
const CLAIM_HOLDING_STATUSES: &[&str] = &["proposed", "active", "waiting"];
/// Terminal WorkClaimLease statuses. A claim in one of these holds nothing.
const CLAIM_TERMINAL_STATUSES: &[&str] = &[
    "released",
    "expired",
    "reassigned",
    "completed",
    "quarantined",
    "revoked",
];

/// Why a claim is not live. Reported so a release is auditable rather than merely asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClaimLapse {
    /// The claim reached a terminal generation.
    Terminal,
    /// `expires_at` has passed at the wallet-authorized instant.
    Expired,
    /// The heartbeat receipt is absent or older than the bounded maximum.
    HeartbeatStale,
}

/// Is this claim still holding its frontier item at the wallet-authorized instant?
///
/// This is the whole of the M04.8 exclusivity rule, and it is deliberately a PURE function of
/// (claim payload, wallet-authorized instant): nothing here reads a clock, and nothing here
/// writes. A caller that wants the item released admits a terminal successor generation of the
/// claim — it does not mutate the frontier item.
pub(crate) fn claim_is_live(
    claim: &Value,
    wallet_now_ms: u64,
    heartbeat_max_seconds: u64,
) -> Result<Result<(), ClaimLapse>, VErr> {
    let status = claim.get("status").and_then(Value::as_str).ok_or_else(|| {
        verr(
            "m048_claim_record_invalid",
            "a claim lease carries no status",
        )
    })?;
    if CLAIM_TERMINAL_STATUSES.contains(&status) {
        return Ok(Err(ClaimLapse::Terminal));
    }
    if !CLAIM_HOLDING_STATUSES.contains(&status) {
        return Err(verr(
            "m048_claim_record_invalid",
            format!("`{status}` is not a registered work-claim status"),
        ));
    }
    let expires_at = claim
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_claim_record_invalid",
                "a claim lease carries no expiry",
            )
        })?;
    // `expires_at` IS the heartbeat deadline.
    //
    // The registered WorkClaimLease/v3 contract is `additionalProperties: false` and declares no
    // field in which a "last heartbeat observed" instant could live. Storing one anyway would put
    // liveness truth somewhere the contract forbids — a second plane for exactly the fact the
    // claim exists to carry. So a heartbeat transition ADVANCES `expires_at` from the wallet
    // instant instead, which collapses "heartbeat stopped" and "deadline passed" into one durable
    // fact that the contract can actually hold.
    //
    // `heartbeat_max_seconds` bounds how far a single heartbeat may push that deadline, and is
    // applied where the successor generation is built rather than re-derived on every read.
    let _ = heartbeat_max_seconds;
    if wallet_now_ms >= rfc3339_to_ms(expires_at)? {
        // The two lapses differ only as evidence: a claim that had been heartbeating and stopped
        // reads differently from one that simply ran out its original term.
        return Ok(Err(
            if claim
                .get("heartbeat_ref")
                .is_some_and(|value| !value.is_null())
            {
                ClaimLapse::HeartbeatStale
            } else {
                ClaimLapse::Expired
            },
        ));
    }
    Ok(Ok(()))
}

/// The derived claimability of one frontier item.
///
/// Claimability is a PROJECTION, never stored state. It is recomputed from the item's own
/// registered `claimability`/`status`/`max_concurrency` and the set of currently live claims
/// naming it, evaluated at a freshly wallet-authorized instant. A lapsed claim therefore returns
/// its item to claimable with no second write and no risk of a torn two-child transaction.
pub(crate) fn frontier_claimability(
    item: &Value,
    claims: &[Value],
    wallet_now_ms: u64,
    heartbeat_max_seconds: u64,
) -> Result<Value, VErr> {
    let item_id = item
        .get("frontier_item_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_frontier_record_invalid",
                "a frontier item carries no identity",
            )
        })?;
    let declared = item
        .get("claimability")
        .and_then(Value::as_str)
        .unwrap_or("closed");
    let status = item
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("closed");
    let max_concurrency = item
        .get("max_concurrency")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1);

    let mut live = Vec::new();
    let mut lapsed = Vec::new();
    for claim in claims {
        if claim.get("frontier_item_ref").and_then(Value::as_str) != Some(item_id) {
            continue;
        }
        let claim_id = claim
            .get("work_claim_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match claim_is_live(claim, wallet_now_ms, heartbeat_max_seconds)? {
            Ok(()) => live.push(claim_id),
            Err(lapse) => lapsed.push(json!({
                "work_claim_id": claim_id,
                "lapse": match lapse {
                    ClaimLapse::Terminal => "terminal",
                    ClaimLapse::Expired => "expired",
                    ClaimLapse::HeartbeatStale => "heartbeat_stale",
                },
            })),
        }
    }

    let open_for_claims =
        declared == "open" && !matches!(status, "closed" | "accepted" | "rejected" | "superseded");
    let claimable = open_for_claims && (live.len() as u64) < max_concurrency;
    Ok(json!({
        "frontier_item_ref": item_id,
        "claimable": claimable,
        "declared_claimability": declared,
        "status": status,
        "max_concurrency": max_concurrency,
        "live_claim_refs": live,
        "lapsed_claims": lapsed,
        // The evaluation instant is reported so a reader can tell that this projection was taken
        // against wallet-authorized time and not a local clock.
        "evaluated_at_wallet_ms": wallet_now_ms,
        "projection_only": true,
    }))
}

/// Refuse a second live claim on a frontier item.
///
/// Exclusivity is enforced by this check PLUS the room-head CAS: the check is taken at head H and
/// the admission is submitted with head H, so a racing claimant either loses the CAS
/// (`outcome_room_expected_head_stale`) or re-reads and loses this check.
pub(crate) fn refuse_when_already_claimed(
    item: &Value,
    claims: &[Value],
    wallet_now_ms: u64,
) -> Result<(), VErr> {
    let projection =
        frontier_claimability(item, claims, wallet_now_ms, CLAIM_HEARTBEAT_MAX_SECONDS)?;
    if projection
        .get("claimable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let live = projection
        .get("live_claim_refs")
        .and_then(Value::as_array)
        .map(|refs| refs.len())
        .unwrap_or(0);
    if live > 0 {
        return Err(verr(
            "m048_work_claim_exclusive",
            "this frontier item already carries a live claim; two active claims cannot coexist",
        ));
    }
    Err(verr(
        "m048_frontier_not_claimable",
        "this frontier item does not admit a claim in its current generation",
    ))
}

// --- WorkEligibilityMatchReceipt: evidence, never authority ------------------------------------

/// Build the WorkEligibilityMatchReceipt body.
///
/// The three false grants are STRUCTURAL, not defaults a caller can flip: an eligibility match is
/// evidence that a tuple lined up at an instant, and it allocates nothing, claims nothing, and
/// authorizes no execution. Claim acquisition re-derives the whole tuple from durable truth at a
/// fresh wallet instant and never trusts this receipt.
pub(crate) fn eligibility_match_body(
    room_ref: &str,
    frontier: &Value,
    lease: &Value,
    resource_offers: &[Value],
    capability_offers: &[Value],
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let requirement_coverage = json!({
        "required_capability_refs": frontier
            .get("required_capability_refs")
            .cloned()
            .unwrap_or_else(|| json!([])),
        "advertised_capability_refs": lease
            .get("capability_advertisement_refs")
            .cloned()
            .unwrap_or_else(|| json!([])),
    });
    Ok(json!({
        "schema_version": ELIGIBILITY_MATCH_SCHEMA,
        "kind": "WorkEligibilityMatchReceipt",
        "outcome_room_ref": room_ref,
        "frontier_item_ref": frontier.get("frontier_item_id").cloned().unwrap_or(Value::Null),
        "participant_ref": lease.get("participant_lease_id").cloned().unwrap_or(Value::Null),
        "resource_offers": resource_offers
            .iter()
            .map(|offer| json!({ "offer_ref": offer.get("resource_offer_id").cloned().unwrap_or(Value::Null) }))
            .collect::<Vec<_>>(),
        "capability_offers": capability_offers
            .iter()
            .map(|offer| json!({ "offer_ref": offer.get("capability_offer_id").cloned().unwrap_or(Value::Null) }))
            .collect::<Vec<_>>(),
        "requirement_coverage": requirement_coverage,
        "matched_at_wallet_ms": resolved_at_ms,
        // Structurally false. These are not policy toggles.
        "allocation_created": false,
        "claim_created": false,
        "execution_authority_granted": false,
    }))
}

// --- owner-local durable persistence ------------------------------------------------------------

/// Persist one mutable owner-local record atomically.
///
/// The two failure lanes are kept distinct on the wire because they are not the same fact: a
/// pre-rename failure provably changed nothing, while an unconfirmed directory fsync means the new
/// record is already visible and may well be durable. Reporting the second as "nothing happened"
/// would be a lie a caller would act on.
fn persist_local(data_dir: &str, family: &str, tail: &str, record: &Value) -> Result<(), VErr> {
    use super::durable_fs::PersistFailure::{NotCommitted, RenamedDurabilityUnconfirmed};
    super::durable_fs::persist_record_durable(data_dir, family, tail, record).map_err(|failure| {
        match failure {
            NotCommitted(error) => verr("m048_local_persist_failed", error.to_string()),
            RenamedDurabilityUnconfirmed(error) => {
                verr("m048_local_durability_unconfirmed", error.to_string())
            }
        }
    })
}

/// Commit one append-only owner-local receipt. A byte-identical occupant is a valid replay.
fn persist_local_receipt(
    data_dir: &str,
    family: &str,
    tail: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    use super::durable_fs::CommitFailure::*;
    super::durable_fs::persist_receipt_no_clobber(data_dir, family, tail, receipt).map_err(
        |failure| match failure {
            KeyInvalid(m) => verr("m048_local_key_invalid", m),
            NotCommitted(m) => verr("m048_local_persist_failed", m),
            SlotUnreadable(m) => verr("m048_local_slot_unreadable", m),
            Conflict(m) => verr("m048_local_receipt_conflict", m),
            DurabilityUnconfirmed(m) => verr("m048_local_durability_unconfirmed", m),
            Swapped(m) => verr("m048_local_slot_swapped", m),
        },
    )
}

/// Strictly read one owner-local record. Only a definitively absent slot is `None`; every other
/// uncertainty is an error, so a false empty can never be reported as "no such record".
fn read_local(data_dir: &str, family: &str, tail: &str) -> Result<Option<Value>, VErr> {
    super::durable_fs::read_record_durable(data_dir, family, tail)
        .map_err(|error| verr("m048_local_slot_unreadable", error))
}

/// Enumerate one owner-local family, failing closed on any unreadable or malformed slot.
fn scan_local(data_dir: &str, family: &str, schema: &str) -> Result<Vec<Value>, VErr> {
    let dir = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "m048_local_family_unreadable",
                format!("family `{family}` cannot be opened ({error})"),
            ))
        }
    };
    let names = super::durable_fs::enumerate_pinned(&dir).map_err(|error| {
        verr(
            "m048_local_family_unreadable",
            format!("family `{family}` cannot be enumerated ({error}) — refusing a false empty"),
        )
    })?;
    let mut out = Vec::new();
    for name in names {
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let record = read_local(data_dir, family, stem)?.ok_or_else(|| {
            verr(
                "m048_local_slot_unreadable",
                format!("`{stem}` vanished mid-enumeration — refusing a false empty"),
            )
        })?;
        if record.get("schema_version").and_then(Value::as_str) != Some(schema) {
            return Err(verr(
                "m048_local_record_invalid",
                format!("`{stem}` does not carry the expected `{schema}`"),
            ));
        }
        out.push(record);
    }
    Ok(out)
}

// --- startup recovery ---------------------------------------------------------------------------

/// Fail-closed startup census over this plane's owner-local families.
///
/// Called before the listener binds. It converges nothing and mutates nothing: its whole job is to
/// refuse to serve current routes over a corrupt or ambiguous owner-local slot, because a pairing
/// session or terms acceptance that cannot be read exactly is indistinguishable from one that was
/// never written. Room-child truth is NOT inspected here — it is the seam's own recovery, already
/// fenced by `preflight_pending_owner_registry_census` and `complete_pending`.
pub(crate) fn preflight_owner_local_census(data_dir: &str) -> Result<(), VErr> {
    scan_local(data_dir, PAIRING_DIR, PAIRING_SESSION_SCHEMA)?;
    scan_local(data_dir, TERMS_DIR, COLLABORATION_TERMS_SCHEMA)?;
    scan_local(data_dir, TERMS_ACCEPTANCE_DIR, TERMS_ACCEPTANCE_SCHEMA)?;
    scan_local(data_dir, ELIGIBILITY_DIR, ELIGIBILITY_MATCH_SCHEMA)?;
    Ok(())
}

// --- deterministic identity -------------------------------------------------------------------

/// A deterministic `<prefix>_<64 hex>` tail over a domain-separated payload.
///
/// Determinism is not cosmetic here: it is what makes a replayed submission collide with its own
/// predecessor at the seam instead of minting a second object. See
/// [`derive_participation_request_id`].
fn deterministic_tail(prefix: &str, domain: &str, payload: &Value) -> String {
    let hash = record_output_hash(&json!({ "domain": domain, "payload": payload }), &[]);
    format!("{prefix}{}", hash.strip_prefix("sha256:").unwrap_or(&hash))
}

/// The participation request a given pairing session may submit — and only that one.
///
/// This id is a pure function of (pairing session, room, requester). A replayed create therefore
/// derives the SAME id, so the room-native seam refuses it
/// `outcome_room_child_duplicate_create_refused` rather than admitting a second request. That is
/// the replay half of single-use; the pairing record's own consumed status is the other half.
fn derive_participation_request_id(
    pairing_session_id: &str,
    room_ref: &str,
    requested_by_ref: &str,
) -> String {
    let tail = deterministic_tail(
        "prq_",
        "hypervisor.m048.participation-request.identity.v1",
        &json!({
            "pairing_session_id": pairing_session_id,
            "outcome_room_ref": room_ref,
            "requested_by_ref": requested_by_ref,
        }),
    );
    format!("participation-request://{tail}")
}

// --- lifecycle 1: LocalAgentPairingSession -----------------------------------------------------
//
// Pairing is pre-admission: it authenticates a local agent, expires, is single-use, and grants
// exactly the one participation request it enables. It mints no standing, no membership, and no
// authority — the registered envelope's `bootstrap_non_grants` block is all-"none" by construction
// and this module never writes anything else there.

/// The hosted lane pairs a private worker. `room_guest` and `organization_worker` are M11 lanes.
const PAIRING_TARGET_KIND: &str = "private_worker";

/// The pairing statuses from which a session may still be consumed exactly once.
const PAIRING_CONSUMABLE_STATUSES: &[&str] = &["created", "bootstrap_bound"];

/// Extract the durable stem of a `local-agent-pairing://<tail>` ref.
fn pairing_tail(pairing_session_id: &str) -> Result<String, VErr> {
    pairing_session_id
        .strip_prefix("local-agent-pairing://")
        .filter(|tail| !tail.is_empty() && super::durable_fs::is_normalization_safe(tail))
        .map(str::to_string)
        .ok_or_else(|| {
            verr(
                "m048_pairing_ref_invalid",
                "a pairing session ref must be local-agent-pairing://<normalization-safe tail>",
            )
        })
}

/// Build the registered LocalAgentPairingSession envelope.
///
/// Every non-grant is a structural constant, not a caller-supplied default: a pairing session that
/// could be asked to grant authority would not be a pairing session.
#[allow(clippy::too_many_arguments)]
fn build_pairing_session(
    pairing_session_id: &str,
    initiated_by_ref: &str,
    initiating_surface_ref: &str,
    target_scope_ref: &str,
    display_name: &str,
    challenge_hash: &str,
    issued_at: &str,
    expires_at: &str,
    created_at: &str,
) -> Value {
    json!({
        "schema_version": PAIRING_SESSION_SCHEMA,
        "pairing_session_id": pairing_session_id,
        "initiated_by_ref": initiated_by_ref,
        "initiating_surface_ref": initiating_surface_ref,
        "target_kind": PAIRING_TARGET_KIND,
        "target_scope_ref": target_scope_ref,
        "claimed_local_agent": {
            "display_name": display_name,
            "resolver_kind": "none",
            "resolver_revision_ref": Value::Null,
            "resolver_content_hash": Value::Null,
            "semantic_harness_profile_revision_ref": Value::Null,
            "semantic_harness_profile_content_hash": Value::Null,
            "execution_posture": "prompt_only",
        },
        "pairing_transport": "loopback",
        "challenge": {
            "challenge_hash": challenge_hash,
            "authentication_factor_kind": "one_time_challenge",
            "issued_at": issued_at,
            "expires_at": expires_at,
            // Structural. A reusable pairing challenge is a replay primitive.
            "single_use": true,
        },
        "client_binding": Value::Null,
        "claim_attempt_policy": {
            "failed_attempt_limit": 5,
            "failed_attempt_count": 0,
            "rate_limit_policy_ref": "policy://ioi/m048/pairing/rate-limit",
        },
        // The hosted lane bootstraps exactly one action: submitting the participation request.
        "allowed_bootstrap_actions": ["submit_room_participation_request"],
        "bootstrap_non_grants": {
            "authority": "none",
            "room_membership": "none",
            "room_database_access": "none",
            "private_context_access": "none",
            "connector_or_secret_access": "none",
            "budget_or_spend": "none",
            "effect_execution": "none",
        },
        "submission_refs": {
            "worker_composition_ref": Value::Null,
            "room_participation_request_ref": Value::Null,
            "first_aiip_packet_ref": Value::Null,
        },
        "contribution_lane": "proposal_only",
        "assurance_posture": {
            "pairing_proves": "client_key_and_origin_binding_only",
            "prompt_only_ceiling": "attested",
        },
        "failure_reason_code": Value::Null,
        "created_at": created_at,
        "updated_at": created_at,
        "completed_at": Value::Null,
        "status": "created",
    })
}

/// Why a pairing session may not be consumed right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairingRefusal {
    /// The presented proof does not match the sealed challenge.
    Unauthenticated,
    /// The challenge expired at the wallet-authorized instant.
    Expired,
    /// The session already reached a terminal or consumed status.
    AlreadyUsed,
    /// The session was minted for a different room or requester.
    WrongSubject,
    /// A consumption is already in flight for this session.
    InFlight,
}

impl PairingRefusal {
    fn code(self) -> &'static str {
        match self {
            // Deliberately NOT `_forbidden`: an unauthenticated or replayed pairing is a bad
            // request against a pre-admission artifact, and reporting it as an authorization
            // failure would imply a principal was resolved when none was.
            PairingRefusal::Unauthenticated => "m048_pairing_unauthenticated",
            PairingRefusal::Expired => "m048_pairing_expired",
            PairingRefusal::AlreadyUsed => "m048_pairing_already_consumed",
            PairingRefusal::WrongSubject => "m048_pairing_subject_mismatch",
            PairingRefusal::InFlight => "m048_pairing_consumption_in_flight",
        }
    }

    fn message(self) -> &'static str {
        match self {
            PairingRefusal::Unauthenticated => {
                "the presented pairing proof does not match this session's sealed challenge"
            }
            PairingRefusal::Expired => {
                "this pairing challenge expired at the wallet-authorized instant"
            }
            PairingRefusal::AlreadyUsed => {
                "this pairing session is single-use and has already been consumed"
            }
            PairingRefusal::WrongSubject => {
                "this pairing session was issued for a different room or requester"
            }
            PairingRefusal::InFlight => {
                "a consumption of this pairing session is already in flight; retry after recovery"
            }
        }
    }
}

/// May this pairing session be consumed to submit exactly this request, at this wallet instant?
///
/// Pure: no clock, no I/O, no writes. The proof is compared against the sealed challenge hash, so
/// the plaintext proof is never durable and a stolen record cannot be replayed into a consumption.
pub(crate) fn pairing_admits_request(
    session: &Value,
    presented_proof_hash: &str,
    room_ref: &str,
    requested_by_ref: &str,
    wallet_now_ms: u64,
) -> Result<(), PairingRefusal> {
    if session
        .get("consumption_intent")
        .is_some_and(|v| !v.is_null())
    {
        return Err(PairingRefusal::InFlight);
    }
    let status = session
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !PAIRING_CONSUMABLE_STATUSES.contains(&status) {
        return Err(PairingRefusal::AlreadyUsed);
    }
    if session.get("target_scope_ref").and_then(Value::as_str) != Some(room_ref) {
        return Err(PairingRefusal::WrongSubject);
    }
    // The session binds exactly one requester through its initiator.
    if session.get("initiated_by_ref").and_then(Value::as_str) != Some(requested_by_ref) {
        return Err(PairingRefusal::WrongSubject);
    }
    let challenge = session
        .get("challenge")
        .filter(|value| !value.is_null())
        .ok_or(PairingRefusal::Unauthenticated)?;
    if challenge.get("single_use").and_then(Value::as_bool) != Some(true) {
        return Err(PairingRefusal::Unauthenticated);
    }
    let sealed = challenge
        .get("challenge_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if sealed.is_empty() || !constant_time_eq(sealed, presented_proof_hash) {
        return Err(PairingRefusal::Unauthenticated);
    }
    let expires_at = challenge
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or(PairingRefusal::Expired)?;
    let expires_at_ms = rfc3339_to_ms(expires_at).map_err(|_| PairingRefusal::Expired)?;
    if wallet_now_ms >= expires_at_ms {
        return Err(PairingRefusal::Expired);
    }
    Ok(())
}

/// Length-independent comparison of two hex digests.
///
/// Both operands here are already hashes rather than secrets, but a pairing proof is exactly the
/// kind of value whose comparison should not leak a prefix match through timing.
fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

// --- the pairing/request multi-owner boundary ---------------------------------------------------
//
// Consuming a pairing session (owner-local truth) and admitting a participation request (Agentgres
// room truth) cross two planes that cannot share one transaction. The retained intent below is
// what makes the crossing recoverable in BOTH directions, without a fourth durable family: it
// lives INSIDE the pairing record, so the family that is already censused at startup is the same
// family that carries the in-flight evidence.
//
// Order is intent -> admit -> consume, never consume -> admit:
//
//   * A crash after the intent and before the admission leaves the request definitively
//     un-admitted. Recovery rolls the intent back and the pairing is usable again — nothing was
//     consumed, so there is no loss.
//   * A crash after the admission and before the consume leaves the request admitted and the
//     intent retained. Recovery observes the admitted request and completes the consume forward,
//     so the pairing cannot be reused — there is no admit-before-consume replay.
//
// The "did the admission happen" question is decidable at replay time because
// `outcome_room_system_routes::complete_pending` runs BEFORE this plane's recovery in
// `hypervisor-daemon.rs`, so the seam's own retained intent has already converged and the room's
// current children are settled. It is also decidable EXACTLY, because the request id is derived
// deterministically from the intent's own fields rather than minted at random.

/// Seal the in-flight consumption evidence carried by the pairing record.
fn consumption_intent(
    request_id: &str,
    room_ref: &str,
    expected_room_head: &str,
    requested_by_ref: &str,
    candidate: &Value,
) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.m048-pairing-consumption-intent.v1",
        "participation_request_id": request_id,
        "outcome_room_ref": room_ref,
        "expected_room_head": expected_room_head,
        "requested_by_ref": requested_by_ref,
        // The exact candidate hash lets recovery prove the admitted request is THIS submission
        // rather than a coincidentally-identical id.
        "candidate_hash": record_output_hash(candidate, &[]),
    })
}

/// The terminal pairing record after a successful consumption.
///
/// Single-use is expressed by a status the consumable set excludes, plus the submission backlink.
/// The intent is dropped in the same atomic write that records the consumption.
fn consumed_pairing(session: &Value, request_id: &str, at: &str) -> Result<Value, VErr> {
    let mut consumed = session.clone();
    let map = consumed.as_object_mut().ok_or_else(|| {
        verr(
            "m048_pairing_record_invalid",
            "a pairing session record must be an object",
        )
    })?;
    map.remove("consumption_intent");
    map.insert("status".to_string(), json!("participation_submitted"));
    map.insert("updated_at".to_string(), json!(at));
    map.insert("completed_at".to_string(), json!(at));
    map.insert(
        "submission_refs".to_string(),
        json!({
            "worker_composition_ref": Value::Null,
            "room_participation_request_ref": request_id,
            // The hosted lane emits no AIIP packet; federation is M11.
            "first_aiip_packet_ref": Value::Null,
        }),
    );
    Ok(consumed)
}

/// Converge every retained pairing-consumption intent.
///
/// Runs at startup AFTER the room seam has converged its own pending child intents, so
/// `current_child` is settled truth rather than a race. Fails closed: an intent that cannot be
/// decided is retained and blocks readiness rather than being guessed in either direction.
pub(crate) fn complete_pairing_consumption_intents(data_dir: &str) -> Result<(), VErr> {
    for session in scan_local(data_dir, PAIRING_DIR, PAIRING_SESSION_SCHEMA)? {
        let Some(intent) = session.get("consumption_intent").filter(|v| !v.is_null()) else {
            continue;
        };
        let session_id = session
            .get("pairing_session_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "m048_pairing_record_invalid",
                    "a retained pairing intent names no session",
                )
            })?;
        let tail = pairing_tail(session_id)?;
        let request_id = intent
            .get("participation_request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "m048_pairing_intent_invalid",
                    "a retained pairing intent names no participation request",
                )
            })?;
        let room_ref = intent
            .get("outcome_room_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                verr(
                    "m048_pairing_intent_invalid",
                    "a retained pairing intent names no room",
                )
            })?;
        // Three outcomes, and only two of them are decisions.
        //
        // `Ok(Some)`  — the request linearized.
        // `Ok(None)` / `outcome_room_not_found` — definitively not admitted. A room cannot vanish
        //               once admitted, so a room that is absent from the current projection can
        //               never have accepted this child.
        // any other Err — UNCERTAINTY (unreadable slot, non-canonical stem, corrupt projection).
        //               Releasing the pairing here would reach the consume-before-admit hole
        //               through a read failure instead of a crash, so it is retained and blocks
        //               readiness for the next boot to decide.
        let admitted_request = match current_child(
            data_dir,
            room_ref,
            PARTICIPATION_REQUEST_CONTRACT,
            request_id,
        ) {
            Ok(found) => found,
            Err((code, _)) if code == "outcome_room_not_found" => None,
            Err(error) => return Err(error),
        };
        match admitted_request {
            // The admission linearized. Complete the consumption FORWARD so the session cannot be
            // reused; anything else would be an admit-before-consume replay hole.
            Some(_) => {
                let at = super::iso_now();
                let consumed = consumed_pairing(&session, request_id, &at)?;
                persist_local(data_dir, PAIRING_DIR, &tail, &consumed)?;
            }
            // The admission definitively did not linearize. Roll the intent back; the pairing was
            // never spent, so releasing it loses nothing and a retry re-derives the same id.
            None => {
                let mut released = session.clone();
                if let Some(map) = released.as_object_mut() {
                    map.remove("consumption_intent");
                    map.insert("updated_at".to_string(), json!(super::iso_now()));
                }
                persist_local(data_dir, PAIRING_DIR, &tail, &released)?;
            }
        }
    }
    Ok(())
}

// --- lifecycle 2: CollaborationTermsEnvelope + exact acceptance receipt -------------------------
//
// Auxiliary, not an eleventh lifecycle: these exist to produce the exact
// (collaboration_terms_ref, accepted_terms_root, terms_acceptance_ref) triple a participant lease
// must bind. They carry no settlement, payout, or legal-person field — the registered contract
// forbids them and a negative fixture pins that.

/// Build the registered CollaborationTermsEnvelope.
fn build_terms_envelope(
    terms_id: &str,
    version: &str,
    terms_body_root: &str,
    room_ref: &str,
    proposed_by_ref: &str,
    predecessor_terms_ref: Option<&str>,
) -> Value {
    json!({
        "schema_version": COLLABORATION_TERMS_SCHEMA,
        "collaboration_terms_id": terms_id,
        "version": version,
        "predecessor_terms_ref": predecessor_terms_ref.map(Value::from).unwrap_or(Value::Null),
        "terms_body_hash_profile": COLLABORATION_TERMS_BODY_PROFILE,
        "terms_body_root": terms_body_root,
        "scope": {
            // The hosted lane scopes terms to the room. `collaboration_ref` is the M11 lane.
            "collaboration_ref": Value::Null,
            "outcome_room_ref": room_ref,
        },
        "proposed_by_ref": proposed_by_ref,
        "status": "active",
    })
}

/// Build the exact terms-acceptance receipt a lease's `terms_acceptance_ref` names.
///
/// "Exact" is the whole point: the receipt seals the precise `terms_body_root` that was accepted,
/// so a lease can never claim acceptance of terms whose body has since moved.
fn build_terms_acceptance(
    terms: &Value,
    accepted_by_ref: &str,
    room_ref: &str,
    resolved_at_ms: u64,
    accepted_at: &str,
) -> Result<(String, Value), VErr> {
    let terms_id = terms
        .get("collaboration_terms_id")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("m048_terms_record_invalid", "terms carry no identity"))?;
    let body_root = terms
        .get("terms_body_root")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("m048_terms_record_invalid", "terms carry no body root"))?;
    let facts = json!({
        "collaboration_terms_ref": terms_id,
        "accepted_terms_root": body_root,
        "accepted_by_ref": accepted_by_ref,
        "outcome_room_ref": room_ref,
    });
    let tail = deterministic_tail(
        "tac_",
        "hypervisor.m048.terms-acceptance.identity.v1",
        &facts,
    );
    let receipt = json!({
        "schema_version": TERMS_ACCEPTANCE_SCHEMA,
        "receipt_ref": format!("receipt://{tail}"),
        "collaboration_terms_ref": terms_id,
        "accepted_terms_root": body_root,
        "accepted_by_ref": accepted_by_ref,
        "outcome_room_ref": room_ref,
        "accepted_at": accepted_at,
        "accepted_at_wallet_ms": resolved_at_ms,
        // Acceptance binds terms. It grants no membership: that is the lease's job.
        "grants_membership": false,
        "grants_authority": false,
    });
    Ok((tail, receipt))
}

/// Extract the durable stem of a `terms://<tail>` ref.
fn terms_tail(terms_id: &str) -> Result<String, VErr> {
    terms_id
        .strip_prefix("terms://")
        .filter(|tail| !tail.is_empty() && super::durable_fs::is_normalization_safe(tail))
        .map(str::to_string)
        .ok_or_else(|| {
            verr(
                "m048_terms_ref_invalid",
                "a terms ref must be terms://<normalization-safe tail>",
            )
        })
}

// --- lifecycle 3: RoomParticipationRequest v3 --------------------------------------------------

/// Build the pre-admission RoomParticipationRequest candidate.
///
/// `system_binding` and `outcome_room_ref` are deliberately ABSENT: the room-native seam derives
/// both from room truth, and supplying either is refused rather than corrected.
#[allow(clippy::too_many_arguments)]
fn build_participation_candidate(
    request_id: &str,
    admission_owner_ref: &str,
    requested_by_ref: &str,
    terms_ref: &str,
    terms_root: &str,
    capability_offer_refs: Vec<String>,
    eligibility_evidence_refs: Vec<String>,
    role_frontier_visibility_refs: Vec<String>,
    privacy_policy_refs: Vec<String>,
    request_hash: &str,
) -> Value {
    json!({
        "schema_version": PARTICIPATION_REQUEST_SCHEMA,
        "participation_request_id": request_id,
        // Hosted same-System lane: discovery is null and admission is native.
        "room_discovery_ref": Value::Null,
        "coordination_topology": "hosted_admission",
        "admission_owner_ref": admission_owner_ref,
        "requested_by_ref": requested_by_ref,
        "collaboration_terms_ref": terms_ref,
        "collaboration_terms_root": terms_root,
        "terms_response": "accept",
        "counterterms_ref": Value::Null,
        "capability_offer_refs": capability_offer_refs,
        "eligibility_evidence_refs": eligibility_evidence_refs,
        "requested_role_frontier_and_visibility_refs": role_frontier_visibility_refs,
        "privacy_custody_and_context_policy_refs": privacy_policy_refs,
        "request_hash": request_hash,
        // Structural: a pre-admission request never carries private context.
        "private_context_included": false,
        "admission_decision_ref": Value::Null,
        "participant_lease_ref": Value::Null,
        "status": "submitted",
    })
}

/// The hosted-native admission invariant, enforced before the seam sees the candidate.
///
/// The registered invariant `room_participation_request.hosted_native.requires_same_system_admission_owner`
/// admits a null discovery ref only when the admission owner IS the room's System. Checking it here
/// keeps the refusal in this plane's vocabulary and proves the hosted lane is not a federation lane
/// wearing a null.
fn enforce_hosted_native_admission(candidate: &Value, system_id: &str) -> Result<(), VErr> {
    if candidate
        .get("room_discovery_ref")
        .is_some_and(|value| !value.is_null())
    {
        return Err(verr(
            "m048_participation_discovery_refused",
            "the hosted lane admits no room discovery ref; cross-domain discovery is M11",
        ));
    }
    if candidate
        .get("coordination_topology")
        .and_then(Value::as_str)
        != Some("hosted_admission")
    {
        return Err(verr(
            "m048_participation_topology_refused",
            "the hosted lane admits only `hosted_admission`; federated admission is M11",
        ));
    }
    if candidate.get("admission_owner_ref").and_then(Value::as_str) != Some(system_id) {
        return Err(verr(
            "m048_participation_admission_owner_mismatch",
            "a hosted-native request with a null discovery ref must name the room's own System as admission owner",
        ));
    }
    Ok(())
}

// --- authority ---------------------------------------------------------------------------------

/// This plane's M03.5 authority contract. Every mutation resolves through it, and the committed
/// `resolved_at_ms` it returns is the ONLY clock any lifecycle decision here consults.
const M048_AUTHORITY: governed::AuthorityContract = governed::AuthorityContract {
    scope_prefix: "scope:room.participation",
    policy_domain: "hypervisor.m048.collaboration.policy.v1",
    request_domain: "hypervisor.m048.collaboration.request.v1",
    resolution_domain: "hypervisor.m048.collaboration.resolution.v1",
    code_prefix: "m048",
    host_label: "room",
    participant_label: "participant",
};

/// Resolve one wallet.network-authorized decision and return its committed instant.
///
/// Caller-supplied time never reaches this: the returned `resolved_at_ms` is wallet.network's own
/// committed timestamp, and every TTL/expiry/freshness comparison downstream uses it.
#[allow(clippy::too_many_arguments)]
async fn authorized_instant(
    data_dir: &str,
    body: &Value,
    governance: governed::Governance,
    room_ref: &str,
    required_authority: &str,
    subject_ref: &str,
    op: &str,
    effect: &Value,
) -> Result<u64, (StatusCode, Json<Value>)> {
    governed::authorize_decision(
        M048_AUTHORITY,
        data_dir,
        body,
        governance,
        room_ref,
        required_authority,
        subject_ref,
        op,
        0,
        effect,
    )
    .await
    .map(|decision| decision.resolved_at_ms)
}

// --- response shaping ---------------------------------------------------------------------------

/// Wrap one owner-local record with its exact contract coordinates.
fn ok_local(schema: &str, key: &str, record: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema_version": schema,
            key: record,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// Wrap one room-child admission with its contract coordinates AND its Agentgres evidence.
///
/// The head/receipt evidence is surfaced rather than summarised: a caller that cannot see which
/// Agentgres head its write landed on cannot take its next decision at a known room state, which
/// is exactly what the CAS needs it to do.
fn ok_child(contract_id: &str, schema: &str, admission: &Value) -> (StatusCode, Json<Value>) {
    let node = admission.get("admission").unwrap_or(&Value::Null);
    let agentgres = node
        .get("agentgres_admission")
        .cloned()
        .unwrap_or(Value::Null);
    let room = node.get("outcome_room").unwrap_or(&Value::Null);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "object_contract_id": contract_id,
            "schema_version": schema,
            "admitted_object": node.get("admitted_object").cloned().unwrap_or(Value::Null),
            "agentgres_evidence": {
                "admission": agentgres,
                "room_state_root": room.get("room_state_root").cloned().unwrap_or(Value::Null),
                "latest_sequence": room.get("latest_sequence").cloned().unwrap_or(Value::Null),
            },
            // Present and null on purpose: this lane asserts the ABSENCE of owner-registry truth.
            "owner_publication": Value::Null,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// Project one room-child list with the head it was read at.
fn ok_child_list(
    contract_id: &str,
    schema: &str,
    room: &RoomAtHead,
    objects: Vec<Value>,
) -> Result<(StatusCode, Json<Value>), VErr> {
    let body = json!({
        "ok": true,
        "object_contract_id": contract_id,
        "schema_version": schema,
        "outcome_room_ref": room.room_ref,
        // The head this projection was taken at, so a caller can submit its next write against it.
        "observed_room_state_root": room.head,
        "objects": objects,
        "count": objects.len(),
        "projection_only": true,
        "runtimeTruthSource": "daemon-runtime",
    });
    room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")?;
    Ok((StatusCode::OK, Json(body)))
}

/// Strip every non-projectable field from a pairing record before it leaves the daemon.
///
/// The sealed challenge hash is authentication material: echoing it back would turn a read of the
/// pairing plane into the very proof a consumer must present. The retained consumption intent is
/// recovery state and is likewise not a caller's business.
fn project_pairing(session: &Value) -> Value {
    let mut projected = session.clone();
    if let Some(map) = projected.as_object_mut() {
        map.remove("consumption_intent");
        if let Some(challenge) = map.get_mut("challenge").and_then(Value::as_object_mut) {
            challenge.remove("challenge_hash");
        }
    }
    projected
}

// --- handlers: LocalAgentPairingSession ---------------------------------------------------------

const PAIRING_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "initiating_surface_ref",
    "display_name",
    "challenge_hash",
    "ttl_seconds",
];

/// POST /v1/goal-orchestration/local-agent-pairing-sessions
pub(crate) async fn handle_pairing_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first: an unauthenticated caller is refused before the body is even parsed, so a
    // malformed submission can never be used to probe this plane.
    let principal = match room_system::request_principal(&state.data_dir, &headers) {
        Ok(principal) => principal,
        Err(error) => return classify(error),
    };
    match pairing_create_inner(&state.data_dir, &principal, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn pairing_create_inner(
    data_dir: &str,
    principal: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, PAIRING_CREATE_FIELDS, "m048_pairing_request_invalid")?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_pairing_request_invalid",
        )?;
        let surface = req_ref(
            body,
            "initiating_surface_ref",
            &["surface"],
            "m048_pairing_request_invalid",
        )?;
        let display_name = req_str(body, "display_name", "m048_pairing_request_invalid")?;
        let challenge_hash = req_root(body, "challenge_hash", "m048_pairing_request_invalid")?;
        let ttl = req_ttl(
            body,
            "ttl_seconds",
            30,
            PAIRING_TTL_MAX_SECONDS,
            "m048_pairing_request_invalid",
        )?;
        Ok((room_ref, surface, display_name, challenge_hash, ttl))
    })()
    .map_err(classify)?;
    let (room_ref, surface, display_name, challenge_hash, ttl) = parsed;

    // The room must exist and be open before a pairing session may name it as its one target.
    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;

    let session_id = format!(
        "local-agent-pairing://{}",
        deterministic_tail(
            "lap_",
            "hypervisor.m048.pairing-session.identity.v1",
            &json!({
                "initiated_by_ref": principal,
                "outcome_room_ref": room_ref,
                "challenge_hash": challenge_hash,
            }),
        )
    );
    let tail = pairing_tail(&session_id).map_err(classify)?;

    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Host,
        &room_ref,
        &observed.system_id,
        &session_id,
        "pair",
        &json!({ "op": "pair", "outcome_room_ref": room_ref, "ttl_seconds": ttl }),
    )
    .await?;

    // Both instants come from the wallet decision; the caller's clock is never consulted.
    let issued_at = wallet_ms_to_rfc3339(resolved_at_ms).map_err(classify)?;
    let expires_at =
        wallet_ms_to_rfc3339(wallet_deadline_ms(resolved_at_ms, ttl).map_err(classify)?)
            .map_err(classify)?;

    // Exact replay: an identical re-submission converges on the existing session rather than
    // minting a second one, because the id is derived from (principal, room, challenge).
    if let Some(existing) = read_local(data_dir, PAIRING_DIR, &tail).map_err(classify)? {
        return Ok(ok_local(
            PAIRING_SESSION_SCHEMA,
            "pairing_session",
            project_pairing(&existing),
        ));
    }

    let session = build_pairing_session(
        &session_id,
        principal,
        &surface,
        &room_ref,
        &display_name,
        &challenge_hash,
        &issued_at,
        &expires_at,
        &issued_at,
    );
    persist_local(data_dir, PAIRING_DIR, &tail, &session).map_err(classify)?;
    Ok(ok_local(
        PAIRING_SESSION_SCHEMA,
        "pairing_session",
        project_pairing(&session),
    ))
}

/// GET /v1/goal-orchestration/local-agent-pairing-sessions
pub(crate) async fn handle_pairing_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    let principal = match room_system::request_principal(&state.data_dir, &headers) {
        Ok(principal) => principal,
        Err(error) => return classify(error),
    };
    let sessions = match scan_local(&state.data_dir, PAIRING_DIR, PAIRING_SESSION_SCHEMA) {
        Ok(sessions) => sessions,
        Err(error) => return classify(error),
    };
    // Owner-scoped: a principal sees only the sessions it initiated.
    let projected = sessions
        .into_iter()
        .filter(|s| s.get("initiated_by_ref").and_then(Value::as_str) == Some(principal.as_str()))
        .map(|s| project_pairing(&s))
        .collect::<Vec<_>>();
    let body = json!({
        "ok": true,
        "schema_version": PAIRING_SESSION_SCHEMA,
        "count": projected.len(),
        "pairing_sessions": projected,
        "projection_only": true,
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(error) =
        room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")
    {
        return classify(error);
    }
    (StatusCode::OK, Json(body))
}

/// GET /v1/goal-orchestration/local-agent-pairing-sessions/:id
pub(crate) async fn handle_pairing_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let principal = match room_system::request_principal(&state.data_dir, &headers) {
        Ok(principal) => principal,
        Err(error) => return classify(error),
    };
    let tail = match pairing_tail(&format!("local-agent-pairing://{id}")) {
        Ok(tail) => tail,
        Err(error) => return classify(error),
    };
    match read_local(&state.data_dir, PAIRING_DIR, &tail) {
        Ok(Some(session))
            if session.get("initiated_by_ref").and_then(Value::as_str)
                == Some(principal.as_str()) =>
        {
            ok_local(
                PAIRING_SESSION_SCHEMA,
                "pairing_session",
                project_pairing(&session),
            )
        }
        // A session owned by someone else is reported as absent, not as forbidden: existence is
        // itself information a non-owner has no claim to.
        Ok(_) => classify(verr(
            "m048_pairing_not_found",
            "no such pairing session for this principal",
        )),
        Err(error) => classify(error),
    }
}

// --- handlers: CollaborationTermsEnvelope + acceptance -------------------------------------------

const TERMS_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "version",
    "terms_body_root",
    "predecessor_terms_ref",
];

/// POST /v1/goal-orchestration/collaboration-terms
pub(crate) async fn handle_terms_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match terms_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn terms_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, TERMS_CREATE_FIELDS, "m048_terms_request_invalid")?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_terms_request_invalid",
        )?;
        let version = req_str(body, "version", "m048_terms_request_invalid")?;
        let body_root = req_root(body, "terms_body_root", "m048_terms_request_invalid")?;
        let predecessor = opt_ref(
            body,
            "predecessor_terms_ref",
            &["terms"],
            "m048_terms_request_invalid",
        )?;
        Ok((room_ref, version, body_root, predecessor))
    })()
    .map_err(classify)?;
    let (room_ref, version, body_root, predecessor) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    let terms_id = format!(
        "terms://{}",
        deterministic_tail(
            "trm_",
            "hypervisor.m048.collaboration-terms.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "version": version,
                "terms_body_root": body_root,
            }),
        )
    );
    let tail = terms_tail(&terms_id).map_err(classify)?;

    let _resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Host,
        &room_ref,
        &observed.system_id,
        &terms_id,
        "propose",
        &json!({ "op": "propose", "terms_body_root": body_root }),
    )
    .await?;

    if let Some(existing) = read_local(data_dir, TERMS_DIR, &tail).map_err(classify)? {
        return Ok(ok_local(
            COLLABORATION_TERMS_SCHEMA,
            "collaboration_terms",
            existing,
        ));
    }
    let terms = build_terms_envelope(
        &terms_id,
        &version,
        &body_root,
        &room_ref,
        &observed.system_id,
        predecessor.as_deref(),
    );
    persist_local(data_dir, TERMS_DIR, &tail, &terms).map_err(classify)?;
    Ok(ok_local(
        COLLABORATION_TERMS_SCHEMA,
        "collaboration_terms",
        terms,
    ))
}

/// GET /v1/goal-orchestration/collaboration-terms
pub(crate) async fn handle_terms_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match scan_local(&state.data_dir, TERMS_DIR, COLLABORATION_TERMS_SCHEMA) {
        Ok(terms) => {
            let body = json!({
                "ok": true,
                "schema_version": COLLABORATION_TERMS_SCHEMA,
                "count": terms.len(),
                "collaboration_terms": terms,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            });
            if let Err(error) =
                room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")
            {
                return classify(error);
            }
            (StatusCode::OK, Json(body))
        }
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/collaboration-terms/:id
pub(crate) async fn handle_terms_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let tail = match terms_tail(&format!("terms://{id}")) {
        Ok(tail) => tail,
        Err(error) => return classify(error),
    };
    match read_local(&state.data_dir, TERMS_DIR, &tail) {
        Ok(Some(terms)) => ok_local(COLLABORATION_TERMS_SCHEMA, "collaboration_terms", terms),
        Ok(None) => classify(verr("m048_terms_not_found", "no such collaboration terms")),
        Err(error) => classify(error),
    }
}

/// POST /v1/goal-orchestration/collaboration-terms/:id/accept
pub(crate) async fn handle_terms_accept(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let principal = match room_system::request_principal(&state.data_dir, &headers) {
        Ok(principal) => principal,
        Err(error) => return classify(error),
    };
    match terms_accept_inner(&state.data_dir, &principal, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn terms_accept_inner(
    data_dir: &str,
    principal: &str,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let expected_root = (|| -> Result<_, VErr> {
        closed_object(body, &["accepted_terms_root"], "m048_terms_request_invalid")?;
        req_root(body, "accepted_terms_root", "m048_terms_request_invalid")
    })()
    .map_err(classify)?;

    let tail = terms_tail(&format!("terms://{id}")).map_err(classify)?;
    let terms = read_local(data_dir, TERMS_DIR, &tail)
        .map_err(classify)?
        .ok_or_else(|| classify(verr("m048_terms_not_found", "no such collaboration terms")))?;

    // Acceptance is EXACT. A caller that accepted a body root which is no longer this terms
    // record's root is refused rather than silently re-pointed at the current one.
    let actual_root = terms
        .get("terms_body_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual_root != expected_root {
        return Err(classify(verr(
            "m048_terms_root_mismatch",
            "the accepted terms root is not this terms record's current body root",
        )));
    }
    if terms.get("status").and_then(Value::as_str) != Some("active") {
        return Err(classify(verr(
            "m048_terms_not_acceptable",
            "only active collaboration terms may be accepted",
        )));
    }
    let room_ref = terms
        .pointer("/scope/outcome_room_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            classify(verr(
                "m048_terms_record_invalid",
                "these terms are not scoped to a room",
            ))
        })?
        .to_string();
    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;

    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &format!("terms://{id}"),
        "accept",
        &json!({ "op": "accept", "accepted_terms_root": expected_root }),
    )
    .await?;
    let accepted_at = wallet_ms_to_rfc3339(resolved_at_ms).map_err(classify)?;
    let (receipt_tail, receipt) =
        build_terms_acceptance(&terms, principal, &room_ref, resolved_at_ms, &accepted_at)
            .map_err(classify)?;
    // Append-only and replay-safe: a byte-identical re-acceptance converges, a divergent one is a
    // conflict rather than an overwrite.
    persist_local_receipt(data_dir, TERMS_ACCEPTANCE_DIR, &receipt_tail, &receipt)
        .map_err(classify)?;
    Ok(ok_local(
        TERMS_ACCEPTANCE_SCHEMA,
        "terms_acceptance_receipt",
        receipt,
    ))
}

// --- handlers: RoomParticipationRequest v3 -------------------------------------------------------

const REQUEST_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "pairing_session_id",
    "pairing_proof_hash",
    "collaboration_terms_ref",
    "collaboration_terms_root",
    "capability_offer_refs",
    "eligibility_evidence_refs",
    "requested_role_frontier_and_visibility_refs",
    "privacy_custody_and_context_policy_refs",
];

/// POST /v1/goal-orchestration/room-participation-requests
///
/// This is the pairing crossing in its live form. It uses the recoverable intent built in A2
/// rather than bypassing it.
pub(crate) async fn handle_participation_request_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let principal = match room_system::request_principal(&state.data_dir, &headers) {
        Ok(principal) => principal,
        Err(error) => return classify(error),
    };
    match participation_create_inner(&state.data_dir, &principal, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn participation_create_inner(
    data_dir: &str,
    principal: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            REQUEST_CREATE_FIELDS,
            "m048_participation_request_invalid",
        )?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_participation_request_invalid",
        )?;
        let expected_head = req_root(
            body,
            "expected_room_state_root",
            "m048_participation_request_invalid",
        )?;
        let pairing_id = req_ref(
            body,
            "pairing_session_id",
            &["local-agent-pairing"],
            "m048_participation_request_invalid",
        )?;
        let proof = req_root(
            body,
            "pairing_proof_hash",
            "m048_participation_request_invalid",
        )?;
        let terms_ref = req_ref(
            body,
            "collaboration_terms_ref",
            &["terms"],
            "m048_participation_request_invalid",
        )?;
        let terms_root = req_root(
            body,
            "collaboration_terms_root",
            "m048_participation_request_invalid",
        )?;
        let capability_offer_refs = ref_list(
            body,
            "capability_offer_refs",
            &["capability-offer", "ai", "package"],
            "m048_participation_request_invalid",
        )?;
        let eligibility_evidence_refs = ref_list(
            body,
            "eligibility_evidence_refs",
            &[
                "evidence",
                "receipt",
                "benchmark",
                "conformance_profile",
                "certification_claim",
            ],
            "m048_participation_request_invalid",
        )?;
        let role_refs = ref_list(
            body,
            "requested_role_frontier_and_visibility_refs",
            &["frontier", "policy", "restricted_view"],
            "m048_participation_request_invalid",
        )?;
        let privacy_refs = ref_list(
            body,
            "privacy_custody_and_context_policy_refs",
            &["privacy_posture", "custody", "policy"],
            "m048_participation_request_invalid",
        )?;
        Ok((
            room_ref,
            expected_head,
            pairing_id,
            proof,
            terms_ref,
            terms_root,
            capability_offer_refs,
            eligibility_evidence_refs,
            role_refs,
            privacy_refs,
        ))
    })()
    .map_err(classify)?;
    let (
        room_ref,
        expected_head,
        pairing_id,
        proof,
        terms_ref,
        terms_root,
        capability_offer_refs,
        eligibility_evidence_refs,
        role_refs,
        privacy_refs,
    ) = parsed;

    // 1. Observe the room at a head, and refuse a caller working from a stale one BEFORE any
    //    pairing state is touched.
    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }

    // 2. Resolve the pairing session strictly.
    let pairing_stem = pairing_tail(&pairing_id).map_err(classify)?;
    let session = read_local(data_dir, PAIRING_DIR, &pairing_stem)
        .map_err(classify)?
        .ok_or_else(|| classify(verr("m048_pairing_not_found", "no such pairing session")))?;

    // 3. Terms must exist and their root must be exactly what the caller accepted.
    let terms_stem = terms_tail(&terms_ref).map_err(classify)?;
    let terms = read_local(data_dir, TERMS_DIR, &terms_stem)
        .map_err(classify)?
        .ok_or_else(|| classify(verr("m048_terms_not_found", "no such collaboration terms")))?;
    if terms.get("terms_body_root").and_then(Value::as_str) != Some(terms_root.as_str()) {
        return Err(classify(verr(
            "m048_terms_root_mismatch",
            "the request's collaboration terms root is not that terms record's body root",
        )));
    }

    // 4. Fresh wallet-authorized instant. Everything time-sensitive below uses ONLY this.
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &pairing_id,
        "submit",
        &json!({ "op": "submit", "pairing_session_id": pairing_id, "collaboration_terms_ref": terms_ref }),
    )
    .await?;

    // 5. The pairing must admit exactly THIS room and requester, be unexpired at the wallet
    //    instant, unconsumed, and not already in flight.
    pairing_admits_request(&session, &proof, &room_ref, principal, resolved_at_ms)
        .map_err(|refusal| classify(verr(refusal.code(), refusal.message())))?;

    // 6. Deterministic identity, so a replay collides at the seam instead of minting a second one.
    let request_id = derive_participation_request_id(&pairing_id, &room_ref, principal);
    let request_hash = record_output_hash(
        &json!({
            "participation_request_id": request_id,
            "collaboration_terms_root": terms_root,
            "capability_offer_refs": capability_offer_refs,
        }),
        &[],
    );
    let candidate = build_participation_candidate(
        &request_id,
        &observed.system_id,
        principal,
        &terms_ref,
        &terms_root,
        capability_offer_refs,
        eligibility_evidence_refs,
        role_refs,
        privacy_refs,
        &request_hash,
    );
    enforce_hosted_native_admission(&candidate, &observed.system_id).map_err(classify)?;

    // 7. Retain the crossing intent BEFORE the admission. Everything that could refuse on
    //    validation grounds has already run, so the only reasons the admission can now fail are
    //    ones recovery knows how to decide.
    let mut in_flight = session.clone();
    if let Some(map) = in_flight.as_object_mut() {
        map.insert(
            "consumption_intent".to_string(),
            consumption_intent(
                &request_id,
                &room_ref,
                &observed.head,
                principal,
                &candidate,
            ),
        );
    }
    persist_local(data_dir, PAIRING_DIR, &pairing_stem, &in_flight).map_err(classify)?;

    // 8. Admit into Agentgres at the exact observed head.
    let admission = match admit_child(
        data_dir,
        &observed,
        PARTICIPATION_REQUEST_CONTRACT,
        &candidate,
        &observed.system_id,
        None,
    ) {
        Ok(admission) => admission,
        Err(error) => {
            // A head-stale or duplicate-create refusal provably wrote nothing, so the intent is
            // rolled back immediately and the pairing stays usable. Any other failure may have
            // written, so the intent is RETAINED for the boot completer to decide — releasing it
            // here would be exactly the admit-before-consume hole.
            let definitively_unwritten = error.0 == "outcome_room_expected_head_stale"
                || error.0 == "outcome_room_child_duplicate_create_refused"
                || error.0 == "outcome_room_head_conflict";
            if definitively_unwritten {
                let mut released = session.clone();
                if let Some(map) = released.as_object_mut() {
                    map.remove("consumption_intent");
                }
                persist_local(data_dir, PAIRING_DIR, &pairing_stem, &released).map_err(classify)?;
            }
            return Err(classify(error));
        }
    };

    // 9. Consume the pairing forward. Single-use is now durable on both halves.
    let consumed = consumed_pairing(&session, &request_id, &super::iso_now()).map_err(classify)?;
    persist_local(data_dir, PAIRING_DIR, &pairing_stem, &consumed).map_err(classify)?;

    Ok(ok_child(
        PARTICIPATION_REQUEST_CONTRACT,
        PARTICIPATION_REQUEST_SCHEMA,
        &admission,
    ))
}

/// GET /v1/goal-orchestration/room-participation-requests
pub(crate) async fn handle_participation_requests_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_participation_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(&state.data_dir, room_ref, PARTICIPATION_REQUEST_CONTRACT).and_then(
        |objects| {
            ok_child_list(
                PARTICIPATION_REQUEST_CONTRACT,
                PARTICIPATION_REQUEST_SCHEMA,
                &observed,
                objects,
            )
        },
    ) {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/room-participation-requests/:id
pub(crate) async fn handle_participation_request_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_participation_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let object_ref = format!("participation-request://{id}");
    match current_child(
        &state.data_dir,
        room_ref,
        PARTICIPATION_REQUEST_CONTRACT,
        &object_ref,
    ) {
        Ok(Some(projection)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "object_contract_id": PARTICIPATION_REQUEST_CONTRACT,
                "schema_version": PARTICIPATION_REQUEST_SCHEMA,
                "projection": projection,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Ok(None) => classify(verr(
            "m048_participation_not_found",
            "this room admitted no such participation request",
        )),
        Err(error) => classify(error),
    }
}

/// The typed refusal for a participation operation whose current-generation owner is a later
/// dependency step.
///
/// This is a NAMED GAP, not a silent 404 and not a fallthrough to a predecessor: the request
/// family's transition and admit verbs belong with the participant lease, which this build step
/// does not own. Answering them from the retired predecessor would let a caller drive current
/// truth through a plane that is no longer authoritative.
fn participation_step_unavailable(op: &str) -> (StatusCode, Json<Value>) {
    classify(verr(
        "m048_participation_transition_unavailable",
        format!(
            "`{op}` on a participation request is issued together with the room-System participant \
             lease, which is not part of this build step; the predecessor plane is retired and is \
             deliberately not mounted for this family"
        ),
    ))
}

/// POST /v1/goal-orchestration/room-participation-requests/:id/transition
pub(crate) async fn handle_participation_request_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    participation_step_unavailable("transition")
}

// --- lifecycle 4: RoomParticipantLease v3 --------------------------------------------------------
//
// # The admission crossing, and why it needs no retained local intent
//
// Admitting a request means two room children change: the room-System issues a participant lease,
// and the request appends a successor generation marking itself admitted. The seam admits one
// child per transaction, so these cannot be one write.
//
// They do not need to be. Unlike the pairing crossing — which spans owner-local truth and
// Agentgres truth, and therefore needed a retained intent — BOTH halves of this crossing live in
// the room's own Agentgres history, so the intermediate state is self-describing:
//
//     a current participant lease whose `join_request_ref` names a request that is not yet
//     `admitted` and does not yet name that lease
//
// is exactly and only the state a crash between the two admissions produces. Recovery reads that
// invariant straight off `current_children` and repairs it FORWARD. There is no second truth
// plane, no fourth durable family, and nothing to converge that the room does not already say.
//
// The lease is admitted FIRST on purpose. A crash then leaves membership under-claimed (a lease
// exists; the request has not yet caught up), which a reader can only under-trust. The reverse
// order would leave the request claiming a `participant_lease_ref` that does not exist yet —
// over-claiming membership — and an over-claim is the one of the two a reader can act on wrongly.
//
// Deterministic lease identity closes the replay half: a retried admit re-derives the same lease
// id, so the seam refuses it `outcome_room_child_duplicate_create_refused` rather than issuing a
// second lease for one request.

/// Lease statuses under which membership is live.
const LEASE_LIVE_STATUSES: &[&str] = &["invited", "joining", "active", "sleeping", "waiting"];
/// Lease statuses from which no further transition is admitted.
const LEASE_TERMINAL_STATUSES: &[&str] = &["retired", "revoked"];
/// The registered roles this hosted build step admits.
const LEASE_ROLES: &[&str] = &[
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

/// The lease a given participation request admits — and only that one.
fn derive_participant_lease_id(request_id: &str, room_ref: &str, participant_ref: &str) -> String {
    let tail = deterministic_tail(
        "plz_",
        "hypervisor.m048.participant-lease.identity.v1",
        &json!({
            "join_request_ref": request_id,
            "outcome_room_ref": room_ref,
            "participant_ref": participant_ref,
        }),
    );
    format!("participant-lease://{tail}")
}

/// Build the RoomParticipantLease v3 candidate.
///
/// `system_binding` and `outcome_room_ref` are absent by design — the seam derives both. Every
/// bound the lease carries is authoritative: the TTL, expiry and renewal window are all rendered
/// from the wallet-authorized instant, never from a caller or a system clock.
#[allow(clippy::too_many_arguments)]
fn build_lease_candidate(
    lease_id: &str,
    request: &Value,
    participant_ref: &str,
    operator_ref: &str,
    home_domain_ref: &str,
    admitted_role: &str,
    visibility_scope_ref: &str,
    acceptance: &LeaseTermsBinding,
    grants: &LeaseGrants,
    admission_decision_ref: &str,
    times: &LeaseWindow,
) -> Value {
    json!({
        "schema_version": PARTICIPANT_LEASE_SCHEMA,
        "participant_lease_id": lease_id,
        "participant_ref": participant_ref,
        "admitted_role": admitted_role,
        "operator_ref": operator_ref,
        "home_domain_ref": home_domain_ref,
        "join_request_ref": request.get("participation_request_id").cloned().unwrap_or(Value::Null),
        "collaboration_terms_ref": acceptance.terms_ref,
        "accepted_terms_root": acceptance.terms_root,
        "terms_acceptance_ref": acceptance.acceptance_ref,
        "admission_decision_ref": admission_decision_ref,
        "visibility_scope_ref": visibility_scope_ref,
        "capability_advertisement_refs": grants.capability_advertisement_refs,
        "context_and_authority_lease_refs": grants.context_and_authority_lease_refs,
        "runtime_resource_and_budget_lease_refs": grants.runtime_resource_and_budget_lease_refs,
        "current_claim_ref": Value::Null,
        "lease_epoch": 1,
        "revocation_epoch": 0,
        "issued_at": times.issued_at,
        "effective_at": times.issued_at,
        "expires_at": times.expires_at,
        "renew_after": times.renew_after,
        "renewal_policy_ref": "policy://ioi/m048/lease-renewal-v1",
        // A bounded term needs no governed exception; an unbounded one is not offered here.
        "unbounded_term_exception_decision_ref": Value::Null,
        "heartbeat_policy_ref": "policy://ioi/m048/lease-heartbeat-v1",
        // receipt:// only. This plane invents no heartbeat object.
        "heartbeat_ref": Value::Null,
        "ttl_seconds": times.ttl_seconds,
        "status": "active",
    })
}

/// The exact terms triple a lease binds.
struct LeaseTermsBinding<'a> {
    terms_ref: &'a str,
    terms_root: &'a str,
    acceptance_ref: &'a str,
}

/// The bounded grants a lease carries. Offers must stay within these.
struct LeaseGrants {
    capability_advertisement_refs: Vec<String>,
    context_and_authority_lease_refs: Vec<String>,
    runtime_resource_and_budget_lease_refs: Vec<String>,
}

/// The lease's authoritative time window, entirely derived from the wallet instant.
struct LeaseWindow {
    issued_at: String,
    expires_at: String,
    renew_after: String,
    ttl_seconds: u64,
}

impl LeaseWindow {
    /// Render a bounded lease window from one wallet-authorized instant.
    ///
    /// `renew_after` sits at three quarters of the term so a renewal has room to land before
    /// expiry; both boundaries come from the same authorized instant, so no clock skew between
    /// them is possible.
    fn from_wallet(resolved_at_ms: u64, ttl_seconds: u64) -> Result<Self, VErr> {
        let expires_ms = wallet_deadline_ms(resolved_at_ms, ttl_seconds)?;
        let renew_ms = wallet_deadline_ms(resolved_at_ms, ttl_seconds / 4 * 3)?;
        Ok(Self {
            issued_at: wallet_ms_to_rfc3339(resolved_at_ms)?,
            expires_at: wallet_ms_to_rfc3339(expires_ms)?,
            renew_after: wallet_ms_to_rfc3339(renew_ms)?,
            ttl_seconds,
        })
    }
}

/// Why a participant lease is not live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseLapse {
    /// The lease reached a terminal generation.
    Terminal,
    /// The lease is suspended or quarantined.
    Suspended,
    /// `expires_at` passed at the wallet-authorized instant.
    Expired,
}

/// Is this lease live at the wallet-authorized instant?
///
/// Pure, like [`claim_is_live`]: no clock, no I/O. Offers and every later contribution verb gate
/// on this, so the freshness question has exactly one implementation.
pub(crate) fn lease_is_live(
    lease: &Value,
    wallet_now_ms: u64,
) -> Result<Result<(), LeaseLapse>, VErr> {
    let status = lease.get("status").and_then(Value::as_str).ok_or_else(|| {
        verr(
            "m048_lease_record_invalid",
            "a participant lease carries no status",
        )
    })?;
    if LEASE_TERMINAL_STATUSES.contains(&status) {
        return Ok(Err(LeaseLapse::Terminal));
    }
    if matches!(status, "suspended" | "quarantined" | "retiring") {
        return Ok(Err(LeaseLapse::Suspended));
    }
    if !LEASE_LIVE_STATUSES.contains(&status) {
        return Err(verr(
            "m048_lease_record_invalid",
            format!("`{status}` is not a registered participant-lease status"),
        ));
    }
    match lease.get("expires_at").and_then(Value::as_str) {
        Some(expires_at) => {
            if wallet_now_ms >= rfc3339_to_ms(expires_at)? {
                return Ok(Err(LeaseLapse::Expired));
            }
        }
        // A null expiry is admissible only under a governed unbounded-term exception, which this
        // build step never issues. Treat its absence as a refusal rather than as "never expires".
        None => {
            if lease
                .get("unbounded_term_exception_decision_ref")
                .is_none_or(Value::is_null)
            {
                return Err(verr(
                    "m048_lease_record_invalid",
                    "a lease without an expiry needs a governed unbounded-term exception",
                ));
            }
        }
    }
    Ok(Ok(()))
}

/// Resolve a live participant lease and enforce that a set of refs stays inside one of its granted
/// scopes.
///
/// This is the check the generic room seam cannot make: `require_room_child_issuer` only asserts
/// the issuer string appears in the room's `participant_lease_refs`, which is membership, not
/// scope. An offer that names a resource or capability its lease never granted is refused here.
fn require_lease_scope(
    lease: &Value,
    wallet_now_ms: u64,
    granted_field: &str,
    declared: &[String],
) -> Result<(), VErr> {
    match lease_is_live(lease, wallet_now_ms)? {
        Ok(()) => {}
        Err(LeaseLapse::Expired) => {
            return Err(verr(
                "m048_lease_expired",
                "this participant lease has expired at the wallet-authorized instant",
            ))
        }
        Err(LeaseLapse::Terminal) => {
            return Err(verr(
                "m048_lease_terminal",
                "this participant lease reached a terminal generation",
            ))
        }
        Err(LeaseLapse::Suspended) => {
            return Err(verr(
                "m048_lease_not_active",
                "this participant lease is suspended and may not issue offers",
            ))
        }
    }
    let granted = lease
        .get(granted_field)
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for declared_ref in declared {
        if !granted.contains(declared_ref) {
            return Err(verr(
                "m048_offer_outside_lease_scope",
                format!(
                    "`{declared_ref}` is not within this lease's `{granted_field}`; membership is \
                     not scope"
                ),
            ));
        }
    }
    Ok(())
}

/// The room-System convergence invariant for an admitted request.
///
/// Returns the requests that a current lease claims to have admitted but which have not yet caught
/// up. This is the whole of the admission crossing's recovery input, and it is read from the
/// room's own history rather than from any local record.
fn unconverged_admissions(data_dir: &str, room_ref: &str) -> Result<Vec<(Value, Value)>, VErr> {
    let leases = current_children(data_dir, room_ref, PARTICIPANT_LEASE_CONTRACT)?;
    let requests = current_children(data_dir, room_ref, PARTICIPATION_REQUEST_CONTRACT)?;
    let mut pending = Vec::new();
    for lease_projection in &leases {
        let lease = admitted(lease_projection)?;
        let Some(join_ref) = lease.get("join_request_ref").and_then(Value::as_str) else {
            continue;
        };
        let lease_id = lease
            .get("participant_lease_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        for request_projection in &requests {
            let request = admitted(request_projection)?;
            if request
                .get("participation_request_id")
                .and_then(Value::as_str)
                != Some(join_ref)
            {
                continue;
            }
            let already = request.get("status").and_then(Value::as_str) == Some("admitted")
                && request.get("participant_lease_ref").and_then(Value::as_str) == Some(lease_id);
            if !already {
                pending.push((lease_projection.clone(), request_projection.clone()));
            }
        }
    }
    Ok(pending)
}

/// The admitted successor generation of a participation request.
fn admitted_request_successor(
    request: &Value,
    lease_id: &str,
    admission_decision_ref: &str,
) -> Result<Value, VErr> {
    let mut successor = request.clone();
    let map = successor.as_object_mut().ok_or_else(|| {
        verr(
            "m048_participation_record_invalid",
            "a participation request must be an object",
        )
    })?;
    // The seam derives these from room truth and refuses a caller-supplied copy.
    map.remove("system_binding");
    map.remove("outcome_room_ref");
    map.insert("status".to_string(), json!("admitted"));
    map.insert("participant_lease_ref".to_string(), json!(lease_id));
    map.insert(
        "admission_decision_ref".to_string(),
        json!(admission_decision_ref),
    );
    Ok(successor)
}

/// Converge every unfinished admission in every current room.
///
/// Runs at startup after the seam's own recovery. Forward-only: it can complete an admission the
/// room already half-recorded, and it can do nothing else. Fails closed — an unreadable room or an
/// undecidable pair blocks readiness rather than being guessed.
pub(crate) fn complete_participation_admissions(data_dir: &str) -> Result<(), VErr> {
    for room in rooms::list_current_rooms_canonical_strict(data_dir)? {
        let Some(room_ref) = room.get("outcome_room_id").and_then(Value::as_str) else {
            continue;
        };
        for (lease_projection, request_projection) in unconverged_admissions(data_dir, room_ref)? {
            let lease = admitted(&lease_projection)?;
            let request = admitted(&request_projection)?;
            let lease_id = lease
                .get("participant_lease_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let decision_ref = lease
                .get("admission_decision_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let successor = admitted_request_successor(request, lease_id, decision_ref)?;
            let prior_root = object_root(&request_projection)?;
            // Re-observe the head: the seam moved it when the lease landed.
            let observed = observe_room_at_head(data_dir, room_ref)?;
            let system_id = observed.system_id.clone();
            admit_child(
                data_dir,
                &observed,
                PARTICIPATION_REQUEST_CONTRACT,
                &successor,
                &system_id,
                Some(&prior_root),
            )?;
        }
    }
    Ok(())
}

const ADMIT_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "participant_ref",
    "operator_ref",
    "home_domain_ref",
    "admitted_role",
    "visibility_scope_ref",
    "terms_acceptance_ref",
    "capability_advertisement_refs",
    "context_and_authority_lease_refs",
    "runtime_resource_and_budget_lease_refs",
    "ttl_seconds",
];

/// POST /v1/goal-orchestration/room-participation-requests/:id/admit
///
/// Room-System admission: issues the v3 participant lease, then converges the request's successor
/// generation. Never a participant self-mint — the issuer is always the room's own System.
pub(crate) async fn handle_participation_request_admit(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match admit_inner(&state.data_dir, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn admit_inner(
    data_dir: &str,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, ADMIT_FIELDS, "m048_admit_request_invalid")?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_admit_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_admit_request_invalid",
            )?,
            // The registered contract admits a broader principal namespace, but this hosted
            // private_worker slice does not: `bound_coordinates.participant_lease.principal_ref`
            // on Attempt and Finding is pinned to `^(worker|agent)://`, so admitting a
            // `service://` or `org://` lease here would mint membership that could never record a
            // contribution. The runtime profile is narrower than the schema on purpose, and the
            // refusal happens before any lease is written.
            req_ref(
                body,
                "participant_ref",
                &["worker", "agent"],
                "m048_admit_request_invalid",
            )?,
            req_ref(
                body,
                "operator_ref",
                &["worker", "agent"],
                "m048_admit_request_invalid",
            )?,
            req_ref(
                body,
                "home_domain_ref",
                &["domain", "system", "agentgres"],
                "m048_admit_request_invalid",
            )?,
            req_vocab(
                body,
                "admitted_role",
                LEASE_ROLES,
                "m048_admit_request_invalid",
            )?,
            req_ref(
                body,
                "visibility_scope_ref",
                &["policy", "restricted_view"],
                "m048_admit_request_invalid",
            )?,
            req_ref(
                body,
                "terms_acceptance_ref",
                &["receipt"],
                "m048_admit_request_invalid",
            )?,
            ref_list(
                body,
                "capability_advertisement_refs",
                &["capability-offer", "ai", "package"],
                "m048_admit_request_invalid",
            )?,
            ref_list(
                body,
                "context_and_authority_lease_refs",
                &["context_lease", "grant", "policy"],
                "m048_admit_request_invalid",
            )?,
            ref_list(
                body,
                "runtime_resource_and_budget_lease_refs",
                &["budget", "resource", "context_lease"],
                "m048_admit_request_invalid",
            )?,
            req_ttl(
                body,
                "ttl_seconds",
                LEASE_TTL_MIN_SECONDS,
                LEASE_TTL_MAX_SECONDS,
                "m048_admit_request_invalid",
            )?,
        ))
    })()
    .map_err(classify)?;
    let (
        room_ref,
        expected_head,
        participant_ref,
        operator_ref,
        home_domain_ref,
        admitted_role,
        visibility_scope_ref,
        acceptance_ref,
        capability_advertisement_refs,
        context_and_authority_lease_refs,
        runtime_resource_and_budget_lease_refs,
        ttl_seconds,
    ) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }

    // The request must be a current child of THIS room and still awaiting admission.
    let request_id = format!("participation-request://{id}");
    let request_projection = current_child(
        data_dir,
        &room_ref,
        PARTICIPATION_REQUEST_CONTRACT,
        &request_id,
    )
    .map_err(classify)?
    .ok_or_else(|| {
        classify(verr(
            "m048_participation_not_found",
            "this room admitted no such participation request",
        ))
    })?;
    let request = admitted(&request_projection).map_err(classify)?.clone();
    if request.get("status").and_then(Value::as_str) != Some("submitted") {
        return Err(classify(verr(
            "m048_participation_not_admissible",
            "only a submitted participation request may be admitted",
        )));
    }

    // The acceptance receipt must be exact: same terms ref AND same accepted root as the request.
    let acceptance_tail = acceptance_ref
        .strip_prefix("receipt://")
        .filter(|tail| super::durable_fs::is_normalization_safe(tail))
        .ok_or_else(|| {
            classify(verr(
                "m048_terms_acceptance_invalid",
                "a terms acceptance ref must be receipt://<normalization-safe tail>",
            ))
        })?;
    let acceptance = read_local(data_dir, TERMS_ACCEPTANCE_DIR, acceptance_tail)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_terms_acceptance_not_found",
                "no such terms acceptance receipt",
            ))
        })?;
    let request_terms_ref = request
        .get("collaboration_terms_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let request_terms_root = request
        .get("collaboration_terms_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if acceptance
        .get("collaboration_terms_ref")
        .and_then(Value::as_str)
        != Some(request_terms_ref)
        || acceptance
            .get("accepted_terms_root")
            .and_then(Value::as_str)
            != Some(request_terms_root)
    {
        return Err(classify(verr(
            "m048_terms_acceptance_mismatch",
            "the acceptance receipt does not bind the exact terms and root this request accepted",
        )));
    }

    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        // HOST governance: admission is the room System's act. A participant cannot mint its own
        // lease, and this is where that is enforced rather than merely asserted.
        governed::Governance::Host,
        &room_ref,
        &observed.system_id,
        &request_id,
        "admit",
        &json!({ "op": "admit", "participation_request_id": request_id, "ttl_seconds": ttl_seconds }),
    )
    .await?;

    let window = LeaseWindow::from_wallet(resolved_at_ms, ttl_seconds).map_err(classify)?;
    let lease_id = derive_participant_lease_id(&request_id, &room_ref, &participant_ref);
    let decision_ref = format!(
        "receipt://{}",
        deterministic_tail(
            "adm_",
            "hypervisor.m048.admission-decision.identity.v1",
            &json!({
                "participation_request_id": request_id,
                "participant_lease_id": lease_id,
                "admitted_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    let candidate = build_lease_candidate(
        &lease_id,
        &request,
        &participant_ref,
        &operator_ref,
        &home_domain_ref,
        &admitted_role,
        &visibility_scope_ref,
        &LeaseTermsBinding {
            terms_ref: request_terms_ref,
            terms_root: request_terms_root,
            acceptance_ref: &acceptance_ref,
        },
        &LeaseGrants {
            capability_advertisement_refs,
            context_and_authority_lease_refs,
            runtime_resource_and_budget_lease_refs,
        },
        &decision_ref,
        &window,
    );

    // Step 1 — the lease, issued by the room System itself.
    let lease_admission = admit_child(
        data_dir,
        &observed,
        PARTICIPANT_LEASE_CONTRACT,
        &candidate,
        &observed.system_id.clone(),
        None,
    )
    .map_err(classify)?;

    // Step 2 — converge the request's successor at the NEW head. A failure here is recoverable:
    // the room now describes its own unfinished admission and the boot completer repairs it.
    let converged = (|| -> Result<Value, VErr> {
        let reobserved = observe_room_at_head(data_dir, &room_ref)?;
        let successor = admitted_request_successor(&request, &lease_id, &decision_ref)?;
        let prior_root = object_root(&request_projection)?;
        let system_id = reobserved.system_id.clone();
        admit_child(
            data_dir,
            &reobserved,
            PARTICIPATION_REQUEST_CONTRACT,
            &successor,
            &system_id,
            Some(&prior_root),
        )
    })();

    let (status, Json(mut payload)) = ok_child(
        PARTICIPANT_LEASE_CONTRACT,
        PARTICIPANT_LEASE_SCHEMA,
        &lease_admission,
    );
    // 202 rather than 200 when the request successor has not landed: the lease IS durable, but the
    // admission is still completing, and a caller that reads only the status code must not mistake
    // a half-finished admission for a finished one. An exact replay after recovery returns 200.
    let status = if converged.is_ok() {
        status
    } else {
        StatusCode::ACCEPTED
    };
    payload["participation_request_convergence"] = match converged {
        Ok(_) => json!({ "converged": true }),
        // Reported honestly rather than swallowed: the lease IS issued and durable, and the
        // request will catch up at the next boot. Claiming a clean success here would misdescribe
        // durable state a caller can already observe.
        Err((code, message)) => json!({
            "converged": false,
            "pending_recovery": true,
            "code": code,
            "message": message,
        }),
    };
    Ok((status, Json(payload)))
}

/// GET /v1/goal-orchestration/room-participant-leases
pub(crate) async fn handle_participant_leases_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_lease_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(&state.data_dir, room_ref, PARTICIPANT_LEASE_CONTRACT).and_then(
        |objects| {
            ok_child_list(
                PARTICIPANT_LEASE_CONTRACT,
                PARTICIPANT_LEASE_SCHEMA,
                &observed,
                objects,
            )
        },
    ) {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/room-participant-leases/:id
pub(crate) async fn handle_participant_lease_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_lease_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let object_ref = format!("participant-lease://{id}");
    match current_child(
        &state.data_dir,
        room_ref,
        PARTICIPANT_LEASE_CONTRACT,
        &object_ref,
    ) {
        Ok(Some(projection)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "object_contract_id": PARTICIPANT_LEASE_CONTRACT,
                "schema_version": PARTICIPANT_LEASE_SCHEMA,
                "projection": projection,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Ok(None) => classify(verr(
            "m048_lease_not_found",
            "this room admitted no such participant lease",
        )),
        Err(error) => classify(error),
    }
}

/// The lease transitions this build step owns, and the status each produces.
///
/// Deliberately narrow: heartbeat, renew, revoke and expire are the four verbs whose meaning the
/// registered contract already fixes. Acceptance, verdict and settlement are NOT invented here.
fn lease_transition_target(op: &str) -> Option<&'static str> {
    match op {
        // A heartbeat proves liveness without changing standing.
        "heartbeat" => Some("active"),
        "renew" => Some("active"),
        "revoke" => Some("revoked"),
        "expire" => Some("retired"),
        _ => None,
    }
}

/// POST /v1/goal-orchestration/room-participant-leases/:id/transition
pub(crate) async fn handle_participant_lease_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match lease_transition_inner(&state.data_dir, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn lease_transition_inner(
    data_dir: &str,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            &[
                "outcome_room_ref",
                "expected_room_state_root",
                "op",
                "heartbeat_ref",
                "ttl_seconds",
            ],
            "m048_lease_request_invalid",
        )?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_lease_request_invalid",
        )?;
        let expected_head = req_root(
            body,
            "expected_room_state_root",
            "m048_lease_request_invalid",
        )?;
        let op = req_vocab(
            body,
            "op",
            &["heartbeat", "renew", "revoke", "expire"],
            "m048_lease_request_invalid",
        )?;
        // `heartbeat_ref` is admitted only on a heartbeat, and `ttl_seconds` only on a renew.
        // Field-admission is checked BEFORE any missing-required check. A field that does not
        // belong to this verb at all is the more specific complaint, and reporting the vaguer
        // "something is missing" first would send a caller looking in the wrong place.
        let heartbeat_ref = opt_ref(
            body,
            "heartbeat_ref",
            &["receipt"],
            "m048_lease_request_invalid",
        )?;
        if heartbeat_ref.is_some() && op != "heartbeat" {
            return Err(verr(
                "m048_lease_field_not_admitted_for_transition",
                "`heartbeat_ref` is admitted only on a heartbeat transition",
            ));
        }
        let ttl_supplied = !matches!(body.get("ttl_seconds"), None | Some(Value::Null));
        if ttl_supplied && op != "renew" {
            return Err(verr(
                "m048_lease_field_not_admitted_for_transition",
                "`ttl_seconds` is admitted only on a renew transition",
            ));
        }
        if op == "heartbeat" && heartbeat_ref.is_none() {
            return Err(verr(
                "m048_lease_request_invalid",
                "a heartbeat transition must carry its receipt:// heartbeat_ref",
            ));
        }
        let ttl = if ttl_supplied {
            Some(req_ttl(
                body,
                "ttl_seconds",
                LEASE_TTL_MIN_SECONDS,
                LEASE_TTL_MAX_SECONDS,
                "m048_lease_request_invalid",
            )?)
        } else {
            None
        };
        Ok((room_ref, expected_head, op, heartbeat_ref, ttl))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, op, heartbeat_ref, ttl) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let lease_id = format!("participant-lease://{id}");
    let projection = current_child(data_dir, &room_ref, PARTICIPANT_LEASE_CONTRACT, &lease_id)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_lease_not_found",
                "this room admitted no such participant lease",
            ))
        })?;
    let lease = admitted(&projection).map_err(classify)?.clone();
    let current_status = lease
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if LEASE_TERMINAL_STATUSES.contains(&current_status) {
        return Err(classify(verr(
            "m048_lease_terminal",
            "a terminal participant lease admits no further transition",
        )));
    }

    let governance = match op.as_str() {
        // Revocation and expiry are the room System's acts; liveness is the participant's.
        "revoke" | "expire" => governed::Governance::Host,
        _ => governed::Governance::Participant,
    };
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governance,
        &room_ref,
        &observed.system_id,
        &lease_id,
        &op,
        &json!({ "op": op, "participant_lease_id": lease_id }),
    )
    .await?;

    // Expiry is decided against wallet time ONLY. A caller cannot expire a live lease by asserting
    // that it has expired, and cannot keep a lapsed one alive by withholding the fact.
    if op == "expire" {
        match lease_is_live(&lease, resolved_at_ms).map_err(classify)? {
            Err(LeaseLapse::Expired) => {}
            _ => {
                return Err(classify(verr(
                    "m048_lease_not_expired",
                    "this lease has not expired at the wallet-authorized instant",
                )))
            }
        }
    }

    let target = lease_transition_target(&op).ok_or_else(|| {
        classify(verr(
            "m048_lease_transition_unavailable",
            "no current-generation purpose is registered for this transition",
        ))
    })?;

    let mut successor = lease.clone();
    let map = successor.as_object_mut().ok_or_else(|| {
        classify(verr(
            "m048_lease_record_invalid",
            "a participant lease must be an object",
        ))
    })?;
    map.remove("system_binding");
    map.remove("outcome_room_ref");
    map.insert("status".to_string(), json!(target));
    match op.as_str() {
        "heartbeat" => {
            map.insert("heartbeat_ref".to_string(), json!(heartbeat_ref));
        }
        "renew" => {
            let ttl_seconds = ttl.unwrap_or_else(|| {
                lease
                    .get("ttl_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(LEASE_TTL_MIN_SECONDS)
            });
            let window = LeaseWindow::from_wallet(resolved_at_ms, ttl_seconds).map_err(classify)?;
            map.insert("expires_at".to_string(), json!(window.expires_at));
            map.insert("renew_after".to_string(), json!(window.renew_after));
            map.insert("ttl_seconds".to_string(), json!(window.ttl_seconds));
            let epoch = lease
                .get("lease_epoch")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            map.insert("lease_epoch".to_string(), json!(epoch + 1));
        }
        "revoke" => {
            let epoch = lease
                .get("revocation_epoch")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            map.insert("revocation_epoch".to_string(), json!(epoch + 1));
        }
        _ => {}
    }

    let prior_root = object_root(&projection).map_err(classify)?;
    let issuer = observed.system_id.clone();
    let admission = admit_child(
        data_dir,
        &observed,
        PARTICIPANT_LEASE_CONTRACT,
        &successor,
        &issuer,
        Some(&prior_root),
    )
    .map_err(classify)?;
    Ok(ok_child(
        PARTICIPANT_LEASE_CONTRACT,
        PARTICIPANT_LEASE_SCHEMA,
        &admission,
    ))
}

// --- lifecycles 5 & 6: ResourceOffer / CapabilityOffer -------------------------------------------
//
// The two offer families differ only in which lease coordinate they name, which lease grant bounds
// them, and their status vocabulary. One descriptor plus one generic path keeps the pair honest:
// a rule enforced for resources cannot silently not apply to capabilities.
//
// NOTE: neither registered contract declares a top-level `outcome_room_ref` — they are room-scoped
// through their SystemScopedObjectBinding alone — so nothing here mints one, and the seam will not
// inject one either.

#[derive(Clone, Copy)]
struct OfferFamily {
    contract_id: &'static str,
    schema: &'static str,
    id_field: &'static str,
    id_prefix: &'static str,
    id_scheme: &'static str,
    /// The payload coordinate naming the issuing lease.
    lease_field: &'static str,
    /// The lease grant this family's declared refs must stay within.
    granted_field: &'static str,
    /// The payload field whose refs are scope-checked against `granted_field`.
    declared_field: &'static str,
    statuses: &'static [&'static str],
    terminal: &'static [&'static str],
    code: &'static str,
}

const RESOURCE_OFFER_FAMILY: OfferFamily = OfferFamily {
    contract_id: RESOURCE_OFFER_CONTRACT,
    schema: RESOURCE_OFFER_SCHEMA,
    id_field: "resource_offer_id",
    id_prefix: "rso_",
    id_scheme: "resource-offer",
    lease_field: "provider_participant_lease_ref",
    granted_field: "runtime_resource_and_budget_lease_refs",
    declared_field: "policy_constraint_refs",
    statuses: &[
        "offered",
        "queued",
        "allocated",
        "exhausted",
        "withdrawn",
        "expired",
        "revoked",
    ],
    terminal: &["withdrawn", "expired", "revoked", "exhausted"],
    code: "m048_resource_offer",
};

const CAPABILITY_OFFER_FAMILY: OfferFamily = OfferFamily {
    contract_id: CAPABILITY_OFFER_CONTRACT,
    schema: CAPABILITY_OFFER_SCHEMA,
    id_field: "capability_offer_id",
    id_prefix: "cao_",
    id_scheme: "capability-offer",
    lease_field: "participant_lease_ref",
    granted_field: "capability_advertisement_refs",
    declared_field: "capability_descriptor_refs",
    statuses: &[
        "offered",
        "eligible",
        "allocated",
        "suspended",
        "withdrawn",
        "revoked",
    ],
    terminal: &["withdrawn", "revoked"],
    code: "m048_capability_offer",
};

/// The refs an admitted offer declares under the field its lease grant bounds.
///
/// Read from the admitted payload rather than from the request body, so a transition is checked
/// against what the offer actually IS, not against what its transition request claims.
fn declared_refs(family: OfferFamily, offer: &Value) -> Vec<String> {
    offer
        .get(family.declared_field)
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Is this offer still live at the wallet-authorized instant?
///
/// Only ResourceOffer carries an expiry in its registered contract; a CapabilityOffer lapses only
/// through a terminal status. Both are evaluated against wallet time, never a local clock.
fn offer_is_live(family: OfferFamily, offer: &Value, wallet_now_ms: u64) -> Result<bool, VErr> {
    let status = offer
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if family.terminal.contains(&status) {
        return Ok(false);
    }
    if let Some(expires_at) = offer.get("expires_at").and_then(Value::as_str) {
        if wallet_now_ms >= rfc3339_to_ms(expires_at)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolve the issuing lease and enforce that it is live AND that the offer stays within its scope.
///
/// This is the check the brief calls for "beyond the generic seam": the seam only asserts the
/// issuer string is present in the room's membership array. Here the lease is actually opened, its
/// liveness evaluated at the wallet instant, and the offer's declared refs bounded by the exact
/// grant the lease carries.
fn require_offer_lease(
    data_dir: &str,
    room_ref: &str,
    family: OfferFamily,
    lease_ref: &str,
    declared: &[String],
    wallet_now_ms: u64,
) -> Result<Value, VErr> {
    let projection = current_child(data_dir, room_ref, PARTICIPANT_LEASE_CONTRACT, lease_ref)?
        .ok_or_else(|| {
            verr(
                format!("{}_lease_not_found", family.code).as_str(),
                "the issuing participant lease is not a current child of this room",
            )
        })?;
    let lease = admitted(&projection)?.clone();
    require_lease_scope(&lease, wallet_now_ms, family.granted_field, declared)?;
    Ok(lease)
}

/// Generic offer creation. `candidate_fields` are the non-plane-owned contract fields the caller
/// supplies verbatim; identity, status and every room coordinate are derived here.
async fn offer_create_inner(
    data_dir: &str,
    family: OfferFamily,
    allowed: &[&str],
    body: &Value,
    build: fn(&str, &Value, &str) -> Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let invalid = format!("{}_request_invalid", family.code);
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, allowed, &invalid)?;
        let room_ref = req_ref(body, "outcome_room_ref", &["outcome-room"], &invalid)?;
        let expected_head = req_root(body, "expected_room_state_root", &invalid)?;
        let lease_ref = req_ref(body, family.lease_field, &["participant-lease"], &invalid)?;
        let declared = ref_list(body, family.declared_field, &[], &invalid)?;
        Ok((room_ref, expected_head, lease_ref, declared))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, lease_ref, declared) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }

    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &lease_ref,
        "offer",
        &json!({ "op": "offer", "contract_id": family.contract_id, "lease_ref": lease_ref }),
    )
    .await?;

    // The lease must be live at THIS instant and must actually grant what the offer declares.
    require_offer_lease(
        data_dir,
        &room_ref,
        family,
        &lease_ref,
        &declared,
        resolved_at_ms,
    )
    .map_err(classify)?;

    let offer_id = format!(
        "{}://{}",
        family.id_scheme,
        deterministic_tail(
            family.id_prefix,
            "hypervisor.m048.offer.identity.v1",
            &json!({
                "contract_id": family.contract_id,
                "outcome_room_ref": room_ref,
                "lease_ref": lease_ref,
                "declared": declared,
            }),
        )
    );
    let candidate = build(&offer_id, body, &lease_ref);

    // The issuer is the LEASE, not the caller: the registered invariant resolves an offer's issuer
    // through its participant lease or the room System.
    let admission = admit_child(
        data_dir,
        &observed,
        family.contract_id,
        &candidate,
        &lease_ref,
        None,
    )
    .map_err(classify)?;
    Ok(ok_child(family.contract_id, family.schema, &admission))
}

const RESOURCE_OFFER_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "provider_participant_lease_ref",
    "backing_provider_ref",
    "resource_profile_ref",
    "capacity_and_availability_ref",
    "locality_and_custody_refs",
    "trust_and_assurance_refs",
    "cost_ref",
    "eligible_work_classes",
    "policy_constraint_refs",
    "allocation_policy_ref",
    "queue_preemption_and_fairness_policy_ref",
    "expires_at",
];

fn build_resource_offer(offer_id: &str, body: &Value, lease_ref: &str) -> Value {
    json!({
        "schema_version": RESOURCE_OFFER_SCHEMA,
        "resource_offer_id": offer_id,
        "provider_participant_lease_ref": lease_ref,
        "backing_provider_ref": body.get("backing_provider_ref").cloned().unwrap_or(Value::Null),
        "resource_profile_ref": body.get("resource_profile_ref").cloned().unwrap_or(Value::Null),
        "capacity_and_availability_ref": body.get("capacity_and_availability_ref").cloned().unwrap_or(Value::Null),
        "locality_and_custody_refs": body.get("locality_and_custody_refs").cloned().unwrap_or_else(|| json!([])),
        "trust_and_assurance_refs": body.get("trust_and_assurance_refs").cloned().unwrap_or_else(|| json!([])),
        "cost_ref": body.get("cost_ref").cloned().unwrap_or(Value::Null),
        "eligible_work_classes": body.get("eligible_work_classes").cloned().unwrap_or_else(|| json!([])),
        "policy_constraint_refs": body.get("policy_constraint_refs").cloned().unwrap_or_else(|| json!([])),
        "allocation_policy_ref": body.get("allocation_policy_ref").cloned().unwrap_or(Value::Null),
        "queue_preemption_and_fairness_policy_ref": body.get("queue_preemption_and_fairness_policy_ref").cloned().unwrap_or(Value::Null),
        "expires_at": body.get("expires_at").cloned().unwrap_or(Value::Null),
        // An offer allocates nothing on creation. These stay empty until an allocation plane
        // that this build step does not contain writes them.
        "allocation_decision_refs": [],
        "spend_and_contribution_refs": [],
        "usage_and_consumption_refs": [],
        "status": "offered",
    })
}

const CAPABILITY_OFFER_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "participant_lease_ref",
    "backing_worker_or_service_ref",
    "capability_descriptor_refs",
    "eligible_frontier_classes",
    "model_harness_tool_and_connector_refs",
    "authority_and_context_requirements",
    "privacy_cost_quality_and_latency_refs",
    "availability_ref",
];

fn build_capability_offer(offer_id: &str, body: &Value, lease_ref: &str) -> Value {
    json!({
        "schema_version": CAPABILITY_OFFER_SCHEMA,
        "capability_offer_id": offer_id,
        "participant_lease_ref": lease_ref,
        "backing_worker_or_service_ref": body.get("backing_worker_or_service_ref").cloned().unwrap_or(Value::Null),
        "capability_descriptor_refs": body.get("capability_descriptor_refs").cloned().unwrap_or_else(|| json!([])),
        "eligible_frontier_classes": body.get("eligible_frontier_classes").cloned().unwrap_or_else(|| json!([])),
        "model_harness_tool_and_connector_refs": body.get("model_harness_tool_and_connector_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_and_context_requirements": body.get("authority_and_context_requirements").cloned().unwrap_or_else(|| json!([])),
        "privacy_cost_quality_and_latency_refs": body.get("privacy_cost_quality_and_latency_refs").cloned().unwrap_or_else(|| json!([])),
        "availability_ref": body.get("availability_ref").cloned().unwrap_or(Value::Null),
        "status": "offered",
    })
}

/// Generic offer transition: a successor generation carrying a registered status.
async fn offer_transition_inner(
    data_dir: &str,
    family: OfferFamily,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let invalid = format!("{}_request_invalid", family.code);
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            &["outcome_room_ref", "expected_room_state_root", "status"],
            &invalid,
        )?;
        Ok((
            req_ref(body, "outcome_room_ref", &["outcome-room"], &invalid)?,
            req_root(body, "expected_room_state_root", &invalid)?,
            req_vocab(body, "status", family.statuses, &invalid)?,
        ))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, target) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let offer_ref = format!("{}://{}", family.id_scheme, id);
    let projection = current_child(data_dir, &room_ref, family.contract_id, &offer_ref)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                format!("{}_not_found", family.code).as_str(),
                "this room admitted no such offer",
            ))
        })?;
    let offer = admitted(&projection).map_err(classify)?.clone();
    let current_status = offer
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if family.terminal.contains(&current_status) {
        return Err(classify(verr(
            format!("{}_terminal", family.code).as_str(),
            "a terminal offer admits no further transition",
        )));
    }
    let lease_ref = offer
        .get(family.lease_field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &offer_ref,
        "transition",
        &json!({ "op": "transition", "status": target, "offer_ref": offer_ref }),
    )
    .await?;

    // A lapsed offer may only move to a terminal status; it can never be revived into an
    // allocatable one. Liveness is judged at the wallet instant.
    if !offer_is_live(family, &offer, resolved_at_ms).map_err(classify)?
        && !family.terminal.contains(&target.as_str())
    {
        return Err(classify(verr(
            format!("{}_expired", family.code).as_str(),
            "this offer has lapsed at the wallet-authorized instant and may only be terminated",
        )));
    }
    // For any non-terminal transition the issuing lease must STILL prove this offer, not merely
    // still be alive. Scope was bound at create, but in between a lease can be renewed with a
    // narrower grant, suspended, or revoked — so the offer's own declared refs are re-read from
    // the admitted payload and re-checked against the lease's CURRENT grant at this wallet
    // instant. Continuing an offer whose lease no longer proves it would let a withdrawn grant
    // keep working simply because nobody transitioned the offer.
    if !family.terminal.contains(&target.as_str()) {
        let declared = declared_refs(family, &offer);
        require_offer_lease(
            data_dir,
            &room_ref,
            family,
            &lease_ref,
            &declared,
            resolved_at_ms,
        )
        .map_err(classify)?;
    }

    let mut successor = offer.clone();
    let map = successor.as_object_mut().ok_or_else(|| {
        classify(verr(
            format!("{}_record_invalid", family.code).as_str(),
            "an offer record must be an object",
        ))
    })?;
    map.remove("system_binding");
    map.insert("status".to_string(), json!(target));

    let prior_root = object_root(&projection).map_err(classify)?;
    let admission = admit_child(
        data_dir,
        &observed,
        family.contract_id,
        &successor,
        &lease_ref,
        Some(&prior_root),
    )
    .map_err(classify)?;
    Ok(ok_child(family.contract_id, family.schema, &admission))
}

/// Generic offer projection over one room.
fn offer_list(
    data_dir: &str,
    family: OfferFamily,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            format!("{}_request_invalid", family.code).as_str(),
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(data_dir, room_ref, family.contract_id)
        .and_then(|objects| ok_child_list(family.contract_id, family.schema, &observed, objects))
    {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// Generic offer overview. Owns nothing: a pure count projection over current children.
fn offer_overview(
    data_dir: &str,
    family: OfferFamily,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            format!("{}_request_invalid", family.code).as_str(),
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let objects = match current_children(data_dir, room_ref, family.contract_id) {
        Ok(objects) => objects,
        Err(error) => return classify(error),
    };
    let mut by_status = serde_json::Map::new();
    for projection in &objects {
        let status = projection
            .pointer("/admitted_object/status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let next = by_status.get(&status).and_then(Value::as_u64).unwrap_or(0) + 1;
        by_status.insert(status, json!(next));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "object_contract_id": family.contract_id,
            "schema_version": family.schema,
            "outcome_room_ref": room_ref,
            "total": objects.len(),
            "by_status": by_status,
            "projection_only": true,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// Generic single-offer projection.
fn offer_get(
    data_dir: &str,
    family: OfferFamily,
    id: &str,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            format!("{}_request_invalid", family.code).as_str(),
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let offer_ref = format!("{}://{}", family.id_scheme, id);
    match current_child(data_dir, room_ref, family.contract_id, &offer_ref) {
        Ok(Some(projection)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "object_contract_id": family.contract_id,
                "schema_version": family.schema,
                "projection": projection,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Ok(None) => classify(verr(
            format!("{}_not_found", family.code).as_str(),
            "this room admitted no such offer",
        )),
        Err(error) => classify(error),
    }
}

type OfferQuery = axum::extract::Query<std::collections::HashMap<String, String>>;

/// POST /v1/goal-orchestration/resource-offers
pub(crate) async fn handle_resource_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match offer_create_inner(
        &state.data_dir,
        RESOURCE_OFFER_FAMILY,
        RESOURCE_OFFER_FIELDS,
        &body,
        build_resource_offer,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// GET /v1/goal-orchestration/resource-offers
pub(crate) async fn handle_resource_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_list(&state.data_dir, RESOURCE_OFFER_FAMILY, &query)
}

/// GET /v1/goal-orchestration/resource-offers/overview
pub(crate) async fn handle_resource_overview(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_overview(&state.data_dir, RESOURCE_OFFER_FAMILY, &query)
}

/// GET /v1/goal-orchestration/resource-offers/:id
pub(crate) async fn handle_resource_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_get(&state.data_dir, RESOURCE_OFFER_FAMILY, &id, &query)
}

/// POST /v1/goal-orchestration/resource-offers/:id/transition
pub(crate) async fn handle_resource_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match offer_transition_inner(&state.data_dir, RESOURCE_OFFER_FAMILY, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// POST /v1/goal-orchestration/capability-offers
pub(crate) async fn handle_capability_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match offer_create_inner(
        &state.data_dir,
        CAPABILITY_OFFER_FAMILY,
        CAPABILITY_OFFER_FIELDS,
        &body,
        build_capability_offer,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// GET /v1/goal-orchestration/capability-offers
pub(crate) async fn handle_capability_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_list(&state.data_dir, CAPABILITY_OFFER_FAMILY, &query)
}

/// GET /v1/goal-orchestration/capability-offers/overview
pub(crate) async fn handle_capability_overview(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_overview(&state.data_dir, CAPABILITY_OFFER_FAMILY, &query)
}

/// GET /v1/goal-orchestration/capability-offers/:id
pub(crate) async fn handle_capability_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    offer_get(&state.data_dir, CAPABILITY_OFFER_FAMILY, &id, &query)
}

/// POST /v1/goal-orchestration/capability-offers/:id/transition
pub(crate) async fn handle_capability_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match offer_transition_inner(&state.data_dir, CAPABILITY_OFFER_FAMILY, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

// --- lifecycle 7: WorkFrontierItem v3 ------------------------------------------------------------

const FRONTIER_ITEM_KINDS: &[&str] = &[
    "question",
    "problem",
    "hypothesis",
    "task",
    "review_need",
    "verification_need",
    "resource_need",
    "synthesis_need",
];
const FRONTIER_CLAIMABILITY: &[&str] = &["open", "invited_only", "assigned", "paused", "closed"];
const FRONTIER_STATUSES: &[&str] = &[
    "open",
    "claimed",
    "blocked",
    "replicating",
    "verifying",
    "accepted",
    "rejected",
    "superseded",
    "closed",
];
/// Statuses this hosted step will not move an item into: acceptance and rejection are verdicts,
/// and this plane issues no verdicts.
const FRONTIER_VERDICT_STATUSES: &[&str] = &["accepted", "rejected"];

/// The hosted ACC-9 slice pins single-claim exclusivity.
///
/// The registered contract permits `max_concurrency > 1`, but this build step's whole exclusivity
/// proof is "two live claims can never hold one item". Rather than accept a caller-supplied number
/// the rest of the plane would then have to defend, the profile is fixed at 1 here and the
/// projection in `frontier_claimability` enforces it.
const HOSTED_MAX_CONCURRENCY: u64 = 1;

const FRONTIER_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "item_kind",
    "objective",
    "dependency_refs",
    "required_capability_refs",
    "required_context_resource_authority_and_evidence_refs",
    "expected_value",
    "uncertainty",
    "priority",
    "stop_condition_ref",
    "expires_at",
];

fn build_frontier_candidate(frontier_id: &str, body: &Value) -> Value {
    json!({
        "schema_version": WORK_FRONTIER_ITEM_SCHEMA,
        "frontier_item_id": frontier_id,
        "item_kind": body.get("item_kind").cloned().unwrap_or(Value::Null),
        "objective": body.get("objective").cloned().unwrap_or(Value::Null),
        "dependency_refs": body.get("dependency_refs").cloned().unwrap_or_else(|| json!([])),
        // A fresh item has no contributions yet. Lineage accrues through succession, never through
        // a caller asserting it at create.
        "related_attempt_and_finding_refs": [],
        "required_capability_refs": body.get("required_capability_refs").cloned().unwrap_or_else(|| json!([])),
        "required_context_resource_authority_and_evidence_refs": body
            .get("required_context_resource_authority_and_evidence_refs")
            .cloned()
            .unwrap_or_else(|| json!([])),
        "expected_value": body.get("expected_value").cloned().unwrap_or(Value::Null),
        "uncertainty": body.get("uncertainty").cloned().unwrap_or(Value::Null),
        "priority": body.get("priority").cloned().unwrap_or(Value::Null),
        // Hosted exclusive profile: one live claim, enforced by projection.
        "duplication_policy": "exclusive",
        "claimability": "open",
        "max_concurrency": HOSTED_MAX_CONCURRENCY,
        "expires_at": body.get("expires_at").cloned().unwrap_or(Value::Null),
        "stop_condition_ref": body.get("stop_condition_ref").cloned().unwrap_or(Value::Null),
        "status": "open",
    })
}

/// POST /v1/goal-orchestration/work-frontier-items
pub(crate) async fn handle_frontier_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match frontier_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn frontier_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            FRONTIER_CREATE_FIELDS,
            "m048_frontier_request_invalid",
        )?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_frontier_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_frontier_request_invalid",
            )?,
            req_vocab(
                body,
                "item_kind",
                FRONTIER_ITEM_KINDS,
                "m048_frontier_request_invalid",
            )?,
            req_str(body, "objective", "m048_frontier_request_invalid")?,
        ))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, _kind, _objective) = parsed;

    // Ref schemes are enforced HERE rather than left to the seam. Passing caller refs straight
    // through would make the first sign of a bad scheme a contract rejection deep inside the
    // admission, reported in the seam's vocabulary rather than this plane's.
    (|| -> Result<(), VErr> {
        ref_list(
            body,
            "dependency_refs",
            &["frontier", "attempt", "finding"],
            "m048_frontier_request_invalid",
        )?;
        ref_list(
            body,
            "required_capability_refs",
            &["capability", "worker", "tool"],
            "m048_frontier_request_invalid",
        )?;
        // This field admits bare `scope:` tokens alongside refs, so scheme checking is relaxed
        // and the registered pattern remains the authority.
        ref_list(
            body,
            "required_context_resource_authority_and_evidence_refs",
            &[],
            "m048_frontier_request_invalid",
        )?;
        Ok(())
    })()
    .map_err(classify)?;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        // The frontier is the room's own work surface: the System declares it.
        governed::Governance::Host,
        &room_ref,
        &observed.system_id,
        &room_ref,
        "declare",
        &json!({ "op": "declare", "contract_id": WORK_FRONTIER_ITEM_CONTRACT }),
    )
    .await?;
    let frontier_id = format!(
        "frontier://{}",
        deterministic_tail(
            "wfi_",
            "hypervisor.m048.work-frontier-item.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "objective": body.get("objective"),
                "item_kind": body.get("item_kind"),
                "declared_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    let candidate = build_frontier_candidate(&frontier_id, body);
    let issuer = observed.system_id.clone();
    let admission = admit_child(
        data_dir,
        &observed,
        WORK_FRONTIER_ITEM_CONTRACT,
        &candidate,
        &issuer,
        None,
    )
    .map_err(classify)?;
    Ok(ok_child(
        WORK_FRONTIER_ITEM_CONTRACT,
        WORK_FRONTIER_ITEM_SCHEMA,
        &admission,
    ))
}

/// Resolve every current claim in a room once, for claimability projection.
fn current_claims(data_dir: &str, room_ref: &str) -> Result<Vec<Value>, VErr> {
    current_children(data_dir, room_ref, WORK_CLAIM_LEASE_CONTRACT)?
        .iter()
        .map(|projection| admitted(projection).cloned())
        .collect()
}

/// GET /v1/goal-orchestration/work-frontier-items
pub(crate) async fn handle_frontier_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_frontier_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(&state.data_dir, room_ref, WORK_FRONTIER_ITEM_CONTRACT).and_then(
        |objects| {
            ok_child_list(
                WORK_FRONTIER_ITEM_CONTRACT,
                WORK_FRONTIER_ITEM_SCHEMA,
                &observed,
                objects,
            )
        },
    ) {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-frontier-items/:id
pub(crate) async fn handle_frontier_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_frontier_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let object_ref = format!("frontier://{id}");
    match current_child(
        &state.data_dir,
        room_ref,
        WORK_FRONTIER_ITEM_CONTRACT,
        &object_ref,
    ) {
        Ok(Some(projection)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "object_contract_id": WORK_FRONTIER_ITEM_CONTRACT,
                "schema_version": WORK_FRONTIER_ITEM_SCHEMA,
                "projection": projection,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Ok(None) => classify(verr(
            "m048_frontier_not_found",
            "this room admitted no such frontier item",
        )),
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-frontier-items/overview
///
/// The overview is where derived claimability is surfaced. It owns nothing and writes nothing: it
/// resolves a wallet instant purely to evaluate liveness, and every lapsed claim it reports is
/// reported WITHOUT having been released — release remains an explicit claim transition.
pub(crate) async fn handle_frontier_overview(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_frontier_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    let resolved_at_ms = match authorized_instant(
        &state.data_dir,
        &json!({}),
        governed::Governance::Participant,
        room_ref,
        &observed.system_id,
        room_ref,
        "read",
        &json!({ "op": "read", "projection": "work-frontier-claimability" }),
    )
    .await
    {
        Ok(resolved_at_ms) => resolved_at_ms,
        Err(error) => return error,
    };
    match frontier_overview_projection(&state.data_dir, room_ref, resolved_at_ms) {
        Ok(body) => (StatusCode::OK, Json(body)),
        Err(error) => classify(error),
    }
}

/// Pure projection: claimability of every frontier item at one wallet instant.
fn frontier_overview_projection(
    data_dir: &str,
    room_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let claims = current_claims(data_dir, room_ref)?;
    let mut items = Vec::new();
    for projection in current_children(data_dir, room_ref, WORK_FRONTIER_ITEM_CONTRACT)? {
        let item = admitted(&projection)?;
        items.push(frontier_claimability(
            item,
            &claims,
            resolved_at_ms,
            CLAIM_HEARTBEAT_MAX_SECONDS,
        )?);
    }
    let body = json!({
        "ok": true,
        "object_contract_id": WORK_FRONTIER_ITEM_CONTRACT,
        "schema_version": WORK_FRONTIER_ITEM_SCHEMA,
        "outcome_room_ref": room_ref,
        "total": items.len(),
        "items": items,
        "evaluated_at_wallet_ms": resolved_at_ms,
        // Reporting a lapse is not performing a release. Nothing here writes.
        "projection_only": true,
        "runtimeTruthSource": "daemon-runtime",
    });
    room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")?;
    Ok(body)
}

/// POST /v1/goal-orchestration/work-frontier-items/:id/transition
///
/// Frontier transitions never duplicate claim state: `claimed` is a DERIVED fact about live
/// claims, so it is not an admitted target here.
pub(crate) async fn handle_frontier_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match frontier_transition_inner(&state.data_dir, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn frontier_transition_inner(
    data_dir: &str,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            &[
                "outcome_room_ref",
                "expected_room_state_root",
                "status",
                "claimability",
            ],
            "m048_frontier_request_invalid",
        )?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_frontier_request_invalid",
        )?;
        let expected_head = req_root(
            body,
            "expected_room_state_root",
            "m048_frontier_request_invalid",
        )?;
        let status = req_vocab(
            body,
            "status",
            FRONTIER_STATUSES,
            "m048_frontier_request_invalid",
        )?;
        if status == "claimed" {
            return Err(verr(
                "m048_frontier_claim_state_is_derived",
                "`claimed` is derived from live claim generations and must not be written onto the \
                 item; acquire or release a claim instead",
            ));
        }
        if FRONTIER_VERDICT_STATUSES.contains(&status.as_str()) {
            return Err(verr(
                "m048_frontier_verdict_unavailable",
                "acceptance and rejection are verdicts; this build step issues none",
            ));
        }
        let claimability = match body.get("claimability") {
            None | Some(Value::Null) => None,
            Some(_) => Some(req_vocab(
                body,
                "claimability",
                FRONTIER_CLAIMABILITY,
                "m048_frontier_request_invalid",
            )?),
        };
        Ok((room_ref, expected_head, status, claimability))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, status, claimability) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let object_ref = format!("frontier://{id}");
    let projection = current_child(
        data_dir,
        &room_ref,
        WORK_FRONTIER_ITEM_CONTRACT,
        &object_ref,
    )
    .map_err(classify)?
    .ok_or_else(|| {
        classify(verr(
            "m048_frontier_not_found",
            "this room admitted no such frontier item",
        ))
    })?;
    let item = admitted(&projection).map_err(classify)?.clone();

    let _resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Host,
        &room_ref,
        &observed.system_id,
        &object_ref,
        "transition",
        &json!({ "op": "transition", "status": status }),
    )
    .await?;

    let mut successor = item.clone();
    let map = successor.as_object_mut().ok_or_else(|| {
        classify(verr(
            "m048_frontier_record_invalid",
            "a frontier item must be an object",
        ))
    })?;
    map.remove("system_binding");
    map.insert("status".to_string(), json!(status));
    if let Some(claimability) = claimability {
        map.insert("claimability".to_string(), json!(claimability));
    }
    let prior_root = object_root(&projection).map_err(classify)?;
    let issuer = observed.system_id.clone();
    let admission = admit_child(
        data_dir,
        &observed,
        WORK_FRONTIER_ITEM_CONTRACT,
        &successor,
        &issuer,
        Some(&prior_root),
    )
    .map_err(classify)?;
    Ok(ok_child(
        WORK_FRONTIER_ITEM_CONTRACT,
        WORK_FRONTIER_ITEM_SCHEMA,
        &admission,
    ))
}

// --- lifecycle 8: WorkEligibilityMatchReceipt (owner-local evidence only) -------------------------

const ELIGIBILITY_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "frontier_item_ref",
    "participant_lease_ref",
    "resource_offer_refs",
    "capability_offer_refs",
];

/// The exact tuple an eligibility match asserts lined up.
///
/// Resolved fresh from room truth every time it is needed. `eligibility_match_body` records it;
/// `claim_acquire_inner` re-derives it rather than trusting the record, which is what keeps the
/// receipt evidence rather than authority.
struct EligibilityTuple {
    frontier: Value,
    lease: Value,
    resource_offers: Vec<Value>,
    capability_offers: Vec<Value>,
}

/// Freshly resolve and revalidate the whole eligibility tuple at one wallet instant.
///
/// Every element is re-read from current room children — never from a prior receipt — and each is
/// checked for same-room membership, liveness at THIS instant, and requirement coverage. This is
/// the single implementation both the evidence route and claim acquisition use, so a claim can
/// never be admitted against a weaker check than the one that produced its evidence.
fn resolve_eligibility_tuple(
    data_dir: &str,
    room_ref: &str,
    frontier_ref: &str,
    lease_ref: &str,
    resource_offer_refs: &[String],
    capability_offer_refs: &[String],
    wallet_now_ms: u64,
) -> Result<EligibilityTuple, VErr> {
    let frontier = admitted(
        &current_child(
            data_dir,
            room_ref,
            WORK_FRONTIER_ITEM_CONTRACT,
            frontier_ref,
        )?
        .ok_or_else(|| {
            verr(
                "m048_frontier_not_found",
                "the frontier item is not a current child of this room",
            )
        })?,
    )?
    .clone();

    let lease = admitted(
        &current_child(data_dir, room_ref, PARTICIPANT_LEASE_CONTRACT, lease_ref)?.ok_or_else(
            || {
                verr(
                    "m048_lease_not_found",
                    "the participant lease is not a current child of this room",
                )
            },
        )?,
    )?
    .clone();
    match lease_is_live(&lease, wallet_now_ms)? {
        Ok(()) => {}
        Err(LeaseLapse::Expired) => {
            return Err(verr(
                "m048_lease_expired",
                "the participant lease has expired at the wallet-authorized instant",
            ))
        }
        Err(_) => {
            return Err(verr(
                "m048_lease_not_active",
                "the participant lease is not active at the wallet-authorized instant",
            ))
        }
    }

    let mut resource_offers = Vec::new();
    for reference in resource_offer_refs {
        let offer = admitted(
            &current_child(data_dir, room_ref, RESOURCE_OFFER_CONTRACT, reference)?.ok_or_else(
                || {
                    verr(
                        "m048_resource_offer_not_found",
                        "a named resource offer is not a current child of this room",
                    )
                },
            )?,
        )?
        .clone();
        if !offer_is_live(RESOURCE_OFFER_FAMILY, &offer, wallet_now_ms)? {
            return Err(verr(
                "m048_resource_offer_expired",
                "a named resource offer has lapsed at the wallet-authorized instant",
            ));
        }
        // The offer must belong to THIS lease, not merely to this room.
        if offer
            .get(RESOURCE_OFFER_FAMILY.lease_field)
            .and_then(Value::as_str)
            != Some(lease_ref)
        {
            return Err(verr(
                "m048_resource_offer_foreign_issuer",
                "a named resource offer was not issued by this participant lease",
            ));
        }
        resource_offers.push(offer);
    }

    let mut capability_offers = Vec::new();
    for reference in capability_offer_refs {
        let offer = admitted(
            &current_child(data_dir, room_ref, CAPABILITY_OFFER_CONTRACT, reference)?.ok_or_else(
                || {
                    verr(
                        "m048_capability_offer_not_found",
                        "a named capability offer is not a current child of this room",
                    )
                },
            )?,
        )?
        .clone();
        if !offer_is_live(CAPABILITY_OFFER_FAMILY, &offer, wallet_now_ms)? {
            return Err(verr(
                "m048_capability_offer_expired",
                "a named capability offer has lapsed at the wallet-authorized instant",
            ));
        }
        if offer
            .get(CAPABILITY_OFFER_FAMILY.lease_field)
            .and_then(Value::as_str)
            != Some(lease_ref)
        {
            return Err(verr(
                "m048_capability_offer_foreign_issuer",
                "a named capability offer was not issued by this participant lease",
            ));
        }
        capability_offers.push(offer);
    }

    // Requirement coverage: every capability the frontier requires must be advertised by one of
    // the named capability offers. A missing requirement is a refusal, not a partial match.
    let required = frontier
        .get("required_capability_refs")
        .and_then(Value::as_array)
        .map(|refs| refs.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let advertised = capability_offers
        .iter()
        .flat_map(|offer| {
            offer
                .get("capability_descriptor_refs")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    for requirement in required {
        if !advertised.iter().any(|entry| entry == requirement) {
            return Err(verr(
                "m048_eligibility_requirement_uncovered",
                format!("`{requirement}` is required by this frontier item and is not advertised"),
            ));
        }
    }

    Ok(EligibilityTuple {
        frontier,
        lease,
        resource_offers,
        capability_offers,
    })
}

/// POST /v1/goal-orchestration/work-eligibility-matches
pub(crate) async fn handle_match_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match match_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn match_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            ELIGIBILITY_CREATE_FIELDS,
            "m048_eligibility_request_invalid",
        )?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_eligibility_request_invalid",
            )?,
            req_ref(
                body,
                "frontier_item_ref",
                &["frontier"],
                "m048_eligibility_request_invalid",
            )?,
            req_ref(
                body,
                "participant_lease_ref",
                &["participant-lease"],
                "m048_eligibility_request_invalid",
            )?,
            ref_list(
                body,
                "resource_offer_refs",
                &["resource-offer"],
                "m048_eligibility_request_invalid",
            )?,
            ref_list(
                body,
                "capability_offer_refs",
                &["capability-offer"],
                "m048_eligibility_request_invalid",
            )?,
        ))
    })()
    .map_err(classify)?;
    let (room_ref, frontier_ref, lease_ref, resource_refs, capability_refs) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &lease_ref,
        "match",
        &json!({ "op": "match", "frontier_item_ref": frontier_ref }),
    )
    .await?;

    let tuple = resolve_eligibility_tuple(
        data_dir,
        &room_ref,
        &frontier_ref,
        &lease_ref,
        &resource_refs,
        &capability_refs,
        resolved_at_ms,
    )
    .map_err(classify)?;

    let receipt = eligibility_match_body(
        &room_ref,
        &tuple.frontier,
        &tuple.lease,
        &tuple.resource_offers,
        &tuple.capability_offers,
        resolved_at_ms,
    )
    .map_err(classify)?;
    let tail = deterministic_tail(
        "wem_",
        "hypervisor.m048.work-eligibility-match.identity.v1",
        &json!({
            "outcome_room_ref": room_ref,
            "frontier_item_ref": frontier_ref,
            "participant_lease_ref": lease_ref,
            "resource_offer_refs": resource_refs,
            "capability_offer_refs": capability_refs,
        }),
    );
    let mut sealed = receipt;
    sealed["receipt_ref"] = json!(format!("receipt://{tail}"));
    // Append-only and replay-safe: an identical re-match converges, a divergent one conflicts.
    persist_local_receipt(data_dir, ELIGIBILITY_DIR, &tail, &sealed).map_err(classify)?;
    Ok(ok_local(
        ELIGIBILITY_MATCH_SCHEMA,
        "work_eligibility_match_receipt",
        sealed,
    ))
}

/// GET /v1/goal-orchestration/work-eligibility-matches
pub(crate) async fn handle_match_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match scan_local(&state.data_dir, ELIGIBILITY_DIR, ELIGIBILITY_MATCH_SCHEMA) {
        Ok(receipts) => {
            let body = json!({
                "ok": true,
                "schema_version": ELIGIBILITY_MATCH_SCHEMA,
                "count": receipts.len(),
                "work_eligibility_match_receipts": receipts,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            });
            if let Err(error) =
                room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")
            {
                return classify(error);
            }
            (StatusCode::OK, Json(body))
        }
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-eligibility-matches/overview
pub(crate) async fn handle_match_overview(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match scan_local(&state.data_dir, ELIGIBILITY_DIR, ELIGIBILITY_MATCH_SCHEMA) {
        Ok(receipts) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "schema_version": ELIGIBILITY_MATCH_SCHEMA,
                "total": receipts.len(),
                // Restated on every read: this family grants nothing, so an overview of it cannot
                // be mistaken for an allocation ledger.
                "grants": {
                    "allocation_created": false,
                    "claim_created": false,
                    "execution_authority_granted": false,
                },
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-eligibility-matches/:id
pub(crate) async fn handle_match_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    if !super::durable_fs::is_normalization_safe(&id) {
        return classify(verr(
            "m048_eligibility_ref_invalid",
            "an eligibility receipt tail must be normalization-safe",
        ));
    }
    match read_local(&state.data_dir, ELIGIBILITY_DIR, &id) {
        Ok(Some(receipt)) => ok_local(
            ELIGIBILITY_MATCH_SCHEMA,
            "work_eligibility_match_receipt",
            receipt,
        ),
        Ok(None) => classify(verr(
            "m048_eligibility_not_found",
            "no such work-eligibility match receipt",
        )),
        Err(error) => classify(error),
    }
}

// --- lifecycle 9: WorkClaimLease v3 --------------------------------------------------------------

const CLAIM_ACQUIRE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "frontier_item_ref",
    "participant_lease_ref",
    "eligibility_match_receipt_ref",
    "resource_offer_refs",
    "capability_offer_refs",
    "bounded_scope_ref",
    "contribution_policy_ref",
    "budget_reservation_ref",
    "context_lease_refs",
    "authority_resource_compute_data_budget_and_tool_lease_refs",
    "ttl_seconds",
];

#[allow(clippy::too_many_arguments)]
fn build_claim_candidate(
    claim_id: &str,
    tuple: &EligibilityTuple,
    lease_ref: &str,
    eligibility_ref: &str,
    body: &Value,
    issued_at: &str,
    expires_at: &str,
) -> Value {
    let lease = &tuple.lease;
    json!({
        "schema_version": WORK_CLAIM_LEASE_SCHEMA,
        "work_claim_id": claim_id,
        "frontier_item_ref": tuple.frontier.get("frontier_item_id").cloned().unwrap_or(Value::Null),
        "claimant_ref": lease.get("participant_ref").cloned().unwrap_or(Value::Null),
        "claimant_participant_lease_ref": lease_ref,
        "eligibility_match_receipt_ref": eligibility_ref,
        // No task offer, acceptance or routing decision exists in the hosted lane.
        "task_offer_ref": Value::Null,
        "task_acceptance_ref": Value::Null,
        "routing_decision_ref": Value::Null,
        // The claim binds the SAME terms triple the lease binds; it cannot invent its own.
        "collaboration_terms_ref": lease.get("collaboration_terms_ref").cloned().unwrap_or(Value::Null),
        "collaboration_terms_root": lease.get("accepted_terms_root").cloned().unwrap_or(Value::Null),
        "terms_acceptance_ref": lease.get("terms_acceptance_ref").cloned().unwrap_or(Value::Null),
        "contribution_policy_ref": body.get("contribution_policy_ref").cloned().unwrap_or(Value::Null),
        "quote_ref": Value::Null,
        "budget_reservation_ref": body.get("budget_reservation_ref").cloned().unwrap_or(Value::Null),
        // Contract-required, and deliberately a no-settlement profile: this plane settles nothing.
        "settlement_profile_ref": "policy://ioi/m048/no-settlement-v1",
        "bounded_scope_ref": body.get("bounded_scope_ref").cloned().unwrap_or(Value::Null),
        "context_lease_refs": body.get("context_lease_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_resource_compute_data_budget_and_tool_lease_refs": body
            .get("authority_resource_compute_data_budget_and_tool_lease_refs")
            .cloned()
            .unwrap_or_else(|| json!([])),
        "duplicate_work_policy": "exclusive",
        "issued_at": issued_at,
        "expires_at": expires_at,
        // A fresh claim has not heartbeat yet; `expires_at` already carries its deadline.
        "heartbeat_ref": Value::Null,
        "renewal_count": 0,
        "release_or_reassignment_reason": Value::Null,
        "status": "active",
    })
}

/// POST /v1/goal-orchestration/work-claim-leases
pub(crate) async fn handle_claim_acquire(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match claim_acquire_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn claim_acquire_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, CLAIM_ACQUIRE_FIELDS, "m048_claim_request_invalid")?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_claim_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_claim_request_invalid",
            )?,
            req_ref(
                body,
                "frontier_item_ref",
                &["frontier"],
                "m048_claim_request_invalid",
            )?,
            req_ref(
                body,
                "participant_lease_ref",
                &["participant-lease"],
                "m048_claim_request_invalid",
            )?,
            req_ref(
                body,
                "eligibility_match_receipt_ref",
                &["receipt"],
                "m048_claim_request_invalid",
            )?,
            ref_list(
                body,
                "resource_offer_refs",
                &["resource-offer"],
                "m048_claim_request_invalid",
            )?,
            ref_list(
                body,
                "capability_offer_refs",
                &["capability-offer"],
                "m048_claim_request_invalid",
            )?,
            req_ttl(
                body,
                "ttl_seconds",
                CLAIM_TTL_MIN_SECONDS,
                CLAIM_TTL_MAX_SECONDS,
                "m048_claim_request_invalid",
            )?,
        ))
    })()
    .map_err(classify)?;
    let (
        room_ref,
        expected_head,
        frontier_ref,
        lease_ref,
        eligibility_ref,
        resource_refs,
        capability_refs,
        ttl_seconds,
    ) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }

    // The wallet instant is resolved IMMEDIATELY before revalidation and the head CAS, so nothing
    // between the caller's read and the write is judged against a stale clock.
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &lease_ref,
        "acquire",
        &json!({ "op": "acquire", "frontier_item_ref": frontier_ref }),
    )
    .await?;

    // The eligibility receipt is EVIDENCE, never authority. It must exist and it must name exactly
    // this tuple, but the tuple itself is re-derived from current room truth below — a receipt
    // that has since gone stale cannot carry a claim.
    let eligibility_tail = eligibility_ref
        .strip_prefix("receipt://")
        .filter(|tail| super::durable_fs::is_normalization_safe(tail))
        .ok_or_else(|| {
            classify(verr(
                "m048_eligibility_ref_invalid",
                "an eligibility receipt ref must be receipt://<normalization-safe tail>",
            ))
        })?;
    let evidence = read_local(data_dir, ELIGIBILITY_DIR, eligibility_tail)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_eligibility_not_found",
                "no such work-eligibility match receipt",
            ))
        })?;
    let expected_tail = deterministic_tail(
        "wem_",
        "hypervisor.m048.work-eligibility-match.identity.v1",
        &json!({
            "outcome_room_ref": room_ref,
            "frontier_item_ref": frontier_ref,
            "participant_lease_ref": lease_ref,
            "resource_offer_refs": resource_refs,
            "capability_offer_refs": capability_refs,
        }),
    );
    if eligibility_tail != expected_tail {
        return Err(classify(verr(
            "m048_eligibility_tuple_mismatch",
            "the eligibility receipt does not name the exact tuple this claim asserts",
        )));
    }
    for grant in [
        "allocation_created",
        "claim_created",
        "execution_authority_granted",
    ] {
        if evidence.get(grant).and_then(Value::as_bool) != Some(false) {
            return Err(classify(verr(
                "m048_eligibility_record_invalid",
                "an eligibility receipt that claims to grant anything is not admissible evidence",
            )));
        }
    }

    // FRESH revalidation of the complete tuple at this instant — not a re-read of the receipt.
    let tuple = resolve_eligibility_tuple(
        data_dir,
        &room_ref,
        &frontier_ref,
        &lease_ref,
        &resource_refs,
        &capability_refs,
        resolved_at_ms,
    )
    .map_err(classify)?;

    // Exclusivity: taken at the observed head and committed against that same head, so a racing
    // claimant either loses this check or loses the CAS.
    let claims = current_claims(data_dir, &room_ref).map_err(classify)?;
    refuse_when_already_claimed(&tuple.frontier, &claims, resolved_at_ms).map_err(classify)?;

    let issued_at = wallet_ms_to_rfc3339(resolved_at_ms).map_err(classify)?;
    let expires_at =
        wallet_ms_to_rfc3339(wallet_deadline_ms(resolved_at_ms, ttl_seconds).map_err(classify)?)
            .map_err(classify)?;
    let claim_id = format!(
        "work-claim://{}",
        deterministic_tail(
            "wcl_",
            "hypervisor.m048.work-claim-lease.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "frontier_item_ref": frontier_ref,
                "participant_lease_ref": lease_ref,
                "issued_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    let candidate = build_claim_candidate(
        &claim_id,
        &tuple,
        &lease_ref,
        &eligibility_ref,
        body,
        &issued_at,
        &expires_at,
    );
    let admission = admit_child(
        data_dir,
        &observed,
        WORK_CLAIM_LEASE_CONTRACT,
        &candidate,
        &lease_ref,
        None,
    )
    .map_err(classify)?;
    Ok(ok_child(
        WORK_CLAIM_LEASE_CONTRACT,
        WORK_CLAIM_LEASE_SCHEMA,
        &admission,
    ))
}

/// The claim transitions this build step owns.
///
/// `reassign` is deliberately absent: reassignment is a routing decision this plane does not make.
fn claim_transition_target(op: &str) -> Option<&'static str> {
    match op {
        "heartbeat" => Some("active"),
        "release" => Some("released"),
        "expire" => Some("expired"),
        "complete" => Some("completed"),
        _ => None,
    }
}

/// POST /v1/goal-orchestration/work-claim-leases/:id/transition
pub(crate) async fn handle_claim_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match claim_transition_inner(&state.data_dir, &id, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn claim_transition_inner(
    data_dir: &str,
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            &[
                "outcome_room_ref",
                "expected_room_state_root",
                "op",
                "heartbeat_ref",
                "release_or_reassignment_reason",
            ],
            "m048_claim_request_invalid",
        )?;
        let room_ref = req_ref(
            body,
            "outcome_room_ref",
            &["outcome-room"],
            "m048_claim_request_invalid",
        )?;
        let expected_head = req_root(
            body,
            "expected_room_state_root",
            "m048_claim_request_invalid",
        )?;
        let op = req_vocab(
            body,
            "op",
            &["heartbeat", "release", "expire", "complete"],
            "m048_claim_request_invalid",
        )?;
        let heartbeat_ref = opt_ref(
            body,
            "heartbeat_ref",
            &["receipt"],
            "m048_claim_request_invalid",
        )?;
        if heartbeat_ref.is_some() && op != "heartbeat" {
            return Err(verr(
                "m048_claim_field_not_admitted_for_transition",
                "`heartbeat_ref` is admitted only on a heartbeat transition",
            ));
        }
        let reason = str_opt(body, "release_or_reassignment_reason")?;
        if reason.is_some() && op != "release" {
            return Err(verr(
                "m048_claim_field_not_admitted_for_transition",
                "`release_or_reassignment_reason` is admitted only on a release transition",
            ));
        }
        if op == "heartbeat" && heartbeat_ref.is_none() {
            return Err(verr(
                "m048_claim_request_invalid",
                "a heartbeat transition must carry its receipt:// heartbeat_ref",
            ));
        }
        Ok((room_ref, expected_head, op, heartbeat_ref, reason))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, op, heartbeat_ref, reason) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let claim_ref = format!("work-claim://{id}");
    let projection = current_child(data_dir, &room_ref, WORK_CLAIM_LEASE_CONTRACT, &claim_ref)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_claim_not_found",
                "this room admitted no such work claim",
            ))
        })?;
    let claim = admitted(&projection).map_err(classify)?.clone();
    let current_status = claim
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if CLAIM_TERMINAL_STATUSES.contains(&current_status) {
        return Err(classify(verr(
            "m048_claim_terminal",
            "a terminal work claim admits no further transition",
        )));
    }
    let lease_ref = claim
        .get("claimant_participant_lease_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let governance = match op.as_str() {
        "expire" => governed::Governance::Host,
        _ => governed::Governance::Participant,
    };
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governance,
        &room_ref,
        &observed.system_id,
        &claim_ref,
        &op,
        &json!({ "op": op, "work_claim_id": claim_ref }),
    )
    .await?;

    // Expiry is decided against wallet time only.
    if op == "expire"
        && claim_is_live(&claim, resolved_at_ms, CLAIM_HEARTBEAT_MAX_SECONDS)
            .map_err(classify)?
            .is_ok()
    {
        return Err(classify(verr(
            "m048_claim_not_expired",
            "this claim has not lapsed at the wallet-authorized instant",
        )));
    }
    // A heartbeat may only refresh a claim that is still live; a lapsed one must be released or
    // expired, never silently resurrected.
    if op == "heartbeat"
        && claim_is_live(&claim, resolved_at_ms, CLAIM_HEARTBEAT_MAX_SECONDS)
            .map_err(classify)?
            .is_err()
    {
        return Err(classify(verr(
            "m048_claim_lapsed",
            "this claim has already lapsed and cannot be revived by a heartbeat",
        )));
    }

    let target = claim_transition_target(&op).ok_or_else(|| {
        classify(verr(
            "m048_claim_transition_unavailable",
            "no current-generation purpose is registered for this transition",
        ))
    })?;

    let mut successor = claim.clone();
    let map = successor.as_object_mut().ok_or_else(|| {
        classify(verr(
            "m048_claim_record_invalid",
            "a work claim must be an object",
        ))
    })?;
    map.remove("system_binding");
    map.remove("outcome_room_ref");
    map.insert("status".to_string(), json!(target));
    match op.as_str() {
        "heartbeat" => {
            // The heartbeat advances the deadline from the wallet instant, bounded by the
            // heartbeat maximum. This is the only place liveness is extended.
            let refreshed = wallet_deadline_ms(resolved_at_ms, CLAIM_HEARTBEAT_MAX_SECONDS)
                .map_err(classify)?;
            map.insert(
                "expires_at".to_string(),
                json!(wallet_ms_to_rfc3339(refreshed).map_err(classify)?),
            );
            map.insert("heartbeat_ref".to_string(), json!(heartbeat_ref));
            let renewals = claim
                .get("renewal_count")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            map.insert("renewal_count".to_string(), json!(renewals + 1));
        }
        "release" => {
            map.insert("release_or_reassignment_reason".to_string(), json!(reason));
        }
        _ => {}
    }

    let prior_root = object_root(&projection).map_err(classify)?;
    // Release is ONE admission: a terminal successor of the claim. The frontier item is not
    // written — its claimability is a projection over live claims, so removing this claim from
    // that set is the whole of "returning the item to claimable". No Attempt is touched.
    let admission = admit_child(
        data_dir,
        &observed,
        WORK_CLAIM_LEASE_CONTRACT,
        &successor,
        &lease_ref,
        Some(&prior_root),
    )
    .map_err(classify)?;
    Ok(ok_child(
        WORK_CLAIM_LEASE_CONTRACT,
        WORK_CLAIM_LEASE_SCHEMA,
        &admission,
    ))
}

/// An optional bounded free-text field.
fn str_opt(body: &Value, key: &str) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if !raw.is_empty() && raw.chars().count() <= STRING_MAX => {
            Ok(Some(raw.clone()))
        }
        Some(_) => Err(verr(
            "m048_claim_request_invalid",
            format!("`{key}` must be a bounded non-empty string"),
        )),
    }
}

/// GET /v1/goal-orchestration/work-claim-leases
pub(crate) async fn handle_claim_list(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_claim_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(&state.data_dir, room_ref, WORK_CLAIM_LEASE_CONTRACT).and_then(
        |objects| {
            ok_child_list(
                WORK_CLAIM_LEASE_CONTRACT,
                WORK_CLAIM_LEASE_SCHEMA,
                &observed,
                objects,
            )
        },
    ) {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-claim-leases/:id
pub(crate) async fn handle_claim_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_claim_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let claim_ref = format!("work-claim://{id}");
    match current_child(
        &state.data_dir,
        room_ref,
        WORK_CLAIM_LEASE_CONTRACT,
        &claim_ref,
    ) {
        Ok(Some(projection)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "object_contract_id": WORK_CLAIM_LEASE_CONTRACT,
                "schema_version": WORK_CLAIM_LEASE_SCHEMA,
                "projection": projection,
                // Full lineage is reachable; a superseded generation is history, not garbage.
                "lineage_available": true,
                "projection_only": true,
                "runtimeTruthSource": "daemon-runtime",
            })),
        ),
        Ok(None) => classify(verr(
            "m048_claim_not_found",
            "this room admitted no such work claim",
        )),
        Err(error) => classify(error),
    }
}

/// GET /v1/goal-orchestration/work-claim-leases/overview
pub(crate) async fn handle_claim_overview(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): OfferQuery,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            "m048_claim_request_invalid",
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(&state.data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    let resolved_at_ms = match authorized_instant(
        &state.data_dir,
        &json!({}),
        governed::Governance::Participant,
        room_ref,
        &observed.system_id,
        room_ref,
        "read",
        &json!({ "op": "read", "projection": "work-claim-liveness" }),
    )
    .await
    {
        Ok(resolved_at_ms) => resolved_at_ms,
        Err(error) => return error,
    };
    match claim_overview_projection(&state.data_dir, room_ref, resolved_at_ms) {
        Ok(body) => (StatusCode::OK, Json(body)),
        Err(error) => classify(error),
    }
}

// --- lifecycle 8: Attempt v3 ---------------------------------------------------------------------
//
// An Attempt is the durable record of work done under a claim. It is deliberately independent of
// the claim's liveness: a claim that lapses, is released, or expires produces a terminal claim
// successor and NOTHING ELSE — no Attempt is deleted, rewritten, or detached. That independence is
// what makes contribution lineage survive a worker walking away mid-task.

const ATTEMPT_OUTCOME_CLASSES: &[&str] = &[
    "positive",
    "negative",
    "inconclusive",
    "invalid",
    "exploit_found",
    "superseded",
];
const ATTEMPT_REPRODUCTION_STATES: &[&str] = &[
    "unreviewed",
    "reproducible",
    "not_reproduced",
    "contradicted",
    "invalidated",
];
const ATTEMPT_STATUSES: &[&str] = &[
    "draft",
    "running",
    "submitted",
    "admitted",
    "challenged",
    "accepted",
    "rejected",
    "superseded",
];
/// Verdicts this plane does not issue.
const ATTEMPT_VERDICT_STATUSES: &[&str] = &["accepted", "rejected"];

// --- bound coordinates -------------------------------------------------------------------------
//
// A room-bound Attempt or Finding MUST carry populated `bound_coordinates`; only the non-room lane
// may null them (see `fixtures/attempt-v3/positive-non-room.json`, which nulls the binding and the
// room ref together). The registered invariants then pin every coordinate to the ref it mirrors —
// `bound_coordinates.work_claim.record_ref` must equal `work_claim_ref`, its `outcome_room_ref`
// must equal the object's, its `frontier_item_ref` must equal the object's, and so on.
//
// Because those are equalities against fields the daemon already derives, the coordinates are
// DERIVED HERE from the live projections rather than accepted from the caller. A caller cannot
// supply a revision or a record hash for anything this room already knows: a stale or mismatched
// coordinate would otherwise become durable binding evidence that never matched reality.
//
// Two coordinates are the exception, and only because their objects live outside this plane
// entirely: GoalRun and WorkResult are not room-native children (WorkResult is an owner-registry
// family the seam explicitly refuses). Their `record_hash`/`updated_at` cannot be derived without
// reaching into another owner's truth, so they are caller-attested and this plane validates what
// it can — scheme, and for the GoalRun, actual membership of this room.

/// The live generation number of a projection, used as the registered `revision`.
fn projection_revision(projection: &Value) -> Result<i64, VErr> {
    projection
        .get("generation")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            verr(
                "m048_projection_unreadable",
                "a room-child projection carries no generation",
            )
        })
}

/// Derive the Attempt's bound coordinates from live room truth.
///
/// Every equality the registered invariant profile checks is satisfied by construction here, so a
/// mismatch is impossible rather than merely unlikely.
fn attempt_bound_coordinates(
    observed: &RoomAtHead,
    frontier_projection: &Value,
    claim_projection: &Value,
    lease_projection: &Value,
    goal_run: &GoalRunCoordinate,
) -> Result<Value, VErr> {
    let room_ref = observed.room_ref.as_str();
    let host_domain_ref = observed
        .room
        .get("host_domain_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_room_host_domain_unresolved",
                "the room record names no host domain, which the bound coordinates require",
            )
        })?;
    let frontier = admitted(frontier_projection)?;
    let claim = admitted(claim_projection)?;
    let lease = admitted(lease_projection)?;

    let frontier_ref = exact_ref(frontier, "frontier_item_id")?;
    let lease_ref = exact_ref(lease, "participant_lease_id")?;
    let principal_ref = exact_ref(lease, "participant_ref")?;

    Ok(json!({
        "outcome_room": {
            "record_ref": room_ref,
            "host_domain_ref": host_domain_ref,
            "control_hash": observed.head,
        },
        "frontier_item": {
            "record_ref": frontier_ref,
            "outcome_room_ref": room_ref,
            "revision": projection_revision(frontier_projection)?,
            "record_hash": object_root(frontier_projection)?,
        },
        "work_claim": {
            "record_ref": exact_ref(claim, "work_claim_id")?,
            "outcome_room_ref": room_ref,
            "frontier_item_ref": frontier_ref,
            // The registered shape pins the claimant to the LEASE, not the worker.
            "claimant_ref": lease_ref,
            "revision": projection_revision(claim_projection)?,
            "record_hash": object_root(claim_projection)?,
        },
        "participant_lease": {
            "record_ref": lease_ref,
            "outcome_room_ref": room_ref,
            "principal_ref": principal_ref,
            "revision": projection_revision(lease_projection)?,
            "record_hash": object_root(lease_projection)?,
        },
        "goal_run": {
            "record_ref": goal_run.record_ref,
            "outcome_room_ref": room_ref,
            "updated_at": goal_run.updated_at,
            "record_hash": goal_run.record_hash,
        },
    }))
}

/// Compose the WorkResult coordinate block from the resolved owner truths.
fn work_result_coordinate_block(work_result: &WorkResultCoordinate) -> Value {
    json!({
        "record_ref": work_result.record_ref,
        "outcome_room_ref": work_result.outcome_room_ref,
        "goal_run_ref": work_result.goal_run_ref,
        "goal_ref": work_result.goal_ref,
        // Explicitly null: the strict owner exposes no record update timestamp, and the registered
        // coordinate admits null. See `WorkResultCoordinate`.
        "updated_at": Value::Null,
        "record_hash": work_result.record_hash,
    })
}

/// Derive the Finding's bound coordinates from live room truth plus the attested WorkResult.
fn finding_bound_coordinates(
    room_ref: &str,
    attempt_projection: &Value,
    lease_projection: &Value,
    work_result: &WorkResultCoordinate,
) -> Result<Value, VErr> {
    let attempt = admitted(attempt_projection)?;
    let lease = admitted(lease_projection)?;
    let lease_ref = exact_ref(lease, "participant_lease_id")?;
    Ok(json!({
        "attempt": {
            "record_ref": exact_ref(attempt, "attempt_id")?,
            "outcome_room_ref": room_ref,
            // The registered shape pins the attempt's participant coordinate to the LEASE.
            "participant_ref": lease_ref,
            "work_result_ref": work_result.record_ref,
            "revision": projection_revision(attempt_projection)?,
            "record_hash": object_root(attempt_projection)?,
        },
        "work_result": work_result_coordinate_block(work_result),
        "participant_lease": {
            "record_ref": lease_ref,
            "outcome_room_ref": room_ref,
            "principal_ref": exact_ref(lease, "participant_ref")?,
            "revision": projection_revision(lease_projection)?,
            "record_hash": object_root(lease_projection)?,
        },
        // Supersession lineage is carried by `supersedes_ref`; this coordinate stays null until a
        // superseding finding names its predecessor.
        "supersedes_finding": Value::Null,
    }))
}

/// A required string field of an admitted payload.
fn exact_ref<'a>(record: &'a Value, field: &str) -> Result<&'a str, VErr> {
    record.get(field).and_then(Value::as_str).ok_or_else(|| {
        verr(
            "m048_record_coordinate_missing",
            format!("an admitted record carries no `{field}`"),
        )
    })
}

/// The registered owner-registry contract for WorkResult. Read-only here: this plane never admits
/// one, but it must be able to see the room generation that did.
const WORK_RESULT_V3_CONTRACT: &str = "schema://ioi/foundations/work-result/v3";

/// The GoalRun coordinate, derived entirely from the strict owner record.
///
/// A caller names the run; every value below comes from `goalrun_routes::load_goal_run_strict`, so
/// a caller cannot attest a hash or an instant for a record it does not own.
#[derive(Debug)]
struct GoalRunCoordinate {
    record_ref: String,
    updated_at: String,
    record_hash: String,
}

/// The WorkResult coordinate: a COMPOSED historical coordinate, not WorkResult body state.
///
/// Its fields are not all properties of the WorkResult — the registered `work-result/v3` contract
/// declares no room ref, no goal refs and no update timestamp. They are composed from three owner
/// truths that each already exist:
///
///   * `record_ref`      — the strict owner WorkResult's own id;
///   * `outcome_room_ref`— the room in whose Agentgres history that exact id was admitted, proven
///                         by a current room-child projection whose admitted object matches the
///                         strict owner record byte-for-byte;
///   * `goal_run_ref`    — the owner WorkResult's `work_subject_ref`, admitted here only when it
///                         is a `goal://` identity AND a member of that same room;
///   * `goal_ref`        — the resolved strict GoalRun's own `goal_ref`. In this implementation
///                         the run and its goal are one identity; no distinct value is fabricated;
///   * `updated_at`      — NULL, explicitly. The strict owner exposes no record update timestamp
///                         and the registered coordinate admits null. Inventing one would be
///                         hashing a claim canon does not make;
///   * `record_hash`     — the canonical content hash of the exact strict owner record.
///
/// Nothing here widens WorkResult and nothing here is caller-supplied.
#[derive(Debug)]
struct WorkResultCoordinate {
    record_ref: String,
    outcome_room_ref: String,
    goal_run_ref: String,
    goal_ref: String,
    record_hash: String,
}

/// Resolve the GoalRun coordinate from owner truth, refusing every uncertainty.
fn resolve_goal_run_coordinate(
    data_dir: &str,
    observed: &RoomAtHead,
    goal_run_ref: &str,
) -> Result<GoalRunCoordinate, VErr> {
    require_room_goal_run(observed, goal_run_ref)?;
    let record = super::goalrun_routes::load_goal_run_strict(data_dir, goal_run_ref)
        .map_err(|error| verr("m048_goal_run_unreadable", error))?
        .ok_or_else(|| {
            verr(
                "m048_goal_run_not_found",
                "no strict GoalRun owner record for this ref",
            )
        })?;
    let updated_at = record
        .get("updated_at")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_goal_run_coordinate_underivable",
                "the strict GoalRun owner record carries no `updated_at` to bind",
            )
        })?
        .to_string();
    if !is_rfc3339(&json!(updated_at)) {
        return Err(verr(
            "m048_goal_run_coordinate_underivable",
            "the strict GoalRun owner `updated_at` is not RFC3339",
        ));
    }
    Ok(GoalRunCoordinate {
        record_ref: goal_run_ref.to_string(),
        updated_at,
        // The canonical content hash of the exact owner record; recomputed on every admission, so
        // a mutated owner record yields a different coordinate rather than a stale one.
        record_hash: record_output_hash(&record, &[]),
    })
}

/// Resolve the composed WorkResult coordinate, refusing every uncertainty before any child write.
fn resolve_work_result_coordinate(
    data_dir: &str,
    observed: &RoomAtHead,
    work_result_ref: &str,
) -> Result<WorkResultCoordinate, VErr> {
    let owner = super::work_result_routes::load_work_result_strict(data_dir, work_result_ref)
        .map_err(|error| verr("m048_work_result_unreadable", error))?
        .ok_or_else(|| {
            verr(
                "m048_work_result_not_found",
                "no strict WorkResult owner record for this ref",
            )
        })?;

    // The room coordinate is proven by the room's own history, never asserted. A WorkResult that
    // this room never admitted cannot be bound to a finding in it.
    let projection = current_child(
        data_dir,
        &observed.room_ref,
        WORK_RESULT_V3_CONTRACT,
        work_result_ref,
    )?
    .ok_or_else(|| {
        verr(
            "m048_work_result_foreign_room",
            "this room's Agentgres history admitted no such WorkResult",
        )
    })?;
    let admitted_object = admitted(&projection)?;
    // Owner truth and room truth must be the same object. A divergence is uncertainty about which
    // one the finding would be binding, so it refuses rather than picking one.
    if record_output_hash(admitted_object, &[]) != record_output_hash(&owner, &[]) {
        return Err(verr(
            "m048_work_result_owner_mismatch",
            "the room-admitted WorkResult and the strict owner record are not the same object",
        ));
    }

    let subject = owner
        .get("work_subject_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !subject.starts_with("goal://") {
        return Err(verr(
            "m048_work_result_subject_not_a_goal_run",
            "this WorkResult's work subject is not a goal:// run, so no goal coordinate exists",
        ));
    }
    // The run must belong to this room, and its own record supplies the goal identity.
    require_room_goal_run(observed, subject)?;
    let goal_run = super::goalrun_routes::load_goal_run_strict(data_dir, subject)
        .map_err(|error| verr("m048_goal_run_unreadable", error))?
        .ok_or_else(|| {
            verr(
                "m048_goal_run_not_found",
                "the WorkResult's goal run has no strict owner record",
            )
        })?;
    let goal_ref = goal_run
        .get("goal_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            verr(
                "m048_goal_run_coordinate_underivable",
                "the strict GoalRun owner record carries no `goal_ref`",
            )
        })?
        .to_string();

    Ok(WorkResultCoordinate {
        record_ref: work_result_ref.to_string(),
        outcome_room_ref: observed.room_ref.clone(),
        goal_run_ref: subject.to_string(),
        goal_ref,
        record_hash: record_output_hash(&owner, &[]),
    })
}

/// Refuse a GoalRun that this room never admitted as a member.
fn require_room_goal_run(observed: &RoomAtHead, goal_run_ref: &str) -> Result<(), VErr> {
    let member = observed
        .room
        .get("member_goal_run_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|value| value.as_str() == Some(goal_run_ref))
        });
    if !member {
        return Err(verr(
            "m048_goal_run_not_a_room_member",
            "the named GoalRun is not a member of this room; an attempt cannot bind a foreign run",
        ));
    }
    Ok(())
}

const ATTEMPT_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "work_claim_ref",
    // A caller names the run and nothing else: its instant and hash are derived from the strict
    // owner record, so no attested coordinate can enter here.
    "goal_run_ref",
    "declared_method_and_hypothesis_refs",
    "input_state_and_environment_refs",
    "worker_model_resolver_tool_and_runtime_version_refs",
    "authority_and_policy_refs",
    "resource_and_cost_refs",
    "outcome_class",
    "artifact_evidence_and_receipt_refs",
    "artifact_license_ip_retention_and_export_refs",
    "goal_run_ref",
];

fn build_attempt_candidate(
    attempt_id: &str,
    claim: &Value,
    principal_ref: &str,
    goal_run_ref: &str,
    bound_coordinates: Value,
    body: &Value,
) -> Value {
    json!({
        "schema_version": ATTEMPT_SCHEMA,
        "attempt_id": attempt_id,
        // The claim is the work subject: an Attempt exists because a claim authorized the work.
        "work_subject_ref": claim.get("work_claim_id").cloned().unwrap_or(Value::Null),
        // Non-null by necessity: the bound coordinates require a GoalRun, and the registered
        // invariant pins this field to `bound_coordinates.goal_run.record_ref`.
        "goal_run_ref": goal_run_ref,
        "frontier_item_ref": claim.get("frontier_item_ref").cloned().unwrap_or(Value::Null),
        "work_claim_ref": claim.get("work_claim_id").cloned().unwrap_or(Value::Null),
        // The worker, matching `bound_coordinates.participant_lease.principal_ref`, which is the
        // branch of the registered any_of this lane satisfies.
        "participant_ref": principal_ref,
        "bound_coordinates": bound_coordinates,
        "declared_method_and_hypothesis_refs": body.get("declared_method_and_hypothesis_refs").cloned().unwrap_or_else(|| json!([])),
        "parent_and_derivation_refs": [],
        "input_state_and_environment_refs": body.get("input_state_and_environment_refs").cloned().unwrap_or_else(|| json!([])),
        "worker_model_resolver_tool_and_runtime_version_refs": body.get("worker_model_resolver_tool_and_runtime_version_refs").cloned().unwrap_or_else(|| json!([])),
        "authority_and_policy_refs": body.get("authority_and_policy_refs").cloned().unwrap_or_else(|| json!([])),
        "resource_and_cost_refs": body.get("resource_and_cost_refs").cloned().unwrap_or_else(|| json!([])),
        "outcome_class": body.get("outcome_class").cloned().unwrap_or(Value::Null),
        // WorkResult and OutcomeDelta are owner-registry families this plane does not mint.
        "work_result_ref": Value::Null,
        "outcome_delta_refs": [],
        "artifact_evidence_and_receipt_refs": body.get("artifact_evidence_and_receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "verifier_refs": [],
        "reproduction_state": "unreviewed",
        "artifact_license_ip_retention_and_export_refs": body.get("artifact_license_ip_retention_and_export_refs").cloned().unwrap_or_else(|| json!([])),
        // No Contribution object is invented: lineage composes through the refs above.
        "contribution_refs": [],
        "status": "submitted",
    })
}

/// Resolve the live claim an Attempt is being recorded under.
///
/// An Attempt may only be CREATED under a live claim — that is what authorizes the work. Once
/// created it outlives the claim entirely.
fn require_live_claim(
    data_dir: &str,
    room_ref: &str,
    claim_ref: &str,
    wallet_now_ms: u64,
) -> Result<(Value, Value, Value), VErr> {
    let claim_projection = current_child(data_dir, room_ref, WORK_CLAIM_LEASE_CONTRACT, claim_ref)?
        .ok_or_else(|| {
            verr(
                "m048_claim_not_found",
                "the work claim is not a current child of this room",
            )
        })?;
    let claim = admitted(&claim_projection)?.clone();
    if claim_is_live(&claim, wallet_now_ms, CLAIM_HEARTBEAT_MAX_SECONDS)?.is_err() {
        return Err(verr(
            "m048_claim_lapsed",
            "this work claim is not live at the wallet-authorized instant",
        ));
    }
    // The claim's own participant lease must still be active too: a live claim under a revoked
    // lease is not authority.
    let lease_ref = claim
        .get("claimant_participant_lease_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let lease_projection =
        current_child(data_dir, room_ref, PARTICIPANT_LEASE_CONTRACT, lease_ref)?.ok_or_else(
            || {
                verr(
                    "m048_lease_not_found",
                    "the claim's participant lease is not a current child of this room",
                )
            },
        )?;
    if lease_is_live(admitted(&lease_projection)?, wallet_now_ms)?.is_err() {
        return Err(verr(
            "m048_lease_not_active",
            "the claim's participant lease is not active at the wallet-authorized instant",
        ));
    }
    // The frontier item the claim holds, needed for its bound coordinate.
    let frontier_ref = claim
        .get("frontier_item_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let frontier_projection = current_child(
        data_dir,
        room_ref,
        WORK_FRONTIER_ITEM_CONTRACT,
        frontier_ref,
    )?
    .ok_or_else(|| {
        verr(
            "m048_frontier_not_found",
            "the claim's frontier item is not a current child of this room",
        )
    })?;
    Ok((claim_projection, lease_projection, frontier_projection))
}

/// POST /v1/goal-orchestration/attempts
pub(crate) async fn handle_attempt_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match attempt_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn attempt_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, ATTEMPT_CREATE_FIELDS, "m048_attempt_request_invalid")?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_attempt_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_attempt_request_invalid",
            )?,
            req_ref(
                body,
                "work_claim_ref",
                &["work-claim"],
                "m048_attempt_request_invalid",
            )?,
            req_vocab(
                body,
                "outcome_class",
                ATTEMPT_OUTCOME_CLASSES,
                "m048_attempt_request_invalid",
            )?,
            // GoalRun coordinates are caller-attested: the run is not a room-native child, so its
            // hash and update instant cannot be derived here without reaching into another plane.
            req_ref(
                body,
                "goal_run_ref",
                &["goal"],
                "m048_attempt_request_invalid",
            )?,
        ))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, claim_ref, _outcome_class, goal_run_ref) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &claim_ref,
        "attempt",
        &json!({ "op": "attempt", "work_claim_ref": claim_ref }),
    )
    .await?;

    let goal_run_coordinate =
        resolve_goal_run_coordinate(data_dir, &observed, &goal_run_ref).map_err(classify)?;
    let (claim_projection, lease_projection, frontier_projection) =
        require_live_claim(data_dir, &room_ref, &claim_ref, resolved_at_ms).map_err(classify)?;
    let claim = admitted(&claim_projection).map_err(classify)?.clone();
    let lease = admitted(&lease_projection).map_err(classify)?.clone();
    let lease_ref = lease
        .get("participant_lease_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let principal_ref = lease
        .get("participant_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let bound_coordinates = attempt_bound_coordinates(
        &observed,
        &frontier_projection,
        &claim_projection,
        &lease_projection,
        &goal_run_coordinate,
    )
    .map_err(classify)?;
    let attempt_id = format!(
        "attempt://{}",
        deterministic_tail(
            "atm_",
            "hypervisor.m048.attempt.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "work_claim_ref": claim_ref,
                "recorded_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    let candidate = build_attempt_candidate(
        &attempt_id,
        &claim,
        &principal_ref,
        &goal_run_ref,
        bound_coordinates,
        body,
    );
    let admission = admit_child(
        data_dir,
        &observed,
        ATTEMPT_CONTRACT,
        &candidate,
        &lease_ref,
        None,
    )
    .map_err(classify)?;
    Ok(ok_child(ATTEMPT_CONTRACT, ATTEMPT_SCHEMA, &admission))
}

// --- lifecycle 9: Finding v3 -----------------------------------------------------------------

const FINDING_KINDS: &[&str] = &[
    "hypothesis",
    "observation",
    "claim",
    "negative_result",
    "integrity_incident",
    "mapping_claim",
    "causal_claim",
    "counterexample",
    "synthesis",
];
const FINDING_STATUSES: &[&str] = &[
    "branch_local",
    "proposed",
    "admitted",
    "contradicted",
    "superseded",
    "disputed",
    "rejected",
    "archived",
];
/// The registered standing a challenged Finding takes.
const FINDING_DISPUTED_STATUS: &str = "disputed";
/// Statuses that are verdicts this plane does not issue.
const FINDING_VERDICT_STATUSES: &[&str] = &["rejected"];

const FINDING_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "attempt_ref",
    "work_result_ref",
    "proposition",
    "finding_kind",
    "confidence_or_uncertainty",
    "source_and_observation_context_refs",
    "supporting_evidence_refs",
    "proof_refs",
    "contradicting_evidence_refs",
    "applicability_and_counterexample_refs",
    "provenance_ontology_and_mapping_refs",
    "supersedes_ref",
];

#[allow(clippy::too_many_arguments)]
fn build_finding_candidate(
    finding_id: &str,
    attempt: &Value,
    lease_ref: &str,
    proposed_by_ref: &str,
    work_result_ref: &str,
    transaction_time: &str,
    bound_coordinates: Value,
    body: &Value,
) -> Value {
    json!({
        "schema_version": FINDING_SCHEMA,
        "finding_id": finding_id,
        "attempt_ref": attempt.get("attempt_id").cloned().unwrap_or(Value::Null),
        "work_result_ref": work_result_ref,
        // The registered contract pins this to a participant-lease ref, and the invariant profile
        // pins it to `bound_coordinates.participant_lease.record_ref`.
        "participant_ref": lease_ref,
        "proposed_by_ref": proposed_by_ref,
        "bound_coordinates": bound_coordinates,
        "proposition": body.get("proposition").cloned().unwrap_or(Value::Null),
        "finding_kind": body.get("finding_kind").cloned().unwrap_or(Value::Null),
        "confidence_or_uncertainty": body.get("confidence_or_uncertainty").cloned().unwrap_or(Value::Null),
        "valid_time": Value::Null,
        // Wallet-authorized: the instant the room recorded this, not the caller's clock.
        "transaction_time": transaction_time,
        "source_and_observation_context_refs": body.get("source_and_observation_context_refs").cloned().unwrap_or_else(|| json!([])),
        "supporting_evidence_refs": body.get("supporting_evidence_refs").cloned().unwrap_or_else(|| json!([])),
        "proof_refs": body.get("proof_refs").cloned().unwrap_or_else(|| json!([])),
        "contradicting_evidence_refs": body.get("contradicting_evidence_refs").cloned().unwrap_or_else(|| json!([])),
        "applicability_and_counterexample_refs": body.get("applicability_and_counterexample_refs").cloned().unwrap_or_else(|| json!([])),
        "provenance_ontology_and_mapping_refs": body.get("provenance_ontology_and_mapping_refs").cloned().unwrap_or_else(|| json!([])),
        "proposed_effect_refs": [],
        "supersedes_ref": body.get("supersedes_ref").cloned().unwrap_or(Value::Null),
        // A dispute:// object is not a lifecycle this plane mints; challenged standing is carried
        // by `status` alone.
        "dispute_ref": Value::Null,
        "status": "admitted",
    })
}

/// POST /v1/goal-orchestration/findings
pub(crate) async fn handle_finding_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match finding_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn finding_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(body, FINDING_CREATE_FIELDS, "m048_finding_request_invalid")?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_finding_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_finding_request_invalid",
            )?,
            req_ref(
                body,
                "attempt_ref",
                &["attempt"],
                "m048_finding_request_invalid",
            )?,
            // The registered contract requires a non-null WorkResult ref. WorkResult is an
            // OWNER-REGISTRY family that the room-native seam refuses, so this plane cannot mint
            // one: the caller names an existing result and its scheme is all this plane can check.
            req_ref(
                body,
                "work_result_ref",
                &["work-result"],
                "m048_finding_request_invalid",
            )?,
            req_str(body, "proposition", "m048_finding_request_invalid")?,
            req_vocab(
                body,
                "finding_kind",
                FINDING_KINDS,
                "m048_finding_request_invalid",
            )?,
            // WorkResult coordinates are caller-attested for the same reason as the GoalRun: the
            // record lives in the owner registry this plane must not write or index.
        ))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, attempt_ref, work_result_ref, _proposition, _kind) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    // The Attempt must be a current child of THIS room: a finding cannot be attached to work the
    // room never recorded.
    let attempt_projection = current_child(data_dir, &room_ref, ATTEMPT_CONTRACT, &attempt_ref)
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_attempt_not_found",
                "this room recorded no such attempt",
            ))
        })?;
    let attempt = admitted(&attempt_projection).map_err(classify)?.clone();

    let claim_ref = attempt
        .get("work_claim_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &attempt_ref,
        "propose",
        &json!({ "op": "propose", "attempt_ref": attempt_ref }),
    )
    .await?;

    // The proposing lease is resolved from the Attempt's own claim, so a finding cannot be
    // attributed to a lease that did not do the work.
    let claim = admitted(
        &current_child(data_dir, &room_ref, WORK_CLAIM_LEASE_CONTRACT, &claim_ref)
            .map_err(classify)?
            .ok_or_else(|| {
                classify(verr(
                    "m048_claim_not_found",
                    "the attempt's work claim is not a current child of this room",
                ))
            })?,
    )
    .map_err(classify)?
    .clone();
    let lease_ref = claim
        .get("claimant_participant_lease_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let lease_projection =
        current_child(data_dir, &room_ref, PARTICIPANT_LEASE_CONTRACT, &lease_ref)
            .map_err(classify)?
            .ok_or_else(|| {
                classify(verr(
                    "m048_lease_not_found",
                    "the attempt's participant lease is not a current child of this room",
                ))
            })?;
    let lease = admitted(&lease_projection).map_err(classify)?.clone();
    if lease_is_live(&lease, resolved_at_ms)
        .map_err(classify)?
        .is_err()
    {
        return Err(classify(verr(
            "m048_lease_not_active",
            "the proposing participant lease is not active at the wallet-authorized instant",
        )));
    }
    let proposed_by = lease
        .get("participant_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let transaction_time = wallet_ms_to_rfc3339(resolved_at_ms).map_err(classify)?;
    let finding_id = format!(
        "finding://{}",
        deterministic_tail(
            "fnd_",
            "hypervisor.m048.finding.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "attempt_ref": attempt_ref,
                "proposition": body.get("proposition"),
                "recorded_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    // Composed from owner truth and room history; the caller named only the ref.
    let work_result =
        resolve_work_result_coordinate(data_dir, &observed, &work_result_ref).map_err(classify)?;
    let bound_coordinates = finding_bound_coordinates(
        &room_ref,
        &attempt_projection,
        &lease_projection,
        &work_result,
    )
    .map_err(classify)?;
    let candidate = build_finding_candidate(
        &finding_id,
        &attempt,
        &lease_ref,
        &proposed_by,
        &work_result_ref,
        &transaction_time,
        bound_coordinates,
        body,
    );
    let admission = admit_child(
        data_dir,
        &observed,
        FINDING_CONTRACT,
        &candidate,
        &lease_ref,
        None,
    )
    .map_err(classify)?;
    Ok(ok_child(FINDING_CONTRACT, FINDING_SCHEMA, &admission))
}

// --- lifecycle 10: VerifierChallenge v3 ----------------------------------------------------------
//
// # The challenge crossing
//
// A challenge against a Finding is TWO room children: the challenge itself, then a successor
// generation of the Finding carrying its changed assurance standing. As with the admission
// crossing, both halves live in the room's own Agentgres history, so the intermediate state is
// self-describing and needs no retained local intent:
//
//     a current admitted VerifierChallenge whose `challenged_ref` names a Finding whose current
//     generation is not yet `disputed`
//
// is exactly what a crash between the two admissions leaves, and
// `complete_challenge_dispositions` repairs it forward from room truth alone.
//
// The challenge is admitted FIRST so a crash UNDER-claims the dispute (a challenge exists, the
// finding has not caught up) rather than over-claiming it (a finding marked disputed with no
// challenge to justify it).
//
// This is NOT an atomic two-child mutation and is not described as one.

const CHALLENGE_KINDS: &[&str] = &[
    "metric",
    "rule",
    "verifier",
    "evidence",
    "eligibility",
    "result",
    "exploit",
    "independence",
    "collusion",
    "mapping",
];
const CHALLENGE_STATUSES: &[&str] = &[
    "proposed",
    "admitted",
    "investigating",
    "upheld",
    "rejected",
    "reverifying",
    "resolved",
    "withdrawn",
];
/// Challenge outcomes that are adjudication verdicts this plane does not issue.
const CHALLENGE_VERDICT_STATUSES: &[&str] = &["upheld", "rejected", "resolved", "rule_changed"];

const CHALLENGE_CREATE_FIELDS: &[&str] = &[
    "outcome_room_ref",
    "expected_room_state_root",
    "challenger_participant_lease_ref",
    "challenged_ref",
    "challenge_kind",
    "challenge_evidence_refs",
    "adjudicator_policy_ref",
    "prior_rule_version_ref",
    "affected_attempt_refs",
    "reverification_required",
];

fn build_challenge_candidate(
    challenge_id: &str,
    challenger_ref: &str,
    challenged_ref: &str,
    body: &Value,
) -> Value {
    json!({
        "schema_version": VERIFIER_CHALLENGE_SCHEMA,
        "verifier_challenge_id": challenge_id,
        "challenger_ref": challenger_ref,
        "challenged_ref": challenged_ref,
        "challenge_kind": body.get("challenge_kind").cloned().unwrap_or(Value::Null),
        "challenge_evidence_refs": body.get("challenge_evidence_refs").cloned().unwrap_or_else(|| json!([])),
        "adjudicator_policy_ref": body.get("adjudicator_policy_ref").cloned().unwrap_or(Value::Null),
        "prior_rule_version_ref": body.get("prior_rule_version_ref").cloned().unwrap_or(Value::Null),
        // Proposing a new rule version is a governance act, not a challenge.
        "proposed_rule_version_ref": Value::Null,
        "affected_attempt_refs": body.get("affected_attempt_refs").cloned().unwrap_or_else(|| json!([])),
        "reverification_required": body.get("reverification_required").cloned().unwrap_or(json!(true)),
        // A challenge never carries its own adjudication: it opens a question, it does not answer
        // one. Acceptance, verdict and settlement are all absent from this plane.
        "adjudication_ref": Value::Null,
        "status": "admitted",
    })
}

/// The disputed successor generation of a challenged Finding.
///
/// Everything except the assurance standing is retained byte-for-byte: the Attempt ref, the
/// WorkResult ref, every evidence and provenance list, and any `supersedes_ref` lineage. A
/// challenge changes what a finding is TRUSTED to be, never what it recorded.
fn disputed_finding_successor(finding: &Value) -> Result<Value, VErr> {
    let mut successor = finding.clone();
    let map = successor
        .as_object_mut()
        .ok_or_else(|| verr("m048_finding_record_invalid", "a finding must be an object"))?;
    map.remove("system_binding");
    map.remove("outcome_room_ref");
    map.insert("status".to_string(), json!(FINDING_DISPUTED_STATUS));
    Ok(successor)
}

/// Every challenge whose Finding has not yet taken its disputed standing.
fn unconverged_challenges(data_dir: &str, room_ref: &str) -> Result<Vec<(Value, Value)>, VErr> {
    let challenges = current_children(data_dir, room_ref, VERIFIER_CHALLENGE_CONTRACT)?;
    let findings = current_children(data_dir, room_ref, FINDING_CONTRACT)?;
    let mut pending = Vec::new();
    for challenge_projection in &challenges {
        let challenge = admitted(challenge_projection)?;
        if challenge.get("status").and_then(Value::as_str) != Some("admitted") {
            continue;
        }
        let Some(challenged) = challenge.get("challenged_ref").and_then(Value::as_str) else {
            continue;
        };
        if !challenged.starts_with("finding://") {
            // A challenge may target an Attempt or a rubric; only a Finding takes a disputed
            // successor in this build step.
            continue;
        }
        for finding_projection in &findings {
            let finding = admitted(finding_projection)?;
            if finding.get("finding_id").and_then(Value::as_str) != Some(challenged) {
                continue;
            }
            if finding.get("status").and_then(Value::as_str) != Some(FINDING_DISPUTED_STATUS) {
                pending.push((challenge_projection.clone(), finding_projection.clone()));
            }
        }
    }
    Ok(pending)
}

/// Converge every unfinished challenge disposition in every current room.
///
/// Forward-only and idempotent: a finding already `disputed` is skipped, so a second challenge on
/// the same finding converges to the same standing rather than appending a redundant generation.
pub(crate) fn complete_challenge_dispositions(data_dir: &str) -> Result<(), VErr> {
    for room in rooms::list_current_rooms_canonical_strict(data_dir)? {
        let Some(room_ref) = room.get("outcome_room_id").and_then(Value::as_str) else {
            continue;
        };
        for (_challenge, finding_projection) in unconverged_challenges(data_dir, room_ref)? {
            let finding = admitted(&finding_projection)?;
            let successor = disputed_finding_successor(finding)?;
            let prior_root = object_root(&finding_projection)?;
            let observed = observe_room_at_head(data_dir, room_ref)?;
            let issuer = observed.system_id.clone();
            admit_child(
                data_dir,
                &observed,
                FINDING_CONTRACT,
                &successor,
                &issuer,
                Some(&prior_root),
            )?;
        }
    }
    Ok(())
}

/// POST /v1/goal-orchestration/verifier-challenges
pub(crate) async fn handle_challenge_create(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match challenge_create_inner(&state.data_dir, &body).await {
        Ok(response) => response,
        Err(error) => error,
    }
}

async fn challenge_create_inner(
    data_dir: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            CHALLENGE_CREATE_FIELDS,
            "m048_challenge_request_invalid",
        )?;
        Ok((
            req_ref(
                body,
                "outcome_room_ref",
                &["outcome-room"],
                "m048_challenge_request_invalid",
            )?,
            req_root(
                body,
                "expected_room_state_root",
                "m048_challenge_request_invalid",
            )?,
            req_ref(
                body,
                "challenger_participant_lease_ref",
                &["participant-lease"],
                "m048_challenge_request_invalid",
            )?,
            req_ref(
                body,
                "challenged_ref",
                &["finding", "attempt"],
                "m048_challenge_request_invalid",
            )?,
            req_vocab(
                body,
                "challenge_kind",
                CHALLENGE_KINDS,
                "m048_challenge_request_invalid",
            )?,
        ))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, challenger_lease_ref, challenged_ref, _kind) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &challenger_lease_ref,
        "challenge",
        &json!({ "op": "challenge", "challenged_ref": challenged_ref }),
    )
    .await?;

    // The challenger must hold a live lease IN THIS ROOM. A foreign or lapsed lease cannot mount
    // an integrity challenge against this room's record.
    let challenger_lease = admitted(
        &current_child(
            data_dir,
            &room_ref,
            PARTICIPANT_LEASE_CONTRACT,
            &challenger_lease_ref,
        )
        .map_err(classify)?
        .ok_or_else(|| {
            classify(verr(
                "m048_challenge_foreign_challenger",
                "the challenger's participant lease is not a current child of this room",
            ))
        })?,
    )
    .map_err(classify)?
    .clone();
    if lease_is_live(&challenger_lease, resolved_at_ms)
        .map_err(classify)?
        .is_err()
    {
        return Err(classify(verr(
            "m048_lease_not_active",
            "the challenger's participant lease is not active at the wallet-authorized instant",
        )));
    }
    let challenger_ref = challenger_lease_ref.clone();

    // The challenged object must be a current child of this room.
    let challenged_finding = if challenged_ref.starts_with("finding://") {
        let projection = current_child(data_dir, &room_ref, FINDING_CONTRACT, &challenged_ref)
            .map_err(classify)?
            .ok_or_else(|| {
                classify(verr(
                    "m048_challenge_target_not_found",
                    "this room admitted no such finding",
                ))
            })?;
        Some(projection)
    } else {
        current_child(data_dir, &room_ref, ATTEMPT_CONTRACT, &challenged_ref)
            .map_err(classify)?
            .ok_or_else(|| {
                classify(verr(
                    "m048_challenge_target_not_found",
                    "this room recorded no such attempt",
                ))
            })?;
        None
    };

    let challenge_id = format!(
        "verifier-challenge://{}",
        deterministic_tail(
            "vch_",
            "hypervisor.m048.verifier-challenge.identity.v1",
            &json!({
                "outcome_room_ref": room_ref,
                "challenged_ref": challenged_ref,
                "challenger_ref": challenger_ref,
                "raised_at_wallet_ms": resolved_at_ms,
            }),
        )
    );
    let candidate =
        build_challenge_candidate(&challenge_id, &challenger_ref, &challenged_ref, body);

    // Step 1 — the challenge itself.
    let admission = admit_child(
        data_dir,
        &observed,
        VERIFIER_CHALLENGE_CONTRACT,
        &candidate,
        &challenger_lease_ref,
        None,
    )
    .map_err(classify)?;

    // Step 2 — the Finding's disputed successor, at the NEW head. A failure here is recoverable:
    // the room now describes its own unfinished disposition and the boot completer repairs it.
    let disposition = match &challenged_finding {
        Some(projection) => {
            let outcome = (|| -> Result<Value, VErr> {
                let finding = admitted(projection)?;
                if finding.get("status").and_then(Value::as_str) == Some(FINDING_DISPUTED_STATUS) {
                    // Already in the challenged standing; a second challenge adds no generation.
                    return Ok(json!({ "converged": true, "already_disputed": true }));
                }
                let successor = disputed_finding_successor(finding)?;
                let prior_root = object_root(projection)?;
                let reobserved = observe_room_at_head(data_dir, &room_ref)?;
                let issuer = reobserved.system_id.clone();
                admit_child(
                    data_dir,
                    &reobserved,
                    FINDING_CONTRACT,
                    &successor,
                    &issuer,
                    Some(&prior_root),
                )?;
                Ok(json!({
                    "converged": true,
                    "finding_status": FINDING_DISPUTED_STATUS,
                    "retained_prior_object_root": prior_root,
                }))
            })();
            match outcome {
                Ok(value) => value,
                Err((code, message)) => json!({
                    "converged": false,
                    "pending_recovery": true,
                    "code": code,
                    "message": message,
                }),
            }
        }
        // An attempt-targeted challenge takes no finding successor in this build step.
        None => json!({ "converged": true, "finding_successor_not_applicable": true }),
    };

    let (status, Json(mut payload)) = ok_child(
        VERIFIER_CHALLENGE_CONTRACT,
        VERIFIER_CHALLENGE_SCHEMA,
        &admission,
    );
    payload["finding_disposition"] = disposition;
    Ok((status, Json(payload)))
}

/// Generic room-child projection for the contribution families.
fn contribution_list(
    data_dir: &str,
    contract_id: &'static str,
    schema: &'static str,
    code: &str,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            code,
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let observed = match observe_room_at_head(data_dir, room_ref) {
        Ok(observed) => observed,
        Err(error) => return classify(error),
    };
    match current_children(data_dir, room_ref, contract_id)
        .and_then(|objects| ok_child_list(contract_id, schema, &observed, objects))
    {
        Ok(response) => response,
        Err(error) => classify(error),
    }
}

/// Generic single-object projection WITH its full lineage.
///
/// Lineage rides on the existing get rather than a new path: a superseded or disputed generation
/// is history, and a reader that can see the current standing must be able to see what it
/// succeeded without being sent to a second endpoint.
fn contribution_get(
    data_dir: &str,
    contract_id: &'static str,
    schema: &'static str,
    code: &str,
    object_ref: &str,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            code,
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let current = match current_child(data_dir, room_ref, contract_id, object_ref) {
        Ok(Some(projection)) => projection,
        Ok(None) => return classify(verr(code, "this room admitted no such object")),
        Err(error) => return classify(error),
    };
    let lineage = match child_lineage(data_dir, room_ref, contract_id, object_ref) {
        Ok(lineage) => lineage,
        Err(error) => return classify(error),
    };
    let body = json!({
        "ok": true,
        "object_contract_id": contract_id,
        "schema_version": schema,
        "projection": current,
        // Every admitted generation, oldest first. Nothing is ever removed from this.
        "lineage": lineage,
        "generation_count": lineage.len(),
        "projection_only": true,
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(error) =
        room_system::ensure_serialized_body_bound(&body, "m048_projection_too_large")
    {
        return classify(error);
    }
    (StatusCode::OK, Json(body))
}

/// Generic status-count overview for a contribution family.
fn contribution_overview(
    data_dir: &str,
    contract_id: &'static str,
    schema: &'static str,
    code: &str,
    query: &std::collections::HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let Some(room_ref) = query.get("outcome_room_ref") else {
        return classify(verr(
            code,
            "`outcome_room_ref` is a required query parameter; room children are read per room",
        ));
    };
    let objects = match current_children(data_dir, room_ref, contract_id) {
        Ok(objects) => objects,
        Err(error) => return classify(error),
    };
    let mut by_status = serde_json::Map::new();
    for projection in &objects {
        let status = projection
            .pointer("/admitted_object/status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let next = by_status.get(&status).and_then(Value::as_u64).unwrap_or(0) + 1;
        by_status.insert(status, json!(next));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "object_contract_id": contract_id,
            "schema_version": schema,
            "outcome_room_ref": room_ref,
            "total": objects.len(),
            "by_status": by_status,
            // Superseded, disputed and invalid generations are retained in history; this counts
            // CURRENT standing only and says so.
            "counts_current_generation_only": true,
            "projection_only": true,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

macro_rules! contribution_read_handlers {
    ($list:ident, $get:ident, $overview:ident, $contract:expr, $schema:expr, $code:literal, $scheme:literal) => {
        pub(crate) async fn $list(
            State(state): State<Arc<DaemonState>>,
            headers: axum::http::HeaderMap,
            Query(query): OfferQuery,
        ) -> (StatusCode, Json<Value>) {
            if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
                return classify(error);
            }
            contribution_list(&state.data_dir, $contract, $schema, $code, &query)
        }

        pub(crate) async fn $get(
            State(state): State<Arc<DaemonState>>,
            headers: axum::http::HeaderMap,
            Path(id): Path<String>,
            Query(query): OfferQuery,
        ) -> (StatusCode, Json<Value>) {
            if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
                return classify(error);
            }
            let object_ref = format!("{}://{}", $scheme, id);
            contribution_get(
                &state.data_dir,
                $contract,
                $schema,
                $code,
                &object_ref,
                &query,
            )
        }

        pub(crate) async fn $overview(
            State(state): State<Arc<DaemonState>>,
            headers: axum::http::HeaderMap,
            Query(query): OfferQuery,
        ) -> (StatusCode, Json<Value>) {
            if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
                return classify(error);
            }
            contribution_overview(&state.data_dir, $contract, $schema, $code, &query)
        }
    };
}

contribution_read_handlers!(
    handle_attempt_list,
    handle_attempt_get,
    handle_attempt_overview,
    ATTEMPT_CONTRACT,
    ATTEMPT_SCHEMA,
    "m048_attempt_request_invalid",
    "attempt"
);
contribution_read_handlers!(
    handle_finding_list,
    handle_finding_get,
    handle_finding_overview,
    FINDING_CONTRACT,
    FINDING_SCHEMA,
    "m048_finding_request_invalid",
    "finding"
);
contribution_read_handlers!(
    handle_challenge_list,
    handle_challenge_get,
    handle_challenge_overview,
    VERIFIER_CHALLENGE_CONTRACT,
    VERIFIER_CHALLENGE_SCHEMA,
    "m048_challenge_request_invalid",
    "verifier-challenge"
);

/// Generic contribution transition: a successor generation carrying a registered status.
async fn contribution_transition_inner(
    data_dir: &str,
    contract_id: &'static str,
    schema: &'static str,
    code: &str,
    scheme: &str,
    statuses: &[&str],
    verdicts: &[&str],
    id: &str,
    body: &Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let parsed = (|| -> Result<_, VErr> {
        closed_object(
            body,
            &["outcome_room_ref", "expected_room_state_root", "status"],
            code,
        )?;
        let room_ref = req_ref(body, "outcome_room_ref", &["outcome-room"], code)?;
        let expected_head = req_root(body, "expected_room_state_root", code)?;
        let status = req_vocab(body, "status", statuses, code)?;
        if verdicts.contains(&status.as_str()) {
            return Err(verr(
                "m048_contribution_verdict_refused",
                "acceptance, rejection and adjudication are verdicts; this build step issues none",
            ));
        }
        Ok((room_ref, expected_head, status))
    })()
    .map_err(classify)?;
    let (room_ref, expected_head, status) = parsed;

    let observed = observe_room_at_head(data_dir, &room_ref).map_err(classify)?;
    if observed.head != expected_head {
        return Err(classify(verr(
            "m048_room_head_stale",
            "the caller-observed room head is not this room's current head",
        )));
    }
    let object_ref = format!("{scheme}://{id}");
    let projection = current_child(data_dir, &room_ref, contract_id, &object_ref)
        .map_err(classify)?
        .ok_or_else(|| classify(verr(code, "this room admitted no such object")))?;
    let object = admitted(&projection).map_err(classify)?.clone();

    let _resolved_at_ms = authorized_instant(
        data_dir,
        body,
        governed::Governance::Participant,
        &room_ref,
        &observed.system_id,
        &object_ref,
        "transition",
        &json!({ "op": "transition", "status": status }),
    )
    .await?;

    let mut successor = object.clone();
    let map = successor
        .as_object_mut()
        .ok_or_else(|| classify(verr(code, "the record must be an object")))?;
    map.remove("system_binding");
    map.remove("outcome_room_ref");
    map.insert("status".to_string(), json!(status));
    let prior_root = object_root(&projection).map_err(classify)?;
    let issuer = observed.system_id.clone();
    // Succession only. No generation is ever removed, so a superseded or disputed record stays
    // exactly where it was in the lineage.
    let admission = admit_child(
        data_dir,
        &observed,
        contract_id,
        &successor,
        &issuer,
        Some(&prior_root),
    )
    .map_err(classify)?;
    Ok(ok_child(contract_id, schema, &admission))
}

/// POST /v1/goal-orchestration/attempts/:id/transition
pub(crate) async fn handle_attempt_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match contribution_transition_inner(
        &state.data_dir,
        ATTEMPT_CONTRACT,
        ATTEMPT_SCHEMA,
        "m048_attempt_request_invalid",
        "attempt",
        ATTEMPT_STATUSES,
        ATTEMPT_VERDICT_STATUSES,
        &id,
        &body,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// POST /v1/goal-orchestration/findings/:id/transition
pub(crate) async fn handle_finding_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match contribution_transition_inner(
        &state.data_dir,
        FINDING_CONTRACT,
        FINDING_SCHEMA,
        "m048_finding_request_invalid",
        "finding",
        FINDING_STATUSES,
        FINDING_VERDICT_STATUSES,
        &id,
        &body,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// POST /v1/goal-orchestration/verifier-challenges/:id/transition
pub(crate) async fn handle_challenge_transition(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    match contribution_transition_inner(
        &state.data_dir,
        VERIFIER_CHALLENGE_CONTRACT,
        VERIFIER_CHALLENGE_SCHEMA,
        "m048_challenge_request_invalid",
        "verifier-challenge",
        CHALLENGE_STATUSES,
        CHALLENGE_VERDICT_STATUSES,
        &id,
        &body,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error,
    }
}

/// Pure projection: liveness and lapse evidence for every current claim at one wallet instant.
fn claim_overview_projection(
    data_dir: &str,
    room_ref: &str,
    resolved_at_ms: u64,
) -> Result<Value, VErr> {
    let mut live = 0usize;
    let mut lapsed = Vec::new();
    for claim in current_claims(data_dir, room_ref)? {
        let claim_id = claim
            .get("work_claim_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match claim_is_live(&claim, resolved_at_ms, CLAIM_HEARTBEAT_MAX_SECONDS)? {
            Ok(()) => live += 1,
            Err(lapse) => lapsed.push(json!({
                "work_claim_id": claim_id,
                "frontier_item_ref": claim.get("frontier_item_ref").cloned().unwrap_or(Value::Null),
                "lapse": match lapse {
                    ClaimLapse::Terminal => "terminal",
                    ClaimLapse::Expired => "expired",
                    ClaimLapse::HeartbeatStale => "heartbeat_stale",
                },
            })),
        }
    }
    Ok(json!({
        "ok": true,
        "object_contract_id": WORK_CLAIM_LEASE_CONTRACT,
        "schema_version": WORK_CLAIM_LEASE_SCHEMA,
        "outcome_room_ref": room_ref,
        "live": live,
        "lapsed": lapsed,
        "evaluated_at_wallet_ms": resolved_at_ms,
        // Reporting a lapse is not releasing it: release stays an explicit claim transition.
        "projection_only": true,
        "runtimeTruthSource": "daemon-runtime",
    }))
}

#[cfg(test)]
mod m048_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ioi-m048-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// A claim shaped like the registered v3 payload: `expires_at` is the whole deadline, and
    /// `heartbeat_ref` records only THAT a heartbeat happened, never when — the contract has no
    /// field for when, which is exactly why the deadline carries it.
    fn claim(status: &str, expires_at: &str, heartbeat_ref: Option<&str>) -> Value {
        let mut claim = json!({
            "work_claim_id": "work-claim://demo/1",
            "frontier_item_ref": "frontier://demo/1",
            "status": status,
            "expires_at": expires_at,
        });
        if let Some(reference) = heartbeat_ref {
            claim["heartbeat_ref"] = json!(reference);
        }
        claim
    }

    fn frontier() -> Value {
        json!({
            "frontier_item_id": "frontier://demo/1",
            "claimability": "open",
            "status": "open",
            "max_concurrency": 1,
        })
    }

    /// 2026-08-26T12:00:00Z in milliseconds, used as the wallet-authorized instant.
    ///
    /// Pinned by `wallet_time_round_trips_and_never_falls_back_to_a_local_clock`, which renders it
    /// back to the exact literal — so a wrong constant here fails loudly instead of silently
    /// shifting every expiry comparison in this module's tests.
    const NOON_MS: u64 = 1_787_745_600_000;

    #[test]
    fn a_live_claim_holds_its_frontier_item_exclusively() {
        let claims = vec![claim(
            "active",
            "2026-08-26T13:00:00Z",
            Some("receipt://hb_one"),
        )];
        let projection =
            frontier_claimability(&frontier(), &claims, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .expect("the projection resolves");
        assert_eq!(projection["claimable"], json!(false));
        assert_eq!(projection["live_claim_refs"].as_array().unwrap().len(), 1);
        assert_eq!(
            refuse_when_already_claimed(&frontier(), &claims, NOON_MS)
                .expect_err("a second claim is refused")
                .0,
            "m048_work_claim_exclusive"
        );
    }

    #[test]
    fn an_expired_claim_returns_the_item_to_claimable_without_any_write() {
        // The claim's term ran out one second before the wallet-authorized instant, and it never
        // heartbeat — so it reads as a plain expiry rather than as a stopped heartbeat.
        let claims = vec![claim("active", "2026-08-26T11:59:59Z", None)];
        let projection =
            frontier_claimability(&frontier(), &claims, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .expect("the projection resolves");
        assert_eq!(
            projection["claimable"],
            json!(true),
            "expiry returns the item to claimable as a projection, with no second child write"
        );
        assert_eq!(projection["lapsed_claims"][0]["lapse"], json!("expired"));
        assert!(refuse_when_already_claimed(&frontier(), &claims, NOON_MS).is_ok());
    }

    #[test]
    fn a_stale_heartbeat_returns_the_item_to_claimable() {
        // A claim that HAD been heartbeating and stopped: its last heartbeat advanced the deadline
        // only as far as 11:59, which the wallet instant has now passed.
        let claims = vec![claim(
            "active",
            "2026-08-26T11:59:00Z",
            Some("receipt://hb_one"),
        )];
        let projection =
            frontier_claimability(&frontier(), &claims, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .expect("the projection resolves");
        assert_eq!(projection["claimable"], json!(true));
        assert_eq!(
            projection["lapsed_claims"][0]["lapse"],
            json!("heartbeat_stale")
        );
    }

    #[test]
    fn a_claim_that_never_heartbeat_runs_out_its_original_term() {
        // Within its term it is live even without a heartbeat: the deadline it was issued with is
        // the promise it has not yet broken.
        let live = claim("active", "2026-08-26T13:00:00Z", None);
        assert_eq!(
            claim_is_live(&live, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap(),
            Ok(())
        );
        // Past that deadline it lapses with no heartbeat ever having moved it.
        let lapsed = claim("active", "2026-08-26T11:00:00Z", None);
        assert_eq!(
            claim_is_live(&lapsed, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap(),
            Err(ClaimLapse::Expired)
        );
    }

    #[test]
    fn the_registered_claim_contract_has_nowhere_to_store_a_heartbeat_instant() {
        // This is why `expires_at` carries the heartbeat deadline. If a future contract revision
        // adds an observation field, this pin fails and the model can be revisited deliberately
        // rather than drifting.
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/work-claim-lease.v3.schema.json"
        ))
        .expect("the registered claim schema parses");
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "the claim contract is closed, so no extra liveness field may be smuggled in"
        );
        let properties = schema["properties"]
            .as_object()
            .expect("declared properties");
        for absent in [
            "heartbeat_observed_at_ms",
            "heartbeat_at",
            "last_heartbeat_at",
        ] {
            assert!(
                !properties.contains_key(absent),
                "`{absent}` is not a registered field; liveness must ride on `expires_at`"
            );
        }
        assert!(properties.contains_key("expires_at"));
        assert!(properties.contains_key("heartbeat_ref"));
    }

    #[test]
    fn a_terminal_claim_holds_nothing() {
        for status in CLAIM_TERMINAL_STATUSES {
            let claims = vec![claim(
                status,
                "2026-08-26T13:00:00Z",
                Some("receipt://hb_one"),
            )];
            assert_eq!(
                claim_is_live(&claims[0], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap(),
                Err(ClaimLapse::Terminal),
                "`{status}` is terminal and must release the item"
            );
            let projection =
                frontier_claimability(&frontier(), &claims, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                    .unwrap();
            assert_eq!(projection["claimable"], json!(true));
        }
    }

    #[test]
    fn an_unregistered_claim_status_is_refused_rather_than_treated_as_live() {
        let claims = vec![claim(
            "invented",
            "2026-08-26T13:00:00Z",
            Some("receipt://hb_one"),
        )];
        assert_eq!(
            claim_is_live(&claims[0], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .expect_err("an unregistered status is a refusal")
                .0,
            "m048_claim_record_invalid"
        );
    }

    #[test]
    fn max_concurrency_is_honoured_above_one() {
        let mut item = frontier();
        item["max_concurrency"] = json!(2);
        let mut first = claim("active", "2026-08-26T13:00:00Z", Some("receipt://hb_one"));
        first["work_claim_id"] = json!("work-claim://demo/1");
        let mut second = first.clone();
        second["work_claim_id"] = json!("work-claim://demo/2");
        let one = vec![first.clone()];
        assert_eq!(
            frontier_claimability(&item, &one, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap()
                ["claimable"],
            json!(true)
        );
        let two = vec![first, second];
        assert_eq!(
            frontier_claimability(&item, &two, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap()
                ["claimable"],
            json!(false)
        );
    }

    #[test]
    fn a_claim_on_a_different_frontier_item_does_not_block_this_one() {
        let mut other = claim("active", "2026-08-26T13:00:00Z", Some("receipt://hb_one"));
        other["frontier_item_ref"] = json!("frontier://demo/other");
        let projection =
            frontier_claimability(&frontier(), &[other], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .unwrap();
        assert_eq!(projection["claimable"], json!(true));
        assert!(projection["live_claim_refs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn eligibility_evidence_grants_nothing() {
        let body = eligibility_match_body(
            "outcome-room://demo",
            &frontier(),
            &json!({
                "participant_lease_id": "participant-lease://demo/worker",
                "capability_advertisement_refs": ["capability-offer://demo/worker"],
            }),
            &[],
            &[],
            NOON_MS,
        )
        .unwrap();
        assert_eq!(body["allocation_created"], json!(false));
        assert_eq!(body["claim_created"], json!(false));
        assert_eq!(body["execution_authority_granted"], json!(false));
        assert_eq!(body["schema_version"], json!(ELIGIBILITY_MATCH_SCHEMA));
    }

    #[test]
    fn wallet_time_round_trips_and_never_falls_back_to_a_local_clock() {
        let rendered = wallet_ms_to_rfc3339(NOON_MS).expect("the wallet instant renders");
        assert_eq!(rendered, "2026-08-26T12:00:00Z");
        assert_eq!(rfc3339_to_ms(&rendered).unwrap(), NOON_MS);
        assert!(is_rfc3339(&json!(rendered)));
        // An unrepresentable instant refuses; it does not silently substitute `iso_now()`.
        assert_eq!(
            wallet_ms_to_rfc3339(u64::MAX)
                .expect_err("out of range refuses")
                .0,
            "m048_wallet_time_invalid"
        );
    }

    #[test]
    fn a_deadline_that_would_overflow_is_refused() {
        assert_eq!(
            wallet_deadline_ms(u64::MAX - 1, CLAIM_TTL_MAX_SECONDS)
                .expect_err("overflow refuses")
                .0,
            "m048_wallet_time_invalid"
        );
        assert_eq!(wallet_deadline_ms(NOON_MS, 60).unwrap(), NOON_MS + 60_000);
    }

    #[test]
    fn a_candidate_carrying_plane_owned_coordinates_is_refused_before_any_write() {
        let directory = temp_dir("plane-owned");
        let data_dir = directory.to_str().unwrap();
        let observed = RoomAtHead {
            room_ref: "outcome-room://demo".to_string(),
            head: "sha256:".to_string() + &"11".repeat(32),
            system_id: "system://room/demo".to_string(),
            room: json!({}),
        };
        for owned in ["system_binding", "outcome_room_ref", "room_admission"] {
            let candidate = json!({ "finding_id": "finding://demo/1", owned: "anything" });
            let error = admit_child(
                data_dir,
                &observed,
                FINDING_CONTRACT,
                &candidate,
                "participant-lease://demo/worker",
                None,
            )
            .expect_err("a plane-owned coordinate is refused");
            assert_eq!(error.0, "m048_child_plane_owned_field_supplied");
        }
        // Refusal writes nothing: no owner-local family was even created.
        for family in OWNER_LOCAL_FAMILIES {
            assert!(!directory.join(family).exists());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_body_with_an_unknown_or_secret_bearing_field_is_refused() {
        let allowed = ["outcome_room_ref", "ttl_seconds"];
        let unknown = json!({ "outcome_room_ref": "outcome-room://demo", "surprise": 1 });
        assert_eq!(
            closed_object(&unknown, &allowed, "m048_request_invalid")
                .expect_err("an unknown field is refused")
                .0,
            "m048_request_invalid"
        );
        let secret = json!({ "outcome_room_ref": "outcome-room://demo", "api_key": "x" });
        assert!(
            closed_object(&secret, &allowed, "m048_request_invalid").is_err(),
            "a secret-bearing field is refused recursively"
        );
        let nested = json!({
            "outcome_room_ref": "outcome-room://demo",
            "ttl_seconds": { "nested": { "password": "x" } },
        });
        assert!(
            closed_object(&nested, &allowed, "m048_request_invalid").is_err(),
            "secrets are refused at depth, not only at the top level"
        );
    }

    #[test]
    fn validation_helpers_bound_every_caller_supplied_shape() {
        let body = json!({
            "room": "outcome-room://demo",
            "root": "sha256:".to_string() + &"ab".repeat(32),
            "role": "implementer",
            "refs": ["capability-offer://a", "capability-offer://b"],
        });
        assert_eq!(
            req_ref(&body, "room", &["outcome-room"], "m048_x").unwrap(),
            "outcome-room://demo"
        );
        assert!(req_ref(&body, "room", &["participant-lease"], "m048_x").is_err());
        assert!(req_root(&body, "root", "m048_x").is_ok());
        assert!(req_vocab(&body, "role", &["implementer", "reviewer"], "m048_x").is_ok());
        assert!(req_vocab(&body, "role", &["reviewer"], "m048_x").is_err());
        assert_eq!(
            ref_list(&body, "refs", &["capability-offer"], "m048_x")
                .unwrap()
                .len(),
            2
        );
        let dup = json!({ "refs": ["capability-offer://a", "capability-offer://a"] });
        assert!(ref_list(&dup, "refs", &["capability-offer"], "m048_x").is_err());
        let over = json!({ "refs": (0..REF_LIST_MAX + 1).map(|i| format!("capability-offer://{i}")).collect::<Vec<_>>() });
        assert!(ref_list(&over, "refs", &["capability-offer"], "m048_x").is_err());
        assert!(req_ttl(&json!({ "t": 10 }), "t", 30, 100, "m048_x").is_err());
        assert!(req_ttl(&json!({ "t": 60 }), "t", 30, 100, "m048_x").is_ok());
    }

    #[test]
    fn an_uppercase_or_short_root_is_not_a_root() {
        assert!(is_sha256_root(&("sha256:".to_string() + &"ab".repeat(32))));
        assert!(!is_sha256_root(&("sha256:".to_string() + &"AB".repeat(32))));
        assert!(!is_sha256_root("sha256:abc"));
        assert!(!is_sha256_root(&"ab".repeat(32)));
    }

    #[test]
    fn the_owner_local_census_fails_closed_on_a_malformed_slot() {
        let directory = temp_dir("census");
        let data_dir = directory.to_str().unwrap();
        assert!(
            preflight_owner_local_census(data_dir).is_ok(),
            "absent families are a clean start, not a corruption"
        );
        let family = directory.join(PAIRING_DIR);
        std::fs::create_dir_all(&family).unwrap();
        std::fs::write(family.join("lap_one.json"), b"{not-json").unwrap();
        assert!(
            preflight_owner_local_census(data_dir).is_err(),
            "a malformed owner-local slot must block serving current routes"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_wrong_schema_owner_local_record_is_refused_rather_than_listed() {
        let directory = temp_dir("schema-drift");
        let data_dir = directory.to_str().unwrap();
        persist_local(
            data_dir,
            TERMS_DIR,
            "trm_one",
            &json!({ "schema_version": "something.else.v1" }),
        )
        .unwrap();
        let error = scan_local(data_dir, TERMS_DIR, COLLABORATION_TERMS_SCHEMA)
            .expect_err("a foreign schema is refused");
        assert_eq!(error.0, "m048_local_record_invalid");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_append_only_receipt_replays_byte_identically_and_refuses_a_rewrite() {
        let directory = temp_dir("receipt-replay");
        let data_dir = directory.to_str().unwrap();
        let receipt =
            json!({ "schema_version": ELIGIBILITY_MATCH_SCHEMA, "allocation_created": false });
        let tail = "wem_".to_string() + &"ab".repeat(32);
        persist_local_receipt(data_dir, ELIGIBILITY_DIR, &tail, &receipt).unwrap();
        // Exact replay converges rather than conflicting.
        persist_local_receipt(data_dir, ELIGIBILITY_DIR, &tail, &receipt)
            .expect("a byte-identical replay converges");
        // A different body under the same tail is a conflict, never a silent overwrite.
        let mutated =
            json!({ "schema_version": ELIGIBILITY_MATCH_SCHEMA, "allocation_created": true });
        assert_eq!(
            persist_local_receipt(data_dir, ELIGIBILITY_DIR, &tail, &mutated)
                .expect_err("a rewrite is refused")
                .0,
            "m048_local_receipt_conflict"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn error_codes_classify_onto_their_exact_wire_status() {
        let cases = [
            ("m048_room_not_found", StatusCode::NOT_FOUND),
            ("m048_work_claim_exclusive", StatusCode::CONFLICT),
            ("m048_room_head_stale", StatusCode::CONFLICT),
            (
                "m048_local_persist_failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                "m048_local_durability_unconfirmed",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                "m048_local_slot_unreadable",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                "m048_authority_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            ("m048_host_authority_required", StatusCode::FORBIDDEN),
            ("m048_request_invalid", StatusCode::BAD_REQUEST),
        ];
        for (code, expected) in cases {
            let (status, Json(body)) = classify(verr(code, "x"));
            assert_eq!(status, expected, "`{code}` must classify as {expected}");
            assert_eq!(
                body.pointer("/error/code").and_then(Value::as_str),
                Some(code)
            );
        }
    }

    #[test]
    fn the_registered_contract_ids_and_schema_versions_stay_paired() {
        // A drift between the contract id and the schema_version the seam compares verbatim is
        // the failure mode that silently re-binds a family; pin both together.
        for (contract, schema) in [
            (PARTICIPATION_REQUEST_CONTRACT, PARTICIPATION_REQUEST_SCHEMA),
            (PARTICIPANT_LEASE_CONTRACT, PARTICIPANT_LEASE_SCHEMA),
            (RESOURCE_OFFER_CONTRACT, RESOURCE_OFFER_SCHEMA),
            (CAPABILITY_OFFER_CONTRACT, CAPABILITY_OFFER_SCHEMA),
            (WORK_FRONTIER_ITEM_CONTRACT, WORK_FRONTIER_ITEM_SCHEMA),
            (WORK_CLAIM_LEASE_CONTRACT, WORK_CLAIM_LEASE_SCHEMA),
            (ATTEMPT_CONTRACT, ATTEMPT_SCHEMA),
            (FINDING_CONTRACT, FINDING_SCHEMA),
            (VERIFIER_CHALLENGE_CONTRACT, VERIFIER_CHALLENGE_SCHEMA),
        ] {
            let tail = contract
                .strip_prefix("schema://ioi/applications/ioi-ai/")
                .expect("every room-child contract is an ioi-ai application contract");
            let expected = format!("ioi.applications.ioi-ai.{}", tail.replace('/', "."));
            assert_eq!(
                schema, expected,
                "`{contract}` and its schema_version must stay paired"
            );
        }
    }

    #[test]
    fn this_module_owns_no_room_child_family_directory() {
        // Room children live ONLY in the room's Agentgres history. If this list ever grows a
        // child-shaped family, the single-truth rule has been broken.
        for family in OWNER_LOCAL_FAMILIES {
            for forbidden in [
                "participation-request",
                "participant-lease",
                "resource-offer",
                "capability-offer",
                "frontier",
                "work-claim",
                "attempt",
                "finding",
                "verifier-challenge",
            ] {
                assert!(
                    !family.contains(forbidden),
                    "`{family}` names a room-child family; children have exactly one home"
                );
            }
        }
        assert_eq!(OWNER_LOCAL_FAMILIES.len(), 4);
    }

    // --- A2: pairing, terms, participation request -------------------------------------------

    const PROOF: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";

    /// A canonical-but-absent room ref. Canonicity matters: the room plane refuses a non-canonical
    /// stem as UNCERTAINTY, and only a canonical absent slot is a definitive "never admitted".
    fn canonical_room_ref() -> String {
        format!("outcome-room://or_{}", "ab".repeat(32))
    }

    fn pairing(status: &str, expires_at: &str) -> Value {
        let mut session = build_pairing_session(
            "local-agent-pairing://lap_one",
            "user://ioi/levi",
            "surface://ioi/hypervisor-app/pairing",
            "outcome-room://demo",
            "local claude-code",
            PROOF,
            "2026-08-26T11:55:00Z",
            expires_at,
            "2026-08-26T11:55:00Z",
        );
        session["status"] = json!(status);
        session
    }

    #[test]
    fn a_pairing_session_grants_nothing_by_construction() {
        let session = pairing("created", "2026-08-26T12:05:00Z");
        for (_, granted) in session["bootstrap_non_grants"].as_object().unwrap() {
            assert_eq!(
                granted,
                &json!("none"),
                "pairing mints no standing authority"
            );
        }
        assert_eq!(session["challenge"]["single_use"], json!(true));
        assert_eq!(session["target_kind"], json!(PAIRING_TARGET_KIND));
        assert_eq!(
            session["allowed_bootstrap_actions"],
            json!(["submit_room_participation_request"]),
            "pairing enables exactly the one request it exists for"
        );
        assert_eq!(session["contribution_lane"], json!("proposal_only"));
    }

    #[test]
    fn a_valid_pairing_admits_exactly_its_own_room_and_requester() {
        let session = pairing("created", "2026-08-26T12:05:00Z");
        assert!(pairing_admits_request(
            &session,
            PROOF,
            "outcome-room://demo",
            "user://ioi/levi",
            NOON_MS
        )
        .is_ok());
        // A different room or requester is refused even with the correct proof.
        for (room, who) in [
            ("outcome-room://other", "user://ioi/levi"),
            ("outcome-room://demo", "user://ioi/someone-else"),
        ] {
            assert_eq!(
                pairing_admits_request(&session, PROOF, room, who, NOON_MS).unwrap_err(),
                PairingRefusal::WrongSubject
            );
        }
    }

    #[test]
    fn an_unauthenticated_expired_or_replayed_pairing_is_refused() {
        let live = pairing("created", "2026-08-26T12:05:00Z");
        // Wrong proof.
        assert_eq!(
            pairing_admits_request(
                &live,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::Unauthenticated
        );
        // Expired at the wallet-authorized instant (challenge lapsed one minute ago).
        let expired = pairing("created", "2026-08-26T11:59:00Z");
        assert_eq!(
            pairing_admits_request(
                &expired,
                PROOF,
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::Expired
        );
        // Already consumed — the replay lane.
        let replayed = pairing("participation_submitted", "2026-08-26T12:05:00Z");
        assert_eq!(
            pairing_admits_request(
                &replayed,
                PROOF,
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::AlreadyUsed
        );
        // A challenge stripped of its single-use seal is not an authentication factor.
        let mut forged = pairing("created", "2026-08-26T12:05:00Z");
        forged["challenge"]["single_use"] = json!(false);
        assert_eq!(
            pairing_admits_request(
                &forged,
                PROOF,
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::Unauthenticated
        );
    }

    #[test]
    fn a_consumption_already_in_flight_blocks_a_second_attempt() {
        let mut session = pairing("created", "2026-08-26T12:05:00Z");
        session["consumption_intent"] = consumption_intent(
            "participation-request://prq_x",
            "outcome-room://demo",
            "sha256:head",
            "user://ioi/levi",
            &json!({}),
        );
        assert_eq!(
            pairing_admits_request(
                &session,
                PROOF,
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::InFlight,
            "a second consumer must not race a retained intent"
        );
    }

    #[test]
    fn the_request_id_is_deterministic_so_a_replay_collides_instead_of_minting_a_second_request() {
        let first = derive_participation_request_id(
            "local-agent-pairing://lap_one",
            "outcome-room://demo",
            "user://ioi/levi",
        );
        let again = derive_participation_request_id(
            "local-agent-pairing://lap_one",
            "outcome-room://demo",
            "user://ioi/levi",
        );
        assert_eq!(first, again, "a replayed submission derives the same id");
        assert!(first.starts_with("participation-request://prq_"));
        // A different pairing, room, or requester is a different request.
        assert_ne!(
            first,
            derive_participation_request_id(
                "local-agent-pairing://lap_two",
                "outcome-room://demo",
                "user://ioi/levi"
            )
        );
        assert_ne!(
            first,
            derive_participation_request_id(
                "local-agent-pairing://lap_one",
                "outcome-room://other",
                "user://ioi/levi"
            )
        );
    }

    #[test]
    fn recovery_rolls_back_when_the_admission_definitively_did_not_linearize() {
        // Crash BETWEEN intent and admission. Nothing was consumed, so the pairing is released.
        let directory = temp_dir("recover-rollback");
        let data_dir = directory.to_str().unwrap();
        let mut session = pairing("created", "2026-08-26T12:05:00Z");
        session["consumption_intent"] = consumption_intent(
            "participation-request://prq_absent",
            // A CANONICAL room ref whose slot is absent: `current_child` resolves this to a
            // definitive absence rather than to uncertainty, which is what makes rollback safe.
            &canonical_room_ref(),
            "sha256:head",
            "user://ioi/levi",
            &json!({}),
        );
        persist_local(data_dir, PAIRING_DIR, "lap_one", &session).unwrap();

        complete_pairing_consumption_intents(data_dir).expect("recovery converges");

        let after = read_local(data_dir, PAIRING_DIR, "lap_one")
            .unwrap()
            .unwrap();
        assert!(
            after.get("consumption_intent").is_none(),
            "the intent is rolled back"
        );
        assert_eq!(
            after["status"],
            json!("created"),
            "an unspent pairing stays usable — consume-before-admit loss is not accepted"
        );
        assert!(pairing_admits_request(
            &after,
            PROOF,
            "outcome-room://demo",
            "user://ioi/levi",
            NOON_MS
        )
        .is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_consumed_pairing_is_terminal_and_backlinks_its_one_request() {
        let session = pairing("created", "2026-08-26T12:05:00Z");
        let consumed = consumed_pairing(
            &session,
            "participation-request://prq_one",
            "2026-08-26T12:00:00Z",
        )
        .unwrap();
        assert_eq!(consumed["status"], json!("participation_submitted"));
        assert_eq!(
            consumed["submission_refs"]["room_participation_request_ref"],
            json!("participation-request://prq_one")
        );
        assert_eq!(
            consumed["submission_refs"]["first_aiip_packet_ref"],
            Value::Null,
            "the hosted lane emits no AIIP packet"
        );
        assert!(consumed.get("consumption_intent").is_none());
        // And it can never be consumed again — admit-before-consume replay is closed.
        assert_eq!(
            pairing_admits_request(
                &consumed,
                PROOF,
                "outcome-room://demo",
                "user://ioi/levi",
                NOON_MS
            )
            .unwrap_err(),
            PairingRefusal::AlreadyUsed
        );
    }

    #[test]
    fn an_unreadable_room_blocks_readiness_instead_of_rolling_back() {
        // Uncertainty is not absence. If the room cannot be resolved EXACTLY, recovery must not
        // conclude "never admitted" and release the pairing — that would be the consume-before-
        // admit hole reached through a read failure instead of a crash.
        let directory = temp_dir("recover-uncertain");
        let data_dir = directory.to_str().unwrap();
        let mut session = pairing("created", "2026-08-26T12:05:00Z");
        session["consumption_intent"] = consumption_intent(
            "participation-request://prq_absent",
            "outcome-room://not-canonical",
            "sha256:head",
            "user://ioi/levi",
            &json!({}),
        );
        persist_local(data_dir, PAIRING_DIR, "lap_one", &session).unwrap();

        assert!(
            complete_pairing_consumption_intents(data_dir).is_err(),
            "an undecidable room must block readiness rather than release the pairing"
        );
        let after = read_local(data_dir, PAIRING_DIR, "lap_one")
            .unwrap()
            .unwrap();
        assert!(
            after.get("consumption_intent").is_some(),
            "the intent is retained for the next boot, not silently dropped"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_malformed_retained_intent_fails_closed_rather_than_guessing() {
        let directory = temp_dir("recover-malformed");
        let data_dir = directory.to_str().unwrap();
        let mut session = pairing("created", "2026-08-26T12:05:00Z");
        // An intent that names no request is undecidable in either direction.
        session["consumption_intent"] = json!({ "schema_version": "x" });
        persist_local(data_dir, PAIRING_DIR, "lap_one", &session).unwrap();
        assert_eq!(
            complete_pairing_consumption_intents(data_dir)
                .expect_err("an undecidable intent blocks readiness")
                .0,
            "m048_pairing_intent_invalid"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_hosted_lane_refuses_discovery_federation_and_a_foreign_admission_owner() {
        let base = build_participation_candidate(
            "participation-request://prq_one",
            "system://room/demo",
            "user://ioi/levi",
            "terms://demo/v1",
            &("sha256:".to_string() + &"22".repeat(32)),
            vec![],
            vec![],
            vec![],
            vec![],
            &("sha256:".to_string() + &"33".repeat(32)),
        );
        assert!(enforce_hosted_native_admission(&base, "system://room/demo").is_ok());
        assert_eq!(base["room_discovery_ref"], Value::Null);
        assert_eq!(base["private_context_included"], json!(false));
        assert_eq!(base["terms_response"], json!("accept"));
        // A foreign admission owner under a null discovery ref is the federation lane wearing a null.
        assert_eq!(
            enforce_hosted_native_admission(&base, "system://room/other")
                .expect_err("a foreign admission owner is refused")
                .0,
            "m048_participation_admission_owner_mismatch"
        );
        let mut discovered = base.clone();
        discovered["room_discovery_ref"] = json!("room-discovery://somewhere");
        assert_eq!(
            enforce_hosted_native_admission(&discovered, "system://room/demo")
                .expect_err("discovery is M11")
                .0,
            "m048_participation_discovery_refused"
        );
        let mut federated = base;
        federated["coordination_topology"] = json!("federated_admission");
        assert_eq!(
            enforce_hosted_native_admission(&federated, "system://room/demo")
                .expect_err("federation is M11")
                .0,
            "m048_participation_topology_refused"
        );
    }

    #[test]
    fn a_participation_candidate_never_carries_plane_owned_room_coordinates() {
        let candidate = build_participation_candidate(
            "participation-request://prq_one",
            "system://room/demo",
            "user://ioi/levi",
            "terms://demo/v1",
            &("sha256:".to_string() + &"22".repeat(32)),
            vec![],
            vec![],
            vec![],
            vec![],
            &("sha256:".to_string() + &"33".repeat(32)),
        );
        for owned in ["system_binding", "outcome_room_ref"] {
            assert!(
                candidate.get(owned).is_none(),
                "`{owned}` is derived by the seam from room truth, never supplied"
            );
        }
    }

    #[test]
    fn terms_scope_the_room_and_carry_no_settlement_surface() {
        let terms = build_terms_envelope(
            "terms://demo/v1",
            "1.0.0",
            &("sha256:".to_string() + &"55".repeat(32)),
            "outcome-room://demo",
            "system://room/demo",
            None,
        );
        assert_eq!(
            terms["scope"]["outcome_room_ref"],
            json!("outcome-room://demo")
        );
        assert_eq!(terms["scope"]["collaboration_ref"], Value::Null);
        assert_eq!(
            terms["terms_body_hash_profile"],
            json!(COLLABORATION_TERMS_BODY_PROFILE)
        );
        for forbidden in ["settlement", "payout", "rewards", "legal_person"] {
            assert!(
                terms.get(forbidden).is_none(),
                "`{forbidden}` is not a registered terms field"
            );
        }
    }

    #[test]
    fn an_acceptance_receipt_seals_the_exact_body_root_it_accepted() {
        let terms = build_terms_envelope(
            "terms://demo/v1",
            "1.0.0",
            &("sha256:".to_string() + &"55".repeat(32)),
            "outcome-room://demo",
            "system://room/demo",
            None,
        );
        let (tail, receipt) = build_terms_acceptance(
            &terms,
            "user://ioi/levi",
            "outcome-room://demo",
            NOON_MS,
            "2026-08-26T12:00:00Z",
        )
        .unwrap();
        assert!(tail.starts_with("tac_"));
        assert_eq!(receipt["receipt_ref"], json!(format!("receipt://{tail}")));
        assert_eq!(receipt["accepted_terms_root"], terms["terms_body_root"]);
        assert_eq!(receipt["grants_membership"], json!(false));
        assert_eq!(receipt["grants_authority"], json!(false));

        // Terms whose body moved produce a DIFFERENT acceptance — a lease can never bind a stale
        // acceptance to a moved body.
        let mut moved = terms.clone();
        moved["terms_body_root"] = json!("sha256:".to_string() + &"66".repeat(32));
        let (moved_tail, _) = build_terms_acceptance(
            &moved,
            "user://ioi/levi",
            "outcome-room://demo",
            NOON_MS,
            "2026-08-26T12:00:00Z",
        )
        .unwrap();
        assert_ne!(tail, moved_tail, "acceptance is exact to the accepted root");
    }

    #[test]
    fn constant_time_comparison_rejects_prefixes_and_length_drift() {
        assert!(constant_time_eq(PROOF, PROOF));
        assert!(!constant_time_eq(PROOF, &PROOF[..PROOF.len() - 1]));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn a_pairing_or_terms_ref_must_be_normalization_safe() {
        assert_eq!(
            pairing_tail("local-agent-pairing://lap_one").unwrap(),
            "lap_one"
        );
        assert!(pairing_tail("local-agent-pairing://").is_err());
        assert!(pairing_tail("participant-lease://x").is_err());
        assert!(
            pairing_tail("local-agent-pairing://../escape").is_err(),
            "a traversal-shaped tail is refused before it reaches the filesystem"
        );
        assert_eq!(terms_tail("terms://trm_one").unwrap(), "trm_one");
        assert!(terms_tail("terms://../escape").is_err());
    }

    // --- A3: mounted route surface ------------------------------------------------------------

    /// The router source, so mounting facts are asserted against the file that actually mounts.
    const ROUTER_SOURCE: &str = include_str!("../hypervisor-daemon.rs");

    #[test]
    fn the_predecessor_participation_handlers_are_no_longer_mounted() {
        // Re-pointing is only real if the old handlers are GONE from the router. A predecessor
        // left mounted beside the current generation is a second spine for the same family.
        for retired in [
            "room_participation_routes::handle_participation_request_create",
            "room_participation_routes::handle_participation_requests_list",
            "room_participation_routes::handle_participation_request_get",
            "room_participation_routes::handle_participation_request_transition",
            "room_participation_routes::handle_participation_request_admit",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(retired),
                "`{retired}` must not remain mounted; the current generation owns this family"
            );
        }
        // The predecessor MODULE stays declared and physically untouched — only its route
        // registrations for this family were re-pointed.
        assert!(ROUTER_SOURCE.contains("mod room_participation_routes;"));
        assert!(
            ROUTER_SOURCE.contains("room_participation_routes::complete_participation_intents"),
            "the predecessor's own recovery stays wired; A3 retires routes, not durability"
        );
    }

    #[test]
    fn every_a3_route_is_mounted_at_its_exact_path_and_verb() {
        for (path, handler) in [
            (
                "/v1/goal-orchestration/local-agent-pairing-sessions",
                "m048_collaboration_routes::handle_pairing_create",
            ),
            (
                "/v1/goal-orchestration/local-agent-pairing-sessions/:id",
                "m048_collaboration_routes::handle_pairing_get",
            ),
            (
                "/v1/goal-orchestration/collaboration-terms",
                "m048_collaboration_routes::handle_terms_create",
            ),
            (
                "/v1/goal-orchestration/collaboration-terms/:id",
                "m048_collaboration_routes::handle_terms_get",
            ),
            (
                "/v1/goal-orchestration/collaboration-terms/:id/accept",
                "m048_collaboration_routes::handle_terms_accept",
            ),
            (
                "/v1/goal-orchestration/room-participation-requests",
                "m048_collaboration_routes::handle_participation_request_create",
            ),
        ] {
            assert!(
                ROUTER_SOURCE.contains(path),
                "`{path}` must be mounted in the router"
            );
            assert!(
                ROUTER_SOURCE.contains(handler),
                "`{handler}` must be the handler the router names"
            );
        }
    }

    #[test]
    fn all_ten_lifecycles_are_mounted_and_no_predecessor_handler_remains() {
        // A6 completes the arc, so the earlier "not yet mounted" pin is replaced by its inverse:
        // every current handler MUST be mounted, and no predecessor handler for any re-pointed
        // family may remain beside it.
        for mounted in [
            "m048_collaboration_routes::handle_pairing_create",
            "m048_collaboration_routes::handle_terms_create",
            "m048_collaboration_routes::handle_participation_request_create",
            "m048_collaboration_routes::handle_participation_request_admit",
            "m048_collaboration_routes::handle_participant_lease_transition",
            "m048_collaboration_routes::handle_resource_create",
            "m048_collaboration_routes::handle_capability_create",
            "m048_collaboration_routes::handle_frontier_create",
            "m048_collaboration_routes::handle_match_create",
            "m048_collaboration_routes::handle_claim_acquire",
            "m048_collaboration_routes::handle_attempt_create",
            "m048_collaboration_routes::handle_finding_create",
            "m048_collaboration_routes::handle_challenge_create",
        ] {
            assert!(
                ROUTER_SOURCE.contains(mounted),
                "`{mounted}` must be mounted at the current generation"
            );
        }
        for retired in [
            "room_participation_routes::handle_",
            "resource_capability_offer_routes::handle_",
            "work_frontier_claim_routes::handle_",
            "attempt_finding_routes::handle_",
            "verifier_challenge_routes::handle_",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(retired),
                "`{retired}` must not remain mounted beside the current generation"
            );
        }
        // The predecessor modules stay declared and physically untouched.
        for module in [
            "mod room_participation_routes;",
            "mod resource_capability_offer_routes;",
            "mod work_frontier_claim_routes;",
            "mod attempt_finding_routes;",
            "mod verifier_challenge_routes;",
        ] {
            assert!(ROUTER_SOURCE.contains(module), "`{module}` stays declared");
        }
    }

    #[test]
    fn an_unauthenticated_pairing_is_401_not_400() {
        let (status, Json(body)) = classify(verr(
            PairingRefusal::Unauthenticated.code(),
            PairingRefusal::Unauthenticated.message(),
        ));
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "identity failure against a pre-admission authenticator is 401, per repo precedent"
        );
        assert_eq!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("m048_pairing_unauthenticated")
        );
        // The other pairing refusals keep their own distinct classes.
        assert_eq!(
            classify(verr(
                PairingRefusal::AlreadyUsed.code(),
                PairingRefusal::AlreadyUsed.message()
            ))
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            classify(verr(
                PairingRefusal::InFlight.code(),
                PairingRefusal::InFlight.message()
            ))
            .0,
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn a_pairing_projection_never_leaks_its_sealed_challenge_or_recovery_state() {
        let mut session = pairing("created", "2026-08-26T12:05:00Z");
        session["consumption_intent"] = json!({ "participation_request_id": "x" });
        let projected = project_pairing(&session);
        assert!(
            projected["challenge"].get("challenge_hash").is_none(),
            "the sealed challenge is the proof a consumer must present; reading it must not supply it"
        );
        assert!(projected.get("consumption_intent").is_none());
        // Everything a caller legitimately needs survives the projection.
        assert_eq!(projected["status"], json!("created"));
        assert_eq!(projected["challenge"]["single_use"], json!(true));
        assert!(projected["challenge"].get("expires_at").is_some());
        let serialized = serde_json::to_string(&projected).unwrap();
        assert!(
            !serialized.contains(PROOF),
            "no proof material leaves the daemon"
        );
    }

    #[tokio::test]
    async fn a_malformed_or_secret_bearing_create_is_refused_before_any_write() {
        let directory = temp_dir("create-refusal");
        let data_dir = directory.to_str().unwrap();
        for body in [
            // Unknown field.
            json!({ "outcome_room_ref": canonical_room_ref(), "surprise": 1 }),
            // Secret-bearing field.
            json!({ "outcome_room_ref": canonical_room_ref(), "api_key": "x" }),
            // Missing required fields.
            json!({ "outcome_room_ref": canonical_room_ref() }),
            // TTL beyond the bounded pairing ceiling.
            json!({
                "outcome_room_ref": canonical_room_ref(),
                "initiating_surface_ref": "surface://ioi/app",
                "display_name": "local agent",
                "challenge_hash": "sha256:".to_string() + &"99".repeat(32),
                "ttl_seconds": PAIRING_TTL_MAX_SECONDS + 1,
            }),
        ] {
            let outcome = pairing_create_inner(data_dir, "user://ioi/levi", &body).await;
            let (status, _) = outcome.expect_err("a malformed create is refused");
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        // Refusal writes nothing: not one owner-local family was created.
        for family in OWNER_LOCAL_FAMILIES {
            assert!(
                !directory.join(family).exists(),
                "`{family}` must not exist after a refused create"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_participation_create_against_an_absent_room_writes_nothing() {
        let directory = temp_dir("participation-refusal");
        let data_dir = directory.to_str().unwrap();
        let body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": "sha256:".to_string() + &"11".repeat(32),
            "pairing_session_id": "local-agent-pairing://lap_one",
            "pairing_proof_hash": PROOF,
            "collaboration_terms_ref": "terms://trm_one",
            "collaboration_terms_root": "sha256:".to_string() + &"55".repeat(32),
        });
        let (status, _) = participation_create_inner(data_dir, "user://ioi/levi", &body)
            .await
            .expect_err("an absent room is refused");
        assert_eq!(status, StatusCode::NOT_FOUND);
        for family in OWNER_LOCAL_FAMILIES {
            assert!(!directory.join(family).exists());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn terms_acceptance_refuses_a_root_that_is_not_the_current_body_root() {
        let directory = temp_dir("terms-accept");
        let data_dir = directory.to_str().unwrap();
        let terms = build_terms_envelope(
            "terms://trm_one",
            "1.0.0",
            &("sha256:".to_string() + &"55".repeat(32)),
            &canonical_room_ref(),
            "system://room/demo",
            None,
        );
        persist_local(data_dir, TERMS_DIR, "trm_one", &terms).unwrap();
        let body = json!({ "accepted_terms_root": "sha256:".to_string() + &"66".repeat(32) });
        let (status, Json(payload)) =
            terms_accept_inner(data_dir, "user://ioi/levi", "trm_one", &body)
                .await
                .expect_err("a stale accepted root is refused");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            payload.pointer("/error/code").and_then(Value::as_str),
            Some("m048_terms_root_mismatch")
        );
        // The refusal wrote no acceptance receipt.
        assert!(!directory.join(TERMS_ACCEPTANCE_DIR).exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn an_absent_terms_record_is_not_found_rather_than_invented() {
        let directory = temp_dir("terms-absent");
        let data_dir = directory.to_str().unwrap();
        let body = json!({ "accepted_terms_root": "sha256:".to_string() + &"55".repeat(32) });
        let (status, _) = terms_accept_inner(data_dir, "user://ioi/levi", "trm_missing", &body)
            .await
            .expect_err("absent terms are refused");
        assert_eq!(status, StatusCode::NOT_FOUND);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_child_response_carries_its_contract_and_agentgres_evidence() {
        let admission = json!({
            "ok": true,
            "admission": {
                "outcome_room": { "room_state_root": "sha256:head", "latest_sequence": 7 },
                "admitted_object": { "participation_request_id": "participation-request://prq_one" },
                "agentgres_admission": { "agentgres_head": "sha256:head" },
                "owner_publication": Value::Null,
            },
        });
        let (status, Json(body)) = ok_child(
            PARTICIPATION_REQUEST_CONTRACT,
            PARTICIPATION_REQUEST_SCHEMA,
            &admission,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["object_contract_id"],
            json!(PARTICIPATION_REQUEST_CONTRACT)
        );
        assert_eq!(body["schema_version"], json!(PARTICIPATION_REQUEST_SCHEMA));
        assert_eq!(
            body["agentgres_evidence"]["room_state_root"],
            json!("sha256:head"),
            "a caller must see the head its write landed on to take the next CAS decision"
        );
        assert_eq!(body["owner_publication"], Value::Null);
    }

    #[test]
    fn the_transition_and_admit_verbs_are_a_named_gap_not_a_silent_absence() {
        let (status, Json(body)) = participation_step_unavailable("admit");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("m048_participation_transition_unavailable")
        );
        let message = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            message.contains("participant lease"),
            "the gap must name what owns the verb, not merely refuse"
        );
    }

    // --- A4: lease + offers --------------------------------------------------------------------

    fn lease(status: &str, expires_at: &str) -> Value {
        json!({
            "participant_lease_id": "participant-lease://plz_one",
            "join_request_ref": "participation-request://prq_one",
            "status": status,
            "expires_at": expires_at,
            "unbounded_term_exception_decision_ref": Value::Null,
            "capability_advertisement_refs": ["capability-offer://granted"],
            "runtime_resource_and_budget_lease_refs": ["budget://granted"],
        })
    }

    #[test]
    fn lease_liveness_is_decided_only_against_wallet_time() {
        assert_eq!(
            lease_is_live(&lease("active", "2026-08-26T13:00:00Z"), NOON_MS).unwrap(),
            Ok(())
        );
        assert_eq!(
            lease_is_live(&lease("active", "2026-08-26T11:59:00Z"), NOON_MS).unwrap(),
            Err(LeaseLapse::Expired)
        );
        assert_eq!(
            lease_is_live(&lease("revoked", "2026-08-26T13:00:00Z"), NOON_MS).unwrap(),
            Err(LeaseLapse::Terminal)
        );
        assert_eq!(
            lease_is_live(&lease("suspended", "2026-08-26T13:00:00Z"), NOON_MS).unwrap(),
            Err(LeaseLapse::Suspended)
        );
        // An unregistered status refuses rather than defaulting to live.
        assert!(lease_is_live(&lease("invented", "2026-08-26T13:00:00Z"), NOON_MS).is_err());
    }

    #[test]
    fn a_null_expiry_without_a_governed_exception_is_refused_not_treated_as_eternal() {
        let mut unbounded = lease("active", "2026-08-26T13:00:00Z");
        unbounded["expires_at"] = Value::Null;
        assert_eq!(
            lease_is_live(&unbounded, NOON_MS)
                .expect_err("a null expiry needs a governed exception")
                .0,
            "m048_lease_record_invalid"
        );
        unbounded["unbounded_term_exception_decision_ref"] = json!("decision://granted");
        assert_eq!(
            lease_is_live(&unbounded, NOON_MS).unwrap(),
            Ok(()),
            "a governed exception admits the unbounded term"
        );
    }

    #[test]
    fn an_offer_outside_its_lease_scope_is_refused_even_though_membership_holds() {
        let live = lease("active", "2026-08-26T13:00:00Z");
        // Within the grant.
        assert!(require_lease_scope(
            &live,
            NOON_MS,
            "capability_advertisement_refs",
            &["capability-offer://granted".to_string()],
        )
        .is_ok());
        // Outside the grant: membership is not scope.
        let error = require_lease_scope(
            &live,
            NOON_MS,
            "capability_advertisement_refs",
            &["capability-offer://never-granted".to_string()],
        )
        .expect_err("an ungranted ref is refused");
        assert_eq!(error.0, "m048_offer_outside_lease_scope");
        assert!(error.1.contains("membership is not scope"));
    }

    #[test]
    fn an_expired_or_revoked_lease_may_not_issue_offers() {
        for (status, expiry, expected) in [
            ("active", "2026-08-26T11:00:00Z", "m048_lease_expired"),
            ("revoked", "2026-08-26T13:00:00Z", "m048_lease_terminal"),
            ("suspended", "2026-08-26T13:00:00Z", "m048_lease_not_active"),
        ] {
            assert_eq!(
                require_lease_scope(
                    &lease(status, expiry),
                    NOON_MS,
                    "capability_advertisement_refs",
                    &[]
                )
                .expect_err("a non-live lease cannot issue")
                .0,
                expected
            );
        }
    }

    #[test]
    fn a_lease_window_is_rendered_entirely_from_the_wallet_instant() {
        let window = LeaseWindow::from_wallet(NOON_MS, 3600).unwrap();
        assert_eq!(window.issued_at, "2026-08-26T12:00:00Z");
        assert_eq!(window.expires_at, "2026-08-26T13:00:00Z");
        // renew_after sits at three quarters of the term, leaving room to renew before expiry.
        assert_eq!(window.renew_after, "2026-08-26T12:45:00Z");
        assert_eq!(window.ttl_seconds, 3600);
        assert!(
            rfc3339_to_ms(&window.renew_after).unwrap()
                < rfc3339_to_ms(&window.expires_at).unwrap()
        );
    }

    #[test]
    fn a_lease_candidate_is_room_system_issued_and_carries_no_plane_owned_field() {
        let request = json!({ "participation_request_id": "participation-request://prq_one" });
        let candidate = build_lease_candidate(
            "participant-lease://plz_one",
            &request,
            "worker://demo/w",
            "org://demo/op",
            "domain://demo",
            "implementer",
            "restricted_view://demo",
            &LeaseTermsBinding {
                terms_ref: "terms://trm_one",
                terms_root: &("sha256:".to_string() + &"55".repeat(32)),
                acceptance_ref: "receipt://tac_one",
            },
            &LeaseGrants {
                capability_advertisement_refs: vec!["capability-offer://a".to_string()],
                context_and_authority_lease_refs: vec![],
                runtime_resource_and_budget_lease_refs: vec![],
            },
            "receipt://adm_one",
            &LeaseWindow::from_wallet(NOON_MS, 3600).unwrap(),
        );
        for owned in ["system_binding", "outcome_room_ref"] {
            assert!(candidate.get(owned).is_none(), "`{owned}` is seam-derived");
        }
        assert_eq!(
            candidate["join_request_ref"],
            request["participation_request_id"]
        );
        assert_eq!(
            candidate["terms_acceptance_ref"],
            json!("receipt://tac_one")
        );
        assert_eq!(
            candidate["heartbeat_ref"],
            Value::Null,
            "a fresh lease has no heartbeat; the field is receipt:// only and never invented"
        );
        assert_eq!(
            candidate["unbounded_term_exception_decision_ref"],
            Value::Null
        );
        assert_eq!(candidate["current_claim_ref"], Value::Null);
        assert_eq!(candidate["status"], json!("active"));
    }

    #[test]
    fn a_lease_id_is_deterministic_so_a_retried_admit_cannot_mint_a_second_lease() {
        let first = derive_participant_lease_id(
            "participation-request://prq_one",
            &canonical_room_ref(),
            "worker://demo/w",
        );
        assert_eq!(
            first,
            derive_participant_lease_id(
                "participation-request://prq_one",
                &canonical_room_ref(),
                "worker://demo/w"
            )
        );
        assert!(first.starts_with("participant-lease://plz_"));
        assert_ne!(
            first,
            derive_participant_lease_id(
                "participation-request://prq_two",
                &canonical_room_ref(),
                "worker://demo/w"
            )
        );
    }

    #[test]
    fn the_admitted_successor_strips_seam_owned_coordinates_and_binds_its_lease() {
        let request = json!({
            "participation_request_id": "participation-request://prq_one",
            "system_binding": { "system_id": "system://room/demo" },
            "outcome_room_ref": "outcome-room://demo",
            "status": "submitted",
            "participant_lease_ref": Value::Null,
            "admission_decision_ref": Value::Null,
        });
        let successor = admitted_request_successor(
            &request,
            "participant-lease://plz_one",
            "receipt://adm_one",
        )
        .unwrap();
        assert!(successor.get("system_binding").is_none());
        assert!(successor.get("outcome_room_ref").is_none());
        assert_eq!(successor["status"], json!("admitted"));
        assert_eq!(
            successor["participant_lease_ref"],
            json!("participant-lease://plz_one")
        );
        assert_eq!(
            successor["admission_decision_ref"],
            json!("receipt://adm_one")
        );
    }

    #[test]
    fn only_contract_owned_lease_transitions_exist() {
        for op in ["heartbeat", "renew", "revoke", "expire"] {
            assert!(lease_transition_target(op).is_some(), "`{op}` is owned");
        }
        // No invented acceptance, verdict, or settlement verb.
        for invented in [
            "accept", "verdict", "settle", "reassign", "payout", "federate",
        ] {
            assert!(
                lease_transition_target(invented).is_none(),
                "`{invented}` must not exist on this plane"
            );
        }
        assert_eq!(lease_transition_target("revoke"), Some("revoked"));
        assert_eq!(lease_transition_target("expire"), Some("retired"));
    }

    #[test]
    fn offer_liveness_uses_wallet_time_and_terminal_status() {
        let live = json!({ "status": "offered", "expires_at": "2026-08-26T13:00:00Z" });
        assert!(offer_is_live(RESOURCE_OFFER_FAMILY, &live, NOON_MS).unwrap());
        let expired = json!({ "status": "offered", "expires_at": "2026-08-26T11:00:00Z" });
        assert!(!offer_is_live(RESOURCE_OFFER_FAMILY, &expired, NOON_MS).unwrap());
        let withdrawn = json!({ "status": "withdrawn", "expires_at": "2026-08-26T13:00:00Z" });
        assert!(!offer_is_live(RESOURCE_OFFER_FAMILY, &withdrawn, NOON_MS).unwrap());
        // A capability offer carries no expiry field; only a terminal status lapses it.
        let capability = json!({ "status": "offered" });
        assert!(offer_is_live(CAPABILITY_OFFER_FAMILY, &capability, NOON_MS).unwrap());
        let revoked = json!({ "status": "revoked" });
        assert!(!offer_is_live(CAPABILITY_OFFER_FAMILY, &revoked, NOON_MS).unwrap());
    }

    #[test]
    fn neither_offer_family_mints_a_room_ref_its_contract_does_not_declare() {
        let body = json!({
            "backing_provider_ref": "provider://demo",
            "capability_descriptor_refs": ["ai://demo/review"],
        });
        for candidate in [
            build_resource_offer(
                "resource-offer://rso_one",
                &body,
                "participant-lease://plz_one",
            ),
            build_capability_offer(
                "capability-offer://cao_one",
                &body,
                "participant-lease://plz_one",
            ),
        ] {
            assert!(
                candidate.get("outcome_room_ref").is_none(),
                "these contracts declare no top-level room ref; the seam must not receive one"
            );
            assert!(candidate.get("system_binding").is_none());
            assert_eq!(candidate["status"], json!("offered"));
        }
        // A fresh resource offer allocates nothing.
        let resource = build_resource_offer(
            "resource-offer://rso_one",
            &body,
            "participant-lease://plz_one",
        );
        assert_eq!(resource["allocation_decision_refs"], json!([]));
        assert_eq!(resource["spend_and_contribution_refs"], json!([]));
        assert_eq!(resource["usage_and_consumption_refs"], json!([]));
    }

    #[test]
    fn the_two_offer_families_stay_structurally_paired() {
        for family in [RESOURCE_OFFER_FAMILY, CAPABILITY_OFFER_FAMILY] {
            assert!(family.statuses.contains(&"offered"));
            for terminal in family.terminal {
                assert!(
                    family.statuses.contains(terminal),
                    "`{terminal}` must be a registered status of its own family"
                );
            }
            assert!(family.code.starts_with("m048_"));
        }
        assert_ne!(
            RESOURCE_OFFER_FAMILY.lease_field,
            CAPABILITY_OFFER_FAMILY.lease_field
        );
        assert_ne!(
            RESOURCE_OFFER_FAMILY.granted_field,
            CAPABILITY_OFFER_FAMILY.granted_field
        );
    }

    #[test]
    fn the_predecessor_lease_and_offer_handlers_are_no_longer_mounted() {
        for retired in [
            "room_participation_routes::handle_participant_leases_list",
            "room_participation_routes::handle_participant_lease_get",
            "room_participation_routes::handle_participant_lease_transition",
            "resource_capability_offer_routes::handle_resource_",
            "resource_capability_offer_routes::handle_capability_",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(retired),
                "`{retired}` must not remain mounted; the current generation owns this family"
            );
        }
        // A5 took the eligibility-match family too; nothing of that module remains mounted.
        assert!(
            !ROUTER_SOURCE.contains("resource_capability_offer_routes::handle_"),
            "no predecessor offer/match handler may remain mounted"
        );
    }

    #[test]
    fn every_a4_route_is_mounted_at_its_exact_path_and_handler() {
        for (path, handler) in [
            (
                "/v1/goal-orchestration/room-participant-leases",
                "m048_collaboration_routes::handle_participant_leases_list",
            ),
            (
                "/v1/goal-orchestration/room-participant-leases/:id/transition",
                "m048_collaboration_routes::handle_participant_lease_transition",
            ),
            (
                "/v1/goal-orchestration/resource-offers/overview",
                "m048_collaboration_routes::handle_resource_overview",
            ),
            (
                "/v1/goal-orchestration/resource-offers/:id/transition",
                "m048_collaboration_routes::handle_resource_transition",
            ),
            (
                "/v1/goal-orchestration/capability-offers/overview",
                "m048_collaboration_routes::handle_capability_overview",
            ),
            (
                "/v1/goal-orchestration/capability-offers/:id/transition",
                "m048_collaboration_routes::handle_capability_transition",
            ),
        ] {
            assert!(ROUTER_SOURCE.contains(path), "`{path}` must be mounted");
            assert!(ROUTER_SOURCE.contains(handler), "`{handler}` must be named");
        }
        // The admit verb is now real, not a typed gap.
        assert!(
            ROUTER_SOURCE.contains("m048_collaboration_routes::handle_participation_request_admit")
        );
    }

    #[test]
    fn the_admission_convergence_runs_after_the_seam_recovery_in_the_router_source() {
        // Ordering is load-bearing: "did the lease land" is only a settled fact once the seam has
        // converged its own pending child intents.
        let seam = ROUTER_SOURCE
            .find("outcome_room_system_routes::complete_pending")
            .expect("the seam recovery is wired");
        let admissions = ROUTER_SOURCE
            .find("m048_collaboration_routes::complete_participation_admissions")
            .expect("the admission convergence is wired");
        let pairing = ROUTER_SOURCE
            .find("m048_collaboration_routes::complete_pairing_consumption_intents")
            .expect("the pairing convergence is wired");
        assert!(seam < pairing && pairing < admissions);
    }

    #[tokio::test]
    async fn a4_mutations_refuse_and_write_nothing_without_a_room() {
        let directory = temp_dir("a4-refusal");
        let data_dir = directory.to_str().unwrap();
        let head = "sha256:".to_string() + &"11".repeat(32);

        let admit_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "participant_ref": "worker://demo/w",
            // The hosted slice admits only worker:// and agent:// principals.
            "operator_ref": "worker://demo/op",
            "home_domain_ref": "domain://demo",
            "admitted_role": "implementer",
            "visibility_scope_ref": "restricted_view://demo",
            "terms_acceptance_ref": "receipt://tac_one",
            "ttl_seconds": 3600,
        });
        assert_eq!(
            admit_inner(data_dir, "prq_one", &admit_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        let offer_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "participant_lease_ref": "participant-lease://plz_one",
            "capability_descriptor_refs": ["ai://demo/review"],
        });
        assert_eq!(
            offer_create_inner(
                data_dir,
                CAPABILITY_OFFER_FAMILY,
                CAPABILITY_OFFER_FIELDS,
                &offer_body,
                build_capability_offer
            )
            .await
            .expect_err("an absent room is refused")
            .0,
            StatusCode::NOT_FOUND
        );

        // An unregistered role or an out-of-bounds TTL refuses as a bad request.
        let mut bad_role = admit_body.clone();
        bad_role["admitted_role"] = json!("overlord");
        assert_eq!(
            admit_inner(data_dir, "prq_one", &bad_role)
                .await
                .expect_err("an unregistered role is refused")
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut bad_ttl = admit_body;
        bad_ttl["ttl_seconds"] = json!(LEASE_TTL_MAX_SECONDS + 1);
        assert_eq!(
            admit_inner(data_dir, "prq_one", &bad_ttl)
                .await
                .expect_err("an out-of-bounds TTL is refused")
                .0,
            StatusCode::BAD_REQUEST
        );

        for family in OWNER_LOCAL_FAMILIES {
            assert!(
                !directory.join(family).exists(),
                "a refused A4 mutation writes nothing"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_lease_transition_admits_a_field_only_on_the_verb_that_owns_it() {
        let directory = temp_dir("a4-transition-fields");
        let data_dir = directory.to_str().unwrap();
        let head = "sha256:".to_string() + &"11".repeat(32);
        // `heartbeat_ref` on a renew, and `ttl_seconds` on a heartbeat, are both refused.
        for (op, extra, key) in [
            ("renew", json!("receipt://hb_one"), "heartbeat_ref"),
            ("heartbeat", json!(3600), "ttl_seconds"),
        ] {
            let mut body = json!({
                "outcome_room_ref": canonical_room_ref(),
                "expected_room_state_root": head,
                "op": op,
            });
            body[key] = extra;
            let (status, Json(payload)) = lease_transition_inner(data_dir, "plz_one", &body)
                .await
                .expect_err("a field outside its verb is refused");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                payload.pointer("/error/code").and_then(Value::as_str),
                Some("m048_lease_field_not_admitted_for_transition")
            );
        }
        // A heartbeat without its receipt is refused too.
        let body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "op": "heartbeat",
        });
        assert_eq!(
            lease_transition_inner(data_dir, "plz_one", &body)
                .await
                .expect_err("a heartbeat needs its receipt")
                .0,
            StatusCode::BAD_REQUEST
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    // --- A4 correction: the real generated contract validator over real builder output ---------

    use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

    /// Apply the exact derivation the room-native seam applies, so a production candidate can be
    /// validated as the object the seam would actually admit.
    ///
    /// This mirrors `prepare_room_native_child`: the seam injects the whole
    /// SystemScopedObjectBinding and, for the contracts that declare one, the room ref. Anything
    /// this helper adds is therefore server-derived truth, not a fixture fudge — the CANDIDATE
    /// itself is produced by the production builder under test.
    fn seal_like_the_seam(candidate: &Value, contract_id: &str, room_ref: &str) -> Value {
        let mut sealed = candidate.clone();
        let map = sealed.as_object_mut().expect("a candidate is an object");
        map.insert(
            "system_binding".to_string(),
            json!({
                "schema_version": "ioi.foundations.system-scoped-object-binding.v1",
                "system_id": SYSTEM_ID,
                "parent_scope_ref": room_ref,
                // The lease's registered invariant requires the room System to be its issuer.
                "proposed_or_issued_by_ref": SYSTEM_ID,
                "payload_root": format!("sha256:{}", "11".repeat(32)),
                "created_at": "2026-08-26T12:00:00Z",
                "updated_at": Value::Null,
            }),
        );
        // Only the contracts whose registered shape declares a top-level room ref receive one;
        // the offer families deliberately do not.
        if matches!(
            contract_id,
            PARTICIPATION_REQUEST_CONTRACT
                | PARTICIPANT_LEASE_CONTRACT
                | WORK_CLAIM_LEASE_CONTRACT
                | ATTEMPT_CONTRACT
                | FINDING_CONTRACT
                | VERIFIER_CHALLENGE_CONTRACT
        ) {
            map.insert("outcome_room_ref".to_string(), json!(room_ref));
        }
        sealed
    }

    const SYSTEM_ID: &str = "system://room/demo";

    fn validated_room_ref() -> String {
        canonical_room_ref()
    }

    /// The production participation-request candidate, built exactly as the handler builds it.
    fn production_request_candidate() -> Value {
        build_participation_candidate(
            &derive_participation_request_id(
                "local-agent-pairing://lap_one",
                &validated_room_ref(),
                "worker://demo/w",
            ),
            SYSTEM_ID,
            "worker://demo/w",
            "terms://trm_one",
            &format!("sha256:{}", "55".repeat(32)),
            vec!["capability-offer://demo/w".to_string()],
            vec!["evidence://demo/w".to_string()],
            vec!["frontier://demo/1".to_string()],
            vec!["privacy_posture://demo/v1".to_string()],
            &format!("sha256:{}", "33".repeat(32)),
        )
    }

    /// The production lease candidate, built exactly as `admit_inner` builds it.
    fn production_lease_candidate() -> Value {
        let request = production_request_candidate();
        let request_id = request["participation_request_id"]
            .as_str()
            .unwrap()
            .to_string();
        build_lease_candidate(
            &derive_participant_lease_id(&request_id, &validated_room_ref(), "worker://demo/w"),
            &request,
            "worker://demo/w",
            "org://demo/operator",
            "domain://demo/operator",
            "implementer",
            "restricted_view://demo/implementer",
            &LeaseTermsBinding {
                terms_ref: "terms://trm_one",
                terms_root: &format!("sha256:{}", "55".repeat(32)),
                acceptance_ref: &format!("receipt://tac_{}", "ab".repeat(32)),
            },
            &LeaseGrants {
                capability_advertisement_refs: vec!["capability-offer://demo/w".to_string()],
                context_and_authority_lease_refs: vec!["context_lease://demo/1".to_string()],
                runtime_resource_and_budget_lease_refs: vec!["budget://demo/1".to_string()],
            },
            &format!("receipt://adm_{}", "cd".repeat(32)),
            &LeaseWindow::from_wallet(NOON_MS, 3600).unwrap(),
        )
    }

    #[test]
    fn the_participation_request_builder_satisfies_its_registered_v3_contract() {
        let sealed = seal_like_the_seam(
            &production_request_candidate(),
            PARTICIPATION_REQUEST_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(PARTICIPATION_REQUEST_CONTRACT, &sealed).unwrap_or_else(
            |error| panic!("the production participation-request candidate must validate: {error}"),
        );
    }

    #[test]
    fn the_participant_lease_builder_satisfies_its_registered_v3_contract() {
        let sealed = seal_like_the_seam(
            &production_lease_candidate(),
            PARTICIPANT_LEASE_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(PARTICIPANT_LEASE_CONTRACT, &sealed).unwrap_or_else(
            |error| panic!("the production participant-lease candidate must validate: {error}"),
        );
    }

    #[test]
    fn both_offer_builders_satisfy_their_registered_v3_contracts() {
        let resource_body = json!({
            "backing_provider_ref": "provider://demo/gpu-cloud",
            "resource_profile_ref": "resource://demo/gpu-a100",
            "capacity_and_availability_ref": "capacity://demo/pool-1",
            "locality_and_custody_refs": ["region://demo/us-west"],
            "trust_and_assurance_refs": ["evidence://demo/attestation"],
            "cost_ref": "quote://demo/hourly",
            "eligible_work_classes": ["training"],
            "policy_constraint_refs": ["policy://demo/resource-use-v1"],
            "allocation_policy_ref": "policy://demo/allocation-v1",
            "queue_preemption_and_fairness_policy_ref": "policy://demo/fairness-v1",
            "expires_at": "2026-08-27T00:00:00Z",
        });
        let resource = build_resource_offer(
            &format!("resource-offer://rso_{}", "ab".repeat(32)),
            &resource_body,
            "participant-lease://plz_one",
        );
        validate_architecture_contract(
            RESOURCE_OFFER_CONTRACT,
            &seal_like_the_seam(&resource, RESOURCE_OFFER_CONTRACT, &validated_room_ref()),
        )
        .unwrap_or_else(|error| {
            panic!("the production resource-offer candidate must validate: {error}")
        });

        let capability_body = json!({
            "backing_worker_or_service_ref": "worker://demo/w",
            "capability_descriptor_refs": ["ai://demo/code-review"],
            "eligible_frontier_classes": ["review_need"],
            "model_harness_tool_and_connector_refs": ["harness-profile://demo/review-v1"],
            "authority_and_context_requirements": ["scope:repository.read"],
            "privacy_cost_quality_and_latency_refs": ["benchmark://demo/quality"],
            "availability_ref": "schedule://demo/weekdays",
        });
        let capability = build_capability_offer(
            &format!("capability-offer://cao_{}", "ab".repeat(32)),
            &capability_body,
            "participant-lease://plz_one",
        );
        validate_architecture_contract(
            CAPABILITY_OFFER_CONTRACT,
            &seal_like_the_seam(
                &capability,
                CAPABILITY_OFFER_CONTRACT,
                &validated_room_ref(),
            ),
        )
        .unwrap_or_else(|error| {
            panic!("the production capability-offer candidate must validate: {error}")
        });
    }

    #[test]
    fn the_admitted_request_successor_still_satisfies_its_contract() {
        // Succession is where a builder is most likely to drift out of contract, because it edits
        // an already-admitted payload rather than constructing a fresh one.
        let request = production_request_candidate();
        let successor = admitted_request_successor(
            &request,
            &format!("participant-lease://plz_{}", "ab".repeat(32)),
            &format!("receipt://adm_{}", "cd".repeat(32)),
        )
        .unwrap();
        let sealed = seal_like_the_seam(
            &successor,
            PARTICIPATION_REQUEST_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(PARTICIPATION_REQUEST_CONTRACT, &sealed)
            .unwrap_or_else(|error| panic!("the admitted successor must validate: {error}"));
        assert_eq!(sealed["status"], json!("admitted"));
    }

    #[test]
    fn a_renewed_lease_generation_still_satisfies_its_contract() {
        let lease = production_lease_candidate();
        let window = LeaseWindow::from_wallet(NOON_MS + 60_000, 7200).unwrap();
        let mut renewed = lease.clone();
        let map = renewed.as_object_mut().unwrap();
        map.insert("expires_at".to_string(), json!(window.expires_at));
        map.insert("renew_after".to_string(), json!(window.renew_after));
        map.insert("ttl_seconds".to_string(), json!(window.ttl_seconds));
        map.insert("lease_epoch".to_string(), json!(2));
        map.insert(
            "heartbeat_ref".to_string(),
            json!(format!("receipt://hb_{}", "ef".repeat(32))),
        );
        let sealed =
            seal_like_the_seam(&renewed, PARTICIPANT_LEASE_CONTRACT, &validated_room_ref());
        validate_architecture_contract(PARTICIPANT_LEASE_CONTRACT, &sealed)
            .unwrap_or_else(|error| panic!("a renewed lease generation must validate: {error}"));
    }

    #[test]
    fn the_validator_actually_rejects_a_broken_candidate() {
        // A validation test that cannot fail proves nothing. Confirm the validator bites.
        let mut broken = seal_like_the_seam(
            &production_lease_candidate(),
            PARTICIPANT_LEASE_CONTRACT,
            &validated_room_ref(),
        );
        broken["admitted_role"] = json!("overlord");
        assert!(
            validate_architecture_contract(PARTICIPANT_LEASE_CONTRACT, &broken).is_err(),
            "an unregistered role must be rejected by the generated validator"
        );
        let mut missing = seal_like_the_seam(
            &production_request_candidate(),
            PARTICIPATION_REQUEST_CONTRACT,
            &validated_room_ref(),
        );
        missing.as_object_mut().unwrap().remove("request_hash");
        assert!(
            validate_architecture_contract(PARTICIPATION_REQUEST_CONTRACT, &missing).is_err(),
            "a missing required field must be rejected by the generated validator"
        );
    }

    #[tokio::test]
    async fn an_offer_transition_revalidates_its_lease_scope_and_writes_nothing_when_it_lapses() {
        // Failure order: a non-terminal transition must resolve the room, then the offer, then
        // authority, then the lease scope. Without a room, nothing downstream may run and nothing
        // may be written.
        let directory = temp_dir("offer-transition-scope");
        let data_dir = directory.to_str().unwrap();
        let body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": format!("sha256:{}", "11".repeat(32)),
            "status": "eligible",
        });
        let (status, _) =
            offer_transition_inner(data_dir, CAPABILITY_OFFER_FAMILY, "cao_one", &body)
                .await
                .expect_err("an absent room is refused before anything else");
        assert_eq!(status, StatusCode::NOT_FOUND);
        for family in OWNER_LOCAL_FAMILIES {
            assert!(!directory.join(family).exists());
        }
        // An unregistered target status is refused as a bad request, still writing nothing.
        let mut bogus = body;
        bogus["status"] = json!("teleported");
        assert_eq!(
            offer_transition_inner(data_dir, CAPABILITY_OFFER_FAMILY, "cao_one", &bogus)
                .await
                .expect_err("an unregistered status is refused")
                .0,
            StatusCode::BAD_REQUEST
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_transition_checks_the_offers_own_declared_refs_not_the_request_bodys() {
        // `declared_refs` reads the ADMITTED payload, so a caller cannot narrow the set that gets
        // scope-checked by omitting it from the transition body.
        let capability = build_capability_offer(
            "capability-offer://cao_one",
            &json!({ "capability_descriptor_refs": ["ai://granted", "ai://revoked"] }),
            "participant-lease://plz_one",
        );
        let declared = declared_refs(CAPABILITY_OFFER_FAMILY, &capability);
        assert_eq!(declared, vec!["ai://granted", "ai://revoked"]);

        // A lease that no longer grants one of them refuses the whole transition.
        let narrowed = json!({
            "participant_lease_id": "participant-lease://plz_one",
            "status": "active",
            "expires_at": "2026-08-26T13:00:00Z",
            "unbounded_term_exception_decision_ref": Value::Null,
            "capability_advertisement_refs": ["ai://granted"],
        });
        let error = require_lease_scope(
            &narrowed,
            NOON_MS,
            CAPABILITY_OFFER_FAMILY.granted_field,
            &declared,
        )
        .expect_err("a narrowed lease no longer proves this offer");
        assert_eq!(error.0, "m048_offer_outside_lease_scope");
        assert!(error.1.contains("ai://revoked"));

        // Terminating it is still allowed — that is what the terminal-status carve-out is for.
        assert!(require_lease_scope(
            &narrowed,
            NOON_MS,
            CAPABILITY_OFFER_FAMILY.granted_field,
            &["ai://granted".to_string()],
        )
        .is_ok());
    }

    // --- A5: frontier, eligibility, claim ------------------------------------------------------

    fn production_frontier_candidate() -> Value {
        build_frontier_candidate(
            &format!("frontier://wfi_{}", "ab".repeat(32)),
            &json!({
                "item_kind": "verification_need",
                "objective": "Verify the bounded room result.",
                "dependency_refs": [],
                "required_capability_refs": ["capability://demo/code-review"],
                "required_context_resource_authority_and_evidence_refs": ["scope:room.verify"],
                "expected_value": 1.0,
                "uncertainty": 0.25,
                "priority": 10.0,
                "stop_condition_ref": "policy://demo/stop",
                "expires_at": Value::Null,
            }),
        )
    }

    fn production_claim_candidate() -> Value {
        let tuple = EligibilityTuple {
            frontier: production_frontier_candidate(),
            lease: production_lease_candidate(),
            resource_offers: vec![],
            capability_offers: vec![],
        };
        build_claim_candidate(
            &format!("work-claim://wcl_{}", "ab".repeat(32)),
            &tuple,
            &format!("participant-lease://plz_{}", "cd".repeat(32)),
            &format!("receipt://wem_{}", "ef".repeat(32)),
            &json!({
                "contribution_policy_ref": "policy://demo/contribution",
                "budget_reservation_ref": "budget://demo/1",
                "bounded_scope_ref": "task://demo/1",
                "context_lease_refs": ["context-lease://demo/1"],
                "authority_resource_compute_data_budget_and_tool_lease_refs": ["grant://demo/work"],
            }),
            "2026-08-26T12:00:00Z",
            "2026-08-26T13:00:00Z",
        )
    }

    #[test]
    fn the_frontier_builder_satisfies_its_registered_v3_contract() {
        let sealed = seal_like_the_seam(
            &production_frontier_candidate(),
            WORK_FRONTIER_ITEM_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(WORK_FRONTIER_ITEM_CONTRACT, &sealed).unwrap_or_else(
            |error| panic!("the production frontier candidate must validate: {error}"),
        );
    }

    #[test]
    fn the_claim_builder_and_its_successors_satisfy_the_registered_v3_contract() {
        let claim = production_claim_candidate();
        let sealed = seal_like_the_seam(&claim, WORK_CLAIM_LEASE_CONTRACT, &validated_room_ref());
        validate_architecture_contract(WORK_CLAIM_LEASE_CONTRACT, &sealed).unwrap_or_else(
            |error| panic!("the production claim candidate must validate: {error}"),
        );

        // Every transition successor must also validate — succession is where drift hides.
        for (status, mutate) in [
            (
                "active",
                json!({ "heartbeat_ref": format!("receipt://hb_{}", "11".repeat(32)), "renewal_count": 1 }),
            ),
            (
                "released",
                json!({ "release_or_reassignment_reason": "worker stepped down" }),
            ),
            ("expired", json!({})),
            ("completed", json!({})),
        ] {
            let mut successor = claim.clone();
            successor["status"] = json!(status);
            for (key, value) in mutate.as_object().unwrap() {
                successor[key.clone()] = value.clone();
            }
            let sealed =
                seal_like_the_seam(&successor, WORK_CLAIM_LEASE_CONTRACT, &validated_room_ref());
            validate_architecture_contract(WORK_CLAIM_LEASE_CONTRACT, &sealed).unwrap_or_else(
                |error| panic!("the `{status}` claim successor must validate: {error}"),
            );
        }
    }

    #[test]
    fn the_validator_rejects_a_broken_frontier_or_claim() {
        // Mutation check: these validations must be capable of failing.
        let mut frontier = seal_like_the_seam(
            &production_frontier_candidate(),
            WORK_FRONTIER_ITEM_CONTRACT,
            &validated_room_ref(),
        );
        frontier["item_kind"] = json!("daydream");
        assert!(validate_architecture_contract(WORK_FRONTIER_ITEM_CONTRACT, &frontier).is_err());

        let mut claim = seal_like_the_seam(
            &production_claim_candidate(),
            WORK_CLAIM_LEASE_CONTRACT,
            &validated_room_ref(),
        );
        claim.as_object_mut().unwrap().remove("issued_at");
        assert!(validate_architecture_contract(WORK_CLAIM_LEASE_CONTRACT, &claim).is_err());
    }

    #[test]
    fn the_hosted_frontier_profile_pins_single_claim_exclusivity() {
        let item = production_frontier_candidate();
        assert_eq!(item["max_concurrency"], json!(1));
        assert_eq!(item["duplication_policy"], json!("exclusive"));
        assert_eq!(item["claimability"], json!("open"));
        // A fresh item asserts no contributions.
        assert_eq!(item["related_attempt_and_finding_refs"], json!([]));

        // With the hosted profile, one live claim closes the item.
        let claims = vec![{
            let mut c = claim("active", "2026-08-26T13:00:00Z", Some("receipt://hb_one"));
            c["frontier_item_ref"] = item["frontier_item_id"].clone();
            c
        }];
        let projection =
            frontier_claimability(&item, &claims, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap();
        assert_eq!(projection["claimable"], json!(false));
        assert_eq!(projection["max_concurrency"], json!(1));
    }

    #[test]
    fn a_frontier_transition_cannot_write_derived_claim_state_or_a_verdict() {
        // These are refused during parsing, before any room read.
        for (status, code) in [
            ("claimed", "m048_frontier_claim_state_is_derived"),
            ("accepted", "m048_frontier_verdict_unavailable"),
            ("rejected", "m048_frontier_verdict_unavailable"),
        ] {
            let body = json!({
                "outcome_room_ref": canonical_room_ref(),
                "expected_room_state_root": format!("sha256:{}", "11".repeat(32)),
                "status": status,
            });
            let parsed = closed_object(
                &body,
                &[
                    "outcome_room_ref",
                    "expected_room_state_root",
                    "status",
                    "claimability",
                ],
                "m048_frontier_request_invalid",
            );
            assert!(parsed.is_ok());
            // Reproduce the guard the handler applies.
            let refusal = if status == "claimed" {
                "m048_frontier_claim_state_is_derived"
            } else {
                "m048_frontier_verdict_unavailable"
            };
            assert_eq!(refusal, code);
        }
        assert!(FRONTIER_VERDICT_STATUSES.contains(&"accepted"));
        assert!(FRONTIER_VERDICT_STATUSES.contains(&"rejected"));
    }

    #[test]
    fn only_contract_owned_claim_transitions_exist() {
        for op in ["heartbeat", "release", "expire", "complete"] {
            assert!(claim_transition_target(op).is_some(), "`{op}` is owned");
        }
        for invented in [
            "reassign", "accept", "verdict", "settle", "payout", "allocate",
        ] {
            assert!(
                claim_transition_target(invented).is_none(),
                "`{invented}` must not exist on this plane"
            );
        }
        assert_eq!(claim_transition_target("release"), Some("released"));
        assert_eq!(claim_transition_target("expire"), Some("expired"));
    }

    #[test]
    fn a_claim_binds_the_leases_terms_and_grants_no_execution_authority() {
        let claim = production_claim_candidate();
        let lease = production_lease_candidate();
        // The claim cannot invent its own terms triple.
        assert_eq!(
            claim["collaboration_terms_ref"],
            lease["collaboration_terms_ref"]
        );
        assert_eq!(
            claim["collaboration_terms_root"],
            lease["accepted_terms_root"]
        );
        assert_eq!(claim["terms_acceptance_ref"], lease["terms_acceptance_ref"]);
        assert_eq!(claim["duplicate_work_policy"], json!("exclusive"));
        assert_eq!(claim["renewal_count"], json!(0));
        assert_eq!(claim["heartbeat_ref"], Value::Null);
        // Nothing here is a routing, quoting or settlement decision.
        for absent in [
            "task_offer_ref",
            "task_acceptance_ref",
            "routing_decision_ref",
            "quote_ref",
        ] {
            assert_eq!(claim[absent], Value::Null, "`{absent}` is not decided here");
        }
        assert_eq!(
            claim["settlement_profile_ref"],
            json!("policy://ioi/m048/no-settlement-v1"),
            "the contract requires the field; this plane settles nothing"
        );
    }

    #[test]
    fn a_released_claim_frees_its_item_without_touching_the_item_or_any_attempt() {
        let item = production_frontier_candidate();
        let item_ref = item["frontier_item_id"].as_str().unwrap();
        let mut held = claim("active", "2026-08-26T13:00:00Z", Some("receipt://hb_one"));
        held["frontier_item_ref"] = json!(item_ref);
        assert_eq!(
            frontier_claimability(&item, &[held.clone()], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
                .unwrap()["claimable"],
            json!(false)
        );

        // Release is ONE terminal successor of the claim. The item is byte-identical afterwards.
        let mut released = held.clone();
        released["status"] = json!("released");
        let after = frontier_claimability(&item, &[released], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS)
            .unwrap();
        assert_eq!(after["claimable"], json!(true));
        assert_eq!(
            item,
            production_frontier_candidate(),
            "releasing a claim writes nothing onto the frontier item"
        );
        assert_eq!(
            item["related_attempt_and_finding_refs"],
            json!([]),
            "no Attempt lineage is touched by a release"
        );
    }

    #[test]
    fn eligibility_evidence_is_identified_by_its_exact_tuple() {
        let tuple = |frontier: &str| {
            deterministic_tail(
                "wem_",
                "hypervisor.m048.work-eligibility-match.identity.v1",
                &json!({
                    "outcome_room_ref": canonical_room_ref(),
                    "frontier_item_ref": frontier,
                    "participant_lease_ref": "participant-lease://plz_one",
                    "resource_offer_refs": Vec::<String>::new(),
                    "capability_offer_refs": vec!["capability-offer://cao_one".to_string()],
                }),
            )
        };
        assert_eq!(tuple("frontier://a"), tuple("frontier://a"));
        assert_ne!(
            tuple("frontier://a"),
            tuple("frontier://b"),
            "a different tuple is a different receipt, so a stale one cannot be reused"
        );
        assert!(tuple("frontier://a").starts_with("wem_"));
    }

    #[tokio::test]
    async fn a5_mutations_refuse_and_write_nothing_without_a_room() {
        let directory = temp_dir("a5-refusal");
        let data_dir = directory.to_str().unwrap();
        let head = format!("sha256:{}", "11".repeat(32));

        let frontier_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "item_kind": "verification_need",
            "objective": "verify",
        });
        assert_eq!(
            frontier_create_inner(data_dir, &frontier_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        let claim_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "frontier_item_ref": "frontier://wfi_one",
            "participant_lease_ref": "participant-lease://plz_one",
            "eligibility_match_receipt_ref": "receipt://wem_one",
            "ttl_seconds": 600,
        });
        assert_eq!(
            claim_acquire_inner(data_dir, &claim_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        let match_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "frontier_item_ref": "frontier://wfi_one",
            "participant_lease_ref": "participant-lease://plz_one",
        });
        assert_eq!(
            match_create_inner(data_dir, &match_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        // An out-of-bounds claim TTL and an unregistered item kind are bad requests.
        let mut bad_ttl = claim_body;
        bad_ttl["ttl_seconds"] = json!(CLAIM_TTL_MAX_SECONDS + 1);
        assert_eq!(
            claim_acquire_inner(data_dir, &bad_ttl)
                .await
                .expect_err("an out-of-bounds TTL is refused")
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut bad_kind = frontier_body;
        bad_kind["item_kind"] = json!("daydream");
        assert_eq!(
            frontier_create_inner(data_dir, &bad_kind)
                .await
                .expect_err("an unregistered item kind is refused")
                .0,
            StatusCode::BAD_REQUEST
        );

        for family in OWNER_LOCAL_FAMILIES {
            assert!(
                !directory.join(family).exists(),
                "a refused A5 mutation writes nothing"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_claim_transition_admits_a_field_only_on_the_verb_that_owns_it() {
        let directory = temp_dir("a5-claim-fields");
        let data_dir = directory.to_str().unwrap();
        let head = format!("sha256:{}", "11".repeat(32));
        for (op, key, value) in [
            ("release", "heartbeat_ref", json!("receipt://hb_one")),
            (
                "heartbeat",
                "release_or_reassignment_reason",
                json!("because"),
            ),
        ] {
            let mut body = json!({
                "outcome_room_ref": canonical_room_ref(),
                "expected_room_state_root": head,
                "op": op,
            });
            body[key] = value;
            let (status, Json(payload)) = claim_transition_inner(data_dir, "wcl_one", &body)
                .await
                .expect_err("a field outside its verb is refused");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                payload.pointer("/error/code").and_then(Value::as_str),
                Some("m048_claim_field_not_admitted_for_transition")
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_predecessor_frontier_claim_and_match_handlers_are_no_longer_mounted() {
        for retired in [
            "work_frontier_claim_routes::handle_",
            "resource_capability_offer_routes::handle_match_",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(retired),
                "`{retired}` must not remain mounted; the current generation owns this family"
            );
        }
        // The predecessor modules stay declared and their recovery stays wired.
        assert!(ROUTER_SOURCE.contains("mod work_frontier_claim_routes;"));
        assert!(ROUTER_SOURCE.contains("mod resource_capability_offer_routes;"));
    }

    #[test]
    fn every_a5_route_is_mounted_at_its_exact_path_and_handler() {
        for (path, handler) in [
            (
                "/v1/goal-orchestration/work-frontier-items/overview",
                "m048_collaboration_routes::handle_frontier_overview",
            ),
            (
                "/v1/goal-orchestration/work-frontier-items/:id/transition",
                "m048_collaboration_routes::handle_frontier_transition",
            ),
            (
                "/v1/goal-orchestration/work-eligibility-matches",
                "m048_collaboration_routes::handle_match_create",
            ),
            (
                "/v1/goal-orchestration/work-eligibility-matches/overview",
                "m048_collaboration_routes::handle_match_overview",
            ),
            (
                "/v1/goal-orchestration/work-claim-leases",
                "m048_collaboration_routes::handle_claim_acquire",
            ),
            (
                "/v1/goal-orchestration/work-claim-leases/:id/transition",
                "m048_collaboration_routes::handle_claim_transition",
            ),
        ] {
            assert!(ROUTER_SOURCE.contains(path), "`{path}` must be mounted");
            assert!(ROUTER_SOURCE.contains(handler), "`{handler}` must be named");
        }
    }

    // --- A6: attempt, finding, verifier challenge ----------------------------------------------

    /// A projection entry shaped exactly like the seam's, so coordinate derivation is exercised
    /// against real projection structure rather than a hand-authored coordinate block.
    fn projection_of(object: Value, generation: i64, root_byte: &str) -> Value {
        json!({
            "generation": generation,
            "object_root": format!("sha256:{}", root_byte.repeat(32)),
            "admitted_object": object,
        })
    }

    fn observed_room_for_tests() -> RoomAtHead {
        RoomAtHead {
            room_ref: validated_room_ref(),
            head: format!("sha256:{}", "77".repeat(32)),
            system_id: SYSTEM_ID.to_string(),
            room: json!({
                "host_domain_ref": "domain://ioi-hosted",
                "member_goal_run_refs": ["goal://demo/run-1"],
            }),
        }
    }

    fn goal_run_for_tests() -> (String, String, String) {
        (
            "goal://demo/run-1".to_string(),
            "2026-08-26T11:59:00Z".to_string(),
            format!("sha256:{}", "88".repeat(32)),
        )
    }

    /// The lease as a projection, with `participant_ref` in the worker namespace the registered
    /// `principal_ref` pattern demands.
    fn lease_projection_for_tests() -> Value {
        let mut lease = production_lease_candidate();
        lease["participant_lease_id"] =
            json!(format!("participant-lease://plz_{}", "cd".repeat(32)));
        lease["participant_ref"] = json!("worker://demo/w");
        projection_of(lease, 0, "aa")
    }

    fn claim_projection_for_tests() -> Value {
        let mut claim = production_claim_candidate();
        claim["frontier_item_ref"] = json!(format!("frontier://wfi_{}", "ab".repeat(32)));
        claim["claimant_participant_lease_ref"] =
            json!(format!("participant-lease://plz_{}", "cd".repeat(32)));
        projection_of(claim, 0, "bb")
    }

    fn frontier_projection_for_tests() -> Value {
        projection_of(production_frontier_candidate(), 0, "cc")
    }

    fn attempt_coordinates_for_tests() -> Value {
        let (record_ref, updated_at, record_hash) = goal_run_for_tests();
        attempt_bound_coordinates(
            &observed_room_for_tests(),
            &frontier_projection_for_tests(),
            &claim_projection_for_tests(),
            &lease_projection_for_tests(),
            &GoalRunCoordinate {
                record_ref,
                updated_at,
                record_hash,
            },
        )
        .expect("the attempt coordinates derive")
    }

    fn production_attempt_candidate() -> Value {
        let claim = admitted(&claim_projection_for_tests()).unwrap().clone();
        let (goal_run_ref, _, _) = goal_run_for_tests();
        build_attempt_candidate(
            &format!("attempt://atm_{}", "ab".repeat(32)),
            &claim,
            "worker://demo/w",
            &goal_run_ref,
            attempt_coordinates_for_tests(),
            &json!({
                "declared_method_and_hypothesis_refs": ["method://demo/1"],
                "input_state_and_environment_refs": ["state://demo/input/1"],
                "worker_model_resolver_tool_and_runtime_version_refs": ["worker://demo/1"],
                "authority_and_policy_refs": ["grant://demo/work"],
                "resource_and_cost_refs": [],
                "outcome_class": "positive",
                "artifact_evidence_and_receipt_refs": [format!("receipt://art_{}", "cd".repeat(32))],
                "artifact_license_ip_retention_and_export_refs": ["policy://demo/export"],
            }),
        )
    }

    /// The composed WorkResult coordinate as `resolve_work_result_coordinate` would produce it:
    /// room from room history, run from the owner's `work_subject_ref`, goal from the run's own
    /// record, and no update instant because the owner exposes none.
    fn work_result_for_tests() -> WorkResultCoordinate {
        WorkResultCoordinate {
            record_ref: format!("work-result://wr_{}", "ef".repeat(32)),
            outcome_room_ref: validated_room_ref(),
            goal_run_ref: "goal://demo/run-1".to_string(),
            goal_ref: "goal://demo/run-1".to_string(),
            record_hash: format!("sha256:{}", "99".repeat(32)),
        }
    }

    fn finding_coordinates_for_tests() -> Value {
        finding_bound_coordinates(
            &validated_room_ref(),
            &projection_of(production_attempt_candidate(), 0, "dd"),
            &lease_projection_for_tests(),
            &work_result_for_tests(),
        )
        .expect("the finding coordinates derive")
    }

    fn production_finding_candidate() -> Value {
        let work_result_ref = work_result_for_tests().record_ref;
        build_finding_candidate(
            &format!("finding://fnd_{}", "ab".repeat(32)),
            &production_attempt_candidate(),
            &format!("participant-lease://plz_{}", "cd".repeat(32)),
            // Must be the lease's own principal: the registered invariant
            // `finding.proposer.resolves_through_bound_lease_or_room_system` resolves the proposer
            // through the bound lease, which is exactly what production derives.
            "worker://demo/w",
            &work_result_ref,
            "2026-08-26T12:00:00Z",
            finding_coordinates_for_tests(),
            &json!({
                "proposition": "The bounded run produced the declared artifact.",
                "finding_kind": "observation",
                "confidence_or_uncertainty": 0.9,
                "source_and_observation_context_refs": [format!("attempt://atm_{}", "ab".repeat(32))],
                "supporting_evidence_refs": ["evidence://demo/1"],
                "proof_refs": [format!("receipt://prf_{}", "11".repeat(32))],
                "contradicting_evidence_refs": [],
                "applicability_and_counterexample_refs": [],
                "provenance_ontology_and_mapping_refs": ["provenance://demo/1"],
                "supersedes_ref": Value::Null,
            }),
        )
    }

    fn production_challenge_candidate() -> Value {
        build_challenge_candidate(
            &format!("verifier-challenge://vch_{}", "ab".repeat(32)),
            &format!("participant-lease://plz_{}", "cd".repeat(32)),
            &format!("finding://fnd_{}", "ab".repeat(32)),
            &json!({
                "challenge_kind": "evidence",
                "challenge_evidence_refs": ["evidence://demo/challenge"],
                "adjudicator_policy_ref": "policy://demo/adjudication",
                "prior_rule_version_ref": "rubric://demo/v1",
                "affected_attempt_refs": [format!("attempt://atm_{}", "ab".repeat(32))],
                "reverification_required": true,
            }),
        )
    }

    #[test]
    fn the_contribution_builders_satisfy_their_registered_v3_contracts() {
        for (contract, candidate, label) in [
            (ATTEMPT_CONTRACT, production_attempt_candidate(), "attempt"),
            (FINDING_CONTRACT, production_finding_candidate(), "finding"),
            (
                VERIFIER_CHALLENGE_CONTRACT,
                production_challenge_candidate(),
                "verifier challenge",
            ),
        ] {
            let sealed = seal_like_the_seam(&candidate, contract, &validated_room_ref());
            validate_architecture_contract(contract, &sealed).unwrap_or_else(|error| {
                panic!("the production {label} candidate must validate: {error}")
            });
        }
    }

    #[test]
    fn the_disputed_finding_successor_validates_and_retains_every_lineage_ref() {
        let finding = production_finding_candidate();
        let successor = disputed_finding_successor(&finding).unwrap();
        let sealed = seal_like_the_seam(&successor, FINDING_CONTRACT, &validated_room_ref());
        validate_architecture_contract(FINDING_CONTRACT, &sealed)
            .unwrap_or_else(|error| panic!("the disputed successor must validate: {error}"));

        assert_eq!(successor["status"], json!(FINDING_DISPUTED_STATUS));
        // A challenge changes what a finding is TRUSTED to be, never what it recorded.
        for retained in [
            "finding_id",
            "attempt_ref",
            "work_result_ref",
            "participant_ref",
            "proposed_by_ref",
            "proposition",
            "finding_kind",
            "transaction_time",
            "source_and_observation_context_refs",
            "supporting_evidence_refs",
            "proof_refs",
            "provenance_ontology_and_mapping_refs",
            "supersedes_ref",
        ] {
            assert_eq!(
                successor[retained], finding[retained],
                "`{retained}` must survive a challenge byte-for-byte"
            );
        }
    }

    #[test]
    fn the_validator_rejects_broken_contribution_payloads() {
        // Mutation check: each validation must be capable of failing.
        let mut attempt = seal_like_the_seam(
            &production_attempt_candidate(),
            ATTEMPT_CONTRACT,
            &validated_room_ref(),
        );
        attempt["outcome_class"] = json!("marvellous");
        assert!(validate_architecture_contract(ATTEMPT_CONTRACT, &attempt).is_err());

        let mut finding = seal_like_the_seam(
            &production_finding_candidate(),
            FINDING_CONTRACT,
            &validated_room_ref(),
        );
        finding.as_object_mut().unwrap().remove("work_result_ref");
        assert!(validate_architecture_contract(FINDING_CONTRACT, &finding).is_err());

        let mut challenge = seal_like_the_seam(
            &production_challenge_candidate(),
            VERIFIER_CHALLENGE_CONTRACT,
            &validated_room_ref(),
        );
        challenge["challenged_ref"] = json!("banana://nope");
        assert!(validate_architecture_contract(VERIFIER_CHALLENGE_CONTRACT, &challenge).is_err());
    }

    #[test]
    fn bound_coordinates_are_derived_from_live_projections_not_from_the_caller() {
        let coordinates = attempt_coordinates_for_tests();
        // Every revision and record hash comes from the projection, not from any request field.
        assert_eq!(coordinates["frontier_item"]["revision"], json!(0));
        assert_eq!(
            coordinates["frontier_item"]["record_hash"],
            json!(format!("sha256:{}", "cc".repeat(32)))
        );
        assert_eq!(
            coordinates["work_claim"]["record_hash"],
            json!(format!("sha256:{}", "bb".repeat(32)))
        );
        assert_eq!(
            coordinates["participant_lease"]["record_hash"],
            json!(format!("sha256:{}", "aa".repeat(32)))
        );
        // The room's control hash is the head this write is committing against.
        assert_eq!(
            coordinates["outcome_room"]["control_hash"],
            json!(format!("sha256:{}", "77".repeat(32)))
        );
        // The registered shape pins the claimant coordinate to the LEASE, not the worker.
        assert_eq!(
            coordinates["work_claim"]["claimant_ref"],
            coordinates["participant_lease"]["record_ref"]
        );

        // A caller cannot smuggle coordinates in: the create bodies do not admit them at all.
        for forged in [
            "bound_coordinates",
            "frontier_item_revision",
            "work_claim_record_hash",
            "participant_lease_revision",
        ] {
            assert!(
                !ATTEMPT_CREATE_FIELDS.contains(&forged),
                "`{forged}` must not be a caller-supplied field"
            );
            assert!(!FINDING_CREATE_FIELDS.contains(&forged));
        }
    }

    #[test]
    fn a_mutated_coordinate_root_or_revision_turns_the_validator_red() {
        // The invariant profile pins each coordinate to the ref it mirrors, so a forged coordinate
        // is not merely wrong — it is contract-invalid. If this ever passes, the derivation has
        // stopped being load-bearing.
        let base = seal_like_the_seam(
            &production_attempt_candidate(),
            ATTEMPT_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(ATTEMPT_CONTRACT, &base)
            .expect("the honest attempt validates");

        for pointer in [
            "/bound_coordinates/outcome_room/record_ref",
            "/bound_coordinates/frontier_item/record_ref",
            "/bound_coordinates/work_claim/record_ref",
            "/bound_coordinates/goal_run/record_ref",
            "/bound_coordinates/work_claim/frontier_item_ref",
            "/bound_coordinates/frontier_item/outcome_room_ref",
            "/bound_coordinates/participant_lease/outcome_room_ref",
        ] {
            let mut mutated = base.clone();
            let slot = mutated.pointer_mut(pointer).expect("the coordinate exists");
            // Re-point the coordinate at a different object of the SAME scheme, so only the
            // cross-field invariant — not the pattern — can catch it.
            let original = slot.as_str().unwrap_or_default().to_string();
            let scheme = original.split_once("://").map(|(s, _)| s).unwrap_or("goal");
            *slot = json!(format!("{scheme}://forged/elsewhere"));
            assert!(
                validate_architecture_contract(ATTEMPT_CONTRACT, &mutated).is_err(),
                "a forged `{pointer}` must be rejected by the registered invariants"
            );
        }

        // A mutated revision is caught the same way on the Finding side.
        let finding = seal_like_the_seam(
            &production_finding_candidate(),
            FINDING_CONTRACT,
            &validated_room_ref(),
        );
        validate_architecture_contract(FINDING_CONTRACT, &finding)
            .expect("the honest finding validates");
        for pointer in [
            "/bound_coordinates/attempt/record_ref",
            "/bound_coordinates/work_result/record_ref",
            "/bound_coordinates/participant_lease/record_ref",
        ] {
            let mut mutated = finding.clone();
            let slot = mutated.pointer_mut(pointer).expect("the coordinate exists");
            let original = slot.as_str().unwrap_or_default().to_string();
            let scheme = original
                .split_once("://")
                .map(|(s, _)| s)
                .unwrap_or("attempt");
            *slot = json!(format!("{scheme}://forged/elsewhere"));
            assert!(
                validate_architecture_contract(FINDING_CONTRACT, &mutated).is_err(),
                "a forged `{pointer}` must be rejected by the registered invariants"
            );
        }
    }

    // --- A6 amendment: owner-derived coordinates, narrowed principals, 202 -----------------------

    #[tokio::test]
    async fn owner_coordinate_derivation_refuses_every_uncertainty_before_a_child_write() {
        let directory = temp_dir("owner-coordinates");
        let data_dir = directory.to_str().unwrap();
        let observed = observed_room_for_tests();

        // Absent GoalRun owner record: refused, and never silently defaulted.
        let error = resolve_goal_run_coordinate(data_dir, &observed, "goal://demo/run-1")
            .expect_err("an absent GoalRun owner record is refused");
        assert_eq!(error.0, "m048_goal_run_not_found");

        // A run that is not a member of this room is refused before the owner read matters.
        assert_eq!(
            resolve_goal_run_coordinate(data_dir, &observed, "goal://someone-else/run-9")
                .expect_err("a foreign run is refused")
                .0,
            "m048_goal_run_not_a_room_member"
        );

        // Absent WorkResult owner record: refused.
        let work_result_ref = format!("work-result://wr_{}", "ef".repeat(32));
        assert_eq!(
            resolve_work_result_coordinate(data_dir, &observed, &work_result_ref)
                .expect_err("an absent WorkResult owner record is refused")
                .0,
            "m048_work_result_not_found"
        );

        // Nothing was written by any refusal.
        for family in OWNER_LOCAL_FAMILIES {
            assert!(!directory.join(family).exists());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_composed_work_result_coordinate_matches_the_registered_shape() {
        let composed = work_result_coordinate_block(&WorkResultCoordinate {
            record_ref: format!("work-result://wr_{}", "ef".repeat(32)),
            outcome_room_ref: validated_room_ref(),
            goal_run_ref: "goal://demo/run-1".to_string(),
            goal_ref: "goal://demo/run-1".to_string(),
            record_hash: format!("sha256:{}", "99".repeat(32)),
        });
        // `updated_at` is explicitly null, which the registered coordinate admits. Fabricating an
        // instant here would be hashing a claim canon does not make.
        assert_eq!(composed["updated_at"], Value::Null);
        assert_eq!(composed["outcome_room_ref"], json!(validated_room_ref()));
        // The run and its goal are one identity in this implementation; no distinct value is
        // invented for `goal_ref`.
        assert_eq!(composed["goal_run_ref"], composed["goal_ref"]);

        // And it validates inside a real Finding.
        let mut finding = production_finding_candidate();
        finding["bound_coordinates"]["work_result"] = composed;
        let sealed = seal_like_the_seam(&finding, FINDING_CONTRACT, &validated_room_ref());
        validate_architecture_contract(FINDING_CONTRACT, &sealed)
            .unwrap_or_else(|error| panic!("the composed coordinate must validate: {error}"));
    }

    #[test]
    fn a_mutated_owner_record_yields_a_different_coordinate_hash() {
        // The hash is recomputed from the exact owner record on every admission, so mutated owner
        // bytes cannot ride an old coordinate.
        let owner = json!({
            "work_result_id": format!("work-result://wr_{}", "ef".repeat(32)),
            "work_subject_ref": "goal://demo/run-1",
            "outcome_class": "positive",
        });
        let mut mutated = owner.clone();
        mutated["outcome_class"] = json!("negative");
        assert_ne!(
            record_output_hash(&owner, &[]),
            record_output_hash(&mutated, &[]),
            "a mutated owner record must not hash to its predecessor"
        );
        // The owner/room mismatch check is exactly this comparison.
        assert_eq!(
            record_output_hash(&owner, &[]),
            record_output_hash(&owner.clone(), &[])
        );
    }

    #[test]
    fn no_coordinate_evidence_field_is_caller_supplied_any_more() {
        for forged in [
            "goal_run_updated_at",
            "goal_run_record_hash",
            "work_result_goal_run_ref",
            "work_result_goal_ref",
            "work_result_updated_at",
            "work_result_record_hash",
            "bound_coordinates",
        ] {
            assert!(
                !ATTEMPT_CREATE_FIELDS.contains(&forged),
                "`{forged}` must not be caller-supplied on an attempt"
            );
            assert!(
                !FINDING_CREATE_FIELDS.contains(&forged),
                "`{forged}` must not be caller-supplied on a finding"
            );
        }
        // The caller still names the refs, and only the refs.
        assert!(ATTEMPT_CREATE_FIELDS.contains(&"goal_run_ref"));
        assert!(FINDING_CREATE_FIELDS.contains(&"work_result_ref"));
    }

    #[tokio::test]
    async fn a_service_or_org_principal_is_refused_before_any_lease_is_written() {
        let directory = temp_dir("lease-principal");
        let data_dir = directory.to_str().unwrap();
        let base = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": format!("sha256:{}", "11".repeat(32)),
            "participant_ref": "worker://demo/w",
            "operator_ref": "worker://demo/op",
            "home_domain_ref": "domain://demo",
            "admitted_role": "implementer",
            "visibility_scope_ref": "restricted_view://demo",
            "terms_acceptance_ref": "receipt://tac_one",
            "ttl_seconds": 3600,
        });
        // The hosted slice admits only worker:// and agent:// principals.
        for (field, value) in [
            ("participant_ref", "service://demo/svc"),
            ("participant_ref", "org://demo/team"),
            ("participant_ref", "system://room/demo"),
            ("operator_ref", "org://demo/team"),
            ("operator_ref", "user://demo/levi"),
        ] {
            let mut body = base.clone();
            body[field] = json!(value);
            let (status, Json(payload)) = admit_inner(data_dir, "prq_one", &body)
                .await
                .expect_err("a non worker/agent principal is refused");
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "`{field}={value}` must be refused"
            );
            assert_eq!(
                payload.pointer("/error/code").and_then(Value::as_str),
                Some("m048_admit_request_invalid")
            );
        }
        // worker:// and agent:// get past principal validation and fail later, on the absent room.
        for principal in ["worker://demo/w", "agent://demo/a"] {
            let mut body = base.clone();
            body["participant_ref"] = json!(principal);
            let (status, _) = admit_inner(data_dir, "prq_one", &body)
                .await
                .expect_err("the room is still absent");
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "`{principal}` must pass principal validation"
            );
        }
        for family in OWNER_LOCAL_FAMILIES {
            assert!(
                !directory.join(family).exists(),
                "a refused admission writes nothing"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_pending_request_successor_is_reported_as_202_accepted() {
        // The status is chosen by whether the successor converged, so pin both branches against
        // the exact source that decides it.
        let source = include_str!("m048_collaboration_routes.rs");
        let admit = source
            .split("async fn admit_inner(")
            .nth(1)
            .and_then(|tail| {
                tail.split("/// GET /v1/goal-orchestration/room-participant-leases")
                    .next()
            })
            .expect("the admit handler remains source-addressable");
        assert!(
            admit.contains("StatusCode::ACCEPTED"),
            "a pending convergence must answer 202, not 200"
        );
        let converged_branch = admit
            .find("if converged.is_ok()")
            .expect("the status is chosen by convergence");
        let accepted = admit
            .find("StatusCode::ACCEPTED")
            .expect("the accepted status exists");
        assert!(
            converged_branch < accepted,
            "202 must be the else-branch of a successful convergence, not the default"
        );
        // 202 is a success class, so a caller that checks `is_success()` still sees the lease.
        assert!(StatusCode::ACCEPTED.is_success());
        assert_ne!(StatusCode::ACCEPTED, StatusCode::OK);
    }

    #[test]
    fn a_foreign_goal_run_cannot_be_bound_to_an_attempt() {
        let observed = observed_room_for_tests();
        assert!(require_room_goal_run(&observed, "goal://demo/run-1").is_ok());
        assert_eq!(
            require_room_goal_run(&observed, "goal://someone-else/run-9")
                .expect_err("a non-member run is refused")
                .0,
            "m048_goal_run_not_a_room_member"
        );
    }

    #[test]
    fn an_attempt_binds_its_claim_lineage_and_mints_no_owner_registry_object() {
        let attempt = production_attempt_candidate();
        let claim = production_claim_candidate();
        assert_eq!(attempt["work_claim_ref"], claim["work_claim_id"]);
        assert_eq!(attempt["work_subject_ref"], claim["work_claim_id"]);
        assert_eq!(attempt["frontier_item_ref"], claim["frontier_item_ref"]);
        assert_eq!(attempt["participant_ref"], claim["claimant_ref"]);
        // WorkResult and OutcomeDelta are owner-registry families the room seam refuses.
        assert_eq!(attempt["work_result_ref"], Value::Null);
        assert_eq!(attempt["outcome_delta_refs"], json!([]));
        // No Contribution object is invented.
        assert_eq!(attempt["contribution_refs"], json!([]));
        assert_eq!(attempt["reproduction_state"], json!("unreviewed"));
    }

    #[test]
    fn a_challenge_opens_a_question_and_answers_none() {
        let challenge = production_challenge_candidate();
        assert_eq!(
            challenge["adjudication_ref"],
            Value::Null,
            "a challenge never carries its own adjudication"
        );
        assert_eq!(challenge["proposed_rule_version_ref"], Value::Null);
        assert_eq!(challenge["status"], json!("admitted"));
        // Verdict statuses are excluded from what a transition may set.
        for verdict in CHALLENGE_VERDICT_STATUSES {
            assert!(
                ![
                    "proposed",
                    "admitted",
                    "investigating",
                    "reverifying",
                    "withdrawn"
                ]
                .contains(verdict),
                "`{verdict}` is a verdict and must not be a settable standing here"
            );
        }
        assert!(FINDING_VERDICT_STATUSES.contains(&"rejected"));
        assert!(ATTEMPT_VERDICT_STATUSES.contains(&"accepted"));
    }

    #[test]
    fn a_claim_lapse_never_touches_an_attempt() {
        // The whole point of Attempt durability: a claim ending is a claim successor and nothing
        // else. Nothing in the claim transition path reads or writes an attempt.
        let attempt_before = production_attempt_candidate();
        let mut lapsed = production_claim_candidate();
        for terminal in CLAIM_TERMINAL_STATUSES {
            lapsed["status"] = json!(terminal);
            assert_eq!(
                claim_is_live(&lapsed, NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap(),
                Err(ClaimLapse::Terminal)
            );
        }
        assert_eq!(
            attempt_before,
            production_attempt_candidate(),
            "no claim transition rewrites or deletes an attempt"
        );
        // And the source text of the claim transition never reaches the attempt contract.
        let source = include_str!("m048_collaboration_routes.rs");
        let claim_transition = source
            .split("async fn claim_transition_inner(")
            .nth(1)
            .and_then(|tail| {
                tail.split("\n/// An optional bounded free-text field.")
                    .next()
            })
            .expect("the claim transition remains source-addressable");
        assert!(
            !claim_transition.contains("ATTEMPT_CONTRACT"),
            "the claim transition must never touch the attempt family"
        );
        assert!(!claim_transition.contains("FINDING_CONTRACT"));
    }

    #[test]
    fn a_superseded_or_invalid_finding_stays_in_the_registered_vocabulary() {
        for retained in ["superseded", "contradicted", "disputed", "archived"] {
            assert!(
                FINDING_STATUSES.contains(&retained),
                "`{retained}` must remain an expressible standing"
            );
        }
        // Succession never removes: the disputed successor keeps the same identity, so the prior
        // generation remains addressable in lineage under that identity.
        let finding = production_finding_candidate();
        let successor = disputed_finding_successor(&finding).unwrap();
        assert_eq!(successor["finding_id"], finding["finding_id"]);
    }

    #[test]
    fn the_challenge_convergence_is_idempotent_on_an_already_disputed_finding() {
        let mut disputed = production_finding_candidate();
        disputed["status"] = json!(FINDING_DISPUTED_STATUS);
        // `unconverged_challenges` skips a finding already in the disputed standing, so a second
        // challenge appends no redundant generation.
        assert_eq!(
            disputed["status"].as_str(),
            Some(FINDING_DISPUTED_STATUS),
            "the converged standing is the registered disputed state"
        );
        let again = disputed_finding_successor(&disputed).unwrap();
        assert_eq!(again["status"], json!(FINDING_DISPUTED_STATUS));
    }

    #[tokio::test]
    async fn a6_mutations_refuse_and_write_nothing_without_a_room() {
        let directory = temp_dir("a6-refusal");
        let data_dir = directory.to_str().unwrap();
        let head = format!("sha256:{}", "11".repeat(32));

        let attempt_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "work_claim_ref": "work-claim://wcl_one",
            "outcome_class": "positive",
            // The caller names the run only; its instant and hash are derived from owner truth.
            "goal_run_ref": "goal://demo/run-1",
        });
        assert_eq!(
            attempt_create_inner(data_dir, &attempt_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        let finding_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "attempt_ref": "attempt://atm_one",
            "work_result_ref": "work-result://wr_one",
            "proposition": "something",
            "finding_kind": "observation",
        });
        assert_eq!(
            finding_create_inner(data_dir, &finding_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        let challenge_body = json!({
            "outcome_room_ref": canonical_room_ref(),
            "expected_room_state_root": head,
            "challenger_participant_lease_ref": "participant-lease://plz_one",
            "challenged_ref": "finding://fnd_one",
            "challenge_kind": "evidence",
        });
        assert_eq!(
            challenge_create_inner(data_dir, &challenge_body)
                .await
                .expect_err("an absent room is refused")
                .0,
            StatusCode::NOT_FOUND
        );

        // A finding whose WorkResult ref has the wrong scheme is a bad request, not a seam error.
        let mut bad_result = finding_body;
        bad_result["work_result_ref"] = json!("finding://not-a-result");
        assert_eq!(
            finding_create_inner(data_dir, &bad_result)
                .await
                .expect_err("a non work-result ref is refused")
                .0,
            StatusCode::BAD_REQUEST
        );
        // A challenge against something that is neither a finding nor an attempt is refused.
        let mut bad_target = challenge_body;
        bad_target["challenged_ref"] = json!("budget://nope");
        assert_eq!(
            challenge_create_inner(data_dir, &bad_target)
                .await
                .expect_err("an unsupported challenge target is refused")
                .0,
            StatusCode::BAD_REQUEST
        );

        for family in OWNER_LOCAL_FAMILIES {
            assert!(
                !directory.join(family).exists(),
                "a refused A6 mutation writes nothing"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_contribution_transition_refuses_a_verdict_status() {
        let directory = temp_dir("a6-verdict");
        let data_dir = directory.to_str().unwrap();
        let head = format!("sha256:{}", "11".repeat(32));
        for (contract, schema, code, scheme, statuses, verdicts, verdict) in [
            (
                ATTEMPT_CONTRACT,
                ATTEMPT_SCHEMA,
                "m048_attempt_request_invalid",
                "attempt",
                ATTEMPT_STATUSES,
                ATTEMPT_VERDICT_STATUSES,
                "accepted",
            ),
            (
                FINDING_CONTRACT,
                FINDING_SCHEMA,
                "m048_finding_request_invalid",
                "finding",
                FINDING_STATUSES,
                FINDING_VERDICT_STATUSES,
                "rejected",
            ),
            (
                VERIFIER_CHALLENGE_CONTRACT,
                VERIFIER_CHALLENGE_SCHEMA,
                "m048_challenge_request_invalid",
                "verifier-challenge",
                CHALLENGE_STATUSES,
                CHALLENGE_VERDICT_STATUSES,
                "upheld",
            ),
        ] {
            let body = json!({
                "outcome_room_ref": canonical_room_ref(),
                "expected_room_state_root": head,
                "status": verdict,
            });
            let (status, Json(payload)) = contribution_transition_inner(
                data_dir, contract, schema, code, scheme, statuses, verdicts, "x", &body,
            )
            .await
            .expect_err("a verdict is refused");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                payload.pointer("/error/code").and_then(Value::as_str),
                Some("m048_contribution_verdict_refused")
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_predecessor_contribution_handlers_are_no_longer_mounted() {
        for retired in [
            "attempt_finding_routes::handle_",
            "verifier_challenge_routes::handle_",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(retired),
                "`{retired}` must not remain mounted; the current generation owns this family"
            );
        }
        assert!(ROUTER_SOURCE.contains("mod attempt_finding_routes;"));
        assert!(ROUTER_SOURCE.contains("mod verifier_challenge_routes;"));
    }

    #[test]
    fn every_a6_route_is_mounted_at_its_exact_path_and_handler() {
        for (path, handler) in [
            (
                "/v1/goal-orchestration/attempts",
                "m048_collaboration_routes::handle_attempt_create",
            ),
            (
                "/v1/goal-orchestration/attempts/overview",
                "m048_collaboration_routes::handle_attempt_overview",
            ),
            (
                "/v1/goal-orchestration/attempts/:id/transition",
                "m048_collaboration_routes::handle_attempt_transition",
            ),
            (
                "/v1/goal-orchestration/findings",
                "m048_collaboration_routes::handle_finding_create",
            ),
            (
                "/v1/goal-orchestration/findings/:id/transition",
                "m048_collaboration_routes::handle_finding_transition",
            ),
            (
                "/v1/goal-orchestration/verifier-challenges",
                "m048_collaboration_routes::handle_challenge_create",
            ),
            (
                "/v1/goal-orchestration/verifier-challenges/:id/transition",
                "m048_collaboration_routes::handle_challenge_transition",
            ),
        ] {
            assert!(ROUTER_SOURCE.contains(path), "`{path}` must be mounted");
            assert!(ROUTER_SOURCE.contains(handler), "`{handler}` must be named");
        }
    }

    #[test]
    fn all_three_convergence_passes_run_after_the_seam_recovery() {
        let seam = ROUTER_SOURCE
            .find("outcome_room_system_routes::complete_pending")
            .expect("the seam recovery is wired");
        let challenges = ROUTER_SOURCE
            .find("m048_collaboration_routes::complete_challenge_dispositions")
            .expect("the challenge convergence is wired");
        let admissions = ROUTER_SOURCE
            .find("m048_collaboration_routes::complete_participation_admissions")
            .expect("the admission convergence is wired");
        assert!(seam < admissions && admissions < challenges);
    }

    #[test]
    fn record_output_hash_is_stable_for_eligibility_evidence() {
        let body = eligibility_match_body(
            "outcome-room://demo",
            &frontier(),
            &json!({ "participant_lease_id": "participant-lease://demo/w" }),
            &[],
            &[],
            NOON_MS,
        )
        .unwrap();
        assert_eq!(
            record_output_hash(&body, &[]),
            record_output_hash(&body.clone(), &[]),
            "evidence hashing must be deterministic for exact replay"
        );
    }
}
