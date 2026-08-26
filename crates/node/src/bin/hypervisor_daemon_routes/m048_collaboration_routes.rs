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

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::governed_authority as governed;
use super::outcome_room_routes::{self as rooms, record_output_hash, reject_sensitive_keys, VErr};
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
    if wallet_now_ms >= rfc3339_to_ms(expires_at)? {
        return Ok(Err(ClaimLapse::Expired));
    }
    // A heartbeat is a `receipt://` ref plus the instant it was last observed. An absent heartbeat
    // is a lapse, not a pass: a claim that has never proven liveness has not proven liveness.
    let heartbeat_at = match claim
        .get("heartbeat_observed_at_ms")
        .and_then(Value::as_u64)
    {
        Some(observed) => observed,
        None => return Ok(Err(ClaimLapse::HeartbeatStale)),
    };
    let deadline = wallet_deadline_ms(heartbeat_at, heartbeat_max_seconds)?;
    if wallet_now_ms >= deadline {
        return Ok(Err(ClaimLapse::HeartbeatStale));
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

/// POST /v1/goal-orchestration/room-participation-requests/:id/admit
pub(crate) async fn handle_participation_request_admit(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Path(_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = room_system::request_principal(&state.data_dir, &headers) {
        return classify(error);
    }
    participation_step_unavailable("admit")
}

#[cfg(test)]
mod m048_tests {
    use super::super::outcome_room_routes::is_rfc3339;
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ioi-m048-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn claim(status: &str, expires_at: &str, heartbeat_ms: Option<u64>) -> Value {
        let mut claim = json!({
            "work_claim_id": "work-claim://demo/1",
            "frontier_item_ref": "frontier://demo/1",
            "status": status,
            "expires_at": expires_at,
        });
        if let Some(observed) = heartbeat_ms {
            claim["heartbeat_observed_at_ms"] = json!(observed);
            claim["heartbeat_ref"] = json!("receipt://demo/heartbeat-1");
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
            Some(NOON_MS - 10_000),
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
        // The claim expired one second before the wallet-authorized instant.
        let claims = vec![claim(
            "active",
            "2026-08-26T11:59:59Z",
            Some(NOON_MS - 10_000),
        )];
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
        // The last heartbeat is older than the bounded maximum at the wallet instant.
        let stale = NOON_MS - (CLAIM_HEARTBEAT_MAX_SECONDS + 1) * 1_000;
        let claims = vec![claim("active", "2026-08-26T13:00:00Z", Some(stale))];
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
    fn a_claim_that_never_heartbeat_is_not_live() {
        let claims = vec![claim("active", "2026-08-26T13:00:00Z", None)];
        assert_eq!(
            claim_is_live(&claims[0], NOON_MS, CLAIM_HEARTBEAT_MAX_SECONDS).unwrap(),
            Err(ClaimLapse::HeartbeatStale),
            "a claim that has never proven liveness has not proven liveness"
        );
    }

    #[test]
    fn a_terminal_claim_holds_nothing() {
        for status in CLAIM_TERMINAL_STATUSES {
            let claims = vec![claim(status, "2026-08-26T13:00:00Z", Some(NOON_MS - 1_000))];
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
        let claims = vec![claim("invented", "2026-08-26T13:00:00Z", Some(NOON_MS))];
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
        let mut first = claim("active", "2026-08-26T13:00:00Z", Some(NOON_MS - 1_000));
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
        let mut other = claim("active", "2026-08-26T13:00:00Z", Some(NOON_MS - 1_000));
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
    fn this_build_step_mounts_no_lease_offer_or_contribution_route_at_the_current_generation() {
        // A3 is narrow on purpose. If a later family gets re-pointed early, this catches it.
        for not_yet in [
            "m048_collaboration_routes::handle_participant_lease",
            "m048_collaboration_routes::handle_resource_",
            "m048_collaboration_routes::handle_capability_",
            "m048_collaboration_routes::handle_frontier",
            "m048_collaboration_routes::handle_claim",
            "m048_collaboration_routes::handle_attempt",
            "m048_collaboration_routes::handle_finding",
        ] {
            assert!(
                !ROUTER_SOURCE.contains(not_yet),
                "`{not_yet}` is a later dependency step and must not be mounted yet"
            );
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
