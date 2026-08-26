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

use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::outcome_room_routes::{self as rooms, reject_sensitive_keys, VErr};
use super::outcome_room_system_routes as room_system;

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

#[cfg(test)]
mod m048_tests {
    use super::super::outcome_room_routes::{is_rfc3339, record_output_hash};
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
