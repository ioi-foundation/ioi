//! `HypervisorDeviceHeldPrincipalProvisioning` — a ceremony provisions custody, and STOPS (M03.8).
//!
//! Canon: [`doctrine.md`](../../../../../docs/architecture/components/wallet-network/doctrine.md)
//! § *Device-Held Wallet-Principal Provisioning*. The wallet-network owner holds portable
//! principal-to-approval-authority bindings, their resolution, WebAuthn/passkey ceremonies and
//! device replacement; this module owns the SEAM between the two — the explicit, receipted event in
//! which a completed local ceremony proposes that one portable principal be bound to one
//! device-held approval-authority key.
//!
//! WHY A SEAM AND NOT A SPINE. The daemon already CONSUMES principal-authority bindings:
//! `governed_authority` resolves a principal's authority and verifies retained binding proofs
//! before any grant is consumed. What did not exist was the other end — anything that turns a
//! completed passkey ceremony into a device-held wallet principal. This module is that and only
//! that. It does not issue the binding: `issue_principal_authority_binding` requires the wallet
//! control root's signature (`ensure_control_root_signer`), and a daemon that could mint its own
//! principal bindings would be a second authority spine. So the daemon PROPOSES, records the
//! proposal as an explicit receipted event, and stops; the control root issues; and the binding
//! state this module reports is read back from wallet.network, never asserted locally.
//!
//! THE BOUNDARY IS THE WHOLE UNIT, so it is structural here rather than documentary:
//!
//! 1. PROVISIONING IS AN EXPLICIT EVENT — IDENTITY NEVER IMPLIES IT. A passkey assertion issues a
//!    session; it does not provision a principal. This route requires the caller to name the exact
//!    `auth_factor_receipt_id` of a COMPLETED ceremony, and re-reads that receipt from the identity
//!    plane's own family: it must exist, belong to this caller, carry `user_verification:
//!    required_and_verified`, and carry `effect_authority_created: false`. There is no path from a
//!    session cookie alone to a provisioned principal, which is the whole difference between
//!    "identity bootstraps custody" and "identity IS custody".
//!
//! 2. ONE CEREMONY PROVISIONS AT MOST ONE PRINCIPAL. A receipt attests one ceremony. Re-presenting
//!    it under a second idempotency key is refused `device_held_principal_ceremony_already_consumed`
//!    rather than treated as a fresh ceremony: a receipt that could back many provisionings would
//!    make one user-verified touch into unbounded custody.
//!
//! 3. THE RECEIPT THIS ROUTE EMITS AUTHORIZES NOTHING, and that is measured rather than asserted.
//!    The provisioning record carries `effect_authority_created: false` and an enumerated
//!    `creates_no` list. Behind it, this module holds NO writer for any approval, grant, standing
//!    envelope, delegation, capability-lease or policy family — not as restraint but because the
//!    code to do it is absent, which is the form of the claim the verifier pins (a source absence,
//!    never a call count).
//!
//! 4. ONLY PUBLIC MATERIAL IS STORED. The admission body is a closed allowlist, and every field
//!    that would carry a private key, seed, mnemonic, recovery phrase, recovery file, password or
//!    passphrase is refused by its OWN code (`device_held_principal_secret_material_field`), never
//!    as a generic unknown field. A caller told "unknown field" about `recovery_phrase` receives a
//!    refusal that is true and useless, and never learns that this plane stores no secret at all.
//!    The production profile therefore emits no reusable operator password and no plaintext
//!    recovery file because it has nowhere to put one.
//!
//! 5. CUSTODY IS NOT CONSENT. Provisioning binds WHICH key may approve. It does not approve
//!    anything, does not pre-authorize a spend, and carries no facets, ceiling, budget or expiry —
//!    those fields are refused by their own code too (`device_held_principal_consent_field`),
//!    because a provisioning that could carry a spend ceiling would be a standing envelope wearing
//!    a custody name. A spend still requires the distinct consent ceremony bound to the exact
//!    request facets, which `M03.9`/`M03.10` own.
//!
//! 6. CONTINUITY IS A SUCCESSOR, NEVER A SILENT REPLACEMENT. A replaced or added device provisions
//!    a successor naming `predecessor_provisioning_ref` on the SAME principal's stream, so the
//!    lineage is readable and a device that vanished leaves a record rather than a gap. A successor
//!    naming a predecessor on a different principal is refused: continuity is per principal, and a
//!    cross-principal "continuity" would be a transfer.
//!
//! NONCLAIMS. Recording a provisioning proves that a user-verified ceremony asked for exactly this
//! binding. It does not prove the key is held in a secure element rather than software, does not
//! prove the person at the device is the account's owner, and does not make the principal
//! resolvable — until the wallet control root issues the binding, `binding_state` is `proposed` and
//! nothing downstream may treat it as authority. What is proven is narrower and checkable: nothing
//! admitted here grants, delegates, approves or spends.
//!
//! Exit surface: `POST /v1/hypervisor/auth/device-held-principals`,
//! `GET /v1/hypervisor/auth/device-held-principals`,
//! `GET /v1/hypervisor/auth/device-held-principals/:id`,
//! `GET /v1/hypervisor/auth/device-held-principals/:id/binding-state`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, replay_stable_id,
    require_write_caller, scope_refusal_reply, stream_tail, ScopedMutation,
};
use super::odk_routes::domain_separated_hash;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity,
};
use super::{read_record_dir, DaemonState};

type Reply = (StatusCode, Json<Value>);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

const OWNER_NAMESPACE: &str = "hypervisor-device-held-principal";
const RESOURCE_KIND: &str = "device-held-principal-provisioning";
const PROVISIONING_SCHEMA_VERSION: &str = "ioi.hypervisor.device-held-principal-provisioning.v1";
const PROVISIONING_HASH_DOMAIN: &str =
    "ioi.hypervisor-device-held-principal-provisioning-jcs-sha256.v1";
const PROVISIONING_OP_KIND: &str = "device_held_principal_provisioning_admitted";

/// The identity plane's own receipt family. This module READS it and never writes it: the
/// attestation that a ceremony happened belongs to the ceremony's owner, and a provisioning that
/// minted its own attestation of someone else's ceremony would be asserting what it should be
/// citing.
const AUTH_FACTOR_RECEIPT_FAMILY: &str = "auth-factor-receipts";

/// The signature suites a device-held approval authority may declare. Closed, because an
/// unrecognised suite is a key nobody here can say anything about, and "probably fine" is not a
/// custody posture.
const SUPPORTED_AUTHORITY_SUITES: &[&str] = &["ed25519", "secp256r1"];

/// Purposes of a completed ceremony that may back a provisioning. `standing_effect_authority` is
/// deliberately ABSENT: a receipt from a standing-authority ceremony attests a consent event, and
/// consenting to an effect is not the same act as enrolling the custody that may later consent.
const ADMISSIBLE_CEREMONY_PURPOSES: &[&str] = &["custody_enrollment", "identity_authentication"];

/// Every field the commitment covers: the complete immutable provisioning, its allocated ref
/// included, excluding only `provisioning_hash`. FLAT AND ENUMERATED — a nested preimage is a
/// number only its producer can recompute, which is not a commitment.
const PROVISIONING_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "device_held_principal_provisioning_ref",
    "principal_ref",
    "owner_ref",
    "auth_factor_receipt_id",
    "auth_factor_receipt_hash",
    "credential_id_hash",
    "custody_tier",
    "authority_id",
    "authority_public_key",
    "authority_signature_suite",
    "approval_authority_snapshot_hash",
    "device_label",
    "device_platform",
    "account_label",
    "predecessor_provisioning_ref",
];

/// Every field an admission request may carry. The ref and the hash are absent by construction: the
/// server allocates the first and derives the second, and a request that authored either would be
/// authoring its own commitment.
const PROVISIONING_REQUEST_FIELDS: &[&str] = &[
    "schema_version",
    "owner_ref",
    "idempotency_key",
    "principal_ref",
    "auth_factor_receipt_id",
    "authority_id",
    "authority_public_key",
    "authority_signature_suite",
    "approval_authority_snapshot_hash",
    "device_label",
    "device_platform",
    "account_label",
    "predecessor_provisioning_ref",
];

/// Fields that would put secret material in a durable record. Refused by their own name so the
/// refusal teaches the boundary instead of hiding it behind "unknown field".
const SECRET_MATERIAL_FIELDS: &[&str] = &[
    "private_key",
    "secret_key",
    "signing_key",
    "authority_private_key",
    "seed",
    "seed_phrase",
    "mnemonic",
    "recovery_phrase",
    "recovery_code",
    "recovery_file",
    "recovery_material",
    "password",
    "passphrase",
    "operator_password",
    "shared_secret",
    "key_shard",
];

/// Fields that would turn a custody record into a consent record. Refused by their own name for the
/// same reason.
const CONSENT_FIELDS: &[&str] = &[
    "approval_grant",
    "wallet_approval_grant",
    "standing_approval_grant",
    "standing_envelope",
    "capability_lease",
    "delegation",
    "lease_request_facets",
    "spend_ceiling",
    "budget",
    "max_usages",
    "required_scope",
    "policy_hash",
    "auto_approve",
];

fn invalid(code: &str, message: impl Into<String>) -> Reply {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "code": code, "message": message.into() })),
    )
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "code": code, "message": message.into() })),
    )
}

fn refuse_unknown_request_fields(body: &Value) -> Result<(), Reply> {
    let Some(fields) = body.as_object() else {
        return Err(invalid(
            "device_held_principal_request_not_an_object",
            "a device-held principal provisioning request is a JSON object",
        ));
    };
    for name in fields.keys() {
        let name = name.as_str();
        if PROVISIONING_REQUEST_FIELDS.contains(&name) {
            continue;
        }
        if SECRET_MATERIAL_FIELDS.contains(&name) {
            return Err(invalid(
                "device_held_principal_secret_material_field",
                format!(
                    "'{name}' carries secret material, and this plane stores none: a device-held principal is public key material plus device metadata, and the private half never leaves the device. There is no field for it here and no writer behind one"
                ),
            ));
        }
        if CONSENT_FIELDS.contains(&name) {
            return Err(invalid(
                "device_held_principal_consent_field",
                format!(
                    "'{name}' names consent, and provisioning is custody: this event binds WHICH key may approve and approves nothing. A spend still requires its own ceremony bound to the exact request facets, so a provisioning carrying '{name}' would be a standing envelope wearing a custody name"
                ),
            ));
        }
        if name == "device_held_principal_provisioning_ref" || name == "provisioning_hash" {
            return Err(invalid(
                "device_held_principal_field_not_caller_authored",
                format!(
                    "'{name}' is derived by the owner of this contract: the ref is allocated before hashing and the hash covers it. A caller that authored either would be authoring its own commitment, and a commitment its subject can choose is not one"
                ),
            ));
        }
        if name == "binding_state" || name == "effect_authority_created" {
            return Err(invalid(
                "device_held_principal_field_not_caller_authored",
                format!(
                    "'{name}' is a fact this daemon establishes, not one a caller declares: binding state is read back from wallet.network and the authority claim is structurally false here"
                ),
            ));
        }
        return Err(invalid(
            "device_held_principal_request_field_unknown",
            format!("'{name}' is not a field of a device-held principal provisioning request"),
        ));
    }
    Ok(())
}

fn required_str<'a>(body: &'a Value, key: &str) -> Result<&'a str, Reply> {
    let value = body.get(key).and_then(Value::as_str).map(str::trim);
    match value {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(invalid(
            "device_held_principal_field_required",
            format!("'{key}' is required and must be a non-empty string"),
        )),
    }
}

fn lowercase_hex(value: &str, expected_bytes: usize, field: &str) -> Result<String, Reply> {
    let normalized = value.trim().to_ascii_lowercase();
    let body = normalized.strip_prefix("0x").unwrap_or(&normalized);
    if body.len() != expected_bytes * 2 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "device_held_principal_hex_field_invalid",
            format!(
                "'{field}' must be exactly {expected_bytes} bytes of lowercase hex ({} characters), so two records naming the same key are byte-comparable rather than merely similar",
                expected_bytes * 2
            ),
        ));
    }
    Ok(body.to_string())
}

/// THE WALLET OWNER'S CANONICAL PRINCIPAL GRAMMAR, enforced here rather than echoed.
///
/// `doctrine.md` § *Portable Principal-to-Authority Binding* states the grammar exactly, and it is
/// deliberately narrow: five schemes, one or more nonempty slash-separated ASCII segments, each
/// segment starting and ending with a letter or digit, internal characters also permitting
/// `. _ - ~ : @`; no leading, trailing or doubled slashes, no query, fragment, wildcard, percent
/// encoding, whitespace or caller-chosen alias.
///
/// This module refuses anything outside it rather than passing it through. The first draft of this
/// route did pass it through, and its own check then provisioned `wallet://…` — a scheme the
/// binding plane has never recognised, so the record named a principal that could never be bound
/// and nothing would have said so until someone tried. Recording a provisioning for an
/// unresolvable principal is worse than refusing it: it is a durable statement that custody was
/// arranged when it was not.
const CANONICAL_PRINCIPAL_SCHEMES: &[&str] = &[
    "worker://",
    "service://",
    "org://",
    "domain://",
    "agentgres://domain/",
];

fn validate_principal_ref(value: &str) -> Result<(), Reply> {
    let refuse_ref = |reason: &str| {
        Err(invalid(
            "device_held_principal_principal_ref_invalid",
            format!(
                "'principal_ref' {reason}. The canonical grammar is wallet.network's and is narrow by design: worker://, service://, org://, domain:// or agentgres://domain/ followed by slash-separated segments that begin and end with a letter or digit"
            ),
        ))
    };
    if value.len() > 256 {
        return refuse_ref("is longer than 256 characters");
    }
    let Some(scheme) = CANONICAL_PRINCIPAL_SCHEMES
        .iter()
        .find(|prefix| value.starts_with(*prefix))
    else {
        return refuse_ref("does not begin with a canonical principal scheme");
    };
    let path = &value[scheme.len()..];
    if path.is_empty() {
        return refuse_ref("names a scheme with no path");
    }
    if path.contains('?') || path.contains('#') || path.contains('*') || path.contains('%') {
        return refuse_ref("carries a query, fragment, wildcard or percent encoding");
    }
    if value.chars().any(char::is_whitespace) {
        return refuse_ref("carries whitespace");
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return refuse_ref("has a leading, trailing or doubled slash");
        }
        let first = segment.chars().next().unwrap_or(' ');
        let last = segment.chars().last().unwrap_or(' ');
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return refuse_ref("has a segment that does not begin and end with a letter or digit");
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | ':' | '@'))
        {
            return refuse_ref("has a segment with a character outside the canonical set");
        }
    }
    Ok(())
}

/// Read the identity plane's receipt for the named ceremony, and refuse every way it could fail to
/// be a completed, user-verified ceremony belonging to this caller.
fn resolve_ceremony_receipt(
    data_dir: &str,
    receipt_id: &str,
    principal_id: &str,
) -> Result<Value, Reply> {
    let receipt = read_record_dir(data_dir, AUTH_FACTOR_RECEIPT_FAMILY)
        .into_iter()
        .find(|record| record["receipt_id"].as_str() == Some(receipt_id));
    let Some(receipt) = receipt else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "device_held_principal_ceremony_receipt_not_found",
            format!(
                "no completed ceremony wrote receipt '{receipt_id}'. Provisioning cites a ceremony that happened; it does not assert one"
            ),
        ));
    };
    if receipt["principal_id"].as_str() != Some(principal_id) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "device_held_principal_ceremony_principal_mismatch",
            "the cited ceremony receipt belongs to a different principal",
        ));
    }
    if receipt["user_verification"].as_str() != Some("required_and_verified") {
        return Err(refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "device_held_principal_ceremony_not_user_verified",
            "the cited ceremony was not user-verified, so it attests possession of a device and nothing about the person holding it",
        ));
    }
    if receipt["effect_authority_created"].as_bool() != Some(false) {
        return Err(refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "device_held_principal_ceremony_receipt_claims_authority",
            "the cited receipt does not carry the structural non-authority claim this plane requires of every factor it reads",
        ));
    }
    let purpose = receipt["purpose"].as_str().unwrap_or_default();
    if !ADMISSIBLE_CEREMONY_PURPOSES.contains(&purpose) {
        return Err(refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "device_held_principal_ceremony_purpose_inadmissible",
            format!(
                "a ceremony recorded for '{purpose}' may not back a provisioning: consenting to an effect is a different act from enrolling the custody that may later consent"
            ),
        ));
    }
    Ok(receipt)
}

/// Build the immutable provisioning record. The ref is allocated BEFORE hashing, so the commitment
/// can cover it; it is derived from owner + idempotency key so a retry is the same object rather
/// than a new one (a wall-clock id can never be idempotent).
fn build_provisioning(
    body: &Value,
    owner_ref: &str,
    idempotency_key: &str,
    receipt: &Value,
) -> Result<Value, Reply> {
    refuse_unknown_request_fields(body)?;
    if let Some(declared) = body.get("schema_version").and_then(Value::as_str) {
        if declared != PROVISIONING_SCHEMA_VERSION {
            return Err(invalid(
                "device_held_principal_schema_version_unsupported",
                format!("this route admits exactly '{PROVISIONING_SCHEMA_VERSION}'"),
            ));
        }
    }
    let principal_ref = required_str(body, "principal_ref")?;
    validate_principal_ref(principal_ref)?;
    let receipt_id = required_str(body, "auth_factor_receipt_id")?;
    let suite = required_str(body, "authority_signature_suite")?;
    if !SUPPORTED_AUTHORITY_SUITES.contains(&suite) {
        return Err(invalid(
            "device_held_principal_signature_suite_unsupported",
            format!(
                "'{suite}' is not a signature suite this build can say anything about; the recognised set is closed ({})",
                SUPPORTED_AUTHORITY_SUITES.join(", ")
            ),
        ));
    }
    let authority_id = lowercase_hex(required_str(body, "authority_id")?, 32, "authority_id")?;
    let public_key_text = required_str(body, "authority_public_key")?;
    let public_key = {
        let normalized = public_key_text.trim().to_ascii_lowercase();
        let hex_body = normalized.strip_prefix("0x").unwrap_or(&normalized);
        if hex_body.is_empty()
            || hex_body.len() % 2 != 0
            || hex_body.len() > 256
            || !hex_body.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(invalid(
                "device_held_principal_hex_field_invalid",
                "'authority_public_key' must be non-empty lowercase hex of at most 128 bytes",
            ));
        }
        hex_body.to_string()
    };
    let snapshot_hash = lowercase_hex(
        required_str(body, "approval_authority_snapshot_hash")?,
        32,
        "approval_authority_snapshot_hash",
    )?;
    let device_label = required_str(body, "device_label")?;
    let device_platform = required_str(body, "device_platform")?;
    if device_label.len() > 120 || device_platform.len() > 120 {
        return Err(invalid(
            "device_held_principal_metadata_too_long",
            "device metadata fields are at most 120 characters",
        ));
    }
    let account_label = body
        .get("account_label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if account_label
        .map(|value| value.len() > 120)
        .unwrap_or(false)
    {
        return Err(invalid(
            "device_held_principal_metadata_too_long",
            "'account_label' is at most 120 characters",
        ));
    }
    let predecessor = body
        .get("predecessor_provisioning_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(predecessor) = predecessor {
        if !predecessor.starts_with("device-held-principal-provisioning://") {
            return Err(invalid(
                "device_held_principal_predecessor_ref_invalid",
                "'predecessor_provisioning_ref' must name a device-held principal provisioning of this plane",
            ));
        }
    }

    let provisioning_id = replay_stable_id("dhp", owner_ref, idempotency_key);
    let provisioning_ref =
        format!("device-held-principal-provisioning://{provisioning_id}/revision/1");
    let mut record = Map::new();
    record.insert("schema_version".into(), json!(PROVISIONING_SCHEMA_VERSION));
    record.insert(
        "device_held_principal_provisioning_ref".into(),
        json!(provisioning_ref),
    );
    record.insert("principal_ref".into(), json!(principal_ref));
    record.insert("owner_ref".into(), json!(owner_ref));
    record.insert("auth_factor_receipt_id".into(), json!(receipt_id));
    record.insert(
        "auth_factor_receipt_hash".into(),
        receipt.get("receipt_hash").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "credential_id_hash".into(),
        receipt
            .get("credential_id_hash")
            .cloned()
            .unwrap_or(Value::Null),
    );
    record.insert(
        "custody_tier".into(),
        json!(match receipt["factor_kind"].as_str() {
            Some("deployment_local_operator") => "deployment_local_operator",
            _ => "device_passkey",
        }),
    );
    record.insert("authority_id".into(), json!(authority_id));
    record.insert("authority_public_key".into(), json!(public_key));
    record.insert("authority_signature_suite".into(), json!(suite));
    record.insert(
        "approval_authority_snapshot_hash".into(),
        json!(snapshot_hash),
    );
    record.insert("device_label".into(), json!(device_label));
    record.insert("device_platform".into(), json!(device_platform));
    record.insert(
        "account_label".into(),
        account_label.map(Value::from).unwrap_or(Value::Null),
    );
    record.insert(
        "predecessor_provisioning_ref".into(),
        predecessor.map(Value::from).unwrap_or(Value::Null),
    );

    // The two facts this plane establishes rather than accepts. `binding_state` is `proposed`
    // because nothing here issues the binding; `creates_no` enumerates what a reader must not infer
    // from a provisioning, so the negative is on the record rather than only in this comment.
    record.insert("binding_state".into(), json!("proposed"));
    record.insert("effect_authority_created".into(), json!(false));
    record.insert(
        "creates_no".into(),
        json!([
            "approval_grant",
            "standing_approval_envelope",
            "capability_lease",
            "delegation",
            "spend_authorization",
            "policy_widening"
        ]),
    );

    let mut record = Value::Object(record);
    let hash = domain_separated_hash(
        &record,
        PROVISIONING_HASH_DOMAIN,
        PROVISIONING_MATERIAL_FIELDS,
    );
    record["provisioning_hash"] = json!(hash);
    Ok(record)
}

/// Every provisioning this caller may read, newest stream tail first.
fn readable_provisionings(st: &DaemonState, headers: &HeaderMap) -> Result<Vec<Value>, Reply> {
    let identity = resolve_request_identity(&st.data_dir, headers).map_err(scope_refusal_reply)?;
    let refs = authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND)
        .map_err(scope_refusal_reply)?;
    let mut out = Vec::new();
    for resource_ref in refs {
        let scope = match authorize_request_resource_scope(
            &st.data_dir,
            &identity,
            RESOURCE_KIND,
            &resource_ref,
            None,
        ) {
            Ok(scope) => scope,
            Err(_) => continue,
        };
        let tail = stream_tail(RESOURCE_KIND, &resource_ref);
        let history = match read_owner_scoped_history(
            &st.data_dir,
            &identity,
            &scope,
            RESOURCE_KIND,
            &resource_ref,
            OWNER_NAMESPACE,
            &tail,
        ) {
            Ok(history) => history,
            Err(_) => continue,
        };
        if let Some(record) = provisioning_from_history(&history) {
            out.push(record);
        }
    }
    out.sort_by(|a, b| {
        a["device_held_principal_provisioning_ref"]
            .as_str()
            .unwrap_or_default()
            .cmp(
                b["device_held_principal_provisioning_ref"]
                    .as_str()
                    .unwrap_or_default(),
            )
    });
    Ok(out)
}

fn provisioning_from_history(history: &[agentgres::mux::ExactProjection]) -> Option<Value> {
    history
        .iter()
        .find(|entry| entry.operation.op_kind == PROVISIONING_OP_KIND)
        .and_then(|entry| entry.operation.payload.get("provisioning").cloned())
}

// ------------------------------------------------------------------------------- admission

/// POST /v1/hypervisor/auth/device-held-principals — record one immutable provisioning.
pub(crate) async fn handle_device_held_principal_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST. Validating content before authenticating answers 422 where 401 is owed and
    // tells an anonymous caller exactly which fields this route wants.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let receipt_id = match body
        .get("auth_factor_receipt_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.to_string(),
        None => {
            return invalid(
                "device_held_principal_field_required",
                "'auth_factor_receipt_id' is required: provisioning cites the completed ceremony that asked for it, and a session alone never provisions custody",
            )
        }
    };
    // THE SAME IDENTITY, RESOLVED BOTH WAYS. The write path resolves a `principal_ref`; the
    // identity plane records its ceremonies against a `principal_id`. Reading the second here, from
    // the identity plane's own resolver, is what lets the ceremony-ownership check be exact rather
    // than a string comparison across two vocabularies — and the two must agree, or a session that
    // authenticates as one principal could cite another's ceremony.
    let Some(identity_principal) =
        super::lifecycle_routes::resolve_principal(&st.data_dir, &headers)
    else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "device_held_principal_authentication_required",
            "provisioning cites a ceremony this caller completed, so the caller must resolve on the identity plane that recorded it",
        );
    };
    let principal_id = identity_principal["principal_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let identity_principal_ref = identity_principal["principal_ref"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("user://{principal_id}"));
    if identity_principal_ref != caller.identity.principal_ref {
        return refuse(
            StatusCode::FORBIDDEN,
            "device_held_principal_identity_resolution_mismatch",
            "the identity plane and the write path resolve this request to different principals; provisioning refuses rather than choosing one",
        );
    }
    let receipt = match resolve_ceremony_receipt(&st.data_dir, &receipt_id, &principal_id) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    let record =
        match build_provisioning(&body, &caller.owner_ref, &caller.idempotency_key, &receipt) {
            Ok(record) => record,
            Err(response) => return response,
        };
    let provisioning_ref = record["device_held_principal_provisioning_ref"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // ONE CEREMONY, AT MOST ONE PRINCIPAL. Checked across everything this caller can read, before
    // the stream is touched: a receipt that could back two provisionings would turn one
    // user-verified touch into unbounded custody.
    match readable_provisionings(&st, &headers) {
        Ok(existing) => {
            for prior in existing {
                if prior["auth_factor_receipt_id"].as_str() == Some(receipt_id.as_str())
                    && prior["device_held_principal_provisioning_ref"].as_str()
                        != Some(provisioning_ref.as_str())
                {
                    return refuse(
                        StatusCode::CONFLICT,
                        "device_held_principal_ceremony_already_consumed",
                        format!(
                            "ceremony receipt '{receipt_id}' already provisioned '{}'. A receipt attests ONE ceremony; enrol another device with another ceremony, or record a successor naming this provisioning as its predecessor",
                            prior["device_held_principal_provisioning_ref"]
                                .as_str()
                                .unwrap_or_default()
                        ),
                    );
                }
            }
        }
        Err(response) => return response,
    }

    // CONTINUITY IS PER PRINCIPAL. A successor naming a predecessor on a different principal would
    // be a transfer of custody wearing a continuity name.
    if let Some(predecessor) = record["predecessor_provisioning_ref"].as_str() {
        let known = match readable_provisionings(&st, &headers) {
            Ok(existing) => existing.into_iter().find(|prior| {
                prior["device_held_principal_provisioning_ref"].as_str() == Some(predecessor)
            }),
            Err(response) => return response,
        };
        let Some(known) = known else {
            return refuse(
                StatusCode::NOT_FOUND,
                "device_held_principal_predecessor_not_found",
                format!("'{predecessor}' is not a provisioning this caller can read"),
            );
        };
        if known["principal_ref"] != record["principal_ref"] {
            return refuse(
                StatusCode::CONFLICT,
                "device_held_principal_predecessor_principal_mismatch",
                "a successor continues custody of the SAME principal; naming a predecessor on another principal would be a transfer, not continuity",
            );
        }
    }

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &provisioning_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(RESOURCE_KIND, &provisioning_ref);

    // REPLAY BEFORE ANYTHING ELSE. A retry under the same key must reach the same answer, and an
    // immutable object makes the divergence check one hash comparison.
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        RESOURCE_KIND,
        &provisioning_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let stored = prior
                .operation
                .payload
                .get("provisioning")
                .cloned()
                .unwrap_or(Value::Null);
            if stored.get("provisioning_hash") != record.get("provisioning_hash") {
                return refuse(
                    StatusCode::CONFLICT,
                    "device_held_principal_provisioning_immutable",
                    format!(
                        "'{provisioning_ref}' is already recorded and a provisioning is immutable: the same ref with a changed principal, ceremony, key, suite or device is a DIFFERENT provisioning, not an amendment. Record it under a new idempotency_key"
                    ),
                );
            }
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "device_held_principal_provisioning_ref": provisioning_ref,
                    "provisioning": stored,
                    "admitted_head": prior.head,
                    "effect_authority_created": false,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }

    let recorded_at_ms = now_ms();
    let payload = json!({
        "provisioning": record,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &provisioning_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: PROVISIONING_OP_KIND,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "device_held_principal_provisioning_ref": provisioning_ref,
            "provisioning": record,
            "admitted_head": commit.projection.head,
            "operation_ref": commit.operation_ref,
            "receipt_ref": commit.receipt_ref,
            "effect_authority_created": false,
        })),
    )
}

// ------------------------------------------------------------------------------- reads

/// GET /v1/hypervisor/auth/device-held-principals
pub(crate) async fn handle_device_held_principal_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    match readable_provisionings(&st, &headers) {
        Ok(provisionings) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "device_held_principals": provisionings })),
        ),
        Err(response) => response,
    }
}

/// GET /v1/hypervisor/auth/device-held-principals/:id
pub(crate) async fn handle_device_held_principal_get(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Reply {
    let provisioning_ref = format!("device-held-principal-provisioning://{id}/revision/1");
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        RESOURCE_KIND,
        &provisioning_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(RESOURCE_KIND, &provisioning_ref);
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &scope,
        RESOURCE_KIND,
        &provisioning_ref,
        OWNER_NAMESPACE,
        &tail,
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some(record) = provisioning_from_history(&history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "device_held_principal_provisioning_not_found",
            format!("'{provisioning_ref}' is not recorded"),
        );
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "device_held_principal_provisioning_ref": provisioning_ref,
            "provisioning": record,
            "admitted_head": history.last().map(|entry| entry.head.clone()),
        })),
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct BindingStateQuery {
    required_scope: Option<String>,
}

/// GET /v1/hypervisor/auth/device-held-principals/:id/binding-state
///
/// The binding state is READ BACK from wallet.network, never asserted here. A daemon that reported
/// its own proposal as "bound" would be answering the one question this whole seam exists to hand
/// to the control root.
pub(crate) async fn handle_device_held_principal_binding_state(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
    Query(query): Query<BindingStateQuery>,
    headers: HeaderMap,
) -> Reply {
    let (status, Json(body)) =
        handle_device_held_principal_get(State(st.clone()), Path(id), headers).await;
    if status != StatusCode::OK {
        return (status, Json(body));
    }
    let record = body["provisioning"].clone();
    let principal_ref = record["principal_ref"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let required_scope = query
        .required_scope
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("scope:wallet.approval.resolve")
        .to_string();

    if !super::wallet_network_capability_client::configured() {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "principal_ref": principal_ref,
                "binding_state": "unresolvable",
                "reason": "no wallet.network capability is configured on this daemon, so the binding state is unknown here rather than absent",
                "recorded_binding_state": record["binding_state"],
                "effect_authority_created": false,
            })),
        );
    }

    let mut request_id = [0u8; 32];
    {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            format!(
                "{}\u{0}{}\u{0}{}",
                principal_ref,
                required_scope,
                record["provisioning_hash"].as_str().unwrap_or_default()
            )
            .as_bytes(),
        );
        request_id.copy_from_slice(&digest);
    }
    let params = ioi_types::app::wallet_network::ResolvePrincipalAuthorityParams {
        request_id,
        principal_ref: principal_ref.clone(),
        authority_kind: ioi_types::app::wallet_network::PrincipalAuthorityKind::Approval,
        required_scope: required_scope.clone(),
        expected_coordinates: None,
    };
    match super::wallet_network_capability_client::resolve_principal_authority(params).await {
        Ok(resolution) => {
            let bound_key = hex::encode(&resolution.binding_proof.statement.authority_public_key);
            let recorded_key = record["authority_public_key"].as_str().unwrap_or_default();
            let matches = bound_key == recorded_key;
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "principal_ref": principal_ref,
                    // `bound` means wallet.network resolves this principal to the exact key this
                    // provisioning named. `diverged` means it resolves to a DIFFERENT key — which
                    // is a real state, not an error, and is reported rather than smoothed over.
                    "binding_state": if matches { "bound" } else { "diverged" },
                    "resolved_authority_public_key": bound_key,
                    "recorded_authority_public_key": recorded_key,
                    "binding_version": resolution.binding_proof.statement.binding_version,
                    "required_scope": required_scope,
                    "effect_authority_created": false,
                })),
            )
        }
        Err(error) => {
            let (state, reason) = match error {
                super::wallet_network_capability_client::ResolveError::Refused(detail) => {
                    ("proposed", detail)
                }
                super::wallet_network_capability_client::ResolveError::NotConfigured(detail) => {
                    ("unresolvable", detail)
                }
                super::wallet_network_capability_client::ResolveError::Unavailable(detail) => {
                    ("unresolvable", detail)
                }
                super::wallet_network_capability_client::ResolveError::Invalid(detail) => {
                    ("unresolvable", detail)
                }
            };
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "principal_ref": principal_ref,
                    "binding_state": state,
                    "reason": reason,
                    "required_scope": required_scope,
                    "effect_authority_created": false,
                })),
            )
        }
    }
}
