//! Device/passkey custody for the Hypervisor operator identity plane.
//!
//! Identity authentication is deliberately separate from effect authority. A successful passkey
//! assertion may issue an operator session, but it does not mint a wallet grant, standing envelope,
//! or provider capability. This identity plane consumes a second, request-bound assertion and emits
//! only a factor receipt; the wallet authority plane must verify and bind that receipt before it can
//! mint any effect authority.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use super::durable_fs::persist_record_durable;
use super::lifecycle_routes::{issue_session, resolve_principal};
use super::{iso_now, read_record_dir, sha256_hex_str, short_hash, DaemonState};

const CEREMONY_FAMILY: &str = "passkey-ceremonies";
const CREDENTIAL_FAMILY: &str = "passkey-credentials";
const RECEIPT_FAMILY: &str = "auth-factor-receipts";
const CEREMONY_TTL_MS: u64 = 5 * 60 * 1_000;
const APPROVAL_CONTEXT_DOMAIN: &[u8] = b"IOI-APPROVAL-CEREMONY-CONTEXT-V1\0";

static CEREMONY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn ceremony_lock() -> &'static Mutex<()> {
    CEREMONY_LOCK.get_or_init(|| Mutex::new(()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn webauthn() -> Result<Webauthn, String> {
    let rp_id = std::env::var("IOI_HYPERVISOR_WEBAUTHN_RP_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let origin_text = std::env::var("IOI_HYPERVISOR_WEBAUTHN_ORIGIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:4197".to_string());
    let origin = Url::parse(&origin_text)
        .map_err(|error| format!("passkey_configuration_invalid: origin: {error}"))?;
    WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|error| format!("passkey_configuration_invalid: {error}"))?
        .rp_name("IOI Hypervisor")
        .build()
        .map_err(|error| format!("passkey_configuration_invalid: {error}"))
}

fn principal_uuid(principal_id: &str) -> Uuid {
    let digest = sha256::digest(principal_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Stable RFC 4122 variant/version bits. This id is an opaque WebAuthn user handle, not an
    // authority coordinate and not a source of identity truth.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

mod sha256 {
    use sha2::{Digest, Sha256};

    pub(super) fn digest(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }
}

fn credential_id_hex(passkey: &Passkey) -> String {
    hex::encode(passkey.cred_id().as_ref())
}

fn all_credential_records(data_dir: &str, principal_id: &str) -> Vec<Value> {
    read_record_dir(data_dir, CREDENTIAL_FAMILY)
        .into_iter()
        .filter(|record| record["principal_id"].as_str() == Some(principal_id))
        .collect()
}

fn credential_records(data_dir: &str, principal_id: &str) -> Vec<(Value, Passkey)> {
    all_credential_records(data_dir, principal_id)
        .into_iter()
        .filter(|record| record["status"].as_str() == Some("active"))
        .filter_map(|record| {
            let passkey = serde_json::from_value(record.get("passkey")?.clone()).ok()?;
            Some((record, passkey))
        })
        .collect()
}

fn persist_ceremony(
    data_dir: &str,
    ceremony_id: &str,
    kind: &str,
    principal_id: &str,
    state: Value,
) -> Result<(), String> {
    persist_ceremony_with_context(data_dir, ceremony_id, kind, principal_id, state, None)
}

fn persist_ceremony_with_context(
    data_dir: &str,
    ceremony_id: &str,
    kind: &str,
    principal_id: &str,
    state: Value,
    approval_context: Option<(&Value, &str)>,
) -> Result<(), String> {
    let record = json!({
        "schema_version": "ioi.hypervisor.passkey-ceremony.v1",
        "ceremony_id": ceremony_id,
        "kind": kind,
        "principal_id": principal_id,
        "status": "pending",
        "created_at": iso_now(),
        "expires_at_ms": now_ms().saturating_add(CEREMONY_TTL_MS),
        "state": state,
    });
    let mut record = record;
    if let Some((context, context_hash)) = approval_context {
        record["approval_ceremony_context"] = context.clone();
        record["approval_ceremony_context_hash"] = json!(context_hash);
    }
    persist_record_durable(data_dir, CEREMONY_FAMILY, ceremony_id, &record)
        .map_err(|error| format!("passkey_ceremony_persistence_failed: {error:?}"))
}

fn sha256_ref_bytes(value: &str, label: &str) -> Result<[u8; 32], String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{label}_invalid"));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label}_invalid"));
    }
    let decoded = hex::decode(hex).map_err(|_| format!("{label}_invalid"))?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn approval_context_hash(context: &Value) -> Result<String, String> {
    let canonical = serde_jcs::to_vec(context)
        .map_err(|error| format!("approval_ceremony_context_not_canonical: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_CONTEXT_DOMAIN);
    hasher.update(canonical);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_approval_context(
    context: &Value,
    expected_hash: &str,
    principal_ref: &str,
) -> Result<[u8; 32], String> {
    const CONTRACT: &str = "schema://ioi/foundations/approval-ceremony-context/v1";
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        CONTRACT, context,
    )
    .map_err(|error| format!("approval_ceremony_context_contract_invalid: {error}"))?;
    let object = context
        .as_object()
        .ok_or_else(|| "approval_ceremony_context_invalid".to_string())?;
    const FIELDS: &[&str] = &[
        "schema_version",
        "approval_ceremony_context_ref",
        "authority_request_ref",
        "authority_request_body_hash",
        "authority_review_ref",
        "authority_review_body_hash",
        "predecessor_authority_review_ref",
        "predecessor_authority_review_body_hash",
        "predecessor_authority_request_ref",
        "predecessor_authority_request_body_hash",
        "predecessor_authority_review_receipt_ref",
        "predecessor_authority_review_receipt_hash",
        "reviewed_representation_hash",
        "principal_ref",
        "acting_subject_ref",
        "product_session_ref",
        "origin_binding_ref",
        "authorization_subject",
        "presentation_surface_ref",
        "presentation_evidence_profile_ref",
        "principal_authority_resolution_ref",
        "principal_authority_resolution_hash",
        "required_auth_factor_posture_refs",
        "required_guardian_surface_refs",
        "posture_satisfaction_profile_ref",
        "interaction_mode",
        "authentication_posture",
        "receipt_timing",
        "policy_decision_receipt_ref",
        "policy_decision_receipt_hash",
        "policy_hash",
        "risk_classes",
        "revocation_epoch",
        "nonce_b64url",
        "issued_at",
        "expires_at",
        "single_use",
    ];
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err("approval_ceremony_context_fields_invalid".to_string());
    }
    if context["schema_version"] != json!("ioi.foundations.approval-ceremony-context.v1")
        || context["principal_ref"].as_str() != Some(principal_ref)
        || context["interaction_mode"].as_str() != Some("interactive")
        || context["authentication_posture"].as_str() != Some("step_up")
        || context["receipt_timing"].as_str() != Some("before_effect")
        || context["single_use"].as_bool() != Some(true)
        || context["authorization_subject"]["kind"].as_str() != Some("standing_envelope")
    {
        return Err("approval_ceremony_context_posture_invalid".to_string());
    }
    for field in [
        "authority_request_body_hash",
        "authority_review_body_hash",
        "reviewed_representation_hash",
        "policy_decision_receipt_hash",
        "policy_hash",
    ] {
        sha256_ref_bytes(context[field].as_str().unwrap_or(""), field)?;
    }
    for field in [
        "predecessor_authority_review_body_hash",
        "predecessor_authority_request_body_hash",
        "predecessor_authority_review_receipt_hash",
        "principal_authority_resolution_hash",
    ] {
        if let Some(value) = context[field].as_str() {
            sha256_ref_bytes(value, field)?;
        }
    }
    sha256_ref_bytes(
        context["authorization_subject"]["subject_hash"]
            .as_str()
            .unwrap_or(""),
        "authorization_subject_hash",
    )?;
    let nonce = context["nonce_b64url"].as_str().unwrap_or("");
    if nonce.len() < 43
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("approval_ceremony_context_nonce_invalid".to_string());
    }
    let issued_at = OffsetDateTime::parse(context["issued_at"].as_str().unwrap_or(""), &Rfc3339)
        .map_err(|_| "approval_ceremony_context_issued_at_invalid".to_string())?;
    let expires_at = OffsetDateTime::parse(context["expires_at"].as_str().unwrap_or(""), &Rfc3339)
        .map_err(|_| "approval_ceremony_context_expires_at_invalid".to_string())?;
    let now = OffsetDateTime::now_utc();
    if issued_at > now + time::Duration::seconds(30)
        || expires_at <= issued_at
        || expires_at - issued_at > time::Duration::minutes(5)
        || expires_at <= now
        || expires_at - now > time::Duration::minutes(5)
    {
        return Err("approval_ceremony_context_validity_invalid".to_string());
    }
    let derived_hash = approval_context_hash(context)?;
    if derived_hash != expected_hash {
        return Err("approval_ceremony_context_hash_mismatch".to_string());
    }
    sha256_ref_bytes(expected_hash, "approval_ceremony_context_hash")
}

fn bind_authentication_challenge(
    mut options: RequestChallengeResponse,
    state: PasskeyAuthentication,
    challenge: [u8; 32],
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), String> {
    options.public_key.challenge = challenge.to_vec().into();
    let encoded = serde_json::to_value(&options)
        .map_err(|error| format!("passkey_challenge_serialization_failed: {error}"))?
        .pointer("/publicKey/challenge")
        .cloned()
        .ok_or_else(|| "passkey_challenge_serialization_failed".to_string())?;
    let mut state_value = serde_json::to_value(state)
        .map_err(|error| format!("passkey_state_serialization_failed: {error}"))?;
    let Some(state_challenge) = state_value.pointer_mut("/ast/challenge") else {
        return Err("passkey_state_challenge_missing".to_string());
    };
    *state_challenge = encoded;
    let state = serde_json::from_value(state_value)
        .map_err(|error| format!("passkey_state_serialization_failed: {error}"))?;
    Ok((options, state))
}

/// Mark a ceremony consumed before cryptographic verification. An invalid assertion burns the
/// challenge; it never leaves a replayable pending record. The process lock closes same-daemon
/// races, while the durable status closes restart replay.
fn consume_ceremony(data_dir: &str, ceremony_id: &str, kind: &str) -> Result<Value, String> {
    let _guard = ceremony_lock()
        .lock()
        .map_err(|_| "passkey_ceremony_lock_poisoned".to_string())?;
    let mut record = read_record_dir(data_dir, CEREMONY_FAMILY)
        .into_iter()
        .find(|record| record["ceremony_id"].as_str() == Some(ceremony_id))
        .ok_or_else(|| "passkey_ceremony_not_found".to_string())?;
    if record["kind"].as_str() != Some(kind) {
        return Err("passkey_ceremony_kind_mismatch".to_string());
    }
    if record["status"].as_str() != Some("pending") {
        return Err("passkey_ceremony_already_consumed".to_string());
    }
    if record["expires_at_ms"].as_u64().unwrap_or(0) <= now_ms() {
        record["status"] = json!("expired");
        record["consumed_at"] = json!(iso_now());
        persist_record_durable(data_dir, CEREMONY_FAMILY, ceremony_id, &record)
            .map_err(|error| format!("passkey_ceremony_persistence_failed: {error:?}"))?;
        return Err("passkey_ceremony_expired".to_string());
    }
    record["status"] = json!("consumed");
    record["consumed_at"] = json!(iso_now());
    persist_record_durable(data_dir, CEREMONY_FAMILY, ceremony_id, &record)
        .map_err(|error| format!("passkey_ceremony_persistence_failed: {error:?}"))?;
    Ok(record)
}

fn persist_factor_receipt(
    data_dir: &str,
    ceremony_id: &str,
    principal_id: &str,
    credential_id: &str,
    purpose: &str,
    approval_context: Option<(&Value, &str)>,
) -> Result<Value, String> {
    let credential_hash = format!("sha256:{}", sha256_hex_str(credential_id));
    let receipt_id = format!(
        "afr_{}",
        short_hash(&sha256_hex_str(&format!(
            "{ceremony_id}:{principal_id}:{credential_hash}:{purpose}"
        )))
    );
    let mut receipt = json!({
        "schema_version": "ioi.hypervisor.auth-factor-receipt.v1",
        "receipt_id": receipt_id,
        "ceremony_id": ceremony_id,
        "principal_id": principal_id,
        "principal_ref": null,
        "factor_kind": "passkey",
        "credential_id_hash": credential_hash,
        "user_verification": "required_and_verified",
        "purpose": purpose,
        "approval_ceremony_context_ref": null,
        "approval_ceremony_context_hash": null,
        "authorization_subject": null,
        "policy_hash": null,
        "effect_authority_created": false,
        "created_at": iso_now(),
    });
    if let Some((context, context_hash)) = approval_context {
        receipt["principal_ref"] = context["principal_ref"].clone();
        receipt["approval_ceremony_context_ref"] = context["approval_ceremony_context_ref"].clone();
        receipt["approval_ceremony_context_hash"] = json!(context_hash);
        receipt["authorization_subject"] = context["authorization_subject"].clone();
        receipt["policy_hash"] = context["policy_hash"].clone();
    }
    let canonical = serde_jcs::to_vec(&receipt)
        .map_err(|error| format!("passkey_receipt_hash_failed: {error}"))?;
    receipt["receipt_hash"] = json!(format!("sha256:{}", hex::encode(Sha256::digest(canonical))));
    const CONTRACT: &str = "schema://ioi/components/hypervisor/auth-factor-receipt/v1";
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        CONTRACT, &receipt,
    )
    .map_err(|error| format!("passkey_receipt_contract_invalid: {error}"))?;
    persist_record_durable(data_dir, RECEIPT_FAMILY, &receipt_id, &receipt)
        .map_err(|error| format!("passkey_receipt_persistence_failed: {error:?}"))?;
    Ok(receipt)
}

/// POST /v1/hypervisor/auth/passkeys/register/start
///
/// Password/OIDC/passkey identity may bootstrap enrollment, but this route mints no provider or
/// wallet authority. The server retains the paired registration state and returns only browser
/// creation options plus an opaque ceremony id.
pub(crate) async fn handle_registration_start(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_enrollment_authentication_required"})),
        );
    };
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let email = principal["email"].as_str().unwrap_or(principal_id);
    let display_name = principal["display_name"].as_str().unwrap_or(email);
    if principal_id.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"ok": false, "code": "passkey_principal_invalid"})),
        );
    }
    let existing = credential_records(&st.data_dir, principal_id);
    let excludes = (!existing.is_empty()).then(|| {
        existing
            .iter()
            .map(|(_, passkey)| passkey.cred_id().clone())
            .collect()
    });
    let webauthn = match webauthn() {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let (options, state) = match webauthn.start_passkey_registration(
        principal_uuid(principal_id),
        email,
        display_name,
        excludes,
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({"ok": false, "code": "passkey_registration_start_refused", "detail": error.to_string()}),
                ),
            )
        }
    };
    let ceremony_id = format!("pkc_{}", Uuid::new_v4().simple());
    let state = serde_json::to_value(state).expect("passkey registration state is serializable");
    if let Err(code) = persist_ceremony(
        &st.data_dir,
        &ceremony_id,
        "registration",
        principal_id,
        state,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "code": code})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"ok": true, "ceremony_id": ceremony_id, "public_key": options})),
    )
}

/// POST /v1/hypervisor/auth/passkeys/register/finish
pub(crate) async fn handle_registration_finish(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_enrollment_authentication_required"})),
        );
    };
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let ceremony_id = body["ceremony_id"].as_str().unwrap_or("");
    let ceremony = match consume_ceremony(&st.data_dir, ceremony_id, "registration") {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    if ceremony["principal_id"].as_str() != Some(principal_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "code": "passkey_ceremony_principal_mismatch"})),
        );
    }
    let state: PasskeyRegistration = match serde_json::from_value(ceremony["state"].clone()) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": "passkey_ceremony_state_invalid"})),
            )
        }
    };
    let credential: RegisterPublicKeyCredential = match serde_json::from_value(
        body.get("credential").cloned().unwrap_or(Value::Null),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"ok": false, "code": "passkey_registration_credential_invalid", "detail": error.to_string()}),
                ),
            )
        }
    };
    let passkey = match webauthn().and_then(|rp| {
        rp.finish_passkey_registration(&credential, &state)
            .map_err(|error| format!("passkey_registration_refused: {error}"))
    }) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let credential_id = credential_id_hex(&passkey);
    if read_record_dir(&st.data_dir, CREDENTIAL_FAMILY)
        .iter()
        .any(|record| record["credential_id"].as_str() == Some(credential_id.as_str()))
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "code": "passkey_credential_already_registered"})),
        );
    }
    let record_id = format!("pk_{}", short_hash(&sha256_hex_str(&credential_id)));
    let record = json!({
        "schema_version": "ioi.hypervisor.passkey-credential.v1",
        "credential_ref": format!("auth_factor://passkey/{record_id}"),
        "credential_id": credential_id,
        "principal_id": principal_id,
        "passkey": passkey,
        "status": "active",
        "revocation_epoch": 0,
        "created_at": iso_now(),
        "updated_at": iso_now(),
    });
    if let Err(error) = persist_record_durable(&st.data_dir, CREDENTIAL_FAMILY, &record_id, &record)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"ok": false, "code": "passkey_credential_persistence_failed", "detail": format!("{error:?}")}),
            ),
        );
    }
    let receipt = match persist_factor_receipt(
        &st.data_dir,
        ceremony_id,
        principal_id,
        record["credential_id"].as_str().unwrap_or(""),
        "custody_enrollment",
        None,
    ) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": code, "credential_persisted": true})),
            )
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "credential_ref": record["credential_ref"],
            "receipt_ref": format!("receipt://auth-factor/{}", receipt["receipt_id"].as_str().unwrap_or("")),
            "effect_authority_created": false,
        })),
    )
}

/// GET /v1/hypervisor/auth/passkeys
///
/// Returns public lifecycle metadata only. WebAuthn public-key material remains server-internal so
/// clients cannot accidentally treat this identity factor as an effect-authority credential.
pub(crate) async fn handle_passkey_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_authentication_required"})),
        );
    };
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let factors: Vec<Value> = all_credential_records(&st.data_dir, principal_id)
        .into_iter()
        .map(|record| {
            json!({
                "credential_ref": record["credential_ref"],
                "kind": "passkey",
                "authentication_protocol": "webauthn",
                "status": record["status"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
                "last_authenticated_at": record.get("last_authenticated_at").cloned().unwrap_or(Value::Null),
                "can_hold_grant": false,
                "can_release_secret": false,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({"ok": true, "factors": factors})),
    )
}

/// DELETE /v1/hypervisor/auth/passkeys/{credential_ref_id}
///
/// Revocation is durable and takes effect on the next authentication start or finish. It does not
/// alter, reset, or resurrect any separately owned authority-envelope state.
pub(crate) async fn handle_passkey_revoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(record_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_authentication_required"})),
        );
    };
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let expected_ref = format!("auth_factor://passkey/{record_id}");
    let _guard = match ceremony_lock().lock() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": "passkey_ceremony_lock_poisoned"})),
            )
        }
    };
    let Some(mut record) = all_credential_records(&st.data_dir, principal_id)
        .into_iter()
        .find(|record| record["credential_ref"].as_str() == Some(expected_ref.as_str()))
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "code": "passkey_credential_not_found"})),
        );
    };
    if record["status"].as_str() == Some("revoked") {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "code": "passkey_credential_already_revoked"})),
        );
    }
    record["status"] = json!("revoked");
    record["revoked_at"] = json!(iso_now());
    record["updated_at"] = json!(iso_now());
    record["revocation_epoch"] = json!(record["revocation_epoch"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(1));
    if let Err(error) = persist_record_durable(&st.data_dir, CREDENTIAL_FAMILY, &record_id, &record)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"ok": false, "code": "passkey_credential_revocation_failed", "detail": format!("{error:?}")}),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "credential_ref": expected_ref,
            "status": "revoked",
            "effect_authority_changed": false,
        })),
    )
}

/// POST /v1/hypervisor/auth/passkeys/authority/start
///
/// Starts a second, effect-consent ceremony for an already authenticated operator. The
/// authenticator challenge is exactly the domain-separated approval-ceremony-context hash. The
/// resulting factor receipt can be committed into a standing grant, but this route creates no
/// grant, capability, provider credential, or provider effect.
pub(crate) async fn handle_authority_start(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_authority_authentication_required"})),
        );
    };
    let Some(body_object) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "code": "passkey_authority_request_invalid"})),
        );
    };
    if body_object.len() != 2
        || !body_object.contains_key("approval_ceremony_context")
        || !body_object.contains_key("approval_ceremony_context_hash")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "code": "passkey_authority_request_fields_invalid"})),
        );
    }
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let principal_ref = principal["principal_ref"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("user://{principal_id}"));
    let context = &body["approval_ceremony_context"];
    let context_hash = body["approval_ceremony_context_hash"]
        .as_str()
        .unwrap_or("");
    let challenge = match validate_approval_context(context, context_hash, &principal_ref) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let passkeys: Vec<Passkey> = credential_records(&st.data_dir, principal_id)
        .into_iter()
        .map(|(_, passkey)| passkey)
        .collect();
    if passkeys.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"ok": false, "code": "passkey_authority_factor_unavailable"})),
        );
    }
    let started = webauthn()
        .and_then(|rp| {
            rp.start_passkey_authentication(&passkeys)
                .map_err(|error| format!("passkey_authority_start_refused: {error}"))
        })
        .and_then(|(options, state)| bind_authentication_challenge(options, state, challenge));
    let (options, state) = match started {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let ceremony_id = format!("pkc_{}", Uuid::new_v4().simple());
    let state = serde_json::to_value(state).expect("passkey authentication state is serializable");
    if let Err(code) = persist_ceremony_with_context(
        &st.data_dir,
        &ceremony_id,
        "effect_authority",
        principal_id,
        state,
        Some((context, context_hash)),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "code": code})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ceremony_id": ceremony_id,
            "approval_ceremony_context_ref": context["approval_ceremony_context_ref"],
            "approval_ceremony_context_hash": context_hash,
            "public_key": options,
            "effect_authority_created": false,
        })),
    )
}

/// POST /v1/hypervisor/auth/passkeys/authority/finish
pub(crate) async fn handle_authority_finish(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_authority_authentication_required"})),
        );
    };
    let Some(body_object) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "code": "passkey_authority_request_invalid"})),
        );
    };
    if body_object.len() != 2
        || !body_object.contains_key("ceremony_id")
        || !body_object.contains_key("credential")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "code": "passkey_authority_request_fields_invalid"})),
        );
    }
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    let principal_ref = principal["principal_ref"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("user://{principal_id}"));
    let ceremony_id = body["ceremony_id"].as_str().unwrap_or("");
    let ceremony = match consume_ceremony(&st.data_dir, ceremony_id, "effect_authority") {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    if ceremony["principal_id"].as_str() != Some(principal_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "code": "passkey_ceremony_principal_mismatch"})),
        );
    }
    let context = &ceremony["approval_ceremony_context"];
    let context_hash = ceremony["approval_ceremony_context_hash"]
        .as_str()
        .unwrap_or("");
    if let Err(code) = validate_approval_context(context, context_hash, &principal_ref) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "code": code})),
        );
    }
    let state: PasskeyAuthentication = match serde_json::from_value(ceremony["state"].clone()) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": "passkey_ceremony_state_invalid"})),
            )
        }
    };
    let credential: PublicKeyCredential = match serde_json::from_value(
        body.get("credential").cloned().unwrap_or(Value::Null),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"ok": false, "code": "passkey_authority_credential_invalid", "detail": error.to_string()}),
                ),
            )
        }
    };
    let result = match webauthn().and_then(|rp| {
        rp.finish_passkey_authentication(&credential, &state)
            .map_err(|error| format!("passkey_authority_refused: {error}"))
    }) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    if !result.user_verified() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_user_verification_required"})),
        );
    }
    let credential_id = hex::encode(result.cred_id().as_ref());
    let Some((mut record, mut passkey)) = credential_records(&st.data_dir, principal_id)
        .into_iter()
        .find(|(record, _)| record["credential_id"].as_str() == Some(credential_id.as_str()))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_credential_not_registered"})),
        );
    };
    passkey.update_credential(&result);
    record["passkey"] = serde_json::to_value(passkey).expect("passkey is serializable");
    record["updated_at"] = json!(iso_now());
    record["last_authorized_at"] = json!(iso_now());
    let record_id = record["credential_ref"]
        .as_str()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or("");
    if let Err(error) = persist_record_durable(&st.data_dir, CREDENTIAL_FAMILY, record_id, &record)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"ok": false, "code": "passkey_counter_persistence_failed", "detail": format!("{error:?}")}),
            ),
        );
    }
    let receipt = match persist_factor_receipt(
        &st.data_dir,
        ceremony_id,
        principal_id,
        &credential_id,
        "standing_effect_authority",
        Some((context, context_hash)),
    ) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "receipt_ref": format!("receipt://auth-factor/{}", receipt["receipt_id"].as_str().unwrap_or("")),
            "receipt_hash": receipt["receipt_hash"],
            "approval_ceremony_context_ref": context["approval_ceremony_context_ref"],
            "approval_ceremony_context_hash": context_hash,
            "authorization_subject": context["authorization_subject"],
            "effect_authority_created": false,
        })),
    )
}

/// POST /v1/hypervisor/auth/passkeys/login/start
pub(crate) async fn handle_login_start(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let email = body["email"].as_str().unwrap_or("").trim();
    let Some(principal) = read_record_dir(&st.data_dir, "principals")
        .into_iter()
        .find(|record| {
            record["email"].as_str().map(str::to_ascii_lowercase)
                == Some(email.to_ascii_lowercase())
        })
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_login_unavailable"})),
        );
    };
    let principal_id = principal["principal_id"].as_str().unwrap_or("");
    if principal["status"].as_str() != Some("active") || principal_id.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_login_unavailable"})),
        );
    }
    let passkeys: Vec<Passkey> = credential_records(&st.data_dir, principal_id)
        .into_iter()
        .map(|(_, passkey)| passkey)
        .collect();
    if passkeys.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_login_unavailable"})),
        );
    }
    let (options, state) = match webauthn().and_then(|rp| {
        rp.start_passkey_authentication(&passkeys)
            .map_err(|error| format!("passkey_authentication_start_refused: {error}"))
    }) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let ceremony_id = format!("pkc_{}", Uuid::new_v4().simple());
    let state = serde_json::to_value(state).expect("passkey authentication state is serializable");
    if let Err(code) = persist_ceremony(
        &st.data_dir,
        &ceremony_id,
        "authentication",
        principal_id,
        state,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "code": code})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"ok": true, "ceremony_id": ceremony_id, "public_key": options})),
    )
}

/// POST /v1/hypervisor/auth/passkeys/login/finish
pub(crate) async fn handle_login_finish(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let ceremony_id = body["ceremony_id"].as_str().unwrap_or("");
    let ceremony = match consume_ceremony(&st.data_dir, ceremony_id, "authentication") {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let principal_id = ceremony["principal_id"].as_str().unwrap_or("");
    let principal_is_active =
        read_record_dir(&st.data_dir, "principals")
            .into_iter()
            .any(|record| {
                record["principal_id"].as_str() == Some(principal_id)
                    && record["status"].as_str() == Some("active")
            });
    if principal_id.is_empty() || !principal_is_active {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_login_unavailable"})),
        );
    }
    let state: PasskeyAuthentication = match serde_json::from_value(ceremony["state"].clone()) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": "passkey_ceremony_state_invalid"})),
            )
        }
    };
    let credential: PublicKeyCredential = match serde_json::from_value(
        body.get("credential").cloned().unwrap_or(Value::Null),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"ok": false, "code": "passkey_authentication_credential_invalid", "detail": error.to_string()}),
                ),
            )
        }
    };
    let result = match webauthn().and_then(|rp| {
        rp.finish_passkey_authentication(&credential, &state)
            .map_err(|error| format!("passkey_authentication_refused: {error}"))
    }) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    if !result.user_verified() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_user_verification_required"})),
        );
    }
    let credential_id = hex::encode(result.cred_id().as_ref());
    let Some((mut record, mut passkey)) = credential_records(&st.data_dir, principal_id)
        .into_iter()
        .find(|(record, _)| record["credential_id"].as_str() == Some(credential_id.as_str()))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "code": "passkey_credential_not_registered"})),
        );
    };
    passkey.update_credential(&result);
    record["passkey"] = serde_json::to_value(passkey).expect("passkey is serializable");
    record["updated_at"] = json!(iso_now());
    record["last_authenticated_at"] = json!(iso_now());
    let record_id = record["credential_ref"]
        .as_str()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or("");
    if let Err(error) = persist_record_durable(&st.data_dir, CREDENTIAL_FAMILY, record_id, &record)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"ok": false, "code": "passkey_counter_persistence_failed", "detail": format!("{error:?}")}),
            ),
        );
    }
    let receipt = match persist_factor_receipt(
        &st.data_dir,
        ceremony_id,
        principal_id,
        &credential_id,
        "identity_authentication",
        None,
    ) {
        Ok(value) => value,
        Err(code) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "code": code})),
            )
        }
    };
    let (status, mut session) = issue_session(&st.data_dir, principal_id, "passkey");
    if let Some(object) = session.as_object_mut() {
        object.insert(
            "auth_factor_receipt_ref".to_string(),
            json!(format!(
                "receipt://auth-factor/{}",
                receipt["receipt_id"].as_str().unwrap_or("")
            )),
        );
    }
    (status, Json(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn standing_approval_context(principal_ref: &str) -> Value {
        let issued_at = (OffsetDateTime::now_utc() - time::Duration::seconds(1))
            .format(&Rfc3339)
            .unwrap();
        let expires_at = (OffsetDateTime::now_utc() + time::Duration::minutes(4))
            .format(&Rfc3339)
            .unwrap();
        json!({
            "schema_version": "ioi.foundations.approval-ceremony-context.v1",
            "approval_ceremony_context_ref": "approval-ceremony-context://standing/test",
            "authority_request_ref": "authority-request://standing/test",
            "authority_request_body_hash": format!("sha256:{}", "1".repeat(64)),
            "authority_review_ref": "review://standing/test",
            "authority_review_body_hash": format!("sha256:{}", "2".repeat(64)),
            "predecessor_authority_review_ref": null,
            "predecessor_authority_review_body_hash": null,
            "predecessor_authority_request_ref": null,
            "predecessor_authority_request_body_hash": null,
            "predecessor_authority_review_receipt_ref": null,
            "predecessor_authority_review_receipt_hash": null,
            "reviewed_representation_hash": format!("sha256:{}", "3".repeat(64)),
            "principal_ref": principal_ref,
            "acting_subject_ref": "runtime://hypervisor/operator",
            "product_session_ref": "session://hypervisor/test",
            "origin_binding_ref": "origin://hypervisor/local",
            "authorization_subject": {
                "kind": "standing_envelope",
                "subject_ref": "standing-envelope://aft/test",
                "subject_hash": format!("sha256:{}", "4".repeat(64)),
                "validation_profile_ref": "schema://ioi/foundations/standing-authority-envelope/v1"
            },
            "presentation_surface_ref": "wallet-client://hypervisor/local",
            "presentation_evidence_profile_ref": "policy://presentation/local/v1",
            "principal_authority_resolution_ref": null,
            "principal_authority_resolution_hash": null,
            "required_auth_factor_posture_refs": ["auth_factor://passkey/operator/device"],
            "required_guardian_surface_refs": [],
            "posture_satisfaction_profile_ref": "policy://auth-posture/step-up/v1",
            "interaction_mode": "interactive",
            "authentication_posture": "step_up",
            "receipt_timing": "before_effect",
            "policy_decision_receipt_ref": "receipt://policy/standing-test",
            "policy_decision_receipt_hash": format!("sha256:{}", "5".repeat(64)),
            "policy_hash": format!("sha256:{}", "6".repeat(64)),
            "risk_classes": ["external_spend", "standing_authority"],
            "revocation_epoch": 1,
            "nonce_b64url": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            "issued_at": issued_at,
            "expires_at": expires_at,
            "single_use": true
        })
    }

    #[test]
    fn principal_user_handle_is_stable_and_distinct() {
        assert_eq!(principal_uuid("operator"), principal_uuid("operator"));
        assert_ne!(principal_uuid("operator"), principal_uuid("worker"));
    }

    #[test]
    fn consumed_ceremony_is_durable_and_never_replayable() {
        let directory = tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        persist_ceremony(
            data_dir,
            "pkc_test",
            "authentication",
            "operator",
            json!({"opaque": true}),
        )
        .unwrap();
        let first = consume_ceremony(data_dir, "pkc_test", "authentication").unwrap();
        assert_eq!(first["status"], json!("consumed"));
        assert_eq!(
            consume_ceremony(data_dir, "pkc_test", "authentication").unwrap_err(),
            "passkey_ceremony_already_consumed"
        );
    }

    #[test]
    fn identity_factor_receipt_never_claims_effect_authority() {
        let directory = tempdir().unwrap();
        let receipt = persist_factor_receipt(
            directory.path().to_str().unwrap(),
            "pkc_test",
            "operator",
            "public-credential-id",
            "custody_enrollment",
            None,
        )
        .unwrap();
        assert_eq!(receipt["effect_authority_created"], json!(false));
        assert!(receipt.get("credential_id").is_none());
        assert!(receipt["receipt_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71));
    }

    #[test]
    fn standing_authority_context_is_the_exact_passkey_challenge() {
        let principal_ref = "user://operator";
        let context = standing_approval_context(principal_ref);
        let context_hash = approval_context_hash(&context).unwrap();
        let challenge = validate_approval_context(&context, &context_hash, principal_ref).unwrap();
        assert_eq!(format!("sha256:{}", hex::encode(challenge)), context_hash);

        let mut widened = context.clone();
        widened["authorization_subject"]["subject_hash"] =
            json!(format!("sha256:{}", "7".repeat(64)));
        assert_eq!(
            validate_approval_context(&widened, &context_hash, principal_ref).unwrap_err(),
            "approval_ceremony_context_hash_mismatch"
        );
    }

    #[test]
    fn authority_context_refuses_future_or_overlong_validity() {
        let principal_ref = "user://operator";
        let mut future = standing_approval_context(principal_ref);
        future["issued_at"] = json!((OffsetDateTime::now_utc() + time::Duration::minutes(1))
            .format(&Rfc3339)
            .unwrap());
        future["expires_at"] = json!((OffsetDateTime::now_utc() + time::Duration::minutes(4))
            .format(&Rfc3339)
            .unwrap());
        let future_hash = approval_context_hash(&future).unwrap();
        assert_eq!(
            validate_approval_context(&future, &future_hash, principal_ref).unwrap_err(),
            "approval_ceremony_context_validity_invalid"
        );

        let mut overlong = standing_approval_context(principal_ref);
        overlong["issued_at"] = json!((OffsetDateTime::now_utc() - time::Duration::minutes(2))
            .format(&Rfc3339)
            .unwrap());
        overlong["expires_at"] = json!((OffsetDateTime::now_utc() + time::Duration::minutes(4))
            .format(&Rfc3339)
            .unwrap());
        let overlong_hash = approval_context_hash(&overlong).unwrap();
        assert_eq!(
            validate_approval_context(&overlong, &overlong_hash, principal_ref).unwrap_err(),
            "approval_ceremony_context_validity_invalid"
        );
    }

    #[test]
    fn authority_context_refuses_malformed_optional_hashes() {
        let principal_ref = "user://operator";
        let mut context = standing_approval_context(principal_ref);
        context["principal_authority_resolution_ref"] =
            json!("artifact://authority-resolution/test");
        context["principal_authority_resolution_hash"] = json!("sha256:not-a-hash");
        let context_hash = approval_context_hash(&context).unwrap();
        assert!(
            validate_approval_context(&context, &context_hash, principal_ref)
                .unwrap_err()
                .contains("approval_ceremony_context_contract_invalid")
        );
    }

    #[test]
    fn authority_factor_receipt_binds_context_but_creates_no_authority() {
        let directory = tempdir().unwrap();
        let context = standing_approval_context("user://operator");
        let context_hash = approval_context_hash(&context).unwrap();
        let receipt = persist_factor_receipt(
            directory.path().to_str().unwrap(),
            "pkc_authority",
            "operator",
            "public-credential-id",
            "standing_effect_authority",
            Some((&context, &context_hash)),
        )
        .unwrap();
        assert_eq!(receipt["approval_ceremony_context_hash"], context_hash);
        assert_eq!(
            receipt["authorization_subject"]["kind"],
            "standing_envelope"
        );
        assert_eq!(receipt["effect_authority_created"], false);
    }

    #[test]
    fn revoked_passkeys_are_not_authentication_candidates() {
        let directory = tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let record = json!({
            "principal_id": "operator",
            "status": "revoked",
            "passkey": Value::Null,
        });
        persist_record_durable(data_dir, CREDENTIAL_FAMILY, "pk_revoked", &record).unwrap();
        assert!(credential_records(data_dir, "operator").is_empty());
        assert_eq!(all_credential_records(data_dir, "operator").len(), 1);
    }
}
