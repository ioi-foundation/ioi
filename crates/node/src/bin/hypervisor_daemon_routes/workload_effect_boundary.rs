//! Workload-bound guest proposal broker for the `trusted_host_hostile_guest` profile.
//!
//! A guest receives one opaque bearer capability for one canonical request. The durable record
//! binds it to the admitted isolation binding, principal, nonce, audience, resource, result
//! destination, and expiry. The broker persists `claimed` before entering its caller-supplied final
//! invoker. A process loss in that window becomes `reconciliation_required`; it never replays.
//! Provider credentials and signing material are not inputs to this module and never enter the
//! guest envelope.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine as _;
use ioi_types::app::generated::architecture_contracts::{
    HypervisorWorkloadBoundEffectProposalV1, HypervisorWorkloadEffectConsumptionReceiptV1,
    HypervisorWorkloadEffectReconciliationReceiptV1,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FAMILY: &str = "workload-effect-capabilities";
const MAX_PROPOSAL_BYTES: usize = 64 * 1024;
static CONSUMPTION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct GovernedEffectRefusal {
    code: String,
    effect_receipt: Option<Value>,
}

impl From<String> for GovernedEffectRefusal {
    fn from(code: String) -> Self {
        Self {
            code,
            effect_receipt: None,
        }
    }
}

impl From<&str> for GovernedEffectRefusal {
    fn from(code: &str) -> Self {
        code.to_owned().into()
    }
}

fn consumption_lock() -> &'static tokio::sync::Mutex<()> {
    CONSUMPTION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn sha256_ref(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_hash(value: &Value) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| format!("workload_effect_proposal_not_canonicalizable: {error}"))?;
    if bytes.len() > MAX_PROPOSAL_BYTES {
        return Err("workload_effect_proposal_oversized".into());
    }
    Ok(sha256_ref(&bytes))
}

fn valid_ref(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 512
        && !value.chars().any(char::is_whitespace)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let longest = left.len().max(right.len());
    for index in 0..longest {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn required_text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("workload_effect_{field}_required"))
}

fn persist(data_dir: &str, id: &str, record: &Value) -> Result<(), String> {
    super::durable_fs::persist_record_durable(data_dir, FAMILY, id, record).map_err(|error| {
        format!(
            "workload_effect_capability_persistence_failed: {}",
            error.detail()
        )
    })
}

/// Mint an exact one-use capability. The plaintext token exists only in this return value; durable
/// state stores its hash. `exact_request` must already be the daemon-issued proposal body the final
/// invoker will consume.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_guest_effect_capability(
    data_dir: &str,
    isolation_binding_ref: &str,
    isolation_binding_hash: &str,
    principal_ref: &str,
    proposal_nonce: &str,
    audience: &str,
    resource_ref: &str,
    result_destination_ref: &str,
    exact_request: &Value,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Value, String> {
    if !valid_ref(isolation_binding_ref, "workload-isolation-binding://") {
        return Err("workload_effect_isolation_binding_ref_invalid".into());
    }
    if !valid_ref(principal_ref, "principal://") {
        return Err("workload_effect_principal_ref_invalid".into());
    }
    if !valid_ref(resource_ref, "provider-resource://") {
        return Err("workload_effect_resource_ref_invalid".into());
    }
    if !valid_ref(result_destination_ref, "result-destination://") {
        return Err("workload_effect_result_destination_ref_invalid".into());
    }
    if !isolation_binding_hash.starts_with("sha256:") || isolation_binding_hash.len() != 71 {
        return Err("workload_effect_isolation_binding_hash_invalid".into());
    }
    if proposal_nonce.is_empty()
        || proposal_nonce.len() > 256
        || audience != "hypervisor-final-invoker"
    {
        return Err("workload_effect_channel_context_invalid".into());
    }
    if expires_at_ms <= issued_at_ms || expires_at_ms.saturating_sub(issued_at_ms) > 15 * 60 * 1000
    {
        return Err("workload_effect_expiry_invalid".into());
    }

    let request_hash = canonical_hash(exact_request)?;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let token = format!("wec_{}", hex::encode(random));
    let token_hash = sha256_ref(token.as_bytes());
    let id = format!(
        "wec_{}",
        &hex::encode(Sha256::digest(token.as_bytes()))[..32]
    );
    let capability_ref = format!("workload-effect-capability://{id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.workload-effect-capability-record.v1",
        "capability_ref": capability_ref,
        "token_hash": token_hash,
        "isolation_binding_ref": isolation_binding_ref,
        "isolation_binding_hash": isolation_binding_hash,
        "principal_ref": principal_ref,
        "proposal_nonce": proposal_nonce,
        "audience": audience,
        "resource_ref": resource_ref,
        "result_destination_ref": result_destination_ref,
        "request_hash": request_hash,
        "exact_request": exact_request,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "status": "issued",
        "final_invoker_calls": 0,
    });
    persist(data_dir, &id, &record)?;
    let proposal = json!({
        "schema_version": "ioi.components.hypervisor.workload-bound-effect-proposal.v1",
        "capability_ref": capability_ref,
        "capability_token": token,
        "isolation_binding_ref": isolation_binding_ref,
        "isolation_binding_hash": isolation_binding_hash,
        "principal_ref": principal_ref,
        "proposal_nonce": proposal_nonce,
        "audience": audience,
        "resource_ref": resource_ref,
        "result_destination_ref": result_destination_ref,
        "request_hash": request_hash,
        "exact_request": exact_request,
        "expires_at_ms": expires_at_ms,
    });
    serde_json::from_value::<HypervisorWorkloadBoundEffectProposalV1>(proposal.clone())
        .map_err(|error| format!("workload_effect_proposal_contract_invalid: {error}"))?;
    Ok(proposal)
}

const HOST_ONLY_PROVIDER_AUTHORITY_FIELDS: &[&str] = &[
    "wallet_approval_grant",
    "wallet_standing_approval_grant",
    "standing_authority_envelope",
    "operation_proposal_ref",
];

fn split_host_provider_authority(full_request: &Value) -> Result<(Value, Value), String> {
    let mut guest_request = full_request.clone();
    let guest = guest_request
        .as_object_mut()
        .ok_or("workload_effect_provider_request_object_required")?;
    let mut attachment = serde_json::Map::new();
    for field in HOST_ONLY_PROVIDER_AUTHORITY_FIELDS {
        if let Some(value) = guest.remove(*field) {
            attachment.insert((*field).to_owned(), value);
        }
    }
    let one_shot = attachment
        .get("wallet_approval_grant")
        .is_some_and(|value| !value.is_null());
    let standing_grant = attachment
        .get("wallet_standing_approval_grant")
        .is_some_and(|value| !value.is_null());
    let standing_envelope = attachment
        .get("standing_authority_envelope")
        .is_some_and(|value| !value.is_null());
    if one_shot == standing_grant || standing_grant != standing_envelope {
        return Err("workload_effect_host_authority_mode_invalid".into());
    }
    if !attachment
        .get("operation_proposal_ref")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("provider-operation-proposal://"))
    {
        return Err("workload_effect_host_proposal_ref_required".into());
    }
    if required_text(&guest_request, "owner_ref")?.is_empty()
        || required_text(&guest_request, "idempotency_key")?.is_empty()
    {
        return Err("workload_effect_host_owner_binding_required".into());
    }
    Ok((guest_request, Value::Object(attachment)))
}

fn verified_host_provider_authority(record: &Value) -> Result<Value, String> {
    let attachment = record
        .get("host_authority_attachment")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or("workload_effect_host_authority_attachment_required")?;
    if canonical_hash(&attachment)? != required_text(record, "host_authority_attachment_hash")? {
        return Err("workload_effect_host_authority_attachment_hash_mismatch".into());
    }
    Ok(attachment)
}

fn verify_host_trigger(record: &Value, host_trigger: &str) -> Result<(), String> {
    let observed_trigger_hash = sha256_ref(host_trigger.as_bytes());
    let expected_trigger_hash = required_text(record, "host_trigger_hash")?;
    if !host_trigger.starts_with("wbt_")
        || host_trigger.len() != 68
        || !constant_time_eq(
            observed_trigger_hash.as_bytes(),
            expected_trigger_hash.as_bytes(),
        )
    {
        return Err("workload_effect_host_trigger_invalid".into());
    }
    Ok(())
}

/// Mint a guest-visible capability for the full governed provider lane.  The guest receives the
/// exact non-authorizing request and one opaque token.  Wallet grants, the standing envelope, and
/// the daemon proposal ref remain in the host-only durable record; no bearer operator session is
/// retained.  Their canonical hash is committed before the capability is emitted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_guest_governed_provider_effect_capability(
    data_dir: &str,
    isolation_binding_ref: &str,
    isolation_binding_hash: &str,
    principal_ref: &str,
    proposal_nonce: &str,
    resource_ref: &str,
    result_destination_ref: &str,
    full_provider_request: &Value,
    authenticated_principal_ref: &str,
    proposal_session_binding: &str,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Value, String> {
    let (guest_request, host_authority) = split_host_provider_authority(full_provider_request)?;
    if !authenticated_principal_ref.starts_with("user://")
        || authenticated_principal_ref.chars().any(char::is_whitespace)
        || !proposal_session_binding.starts_with("sha256:")
        || proposal_session_binding.len() != 71
    {
        return Err("workload_effect_host_principal_binding_invalid".into());
    }
    let proposal = mint_guest_effect_capability(
        data_dir,
        isolation_binding_ref,
        isolation_binding_hash,
        principal_ref,
        proposal_nonce,
        "hypervisor-final-invoker",
        resource_ref,
        result_destination_ref,
        &guest_request,
        issued_at_ms,
        expires_at_ms,
    )?;
    let id = record_id(&proposal)?;
    let mut record = load(data_dir, id)?;
    let mut trigger_random = [0u8; 32];
    OsRng.fill_bytes(&mut trigger_random);
    let host_trigger = format!("wbt_{}", hex::encode(trigger_random));
    record["host_trigger_hash"] = json!(sha256_ref(host_trigger.as_bytes()));
    record["host_authority_attachment_hash"] = json!(canonical_hash(&host_authority)?);
    record["host_authority_attachment"] = host_authority;
    record["authenticated_principal_ref"] = json!(authenticated_principal_ref);
    record["proposal_session_binding"] = json!(proposal_session_binding);
    persist(data_dir, id, &record)?;
    Ok(json!({
        "schema_version": "ioi.hypervisor.workload-effect-broker-bundle.v1",
        "guest_proposal": proposal,
        "host_trigger": host_trigger,
    }))
}

fn record_id_from_capability_ref(capability_ref: &str) -> Result<&str, String> {
    capability_ref
        .strip_prefix("workload-effect-capability://")
        .filter(|id| id.starts_with("wec_") && id.len() == 36)
        .ok_or_else(|| "workload_effect_capability_ref_invalid".into())
}

fn record_id(proposal: &Value) -> Result<&str, String> {
    record_id_from_capability_ref(required_text(proposal, "capability_ref")?)
}

fn load(data_dir: &str, id: &str) -> Result<Value, String> {
    super::durable_fs::read_record_durable(data_dir, FAMILY, id)
        .map_err(|error| format!("workload_effect_capability_read_refused: {error:?}"))?
        .ok_or_else(|| "workload_effect_capability_absent".into())
}

fn parse_canonical_proposal_bytes(proposal_bytes: &[u8]) -> Result<Value, String> {
    if proposal_bytes.len() > MAX_PROPOSAL_BYTES {
        return Err("workload_effect_proposal_oversized".into());
    }
    let proposal: Value = serde_json::from_slice(proposal_bytes)
        .map_err(|error| format!("workload_effect_proposal_json_invalid: {error}"))?;
    let canonical = serde_jcs::to_vec(&proposal)
        .map_err(|error| format!("workload_effect_proposal_not_canonicalizable: {error}"))?;
    if !constant_time_eq(proposal_bytes, &canonical) {
        return Err("workload_effect_proposal_noncanonical".into());
    }
    Ok(proposal)
}

fn static_provider_coordinates(proposal: &Value) -> Result<(&Value, &str, &str), String> {
    let request = proposal
        .get("exact_request")
        .ok_or("workload_effect_exact_request_required")?;
    let provider_id = required_text(request, "provider_id")?;
    let environment_ref = required_text(request, "environment_ref")?;
    let expected_resource = format!("provider-resource://{provider_id}/{environment_ref}");
    if required_text(proposal, "resource_ref")? != expected_resource {
        return Err("workload_effect_provider_resource_binding_mismatch".into());
    }
    Ok((request, provider_id, environment_ref))
}

fn provider_operation_count(data_dir: &str, provider_id: &str, environment_ref: &str) -> u64 {
    super::read_record_dir(data_dir, "provider-operations")
        .into_iter()
        .filter(|record| {
            record.get("provider").and_then(Value::as_str) == Some(provider_id)
                && record.get("environment_ref").and_then(Value::as_str) == Some(environment_ref)
        })
        .count() as u64
}

fn proposal_matches_record(proposal: &Value, record: &Value) -> Result<(), String> {
    if proposal.get("schema_version").and_then(Value::as_str)
        != Some("ioi.components.hypervisor.workload-bound-effect-proposal.v1")
    {
        return Err("workload_effect_proposal_schema_invalid".into());
    }
    for field in [
        "capability_ref",
        "isolation_binding_ref",
        "isolation_binding_hash",
        "principal_ref",
        "proposal_nonce",
        "audience",
        "resource_ref",
        "result_destination_ref",
        "request_hash",
        "expires_at_ms",
        "exact_request",
    ] {
        if proposal.get(field) != record.get(field) {
            return Err(format!("workload_effect_{field}_substitution_refused"));
        }
    }
    let token = required_text(proposal, "capability_token")?;
    let observed = sha256_ref(token.as_bytes());
    let expected = required_text(record, "token_hash")?;
    if !constant_time_eq(observed.as_bytes(), expected.as_bytes()) {
        return Err("workload_effect_capability_token_invalid".into());
    }
    if canonical_hash(&proposal["exact_request"])? != required_text(record, "request_hash")? {
        return Err("workload_effect_request_hash_mismatch".into());
    }
    Ok(())
}

/// Durably claim, invoke exactly once, and settle a guest proposal. The callback is the sole final
/// invoker seam; direct guest network attempts are counted independently by the VM boundary probe.
fn consume_guest_effect_capability<F>(
    data_dir: &str,
    proposal: &Value,
    now_ms: u64,
    final_invoker: F,
) -> Result<Value, String>
where
    F: FnOnce(&Value) -> Result<Value, String>,
{
    let _guard = consumption_lock().blocking_lock();
    let id = record_id(proposal)?;
    let mut record = load(data_dir, id)?;
    proposal_matches_record(proposal, &record)?;
    if now_ms > record["expires_at_ms"].as_u64().unwrap_or_default() {
        return Err("workload_effect_capability_expired".into());
    }
    match record["status"].as_str().unwrap_or_default() {
        "issued" => {}
        "claimed" | "reconciliation_required" => {
            if record["status"] == "claimed" {
                record["status"] = json!("reconciliation_required");
                record["reconciliation_reason"] = json!("prior_process_lost_after_durable_claim");
                persist(data_dir, id, &record)?;
            }
            return Err("workload_effect_prior_claim_requires_reconciliation".into());
        }
        _ => return Err("workload_effect_capability_already_consumed".into()),
    }

    record["status"] = json!("claimed");
    record["claimed_at_ms"] = json!(now_ms);
    persist(data_dir, id, &record)?;
    super::durable_fs::test_crash_pause_if_selected(
        "IOI_TEST_CRASH_AT",
        "workload_effect_claimed",
        "IOI_TEST_CRASH_MARKER_PATH",
        id,
    )
    .map_err(|error| format!("workload_effect_crash_coordination_failed: {error}"))?;

    match final_invoker(&record["exact_request"]) {
        Ok(effect_receipt) => {
            record["status"] = json!("consumed");
            record["final_invoker_calls"] = json!(1);
            record["effect_receipt_hash"] = json!(canonical_hash(&effect_receipt)?);
            record["settled_at_ms"] = json!(now_ms);
            persist(data_dir, id, &record)?;
            let receipt = json!({
                "schema_version": "ioi.components.hypervisor.workload-effect-consumption-receipt.v1",
                "capability_ref": record["capability_ref"],
                "isolation_binding_ref": record["isolation_binding_ref"],
                "principal_ref": record["principal_ref"],
                "request_hash": record["request_hash"],
                "effect_receipt_hash": record["effect_receipt_hash"],
                "final_invoker_calls": 1,
                "status": "consumed"
            });
            serde_json::from_value::<HypervisorWorkloadEffectConsumptionReceiptV1>(receipt.clone())
                .map_err(|error| format!("workload_effect_receipt_contract_invalid: {error}"))?;
            Ok(receipt)
        }
        Err(reason) => {
            record["status"] = json!("refused");
            record["final_invoker_calls"] = json!(0);
            record["refusal_reason"] = json!(reason.clone());
            record["settled_at_ms"] = json!(now_ms);
            persist(data_dir, id, &record)?;
            Err(format!("workload_effect_final_invoker_refused: {reason}"))
        }
    }
}

/// Async form of the exact same durable one-use boundary.  The async mutex remains held across
/// the host final invoker so an in-process replay cannot turn a currently executing claim into a
/// restart ambiguity.  A process death still leaves the durable `claimed` record for the explicit
/// reconciler, exactly like the synchronous path.
async fn consume_guest_effect_capability_async<F, Fut>(
    data_dir: &str,
    proposal: &Value,
    now_ms: u64,
    final_invoker: F,
) -> Result<Value, GovernedEffectRefusal>
where
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<Value, GovernedEffectRefusal>>,
{
    let _guard = consumption_lock().lock().await;
    let id = record_id(proposal)?;
    let mut record = load(data_dir, id)?;
    proposal_matches_record(proposal, &record)?;
    if now_ms > record["expires_at_ms"].as_u64().unwrap_or_default() {
        return Err("workload_effect_capability_expired".into());
    }
    match record["status"].as_str().unwrap_or_default() {
        "issued" => {}
        "claimed" | "reconciliation_required" => {
            if record["status"] == "claimed" {
                record["status"] = json!("reconciliation_required");
                record["reconciliation_reason"] = json!("prior_process_lost_after_durable_claim");
                persist(data_dir, id, &record)?;
            }
            return Err("workload_effect_prior_claim_requires_reconciliation".into());
        }
        _ => return Err("workload_effect_capability_already_consumed".into()),
    }

    record["status"] = json!("claimed");
    record["claimed_at_ms"] = json!(now_ms);
    persist(data_dir, id, &record)?;
    super::durable_fs::test_crash_pause_if_selected(
        "IOI_TEST_CRASH_AT",
        "workload_effect_claimed",
        "IOI_TEST_CRASH_MARKER_PATH",
        id,
    )
    .map_err(|error| format!("workload_effect_crash_coordination_failed: {error}"))?;

    match final_invoker(record["exact_request"].clone()).await {
        Ok(effect_receipt) => {
            record["status"] = json!("consumed");
            record["final_invoker_calls"] = json!(1);
            record["effect_receipt_hash"] = json!(canonical_hash(&effect_receipt)?);
            record["settled_at_ms"] = json!(now_ms);
            persist(data_dir, id, &record)?;
            let receipt = json!({
                "schema_version": "ioi.components.hypervisor.workload-effect-consumption-receipt.v1",
                "capability_ref": record["capability_ref"],
                "isolation_binding_ref": record["isolation_binding_ref"],
                "principal_ref": record["principal_ref"],
                "request_hash": record["request_hash"],
                "effect_receipt_hash": record["effect_receipt_hash"],
                "final_invoker_calls": 1,
                "status": "consumed"
            });
            serde_json::from_value::<HypervisorWorkloadEffectConsumptionReceiptV1>(receipt.clone())
                .map_err(|error| format!("workload_effect_receipt_contract_invalid: {error}"))?;
            Ok(json!({
                "consumption_receipt": receipt,
                "effect_receipt": effect_receipt,
            }))
        }
        Err(refusal) => {
            let final_invoker_calls = usize::from(refusal.effect_receipt.is_some());
            record["status"] = json!("refused");
            record["final_invoker_calls"] = json!(final_invoker_calls);
            record["refusal_reason"] = json!(refusal.code.clone());
            if let Some(effect_receipt) = refusal.effect_receipt.as_ref() {
                record["effect_receipt_hash"] = json!(canonical_hash(effect_receipt)?);
            }
            record["settled_at_ms"] = json!(now_ms);
            persist(data_dir, id, &record)?;
            Err(GovernedEffectRefusal {
                code: format!("workload_effect_final_invoker_refused: {}", refusal.code),
                effect_receipt: refusal.effect_receipt,
            })
        }
    }
}

/// Cross the guest parser boundary only with byte-canonical JSON. This rejects duplicate-key,
/// whitespace, numeric-spelling, and ordering differentials before the proposal can be interpreted
/// by a second component under different JSON semantics.
pub(crate) fn consume_guest_effect_proposal_bytes<F>(
    data_dir: &str,
    proposal_bytes: &[u8],
    now_ms: u64,
    final_invoker: F,
) -> Result<Value, String>
where
    F: FnOnce(&Value) -> Result<Value, String>,
{
    let proposal = parse_canonical_proposal_bytes(proposal_bytes)?;
    consume_guest_effect_capability(data_dir, &proposal, now_ms, final_invoker)
}

/// Cross from a canonical guest proposal into the daemon's existing static-provider final
/// invoker. This is intentionally an internal composition seam, not an HTTP route available to
/// the guest. The request's provider/environment coordinates must name the capability resource.
pub(crate) fn consume_guest_static_provider_operation_bytes(
    data_dir: &str,
    proposal_bytes: &[u8],
    now_ms: u64,
) -> Result<Value, String> {
    let proposal = parse_canonical_proposal_bytes(proposal_bytes)?;
    static_provider_coordinates(&proposal)?;

    consume_guest_effect_capability(data_dir, &proposal, now_ms, |exact_request| {
        let (status, axum::Json(reply)) =
            super::provider_routes::invoke_static_provider_operation(data_dir, exact_request);
        if !status.is_success() || reply.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "provider_final_invoker_refused:{}",
                reply
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        Ok(reply)
    })
}

/// Cross the hostile-guest boundary into the complete governed provider path.  The host-only
/// attachment is recovered from the durable capability record, hash-checked, and combined with
/// the guest's immutable non-authorizing request only after the one-use capability is durably
/// claimed.  This invokes the same wallet draw, proposal consumption, C2 intent/outcome, provider,
/// receipt, teardown, and settlement implementation used by the public provider route.
pub(crate) async fn consume_guest_governed_provider_operation_bytes(
    st: Arc<super::DaemonState>,
    proposal_bytes: &[u8],
    host_trigger: &str,
    now_ms: u64,
) -> Result<Value, GovernedEffectRefusal> {
    let proposal = parse_canonical_proposal_bytes(proposal_bytes)?;
    static_provider_coordinates(&proposal)?;
    let id = record_id(&proposal)?;
    let record = load(&st.data_dir, id)?;
    proposal_matches_record(&proposal, &record)?;
    verify_host_trigger(&record, host_trigger)?;
    let attachment = verified_host_provider_authority(&record)?;
    let authenticated_principal_ref =
        required_text(&record, "authenticated_principal_ref")?.to_owned();
    let proposal_session_binding = required_text(&record, "proposal_session_binding")?.to_owned();
    let correlation_ref = required_text(&record, "capability_ref")?.to_owned();
    let data_dir = st.data_dir.clone();
    let broker_data_dir = data_dir.clone();

    consume_guest_effect_capability_async(
        &data_dir,
        &proposal,
        now_ms,
        move |mut guest_request| async move {
            let target = guest_request
                .as_object_mut()
                .ok_or_else(|| "workload_effect_provider_request_object_required".to_string())?;
            for (key, value) in attachment
                .as_object()
                .ok_or_else(|| "workload_effect_host_authority_attachment_required".to_string())?
            {
                if target.insert(key.clone(), value.clone()).is_some() {
                    return Err(
                        String::from("workload_effect_guest_authority_field_collision").into(),
                    );
                }
            }
            let owner_ref = required_text(&guest_request, "owner_ref")?.to_owned();
            let idempotency_key = required_text(&guest_request, "idempotency_key")?.to_owned();
            let authority = super::provider_routes::WorkloadBrokerProviderAuthority::resolve(
                &broker_data_dir,
                &authenticated_principal_ref,
                &owner_ref,
                &idempotency_key,
                &proposal_session_binding,
                &correlation_ref,
            )
            .map_err(|(_, axum::Json(reply))| {
                GovernedEffectRefusal::from(format!(
                    "provider_broker_authority_refused:{}",
                    reply
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ))
            })?;
            let (status, axum::Json(reply)) =
                super::provider_routes::invoke_workload_brokered_provider_operation(
                    st,
                    guest_request,
                    authority,
                )
                .await;
            if !status.is_success() || reply.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(GovernedEffectRefusal {
                    code: format!(
                        "provider_final_invoker_refused:{}",
                        reply
                            .get("code")
                            .or_else(|| reply.get("reason"))
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                    ),
                    effect_receipt: Some(reply),
                });
            }
            Ok(reply)
        },
    )
    .await
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Authenticated host-controller mint.  The response deliberately separates the guest proposal
/// from the host trigger; a controller sends only `guest_proposal` into the hostile VM and retains
/// `host_trigger` outside it.  The submitted provider request must already carry a daemon-issued
/// proposal and either exact or standing wallet authority.
pub(crate) async fn handle_governed_capability_mint(
    State(st): State<Arc<super::DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let full_request = body
        .get("full_provider_request")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(Value::Null);
    // Authenticate before returning any request-shape detail. `require_write_caller` resolves the
    // session as its first operation, then binds the nested provider request's owner and replay
    // key. This preserves the daemon-wide write-path rule for the host-controller mint route.
    let caller = match super::mutation_event_foundation::require_write_caller(
        &st.data_dir,
        &headers,
        &full_request,
    ) {
        Ok(caller) => caller,
        Err(reply) => return reply,
    };
    let Some(object) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_mint_request_invalid"})),
        );
    };
    const FIELDS: &[&str] = &[
        "isolation_binding_ref",
        "isolation_binding_hash",
        "guest_principal_ref",
        "proposal_nonce",
        "resource_ref",
        "result_destination_ref",
        "full_provider_request",
        "expires_at_ms",
    ];
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_mint_fields_invalid"})),
        );
    }
    let session_binding = match super::provider_routes::provider_proposal_session_binding(&headers)
    {
        Ok(binding) => binding,
        Err(reply) => return reply,
    };
    let issued_at_ms = unix_millis();
    let expires_at_ms = body
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let field = |name: &str| body.get(name).and_then(Value::as_str).unwrap_or("");
    match mint_guest_governed_provider_effect_capability(
        &st.data_dir,
        field("isolation_binding_ref"),
        field("isolation_binding_hash"),
        field("guest_principal_ref"),
        field("proposal_nonce"),
        field("resource_ref"),
        field("result_destination_ref"),
        &full_request,
        &caller.identity.principal_ref,
        &session_binding,
        issued_at_ms,
        expires_at_ms,
    ) {
        Ok(bundle) => (
            StatusCode::CREATED,
            Json(json!({"ok":true,"broker_bundle":bundle})),
        ),
        Err(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"ok":false,"code":reason,"host_mutation":false})),
        ),
    }
}

fn authorize_hostile_guest_roundtrip(
    data_dir: &str,
    proposal_bytes: &[u8],
    authenticated_principal_ref: &str,
    proposal_session_binding: &str,
    now_ms: u64,
) -> Result<Value, String> {
    let proposal = parse_canonical_proposal_bytes(proposal_bytes)?;
    static_provider_coordinates(&proposal)?;
    let id = record_id(&proposal)?;
    let record = load(data_dir, id)?;
    proposal_matches_record(&proposal, &record)?;
    if required_text(&record, "authenticated_principal_ref")? != authenticated_principal_ref
        || required_text(&record, "proposal_session_binding")? != proposal_session_binding
    {
        return Err("workload_effect_roundtrip_host_controller_mismatch".into());
    }
    if record.get("status").and_then(Value::as_str) != Some("issued") {
        return Err("workload_effect_roundtrip_capability_not_issued".into());
    }
    if now_ms > record["expires_at_ms"].as_u64().unwrap_or_default() {
        return Err("workload_effect_capability_expired".into());
    }
    required_text(&record, "host_trigger_hash")?;
    verified_host_provider_authority(&record)?;
    Ok(proposal)
}

/// Authenticated host-controller isolation step. It sends only the canonical guest proposal into
/// a fresh no-NIC KVM guest, runs the fixed root-level bypass/secret probes, quarantines the output,
/// and returns the byte-exact proposal plus enforcement evidence. The host trigger remains outside
/// this call and this route cannot invoke a provider.
pub(crate) async fn handle_hostile_guest_roundtrip(
    State(st): State<Arc<super::DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::mutation_event_foundation::scope_refusal_reply(error),
    };
    let Some(object) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_roundtrip_request_invalid"})),
        );
    };
    if object.len() != 1 || !object.contains_key("proposal_jcs_base64") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_roundtrip_fields_invalid"})),
        );
    }
    let encoded = body
        .get("proposal_jcs_base64")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proposal_bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(bytes) if bytes.len() <= MAX_PROPOSAL_BYTES => bytes,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok":false,"code":"workload_effect_proposal_base64_invalid"})),
            )
        }
    };
    let session_binding = match super::provider_routes::provider_proposal_session_binding(&headers)
    {
        Ok(binding) => binding,
        Err(reply) => return reply,
    };
    let proposal = match authorize_hostile_guest_roundtrip(
        &st.data_dir,
        &proposal_bytes,
        &identity.principal_ref,
        &session_binding,
        unix_millis(),
    ) {
        Ok(proposal) => proposal,
        Err(reason) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"ok":false,"code":reason,"host_mutation":false})),
            )
        }
    };
    let exact_request = &proposal["exact_request"];
    let owner_ref = exact_request
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let idempotency_key = exact_request
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap_or("");
    if owner_ref.is_empty() || idempotency_key.is_empty() || !identity.authorizes_tenant(owner_ref)
    {
        return super::mutation_event_foundation::scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired,
        );
    }
    let roundtrip = tokio::task::spawn_blocking(move || {
        super::microvm::hostile_guest_proposal_roundtrip(&proposal_bytes)
    })
    .await;
    match roundtrip {
        Ok(Ok((returned, evidence))) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "proposal_jcs_base64": base64::engine::general_purpose::STANDARD.encode(returned),
                "enforcement_evidence": evidence,
            })),
        ),
        Ok(Err(reason)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"ok":false,"code":reason,"host_mutation":false})),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"ok":false,"code":"workload_effect_roundtrip_join_failed","detail":error.to_string()}),
            ),
        ),
    }
}

/// Capability-authenticated host finalizer.  It needs no operator password or session: the random
/// host trigger names one already-authenticated, already-reviewed capability, while current owner
/// membership, wallet state, proposal one-shot state, and every provider/C2 gate are rechecked at
/// invocation.  The selected hostile-guest profile has no route or network path to this trigger.
pub(crate) async fn handle_governed_capability_consume(
    State(st): State<Arc<super::DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(object) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_consume_request_invalid"})),
        );
    };
    if object.len() != 2
        || !object.contains_key("proposal_jcs_base64")
        || !object.contains_key("host_trigger")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"code":"workload_effect_consume_fields_invalid"})),
        );
    }
    let encoded = body
        .get("proposal_jcs_base64")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proposal_bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(bytes) if bytes.len() <= MAX_PROPOSAL_BYTES => bytes,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok":false,"code":"workload_effect_proposal_base64_invalid"})),
            )
        }
    };
    let host_trigger = body
        .get("host_trigger")
        .and_then(Value::as_str)
        .unwrap_or("");
    match consume_guest_governed_provider_operation_bytes(
        st,
        &proposal_bytes,
        host_trigger,
        unix_millis(),
    )
    .await
    {
        Ok(receipts) => (StatusCode::OK, Json(json!({"ok":true,"receipts":receipts}))),
        Err(refusal) => {
            let status = if refusal.code == "workload_effect_host_trigger_invalid" {
                StatusCode::UNAUTHORIZED
            } else if refusal.code.contains("already_consumed")
                || refusal.code.contains("requires_reconciliation")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            (
                status,
                Json(json!({
                    "ok":false,
                    "code":refusal.code,
                    "effect_receipt":refusal.effect_receipt,
                    "host_mutation":false
                })),
            )
        }
    }
}

/// Resolve an ambiguous durable claim without replaying its original effect. The reconciler first
/// observes the exact provider/environment bound into the capability. An absent resource closes as
/// `reconciled_no_effect`; an observed resource is deleted and must return positive cleanup truth.
/// The observation and optional cleanup are ordinary provider operations and are counted exactly.
pub(crate) fn reconcile_guest_static_provider_operation(
    data_dir: &str,
    capability_ref: &str,
    now_ms: u64,
) -> Result<Value, String> {
    let _guard = consumption_lock().blocking_lock();
    let id = record_id_from_capability_ref(capability_ref)?;
    let mut record = load(data_dir, id)?;
    if record.get("capability_ref").and_then(Value::as_str) != Some(capability_ref) {
        return Err("workload_effect_capability_ref_substitution_refused".into());
    }
    let (request, provider_id, environment_ref) = static_provider_coordinates(&record)?;
    if required_text(request, "op")? != "create" {
        return Err("workload_effect_reconciliation_operation_unsupported".into());
    }
    let provider_id = provider_id.to_string();
    let environment_ref = environment_ref.to_string();
    let prior_status = record["status"].as_str().unwrap_or_default().to_string();
    if !matches!(prior_status.as_str(), "claimed" | "reconciliation_required") {
        return Err("workload_effect_reconciliation_not_required".into());
    }
    if prior_status == "claimed" {
        record["status"] = json!("reconciliation_required");
        record["reconciliation_reason"] = json!("prior_process_lost_after_durable_claim");
        persist(data_dir, id, &record)?;
    }

    let provider_operations_before =
        provider_operation_count(data_dir, &provider_id, &environment_ref);
    let observe_request = json!({
        "provider_id": provider_id,
        "op": "observe",
        "environment_ref": environment_ref,
    });
    let (observe_status, axum::Json(observe_reply)) =
        super::provider_routes::invoke_static_provider_operation(data_dir, &observe_request);
    if !observe_status.is_success()
        || observe_reply.get("ok").and_then(Value::as_bool) != Some(true)
    {
        return Err("workload_effect_reconciliation_observe_refused".into());
    }
    let observed_phase = observe_reply
        .pointer("/evidence/phase")
        .and_then(Value::as_str)
        .ok_or("workload_effect_reconciliation_phase_missing")?
        .to_string();

    let (disposition, status, invoker_calls, reconciliation_evidence) =
        if observed_phase == "absent" {
            (
                "no_effect_observed",
                "reconciled_no_effect",
                1_u64,
                json!({ "observation": observe_reply }),
            )
        } else {
            let delete_request = json!({
                "provider_id": provider_id,
                "op": "delete",
                "environment_ref": environment_ref,
            });
            let (delete_status, axum::Json(delete_reply)) =
                super::provider_routes::invoke_static_provider_operation(data_dir, &delete_request);
            if !delete_status.is_success()
                || delete_reply.get("ok").and_then(Value::as_bool) != Some(true)
                || delete_reply
                    .pointer("/evidence/cleanup_verified")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err("workload_effect_reconciliation_cleanup_unverified".into());
            }
            (
                "cleanup_succeeded",
                "reconciled_cleanup_succeeded",
                2_u64,
                json!({ "observation": observe_reply, "cleanup": delete_reply }),
            )
        };

    let provider_operations_after =
        provider_operation_count(data_dir, &provider_id, &environment_ref);
    if provider_operations_after != provider_operations_before.saturating_add(invoker_calls) {
        return Err("workload_effect_reconciliation_operation_count_mismatch".into());
    }
    let reconciliation_evidence_hash = canonical_hash(&reconciliation_evidence)?;
    let receipt = json!({
        "schema_version": "ioi.components.hypervisor.workload-effect-reconciliation-receipt.v1",
        "capability_ref": record["capability_ref"],
        "isolation_binding_ref": record["isolation_binding_ref"],
        "principal_ref": record["principal_ref"],
        "request_hash": record["request_hash"],
        "prior_status": prior_status,
        "disposition": disposition,
        "observed_phase": observed_phase,
        "cleanup_verified": true,
        "original_effect_reinvoked": false,
        "reconciliation_invoker_calls": invoker_calls,
        "provider_operations_before": provider_operations_before,
        "provider_operations_after": provider_operations_after,
        "reconciliation_evidence_hash": reconciliation_evidence_hash,
        "status": status,
    });
    serde_json::from_value::<HypervisorWorkloadEffectReconciliationReceiptV1>(receipt.clone())
        .map_err(|error| {
            format!("workload_effect_reconciliation_receipt_contract_invalid: {error}")
        })?;
    record["status"] = json!(status);
    record["original_effect_reinvoked"] = json!(false);
    record["reconciliation_invoker_calls"] = json!(invoker_calls);
    record["provider_operations_before_reconciliation"] = json!(provider_operations_before);
    record["provider_operations_after_reconciliation"] = json!(provider_operations_after);
    record["reconciliation_evidence_hash"] = json!(reconciliation_evidence_hash);
    record["reconciled_at_ms"] = json!(now_ms);
    persist(data_dir, id, &record)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn mint(data_dir: &str) -> Value {
        mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://worker-1",
            "nonce-1",
            "hypervisor-final-invoker",
            "provider-resource://akash/deployment",
            "result-destination://aft/u1",
            &json!({"operation":"create_deployment","deposit_usd":1.0}),
            1_000,
            61_000,
        )
        .unwrap()
    }

    #[test]
    fn governed_guest_proposal_contains_no_wallet_authority_or_operator_session() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let full_request = json!({
            "provider_id": "provider-account",
            "op": "create",
            "environment_ref": "env-host-authority-hidden",
            "owner_ref": "org://local",
            "idempotency_key": "host-authority-hidden",
            "plan": {"deposit_usd": 1.0},
            "operation_proposal_ref": "provider-operation-proposal://popp_exact",
            "wallet_approval_grant": {
                "grant_ref": "wallet.network://grant/secret-marker-must-not-reach-guest"
            }
        });
        let bundle = mint_guest_governed_provider_effect_capability(
            data_dir,
            "workload-isolation-binding://run-governed-provider",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://worker-governed-provider",
            "nonce-governed-provider",
            "provider-resource://provider-account/env-host-authority-hidden",
            "result-destination://aft/u1",
            &full_request,
            "user://operator",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            1_000,
            61_000,
        )
        .unwrap();
        let proposal = bundle["guest_proposal"].clone();
        let host_trigger = bundle["host_trigger"].as_str().unwrap();
        assert!(host_trigger.starts_with("wbt_") && host_trigger.len() == 68);
        let guest_bytes = serde_jcs::to_vec(&proposal).unwrap();
        let guest_text = String::from_utf8(guest_bytes).unwrap();
        for forbidden in [
            "wallet_approval_grant",
            "wallet_standing_approval_grant",
            "standing_authority_envelope",
            "operation_proposal_ref",
            "secret-marker-must-not-reach-guest",
            "ioi_session",
            host_trigger,
        ] {
            assert!(!guest_text.contains(forbidden), "guest leaked {forbidden}");
        }
        let id = record_id(&proposal).unwrap();
        let mut record = load(data_dir, id).unwrap();
        assert!(record.get("host_trigger").is_none());
        assert_eq!(
            record["host_trigger_hash"],
            sha256_ref(host_trigger.as_bytes())
        );
        assert!(verify_host_trigger(&record, host_trigger).is_ok());
        assert_eq!(
            verify_host_trigger(
                &record,
                "wbt_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            .unwrap_err(),
            "workload_effect_host_trigger_invalid"
        );
        assert_eq!(
            verify_host_trigger(&record, "wbt_too-short").unwrap_err(),
            "workload_effect_host_trigger_invalid"
        );
        let attachment = verified_host_provider_authority(&record).unwrap();
        assert_eq!(
            attachment["wallet_approval_grant"]["grant_ref"],
            "wallet.network://grant/secret-marker-must-not-reach-guest"
        );
        record["host_authority_attachment"]["wallet_approval_grant"]["grant_ref"] =
            json!("wallet.network://grant/mutated");
        assert_eq!(
            verified_host_provider_authority(&record).unwrap_err(),
            "workload_effect_host_authority_attachment_hash_mismatch"
        );
    }

    #[test]
    fn governed_guest_capability_refuses_ambiguous_or_incomplete_authority_modes() {
        let base = json!({
            "provider_id": "provider-account",
            "op": "create",
            "environment_ref": "env-authority-mode",
            "owner_ref": "org://local",
            "idempotency_key": "authority-mode",
            "operation_proposal_ref": "provider-operation-proposal://popp_exact"
        });
        assert_eq!(
            split_host_provider_authority(&base).unwrap_err(),
            "workload_effect_host_authority_mode_invalid"
        );
        let mut ambiguous = base.clone();
        ambiguous["wallet_approval_grant"] = json!({"grant_ref":"wallet.network://grant/one"});
        ambiguous["wallet_standing_approval_grant"] =
            json!({"grant_ref":"wallet.network://standing/one"});
        ambiguous["standing_authority_envelope"] = json!({"body_hash":"sha256:one"});
        assert_eq!(
            split_host_provider_authority(&ambiguous).unwrap_err(),
            "workload_effect_host_authority_mode_invalid"
        );
    }

    #[test]
    fn governed_roundtrip_requires_the_exact_authenticated_host_controller() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let bundle = mint_guest_governed_provider_effect_capability(
            data_dir,
            "workload-isolation-binding://roundtrip-controller",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://hostile-roundtrip-worker",
            "nonce-roundtrip-controller",
            "provider-resource://provider-account/env-roundtrip-controller",
            "result-destination://aft/u1",
            &json!({
                "provider_id":"provider-account",
                "op":"create",
                "environment_ref":"env-roundtrip-controller",
                "owner_ref":"org://local",
                "idempotency_key":"roundtrip-controller",
                "operation_proposal_ref":"provider-operation-proposal://popp_roundtrip",
                "wallet_approval_grant":{"grant_ref":"wallet.network://grant/roundtrip"}
            }),
            "user://operator",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            1_000,
            61_000,
        )
        .unwrap();
        let bytes = serde_jcs::to_vec(&bundle["guest_proposal"]).unwrap();
        assert!(authorize_hostile_guest_roundtrip(
            data_dir,
            &bytes,
            "user://operator",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            2_000,
        )
        .is_ok());
        assert_eq!(
            authorize_hostile_guest_roundtrip(
                data_dir,
                &bytes,
                "user://other",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                2_000,
            )
            .unwrap_err(),
            "workload_effect_roundtrip_host_controller_mismatch"
        );
        assert_eq!(
            authorize_hostile_guest_roundtrip(
                data_dir,
                &bytes,
                "user://operator",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                2_000,
            )
            .unwrap_err(),
            "workload_effect_roundtrip_host_controller_mismatch"
        );
    }

    #[test]
    #[ignore = "requires /dev/kvm and the checksum-pinned ~/.ioi/vm-toolchain"]
    fn governed_proposal_crosses_the_real_hostile_guest_roundtrip_without_host_authority() {
        let dir = fixture();
        let bundle = mint_guest_governed_provider_effect_capability(
            dir.path().to_str().unwrap(),
            "workload-isolation-binding://governed-live-roundtrip",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://hostile-governed-live-worker",
            "nonce-governed-live-roundtrip",
            "provider-resource://provider-account/env-governed-live-roundtrip",
            "result-destination://aft/u1",
            &json!({
                "provider_id":"provider-account",
                "op":"create",
                "environment_ref":"env-governed-live-roundtrip",
                "owner_ref":"org://local",
                "idempotency_key":"governed-live-roundtrip",
                "operation_proposal_ref":"provider-operation-proposal://popp_governed_live",
                "wallet_approval_grant":{"grant_ref":"wallet.network://grant/governed-live"}
            }),
            "user://operator",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            1_000,
            61_000,
        )
        .unwrap();
        let guest_bytes = serde_jcs::to_vec(&bundle["guest_proposal"]).unwrap();
        let host_trigger = bundle["host_trigger"].as_str().unwrap();
        assert!(!String::from_utf8_lossy(&guest_bytes).contains(host_trigger));
        let (returned, evidence) =
            super::super::microvm::hostile_guest_proposal_roundtrip(&guest_bytes).unwrap();
        assert_eq!(returned, guest_bytes);
        assert_eq!(evidence["guest_uid"], 0);
        assert_eq!(evidence["direct_protected_provider_invocations"], 0);
        assert_eq!(evidence["host_trigger_in_guest"], false);
        assert_eq!(evidence["proposal_roundtrip_exact"], true);
        assert_eq!(evidence["monitor_terminal"], true);
    }

    #[test]
    fn exact_guest_proposal_invokes_once_and_replay_preserves_one() {
        let dir = fixture();
        let calls = AtomicUsize::new(0);
        let proposal = mint(dir.path().to_str().unwrap());
        let receipt = consume_guest_effect_capability(
            dir.path().to_str().unwrap(),
            &proposal,
            2_000,
            |request| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"provider_receipt_ref":"provider-receipt://one","request":request}))
            },
        )
        .unwrap();
        assert_eq!(receipt["final_invoker_calls"], 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            consume_guest_effect_capability(
                dir.path().to_str().unwrap(),
                &proposal,
                3_000,
                |_| panic!("replay must never enter the invoker"),
            )
            .unwrap_err(),
            "workload_effect_capability_already_consumed"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn governed_refusal_retains_the_called_provider_receipt_for_compensation() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let proposal = mint(data_dir);
        let provider_reply = json!({
            "ok": false,
            "reason": "provider_outcome_requires_reconciliation",
            "evidence": {"dseq": "1787000000000"}
        });
        let refusal =
            consume_guest_effect_capability_async(data_dir, &proposal, 2_000, |_| async {
                Err(GovernedEffectRefusal {
                    code: "provider_final_invoker_refused:reconciliation_required".into(),
                    effect_receipt: Some(provider_reply.clone()),
                })
            })
            .await
            .unwrap_err();
        assert!(refusal.code.contains("reconciliation_required"));
        assert_eq!(refusal.effect_receipt, Some(provider_reply.clone()));
        let record = load(data_dir, record_id(&proposal).unwrap()).unwrap();
        assert_eq!(record["status"], "refused");
        assert_eq!(record["final_invoker_calls"], 1);
        assert_eq!(
            record["effect_receipt_hash"],
            canonical_hash(&provider_reply).unwrap()
        );
        let replay = consume_guest_effect_capability_async(data_dir, &proposal, 3_000, |_| async {
            panic!("refused capability replay cannot call the provider")
        })
        .await
        .unwrap_err();
        assert_eq!(replay.code, "workload_effect_capability_already_consumed");
    }

    #[test]
    fn every_security_relevant_channel_coordinate_is_exact() {
        for pointer in [
            "/isolation_binding_ref",
            "/isolation_binding_hash",
            "/principal_ref",
            "/proposal_nonce",
            "/audience",
            "/resource_ref",
            "/result_destination_ref",
            "/request_hash",
            "/exact_request/deposit_usd",
            "/expires_at_ms",
            "/capability_token",
        ] {
            let dir = fixture();
            let mut proposal = mint(dir.path().to_str().unwrap());
            let slot = proposal.pointer_mut(pointer).unwrap();
            *slot = match slot {
                Value::String(value) => json!(format!("{value}-mutated")),
                Value::Number(_) => json!(999_999),
                _ => json!("mutated"),
            };
            let calls = AtomicUsize::new(0);
            let error = consume_guest_effect_capability(
                dir.path().to_str().unwrap(),
                &proposal,
                2_000,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({}))
                },
            )
            .unwrap_err();
            assert!(
                error.contains("substitution_refused")
                    || error.contains("token_invalid")
                    || error.contains("expired"),
                "{pointer}: {error}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0, "{pointer}");
        }
    }

    #[test]
    fn a_restart_observing_a_durable_claim_never_reinvokes() {
        let dir = fixture();
        let proposal = mint(dir.path().to_str().unwrap());
        let id = record_id(&proposal).unwrap();
        let mut record = load(dir.path().to_str().unwrap(), id).unwrap();
        record["status"] = json!("claimed");
        persist(dir.path().to_str().unwrap(), id, &record).unwrap();
        let error =
            consume_guest_effect_capability(dir.path().to_str().unwrap(), &proposal, 2_000, |_| {
                panic!("an ambiguous prior claim cannot be replayed")
            })
            .unwrap_err();
        assert_eq!(error, "workload_effect_prior_claim_requires_reconciliation");
        assert_eq!(
            load(dir.path().to_str().unwrap(), id).unwrap()["status"],
            "reconciliation_required"
        );
    }

    #[test]
    fn reconciliation_proves_no_effect_without_reinvoking_the_original() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let environment_ref = "env-t2-reconcile-absent";
        let request = json!({
            "provider_id": "loopback-runner",
            "op": "create",
            "environment_ref": environment_ref,
            "plan": {}
        });
        let proposal = mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-reconcile-absent",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://worker-reconcile-absent",
            "nonce-reconcile-absent",
            "hypervisor-final-invoker",
            &format!("provider-resource://loopback-runner/{environment_ref}"),
            "result-destination://aft/u1",
            &request,
            1_000,
            61_000,
        )
        .unwrap();
        let id = record_id(&proposal).unwrap();
        let mut record = load(data_dir, id).unwrap();
        record["status"] = json!("claimed");
        persist(data_dir, id, &record).unwrap();
        let receipt = reconcile_guest_static_provider_operation(
            data_dir,
            proposal["capability_ref"].as_str().unwrap(),
            62_000,
        )
        .unwrap();
        assert_eq!(receipt["prior_status"], "claimed");
        assert_eq!(receipt["disposition"], "no_effect_observed");
        assert_eq!(receipt["status"], "reconciled_no_effect");
        assert_eq!(receipt["original_effect_reinvoked"], false);
        assert_eq!(receipt["reconciliation_invoker_calls"], 1);
        assert_eq!(receipt["provider_operations_before"], 0);
        assert_eq!(receipt["provider_operations_after"], 1);
        let operations = super::super::read_record_dir(data_dir, "provider-operations");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["op"], "observe");
        assert!(!dir
            .path()
            .join("providers/loopback")
            .join(environment_ref)
            .exists());
        assert_eq!(
            reconcile_guest_static_provider_operation(
                data_dir,
                proposal["capability_ref"].as_str().unwrap(),
                63_000,
            )
            .unwrap_err(),
            "workload_effect_reconciliation_not_required"
        );
    }

    #[test]
    fn reconciliation_observes_and_cleans_an_effect_without_duplicate_create() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let environment_ref = "env-t2-reconcile-created";
        let request = json!({
            "provider_id": "loopback-runner",
            "op": "create",
            "environment_ref": environment_ref,
            "plan": {}
        });
        let proposal = mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-reconcile-created",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "principal://worker-reconcile-created",
            "nonce-reconcile-created",
            "hypervisor-final-invoker",
            &format!("provider-resource://loopback-runner/{environment_ref}"),
            "result-destination://aft/u1",
            &request,
            1_000,
            61_000,
        )
        .unwrap();
        let id = record_id(&proposal).unwrap();
        let mut record = load(data_dir, id).unwrap();
        record["status"] = json!("reconciliation_required");
        persist(data_dir, id, &record).unwrap();
        let (status, axum::Json(created)) =
            super::super::provider_routes::invoke_static_provider_operation(data_dir, &request);
        assert!(status.is_success());
        assert_eq!(created["ok"], true);
        let receipt = reconcile_guest_static_provider_operation(
            data_dir,
            proposal["capability_ref"].as_str().unwrap(),
            2_000,
        )
        .unwrap();
        assert_eq!(receipt["prior_status"], "reconciliation_required");
        assert_eq!(receipt["disposition"], "cleanup_succeeded");
        assert_eq!(receipt["observed_phase"], "created");
        assert_eq!(receipt["status"], "reconciled_cleanup_succeeded");
        assert_eq!(receipt["original_effect_reinvoked"], false);
        assert_eq!(receipt["reconciliation_invoker_calls"], 2);
        assert_eq!(receipt["provider_operations_before"], 1);
        assert_eq!(receipt["provider_operations_after"], 3);
        let operations = super::super::read_record_dir(data_dir, "provider-operations");
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation["op"] == "create")
                .count(),
            1
        );
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation["op"] == "observe")
                .count(),
            1
        );
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation["op"] == "delete")
                .count(),
            1
        );
        assert!(!dir
            .path()
            .join("providers/loopback")
            .join(environment_ref)
            .exists());
    }

    #[test]
    fn guest_bytes_refuse_parser_differentials_and_oversize_before_invocation() {
        let dir = fixture();
        let proposal = mint(dir.path().to_str().unwrap());
        let canonical = serde_jcs::to_vec(&proposal).unwrap();
        let calls = AtomicUsize::new(0);
        let mut spaced = canonical.clone();
        spaced.insert(1, b' ');
        assert_eq!(
            consume_guest_effect_proposal_bytes(
                dir.path().to_str().unwrap(),
                &spaced,
                2_000,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({}))
                },
            )
            .unwrap_err(),
            "workload_effect_proposal_noncanonical"
        );
        let oversized = vec![b'x'; MAX_PROPOSAL_BYTES + 1];
        assert_eq!(
            consume_guest_effect_proposal_bytes(
                dir.path().to_str().unwrap(),
                &oversized,
                2_000,
                |_| panic!("oversize cannot invoke"),
            )
            .unwrap_err(),
            "workload_effect_proposal_oversized"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_guest_proposal_crosses_the_daemon_static_provider_final_invoker() {
        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let environment_ref = "env-t2-static-provider";
        let create_request = json!({
            "provider_id": "loopback-runner",
            "op": "create",
            "environment_ref": environment_ref,
            "plan": {}
        });
        let create = mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-static-provider",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://worker-static-provider",
            "nonce-create",
            "hypervisor-final-invoker",
            &format!("provider-resource://loopback-runner/{environment_ref}"),
            "result-destination://aft/u1",
            &create_request,
            1_000,
            61_000,
        )
        .unwrap();
        let create_bytes = serde_jcs::to_vec(&create).unwrap();
        let receipt =
            consume_guest_static_provider_operation_bytes(data_dir, &create_bytes, 2_000).unwrap();
        assert_eq!(receipt["final_invoker_calls"], 1);
        let operations = super::super::read_record_dir(data_dir, "provider-operations");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["provider"], "loopback-runner");
        assert_eq!(operations[0]["op"], "create");
        assert_eq!(
            operations[0].pointer("/evidence/phase"),
            Some(&json!("created"))
        );
        assert_eq!(
            consume_guest_static_provider_operation_bytes(data_dir, &create_bytes, 3_000)
                .unwrap_err(),
            "workload_effect_capability_already_consumed"
        );
        assert_eq!(
            super::super::read_record_dir(data_dir, "provider-operations").len(),
            1
        );

        let delete_request = json!({
            "provider_id": "loopback-runner",
            "op": "delete",
            "environment_ref": environment_ref
        });
        let delete = mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-static-provider",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal://worker-static-provider",
            "nonce-delete",
            "hypervisor-final-invoker",
            &format!("provider-resource://loopback-runner/{environment_ref}"),
            "result-destination://aft/u1",
            &delete_request,
            4_000,
            64_000,
        )
        .unwrap();
        let delete_bytes = serde_jcs::to_vec(&delete).unwrap();
        let delete_receipt =
            consume_guest_static_provider_operation_bytes(data_dir, &delete_bytes, 5_000).unwrap();
        assert_eq!(delete_receipt["final_invoker_calls"], 1);
        assert_eq!(
            super::super::read_record_dir(data_dir, "provider-operations").len(),
            2
        );
        assert!(!dir
            .path()
            .join("provider-loopback-runner")
            .join(environment_ref)
            .exists());
    }

    #[test]
    #[ignore = "spawns and SIGKILLs a child at the durable workload-effect claim boundary"]
    fn daemon_kill_after_durable_claim_never_duplicates_provider_effect() {
        const CHILD_ENV: &str = "IOI_T2_WORKLOAD_EFFECT_CRASH_CHILD";
        const DATA_DIR_ENV: &str = "IOI_T2_WORKLOAD_EFFECT_DATA_DIR";
        const PROPOSAL_PATH_ENV: &str = "IOI_T2_WORKLOAD_EFFECT_PROPOSAL_PATH";

        if std::env::var(CHILD_ENV).ok().as_deref() == Some("1") {
            let data_dir = std::env::var(DATA_DIR_ENV).unwrap();
            let proposal_path = std::env::var(PROPOSAL_PATH_ENV).unwrap();
            let proposal = std::fs::read(proposal_path).unwrap();
            let _ = consume_guest_static_provider_operation_bytes(&data_dir, &proposal, 2_000);
            panic!("crash child escaped the selected durable-claim pause");
        }

        let dir = fixture();
        let data_dir = dir.path().to_str().unwrap();
        let environment_ref = "env-t2-crash-window";
        let request = json!({
            "provider_id": "loopback-runner",
            "op": "create",
            "environment_ref": environment_ref,
            "plan": {}
        });
        let proposal = mint_guest_effect_capability(
            data_dir,
            "workload-isolation-binding://run-crash-window",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "principal://worker-crash-window",
            "nonce-crash-window",
            "hypervisor-final-invoker",
            &format!("provider-resource://loopback-runner/{environment_ref}"),
            "result-destination://aft/u1",
            &request,
            1_000,
            61_000,
        )
        .unwrap();
        let proposal_bytes = serde_jcs::to_vec(&proposal).unwrap();
        let proposal_path = dir.path().join("proposal.jcs.json");
        let marker_path = dir.path().join("claimed.marker");
        std::fs::write(&proposal_path, &proposal_bytes).unwrap();

        let current_exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg(
                "workload_effect_boundary::tests::daemon_kill_after_durable_claim_never_duplicates_provider_effect",
            )
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env(DATA_DIR_ENV, data_dir)
            .env(PROPOSAL_PATH_ENV, &proposal_path)
            .env("IOI_TEST_CRASH_AT", "workload_effect_claimed")
            .env("IOI_TEST_CRASH_MARKER_PATH", &marker_path)
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !marker_path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            marker_path.exists(),
            "child never reached durable claim boundary"
        );
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());

        assert_eq!(
            consume_guest_static_provider_operation_bytes(data_dir, &proposal_bytes, 3_000)
                .unwrap_err(),
            "workload_effect_prior_claim_requires_reconciliation"
        );
        assert!(super::super::read_record_dir(data_dir, "provider-operations").is_empty());
        let record = load(data_dir, record_id(&proposal).unwrap()).unwrap();
        assert_eq!(record["status"], "reconciliation_required");
        assert_eq!(record["final_invoker_calls"], 0);
        assert!(!dir
            .path()
            .join("provider-loopback-runner")
            .join(environment_ref)
            .exists());

        let receipt = reconcile_guest_static_provider_operation(
            data_dir,
            proposal["capability_ref"].as_str().unwrap(),
            4_000,
        )
        .unwrap();
        assert_eq!(receipt["disposition"], "no_effect_observed");
        assert_eq!(receipt["status"], "reconciled_no_effect");
        assert_eq!(receipt["original_effect_reinvoked"], false);
        assert_eq!(receipt["reconciliation_invoker_calls"], 1);
        let operations = super::super::read_record_dir(data_dir, "provider-operations");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["op"], "observe");
    }
}
