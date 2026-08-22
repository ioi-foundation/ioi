//! Workload-bound guest proposal broker for the `trusted_host_hostile_guest` profile.
//!
//! A guest receives one opaque bearer capability for one canonical request. The durable record
//! binds it to the admitted isolation binding, principal, nonce, audience, resource, result
//! destination, and expiry. The broker persists `claimed` before entering its caller-supplied final
//! invoker. A process loss in that window becomes `reconciliation_required`; it never replays.
//! Provider credentials and signing material are not inputs to this module and never enter the
//! guest envelope.

use std::sync::Mutex;

use ioi_types::app::generated::architecture_contracts::{
    HypervisorWorkloadBoundEffectProposalV1, HypervisorWorkloadEffectConsumptionReceiptV1,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FAMILY: &str = "workload-effect-capabilities";
const MAX_PROPOSAL_BYTES: usize = 64 * 1024;
static CONSUMPTION_LOCK: Mutex<()> = Mutex::new(());

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

fn record_id(proposal: &Value) -> Result<&str, String> {
    required_text(proposal, "capability_ref")?
        .strip_prefix("workload-effect-capability://")
        .filter(|id| id.starts_with("wec_") && id.len() == 36)
        .ok_or_else(|| "workload_effect_capability_ref_invalid".into())
}

fn load(data_dir: &str, id: &str) -> Result<Value, String> {
    super::durable_fs::read_record_durable(data_dir, FAMILY, id)
        .map_err(|error| format!("workload_effect_capability_read_refused: {error:?}"))?
        .ok_or_else(|| "workload_effect_capability_absent".into())
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
    let _guard = CONSUMPTION_LOCK
        .lock()
        .map_err(|_| "workload_effect_consumption_lock_poisoned".to_string())?;
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

    let request = proposal
        .get("exact_request")
        .ok_or("workload_effect_exact_request_required")?;
    let provider_id = required_text(request, "provider_id")?;
    let environment_ref = required_text(request, "environment_ref")?;
    let expected_resource = format!("provider-resource://{provider_id}/{environment_ref}");
    if required_text(&proposal, "resource_ref")? != expected_resource {
        return Err("workload_effect_provider_resource_binding_mismatch".into());
    }

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
    }
}
