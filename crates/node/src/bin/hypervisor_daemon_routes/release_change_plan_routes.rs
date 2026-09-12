//! Release change plans — the admitted update / rollback path for the packaged Hypervisor
//! release (bounded-alpha-profile.md step 12; core-clients-surfaces.md § Zero-To-Operable Local
//! Deployment; `HypervisorChangePlan` in providers-and-environments.md).
//!
//! The daemon cannot replace its own binary while it runs, so the effect actor for an update or
//! rollback is the installer acting under the HOST's authority (the pre-daemon trust bridge canon
//! names). What the daemon owns is the ADMISSION and the OBSERVED OUTCOME:
//!
//! * `POST /v1/hypervisor/release-change-plans` admits a plan — kind `update` or `rollback`, the
//!   exact target release (version + manifest digest + signer public key) and the current release
//!   the operator believes is running. Admission records the daemon's OWN executable digest at
//!   admission time (never the caller's word), persists the plan, and writes an admission receipt.
//! * `POST /v1/hypervisor/release-change-plans/:id/observe` is called after the installer has
//!   activated the target and restarted the daemon. The daemon hashes its own executable again and
//!   compares it with the target's declared daemon digest: equal → `completed`; different →
//!   `failed` (the activation did not put the target's bytes in charge). Both outcomes receipt.
//!   A plan that is never observed stays `admitted`, which is the honest state of an update whose
//!   restart never came back.
//! * `POST /v1/hypervisor/release-change-plans/:id/cancel` cancels an admitted plan (receipted).
//!
//! Records are daemon truth: the served App and the headless client both read them here.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::durable_fs::persist_receipt_no_clobber;
use super::scm_publication_routes::request_identity;
use super::{persist_record, DaemonState};

const RECORD_DIR: &str = "release-change-plans";
const SCHEMA: &str = "ioi.hypervisor.release-change-plan.v1";
const KINDS: [&str; 2] = ["update", "rollback"];

fn reply(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    reply(
        status,
        json!({ "ok": false, "error": { "code": code, "message": message.into(), "runtimeTruthSource": "daemon-runtime" } }),
    )
}

fn hex64(value: Option<&Value>) -> Option<String> {
    let text = value?
        .as_str()?
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase();
    (text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())).then_some(text)
}

/// The digest of THIS daemon's executable, read from the running image's own path. This is the
/// only identity a change plan trusts for "which release is in charge".
pub(crate) fn running_daemon_sha256() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bytes = std::fs::read(&exe).map_err(|e| format!("read {}: {e}", exe.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn records_dir(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join(RECORD_DIR)
}

fn load_plan(data_dir: &str, plan_id: &str) -> Option<Value> {
    if !plan_id.starts_with("rcp_")
        || !plan_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    let path = records_dir(data_dir).join(format!("{plan_id}.json"));
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn list_plans(data_dir: &str) -> Vec<Value> {
    let mut plans = Vec::new();
    if let Ok(entries) = std::fs::read_dir(records_dir(data_dir)) {
        for entry in entries.flatten() {
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    if value.get("schema").and_then(Value::as_str) == Some(SCHEMA) {
                        plans.push(value);
                    }
                }
            }
        }
    }
    plans.sort_by(|a, b| a["created_at"].as_str().cmp(&b["created_at"].as_str()));
    plans
}

fn write_receipt(
    data_dir: &str,
    plan: &Value,
    event: &str,
    detail: Value,
) -> Result<String, String> {
    let plan_id = plan["plan_id"].as_str().unwrap_or_default();
    let receipt_ref = format!("receipt://hypervisor/release-change-plan/{plan_id}/{event}");
    let receipt = json!({
        "id": receipt_ref,
        "kind": format!("hypervisor.release.change-plan.{event}"),
        "plan_id": plan_id,
        "plan_kind": plan["kind"],
        "target_release": plan["target_release"],
        "status": plan["status"],
        "detail": detail,
        "recorded_at": super::iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    persist_receipt_no_clobber(
        data_dir,
        "receipts",
        &format!("release-change-plan-{plan_id}-{event}"),
        &receipt,
    )
    .map_err(|e| format!("{e:?}"))?;
    Ok(receipt_ref)
}

fn persist_plan(data_dir: &str, plan: &Value) -> Result<(), String> {
    let plan_id = plan["plan_id"].as_str().unwrap_or_default();
    persist_record(data_dir, RECORD_DIR, plan_id, plan).map_err(|e| e.to_string())
}

/// POST /v1/hypervisor/release-change-plans
pub(crate) async fn handle_release_change_plan_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err((status, Json(value))) => return reply(status, value),
    };
    let kind = body
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !KINDS.contains(&kind.as_str()) {
        return refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "release_change_plan_kind_invalid",
            "kind must be update or rollback",
        );
    }
    let target = body.get("target_release").cloned().unwrap_or(Value::Null);
    let target_version = target
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let target_manifest = hex64(target.get("manifest_sha256"));
    let target_daemon = hex64(target.get("daemon_sha256"));
    let signer = target
        .get("signer_public_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if target_version.is_empty()
        || target_manifest.is_none()
        || target_daemon.is_none()
        || signer.is_empty()
    {
        return refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "release_change_plan_target_invalid",
            "target_release requires version, manifest_sha256 (64 hex), daemon_sha256 (64 hex) and signer_public_key",
        );
    }
    let verified_by = target
        .get("signature_verified_by")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if verified_by.is_empty() {
        return refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "release_change_plan_signature_unverified",
            "target_release.signature_verified_by must name the verifier that checked the release signature against the pinned signer before admission",
        );
    }
    let running = match running_daemon_sha256() {
        Ok(digest) => digest,
        Err(error) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "release_change_plan_self_identity_unavailable",
                error,
            )
        }
    };
    // Refuse a plan whose target is what is ALREADY running: an update to self is not a change,
    // and admitting it would mint a completed-looking receipt for nothing.
    if target_daemon.as_deref() == Some(running.as_str()) {
        return refuse(
            StatusCode::CONFLICT,
            "release_change_plan_target_is_running",
            format!("the running daemon already has digest {running}; nothing to change"),
        );
    }
    // One in-flight plan at a time: a second admitted plan would make the observed outcome ambiguous.
    if let Some(open) = list_plans(&st.data_dir)
        .into_iter()
        .find(|p| p["status"] == json!("admitted"))
    {
        return refuse(
            StatusCode::CONFLICT,
            "release_change_plan_already_admitted",
            format!(
                "plan {} is admitted and not yet observed or cancelled",
                open["plan_id"].as_str().unwrap_or("?")
            ),
        );
    }
    let plan_id = format!(
        "rcp_{}",
        &hex::encode(Sha256::digest(
            format!(
                "{kind}|{target_version}|{}|{}|{}",
                target_manifest.as_deref().unwrap_or(""),
                running,
                super::iso_now()
            )
            .as_bytes()
        ))[..24]
    );
    let plan = json!({
        "schema": SCHEMA,
        "plan_id": plan_id,
        "kind": kind,
        "status": "admitted",
        "requested_by": identity.principal_ref,
        "target_release": {
            "version": target_version,
            "manifest_sha256": target_manifest,
            "daemon_sha256": target_daemon,
            "signer_public_key": signer,
            "signature_verified_by": verified_by,
        },
        "current_release": {
            "declared_version": body.get("current_release").and_then(|c| c.get("version")).cloned().unwrap_or(Value::Null),
            "observed_daemon_sha256_at_admission": running,
        },
        "effect_actor": "installer under host authority (the daemon cannot replace its own executable); the daemon admits the plan and observes the outcome",
        "created_at": super::iso_now(),
        "updated_at": super::iso_now(),
        "receipt_refs": [],
        "runtimeTruthSource": "daemon-runtime",
    });
    let mut plan = plan;
    match write_receipt(
        &st.data_dir,
        &plan,
        "admitted",
        json!({ "running_daemon_sha256": plan["current_release"]["observed_daemon_sha256_at_admission"] }),
    ) {
        Ok(receipt_ref) => plan["receipt_refs"] = json!([receipt_ref]),
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "release_change_plan_receipt_failed",
                error,
            )
        }
    }
    if let Err(error) = persist_plan(&st.data_dir, &plan) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "release_change_plan_persist_failed",
            error,
        );
    }
    reply(StatusCode::CREATED, json!({ "ok": true, "plan": plan }))
}

/// GET /v1/hypervisor/release-change-plans
pub(crate) async fn handle_release_change_plan_list(
    State(st): State<Arc<DaemonState>>,
) -> Response {
    let running = running_daemon_sha256().ok();
    // v2 of the family also reports the running daemon's crate version beside its digest, so a
    // client can tell WHICH release answered without hashing anything itself.
    reply(
        StatusCode::OK,
        json!({ "ok": true, "running_daemon_sha256": running, "running_daemon_crate_version": env!("CARGO_PKG_VERSION"), "plans": list_plans(&st.data_dir) }),
    )
}

/// GET /v1/hypervisor/release-change-plans/:id
pub(crate) async fn handle_release_change_plan_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(plan_id): AxumPath<String>,
) -> Response {
    match load_plan(&st.data_dir, &plan_id) {
        Some(plan) => reply(StatusCode::OK, json!({ "ok": true, "plan": plan })),
        None => refuse(
            StatusCode::NOT_FOUND,
            "release_change_plan_not_found",
            format!("no plan {plan_id}"),
        ),
    }
}

/// POST /v1/hypervisor/release-change-plans/:id/:action  (observe | cancel)
pub(crate) async fn handle_release_change_plan_action(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((plan_id, action)): AxumPath<(String, String)>,
) -> Response {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err((status, Json(value))) => return reply(status, value),
    };
    let Some(mut plan) = load_plan(&st.data_dir, &plan_id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "release_change_plan_not_found",
            format!("no plan {plan_id}"),
        );
    };
    if plan["status"] != json!("admitted") {
        // Terminal truth is replayed, never re-decided.
        return reply(
            StatusCode::OK,
            json!({ "ok": true, "plan": plan, "replayed": true }),
        );
    }
    match action.as_str() {
        "observe" => {
            let running = match running_daemon_sha256() {
                Ok(digest) => digest,
                Err(error) => {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "release_change_plan_self_identity_unavailable",
                        error,
                    )
                }
            };
            let expected = plan["target_release"]["daemon_sha256"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let matched = running == expected;
            plan["status"] = json!(if matched { "completed" } else { "failed" });
            plan["observed"] = json!({
                "at": super::iso_now(),
                "by": identity.principal_ref,
                "running_daemon_sha256": running,
                "target_daemon_sha256": expected,
                "matched": matched,
                "reason": if matched { Value::Null } else { json!("the daemon that came back is not the target release's bytes; the activation did not take effect or was reverted") },
            });
        }
        "cancel" => {
            plan["status"] = json!("cancelled");
            plan["cancelled"] = json!({ "at": super::iso_now(), "by": identity.principal_ref });
        }
        other => {
            return refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                "release_change_plan_action_invalid",
                format!("unknown action {other}; expected observe or cancel"),
            )
        }
    }
    plan["updated_at"] = json!(super::iso_now());
    let event = plan["status"].as_str().unwrap_or("updated").to_string();
    match write_receipt(
        &st.data_dir,
        &plan,
        &event,
        plan.get("observed").cloned().unwrap_or(Value::Null),
    ) {
        Ok(receipt_ref) => {
            if let Some(refs) = plan["receipt_refs"].as_array_mut() {
                refs.push(json!(receipt_ref));
            }
        }
        Err(error) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "release_change_plan_receipt_failed",
                error,
            )
        }
    }
    if let Err(error) = persist_plan(&st.data_dir, &plan) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "release_change_plan_persist_failed",
            error,
        );
    }
    reply(StatusCode::OK, json!({ "ok": true, "plan": plan }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex64_accepts_bare_and_prefixed_digests_only() {
        let d = "ab".repeat(32);
        assert_eq!(hex64(Some(&json!(d))), Some(d.clone()));
        assert_eq!(hex64(Some(&json!(format!("sha256:{d}")))), Some(d));
        assert_eq!(hex64(Some(&json!("abc"))), None);
        assert_eq!(hex64(None), None);
    }

    #[test]
    fn running_daemon_digest_is_the_executable_bytes() {
        let digest = running_daemon_sha256().expect("self digest");
        let exe = std::env::current_exe().unwrap();
        let expected = hex::encode(Sha256::digest(std::fs::read(exe).unwrap()));
        assert_eq!(digest, expected);
    }

    #[test]
    fn plan_ids_are_shape_checked_before_touching_the_filesystem() {
        assert!(load_plan("/nonexistent", "../etc/passwd").is_none());
        assert!(load_plan("/nonexistent", "rcp_abc").is_none());
    }
}
