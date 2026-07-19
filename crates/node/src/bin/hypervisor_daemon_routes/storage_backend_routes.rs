//! Storage backends — Filecoin/CAS/IPFS/local-disk ARCHIVE CUSTODY (the storage leg after the
//! compute trio). Canon: docs/architecture/components/storage-backends/{doctrine,filecoin-cas}.md.
//!
//! **Storage backends hold payload bytes. They do not own operational truth.** This plane is
//! byte availability behind daemon-owned refs: not compute, not authority, not restore truth,
//! not a peer control plane. Daemon-admitted sha256 state roots remain the ONLY restore truth;
//! CIDs, gateway responses, deals, and pins are availability EVIDENCE. Archive bytes are sealed
//! (Argon2id KDF + AEAD under the wallet-secret passphrase) BEFORE any write — public or
//! decentralized backends never receive plaintext private material. Export/restore cross the
//! wallet capability-lease gateway; every crossing (success AND failure) mints a storage
//! receipt. Availability failures open ArtifactAvailabilityIncident records; repair emits an
//! ArtifactRepairReceipt and only admits repaired refs after a verified commitment.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::lifecycle_routes::{
    authorize_capability_lease, open_scm_token, scm_key_source, scm_secret_passphrase,
    seal_scm_token, CapabilityLeaseRequest,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const ACCOUNT_KIND: &str = "storage-backend-accounts";
const CREDENTIAL_VAULT: &str = "storage-credentials";
const ARCHIVE_KIND: &str = "storage-archive-objects";
const INCIDENT_KIND: &str = "artifact-availability-incidents";
const REPAIR_KIND: &str = "artifact-repair-receipts";
const RECEIPT_KIND: &str = "storage-receipts";
const MATERIAL_KIND: &str = "provider-materials";
pub(crate) const BACKEND_KINDS: &[&str] = &["local_disk", "cas", "ipfs", "filecoin"];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Seal raw archive bytes with the SAME wallet-secret discipline as sealed credentials
/// (Argon2id KDF + AEAD; key supplied out-of-band, never in the data dir). Public/decentralized
/// backends only ever see this ciphertext.
fn seal_archive_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    ioi_crypto::key_store::encrypt_key(bytes, &scm_secret_passphrase())
        .map_err(|e| format!("archive_seal_failed: {e:?}"))
}
fn open_archive_bytes(sealed: &[u8]) -> Result<Vec<u8>, String> {
    ioi_crypto::key_store::decrypt_key(sealed, &scm_secret_passphrase())
        .map(|plain| plain.0.to_vec())
        .map_err(|_| "archive_decrypt_failed — sealed archive bytes did not decrypt under the wallet-secret passphrase (wrong key or corrupt ciphertext)".to_string())
}

/// Honest per-kind capabilities. EVERY kind carries the availability-is-not-restore-truth rule.
fn kind_capabilities(kind: &str) -> Value {
    let base_rule = "storage availability is NOT restore truth — daemon-admitted sha256 state roots remain the only restore truth; backend addresses/CIDs/deals/pins are availability evidence";
    match kind {
        "local_disk" => json!({
            "class": "byte_store", "addressing": "content-addressed path (cas://sha256/<hex>)",
            "custody_posture": "private_local — bytes stay inside the daemon trust boundary",
            "encryption": "sealed_wallet_secret (applied anyway — custody bytes never sit plaintext in the backend store)",
            "public_availability": false, "network": "none — device-local",
            "authority": format!("none — {base_rule}"),
        }),
        "cas" => json!({
            "class": "byte_store", "addressing": "content-addressed (cas://sha256/<hex> of the SEALED bytes)",
            "custody_posture": "content-addressed store — replicas possible; treat as shareable",
            "encryption_required": true,
            "encryption": "sealed_wallet_secret REQUIRED before write",
            "public_availability": "deployment-dependent — assume shareable",
            "authority": format!("none — {base_rule}"),
        }),
        "ipfs" => json!({
            "class": "decentralized_availability", "addressing": "CID (content-addressed); fixture mode uses local-cas://sha256/<hex> and NEVER claims network availability",
            "custody_posture": "PUBLIC availability network — anyone holding the CID can fetch the (sealed) bytes",
            "encryption_required": true,
            "encryption": "sealed_wallet_secret REQUIRED before write — plaintext private material never reaches the network",
            "public_availability": true, "retrieval": "gateway / pinned node",
            "authority": format!("none — {base_rule}"),
        }),
        "filecoin" => json!({
            "class": "decentralized_availability", "addressing": "CID + storage deals; fixture mode uses local-cas://sha256/<hex> and NEVER claims deal-backed availability",
            "custody_posture": "PUBLIC deal-backed durable availability — deals/proofs are availability evidence only",
            "encryption_required": true,
            "encryption": "sealed_wallet_secret REQUIRED before write — plaintext private material never reaches the network",
            "public_availability": true, "durability": "deal-backed (evidence when live)",
            "authority": format!("none — {base_rule}"),
        }),
        other => json!({ "class": "unknown", "note": format!("unknown kind '{other}'") }),
    }
}

fn storage_receipt(
    data_dir: &str,
    backend: &str,
    op: &str,
    outcome: &str,
    extra: &Value,
) -> String {
    let id = format!("stc_{:x}", nanos());
    let receipt_ref = format!("agentgres://storage-receipt/{id}");
    let mut rec = json!({
        "schema_version": "ioi.hypervisor.storage-receipt.v1",
        "receipt_id": id, "receipt_ref": receipt_ref,
        "backend": backend, "op": op, "outcome": outcome, "at": iso_now(),
    });
    if let (Some(target), Some(fields)) = (rec.as_object_mut(), extra.as_object()) {
        for (key, value) in fields {
            if !value.is_null() {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    let _ = persist_record(data_dir, RECEIPT_KIND, &id, &rec);
    receipt_ref
}

fn load_account(data_dir: &str, id_or_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, ACCOUNT_KIND)
        .into_iter()
        .find(|a| text(a, "account_id") == id_or_ref || text(a, "account_ref") == id_or_ref)
}
fn load_archive(data_dir: &str, id_or_ref: &str) -> Option<Value> {
    read_record_dir(data_dir, ARCHIVE_KIND)
        .into_iter()
        .find(|a| text(a, "archive_id") == id_or_ref || text(a, "archive_ref") == id_or_ref)
}
fn account_mode(account: &Value) -> String {
    let m = account
        .pointer("/endpoint/mode")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !m.is_empty() {
        return m.to_string();
    }
    // local kinds default to the real local store; network kinds must choose fixture|live.
    match text(account, "kind") {
        "local_disk" | "cas" => "local".into(),
        _ => "unset".into(),
    }
}
fn open_incidents_for(data_dir: &str, archive_ref: &str) -> Vec<Value> {
    read_record_dir(data_dir, INCIDENT_KIND)
        .into_iter()
        .filter(|i| text(i, "archive_ref") == archive_ref && text(i, "status") == "open")
        .collect()
}

fn open_incident(
    data_dir: &str,
    account: &Value,
    archive: &Value,
    kind: &str,
    detail: String,
    evidence: Value,
) -> String {
    let archive_ref = text(archive, "archive_ref");
    // One OPEN incident per (archive, kind) — repeat detections accrete evidence, not rows.
    if let Some(mut existing) = read_record_dir(data_dir, INCIDENT_KIND)
        .into_iter()
        .find(|i| {
            text(i, "archive_ref") == archive_ref
                && text(i, "kind") == kind
                && text(i, "status") == "open"
        })
    {
        let id = text(&existing, "incident_id").to_string();
        let mut seen = existing
            .get("detections")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        seen += 1;
        existing["detections"] = json!(seen);
        existing["last_evidence"] = evidence;
        existing["last_detected_at"] = json!(iso_now());
        let _ = persist_record(data_dir, INCIDENT_KIND, &id, &existing);
        return text(&existing, "incident_ref").to_string();
    }
    let id = format!("aai_{:x}", nanos());
    let incident_ref = format!("artifact-availability-incident://{id}");
    let record = json!({
        "schema_version": "ioi.hypervisor.artifact-availability-incident.v1",
        "incident_id": id, "incident_ref": incident_ref,
        "archive_ref": archive_ref, "material_ref": archive["material_ref"],
        "backend_ref": text(account, "account_ref"), "backend_kind": account["kind"],
        "environment_ref": archive["environment_ref"],
        "kind": kind, "detail": detail, "evidence": evidence,
        "detections": 1, "status": "open",
        "truth_note": "an availability incident quarantines the BYTES, not the artifact meaning — the daemon material record and admitted state_root remain the truth to repair against",
        "opened_at": iso_now(),
    });
    let _ = persist_record(data_dir, INCIDENT_KIND, &id, &record);
    incident_ref
}

// ── Backend byte stores ─────────────────────────────────────────────────────────────────────
// local | fixture: a REAL local content-addressed object store (bytes really persist and
// really verify; fixture is unmistakably labelled and never claims network availability).
// live (ipfs/filecoin): the real service API — code-complete, blocks NAMED without config.

fn object_dir(data_dir: &str, account: &Value) -> PathBuf {
    let configured = account
        .pointer("/endpoint/root_dir")
        .and_then(Value::as_str)
        .unwrap_or("");
    if configured.is_empty() {
        Path::new(data_dir)
            .join("storage-backends")
            .join(safe(text(account, "account_id")))
            .join("objects")
    } else {
        PathBuf::from(configured)
    }
}

/// Store SEALED bytes; returns the commitment evidence {address, stored_sha256, size_bytes, mode}.
fn store_bytes(data_dir: &str, account: &Value, sealed: &[u8]) -> Result<Value, String> {
    let kind = text(account, "kind");
    let mode = account_mode(account);
    let digest = sha256_bytes(sealed);
    let hexpart = digest.trim_start_matches("sha256:");
    match (kind, mode.as_str()) {
        ("local_disk" | "cas", "local") | ("ipfs" | "filecoin", "fixture") => {
            let dir = object_dir(data_dir, account);
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let file = dir.join(format!("{hexpart}.bin"));
            std::fs::write(&file, sealed).map_err(|e| e.to_string())?;
            // Read-back verification: commitment holds only if the stored bytes re-hash.
            let back = std::fs::read(&file).map_err(|e| e.to_string())?;
            if sha256_bytes(&back) != digest {
                return Err(
                    "storage_write_verify_failed — read-back hash does not match what was written"
                        .into(),
                );
            }
            let fixture = mode == "fixture";
            let address = if fixture {
                format!("local-cas://sha256/{hexpart}")
            } else {
                format!("cas://sha256/{hexpart}")
            };
            Ok(json!({
                "address": address, "stored_sha256": digest, "size_bytes": sealed.len(),
                "path": file.to_string_lossy(),
                "mode": if fixture { "fixture_evidence" } else { "real_local" },
                "read_back_verified": true,
                "warning": if fixture { json!(format!("local deterministic CAS FIXTURE for {kind} — bytes persist locally only; NOT network availability, no pin, no deal")) } else { Value::Null },
            }))
        }
        ("ipfs", "live") => {
            let (endpoint, bearer) = live_config(data_dir, account)?;
            // Hand-rolled multipart (kubo /api/v0/add expects form-data; the reqwest multipart
            // feature is not enabled workspace-wide and one part does not justify it).
            let boundary = format!("ioi-archive-{:x}", nanos());
            let mut body: Vec<u8> = Vec::with_capacity(sealed.len() + 512);
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"archive.sealed\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
            body.extend_from_slice(sealed);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let result: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut req = reqwest::Client::new()
                        .post(format!("{endpoint}/api/v0/add?cid-version=1"))
                        .header(
                            "content-type",
                            format!("multipart/form-data; boundary={boundary}"),
                        )
                        .body(body)
                        .timeout(std::time::Duration::from_secs(60));
                    if let Some(token) = &bearer {
                        req = req.bearer_auth(token);
                    }
                    let resp = req
                        .send()
                        .await
                        .map_err(|e| format!("ipfs_live_add_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let doc: Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("ipfs_live_add_failed: non-JSON response: {e}"))?;
                    if !(200..300).contains(&status) {
                        return Err(format!("ipfs_live_add_failed: http {status} {doc}"));
                    }
                    Ok(doc)
                })
            });
            let doc = result?;
            let cid = doc.get("Hash").and_then(Value::as_str).unwrap_or("");
            if cid.is_empty() {
                return Err("ipfs_live_add_failed: response carried no CID".into());
            }
            Ok(
                json!({ "address": format!("ipfs://{cid}"), "cid": cid, "stored_sha256": digest,
                       "size_bytes": sealed.len(), "mode": "live_evidence", "endpoint": endpoint,
                       "read_back_verified": false,
                       "note": "live IPFS add — CID is availability evidence, verified on next fetch" }),
            )
        }
        ("filecoin", "live") => {
            let (endpoint, bearer) = live_config(data_dir, account)?;
            let Some(token) = bearer else {
                return Err("filecoin_live_credentials_absent — a filecoin backend needs a bound api token for its deal/pin service".into());
            };
            let body = sealed.to_vec();
            let result: Result<Value, String> = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let resp = reqwest::Client::new()
                        .post(format!("{endpoint}/upload"))
                        .bearer_auth(&token)
                        .header("content-type", "application/octet-stream")
                        .body(body)
                        .timeout(std::time::Duration::from_secs(120))
                        .send()
                        .await
                        .map_err(|e| format!("filecoin_live_upload_failed: {e}"))?;
                    let status = resp.status().as_u16();
                    let doc: Value = resp.json().await.map_err(|e| {
                        format!("filecoin_live_upload_failed: non-JSON response: {e}")
                    })?;
                    if !(200..300).contains(&status) {
                        return Err(format!("filecoin_live_upload_failed: http {status} {doc}"));
                    }
                    Ok(doc)
                })
            });
            let doc = result?;
            let cid = doc
                .pointer("/cid")
                .and_then(Value::as_str)
                .or_else(|| doc.pointer("/value/cid").and_then(Value::as_str))
                .unwrap_or("");
            if cid.is_empty() {
                return Err("filecoin_live_upload_failed: response carried no CID".into());
            }
            Ok(
                json!({ "address": format!("filecoin://{cid}"), "cid": cid, "stored_sha256": digest,
                       "size_bytes": sealed.len(), "mode": "live_evidence", "endpoint": endpoint,
                       "read_back_verified": false,
                       "note": "live upload accepted — deal/pin state is availability evidence to poll, never restore truth" }),
            )
        }
        (_, "unset") => Err(format!(
            "{kind}_mode_unset — set endpoint.mode to fixture (local deterministic CAS) or live",
            kind = kind
        )),
        (k, m) => Err(format!(
            "storage_mode_unsupported — kind '{k}' has no '{m}' store lane"
        )),
    }
}

/// Fetch bytes by the recorded commitment; Err carries a named incident kind + detail.
fn fetch_bytes(
    data_dir: &str,
    account: &Value,
    commitment: &Value,
) -> Result<Vec<u8>, (String, String)> {
    let mode = text(commitment, "mode");
    if mode == "real_local" || mode == "fixture_evidence" {
        let path = text(commitment, "path");
        return std::fs::read(path).map_err(|e| {
            (
                "missing_bytes".into(),
                format!("backend object unreadable at its recorded address: {e}"),
            )
        });
    }
    // live: gateway/API fetch by CID.
    let cid = text(commitment, "cid").to_string();
    let (endpoint, bearer) =
        live_config(data_dir, account).map_err(|e| ("backend_unreachable".into(), e))?;
    let kind = text(account, "kind");
    let url = if kind == "ipfs" {
        format!("{endpoint}/api/v0/cat?arg={cid}")
    } else {
        format!("{endpoint}/download/{cid}")
    };
    let result: Result<Vec<u8>, String> = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let client = reqwest::Client::new();
            let mut req = if kind == "ipfs" {
                client.post(&url)
            } else {
                client.get(&url)
            };
            if let Some(token) = &bearer {
                req = req.bearer_auth(token);
            }
            let resp = req
                .timeout(std::time::Duration::from_secs(120))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(format!("http {status}"));
            }
            resp.bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| e.to_string())
        })
    });
    result.map_err(|e| {
        (
            "backend_unreachable".into(),
            format!("live retrieval of {cid} failed: {e}"),
        )
    })
}

fn live_config(data_dir: &str, account: &Value) -> Result<(String, Option<String>), String> {
    let kind = text(account, "kind");
    let endpoint = account
        .pointer("/endpoint/endpoint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    if endpoint.is_empty() {
        return Err(format!("{kind}_live_config_absent — endpoint.endpoint is required for live mode (gateway/API base)"));
    }
    let bearer = read_record_dir(data_dir, CREDENTIAL_VAULT)
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(text(account, "account_id")))
        .and_then(|c| c["sealed_token"].as_str().and_then(open_scm_token));
    Ok((endpoint, bearer))
}

// ── Account plane ───────────────────────────────────────────────────────────────────────────

/// GET /v1/hypervisor/storage-backends — accounts + health + archive/incident counts.
pub(crate) async fn handle_storage_backends_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let archives = read_record_dir(&st.data_dir, ARCHIVE_KIND);
    let incidents = read_record_dir(&st.data_dir, INCIDENT_KIND);
    let accounts: Vec<Value> = read_record_dir(&st.data_dir, ACCOUNT_KIND)
        .into_iter()
        .map(|mut a| {
            let account_ref = text(&a, "account_ref").to_string();
            let objects = archives.iter().filter(|x| text(x, "backend_ref") == account_ref).count();
            let open = incidents.iter().filter(|i| text(i, "backend_ref") == account_ref && text(i, "status") == "open").count();
            a["health"] = json!({
                "objects": objects,
                "open_incidents": open,
                "state": if text(&a, "status") != "verified" { "unverified" } else if open > 0 { "impaired" } else { "available" },
                "basis": "daemon records (archive objects + open availability incidents) — backend self-reports are evidence, not health truth",
            });
            a
        })
        .collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.storage-backends.v1",
        "custody_rule": "storage backends hold payload bytes; they do not own operational truth — daemon-admitted sha256 state roots remain restore truth",
        "backends": accounts, "at": iso_now(),
    }))
}

/// POST /v1/hypervisor/storage-backends — create a bounded-kind backend account.
pub(crate) async fn handle_storage_backend_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = text(&body, "kind").to_string();
    if !BACKEND_KINDS.contains(&kind.as_str()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "reason": format!("unknown storage backend kind '{kind}' — bounded kinds: {BACKEND_KINDS:?} (S3/customer-VPC land as later siblings)"),
            })),
        );
    }
    let display_name = {
        let n = text(&body, "display_name").trim().to_string();
        if n.is_empty() {
            format!("{kind} backend")
        } else {
            n
        }
    };
    let id = format!("sba_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.storage-backend-account.v1",
        "account_id": id,
        "account_ref": format!("storage-backend://{id}"),
        "display_name": display_name,
        "kind": kind,
        "status": "unverified",
        "endpoint": body.get("endpoint").cloned().unwrap_or_else(|| json!({})),
        "capabilities": kind_capabilities(&kind),
        "created_at": now, "updated_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "backend": record })),
    )
}

/// PATCH /v1/hypervisor/storage-backends/{id} — endpoint/mode changes reset verification.
pub(crate) async fn handle_storage_backend_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage backend" })),
        );
    };
    if let Some(endpoint) = body.get("endpoint") {
        account["endpoint"] = endpoint.clone();
        account["status"] = json!("unverified");
        account["preflight"] = Value::Null;
    }
    if let Some(name) = body.get("display_name").and_then(Value::as_str) {
        account["display_name"] = json!(name);
    }
    account["updated_at"] = json!(iso_now());
    let account_id = text(&account, "account_id").to_string();
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "backend": account })),
    )
}

/// DELETE /v1/hypervisor/storage-backends/{id}.
pub(crate) async fn handle_storage_backend_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(account) = load_account(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "no such storage backend" }));
    };
    let account_id = text(&account, "account_id").to_string();
    let dir = Path::new(&st.data_dir).join(ACCOUNT_KIND);
    let _ = std::fs::remove_file(dir.join(format!("{account_id}.json")));
    let cred_dir = Path::new(&st.data_dir).join(CREDENTIAL_VAULT);
    if let Ok(entries) = std::fs::read_dir(&cred_dir) {
        for entry in entries.flatten() {
            if let Ok(raw) = std::fs::read_to_string(entry.path()) {
                if let Ok(rec) = serde_json::from_str::<Value>(&raw) {
                    if rec["connector_id"].as_str() == Some(account_id.as_str()) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
    Json(
        json!({ "ok": true, "deleted": account_id, "note": "archive objects/incidents/receipts remain as evidence — deleting a backend never deletes daemon truth" }),
    )
}

/// POST /v1/hypervisor/storage-backends/{id}/credential — bind a sealed bearer (ipfs/filecoin live).
pub(crate) async fn handle_storage_backend_credential(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage backend" })),
        );
    };
    let secret = text(&body, "api_key").trim().to_string();
    if secret.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "ok": false, "reason": "api_key is required" })),
        );
    }
    let Some(sealed) = seal_scm_token(&secret) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "reason": "credential_seal_failed" })),
        );
    };
    let account_id = text(&account, "account_id").to_string();
    let cred = json!({
        "schema_version": "ioi.hypervisor.storage-credential.v1",
        "connector_id": account_id, "scheme": "bearer",
        "sealed_token": sealed, "key_source": scm_key_source(),
        "bound_at": iso_now(),
    });
    let _ = persist_record(&st.data_dir, CREDENTIAL_VAULT, &account_id, &cred);
    account["credential_binding_ref"] = json!(format!("storage-credential://{account_id}"));
    account["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account);
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "credential_binding_ref": account["credential_binding_ref"], "scheme": "bearer", "sealed": true }),
        ),
    )
}

/// POST /v1/hypervisor/storage-backends/{id}/preflight — REAL probe or named block.
/// local|fixture: write/read/delete a probe object in the real store dir. live: probe the API.
pub(crate) async fn handle_storage_backend_preflight(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut account) = load_account(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage backend" })),
        );
    };
    let kind = text(&account, "kind").to_string();
    let mode = account_mode(&account);
    let probe: Result<Value, String> = match mode.as_str() {
        "local" | "fixture" => {
            let dir = object_dir(&st.data_dir, &account);
            (|| {
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let probe_path = dir.join(".preflight-probe");
                let payload = format!("probe-{:x}", nanos());
                std::fs::write(&probe_path, &payload).map_err(|e| e.to_string())?;
                let back = std::fs::read_to_string(&probe_path).map_err(|e| e.to_string())?;
                std::fs::remove_file(&probe_path).map_err(|e| e.to_string())?;
                if back != payload {
                    return Err("probe read-back mismatch".into());
                }
                Ok(
                    json!({ "probe": "write/read/delete round-trip", "store_dir": dir.to_string_lossy(),
                           "mode": if mode == "fixture" { "fixture_evidence" } else { "real_local" },
                           "warning": if mode == "fixture" { json!(format!("local deterministic CAS FIXTURE for {kind} — NOT network availability")) } else { Value::Null } }),
                )
            })()
        }
        "live" => match live_config(&st.data_dir, &account) {
            Err(e) => Err(e),
            Ok((endpoint, bearer)) => {
                if bearer.is_none()
                    && matches!(kind.as_str(), "ipfs" | "filecoin")
                    && account
                        .get("credential_binding_ref")
                        .map(Value::is_null)
                        .unwrap_or(true)
                {
                    Err(format!("{kind}_live_credentials_absent — bind an api_key before live preflight; live availability is never claimed unauthenticated"))
                } else {
                    let url = if kind == "ipfs" {
                        format!("{endpoint}/api/v0/version")
                    } else {
                        format!("{endpoint}/health")
                    };
                    let result: Result<u16, String> = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            let client = reqwest::Client::new();
                            let mut req = if kind == "ipfs" {
                                client.post(&url)
                            } else {
                                client.get(&url)
                            };
                            if let Some(token) = &bearer {
                                req = req.bearer_auth(token);
                            }
                            req.timeout(std::time::Duration::from_secs(10))
                                .send()
                                .await
                                .map(|r| r.status().as_u16())
                                .map_err(|e| e.to_string())
                        })
                    });
                    match result {
                        Ok(status) if (200..300).contains(&status) => Ok(
                            json!({ "probe": url, "http_status": status, "mode": "live_evidence" }),
                        ),
                        Ok(status) => Err(format!(
                            "{kind}_live_probe_failed — {url} answered http {status}"
                        )),
                        Err(e) => Err(format!("{kind}_live_unreachable — {e}")),
                    }
                }
            }
        },
        _ => Err(format!(
            "{kind}_mode_unset — set endpoint.mode to fixture (local deterministic CAS) or live"
        )),
    };
    let account_id = text(&account, "account_id").to_string();
    match probe {
        Ok(evidence) => {
            account["status"] = json!("verified");
            account["preflight"] =
                json!({ "admitted": true, "evidence": evidence, "at": iso_now() });
            account["updated_at"] = json!(iso_now());
            let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account);
            (
                StatusCode::OK,
                Json(
                    json!({ "ok": true, "status": "verified", "preflight": account["preflight"] }),
                ),
            )
        }
        Err(reason) => {
            account["status"] = json!("unverified");
            account["preflight"] =
                json!({ "admitted": false, "evidence": { "reason": reason }, "at": iso_now() });
            account["updated_at"] = json!(iso_now());
            let _ = persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account);
            (
                StatusCode::CONFLICT,
                Json(json!({ "ok": false, "reason": reason })),
            )
        }
    }
}

// ── Archive custody ops (body-dispatched like provider-ops to avoid route collisions) ───────

/// POST /v1/hypervisor/storage-archive-ops — {op: export|verify|restore|repair, ...}.
pub(crate) async fn handle_storage_archive_op(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let op = text(&body, "op").to_string();
    match op.as_str() {
        "export" => op_export(&st, &body).await,
        "verify" => op_verify(&st, &body).await,
        "restore" => op_restore(&st, &body).await,
        "repair" => op_repair(&st, &body).await,
        other => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false, "reason": format!("unknown storage archive op '{other}' — ops: export | verify | restore | repair"),
            })),
        ),
    }
}

/// The wallet capability-lease crossing for archive export/restore. Facets bind the exact
/// material/archive + state_root + backend + encryption posture; the grant can never be
/// replayed across ops or payloads.
async fn storage_lease(
    st: &Arc<DaemonState>,
    account: &Value,
    op: &str,
    facets: Value,
    grant_value: Value,
) -> Result<(Value, String), (StatusCode, Value)> {
    let account_id = text(account, "account_id").to_string();
    let needs_credential = account_mode(account) == "live";
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("storage:backend:{account_id}"),
        allowed_tools: vec![format!("storage.archive_{op}")],
        resource_refs: vec![text(account, "account_ref").to_string()],
        scopes: vec!["storage.archive".to_string()],
        policy_domain: "hypervisor.storage.archive.policy.v1".to_string(),
        request_domain: "hypervisor.storage.archive.request.v1".to_string(),
        request_facets: facets,
        credential_connector_id: if needs_credential {
            Some(account_id.clone())
        } else {
            None
        },
        credential_store: CREDENTIAL_VAULT.to_string(),
        credential_required: needs_credential,
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("storage-backends/{account_id}/credential"),
        authority_reason: "storage_archive_authority_required".to_string(),
        grant_value,
    };
    match authorize_capability_lease(st, &lease_req).await {
        Ok(lease) => Ok((lease.descriptor.clone(), lease.grant_ref.clone())),
        Err((status, challenge)) => Err((status, challenge)),
    }
}

async fn op_export(st: &Arc<DaemonState>, body: &Value) -> (StatusCode, Json<Value>) {
    let data_dir = &st.data_dir;
    let backend_id = text(body, "backend_id");
    let material_ref = text(body, "material_ref").to_string();
    let Some(account) = load_account(data_dir, backend_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "no such storage backend — create + preflight one first" }),
            ),
        );
    };
    let kind = text(&account, "kind").to_string();
    let account_ref = text(&account, "account_ref").to_string();
    if text(&account, "status") != "verified" {
        let receipt = storage_receipt(
            data_dir,
            &kind,
            "export",
            "backend_unverified",
            &json!({ "backend_ref": account_ref, "material_ref": material_ref }),
        );
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "ok": false, "reason": "storage_backend_unverified — preflight the backend before exporting archive bytes", "receipt_ref": receipt }),
            ),
        );
    }
    // Custody truth FIRST: the daemon material record + admitted state_root gate everything.
    let Some(material) = read_record_dir(data_dir, MATERIAL_KIND)
        .into_iter()
        .find(|m| text(m, "material_ref") == material_ref)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": format!("material '{material_ref}' is not daemon-admitted — only admitted custody material can be archived") }),
            ),
        );
    };
    let admitted_root = text(&material, "state_root").to_string();
    let plaintext = match std::fs::read(text(&material, "path")) {
        Ok(b) => b,
        Err(e) => {
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "export",
                "custody_unreadable",
                &json!({ "backend_ref": account_ref, "material_ref": material_ref, "error": e.to_string() }),
            );
            return (
                StatusCode::CONFLICT,
                Json(
                    json!({ "ok": false, "reason": format!("custody material unreadable: {e}"), "receipt_ref": receipt }),
                ),
            );
        }
    };
    if sha256_bytes(&plaintext) != admitted_root {
        let receipt = storage_receipt(
            data_dir,
            &kind,
            "export",
            "custody_hash_mismatch",
            &json!({ "backend_ref": account_ref, "material_ref": material_ref, "state_root": admitted_root }),
        );
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "ok": false, "reason": "custody_material_hash_mismatch — custody bytes no longer match the admitted state_root; refusing to archive corrupt material", "receipt_ref": receipt }),
            ),
        );
    }
    // Wallet authority: the 403 challenge binds material + state_root + backend + encryption.
    let facets = json!({
        "op": "export", "material_ref": material_ref, "state_root": admitted_root,
        "backend_ref": account_ref, "backend_kind": kind,
        "encryption": "sealed_wallet_secret", "payload_bytes": plaintext.len(),
    });
    let (lease_descriptor, grant_ref) = match storage_lease(
        st,
        &account,
        "export",
        facets.clone(),
        body.get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .await
    {
        Ok(pair) => pair,
        Err((status, mut challenge)) => {
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "export",
                "authority_missing",
                &json!({ "backend_ref": account_ref, "material_ref": material_ref, "state_root": admitted_root }),
            );
            if let Some(o) = challenge.as_object_mut() {
                o.insert("receipt_ref".into(), json!(receipt));
                o.insert("lease_request_facets".into(), facets);
            }
            return (status, Json(challenge));
        }
    };
    // Seal ALWAYS — no plaintext private material at any backend, local included.
    let sealed = match seal_archive_bytes(&plaintext) {
        Ok(s) => s,
        Err(e) => {
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "export",
                "seal_failed",
                &json!({ "backend_ref": account_ref, "material_ref": material_ref, "error": e }),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "reason": e, "receipt_ref": receipt })),
            );
        }
    };
    let commitment = match store_bytes(data_dir, &account, &sealed) {
        Ok(c) => c,
        Err(e) => {
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "export",
                "store_failed",
                &json!({ "backend_ref": account_ref, "material_ref": material_ref, "grant_ref": grant_ref, "error": e }),
            );
            return (
                StatusCode::CONFLICT,
                Json(json!({ "ok": false, "reason": e, "receipt_ref": receipt })),
            );
        }
    };
    let id = format!("sao_{:x}", nanos());
    let archive_ref = format!("storage-archive://{id}");
    let receipt = storage_receipt(
        data_dir,
        &kind,
        "export",
        "ok",
        &json!({
            "backend_ref": account_ref, "archive_ref": archive_ref, "material_ref": material_ref,
            "environment_ref": material["environment_ref"], "state_root": admitted_root,
            "commitment": commitment, "grant_ref": grant_ref, "capability_lease": lease_descriptor,
            "encryption": { "scheme": "sealed_wallet_secret (Argon2id KDF + AEAD)", "key_source": scm_key_source() },
        }),
    );
    let record = json!({
        "schema_version": "ioi.hypervisor.storage-archive-object.v1",
        "archive_id": id, "archive_ref": archive_ref,
        "backend_ref": account_ref, "backend_kind": kind,
        "material_ref": material_ref, "environment_ref": material["environment_ref"],
        "provider_account_ref": material["account_ref"],
        "state_root": admitted_root,
        "media_type": "application/x-tar+gzip",
        "payload_bytes": plaintext.len(),
        "commitment": commitment,
        "encryption": { "scheme": "sealed_wallet_secret (Argon2id KDF + AEAD)", "key_source": scm_key_source(), "plaintext_at_backend": false },
        "status": "available",
        "availability_note": "storage availability is NOT restore truth — restore admits only after fetch + commitment hash + decrypt + admitted state_root all verify",
        "authority": "none — no CID, deal, pin, or backend id ever becomes authority or restore validity",
        "grant_ref": grant_ref,
        "receipt_refs": [receipt],
        "exported_at": iso_now(),
    });
    let _ = persist_record(data_dir, ARCHIVE_KIND, &id, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "op": "export", "archive": record, "receipt_ref": receipt })),
    )
}

async fn op_verify(st: &Arc<DaemonState>, body: &Value) -> (StatusCode, Json<Value>) {
    let data_dir = &st.data_dir;
    let Some(mut archive) = load_archive(data_dir, text(body, "archive_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage archive object" })),
        );
    };
    let Some(account) = load_account(data_dir, text(&archive, "backend_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "the archive's backend account no longer exists" }),
            ),
        );
    };
    let kind = text(&account, "kind").to_string();
    let archive_id = text(&archive, "archive_id").to_string();
    let archive_ref = text(&archive, "archive_ref").to_string();
    let commitment = archive.get("commitment").cloned().unwrap_or(Value::Null);
    let outcome = match fetch_bytes(data_dir, &account, &commitment) {
        Err((incident_kind, detail)) => {
            let incident_ref = open_incident(
                data_dir,
                &account,
                &archive,
                &incident_kind,
                detail.clone(),
                json!({ "op": "verify", "error": detail }),
            );
            archive["status"] = json!("impaired");
            archive["last_verify"] =
                json!({ "ok": false, "incident_ref": incident_ref, "at": iso_now() });
            let _ = persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive);
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "verify",
                "availability_incident",
                &json!({
                    "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "incident_ref": incident_ref,
                    "incident_kind": incident_kind, "state_root": archive["state_root"], "detail": detail,
                }),
            );
            (
                StatusCode::CONFLICT,
                Json(
                    json!({ "ok": false, "op": "verify", "reason": detail, "incident_ref": incident_ref, "receipt_ref": receipt, "archive_status": "impaired" }),
                ),
            )
        }
        Ok(bytes) => {
            let actual = sha256_bytes(&bytes);
            let expected = text(&commitment, "stored_sha256");
            if actual != expected {
                let detail = format!("stored bytes hash {actual} but the admitted commitment is {expected} — replica is stale or corrupt (a fetchable object is not a valid object)");
                let incident_ref = open_incident(
                    data_dir,
                    &account,
                    &archive,
                    "hash_mismatch",
                    detail.clone(),
                    json!({ "op": "verify", "actual": actual, "expected": expected }),
                );
                archive["status"] = json!("impaired");
                archive["last_verify"] =
                    json!({ "ok": false, "incident_ref": incident_ref, "at": iso_now() });
                let _ = persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive);
                let receipt = storage_receipt(
                    data_dir,
                    &kind,
                    "verify",
                    "availability_incident",
                    &json!({
                        "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "incident_ref": incident_ref,
                        "incident_kind": "hash_mismatch", "state_root": archive["state_root"], "detail": detail,
                    }),
                );
                (
                    StatusCode::CONFLICT,
                    Json(
                        json!({ "ok": false, "op": "verify", "reason": detail, "incident_ref": incident_ref, "receipt_ref": receipt, "archive_status": "impaired" }),
                    ),
                )
            } else {
                archive["last_verify"] = json!({ "ok": true, "stored_sha256": actual, "size_bytes": bytes.len(), "at": iso_now() });
                if text(&archive, "status") == "impaired"
                    && open_incidents_for(data_dir, &archive_ref).is_empty()
                {
                    archive["status"] = json!("available");
                }
                let _ = persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive);
                let receipt = storage_receipt(
                    data_dir,
                    &kind,
                    "verify",
                    "ok",
                    &json!({
                        "backend_ref": archive["backend_ref"], "archive_ref": archive_ref,
                        "state_root": archive["state_root"], "commitment": commitment,
                    }),
                );
                (
                    StatusCode::OK,
                    Json(
                        json!({ "ok": true, "op": "verify", "stored_sha256": actual, "size_bytes": bytes.len(), "receipt_ref": receipt,
                    "note": "commitment verified — availability evidence only, still not restore truth" }),
                    ),
                )
            }
        }
    };
    outcome
}

async fn op_restore(st: &Arc<DaemonState>, body: &Value) -> (StatusCode, Json<Value>) {
    let data_dir = &st.data_dir;
    let Some(archive) = load_archive(data_dir, text(body, "archive_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage archive object" })),
        );
    };
    let Some(account) = load_account(data_dir, text(&archive, "backend_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "the archive's backend account no longer exists" }),
            ),
        );
    };
    let kind = text(&account, "kind").to_string();
    let archive_ref = text(&archive, "archive_ref").to_string();
    let material_ref = text(&archive, "material_ref").to_string();
    let admitted_root = text(&archive, "state_root").to_string();
    // The daemon material RECORD is the admission — bytes can be repaired, meaning cannot.
    let Some(material) = read_record_dir(data_dir, MATERIAL_KIND)
        .into_iter()
        .find(|m| text(m, "material_ref") == material_ref)
    else {
        let receipt = storage_receipt(
            data_dir,
            &kind,
            "restore",
            "material_record_absent",
            &json!({ "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "material_ref": material_ref }),
        );
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "ok": false, "reason": "storage_material_record_absent — the daemon admission record for this material is gone; bytes alone cannot reconstruct meaning (availability is not truth)", "receipt_ref": receipt }),
            ),
        );
    };
    let facets = json!({
        "op": "restore", "archive_ref": archive_ref, "material_ref": material_ref,
        "state_root": admitted_root, "backend_ref": archive["backend_ref"], "backend_kind": kind,
    });
    let (lease_descriptor, grant_ref) = match storage_lease(
        st,
        &account,
        "restore",
        facets.clone(),
        body.get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .await
    {
        Ok(pair) => pair,
        Err((status, mut challenge)) => {
            let receipt = storage_receipt(
                data_dir,
                &kind,
                "restore",
                "authority_missing",
                &json!({ "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "state_root": admitted_root }),
            );
            if let Some(o) = challenge.as_object_mut() {
                o.insert("receipt_ref".into(), json!(receipt));
                o.insert("lease_request_facets".into(), facets);
            }
            return (status, Json(challenge));
        }
    };
    let refuse = |outcome: &str, incident: Option<(&str, String)>, reason: String| {
        let mut archive = archive.clone();
        let incident_ref = incident.map(|(ikind, detail)| {
            let r = open_incident(
                data_dir,
                &account,
                &archive,
                ikind,
                detail,
                json!({ "op": "restore", "error": reason }),
            );
            let archive_id = text(&archive, "archive_id").to_string();
            archive["status"] = json!("impaired");
            let _ = persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive);
            r
        });
        let receipt = storage_receipt(
            data_dir,
            &kind,
            "restore",
            outcome,
            &json!({
                "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "material_ref": material_ref,
                "state_root": admitted_root, "grant_ref": grant_ref,
                "incident_ref": incident_ref, "error": reason,
            }),
        );
        (
            StatusCode::CONFLICT,
            Json(
                json!({ "ok": false, "op": "restore", "reason": reason, "incident_ref": incident_ref, "receipt_ref": receipt }),
            ),
        )
    };
    // 1) fetch by the recorded address — bytes may be gone (that is an incident, not truth-loss).
    let commitment = archive.get("commitment").cloned().unwrap_or(Value::Null);
    let sealed = match fetch_bytes(data_dir, &account, &commitment) {
        Ok(b) => b,
        Err((ikind, detail)) => {
            return refuse(
                "availability_incident",
                Some((&ikind.clone(), detail.clone())),
                format!("storage_bytes_unavailable — {detail}"),
            )
        }
    };
    // 2) commitment hash — a fetchable-but-wrong object is stale/corrupt, never restorable.
    let actual = sha256_bytes(&sealed);
    let expected = text(&commitment, "stored_sha256").to_string();
    if actual != expected {
        return refuse("commitment_mismatch", Some(("hash_mismatch", format!("stored bytes hash {actual}, commitment {expected}"))),
            "storage_commitment_mismatch — fetched bytes do not match the admitted commitment; a successful fetch (CID/gateway) is NOT restore validity".to_string());
    }
    // 3) decrypt only through the wallet-secret authority path.
    let plaintext = match open_archive_bytes(&sealed) {
        Ok(p) => p,
        Err(e) => return refuse("decrypt_failed", Some(("decrypt_failure", e.clone())), e),
    };
    // 4) the admitted state_root is the ONLY restore truth.
    let plain_root = sha256_bytes(&plaintext);
    if plain_root != admitted_root {
        return refuse("state_root_mismatch", Some(("hash_mismatch", format!("decrypted bytes hash {plain_root}, admitted state_root {admitted_root}"))),
            "storage_restore_state_root_mismatch — decrypted bytes do not match the daemon-admitted state_root; refusing restore".to_string());
    }
    // 5) re-materialize daemon custody at the admitted path (repairing lost/corrupt custody bytes).
    let custody_path = text(&material, "path").to_string();
    if let Some(parent) = Path::new(&custody_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&custody_path, &plaintext) {
        return refuse(
            "custody_write_failed",
            None,
            format!("custody re-materialization failed: {e}"),
        );
    }
    let receipt = storage_receipt(
        data_dir,
        &kind,
        "restore",
        "ok",
        &json!({
            "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "material_ref": material_ref,
            "environment_ref": archive["environment_ref"],
            "state_root": admitted_root, "state_root_verified": admitted_root,
            "commitment": commitment, "grant_ref": grant_ref, "capability_lease": lease_descriptor,
            "custody_path": custody_path,
        }),
    );
    (
        StatusCode::OK,
        Json(json!({
            "ok": true, "op": "restore",
            "state_root_verified": admitted_root, "material_ref": material_ref,
            "custody_rematerialized": true, "receipt_ref": receipt,
            "note": "custody bytes re-admitted under the ORIGINAL daemon material record — environment restore continues through provider-ops restore, which re-verifies the state_root",
        })),
    )
}

async fn op_repair(st: &Arc<DaemonState>, body: &Value) -> (StatusCode, Json<Value>) {
    let data_dir = &st.data_dir;
    let Some(mut archive) = load_archive(data_dir, text(body, "archive_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "no such storage archive object" })),
        );
    };
    let Some(account) = load_account(data_dir, text(&archive, "backend_ref")) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "the archive's backend account no longer exists" }),
            ),
        );
    };
    let kind = text(&account, "kind").to_string();
    let archive_id = text(&archive, "archive_id").to_string();
    let archive_ref = text(&archive, "archive_ref").to_string();
    let material_ref = text(&archive, "material_ref").to_string();
    let admitted_root = text(&archive, "state_root").to_string();
    let incidents = open_incidents_for(data_dir, &archive_ref);
    let repair_id = format!("arr_{:x}", nanos());
    let repair_ref = format!("artifact-repair-receipt://{repair_id}");
    let mut fail = |reason: String, verification: Value| {
        let record = json!({
            "schema_version": "ioi.hypervisor.artifact-repair-receipt.v1",
            "repair_id": repair_id, "repair_ref": repair_ref,
            "archive_ref": archive_ref, "material_ref": material_ref, "backend_ref": archive["backend_ref"],
            "source": "daemon_custody", "outcome": "repair_failed",
            "reason": reason, "verification": verification,
            "incident_refs": incidents.iter().map(|i| i["incident_ref"].clone()).collect::<Vec<_>>(),
            "at": iso_now(),
        });
        let _ = persist_record(data_dir, REPAIR_KIND, &repair_id, &record);
        let receipt = storage_receipt(
            data_dir,
            &kind,
            "repair",
            "repair_failed",
            &json!({
                "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "repair_ref": repair_ref,
                "state_root": admitted_root, "error": reason,
            }),
        );
        (
            StatusCode::CONFLICT,
            Json(
                json!({ "ok": false, "op": "repair", "outcome": "repair_failed", "reason": reason, "repair_ref": repair_ref, "receipt_ref": receipt, "archive_status": "impaired" }),
            ),
        )
    };
    // Repair source: daemon custody — the material record + admitted state_root gate it.
    let Some(material) = read_record_dir(data_dir, MATERIAL_KIND)
        .into_iter()
        .find(|m| text(m, "material_ref") == material_ref)
    else {
        return fail("storage_material_record_absent — no daemon admission record to repair from; bytes alone cannot reconstruct meaning".into(), Value::Null);
    };
    let plaintext = match std::fs::read(text(&material, "path")) {
        Ok(b) => b,
        Err(e) => {
            return fail(
                format!("custody_unreadable — daemon custody bytes unavailable for repair: {e}"),
                Value::Null,
            )
        }
    };
    let plain_root = sha256_bytes(&plaintext);
    if plain_root != admitted_root {
        return fail(format!("custody_hash_mismatch — custody bytes hash {plain_root} but the admitted state_root is {admitted_root}; a stale/wrong source can never repair an archive"),
            json!({ "actual": plain_root, "expected": admitted_root }));
    }
    let sealed = match seal_archive_bytes(&plaintext) {
        Ok(s) => s,
        Err(e) => return fail(e, Value::Null),
    };
    let new_commitment = match store_bytes(data_dir, &account, &sealed) {
        Ok(c) => c,
        Err(e) => return fail(format!("repair_store_failed — {e}"), Value::Null),
    };
    // Verified replacement commitment: admit it on the object, close incidents, mint receipts.
    let old_commitment = archive.get("commitment").cloned().unwrap_or(Value::Null);
    archive["commitment"] = new_commitment.clone();
    archive["status"] = json!("available");
    archive["repaired_at"] = json!(iso_now());
    archive["repair_ref"] = json!(repair_ref);
    let _ = persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive);
    let mut closed: Vec<Value> = Vec::new();
    for mut incident in incidents {
        let iid = text(&incident, "incident_id").to_string();
        incident["status"] = json!("repaired");
        incident["repair_ref"] = json!(repair_ref);
        incident["closed_at"] = json!(iso_now());
        let _ = persist_record(data_dir, INCIDENT_KIND, &iid, &incident);
        closed.push(incident["incident_ref"].clone());
    }
    let record = json!({
        "schema_version": "ioi.hypervisor.artifact-repair-receipt.v1",
        "repair_id": repair_id, "repair_ref": repair_ref,
        "archive_ref": archive_ref, "material_ref": material_ref, "backend_ref": archive["backend_ref"],
        "source": "daemon_custody", "outcome": "repaired",
        "old_commitment": old_commitment, "new_commitment": new_commitment,
        "state_root": admitted_root,
        "verification": { "custody_state_root_verified": true, "read_back_verified": new_commitment.get("read_back_verified").cloned().unwrap_or(Value::Null) },
        "incident_refs": closed,
        "admission_note": "the replacement commitment preserves meaning ONLY because it is linked here to the same material_ref, state_root, and receipt chain — a new CID alone repairs nothing",
        "at": iso_now(),
    });
    let _ = persist_record(data_dir, REPAIR_KIND, &repair_id, &record);
    let receipt = storage_receipt(
        data_dir,
        &kind,
        "repair",
        "ok",
        &json!({
            "backend_ref": archive["backend_ref"], "archive_ref": archive_ref, "repair_ref": repair_ref,
            "material_ref": material_ref, "state_root": admitted_root, "commitment": new_commitment,
        }),
    );
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "op": "repair", "outcome": "repaired", "repair_ref": repair_ref, "repair": record, "receipt_ref": receipt }),
        ),
    )
}

// ── Projections ─────────────────────────────────────────────────────────────────────────────

/// GET /v1/hypervisor/storage-archives — archive objects (+ per-object open incident refs).
pub(crate) async fn handle_storage_archives_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let incidents = read_record_dir(&st.data_dir, INCIDENT_KIND);
    let mut archives = read_record_dir(&st.data_dir, ARCHIVE_KIND);
    for a in archives.iter_mut() {
        let archive_ref = text(a, "archive_ref").to_string();
        let open: Vec<Value> = incidents
            .iter()
            .filter(|i| text(i, "archive_ref") == archive_ref && text(i, "status") == "open")
            .map(|i| i["incident_ref"].clone())
            .collect();
        a["open_incident_refs"] = json!(open);
    }
    archives.sort_by(|a, b| text(b, "exported_at").cmp(text(a, "exported_at")));
    Json(json!({
        "schema_version": "ioi.hypervisor.storage-archives.v1",
        "custody_rule": "storage availability is NOT restore truth — restore admits only after fetch + commitment hash + decrypt + admitted state_root all verify",
        "archives": archives, "at": iso_now(),
    }))
}

/// GET /v1/hypervisor/storage-incidents — availability incidents + repair receipts.
pub(crate) async fn handle_storage_incidents(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut incidents = read_record_dir(&st.data_dir, INCIDENT_KIND);
    incidents.sort_by(|a, b| text(b, "opened_at").cmp(text(a, "opened_at")));
    let mut repairs = read_record_dir(&st.data_dir, REPAIR_KIND);
    repairs.sort_by(|a, b| text(b, "at").cmp(text(a, "at")));
    Json(json!({
        "schema_version": "ioi.hypervisor.storage-incidents.v1",
        "incidents": incidents, "repair_receipts": repairs, "at": iso_now(),
    }))
}

/// GET /v1/hypervisor/storage-receipts — the storage custody proof stream.
pub(crate) async fn handle_storage_receipts(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_KIND);
    receipts.sort_by(|a, b| text(b, "at").cmp(text(a, "at")));
    Json(
        json!({ "schema_version": "ioi.hypervisor.storage-receipts.v1", "receipts": receipts, "at": iso_now() }),
    )
}

/// storage_network candidate-source posture — real backend records or an honest absence.
pub(crate) fn source_state(data_dir: &str) -> Value {
    let facts = backend_facts(data_dir);
    if facts.is_empty() {
        return json!({ "source": "storage_network", "state": "candidate_source_unavailable",
            "reason": "storage_backend_absent — no StorageBackendAccount exists; create one (local_disk | cas | ipfs | filecoin) and preflight it",
            "evidence": { "storage_backends": 0, "basis": "storage-backend-accounts records" } });
    }
    let verified: Vec<&Value> = facts
        .iter()
        .filter(|f| f["account"]["status"] == "verified")
        .collect();
    if verified.is_empty() {
        return json!({ "source": "storage_network", "state": "candidate_source_unavailable",
            "reason": "storage_backend_unverified — backends exist but none passed preflight",
            "evidence": { "storage_backends": facts.len(), "verified": 0, "basis": "storage-backend-accounts records + preflight posture" } });
    }
    let kinds: Vec<String> = verified
        .iter()
        .map(|f| f["account"]["kind"].as_str().unwrap_or("?").to_string())
        .collect();
    let objects: u64 = verified
        .iter()
        .map(|f| f["objects"].as_u64().unwrap_or(0))
        .sum();
    let open: u64 = verified
        .iter()
        .map(|f| f["open_incidents"].as_u64().unwrap_or(0))
        .sum();
    json!({ "source": "storage_network", "state": "storage_backends_engaged",
        "coverage": "verified StorageBackendAccounts — archive/CAS byte custody candidates from local facts",
        "rule": "storage availability is NOT restore truth — daemon-admitted sha256 state roots remain restore truth",
        "evidence": { "verified_backends": verified.len(), "kinds": kinds, "archive_objects": objects,
                      "open_incidents": open, "basis": "storage-backend-accounts + archive objects + incidents (daemon records)" } })
}

/// Storage-backend facts for the candidate plane (decentralized_cloud_routes) — verified
/// accounts with honest posture; NEVER availability claims beyond daemon records.
pub(crate) fn backend_facts(data_dir: &str) -> Vec<Value> {
    let archives = read_record_dir(data_dir, ARCHIVE_KIND);
    let incidents = read_record_dir(data_dir, INCIDENT_KIND);
    read_record_dir(data_dir, ACCOUNT_KIND)
        .into_iter()
        .map(|a| {
            let account_ref = text(&a, "account_ref").to_string();
            let objects = archives
                .iter()
                .filter(|x| text(x, "backend_ref") == account_ref)
                .count();
            let open = incidents
                .iter()
                .filter(|i| text(i, "backend_ref") == account_ref && text(i, "status") == "open")
                .count();
            json!({
                "account": a, "objects": objects, "open_incidents": open,
            })
        })
        .collect()
}
