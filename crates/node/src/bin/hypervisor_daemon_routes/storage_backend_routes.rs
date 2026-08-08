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

/// A storage-plane durable write that did not land. The house refusal shape (code + honest
/// message); callers name the external effect / committed evidence the lost write leaves behind.
fn storage_persist_failed(code: &str, message: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "ok": false, "code": code, "message": message })),
    )
}

fn storage_receipt(
    data_dir: &str,
    backend: &str,
    op: &str,
    outcome: &str,
    extra: &Value,
) -> Option<String> {
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
    // W1.2 / MEF-GAP-008 — Option-return on a failed persist (provider_receipt_ext is the
    // template): no response may cite a `receipt_ref` that resolves to nothing. Callers that
    // embed the receipt as evidence serialize None as null (honest); a caller for whom the
    // receipt IS the recorded effect refuses instead.
    persist_record(data_dir, RECEIPT_KIND, &id, &rec)
        .ok()
        .map(|_| receipt_ref)
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
) -> Option<String> {
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
        let existing_ref = text(&existing, "incident_ref").to_string();
        let mut seen = existing
            .get("detections")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        seen += 1;
        existing["detections"] = json!(seen);
        existing["last_evidence"] = evidence;
        existing["last_detected_at"] = json!(iso_now());
        // W1.2 / MEF-GAP-008 — a lost accretion write drops this detection from the durable
        // incident; return None so the caller refuses rather than citing an unrecorded update.
        return persist_record(data_dir, INCIDENT_KIND, &id, &existing)
            .ok()
            .map(|_| existing_ref);
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
    // W1.2 / MEF-GAP-008 — an availability incident that did not commit quarantines nothing:
    // the impaired archive would still list `available` and repair targeting (open_incidents_for)
    // would never find it. Return None so the caller refuses with storage_incident_persistence_failed.
    persist_record(data_dir, INCIDENT_KIND, &id, &record)
        .ok()
        .map(|_| incident_ref)
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
    // W1.2 / MEF-GAP-008 — a discarded account write returns a backend the caller can act on
    // (bind credentials, gate exports) yet no reader will ever find. Refuse before claiming CREATED.
    if persist_record(&st.data_dir, ACCOUNT_KIND, &id, &record).is_err() {
        return storage_persist_failed(
            "storage_backend_account_persistence_failed",
            "the storage backend account did not commit — nothing was created".into(),
        );
    }
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
    // W1.2 / MEF-GAP-008 — an endpoint/mode change resets status to `unverified`; a lost write
    // leaves the account reading stale `verified` with the export gate open on a changed endpoint.
    if persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account).is_err() {
        return storage_persist_failed(
            "storage_backend_account_persistence_failed",
            "the backend patch did not commit — the account still reflects its prior endpoint and verification status".into(),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "backend": account })),
    )
}

// ── Backend account destruction ─────────────────────────────────────────────────────────────
// Deleting a backend destroys TWO daemon-owned things: the account record and the sealed bearer
// credential bound to it. The credential is the LIVE bearer-resolution path — `live_config` opens
// `sealed_token` on every live store, fetch, and preflight — not cleanup. It is therefore removed
// FIRST, so that for every credential THIS DELETION OBSERVED, no acknowledged or partially failed
// run can leave a live, resolvable credential orphaned behind an account no listing shows and no
// delete path can reach again.
//
// THAT GUARANTEE IS SCOPED TO WHAT THE VAULT WALK SAW, and is NOT a concurrency claim. Nothing here
// holds a lock. A credential bound by `handle_storage_backend_credential` AFTER this deletion has
// classified the vault, but BEFORE the account record is unlinked, is not observed by the walk and
// IS orphaned exactly as before — it survives, still resolves, and its account is gone. Closing
// that window needs a lock or a compare-and-swap on the account record, neither of which exists on
// this plane; it is an explicit nonclaim recorded in the mutation coverage registry, not a
// guarantee this ordering provides.

/// The typed disposition of ONE slot unlink, mapped from `durable_fs::UnlinkOutcome`.
///
/// `RemovedDurable` and `AlreadyAbsent` are kept DISTINCT rather than folded into one
/// confirmed-absence variant, because they support different claims and only one of them is
/// causal. Folding them is how a count of "credentials revoked by this request" comes to include
/// slots this request never touched.
///
/// Extracted from the effect lanes so the dispositions that have NO deterministic, uid-independent
/// injection on these unpromoted daemon-file families are asserted DIRECTLY from constructed
/// variants rather than only reviewed: `DurabilityUnconfirmed`, whose only injection point is a
/// process-global env var owned by `durable_fs`, and `NotPerformed` on the credential lane, which
/// no path shadow can reach because every shadow that breaks a slot's unlink also breaks the
/// strict read that classifies it, and that read refuses first.
#[derive(Debug, PartialEq, Eq)]
enum SlotUnlink {
    /// THIS request unlinked the slot AND the parent-directory fsync confirmed its absence. This
    /// is the only disposition that supports a causal claim: the credential was revoked here.
    RemovedDurable,
    /// The unlink returned ENOENT: the name was not in the live namespace at the moment THIS
    /// request attempted to unlink it. The slot is absent — but this request did NOT remove it, and
    /// no fsync of that absence was performed here, so its durability rests on whatever actor did.
    /// Note the tense: the strict read that classified this slot ALSO ran during this request, so
    /// the slot may have gone away between the two; `AlreadyAbsent` never licenses the claim that
    /// it was absent BEFORE this request began. Counted and narrated separately from
    /// `RemovedDurable` for exactly that reason.
    AlreadyAbsent,
    /// Removed-but-unconfirmed, or durably restored after an unconfirmed removal. Never a success
    /// claim in EITHER direction: this is not "gone" and it is not "unchanged".
    DurabilityUnconfirmed(String),
    /// The unlink did not happen. The slot provably still occupies its name.
    NotPerformed(String),
}

fn classify_unlink(outcome: std::io::Result<super::durable_fs::UnlinkOutcome>) -> SlotUnlink {
    use super::durable_fs::UnlinkOutcome;
    match outcome {
        Ok(UnlinkOutcome::Durable) => SlotUnlink::RemovedDurable,
        Ok(UnlinkOutcome::Absent) => SlotUnlink::AlreadyAbsent,
        Ok(UnlinkOutcome::RemovedDurabilityUnconfirmed(error)) => SlotUnlink::DurabilityUnconfirmed(
            format!("the slot is absent from the live namespace but the directory fsync did not confirm it ({error})"),
        ),
        Ok(UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(error)) => {
            SlotUnlink::DurabilityUnconfirmed(format!(
                "the removal was unconfirmed and a byte-exact replay anchor was durably restored in its place ({error})"
            ))
        }
        Err(error) => SlotUnlink::NotPerformed(error.to_string()),
    }
}

/// Open a daemon record family as a walk root, FOLLOWING a symlinked family directory exactly as
/// the production readers do.
///
/// `durable_fs::open_family_dir_pinned` adds `O_NOFOLLOW`, which refuses a symlinked family. Using
/// it here would have denied EVERY deletion in any deployment that symlinks a record family — a
/// container volume mount, or an atomic-swap release directory — while `read_record_dir`,
/// `load_account` and `live_config` all followed that same symlink happily and kept working. That
/// asymmetry buys no containment: whoever can replace `data_dir/<family>` equally controls its
/// contents. This is the same ruling the command-execution guardrail closure reached for a
/// symlinked data directory.
///
/// CONTAINMENT IS RETAINED WHERE IT MATTERS: no terminal slot under the returned descriptor is
/// ever FOLLOWED, and the two lanes get there differently.
///   * The credential lane READS every slot first, through `durable_fs::read_slot_strict`, which
///     opens `O_NOFOLLOW` — so a symlinked credential slot refuses the whole deletion rather than
///     being read, classified, or removed through.
///   * The account lane does NOT pre-read its slot: it goes straight to
///     `durable_fs::unlink_durable_at`, which is `unlinkat(dirfd, name, 0)`. That is not
///     `O_NOFOLLOW` and it does not refuse a symlink — it removes the SYMLINK ENTRY ITSELF and
///     never touches or deletes whatever it points at. A symlinked account slot is therefore
///     safely unlinked rather than refused, and the reloaded-absence gate below still decides the
///     acknowledgement from `load_account`, so the answer stays honest either way.
/// Both families this is called with are compile-time constants and single non-traversing
/// components.
fn open_record_family(data_dir: &str, family: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(Path::new(data_dir).join(family))
}

/// What the credential purge actually established, split by whether THIS request caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PurgeTally {
    /// Slots this request unlinked and fsync-confirmed. The only causal count.
    revoked: u64,
    /// Slots that were already gone when this request looked. Confirmed absent, not revoked here.
    already_absent: u64,
}

/// The posture EVERY deletion response carries — refusals AND success — so no caller has to know
/// which lane it came from to learn what this request did.
///
/// The purge is a LOOP over one slot at a time and is therefore NOT atomic: slot two's unlink can
/// fail after slot one's already fsynced. A response that said "nothing was deleted" there would be
/// false about a destruction that cannot be undone.
///
/// The state vocabulary, over `revoked` (caused here) and `unconfirmed` (in doubt):
///   * `none` — nothing was revoked here and nothing is in doubt.
///   * `partial_confirmed` — `revoked` credentials were destroyed here AND at least one bound
///     credential provably remains; the purge stopped part-way.
///   * `ambiguous` — nothing confirmed revoked, and one removal is visible-but-unconfirmed. NOT
///     `none`: reporting "nothing happened" over an outstanding unconfirmed removal is the same
///     class of false claim in the opposite direction.
///   * `partial_ambiguous` — both at once, so the true number destroyed here is `revoked` or
///     `revoked + 1`.
///   * `already_completed` — the purge finished: every bound slot it found is absent.
fn purge_state(revoked: u64, unconfirmed: u64, complete: bool) -> &'static str {
    if unconfirmed > 0 {
        if revoked > 0 {
            "partial_ambiguous"
        } else {
            "ambiguous"
        }
    } else if complete {
        "already_completed"
    } else if revoked > 0 {
        "partial_confirmed"
    } else {
        "none"
    }
}

fn with_purge_posture(
    response: (StatusCode, Value),
    tally: PurgeTally,
    unconfirmed: u64,
    complete: bool,
) -> (StatusCode, Value) {
    let (status, mut body) = response;
    body["credential_revocation"] = json!(purge_state(tally.revoked, unconfirmed, complete));
    body["credentials_revoked"] = json!(tally.revoked);
    body["credentials_already_absent"] = json!(tally.already_absent);
    body["credentials_unconfirmed"] = json!(unconfirmed);
    (status, body)
}

/// The WHOLE consequence sentence, GENERATED from the tally AND the unconfirmed count, rather
/// than spliced in front of a fixed tail.
///
/// Splicing is what produced the defect this replaces: a zero-count refusal opened with "No sealed
/// credential was removed" and then inherited a tail asserting "so this purge is PARTIAL and the
/// vault is not in the state it started in", and the account lane opened with "This backend had no
/// bound credential to revoke" and inherited "the revocation already happened and will not be
/// undone". Every clause that asserts something about what changed is produced HERE, so a
/// zero-count response can never carry a partial-purge claim and a nonzero-count response can never
/// carry a nothing-happened claim.
///
/// `unconfirmed` is load-bearing and NOT decoration. A visible-but-unconfirmed removal means the
/// vault MAY already differ, so no arm reachable with `unconfirmed > 0` may describe the vault as
/// unchanged or as exactly-as-found — including the zero-confirmed arm, which otherwise reads as a
/// nothing-happened claim over a removal that very likely landed.
///
/// `complete` distinguishes a purge that stopped part-way from one that finished.
fn purge_consequence(tally: PurgeTally, unconfirmed: u64, complete: bool) -> String {
    // NOTE ON TENSE: a slot is `AlreadyAbsent` because the unlink returned ENOENT DURING this
    // request — the strict read that classified it also ran during this request, so the slot may
    // have gone away between the two. The honest statement is that it was absent when this request
    // attempted its unlink, NOT that it was absent before this request began.
    let already = match tally.already_absent {
        0 => String::new(),
        1 => " (a further 1 bound slot was absent when this request attempted its unlink, so this request did not remove it)".to_string(),
        many => format!(" (a further {many} bound slots were absent when this request attempted their unlinks, so this request did not remove them)"),
    };
    if unconfirmed > 0 {
        // AMBIGUOUS. The vault is never describable as unchanged from here.
        return match tally.revoked {
            0 => format!("No sealed credential was CONFIRMED revoked by this request, and the removal named above is VISIBLE but UNCONFIRMED — so the vault MAY already have changed and must NOT be assumed unchanged{already}"),
            confirmed => format!(
                "{confirmed} sealed credential{plural} bound to this backend {verb} durably revoked by this request and {are} not restored{already}, and a further removal is VISIBLE but UNCONFIRMED — so this purge is PARTIAL AND AMBIGUOUS: the number destroyed here is {confirmed} or {upper}",
                plural = if confirmed == 1 { "" } else { "s" },
                verb = if confirmed == 1 { "WAS" } else { "WERE" },
                are = if confirmed == 1 { "is" } else { "are" },
                upper = confirmed + 1,
            ),
        };
    }
    match (tally.revoked, complete) {
        (0, false) => match tally.already_absent {
            0 => "No sealed credential was revoked by this request and no slot was removed, so this backend's vault is exactly as this deletion found it".to_string(),
            1 => "No sealed credential was revoked by this request — 1 bound slot was already absent when this request attempted its unlink — so this request itself removed nothing".to_string(),
            many => format!("No sealed credential was revoked by this request — {many} bound slots were already absent when this request attempted their unlinks — so this request itself removed nothing"),
        },
        (0, true) => match tally.already_absent {
            0 => "This backend had no bound sealed credential, so nothing was revoked by this request".to_string(),
            1 => "This backend's 1 bound sealed-credential slot was already absent when this request attempted its unlink, so nothing was revoked by this request".to_string(),
            many => format!("This backend's {many} bound sealed-credential slots were already absent when this request attempted their unlinks, so nothing was revoked by this request"),
        },
        (1, false) => format!("1 sealed credential bound to this backend WAS durably revoked by this request and is not restored{already}, so this purge is PARTIAL and the vault is not in the state it started in"),
        (many, false) => format!("{many} sealed credentials bound to this backend WERE durably revoked by this request and are not restored{already}, so this purge is PARTIAL and the vault is not in the state it started in"),
        (1, true) => format!("This backend's 1 sealed credential WAS durably revoked by this request and is not restored{already}"),
        (many, true) => format!("This backend's {many} sealed credentials WERE durably revoked by this request and are not restored{already}"),
    }
}

fn deletion_refusal(status: StatusCode, code: &str, message: String) -> (StatusCode, Value) {
    (
        status,
        json!({ "ok": false, "error": { "code": code, "message": message } }),
    )
}

/// A refusal raised BEFORE any unlink was attempted: the tally is empty by construction.
fn refusal_before_any_unlink(
    status: StatusCode,
    code: &str,
    message: String,
) -> (StatusCode, Value) {
    with_purge_posture(
        deletion_refusal(status, code, message),
        PurgeTally::default(),
        0,
        false,
    )
}

/// Map a credential-slot unlink disposition onto this plane's refusal; `None` means the slot is
/// absent and the purge may continue. `tally` is what this request has established BEFORE reaching
/// `slot`.
fn credential_slot_refusal(
    disposition: &SlotUnlink,
    slot: &str,
    tally: PurgeTally,
) -> Option<(StatusCode, Value)> {
    match disposition {
        SlotUnlink::RemovedDurable | SlotUnlink::AlreadyAbsent => None,
        // Visible-but-unconfirmed removal. The bearer may or may not survive a crash, so neither
        // "revoked" nor "still bound" is sayable, and the account MUST NOT be destroyed on top of
        // that: a surviving credential behind a missing account is unreachable.
        SlotUnlink::DurabilityUnconfirmed(detail) => Some(with_purge_posture(
            deletion_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_backend_credential_revocation_durability_unconfirmed",
                format!("the sealed credential at '{slot}' has an UNCONFIRMED removal ({detail}) — it may or may not still resolve as this backend's live bearer. {consequence}. The backend account was NOT deleted, deliberately, so every remaining credential stays reachable through it. Delete again to converge.", consequence = purge_consequence(tally, 1, false)),
            ),
            tally,
            1,
            false,
        )),
        SlotUnlink::NotPerformed(detail) => Some(with_purge_posture(
            deletion_refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_credential_revocation_failed",
                format!("the sealed credential at '{slot}' could not be removed ({detail}) — it still resolves as this backend's live bearer. {consequence}. The backend account was NOT deleted, so the remaining credentials stay reachable through it. Delete again to retry.", consequence = purge_consequence(tally, 0, false)),
            ),
            tally,
            0,
            false,
        )),
    }
}

/// Map the account-record unlink disposition onto this plane's refusal; `None` means the record's
/// name is absent and the reloaded-absence gate may run.
fn account_deletion_refusal(
    disposition: &SlotUnlink,
    tally: PurgeTally,
) -> Option<(StatusCode, Value)> {
    let consequence = purge_consequence(tally, 0, true);
    match disposition {
        SlotUnlink::RemovedDurable | SlotUnlink::AlreadyAbsent => None,
        SlotUnlink::DurabilityUnconfirmed(detail) => Some(with_purge_posture(
            deletion_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_backend_account_deletion_durability_unconfirmed",
                format!("{consequence}. The account record's removal is UNCONFIRMED ({detail}) — the deletion may or may not have applied and is NOT acknowledged. Delete again to converge."),
            ),
            tally,
            0,
            true,
        )),
        SlotUnlink::NotPerformed(detail) => Some(with_purge_posture(
            deletion_refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_account_deletion_failed",
                format!("{consequence}. The account record could not be removed ({detail}), so the backend still exists and can no longer authenticate. Delete again to retry."),
            ),
            tally,
            0,
            true,
        )),
    }
}

/// Does a sealed bearer credential for this account still resolve through the PRODUCTION reader —
/// the same `read_record_dir` family scan and `connector_id` match `live_config` performs before
/// it opens a token? A credential this still finds is live, whatever the unlinks reported.
fn account_credential_resolves(data_dir: &str, account_id: &str) -> bool {
    read_record_dir(data_dir, CREDENTIAL_VAULT)
        .into_iter()
        .any(|c| c["connector_id"].as_str() == Some(account_id))
}

/// Remove every sealed credential bound to `account_id`, returning what was established, SPLIT by
/// whether this request caused it.
///
/// The vault is walked with `durable_fs`'s pinned enumeration and STRICT slot reads, so the walk
/// inherits the shared boundary's rule that only `ENOENT` means empty. The shipped walk used
/// `read_dir` + `read_to_string` + `from_str` and SKIPPED every unreadable entry and every parse
/// failure, so an unreadable vault, an unreadable slot, and a malformed slot were all silently
/// indistinguishable from "no credential is bound" — and the response then claimed the backend was
/// deleted over them. An absent vault or an absent slot is genuinely absent; an UNREADABLE one is
/// unknown, and unknown fails closed.
///
/// EVERY slot is classified BEFORE any slot is unlinked, so a classification refusal leaves the
/// vault exactly as it was found rather than half-purged.
fn revoke_account_credentials(
    data_dir: &str,
    account_id: &str,
) -> Result<PurgeTally, (StatusCode, Value)> {
    let vault = match open_record_family(data_dir, CREDENTIAL_VAULT) {
        Ok(directory) => directory,
        // ONLY ENOENT is absence: a vault that was never created holds no bearer, so there is
        // nothing to remove and the tally is honestly empty.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PurgeTally::default())
        }
        Err(error) => {
            return Err(refusal_before_any_unlink(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_credential_vault_unpinnable",
                format!("the sealed-credential vault could not be opened as a directory ({error}) — an unreadable vault is NOT an empty one, so this backend's bearer cannot be proven gone. No credential was removed and the backend account remains. Repair the vault and delete again."),
            ))
        }
    };
    let names = super::durable_fs::enumerate_pinned(&vault).map_err(|error| {
        refusal_before_any_unlink(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_backend_credential_vault_unreadable",
            format!("the sealed-credential vault could not be enumerated ({error}) — a partial listing is never served as the whole vault, so this backend's bearer cannot be proven gone. No credential was removed and the backend account remains. Delete again to retry."),
        )
    })?;

    let mut targets: Vec<String> = Vec::new();
    for name in names {
        // The SAME record selection the live bearer path uses: `read_record_dir` admits only
        // entries whose extension is exactly `json`, so an entry that reader can never resolve as
        // a bearer is classified — not unclassifiable — and is left alone.
        if Path::new(&name).extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let slot = super::durable_fs::read_slot_strict(&vault, &name).map_err(|error| {
            refusal_before_any_unlink(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_credential_slot_unreadable",
                format!("the sealed-credential slot '{name}' is occupied but not readable as a regular file ({error}) — a symlink, a directory, or an unreadable occupant cannot be proven to be some OTHER backend's credential, so this deletion refuses rather than treating it as absent. No credential was removed and the backend account remains. Repair the slot and delete again."),
            )
        })?;
        // Only ENOENT reaches here as `None`: the name went away between enumeration and the read,
        // which is absence, and an absent slot holds no bearer.
        let Some((_pinned, bytes)) = slot else {
            continue;
        };
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            refusal_before_any_unlink(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_credential_slot_malformed",
                format!("the sealed-credential slot '{name}' is not valid JSON ({error}) — it cannot be proven to belong to another backend, so this deletion refuses rather than skipping it. No credential was removed and the backend account remains. Repair or remove the slot and delete again."),
            )
        })?;
        match record.get("connector_id").and_then(Value::as_str) {
            Some(bound) if bound == account_id => targets.push(name),
            Some(_) => {}
            None => {
                return Err(refusal_before_any_unlink(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage_backend_credential_slot_unclassifiable",
                    format!("the sealed-credential slot '{name}' names no connector_id, so it cannot be shown to belong to a DIFFERENT backend — refusing rather than guessing which credentials this deletion is allowed to leave live. No credential was removed and the backend account remains. Repair or remove the slot and delete again."),
                ))
            }
        }
    }

    // NOT ATOMIC, and the refusals must not pretend otherwise: this loop unlinks and fsyncs one
    // slot at a time, so a failure at slot N leaves slots 1..N-1 destroyed. The tally is threaded
    // into every refusal, and `RemovedDurable` is counted apart from `AlreadyAbsent` so the causal
    // count never absorbs slots this request did not touch.
    let mut tally = PurgeTally::default();
    for name in &targets {
        let disposition = classify_unlink(super::durable_fs::unlink_durable_at(
            &vault,
            name,
            CREDENTIAL_VAULT,
        ));
        if let Some(refusal) = credential_slot_refusal(&disposition, name, tally) {
            return Err(refusal);
        }
        match disposition {
            SlotUnlink::RemovedDurable => tally.revoked += 1,
            SlotUnlink::AlreadyAbsent => tally.already_absent += 1,
            SlotUnlink::DurabilityUnconfirmed(_) | SlotUnlink::NotPerformed(_) => unreachable!(
                "credential_slot_refusal returns Some for every disposition except absence"
            ),
        }
    }
    // Reloaded through the production reader, never from the unlink outcomes: a credential the
    // bearer path can still resolve is live, whatever the syscalls reported. This is REACHABLE,
    // not defensive — `durable_fs::enumerate_pinned` silently drops directory entries whose names
    // are not valid UTF-8, while `read_record_dir` reads them by OsString, so such a slot is
    // invisible to the purge above and fully live to the bearer path below.
    if account_credential_resolves(data_dir, account_id) {
        return Err(with_purge_posture(
            deletion_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_backend_credential_revocation_unconfirmed",
                format!("every sealed-credential slot this purge could enumerate for '{account_id}' is now absent, but the live bearer path STILL resolves one — the revocation is not acknowledged and the backend account was NOT deleted. {consequence}. Delete again to retry; if it keeps refusing, the surviving credential is not reachable by this walk (for example its filename is not valid UTF-8) and must be removed out of band.", consequence = purge_consequence(tally, 0, false)),
            ),
            tally,
            0,
            false,
        ));
    }
    Ok(tally)
}

/// Delete a storage-backend account and every sealed credential bound to it, acknowledging ONLY
/// from reloaded absence. Daemon-state-free so every lane is directly testable; the Axum handler
/// below is the adapter.
///
/// The shipped handler discarded both `std::fs::remove_file` results and returned `ok:true`
/// unconditionally. Two consequences, in ascending severity. The account record could survive its
/// own deletion while the caller was told it was gone. Worse, the ACCOUNT was removed first and the
/// credential second, and the credential removal could fail silently: the sealed bearer then stayed
/// on disk, bound by `connector_id` to an account no listing shows — `handle_storage_backends_list`
/// enumerates accounts, and every credential affordance this plane has is keyed on a loadable
/// account — so the surviving credential was permanently unreachable through the API. That is a
/// credential leak reported as a successful destruction.
///
/// ORDER IS LOAD-BEARING and is asserted in both directions: credentials first, then the account.
/// Its guarantee is bounded by what the vault walk observed; see the nonclaim at the top of this
/// section for the unlocked concurrent-bind window it does not close.
///
/// This function uses `durable_fs::unlink_durable_at` rather than `remove_file` because "the name
/// is gone from the live namespace" and "the removal is on disk" are different facts and a
/// destruction acknowledgement may only be made on the second.
pub(crate) fn delete_storage_backend_account(
    data_dir: &str,
    id_or_ref: &str,
) -> (StatusCode, Value) {
    let Some(account) = load_account(data_dir, id_or_ref) else {
        // PRESERVED VERBATIM. This packet changes the destruction contract, not the not-found
        // contract; the return type had to name a status, and naming OK keeps the shipped wire
        // response byte-for-byte rather than silently broadening it to 404.
        return (
            StatusCode::OK,
            json!({ "ok": false, "reason": "no such storage backend" }),
        );
    };
    let account_id = text(&account, "account_id").to_string();
    if account_id.is_empty() {
        return refusal_before_any_unlink(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_backend_account_unidentified",
            format!("the record matched by '{id_or_ref}' carries no account_id, so neither its own record slot nor the credentials bound to it can be named — refusing rather than deleting a guessed target. Nothing was deleted."),
        );
    }
    // A PROMOTED family is substrate-owned truth: `persist_record`/`read_record_dir` route it into
    // the Agentgres engine and write NO legacy JSON file, so unlinking daemon files would delete
    // nothing while reporting a destruction. Fail closed instead of pretending.
    for family in [CREDENTIAL_VAULT, ACCOUNT_KIND] {
        if super::substrate_store::is_promoted(family) {
            return refusal_before_any_unlink(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_backend_deletion_substrate_owned",
                format!("record family '{family}' is promoted to the Agentgres substrate, whose truth this raw daemon-file deletion cannot remove — deleting the legacy files would report a destruction that did not happen. Nothing was deleted. This route needs a substrate-admitted deletion before it can serve promoted families."),
            );
        }
    }

    // ── EFFECT 1: the live bearer ───────────────────────────────────────────────────────────
    let tally = match revoke_account_credentials(data_dir, &account_id) {
        Ok(tally) => tally,
        Err(refusal) => return refusal,
    };

    // ── EFFECT 2: the account record ────────────────────────────────────────────────────────
    // The SAME filename normalization the writer applies: `persist_record` maps every byte outside
    // [A-Za-z0-9_-] to `_` before joining `.json`, so this names exactly the file the account was
    // written to. A record that is loadable but does NOT live at that name is not deleted here —
    // it is caught by the reloaded-absence gate below and refused, never acknowledged.
    let target = format!("{}.json", safe(&account_id));
    let mut account_slot = "already_absent";
    match open_record_family(data_dir, ACCOUNT_KIND) {
        Ok(accounts) => {
            let disposition = classify_unlink(super::durable_fs::unlink_durable_at(
                &accounts,
                &target,
                ACCOUNT_KIND,
            ));
            if let Some(refusal) = account_deletion_refusal(&disposition, tally) {
                return refusal;
            }
            if disposition == SlotUnlink::RemovedDurable {
                account_slot = "removed_durable";
            }
        }
        // ONLY ENOENT is absence: no family directory means no record slot to unlink. The gate
        // below still has to prove the account no longer resolves before anything is acknowledged.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return with_purge_posture(
                deletion_refusal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage_backend_account_family_unpinnable",
                    format!("{consequence}. The account record family could not be opened as a directory ({error}), so the account record was not removed and the backend still exists. Delete again to retry.", consequence = purge_consequence(tally, 0, true)),
                ),
                tally,
                0,
                true,
            )
        }
    }

    // ── Acknowledge from the RELOADED absence, never from the unlink outcomes ───────────────
    // Both the canonical account id and the ref the caller presented are re-resolved through
    // `load_account`, the same production reader every other route on this plane uses.
    if load_account(data_dir, &account_id).is_some() || load_account(data_dir, id_or_ref).is_some()
    {
        return with_purge_posture(
            deletion_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_backend_deletion_unconfirmed",
                format!("both removals reported done, but '{account_id}' STILL resolves as a storage backend — the deletion is not acknowledged. This happens when the record does not live at the filename the writer would give it. {consequence}. Delete again to retry, or repair the record's slot out of band.", consequence = purge_consequence(tally, 0, true)),
            ),
            tally,
            0,
            true,
        );
    }
    with_purge_posture(
        (
            StatusCode::OK,
            json!({
                "ok": true,
                "deleted": account_id,
                "account_slot": account_slot,
                "note": "archive objects/incidents/receipts remain as evidence — deleting a backend never deletes daemon truth",
            }),
        ),
        tally,
        0,
        true,
    )
}

/// DELETE /v1/hypervisor/storage-backends/{id}.
pub(crate) async fn handle_storage_backend_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = delete_storage_backend_account(&st.data_dir, &id);
    (status, Json(payload))
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
    // W1.2 / MEF-GAP-008 — ORDER IS LOAD-BEARING: the sealed bearer (the live bearer-resolution
    // path) is the durable secret; write it FIRST and refuse if it does not land, so the response
    // never claims a binding over a vault that holds nothing.
    if persist_record(&st.data_dir, CREDENTIAL_VAULT, &account_id, &cred).is_err() {
        return storage_persist_failed(
            "storage_credential_persistence_failed",
            "the sealed bearer credential did not commit — no credential was bound".into(),
        );
    }
    account["credential_binding_ref"] = json!(format!("storage-credential://{account_id}"));
    account["updated_at"] = json!(iso_now());
    // The credential IS durably bound above; a lost account-pointer write is a SAFE split because
    // `live_config` resolves the credential by connector_id, not through this pointer — but the
    // response must not claim the binding landed on the account. Refuse honestly and name the split.
    if persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account).is_err() {
        return storage_persist_failed(
            "storage_backend_account_persistence_failed",
            "the sealed credential committed to the vault (and is already resolvable by connector_id for live ops), but the account's credential_binding_ref pointer did not commit — retry the bind to record the pointer".into(),
        );
    }
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
            // W1.2 / MEF-GAP-008 — the probe verified the backend; a lost write leaves the account
            // reading `unverified` with export still gated. Refuse rather than report a status the
            // durable record does not carry.
            if persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account).is_err() {
                return storage_persist_failed(
                    "storage_backend_account_persistence_failed",
                    "the backend preflight verified but the verified status did not commit — the account still reads unverified; retry preflight".into(),
                );
            }
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
            // W1.2 / MEF-GAP-008 — the probe failed; a lost write drops the recorded unverified
            // evidence. Refuse so the account's durable posture matches the response.
            if persist_record(&st.data_dir, ACCOUNT_KIND, &account_id, &account).is_err() {
                return storage_persist_failed(
                    "storage_backend_account_persistence_failed",
                    "the backend preflight failed and the unverified status did not commit — retry preflight".into(),
                );
            }
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
    // W1.2 / MEF-GAP-008 — store_bytes ALREADY committed the sealed archive bytes to the backend
    // (possibly live IPFS): those bytes cannot be unwritten. A lost archive record orphans them —
    // no listable archive, no verify/restore lane. Name the stored commitment + receipt rather than
    // implying nothing happened; the content-addressed store makes a retried export idempotent.
    if persist_record(data_dir, ARCHIVE_KIND, &id, &record).is_err() {
        return storage_persist_failed(
            "storage_archive_persistence_failed",
            format!(
                "the sealed archive bytes were already stored at {stored} (receipt {rcpt}), but the archive object record did not commit — those bytes are orphaned evidence, not a listable archive; retry export to re-record (the store is content-addressed, so no bytes are duplicated)",
                stored = text(&commitment, "address"),
                rcpt = receipt.as_deref().unwrap_or("<receipt-not-persisted>"),
            ),
        );
    }
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
            // W1.2 / MEF-GAP-008 — refuse if the availability incident did not commit: without it
            // the impaired archive would still list `available` and repair could never find it.
            let Some(incident_ref) = open_incident(
                data_dir,
                &account,
                &archive,
                &incident_kind,
                detail.clone(),
                json!({ "op": "verify", "error": detail }),
            ) else {
                return storage_persist_failed(
                    "storage_incident_persistence_failed",
                    format!("verify of {archive_ref} could not fetch the bytes ({detail}) and the availability incident did not commit — nothing quarantined this archive; retry verify"),
                );
            };
            archive["status"] = json!("impaired");
            archive["last_verify"] =
                json!({ "ok": false, "incident_ref": incident_ref, "at": iso_now() });
            // The incident committed; if the impaired MARK does not, degrade to a typed refusal that
            // NAMES the incident that DID commit rather than reporting a status the record lacks.
            if persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive).is_err() {
                return storage_persist_failed(
                    "storage_archive_persistence_failed",
                    format!("availability incident {incident_ref} committed for {archive_ref}, but the archive could not be marked impaired — the incident is the durable quarantine truth (repair targets it); retry verify to re-mark"),
                );
            }
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
                // W1.2 / MEF-GAP-008 — same lane: a lost hash-mismatch incident leaves a corrupt
                // archive listing `available`. Refuse if it did not commit.
                let Some(incident_ref) = open_incident(
                    data_dir,
                    &account,
                    &archive,
                    "hash_mismatch",
                    detail.clone(),
                    json!({ "op": "verify", "actual": actual, "expected": expected }),
                ) else {
                    return storage_persist_failed(
                        "storage_incident_persistence_failed",
                        format!("verify of {archive_ref} detected a commitment hash mismatch but the incident did not commit — nothing quarantined the corrupt replica; retry verify"),
                    );
                };
                archive["status"] = json!("impaired");
                archive["last_verify"] =
                    json!({ "ok": false, "incident_ref": incident_ref, "at": iso_now() });
                // The incident committed; if the impaired MARK does not, refuse naming the incident.
                if persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive).is_err() {
                    return storage_persist_failed(
                        "storage_archive_persistence_failed",
                        format!("hash-mismatch incident {incident_ref} committed for {archive_ref}, but the archive could not be marked impaired — the incident is the durable quarantine truth; retry verify to re-mark"),
                    );
                }
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
                // W1.2 / MEF-GAP-008 — verify succeeded and may clear an impaired mark; a lost write
                // would report `ok` while the archive keeps its stale status. Refuse.
                if persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive).is_err() {
                    return storage_persist_failed(
                        "storage_archive_persistence_failed",
                        format!("verify of {archive_ref} succeeded but the verified status did not commit — the archive keeps its prior status; retry verify"),
                    );
                }
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
        let mut impaired_recorded = false;
        // W1.2 / MEF-GAP-008 — flatten to a real incident_ref: `and_then` yields None (not a phantom
        // ref) when the incident did not commit, and the impaired MARK is MEASURED, not asserted —
        // the committed incident is the durable quarantine that open_incidents_for gates repair on.
        let incident_ref = incident.and_then(|(ikind, detail)| {
            let r = open_incident(
                data_dir,
                &account,
                &archive,
                ikind,
                detail,
                json!({ "op": "restore", "error": reason }),
            );
            if r.is_some() {
                let archive_id = text(&archive, "archive_id").to_string();
                archive["status"] = json!("impaired");
                impaired_recorded =
                    persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive).is_ok();
            }
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
                json!({ "ok": false, "op": "restore", "reason": reason, "incident_ref": incident_ref, "receipt_ref": receipt, "archive_impaired_recorded": impaired_recorded }),
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
        // W1.2 / MEF-GAP-008 — the repair-failed receipt is the durable evidence of the attempt; if
        // even it does not commit, refuse rather than return a CONFLICT that leaves no trace.
        if persist_record(data_dir, REPAIR_KIND, &repair_id, &record).is_err() {
            return storage_persist_failed(
                "storage_repair_receipt_persistence_failed",
                format!("repair of {archive_ref} failed ({reason}) and the repair-failed receipt {repair_ref} could not be recorded — no durable evidence of the attempt exists; retry"),
            );
        }
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
    // W1.2 / MEF-GAP-008 — store_bytes already committed the replacement bytes; if the commitment
    // swap does not land, the archive still points at the impaired commitment while the new bytes
    // sit orphaned. Refuse BEFORE closing incidents or minting the receipt, naming the orphan.
    if persist_record(data_dir, ARCHIVE_KIND, &archive_id, &archive).is_err() {
        return storage_persist_failed(
            "storage_archive_persistence_failed",
            format!(
                "repair of {archive_ref} sealed and stored replacement bytes at {stored}, but the archive's commitment swap did not commit — the archive still points at the old (impaired) commitment while the new bytes are orphaned; incidents were left open and no repair receipt was minted; retry repair (the store is content-addressed)",
                stored = text(&new_commitment, "address"),
            ),
        );
    }
    let mut closed: Vec<Value> = Vec::new();
    let mut close_failed: Vec<Value> = Vec::new();
    for mut incident in incidents {
        let iid = text(&incident, "incident_id").to_string();
        incident["status"] = json!("repaired");
        incident["repair_ref"] = json!(repair_ref);
        incident["closed_at"] = json!(iso_now());
        // W1.2 / MEF-GAP-008 — per-row checked: only claim an incident closed if its close
        // committed; a lost close leaves it open (it would re-impair the archive on next verify).
        if persist_record(data_dir, INCIDENT_KIND, &iid, &incident).is_ok() {
            closed.push(incident["incident_ref"].clone());
        } else {
            close_failed.push(incident["incident_ref"].clone());
        }
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
    // W1.2 / MEF-GAP-008 — the archive IS repaired (bytes swapped, incidents closed above); if the
    // repair receipt does not commit, the repair happened without its durable receipt. Refuse so no
    // success response cites a repair_ref that resolves to nothing.
    if persist_record(data_dir, REPAIR_KIND, &repair_id, &record).is_err() {
        return storage_persist_failed(
            "storage_repair_receipt_persistence_failed",
            format!(
                "the archive {archive_ref} was repaired (commitment swapped to {stored}, {n} incident(s) closed) but the repair receipt {repair_ref} did not commit — retry to record it",
                stored = text(&new_commitment, "address"),
                n = closed.len(),
            ),
        );
    }
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
            json!({ "ok": true, "op": "repair", "outcome": "repaired", "repair_ref": repair_ref, "repair": record, "receipt_ref": receipt, "incidents_close_failed": close_failed }),
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

/// M2 storage contract proofs over THIS plane's real helpers: the registered
/// storage-archive-object and storage-artifact-availability-incident contracts are pinned to
/// what `store_bytes`/`fetch_bytes`/`open_incident`/`storage_receipt` actually produce, and the
/// receipted-close discipline (`op_repair`) is structurally unrepresentable to fake.
#[cfg(test)]
mod m2_contract_tests {
    use super::*;
    use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

    const ARCHIVE_CONTRACT: &str = "schema://ioi/components/hypervisor/storage-archive-object/v1";
    const INCIDENT_CONTRACT: &str =
        "schema://ioi/components/hypervisor/storage-artifact-availability-incident/v1";
    const REPAIR_CONTRACT: &str = "schema://ioi/components/hypervisor/artifact-repair-receipt/v1";

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-m2-storage-{label}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn local_account(id: &str) -> Value {
        json!({
            "schema_version": "ioi.hypervisor.storage-backend-account.v1",
            "account_id": id,
            "account_ref": format!("storage-backend://{id}"),
            "display_name": "local_disk backend",
            "kind": "local_disk",
            "status": "verified",
            "endpoint": {},
        })
    }

    /// Export-shaped archive record over the REAL commitment `store_bytes` returned and a REAL
    /// minted storage receipt (the op_export literal shape; the export handler itself needs the
    /// daemon state + wallet lease, so the surrounding literals are pinned here).
    fn export_shaped_archive(
        account: &Value,
        state_root: &str,
        payload_bytes: usize,
        commitment: &Value,
        receipt_ref: &str,
    ) -> Value {
        let id = format!("sao_{:x}", nanos());
        json!({
            "schema_version": "ioi.hypervisor.storage-archive-object.v1",
            "archive_id": id, "archive_ref": format!("storage-archive://{id}"),
            "backend_ref": text(account, "account_ref"), "backend_kind": text(account, "kind"),
            "material_ref": "provider-material://pm_env-alpha-workspace",
            "environment_ref": "environment://local/env-alpha",
            "provider_account_ref": "provider-account://pacc_3f2e1d0c",
            "state_root": state_root,
            "media_type": "application/x-tar+gzip",
            "payload_bytes": payload_bytes,
            "commitment": commitment,
            "encryption": { "scheme": "sealed_wallet_secret (Argon2id KDF + AEAD)", "key_source": scm_key_source(), "plaintext_at_backend": false },
            "status": "available",
            "availability_note": "storage availability is NOT restore truth — restore admits only after fetch + commitment hash + decrypt + admitted state_root all verify",
            "authority": "none — no CID, deal, pin, or backend id ever becomes authority or restore validity",
            "grant_ref": "grant://wallet.network/storage-archive/export/test",
            "receipt_refs": [receipt_ref],
            "exported_at": iso_now(),
        })
    }

    /// Dimension silent corruption/loss + unverified restore: the REAL sealed store round-trip
    /// produces a verified commitment; the export-shaped archive record over it validates the
    /// registered contract.
    #[test]
    fn sealed_store_commitment_and_archive_record_validate_registered_contract() {
        let data = temp_dir("archive");
        let data_dir = data.to_str().expect("utf8");
        let account = local_account("sba_m2test01");
        let plaintext = b"m2 storage cut custody bytes".to_vec();
        let state_root = sha256_bytes(&plaintext);
        let sealed = seal_archive_bytes(&plaintext).expect("seal");
        let commitment = store_bytes(data_dir, &account, &sealed).expect("real local store");

        // The commitment is REAL evidence: read-back verified, content-addressed, hash-bound.
        assert_eq!(commitment["read_back_verified"], json!(true));
        assert_eq!(commitment["stored_sha256"], json!(sha256_bytes(&sealed)));
        assert!(text(&commitment, "address").starts_with("cas://sha256/"));

        // The sealed round-trip restores the exact custody bytes (decrypt + state-root check).
        let fetched = fetch_bytes(data_dir, &account, &commitment).expect("fetch");
        let opened = open_archive_bytes(&fetched).expect("sealed bytes decrypt");
        assert_eq!(sha256_bytes(&opened), state_root);

        let receipt_ref = storage_receipt(
            data_dir,
            "local_disk",
            "export",
            "ok",
            &json!({ "backend_ref": account["account_ref"] }),
        )
        .expect("test receipt persists to the temp dir");
        let archive = export_shaped_archive(
            &account,
            &state_root,
            plaintext.len(),
            &commitment,
            &receipt_ref,
        );
        validate_architecture_contract(ARCHIVE_CONTRACT, &archive)
            .expect("export-shaped archive over the real commitment validates");
    }

    /// Dimension silent corruption/loss: corrupted or missing custody bytes surface as NAMED
    /// availability incidents from the real helpers — never as a healthy read.
    #[test]
    fn corruption_and_loss_surface_as_named_incidents_never_silent_success() {
        let data = temp_dir("incident");
        let data_dir = data.to_str().expect("utf8");
        let account = local_account("sba_m2test02");
        let sealed = seal_archive_bytes(b"corruptible bytes").expect("seal");
        let commitment = store_bytes(data_dir, &account, &sealed).expect("store");
        let receipt_ref = storage_receipt(
            data_dir,
            "local_disk",
            "export",
            "ok",
            &json!({ "backend_ref": account["account_ref"] }),
        )
        .expect("test receipt persists to the temp dir");
        let archive = export_shaped_archive(
            &account,
            &sha256_bytes(b"corruptible bytes"),
            17,
            &commitment,
            &receipt_ref,
        );

        // Corrupt the stored object: a fetchable-but-wrong object is stale/corrupt.
        std::fs::write(text(&commitment, "path"), b"substituted bytes").expect("corrupt");
        let fetched = fetch_bytes(data_dir, &account, &commitment).expect("still fetchable");
        let actual = sha256_bytes(&fetched);
        let expected = text(&commitment, "stored_sha256");
        assert_ne!(actual, expected, "corruption is detectable, not silent");
        let incident_ref = open_incident(
            data_dir,
            &account,
            &archive,
            "hash_mismatch",
            format!("stored bytes hash {actual} but the admitted commitment is {expected}"),
            json!({ "op": "verify", "actual": actual, "expected": expected }),
        )
        .expect("test incident persists to the temp dir");
        let incident = read_record_dir(data_dir, INCIDENT_KIND)
            .into_iter()
            .find(|record| text(record, "incident_ref") == incident_ref)
            .expect("incident persisted");
        assert_eq!(incident["status"], json!("open"));
        validate_architecture_contract(INCIDENT_CONTRACT, &incident)
            .expect("real open incident validates the registered contract");

        // Repeat detection ACCRETES onto the same open incident — evidence, not rows.
        let second_ref = open_incident(
            data_dir,
            &account,
            &archive,
            "hash_mismatch",
            "re-detected".to_string(),
            json!({ "op": "restore" }),
        )
        .expect("test incident accretion persists to the temp dir");
        assert_eq!(
            second_ref, incident_ref,
            "one open incident per (archive, kind)"
        );
        let accreted = read_record_dir(data_dir, INCIDENT_KIND)
            .into_iter()
            .find(|record| text(record, "incident_ref") == incident_ref)
            .expect("incident persisted");
        assert_eq!(accreted["detections"], json!(2));
        validate_architecture_contract(INCIDENT_CONTRACT, &accreted)
            .expect("accreted incident still validates");

        // Loss: missing bytes surface as the NAMED missing_bytes kind from the real helper.
        std::fs::remove_file(text(&commitment, "path")).expect("lose bytes");
        let (kind, _detail) = fetch_bytes(data_dir, &account, &commitment)
            .expect_err("missing bytes are an error, never an empty success");
        assert_eq!(kind, "missing_bytes");
        let loss_ref = open_incident(
            data_dir,
            &account,
            &archive,
            &kind,
            "backend object unreadable at its recorded address".to_string(),
            json!({ "op": "verify" }),
        )
        .expect("test loss incident persists to the temp dir");
        assert_ne!(
            loss_ref, incident_ref,
            "a distinct failure kind opens its own incident"
        );
        let loss = read_record_dir(data_dir, INCIDENT_KIND)
            .into_iter()
            .find(|record| text(record, "incident_ref") == loss_ref)
            .expect("loss incident persisted");
        validate_architecture_contract(INCIDENT_CONTRACT, &loss).expect("loss incident validates");
    }

    /// Dimension unverified restore: an incident leaves `open` only through a named repair
    /// receipt (the op_repair close discipline); a repaired incident without its repair_ref and
    /// an unverified repaired receipt are both unrepresentable under the registered contracts.
    #[test]
    fn unreceipted_or_unverified_close_is_unrepresentable() {
        let data = temp_dir("close");
        let data_dir = data.to_str().expect("utf8");
        let account = local_account("sba_m2test03");
        let sealed = seal_archive_bytes(b"close discipline").expect("seal");
        let commitment = store_bytes(data_dir, &account, &sealed).expect("store");
        let receipt_ref = storage_receipt(
            data_dir,
            "local_disk",
            "export",
            "ok",
            &json!({ "backend_ref": account["account_ref"] }),
        )
        .expect("test receipt persists to the temp dir");
        let archive = export_shaped_archive(
            &account,
            &sha256_bytes(b"close discipline"),
            16,
            &commitment,
            &receipt_ref,
        );
        let incident_ref = open_incident(
            data_dir,
            &account,
            &archive,
            "decrypt_failure",
            "sealed archive bytes did not decrypt".to_string(),
            json!({ "op": "restore" }),
        )
        .expect("test incident persists to the temp dir");
        let mut incident = read_record_dir(data_dir, INCIDENT_KIND)
            .into_iter()
            .find(|record| text(record, "incident_ref") == incident_ref)
            .expect("incident persisted");

        // Silent close: repaired without the repair receipt ref refuses.
        incident["status"] = json!("repaired");
        incident["closed_at"] = json!(iso_now());
        validate_architecture_contract(INCIDENT_CONTRACT, &incident)
            .expect_err("a repaired incident without its repair receipt is unrepresentable");

        // The op_repair close shape (repair_ref + closed_at) validates.
        incident["repair_ref"] = json!("artifact-repair-receipt://arr_1b2c3d4e5f60718");
        validate_architecture_contract(INCIDENT_CONTRACT, &incident)
            .expect("the receipted close validates");

        // The registered repair-receipt contract refuses an unverified repaired claim.
        let unverified = json!({
            "schema_version": "ioi.hypervisor.artifact-repair-receipt.v1",
            "repair_id": "arr_1b2c3d4e5f60718",
            "repair_ref": "artifact-repair-receipt://arr_1b2c3d4e5f60718",
            "archive_ref": text(&archive, "archive_ref"),
            "material_ref": "provider-material://pm_env-alpha-workspace",
            "backend_ref": text(&account, "account_ref"),
            "source": "daemon_custody",
            "outcome": "repaired",
            "incident_refs": [incident_ref],
            "at": iso_now(),
        });
        validate_architecture_contract(REPAIR_CONTRACT, &unverified)
            .expect_err("repaired without commitment/state-root/verification is unrepresentable");
    }
}

/// The destruction contract for `DELETE /v1/hypervisor/storage-backends/{id}`.
///
/// Every fault below is DETERMINISTIC, UID-INDEPENDENT and PROCESS-LOCAL. chmod is deliberately NOT
/// used: root bypasses mode-bit denial, so a permission-based fault would pass vacuously whenever
/// the suite runs as root. No env var and no cwd change is used either, which also rules out
/// `durable_fs`'s process-global `IOI_TEST_FORCE_UNLINK_DIRSYNC_UNCONFIRMED` seam — nothing here can
/// race the rest of the suite. Every fault is a PATH SHADOW or a constructed variant, and every
/// postcondition is judged through the production readers rather than through the response.
///
/// `storage-backend-accounts` and `storage-credentials` are in neither `PROMOTED_DOMAINS` nor
/// `REQUIRED_ADMISSION_DOMAINS`, so both take the daemon-file path; a promoted family would route
/// through the substrate engine and its failure points would differ (see the promotion guard).
#[cfg(test)]
mod storage_backend_deletion_tests {
    use super::*;

    const ALPHA: &str = "sba_alpha";
    const BETA: &str = "sba_beta";
    const ALPHA_TOKEN: &str = "ipfs_live_bearer_for_alpha";
    const BETA_TOKEN: &str = "ipfs_live_bearer_for_beta";
    const SHIPPED_NOTE: &str = "archive objects/incidents/receipts remain as evidence — deleting a backend never deletes daemon truth";

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    /// A live-mode account, so `live_config` — the real bearer-resolution path — applies.
    fn live_account(id: &str) -> Value {
        json!({
            "schema_version": "ioi.hypervisor.storage-backend-account.v1",
            "account_id": id,
            "account_ref": format!("storage-backend://{id}"),
            "display_name": "ipfs backend",
            "kind": "ipfs",
            "status": "verified",
            "endpoint": { "mode": "live", "endpoint": "https://gateway.invalid/" },
            "capabilities": kind_capabilities("ipfs"),
            "created_at": iso_now(), "updated_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        })
    }

    /// Seed through the PRODUCTION writer, under the record id the writer would be handed.
    fn seed_account(data_dir: &str, record_id: &str, account: &Value) {
        persist_record(data_dir, ACCOUNT_KIND, record_id, account).expect("account seeded");
    }

    /// Byte-for-byte the record `handle_storage_backend_credential` persists, sealed with the same
    /// wallet-secret discipline, through the same writer.
    fn seed_credential(data_dir: &str, record_id: &str, account_id: &str, token: &str) {
        let sealed = seal_scm_token(token).expect("token seals");
        let credential = json!({
            "schema_version": "ioi.hypervisor.storage-credential.v1",
            "connector_id": account_id, "scheme": "bearer",
            "sealed_token": sealed, "key_source": scm_key_source(),
            "bound_at": iso_now(),
        });
        persist_record(data_dir, CREDENTIAL_VAULT, record_id, &credential)
            .expect("credential seeded");
    }

    /// THE LIVE BEARER PATH ITSELF. `live_config` is what `store_bytes`, `fetch_bytes` and
    /// `handle_storage_backend_preflight` call to turn a sealed vault record into an Authorization
    /// header. A credential is revoked when, and only when, this stops yielding a token.
    fn live_bearer(data_dir: &str, account: &Value) -> Option<String> {
        live_config(data_dir, account)
            .expect("endpoint configured")
            .1
    }

    /// Byte-exact contents of the evidence families a backend deletion must never touch.
    fn evidence_snapshot(root: &Path) -> Vec<(String, String, Vec<u8>)> {
        let mut out = Vec::new();
        for family in [ARCHIVE_KIND, INCIDENT_KIND, REPAIR_KIND, RECEIPT_KIND] {
            let Ok(entries) = std::fs::read_dir(root.join(family)) else {
                continue;
            };
            for entry in entries.flatten() {
                out.push((
                    family.to_string(),
                    entry.file_name().to_string_lossy().to_string(),
                    std::fs::read(entry.path()).unwrap_or_default(),
                ));
            }
        }
        out.sort();
        out
    }

    fn seed_evidence(data_dir: &str, account_ref: &Value) {
        persist_record(
            data_dir,
            ARCHIVE_KIND,
            "sao_keep",
            &json!({
                "archive_id": "sao_keep", "archive_ref": "storage-archive://sao_keep",
                "backend_ref": account_ref, "state_root": "sha256:deadbeef",
            }),
        )
        .expect("archive seeded");
        persist_record(data_dir, INCIDENT_KIND, "aai_keep", &json!({
            "incident_id": "aai_keep", "incident_ref": "artifact-availability-incident://aai_keep",
            "backend_ref": account_ref, "status": "open",
        }))
        .expect("incident seeded");
        persist_record(
            data_dir,
            RECEIPT_KIND,
            "stc_keep",
            &json!({
                "receipt_id": "stc_keep", "receipt_ref": "agentgres://storage-receipt/stc_keep",
                "backend": "ipfs", "op": "export", "outcome": "ok",
            }),
        )
        .expect("receipt seeded");
    }

    // ── The preserved wire response ─────────────────────────────────────────────────────────

    #[test]
    fn an_absent_backend_preserves_the_shipped_wire_response() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");

        let (status, body) = delete_storage_backend_account(data_dir, "sba_never_existed");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "ok": false, "reason": "no such storage backend" })
        );
    }

    // ── Success lanes ───────────────────────────────────────────────────────────────────────

    #[test]
    fn a_clean_delete_is_acknowledged_only_after_reloaded_absence() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        seed_evidence(data_dir, &account["account_ref"]);
        let evidence_before = evidence_snapshot(directory.path());
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["deleted"], json!(ALPHA));
        assert_eq!(body["note"], json!(SHIPPED_NOTE));
        // S4: SUCCESS carries the same posture every refusal does, so a caller never has to infer
        // what happened from the status code alone.
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(body["credentials_already_absent"], json!(0));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        assert_eq!(body["account_slot"], json!("removed_durable"));
        // The acknowledgement is judged from the RELOADED readers, not from the response.
        assert!(load_account(data_dir, ALPHA).is_none());
        assert!(load_account(data_dir, "storage-backend://sba_alpha").is_none());
        assert!(!account_credential_resolves(data_dir, ALPHA));
        // The strongest form of "revoked": the live bearer path yields nothing.
        assert!(live_bearer(data_dir, &account).is_none());
        assert_eq!(
            evidence_snapshot(directory.path()),
            evidence_before,
            "deleting a backend must leave archive/incident/repair/receipt evidence byte-identical"
        );
    }

    #[test]
    fn a_backend_with_no_credential_bound_succeeds_reporting_zero() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_account(data_dir, ALPHA, &live_account(ALPHA));
        // No vault family exists at all — absence is already revoked.
        assert!(!directory.path().join(CREDENTIAL_VAULT).exists());

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(0));
        assert_eq!(body["credentials_already_absent"], json!(0));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        assert_eq!(body["account_slot"], json!("removed_durable"));
        assert!(load_account(data_dir, ALPHA).is_none());
    }

    #[test]
    fn a_vault_holding_only_other_backends_credentials_reports_zero_and_touches_nothing() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let beta = live_account(BETA);
        seed_account(data_dir, ALPHA, &live_account(ALPHA));
        seed_account(data_dir, BETA, &beta);
        seed_credential(data_dir, BETA, BETA, BETA_TOKEN);

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["credentials_revoked"], json!(0));
        assert_eq!(live_bearer(data_dir, &beta).as_deref(), Some(BETA_TOKEN));
    }

    #[test]
    fn a_sibling_backends_credential_survives_the_deletion() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let alpha = live_account(ALPHA);
        let beta = live_account(BETA);
        seed_account(data_dir, ALPHA, &alpha);
        seed_account(data_dir, BETA, &beta);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        seed_credential(data_dir, BETA, BETA, BETA_TOKEN);

        let (status, body) =
            delete_storage_backend_account(data_dir, "storage-backend://sba_alpha");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["deleted"], json!(ALPHA));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert!(live_bearer(data_dir, &alpha).is_none());
        // The refusal to over-delete is the point: beta keeps its account AND its live bearer.
        assert!(load_account(data_dir, BETA).is_some());
        assert_eq!(live_bearer(data_dir, &beta).as_deref(), Some(BETA_TOKEN));
    }

    /// The vault walk selects records exactly as `read_record_dir` — and therefore `live_config` —
    /// does: only an entry whose extension is `json` can ever resolve as a bearer, so an entry that
    /// reader can never reach is left alone rather than destroyed on suspicion.
    #[test]
    fn a_non_json_vault_entry_is_neither_deleted_nor_treated_as_unclassifiable() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_account(data_dir, ALPHA, &live_account(ALPHA));
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        let stray = directory.path().join(CREDENTIAL_VAULT).join("notes.txt");
        std::fs::write(&stray, b"operator scratch, not a record").expect("stray written");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(
            std::fs::read(&stray).expect("stray survives"),
            b"operator scratch, not a record"
        );
    }

    /// Reader, writer, and this deletion must agree on ONE filename for an id that normalizes.
    #[test]
    fn an_unsafe_looking_id_proves_reader_writer_and_delete_normalization_agree() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let unsafe_id = "sba_../../etc/passwd";
        let mut account = live_account(unsafe_id);
        account["account_ref"] = json!(format!("storage-backend://{unsafe_id}"));
        // The production writer chooses the filename; nothing here hand-picks it.
        seed_account(data_dir, unsafe_id, &account);
        seed_credential(data_dir, unsafe_id, unsafe_id, ALPHA_TOKEN);
        let written = directory
            .path()
            .join(ACCOUNT_KIND)
            .join(format!("{}.json", safe(unsafe_id)));
        assert!(written.exists(), "the writer normalized to {written:?}");
        // Canaries a traversing delete would reach if normalization disagreed anywhere.
        std::fs::write(directory.path().join("passwd"), b"canary").expect("canary written");
        seed_account(data_dir, BETA, &live_account(BETA));
        // The reader resolves the record by FIELD, from that same normalized file.
        assert!(load_account(data_dir, unsafe_id).is_some());

        let (status, body) = delete_storage_backend_account(data_dir, unsafe_id);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["deleted"], json!(unsafe_id));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert!(!written.exists(), "the delete removed the writer's file");
        assert!(load_account(data_dir, unsafe_id).is_none());
        assert!(!account_credential_resolves(data_dir, unsafe_id));
        assert_eq!(
            std::fs::read(directory.path().join("passwd")).expect("canary survives"),
            b"canary"
        );
        assert!(load_account(data_dir, BETA).is_some());
    }

    // ── Credential-lane refusals: nothing is destroyed and the bearer stays reachable ────────

    /// THE ORDER PROOF, DIRECTION ONE. The canonical credential target is shadowed by a directory
    /// while a legacy-named slot still holds the account's resolvable bearer — `live_config` matches
    /// on the `connector_id` FIELD, not on a filename. The refusal must land BEFORE any unlink, so
    /// the account survives and the bearer keeps resolving.
    #[test]
    fn a_credential_slot_shadowed_by_a_directory_refuses_before_any_unlink() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, "alpha-legacy-slot", ALPHA, ALPHA_TOKEN);
        std::fs::create_dir_all(
            directory
                .path()
                .join(CREDENTIAL_VAULT)
                .join(format!("{ALPHA}.json")),
        )
        .expect("directory shadow");
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_slot_unreadable")
        );
        assert!(load_account(data_dir, ALPHA).is_some(), "account remains");
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN),
            "the live bearer must still resolve — nothing was unlinked"
        );
    }

    #[test]
    fn a_vault_family_shadowed_by_a_file_refuses_before_the_account_is_destroyed() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        seed_account(data_dir, ALPHA, &live_account(ALPHA));
        let shadow = directory.path().join(CREDENTIAL_VAULT);
        std::fs::write(&shadow, b"not a directory").expect("family shadow");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_vault_unpinnable")
        );
        assert!(load_account(data_dir, ALPHA).is_some(), "account remains");
        assert_eq!(
            std::fs::read(&shadow).expect("shadow read"),
            b"not a directory"
        );
    }

    #[test]
    fn a_malformed_vault_slot_refuses_and_leaves_its_bytes_unchanged() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        let malformed = directory.path().join(CREDENTIAL_VAULT).join("broken.json");
        std::fs::write(&malformed, b"{ this was never JSON").expect("malformed slot");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_slot_malformed")
        );
        assert_eq!(
            std::fs::read(&malformed).expect("malformed slot read"),
            b"{ this was never JSON"
        );
        assert!(load_account(data_dir, ALPHA).is_some());
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );
    }

    #[test]
    fn an_unclassifiable_vault_slot_refuses_and_leaves_its_bytes_unchanged() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        let anonymous = directory
            .path()
            .join(CREDENTIAL_VAULT)
            .join("anonymous.json");
        let bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": "ioi.hypervisor.storage-credential.v1",
            "scheme": "bearer", "sealed_token": "deadbeef",
        }))
        .expect("bytes");
        std::fs::write(&anonymous, &bytes).expect("unclassifiable slot");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_slot_unclassifiable")
        );
        assert_eq!(std::fs::read(&anonymous).expect("slot read"), bytes);
        assert!(load_account(data_dir, ALPHA).is_some());
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );
    }

    // ── Account-lane refusals: the revocation already happened and the response says so ──────

    /// THE ORDER PROOF, DIRECTION TWO. The account record is loadable (from a legacy-named slot)
    /// but its writer-named slot is shadowed by a directory, so the account unlink fails AFTER the
    /// credential purge has already succeeded. Swapping the effect order breaks `credential gone`.
    #[test]
    fn an_account_slot_shadowed_by_a_directory_refuses_after_the_credential_is_already_revoked() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, "alpha-legacy-slot", &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        std::fs::create_dir_all(
            directory
                .path()
                .join(ACCOUNT_KIND)
                .join(format!("{ALPHA}.json")),
        )
        .expect("directory shadow");
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_account_deletion_failed")
        );
        // The credential effect ALREADY happened, is reported as such, and is not undone.
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert!(live_bearer(data_dir, &account).is_none(), "credential gone");
        assert!(!account_credential_resolves(data_dir, ALPHA));
        // ...and the account is still there, so the refusal is not a partial success claim.
        assert!(load_account(data_dir, ALPHA).is_some(), "account remains");
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("Delete again to retry"),
            "recovery must name the retry that converges, got: {message}"
        );
        assert!(
            message.contains("revoked"),
            "recovery must say the revocation already happened, got: {message}"
        );
    }

    /// THE RELOAD GATE. Both unlinks report done — the writer-named account slot genuinely is not
    /// there — but the record still resolves through the production reader from a legacy-named
    /// slot. Acknowledging here would report a destruction that did not happen.
    #[test]
    fn an_account_that_still_resolves_after_both_unlinks_is_never_acknowledged_deleted() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, "alpha-legacy-slot", &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        assert!(!directory
            .path()
            .join(ACCOUNT_KIND)
            .join(format!("{ALPHA}.json"))
            .exists());

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_deletion_unconfirmed")
        );
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert!(body.get("deleted").is_none(), "no destruction was claimed");
        assert!(
            load_account(data_dir, ALPHA).is_some(),
            "the record that survived is exactly why this refused"
        );
    }

    // ── Directly-asserted mappings for the lanes no uid-independent fault can reach ──────────

    /// `Durable` and `Absent` map to DISTINCT dispositions. Folding them is how a count of
    /// `credentials revoked by this request` comes to include slots this request never touched.
    #[test]
    fn durable_and_absent_are_distinct_dispositions_and_only_durable_is_causal() {
        use super::super::durable_fs::UnlinkOutcome;
        assert_eq!(
            classify_unlink(Ok(UnlinkOutcome::Durable)),
            SlotUnlink::RemovedDurable
        );
        assert_eq!(
            classify_unlink(Ok(UnlinkOutcome::Absent)),
            SlotUnlink::AlreadyAbsent
        );
        assert_ne!(SlotUnlink::RemovedDurable, SlotUnlink::AlreadyAbsent);
        assert!(matches!(
            classify_unlink(Ok(UnlinkOutcome::RemovedDurabilityUnconfirmed(
                std::io::Error::other("directory fsync failed")
            ))),
            SlotUnlink::DurabilityUnconfirmed(_)
        ));
        assert!(matches!(
            classify_unlink(Ok(
                UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(std::io::Error::other(
                    "restored"
                ))
            )),
            SlotUnlink::DurabilityUnconfirmed(_)
        ));
        assert!(matches!(
            classify_unlink(Err(std::io::Error::other("EISDIR"))),
            SlotUnlink::NotPerformed(_)
        ));
        // Both absence dispositions let the purge continue; neither refuses.
        let empty = PurgeTally::default();
        assert!(credential_slot_refusal(&SlotUnlink::RemovedDurable, "s.json", empty).is_none());
        assert!(credential_slot_refusal(&SlotUnlink::AlreadyAbsent, "s.json", empty).is_none());
        assert!(account_deletion_refusal(&SlotUnlink::RemovedDurable, empty).is_none());
        assert!(account_deletion_refusal(&SlotUnlink::AlreadyAbsent, empty).is_none());
    }

    /// A slot found absent is NOT counted as revoked and is NOT narrated as one, and the prose
    /// never claims it was absent BEFORE this request: the strict read that classified it also ran
    /// during this request, so all that is knowable is that it was gone when the unlink ran.
    #[test]
    fn a_slot_found_absent_is_counted_and_narrated_apart_from_one_this_request_revoked() {
        let found = PurgeTally {
            revoked: 0,
            already_absent: 2,
        };
        let (_, body) =
            credential_slot_refusal(&SlotUnlink::NotPerformed("EISDIR".into()), "s.json", found)
                .expect("refuses");
        assert_eq!(body["credential_revocation"], json!("none"));
        assert_eq!(body["credentials_revoked"], json!(0));
        assert_eq!(body["credentials_already_absent"], json!(2));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("No sealed credential was revoked by this request"),
            "found-absent slots are not revocations, got: {message}"
        );
        assert!(
            message.contains("absent when this request attempted their unlinks"),
            "tense must not claim absence predates the request, got: {message}"
        );
        assert!(
            !message.contains("before this request"),
            "AlreadyAbsent never licenses a `before this request` claim, got: {message}"
        );

        // Mixed: one destroyed here, one merely found gone — the counts stay separate.
        let mixed = PurgeTally {
            revoked: 1,
            already_absent: 1,
        };
        let (_, body) = account_deletion_refusal(&SlotUnlink::NotPerformed("EISDIR".into()), mixed)
            .expect("refuses");
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(body["credentials_already_absent"], json!(1));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("1 sealed credential WAS durably revoked by this request"),
            "got: {message}"
        );
        assert!(
            message.contains(
                "a further 1 bound slot was absent when this request attempted its unlink"
            ),
            "got: {message}"
        );
    }

    /// The credential lane's two refusal dispositions. `NotPerformed` has no path-shadow injection
    /// here BY CONSTRUCTION — every shadow that breaks a slot's unlink also breaks the strict read
    /// that classifies it, and that read refuses first — and `DurabilityUnconfirmed`'s only
    /// injection point is a process-global env var this suite refuses to use. Both are asserted
    /// from constructed variants instead of left to review.
    ///
    /// THE ZERO-CONFIRMED CONSEQUENCE IS THE POINT. A refusal with nothing confirmed revoked must
    /// not inherit a partial-purge tail, and — separately — a refusal with an UNCONFIRMED removal
    /// outstanding must not inherit a nothing-changed tail. Both directions are asserted
    /// negatively, because a spliced tail is exactly how each one got said.
    #[test]
    fn zero_confirmed_refusals_claim_neither_a_partial_purge_nor_an_unchanged_vault() {
        let empty = PurgeTally::default();

        // NotPerformed at zero: nothing was removed, and the vault really is as found.
        let (status, body) = credential_slot_refusal(
            &SlotUnlink::NotPerformed("EISDIR".into()),
            "sba_a.json",
            empty,
        )
        .expect("not-performed refuses");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_revocation_failed")
        );
        assert_eq!(body["credential_revocation"], json!("none"));
        assert_eq!(body["credentials_revoked"], json!(0));
        assert_eq!(body["credentials_already_absent"], json!(0));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        assert!(body.get("deleted").is_none());
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("vault is exactly as this deletion found it"),
            "got: {message}"
        );
        assert!(
            !message.contains("PARTIAL"),
            "a zero-confirmed refusal must not claim a partial purge, got: {message}"
        );
        assert!(
            !message.contains("not in the state it started in"),
            "a zero-confirmed refusal must not claim the vault changed, got: {message}"
        );

        // DurabilityUnconfirmed at zero: nothing CONFIRMED, but a removal is outstanding, so the
        // vault must never be described as unchanged.
        let (status, body) = credential_slot_refusal(
            &SlotUnlink::DurabilityUnconfirmed("unconfirmed".into()),
            "sba_a.json",
            empty,
        )
        .expect("unconfirmed refuses");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_revocation_durability_unconfirmed")
        );
        assert_eq!(body["credential_revocation"], json!("ambiguous"));
        assert_eq!(body["credentials_revoked"], json!(0));
        assert_eq!(body["credentials_unconfirmed"], json!(1));
        assert!(body.get("deleted").is_none());
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("MAY already have changed"),
            "an outstanding unconfirmed removal must be stated, got: {message}"
        );
        assert!(
            !message.contains("exactly as this deletion found it"),
            "an unconfirmed removal makes `exactly as found` false, got: {message}"
        );
        assert!(
            !message.contains("no slot was removed"),
            "an unconfirmed removal makes `no slot was removed` false, got: {message}"
        );
        assert!(
            !message.contains("PARTIAL AND AMBIGUOUS"),
            "nothing is confirmed here, so it is not a partial purge, got: {message}"
        );
    }

    /// THE PARTIAL-PURGE CONTRACT. The purge is a LOOP: slot two can fail after slot one has
    /// already fsynced. A refusal claiming nothing changed would be false about a destruction that
    /// already happened and cannot be undone. Both later-slot branches are asserted over a REAL
    /// prior-confirmed count. The end-to-end partial lane IS proven behaviourally, by
    /// `a_credential_the_purge_cannot_enumerate_leaves_an_honest_partial_revocation`.
    #[test]
    fn a_later_slot_refusal_reports_the_exact_count_already_durably_revoked() {
        let one = PurgeTally {
            revoked: 1,
            already_absent: 0,
        };
        let (status, body) = credential_slot_refusal(
            &SlotUnlink::NotPerformed("EISDIR".into()),
            "sba_alpha-second.json",
            one,
        )
        .expect("not-performed refuses");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_revocation_failed")
        );
        // PARTIAL, CONFIRMED: one credential is durably gone and at least one provably remains.
        assert_eq!(body["credential_revocation"], json!("partial_confirmed"));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains(
                "1 sealed credential bound to this backend WAS durably revoked by this request"
            ),
            "a partial purge must not read as unchanged, got: {message}"
        );
        assert!(message.contains("this purge is PARTIAL"), "got: {message}");
        assert!(
            !message.contains("exactly as this deletion found it"),
            "a confirmed removal makes `exactly as found` false, got: {message}"
        );
        assert!(
            message.contains("account was NOT deleted"),
            "the account is the retry anchor and must be named, got: {message}"
        );

        let two = PurgeTally {
            revoked: 2,
            already_absent: 0,
        };
        let (status, body) = credential_slot_refusal(
            &SlotUnlink::DurabilityUnconfirmed("unconfirmed".into()),
            "sba_alpha-third.json",
            two,
        )
        .expect("unconfirmed refuses");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_revocation_durability_unconfirmed")
        );
        // PARTIAL AND AMBIGUOUS: two durably gone, plus one whose durability is unknown — the true
        // number removed is two or three, and the message says exactly that instead of guessing.
        assert_eq!(body["credential_revocation"], json!("partial_ambiguous"));
        assert_eq!(body["credentials_revoked"], json!(2));
        assert_eq!(body["credentials_unconfirmed"], json!(1));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("2 sealed credentials bound to this backend WERE durably revoked"),
            "got: {message}"
        );
        assert!(
            message.contains("PARTIAL AND AMBIGUOUS: the number destroyed here is 2 or 3"),
            "the ambiguity must be stated as a range, got: {message}"
        );
        assert!(
            message.contains("account was NOT deleted"),
            "got: {message}"
        );
    }

    /// THE END-TO-END PARTIAL LANE, deterministic and real. `durable_fs::enumerate_pinned` drops
    /// directory entries whose names are not valid UTF-8, while `read_record_dir` — and therefore
    /// `live_config` — reads them by `OsString`. A second credential bound to the same account
    /// under such a name is INVISIBLE to the purge and fully live to the bearer path: the first
    /// slot is durably revoked, the reload gate catches the survivor, and the refusal must report
    /// exactly one confirmed revocation with the account left standing as the retry anchor.
    #[test]
    fn a_credential_the_purge_cannot_enumerate_leaves_an_honest_partial_revocation() {
        use std::os::unix::ffi::OsStrExt;
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        let enumerable = directory
            .path()
            .join(CREDENTIAL_VAULT)
            .join(format!("{ALPHA}.json"));
        // A second, equally live credential for the SAME account under a non-UTF-8 filename.
        let hidden = directory
            .path()
            .join(CREDENTIAL_VAULT)
            .join(std::ffi::OsStr::from_bytes(b"sba_alpha-\xff.json"));
        std::fs::copy(&enumerable, &hidden).expect("second credential seeded");
        assert!(account_credential_resolves(data_dir, ALPHA));

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_revocation_unconfirmed")
        );
        // The exact partial state: one confirmed removal, none found absent, none in doubt.
        assert_eq!(body["credential_revocation"], json!("partial_confirmed"));
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(body["credentials_already_absent"], json!(0));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        assert!(body.get("deleted").is_none(), "no destruction was claimed");
        // The enumerable slot really is gone — this is a PARTIAL purge, not a no-op.
        assert!(!enumerable.exists());
        // ...and the survivor is exactly why it refused, still live to the bearer path.
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );
        // The account is the retry anchor and MUST remain, or the survivor becomes unreachable.
        assert!(load_account(data_dir, ALPHA).is_some(), "account remains");
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains(
                "1 sealed credential bound to this backend WAS durably revoked by this request"
            ),
            "got: {message}"
        );
        assert!(
            message.contains("not valid UTF-8"),
            "recovery must name a repair that exists, got: {message}"
        );
    }

    /// The account lane's refusal arms — a 503 ambiguity and a 500, both of which still report the
    /// completed purge, because the operator's next action depends on knowing it happened.
    #[test]
    fn account_deletion_refusals_report_the_completed_revocation_and_never_acknowledge() {
        let two = PurgeTally {
            revoked: 2,
            already_absent: 0,
        };
        let (status, body) = account_deletion_refusal(
            &SlotUnlink::DurabilityUnconfirmed("unconfirmed".into()),
            two,
        )
        .expect("unconfirmed refuses");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_account_deletion_durability_unconfirmed")
        );
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(2));
        assert_eq!(body["credentials_unconfirmed"], json!(0));
        assert!(body.get("deleted").is_none());

        let one = PurgeTally {
            revoked: 1,
            already_absent: 0,
        };
        let (status, body) =
            account_deletion_refusal(&SlotUnlink::NotPerformed("EISDIR".into()), one)
                .expect("not-performed refuses");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_account_deletion_failed")
        );
        assert_eq!(body["credentials_revoked"], json!(1));

        // At ZERO the account lane must not claim a revocation happened either.
        let (_, body) = account_deletion_refusal(
            &SlotUnlink::NotPerformed("EISDIR".into()),
            PurgeTally::default(),
        )
        .expect("not-performed refuses");
        assert_eq!(body["credential_revocation"], json!("already_completed"));
        assert_eq!(body["credentials_revoked"], json!(0));
        let message = body["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("had no bound sealed credential, so nothing was revoked"),
            "got: {message}"
        );
        assert!(
            !message.contains("WAS durably revoked") && !message.contains("WERE durably revoked"),
            "a zero purge must not claim a revocation, got: {message}"
        );
    }

    /// The promotion guard is INERT today, and this pins why: if either family is ever promoted,
    /// this test fails and forces the guard — and this whole raw-file deletion — to be re-read
    /// before a substrate-owned record can be "deleted" by unlinking legacy JSON that no longer
    /// carries its truth.
    #[test]
    fn neither_deleted_family_is_promoted_to_the_substrate_today() {
        assert!(!super::super::substrate_store::is_promoted(ACCOUNT_KIND));
        assert!(!super::super::substrate_store::is_promoted(
            CREDENTIAL_VAULT
        ));
    }

    // ── Source-shape pins for the claims no injectable fault can catch ──────────────────────

    fn production_fn<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("the production function `{signature}` is gone"));
        let rest = &source[start..];
        let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
        &rest[..end]
    }

    /// Both destructions must go through the pinned, durability-honest unlink, and the credential
    /// must be revoked BEFORE the account family is even opened.
    ///
    /// The account lane's revert to a discarded `remove_file` is caught behaviourally by
    /// `an_account_slot_shadowed_by_a_directory_refuses_after_the_credential_is_already_revoked`
    /// (a discarded failure would fall through to a 503 instead of the typed 500). The CREDENTIAL
    /// lane's revert has no such behavioural catch on this family — see the disposition test above
    /// — so it is pinned here, in the same spirit as
    /// `managed_runtime_routes::restore_effects_are_admitted_before_they_are_performed`.
    #[test]
    fn both_destructions_use_the_pinned_durable_unlink_in_credential_first_order() {
        let source = include_str!("storage_backend_routes.rs");

        let revoke = production_fn(source, "fn revoke_account_credentials");
        assert!(
            revoke.contains("unlink_durable_at("),
            "credential revocation must unlink through durable_fs, never a raw remove"
        );
        assert!(
            !revoke.contains("remove_file"),
            "a discarded remove_file cannot tell a failed revocation from a completed one"
        );
        assert!(
            revoke.contains("enumerate_pinned(") && revoke.contains("read_slot_strict("),
            "the vault walk must use the pinned enumeration and strict slot reads"
        );
        // The purge is NOT atomic, so every later-slot refusal must carry the tally this request
        // has already established. Passing a constant here would make a partial purge read as
        // unchanged, and that lane has no end-to-end injection to catch it.
        assert!(
            revoke.contains("credential_slot_refusal(&disposition, name, tally)"),
            "a later-slot refusal must report the exact tally already established"
        );

        let delete = production_fn(source, "pub(crate) fn delete_storage_backend_account");
        assert!(
            delete.contains("unlink_durable_at("),
            "the account record must unlink through durable_fs, never a raw remove"
        );
        assert!(
            !delete.contains("remove_file"),
            "a discarded remove_file cannot tell a failed deletion from a completed one"
        );
        let revoked_at = delete
            .find("revoke_account_credentials(data_dir")
            .expect("the credential effect is gone");
        let account_at = delete
            .find("open_record_family(data_dir, ACCOUNT_KIND)")
            .expect("the account effect is gone");
        assert!(
            revoked_at < account_at,
            "credentials must be revoked before the account record is destroyed — otherwise a \
             surviving credential is orphaned behind a missing account and is unreachable"
        );
        assert!(
            delete.contains("load_account(data_dir, &account_id).is_some()"),
            "the acknowledgement must be gated on reloaded absence"
        );
    }

    /// THE CONCURRENCY NONCLAIM. Nothing on this plane holds a lock, so the credentials-first
    /// ordering only protects credentials the vault walk OBSERVED. A credential bound after
    /// classification but before the account unlink is still orphaned. That window has no test
    /// because it has no deterministic single-process injection, so the nonclaim is pinned in the
    /// source instead of being left to a reader's charity.
    #[test]
    fn the_ordering_guarantee_names_its_unlocked_concurrent_bind_window() {
        let source = include_str!("storage_backend_routes.rs");
        let start = source
            .find("// ── Backend account destruction")
            .expect("destruction section");
        let header = &source[start..start + 2000];
        assert!(
            header.contains("is NOT a concurrency claim") && header.contains("Nothing here"),
            "the ordering guarantee must state that it is not a concurrency claim"
        );
        assert!(
            header.contains("IS orphaned exactly as before"),
            "the surviving concurrent-bind window must be named, not implied"
        );
    }

    /// Every refusal code this route can emit is either behaviourally covered, asserted from a
    /// constructed variant, or ENUMERATED as noncoverage with its reason. A new code that is in
    /// none of the three lists fails this test, so noncoverage cannot accrue silently.
    #[test]
    fn every_refusal_code_is_covered_or_explicitly_enumerated_as_noncoverage() {
        // Reached by a deterministic path shadow or real data state in this module.
        const BEHAVIOURAL: &[&str] = &[
            "storage_backend_account_unidentified",
            "storage_backend_credential_vault_unpinnable",
            "storage_backend_credential_slot_unreadable",
            "storage_backend_credential_slot_malformed",
            "storage_backend_credential_slot_unclassifiable",
            "storage_backend_credential_revocation_unconfirmed",
            "storage_backend_account_deletion_failed",
            "storage_backend_deletion_unconfirmed",
        ];
        // Asserted from constructed variants against the extracted refusal builders. No
        // path-shadow injection exists: every shadow that breaks a slot's unlink also breaks the
        // strict read that classifies it, and `DurabilityUnconfirmed`'s only injection point is a
        // process-global env var this suite refuses to use.
        const CONSTRUCTED: &[&str] = &[
            "storage_backend_credential_revocation_failed",
            "storage_backend_credential_revocation_durability_unconfirmed",
            "storage_backend_account_deletion_durability_unconfirmed",
        ];
        // NOT EXERCISED AT ALL, with the reason each one is unreachable here:
        //  * vault_unreadable — `enumerate_pinned` fails only inside fdopendir/readdir, which has
        //    no uid-independent injection; the pin and the slot reads absorb every path shadow.
        //  * account_family_unpinnable — any family state that stops `open_record_family` also
        //    stops `read_record_dir`, so `load_account` returns None and the request answers
        //    not-found first. Pinned by
        //    `an_unopenable_account_family_answers_not_found_rather_than_reaching_its_refusal`.
        //  * deletion_substrate_owned — PROMOTED_DOMAINS is a compile-time constant; pinned by
        //    `neither_deleted_family_is_promoted_to_the_substrate_today`.
        const ENUMERATED_NONCOVERAGE: &[&str] = &[
            "storage_backend_credential_vault_unreadable",
            "storage_backend_account_family_unpinnable",
            "storage_backend_deletion_substrate_owned",
        ];

        let source = include_str!("storage_backend_routes.rs");
        let start = source
            .find("// ── Backend account destruction")
            .expect("destruction section");
        let end = source
            .find("/// POST /v1/hypervisor/storage-backends/{id}/credential")
            .expect("section end");
        let mut emitted: Vec<String> = Vec::new();
        for chunk in source[start..end].split("\"storage_backend_").skip(1) {
            let code = format!(
                "storage_backend_{}",
                &chunk[..chunk.find('"').expect("closing quote")]
            );
            if !emitted.contains(&code) {
                emitted.push(code);
            }
        }
        assert!(
            !emitted.is_empty(),
            "no refusal codes found — scraper broke"
        );
        for code in &emitted {
            let code = code.as_str();
            let known = BEHAVIOURAL.contains(&code)
                || CONSTRUCTED.contains(&code)
                || ENUMERATED_NONCOVERAGE.contains(&code);
            assert!(
                known,
                "refusal code `{code}` is in none of the three coverage lists — cover it or \
                 enumerate it as noncoverage with a reason"
            );
        }
        for code in BEHAVIOURAL
            .iter()
            .chain(CONSTRUCTED)
            .chain(ENUMERATED_NONCOVERAGE)
        {
            assert!(
                emitted.iter().any(|e| e == code),
                "coverage list names `{code}`, which this route no longer emits — prune the list"
            );
        }
    }

    // ── Symlinked record families: compatibility WITHOUT losing terminal containment ─────────

    /// S2 REGRESSION GUARD. `durable_fs::open_family_dir_pinned` adds `O_NOFOLLOW`, which refuses a
    /// SYMLINKED family directory — while `read_record_dir`, `load_account` and `live_config` all
    /// follow that same symlink and keep working. Using it here would have denied EVERY deletion in
    /// any deployment that symlinks a record family (a container volume mount, an atomic-swap
    /// release directory) while every other route on the plane carried on. Both families are
    /// asserted, because the account family is the one a deployment is most likely to relocate.
    #[test]
    fn a_symlinked_record_family_deletes_exactly_as_a_real_one_does() {
        let directory = temp();
        let root = directory.path();
        let data_dir = root.to_str().expect("utf8");
        // Both families live somewhere else entirely and are reached through symlinks.
        let elsewhere = root.join("relocated");
        std::fs::create_dir_all(elsewhere.join(ACCOUNT_KIND)).expect("relocated accounts");
        std::fs::create_dir_all(elsewhere.join(CREDENTIAL_VAULT)).expect("relocated vault");
        std::os::unix::fs::symlink(elsewhere.join(ACCOUNT_KIND), root.join(ACCOUNT_KIND))
            .expect("account family symlink");
        std::os::unix::fs::symlink(
            elsewhere.join(CREDENTIAL_VAULT),
            root.join(CREDENTIAL_VAULT),
        )
        .expect("vault symlink");

        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, ALPHA, ALPHA, ALPHA_TOKEN);
        // The production readers follow the symlink, so the account and its bearer both resolve.
        assert!(load_account(data_dir, ALPHA).is_some());
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["credentials_revoked"], json!(1));
        assert_eq!(body["account_slot"], json!("removed_durable"));
        assert!(load_account(data_dir, ALPHA).is_none());
        assert!(live_bearer(data_dir, &account).is_none());
        // The records really left the relocated directories, not some path beside the symlink.
        assert!(!elsewhere
            .join(ACCOUNT_KIND)
            .join(format!("{ALPHA}.json"))
            .exists());
        assert!(!elsewhere
            .join(CREDENTIAL_VAULT)
            .join(format!("{ALPHA}.json"))
            .exists());
    }

    /// ...and the containment that matters is RETAINED. Following the family directory does not
    /// license following a terminal SLOT: `read_slot_strict` opens every slot `O_NOFOLLOW`, so a
    /// symlinked credential record refuses rather than being read — and unlinked — through.
    ///
    /// SCOPED TO THE CREDENTIAL LANE, which is the lane that pre-reads. The account lane has no
    /// such read and does not refuse a symlinked slot; `unlink_durable_at` is `unlinkat(.., 0)`,
    /// which removes the symlink entry itself and never follows it to a target. That is safe for a
    /// different reason, and it is not what this test proves.
    #[test]
    fn a_symlinked_credential_slot_still_refuses_inside_a_symlinked_family() {
        let directory = temp();
        let root = directory.path();
        let data_dir = root.to_str().expect("utf8");
        let elsewhere = root.join("relocated");
        std::fs::create_dir_all(elsewhere.join(CREDENTIAL_VAULT)).expect("relocated vault");
        std::os::unix::fs::symlink(
            elsewhere.join(CREDENTIAL_VAULT),
            root.join(CREDENTIAL_VAULT),
        )
        .expect("vault symlink");
        let account = live_account(ALPHA);
        seed_account(data_dir, ALPHA, &account);
        seed_credential(data_dir, "alpha-legacy-slot", ALPHA, ALPHA_TOKEN);
        // A slot that is a SYMLINK to the real credential record.
        std::os::unix::fs::symlink(
            elsewhere
                .join(CREDENTIAL_VAULT)
                .join("alpha-legacy-slot.json"),
            elsewhere
                .join(CREDENTIAL_VAULT)
                .join(format!("{ALPHA}.json")),
        )
        .expect("slot symlink");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_credential_slot_unreadable")
        );
        assert_eq!(body["credentials_revoked"], json!(0));
        assert!(load_account(data_dir, ALPHA).is_some(), "account remains");
        assert_eq!(
            live_bearer(data_dir, &account).as_deref(),
            Some(ALPHA_TOKEN)
        );
    }

    // ── Remaining refusal codes ──────────────────────────────────────────────────────────────

    /// S3. A record that resolves by ref but carries no account_id names no deletion target, so it
    /// refuses rather than unlinking a guessed one — `safe("")` would have targeted `.json`.
    #[test]
    fn a_record_with_no_account_id_refuses_rather_than_deleting_a_guessed_target() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        let anonymous = json!({
            "schema_version": "ioi.hypervisor.storage-backend-account.v1",
            "account_ref": "storage-backend://sba_anonymous",
            "kind": "ipfs",
            "status": "verified",
        });
        seed_account(data_dir, "anonymous", &anonymous);
        std::fs::write(directory.path().join(ACCOUNT_KIND).join(".json"), b"decoy")
            .expect("decoy written");

        let (status, body) =
            delete_storage_backend_account(data_dir, "storage-backend://sba_anonymous");

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("storage_backend_account_unidentified")
        );
        assert_eq!(body["credential_revocation"], json!("none"));
        assert_eq!(body["credentials_revoked"], json!(0));
        // Nothing was unlinked — including the file `safe("")` would have named.
        assert!(load_account(data_dir, "storage-backend://sba_anonymous").is_some());
        assert_eq!(
            std::fs::read(directory.path().join(ACCOUNT_KIND).join(".json")).expect("decoy"),
            b"decoy"
        );
    }

    /// S3, the enumerated-noncoverage pin. `storage_backend_account_family_unpinnable` is
    /// UNREACHABLE, and this proves the reason rather than asserting it in a comment: any account
    /// family state that stops `open_record_family` also stops `read_record_dir`, so `load_account`
    /// finds nothing and the request answers the preserved not-found response long before that
    /// refusal could be built. If a future change makes the lane reachable, this test fails and the
    /// coverage lists must be revisited.
    #[test]
    fn an_unopenable_account_family_answers_not_found_rather_than_reaching_its_refusal() {
        let directory = temp();
        let data_dir = directory.path().to_str().expect("utf8");
        std::fs::write(directory.path().join(ACCOUNT_KIND), b"not a directory")
            .expect("family shadow");

        let (status, body) = delete_storage_backend_account(data_dir, ALPHA);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "ok": false, "reason": "no such storage backend" })
        );
    }
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
