//! GoalRun plane — daemon-owned multi-harness orchestration (first cut).
//!
//! Moves the estate from "interchangeable harnesses can each execute" to "the daemon can
//! orchestrate multiple harnesses in ONE governed GoalRun" under the canonical ladder:
//! GoalRun → GoalGroundingLoop → RoleTopology → ContextCell → ContextLease →
//! ContextHandoff/TaskBriefPayload → HarnessInvocation → HarnessAdapterEvent →
//! ImplementationResultPayload → VerifierPath → reconciliation.
//!
//! First orchestration policy: `parallel_implement_reconcile` — conductor (native worker,
//! deterministic), two implementer cells (OpenCode + DeepSeek TUI adapter drivers) running the
//! SAME typed TaskBriefPayload in ISOLATED candidate session workspaces, then a conductor-run
//! deterministic VerifierPath and an admitted reconciliation that alone may copy candidate
//! artifacts into the target session workspace.
//!
//! Boundaries this plane enforces (never relaxed here):
//!   - the kernel planner (`runtime_goal_run_admission`) admits creation, role topology, every
//!     invocation, and the reconciliation — pure fail-closed checks over live registry facts;
//!   - `start` is wallet-gated exactly like session execute (403 challenge → grant), and the
//!     capability lease ref is recorded on every invocation receipt;
//!   - implementers NEVER write the target workspace — each writes its own candidate session
//!     workspace; only an admitted reconciliation copies selected files across;
//!   - raw prompts are not durable orchestration truth: the durable contract is the typed task
//!     brief; the rendered harness input is adapter-private;
//!   - a failed/ineligible implementer becomes an EXPLICIT partial result with a blocker record,
//!     never a silent skip;
//!   - every invocation and the reconciliation post agent-run transcripts (tamper-evident
//!     state_root) and mint receipts, so Run Timeline / Work Ledger carry the proof.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::lifecycle_routes::{
    execute_authority_gate, load_session_record, resolve_adapter_driver, run_host_spawn_lane,
};
use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};
use ioi_services::agentic::runtime::kernel::approval::verify_wallet_approval_grant_binding;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

const GOAL_RUN_KIND: &str = "goal-runs";

/// GoalRun record mutation lock (#72 review round 2). LOCK ORDERING (fixed, documented):
/// ROOM_MUTATION_LOCK — when held — is always acquired BEFORE this lock; no .await ever executes
/// under it (update_goal_run_guarded's predicate and closure are synchronous).
pub(crate) static GOAL_RUN_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// ATOMIC-DURABLE record persistence (#72 round 6 finding 1): temporary sibling → file fsync →
/// rename → CHECKED directory fsync → cleanup on every failure boundary. A crash at any instant
/// leaves either the old record or the complete new record — never a torn one — and a reported
/// Ok means the rename itself reached stable storage. Used for every record whose loss beside
/// durable output would orphan evidence: goal-run records (reservations, intents, releases),
/// reconciliation receipts, reconciliation/WAL operation records, and recovery receipts.
fn persist_record_durable(data_dir: &str, family: &str, record_id: &str, record: &Value) -> std::io::Result<()> {
    use std::io::Write;
    // Parity with persist_record (#72 round 3): promoted families have exactly one write path;
    // not-yet-promoted families still feed the opt-in dual-write soak.
    if super::substrate_store::is_promoted(family) {
        return super::substrate_store::persist_promoted(data_dir, family, record_id, record);
    }
    let dir = std::path::Path::new(data_dir).join(family);
    std::fs::create_dir_all(&dir)?;
    let safe: String = record_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let tmp = dir.join(format!(".{safe}.tmp-{:x}", nanos()));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(record).unwrap_or_default())?;
        f.sync_all()
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{safe}.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // CHECKED directory fsync: without it a crash can un-happen the rename; an error here is a
    // durability failure the caller must treat as a failed persist (fail closed, never assume).
    std::fs::File::open(&dir)?.sync_all()?;
    super::substrate_store::dual_write(data_dir, family, record_id, record);
    Ok(())
}

/// ATOMIC-DURABLE replacement for the mutable goal-run record — the durable helper over the
/// goal-run family (reservations, recovery intents, and releases order-depend on durability).
fn persist_goal_run_atomic(data_dir: &str, goal_run_id: &str, record: &Value) -> std::io::Result<()> {
    persist_record_durable(data_dir, GOAL_RUN_KIND, goal_run_id, record)
}

/// Descriptor-relative, symlink-refusing filesystem walks (#72 round 6 finding 3): every
/// component is opened O_NOFOLLOW relative to the previously PINNED directory fd
/// (openat/mkdirat/renameat), so a concurrent path or ancestor swap cannot redirect a read or a
/// write after validation — the enforcement IS the open, not a check before it. A symlink
/// anywhere in the walk fails with ELOOP/ENOTDIR at use time.
mod nofollow {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    fn cstr(name: &std::ffi::OsStr) -> std::io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component"))
    }

    /// Pin the walk ROOT itself: must be a directory, terminal symlink refused.
    pub(super) fn open_root(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub(super) fn open_dir_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        let c = cstr(name)?;
        let fd = unsafe {
            libc::openat(parent.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(super) fn mkdir_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
        let c = cstr(name)?;
        let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o755) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(e);
            }
        }
        Ok(())
    }

    pub(super) fn open_file_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        let c = cstr(name)?;
        let fd = unsafe {
            libc::openat(parent.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(super) fn create_file_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        let c = cstr(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(super) fn rename_at(parent: &std::fs::File, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> std::io::Result<()> {
        let cf = cstr(from)?;
        let ct = cstr(to)?;
        let rc = unsafe { libc::renameat(parent.as_raw_fd(), cf.as_ptr(), parent.as_raw_fd(), ct.as_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn unlink_at(parent: &std::fs::File, name: &std::ffi::OsStr) {
        if let Ok(c) = cstr(name) {
            unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), 0) };
        }
    }

    /// Walk (and in `create` mode, mkdirat) each PARENT component of `rel` under `root`,
    /// returning the pinned parent directory fd.
    pub(super) fn pin_parent(root: &std::fs::File, rel: &std::path::Path, create: bool) -> std::io::Result<std::fs::File> {
        let mut cur = root.try_clone()?;
        if let Some(parent) = rel.parent() {
            for comp in parent.components() {
                if let std::path::Component::Normal(seg) = comp {
                    if create {
                        mkdir_at(&cur, seg)?;
                    }
                    cur = open_dir_at(&cur, seg)?;
                }
            }
        }
        Ok(cur)
    }

    /// Read a workspace file ENTIRELY through pinned descriptors (root fd → NOFOLLOW component
    /// walk → NOFOLLOW file open) — no path is re-resolved between validation and read.
    pub(super) fn read_contained(root: &std::fs::File, rel: &std::path::Path) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let parent = pin_parent(root, rel, false)?;
        let name = rel
            .file_name()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
        let mut f = open_file_at(&parent, name)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// A typed seam refusal: (code, message). Codes are wire-facing.
pub(crate) type SeamErr = (String, String);

/// THE SHARED GoalRun MUTATION/CAS SEAM (#72 review rounds 2 + 3): every GoalRun-record writer —
/// lifecycle `start`/`reconcile` here, the room plane's reciprocal membership stamp — re-reads
/// the LATEST record under GOAL_RUN_MUTATION_LOCK, evaluates the caller's `expect` predicate
/// against that FRESH record (this is the CAS: state prechecks and operation-token comparisons
/// happen atomically with the write, never against a stale snapshot), then merges ONLY the
/// fields the caller owns and persists via atomic replacement. Outcomes are TYPED and distinct —
/// `goal_run_not_found`, the predicate's own refusal, `goal_run_persist_failed` — because a
/// caller that reports success without an `Ok` from this seam is fail-open (round 3 finding 1).
pub(crate) fn update_goal_run_guarded(
    data_dir: &str,
    goal_run_id: &str,
    expect: impl FnOnce(&Value) -> Result<(), SeamErr>,
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<Value, SeamErr> {
    let _guard = GOAL_RUN_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut fresh) = read_record_dir(data_dir, GOAL_RUN_KIND)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
    else {
        return Err((
            "goal_run_not_found".to_string(),
            format!("no durable GoalRun record '{goal_run_id}'"),
        ));
    };
    expect(&fresh)?;
    if let Some(obj) = fresh.as_object_mut() {
        mutate(obj);
    }
    if let Err(e) = persist_goal_run_atomic(data_dir, goal_run_id, &fresh) {
        return Err((
            "goal_run_persist_failed".to_string(),
            format!("the GoalRun record write did not commit ({e}) — the durable record is unchanged"),
        ));
    }
    Ok(fresh)
}

/// Release a lifecycle operation reservation (token-guarded): restore `status`, drop
/// `lifecycle_op`. Every post-reservation refusal/rollback path releases through here so a
/// refused request leaves the run exactly re-runnable. A token mismatch means this request no
/// longer owns the run — it must not touch it.
pub(crate) fn release_lifecycle_reservation(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    restore_status: &str,
) -> Result<(), SeamErr> {
    update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "lifecycle reservation token mismatch — another operation owns this run".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!(restore_status));
            obj.remove("lifecycle_op");
        },
    )
    .map(|_| ())
}

/// HTTP status for a seam/lifecycle refusal code — persistence and rollback lanes are 5xx
/// (infrastructure truth), a missing run is 404, every state/token refusal is a 409 conflict.
fn seam_status(code: &str) -> StatusCode {
    match code {
        "goal_run_not_found" => StatusCode::NOT_FOUND,
        "goal_run_persist_failed" | "goal_run_finalize_failed" | "goal_run_rollback_failed"
        | "goal_run_release_failed" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    }
}

/// PRE-EFFECT reconcile rollback lane (#72 rounds 3 + 4): valid ONLY while the target workspace
/// is untouched (before the output-commit step) — remove the listed partial records (checked),
/// release the reservation back to `active`, and refuse typed. On success the durable state is
/// EXACTLY as before this request — target workspace included — so the reconcile is retryable.
/// Once output MAY have reached the target, `reconcile_preserve_abort` applies instead: nothing
/// is deleted there. Any incomplete step escalates to `goal_run_rollback_failed` with the
/// surviving pieces named for manual repair.
fn reconcile_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    code: &str,
    detail: &str,
    cleanup: &[(&str, &str)],
) -> (StatusCode, Json<Value>) {
    let mut failures: Vec<String> = Vec::new();
    for (family, record_id) in cleanup {
        if !remove_record(data_dir, family, record_id) {
            failures.push(format!("{family}/{record_id}"));
        }
    }
    if let Err((rcode, rmsg)) = release_lifecycle_reservation(data_dir, goal_run_id, token, "active") {
        failures.push(format!("reservation release ({rcode}: {rmsg})"));
    }
    if failures.is_empty() {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            &format!("{detail}; every partial record was rolled back and the reservation released — the run remains `active` and reconcile may be retried (nothing partial persists)"),
        )
    } else {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("{detail} AND rollback was incomplete ({}) — manual repair required", failures.join(", ")),
        )
    }
}

/// POST-EFFECT reconcile abort (#72 round 4 finding 1): once the pre-output receipt exists and
/// the output commit MAY have begun, NOTHING is deleted — deleting the receipt would orphan the
/// output and every artifact (transcript, journal) that references it. Instead the operation
/// record is UPDATED (checked) to a recovery status carrying the commit journal, the
/// reservation is released so the idempotent reconcile can be retried, and the refusal names
/// the preserved evidence. Incomplete bookkeeping escalates to manual repair — still deleting
/// nothing.
fn reconcile_preserve_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    reconciliation_id: &str,
    preserved_record: &Value,
    code: &str,
    detail: &str,
) -> (StatusCode, Json<Value>) {
    let mut failures: Vec<String> = Vec::new();
    let mut preserved = preserved_record.clone();
    if let Some(obj) = preserved.as_object_mut() {
        obj.insert(
            "recovery".into(),
            json!({ "code": code, "detail": detail, "at": iso_now() }),
        );
    }
    if let Err(e) = persist_record_durable(data_dir, RECONCILIATION_KIND, reconciliation_id, &preserved) {
        failures.push(format!("operation-record update ({RECONCILIATION_KIND}/{reconciliation_id}: {e})"));
    }
    // Release + APPEND-ONLY attempt retention (#72 round 5 finding 2): the failed attempt's ref
    // joins the run's `reconciliation_attempt_refs` so no retry can orphan its evidence.
    let attempt_ref = format!("reconciliation_result://{reconciliation_id}");
    let released = update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "lifecycle reservation token mismatch — another operation owns this run".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!("active"));
            obj.remove("lifecycle_op");
            let mut attempts: Vec<Value> = obj
                .get("reconciliation_attempt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !attempts.iter().any(|a| a.as_str() == Some(attempt_ref.as_str())) {
                attempts.push(json!(attempt_ref));
            }
            obj.insert("reconciliation_attempt_refs".into(), Value::Array(attempts));
        },
    );
    if let Err((rcode, rmsg)) = released {
        failures.push(format!("reservation release ({rcode}: {rmsg})"));
    }
    let status = preserved_record.get("status").and_then(Value::as_str).unwrap_or("recovery_required");
    if failures.is_empty() {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            &format!("{detail}; the pre-output receipt and the operation record (status `{status}`, commit journal included) are PRESERVED as evidence — nothing was deleted; the reservation was released and the idempotent reconcile may be retried"),
        )
    } else {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("{detail} AND the recovery bookkeeping was incomplete ({}) — the receipt and any persisted evidence are preserved; manual repair required", failures.join(", ")),
        )
    }
}
const INVOCATION_KIND: &str = "goal-run-invocations";
const VERIFICATION_KIND: &str = "goal-run-verifications";
const RECONCILIATION_KIND: &str = "goal-run-reconciliations";
/// Plane-owned staging area for reconcile output commits (#72 round 4): candidate outputs are
/// staged here BEFORE the pre-output receipt, so every refusal up to the commit step leaves the
/// target workspace untouched — literally, not rhetorically. An attempt's staging is PRESERVED
/// until that attempt terminates successfully (#72 round 5 finding 3): after a post-effect
/// failure or a crash it remains the immutable evidence of exactly what was declared.
const STAGING_KIND: &str = "goal-run-reconcile-staging";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Canonical JSON hash (serde_json BTreeMap key order — recomputable from the durable record).
fn sha256_canonical(value: &Value) -> String {
    sha256_hex(&serde_json::to_vec(value).unwrap_or_default())
}

/// Containment validator for a declared changed-file path (#72 round 5 finding 1): outputs are
/// canonical RELATIVE paths made of plain components only — an absolute path or a parent/
/// current-dir/root/prefix component can never cross a workspace boundary at any of the three
/// joins (candidate read, staging write, target commit).
fn contained_rel_path(file: &str) -> Result<std::path::PathBuf, String> {
    if file.trim().is_empty() {
        return Err("an empty output path is never a workspace file".to_string());
    }
    let p = std::path::Path::new(file);
    if p.is_absolute() {
        return Err(format!("'{file}' is absolute — outputs are declared relative to their workspace root"));
    }
    let mut normalized = std::path::PathBuf::new();
    for component in p.components() {
        match component {
            std::path::Component::Normal(seg) => normalized.push(seg),
            _ => {
                return Err(format!("'{file}' carries a parent/current-dir/root/prefix component — only normalized plain components cross into a workspace"));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(format!("'{file}' normalizes to nothing"));
    }
    Ok(normalized)
}

/// NON-MUTATING symlink-containment check (#72 round 5 finding 1), staging-time: walk to the
/// deepest EXISTING ancestor of the destination's parent and prove its canonical form is still
/// inside the canonical root. Directories that do not exist yet are created fresh at commit
/// time (a fresh directory cannot be a symlink); a pre-existing symlinked ancestor is caught
/// here BEFORE any receipt exists, with zero target mutation.
fn symlink_contained(canon_root: &std::path::Path, rel: &std::path::Path) -> Result<(), String> {
    let mut probe = canon_root
        .join(rel)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| canon_root.to_path_buf());
    while !probe.exists() {
        match probe.parent() {
            Some(parent) => probe = parent.to_path_buf(),
            None => break,
        }
    }
    let canon_probe = probe
        .canonicalize()
        .map_err(|e| format!("'{}' does not resolve ({e})", probe.display()))?;
    if !canon_probe.starts_with(canon_root) {
        return Err(format!("'{}' escapes the workspace through a symlinked ancestor ('{}' resolves outside)", rel.display(), probe.display()));
    }
    Ok(())
}

/// CRASH-DURABLE, DESCRIPTOR-RELATIVE single-file commit (#72 rounds 5 + 6): the destination
/// parent is reached by a NOFOLLOW openat walk from the PINNED target-root fd (a concurrent
/// ancestor swap cannot redirect the write — finding 3), the full content goes to a
/// target-local temporary sibling via openat(O_CREAT|O_EXCL|O_NOFOLLOW), is fsynced, renamed
/// atomically with renameat against the same pinned parent fd, and the parent directory fsync
/// is CHECKED (finding 1 — an unconfirmed rename is a failed commit, not a shrug). A crash at
/// any instant leaves the destination either absent or complete — never truncated.
fn commit_one(staged: &std::path::Path, target_root: &std::fs::File, rel: &std::path::Path) -> Result<(u64, String), String> {
    use std::io::Write;
    let parent = nofollow::pin_parent(target_root, rel, true)
        .map_err(|e| format!("'{}': pinned parent walk refused ({e}) — a symlinked or swapped ancestor never redirects a write", rel.display()))?;
    let file_name = rel
        .file_name()
        .ok_or_else(|| "destination has no file name".to_string())?;
    let bytes = std::fs::read(staged).map_err(|e| format!("staged read failed ({e})"))?;
    let sha = sha256_hex(&bytes);
    let tmp_name = std::ffi::OsString::from(format!(".{}.wal-tmp-{:x}", file_name.to_string_lossy(), nanos()));
    let write_result = (|| -> std::io::Result<()> {
        let mut f = nofollow::create_file_at(&parent, &tmp_name)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    if let Err(e) = write_result {
        nofollow::unlink_at(&parent, &tmp_name);
        return Err(format!("temporary write failed ({e})"));
    }
    if let Err(e) = nofollow::rename_at(&parent, &tmp_name, file_name) {
        nofollow::unlink_at(&parent, &tmp_name);
        return Err(format!("atomic rename failed ({e})"));
    }
    parent
        .sync_all()
        .map_err(|e| format!("parent directory sync failed ({e}) — the rename's durability is unconfirmed"))?;
    Ok((bytes.len() as u64, sha))
}

const GOAL_RUN_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run.v1";
const INVOCATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-invocation.v1";
const RECONCILIATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-reconciliation.v1";

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn safe(seg: &str) -> String {
    seg.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn bad(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

fn kernel_err(
    error: ioi_services::agentic::runtime::kernel::runtime_goal_run_admission::RuntimeGoalRunAdmissionError,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
        Json(json!({
            "ok": false,
            "error": { "code": error.code, "message": error.message, "details": error.details },
        })),
    )
}

pub(crate) fn load_goal_run(st: &DaemonState, goal_run_id: &str) -> Option<Value> {
    load(st, GOAL_RUN_KIND, goal_run_id)
}

fn load(st: &DaemonState, kind: &str, goal_run_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, kind)
        .into_iter()
        .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

async fn self_get(url: &str) -> Option<Value> {
    reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_millis(8000))
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

async fn self_post(url: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(url)
        .json(body)
        .timeout(Duration::from_millis(20000))
        .send()
        .await;
    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let value = resp.json::<Value>().await.unwrap_or(Value::Null);
            (status, value)
        }
        Err(err) => (0, json!({ "error": err.to_string() })),
    }
}

/// Live harness fact for the kernel planner — from the registry's own live probe projection.
pub(crate) fn fact_from_profile(profile: &Value, route_ref: &str, route_state: &str) -> Value {
    json!({
        "profile_ref": text(profile, "profile_ref"),
        "harness": text(profile, "harness"),
        "lifecycle_status": profile.pointer("/lifecycle/status").and_then(Value::as_str).unwrap_or(""),
        "execution_wiring": profile.pointer("/adapter/execution_wiring").and_then(Value::as_str).unwrap_or(""),
        "runnability_state": profile.pointer("/runnability/state").and_then(Value::as_str).unwrap_or("not_probed"),
        "provider_trust": profile.pointer("/adapter/provider_trust").and_then(Value::as_str).unwrap_or(""),
        "model_route_ref": route_ref,
        "model_route_state": route_state,
    })
}

/// The selected model route's (ref, availability state, model_id, endpoint) — the explicit ref
/// or the registry default. Read from the persisted registry (availability is probe truth).
pub(crate) fn route_fact(st: &DaemonState, explicit_ref: Option<&str>) -> (String, String, String, String) {
    let routes = read_record_dir(&st.data_dir, "model-route-registry");
    let route = routes.iter().find(|route| match explicit_ref {
        Some(wanted) => text(route, "route_ref") == wanted,
        None => route.get("default_route").and_then(Value::as_bool) == Some(true),
    });
    match route {
        Some(route) => (
            text(route, "route_ref").to_string(),
            route
                .pointer("/availability/state")
                .and_then(Value::as_str)
                .unwrap_or("declared")
                .to_string(),
            route
                .pointer("/model/model_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            route
                .pointer("/provider_binding/base_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        None => (String::new(), "unresolved".into(), String::new(), String::new()),
    }
}

pub(crate) async fn live_profiles(st: &DaemonState) -> Vec<Value> {
    self_get(&format!("{}/v1/hypervisor/harness-profiles?live=1", st.base_url))
        .await
        .and_then(|body| body.get("profiles").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

pub(crate) fn profile_by_harness<'a>(profiles: &'a [Value], harness: &str) -> Option<&'a Value> {
    profiles
        .iter()
        .find(|profile| text(profile, "harness") == harness)
}

// ---------------------------------------------------------------------------
// create / list / get
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_runs_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let goal = text(&body, "goal").trim().to_string();
    let session_ref = text(&body, "session_ref").to_string();
    let Some(target_session) = load_session_record(&st, &session_ref) else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_target_session_unresolved",
            "A GoalRun binds to an existing session (its workspace is the reconciliation target).",
        );
    };
    let target_workspace = text(&target_session, "workspace_root").to_string();
    if target_workspace.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_target_workspace_missing",
            "The target session has no provisioned workspace.",
        );
    }
    let project_ref = {
        let recorded = text(&target_session, "project_ref");
        if recorded.starts_with("project:") {
            recorded.to_string()
        } else {
            "project:hypervisor".to_string()
        }
    };

    // Live registry facts for the three roles (probe truth, never fabricated).
    let profiles = live_profiles(&st).await;
    let (route_ref, route_state, _, _) =
        route_fact(&st, body.get("model_route_ref").and_then(Value::as_str));
    let conductor = profile_by_harness(&profiles, "hypervisor_worker")
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .unwrap_or(Value::Null);
    let implementer_candidates: Vec<Value> = ["opencode", "deepseek_tui"]
        .iter()
        .filter_map(|harness| profile_by_harness(&profiles, harness))
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .collect();

    let goal_run_id = format!("gr_{:x}", nanos());
    let goal_ref = format!("goal://{goal_run_id}");
    let kernel = RuntimeKernelService::new();

    let topology = match kernel.select_goal_run_role_topology(&json!({
        "goal_ref": goal_ref,
        "conductor": conductor,
        "implementer_candidates": implementer_candidates,
    })) {
        Ok(selected) => selected,
        Err(error) => return kernel_err(error),
    };
    let admission = match kernel.admit_goal_run(
        &json!({
            "goal_ref": goal_ref,
            "normalized_goal": goal,
            "target_session_ref": session_ref,
            "project_ref": project_ref,
            "orchestration_policy": "parallel_implement_reconcile",
            "max_parallel_invocations": 2,
            "receipt_required": true,
            "authority_scope_refs": ["scope:goal.run.orchestrate"],
            "state_root_ref": format!("agentgres://state-root/goal-run/{goal_run_id}"),
        }),
        &iso_now(),
    ) {
        Ok(admitted) => admitted,
        Err(error) => return kernel_err(error),
    };

    // The typed ladder — durable coordination objects. The goal text lives ONCE as the
    // normalized goal; the task brief is the durable implementer contract (no raw prompts).
    let implementer_refs: Vec<String> = topology
        .get("implementer_refs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let harness_of = |profile_ref: &str| -> String {
        profiles
            .iter()
            .find(|p| text(p, "profile_ref") == profile_ref)
            .map(|p| text(p, "harness").to_string())
            .unwrap_or_default()
    };
    let role_keys = ["implementer_a", "implementer_b"];
    let mut context_cells = vec![json!({
        "context_cell_id": format!("context_cell://cc_{goal_run_id}_conductor"),
        "goal_ref": goal_ref,
        "role": "conductor",
        "harness_ref": text(&topology, "conductor_ref"),
        "model_route_ref": route_ref,
        "status": "open",
    })];
    let mut context_leases: Vec<Value> = Vec::new();
    let mut task_briefs: Vec<Value> = Vec::new();
    let mut handoffs: Vec<Value> = Vec::new();
    for (index, profile_ref) in implementer_refs.iter().enumerate() {
        let role_key = role_keys.get(index).copied().unwrap_or("implementer_x");
        let cell_ref = format!("context_cell://cc_{goal_run_id}_{role_key}");
        let lease_ref = format!("context_lease://cl_{goal_run_id}_{role_key}");
        let brief_ref = format!("task_brief://tb_{goal_run_id}_{role_key}");
        context_cells.push(json!({
            "context_cell_id": cell_ref,
            "goal_ref": goal_ref,
            "role": "implementer",
            "role_key": role_key,
            "harness_ref": profile_ref,
            "harness": harness_of(profile_ref),
            "model_route_ref": route_ref,
            "context_lease_refs": [lease_ref],
            "status": "open",
        }));
        context_leases.push(json!({
            "context_lease_id": lease_ref,
            "goal_ref": goal_ref,
            "context_cell_ref": cell_ref,
            "issued_to": profile_ref,
            "lease_kind": "worktree",
            // The implementer's writable surface is ITS candidate session workspace only.
            "allowed_ref_patterns": [format!("workspace://goal-run/{goal_run_id}/{role_key}")],
            "denied_ref_patterns": ["secret://", "unsafe_plaintext://", format!("workspace://session/{}", safe(&session_ref))],
            "budget_ref": format!("budget://goal-run/{goal_run_id}/invocation"),
            "ttl_seconds": 3600,
            "receipt_required": true,
            "status": "active",
        }));
        task_briefs.push(json!({
            "task_brief_id": brief_ref,
            "goal_ref": goal_ref,
            "handoff_ref": format!("handoff://ho_{goal_run_id}_{role_key}"),
            "objective": goal,
            "objective_class": "implement",
            "scope_refs": [format!("workspace://goal-run/{goal_run_id}/{role_key}")],
            "constraints": ["write only inside the leased candidate workspace"],
            "do_not_touch_refs": [format!("workspace://session/{}", safe(&session_ref))],
            "context_lease_refs": [lease_ref],
            "output_contract": {
                "changed_files_required": true,
                "diff_summary_required": false,
                "tests_required": false,
                "blocker_report_required": true,
                "receipt_refs_required": true,
            },
            "status": "ready",
        }));
        handoffs.push(json!({
            "handoff_id": format!("handoff://ho_{goal_run_id}_{role_key}"),
            "goal_ref": goal_ref,
            "from_context_cell_ref": format!("context_cell://cc_{goal_run_id}_conductor"),
            "to_context_cell_ref": cell_ref,
            "handoff_kind": "task_brief",
            "payload_ref": brief_ref,
            "context_lease_refs": [lease_ref],
            "status": "sent",
        }));
    }
    context_cells.push(json!({
        "context_cell_id": format!("context_cell://cc_{goal_run_id}_verifier"),
        "goal_ref": goal_ref,
        "role": "verifier",
        "harness_ref": text(&topology, "verifier_ref"),
        "model_route_ref": route_ref,
        "status": "open",
    }));

    let now = iso_now();
    let record = json!({
        "schema_version": GOAL_RUN_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "origin_surface": "api",
        "normalized_goal": goal,
        "target_session_ref": session_ref,
        "target_workspace_root": target_workspace,
        "project_ref": project_ref,
        "orchestration_policy": "parallel_implement_reconcile",
        "max_parallel_invocations": 2,
        "role_topology": topology,
        "role_topology_ref": format!("role_topology://rt_{goal_run_id}"),
        "grounding_loop": {
            "goal_loop_id": format!("goal_loop://gl_{goal_run_id}"),
            "goal_ref": goal_ref,
            "conductor_context_cell_ref": format!("context_cell://cc_{goal_run_id}_conductor"),
            "loop_iteration": 0,
            "phase": "receive_intent",
            "escalation_state": "none",
        },
        "context_cells": context_cells,
        "context_leases": context_leases,
        "task_briefs": task_briefs,
        "handoffs": handoffs,
        "verifier_path": {
            "verifier_path_id": format!("verifier_path://vp_{goal_run_id}"),
            "owner_ref": text(&topology, "verifier_ref"),
            "verification_kind": "deterministic",
            "required_evidence": [
                "reported files exist with content in the candidate workspace",
                "driver exit_code == 0",
                "report equals disk truth",
            ],
            "independence_requirement": "none",
            "replay_required": false,
            "status": "active",
        },
        "admission": { "admission_id": text(&admission, "admission_id"), "receipt_refs": admission.get("receipt_refs").cloned().unwrap_or(json!([])) },
        // Optional launch-policy provenance (IOI Agent lane) — advanced/proof metadata only.
        "policy_ref": body.get("policy_ref").cloned().unwrap_or(Value::Null),
        "invocation_refs": [],
        "verification_refs": [],
        "reconciliation_ref": Value::Null,
        "blockers": [],
        "active_loop_phase": "receive_intent",
        "continuation_state": "open",
        "status": "draft",
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, GOAL_RUN_KIND, &goal_run_id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "goal_run": record })))
}

pub(crate) async fn handle_goal_runs_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut runs = read_record_dir(&st.data_dir, GOAL_RUN_KIND);
    if let Some(session) = query.get("session") {
        runs.retain(|run| text(run, "target_session_ref") == session);
    }
    runs.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    (StatusCode::OK, Json(json!({ "ok": true, "goal_runs": runs })))
}

pub(crate) async fn handle_goal_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load(&st, GOAL_RUN_KIND, &id) {
        Some(run) => (StatusCode::OK, Json(json!({ "ok": true, "goal_run": run }))),
        None => bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun."),
    }
}

// ---------------------------------------------------------------------------
// start — wallet-gated, then the two implementer invocations run CONCURRENTLY
// ---------------------------------------------------------------------------

/// Start side-record persist failure (#72 round 4 finding 2): the wallet crossing and the
/// harness invocations already EXECUTED, so this can become neither a 200 with dangling refs
/// nor a silent release (a restored `draft` would re-open a duplicate wallet-gated crossing).
/// The run KEEPS its reservation, now marked `recovery_required` with the failure and the
/// executed-invocation evidence embedded durably on the run record itself — the side-record
/// family that refused the write is exactly the family that cannot hold the attempt evidence.
/// Recovery is the token-addressed, receipted lifecycle-recovery transition.
fn start_evidence_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    family: &str,
    record_id: &str,
    error: &str,
    executed: &[Value],
) -> (StatusCode, Json<Value>) {
    let evidence: Vec<Value> = executed
        .iter()
        .map(|i| {
            json!({
                "harness_invocation_id": text(i, "harness_invocation_id"),
                "role_key": text(i, "role_key"),
                "status": text(i, "status"),
            })
        })
        .collect();
    let marked = update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "the reservation token changed while marking the start for recovery".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            let mut op = obj.get("lifecycle_op").cloned().unwrap_or_else(|| json!({}));
            if let Some(o) = op.as_object_mut() {
                o.insert("phase".into(), json!("recovery_required"));
                o.insert(
                    "failure".into(),
                    json!({ "code": "goal_run_side_record_persist_failed", "family": family, "record_id": record_id, "error": error, "at": iso_now() }),
                );
                o.insert("executed_invocations".into(), json!(evidence));
            }
            obj.insert("lifecycle_op".into(), op);
        },
    );
    match marked {
        Ok(_) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_side_record_persist_failed",
            &format!("the {family} record '{record_id}' did not persist ({error}); NO ref was bound to the run, which keeps its `starting` reservation marked recovery_required with the executed-invocation evidence embedded durably — no duplicate wallet crossing is possible; recover via the token-addressed lifecycle-recovery transition"),
        ),
        Err((rcode, rmsg)) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("the {family} record '{record_id}' did not persist ({error}) AND the recovery marking did not commit ({rcode}: {rmsg}) — manual repair required"),
        ),
    }
}

struct InvocationPlan {
    role_key: String,
    profile_ref: String,
    harness: String,
    cell_ref: String,
    brief_ref: String,
    invocation_ref: String,
    objective: String,
    /// Scoped intelligence projection for THIS harness (portable memory → rendered summary;
    /// the raw MemoryEntry records never reach the driver).
    memory_projection_ref: String,
    projection_summary: String,
}

/// One admitted implementer invocation, end to end: isolated candidate session → adapter driver
/// spawn → events/receipt/transcript → typed ImplementationResultPayload. Returns the durable
/// invocation record (completed or failed; failure is explicit, never silent).
async fn run_invocation(
    st: Arc<DaemonState>,
    goal_run_id: String,
    goal_ref: String,
    plan: InvocationPlan,
    route_ref: String,
    capability_lease_ref: String,
) -> Value {
    let started_at = iso_now();
    let candidate_session_ref = format!("session:goalrun-{}-{}", goal_run_id, plan.role_key);
    let fail = |failure_kind: &str, message: String, session_ref: &str, workspace: &str| -> Value {
        json!({
            "schema_version": INVOCATION_SCHEMA_VERSION,
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "harness_invocation_id": plan.invocation_ref,
            "role_key": plan.role_key,
            "context_cell_ref": plan.cell_ref,
            "task_brief_ref": plan.brief_ref,
            "harness_ref": plan.profile_ref,
            "harness": plan.harness,
            "model_route_ref": route_ref,
            "session_ref": session_ref,
            "candidate_workspace_root": workspace,
            "status": "failed",
            "implementation_result": {
                "implementation_result_id": format!("implementation_result://ir_{}_{}", goal_run_id, plan.role_key),
                "goal_ref": goal_ref,
                "harness_invocation_ref": plan.invocation_ref,
                "harness_profile_ref": plan.profile_ref,
                "model_route_ref": route_ref,
                "status": "failed",
                "failure_kind": failure_kind,
                "summary": message,
                "changed_files": [],
                "candidate_artifact_refs": [],
                "receipt_refs": [],
            },
            "blocker": { "reason_code": failure_kind, "message": message },
            "started_at": started_at,
            "finished_at": iso_now(),
        })
    };

    // Isolated candidate session (its workspace IS the candidate namespace).
    let (status, created) = self_post(
        &format!("{}/v1/hypervisor/sessions", st.base_url),
        &json!({
            "session_ref": candidate_session_ref,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": route_ref,
        }),
    )
    .await;
    if !(200..300).contains(&(status as usize)) {
        return fail(
            "candidate_session_create_failed",
            format!(
                "candidate session create returned {status}: {}",
                created.pointer("/error/code").and_then(Value::as_str).unwrap_or("unknown")
            ),
            &candidate_session_ref,
            "",
        );
    }
    let Some(session_record) = load_session_record(&st, &candidate_session_ref) else {
        return fail(
            "candidate_session_record_missing",
            "candidate session record not persisted".into(),
            &candidate_session_ref,
            "",
        );
    };
    let workspace = text(&session_record, "workspace_root").to_string();

    // Model + endpoint from the session's admitted route binding (bound at create above).
    let binding =
        super::model_routes::resolve_session_route_binding(&st.data_dir, &candidate_session_ref);
    let (model, endpoint) = match &binding {
        Some((model_id, endpoint, _, _)) => (model_id.clone(), Some(endpoint.clone())),
        None => (
            std::env::var("IOI_HYPERVISOR_MODEL").unwrap_or_else(|_| "qwen2.5:7b".into()),
            std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM").ok().filter(|v| !v.is_empty()),
        ),
    };

    let driver = match resolve_adapter_driver(&session_record, &model, &workspace, endpoint.as_deref()) {
        Ok(Some(driver)) => driver,
        Ok(None) => {
            return fail(
                "adapter_driver_unresolved",
                "implementer session has no wired adapter driver".into(),
                &candidate_session_ref,
                &workspace,
            )
        }
        Err((reason, message)) => {
            return fail(reason, message, &candidate_session_ref, &workspace)
        }
    };

    // REAL adapter execution: the harness drives the model and edits ONLY its candidate
    // workspace (bwrap-confined by the driver lane). The rendered input is adapter-private;
    // the durable contract stays the task brief.
    let (_, argv) = driver;
    let delivered_objective = if plan.projection_summary.is_empty() {
        plan.objective.clone()
    } else {
        format!(
            "{}\n\n[Workspace intelligence — scoped projection]\n{}",
            plan.objective, plan.projection_summary
        )
    };
    let outcome = run_host_spawn_lane(&argv, &workspace, &delivered_objective, endpoint.as_deref()).await;

    // Persist normalized adapter events with the goal-run linkage.
    let run_tag = format!("{}_{}_{:x}", safe(&goal_run_id), plan.role_key, nanos());
    let mut adapter_event_refs: Vec<String> = Vec::new();
    for (index, event) in outcome.adapter_events.iter().enumerate() {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("hae_{run_tag}_{index}"));
        let mut stored = event.clone();
        stored["goal_run_ref"] = json!(goal_ref);
        stored["harness_invocation_ref"] = json!(plan.invocation_ref);
        stored["session_ref"] = json!(candidate_session_ref);
        stored["sequence"] = json!(index + 1);
        let _ = persist_record(&st.data_dir, "harness-adapter-events", &event_id, &stored);
        adapter_event_refs.push(format!("agentgres://harness-adapter-event/{event_id}"));
    }

    let exit_status = if outcome.ok { "success" } else { "failure" };
    let candidate_artifact_refs: Vec<String> = outcome
        .files_written
        .iter()
        .map(|file| format!("artifact://goal-run/{}/{}/{}", goal_run_id, plan.role_key, file))
        .collect();

    // Invocation receipt (admitted authority named).
    let receipt_ref = format!(
        "receipt://hypervisor/goal-run-invocation/{}_{}",
        safe(&goal_run_id),
        plan.role_key
    );
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.goal-run.invoke",
        "goal_run_ref": goal_ref,
        "harness_invocation_ref": plan.invocation_ref,
        "role_key": plan.role_key,
        "harness": plan.harness,
        "harness_profile_ref": plan.profile_ref,
        "model_route_ref": route_ref,
        "session_ref": candidate_session_ref,
        "exit_status": exit_status,
        "exit_code": outcome.exit_code,
        "files_written": outcome.files_written,
        "adapter_event_refs": adapter_event_refs,
        "capability_lease_ref": capability_lease_ref,
        "started_at": started_at,
        "finished_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    // Tamper-evident transcript (state_root computed by the transcript plane).
    let transcript_run = super::harness_routes::post_op_transcript(
        &st.base_url,
        "goal_run_execute",
        &plan.profile_ref,
        &json!({
            "goal_run_ref": goal_ref,
            "role_key": plan.role_key,
            "session_ref": candidate_session_ref,
            "harness": plan.harness,
            "exit_status": exit_status,
            "files_written": outcome.files_written,
            "adapter_event_count": outcome.adapter_events.len(),
            "implementation_result": outcome.implementation_result,
            "receipt_ref": receipt_ref,
        }),
    )
    .await;
    let state_root = match &transcript_run {
        Some(run_id) => self_get(&format!(
            "{}/v1/hypervisor/agent-run-transcripts/{run_id}",
            st.base_url
        ))
        .await
        .and_then(|body| {
            body.pointer("/run/state_root")
                .or_else(|| body.get("state_root"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default(),
        None => String::new(),
    };

    let failure_kind = if outcome.ok {
        Value::Null
    } else if outcome.timed_out {
        json!("timeout")
    } else if outcome.spawn_error.is_some() {
        json!("spawn_error")
    } else {
        json!("exit_nonzero")
    };
    let shim = argv
        .iter()
        .find(|arg| arg.ends_with("-driver.mjs"))
        .cloned()
        .unwrap_or_default();
    json!({
        "schema_version": INVOCATION_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "harness_invocation_id": plan.invocation_ref,
        "role_key": plan.role_key,
        "context_cell_ref": plan.cell_ref,
        "task_brief_ref": plan.brief_ref,
        "harness_ref": plan.profile_ref,
        "harness": plan.harness,
        "model_route_ref": route_ref,
        "session_ref": candidate_session_ref,
        "candidate_workspace_root": workspace,
        "status": if outcome.ok { "completed" } else { "failed" },
        "adapter_event_refs": adapter_event_refs,
        "adapter_event_count": outcome.adapter_events.len(),
        "memory_projection_ref": plan.memory_projection_ref,
        "implementation_result": {
            "implementation_result_id": format!("implementation_result://ir_{}_{}", goal_run_id, plan.role_key),
            "goal_ref": goal_ref,
            "harness_invocation_ref": plan.invocation_ref,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": route_ref,
            "memory_projection_ref": plan.memory_projection_ref,
            "command_contract_ref": format!("command-contract://harness-shim/{}", safe(&shim)),
            "workspace_ref": format!("workspace://goal-run/{}/{}", goal_run_id, plan.role_key),
            "workspace_root": workspace,
            "candidate_artifact_refs": candidate_artifact_refs,
            "changed_files": outcome.files_written,
            "summary": outcome.summary,
            "status": if outcome.ok { "completed" } else { "failed" },
            "failure_kind": failure_kind,
            "receipt_refs": [receipt_ref],
            "transcript_run_ref": transcript_run,
            "state_root": state_root,
            "driver_result": outcome.implementation_result,
        },
        "started_at": started_at,
        "finished_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    })
}

pub(crate) async fn handle_goal_run_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // OPERATION RESERVATION (#72 round 3 finding 2): `start` is one-shot and wallet-gated — the
    // draft precheck and the transition to `starting` are ONE atomic CAS under the seam, before
    // any await and before the wallet crossing. Exactly one concurrent start wins the
    // reservation; the loser refuses typed, so a duplicate wallet-gated start is impossible.
    let op_token = format!("lop_{:x}", nanos());
    let reserved_at = iso_now();
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if text(fresh, "status") != "draft" {
                return Err((
                    "goal_run_already_started".to_string(),
                    "This GoalRun has already been started.".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!("starting"));
            obj.insert(
                "lifecycle_op".into(),
                json!({ "op": "start", "token": op_token.clone(), "reserved_at": reserved_at, "from_status": "draft" }),
            );
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal = text(&run, "normalized_goal").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    // Wallet authority gate — one admitted crossing covers the run's bounded invocations; the
    // lease ref is named on every invocation receipt. 403 challenge shape identical to execute.
    // A refusal here happened before any side effect: release the reservation so the draft is
    // exactly re-runnable; a failed release is itself a typed 5xx, never a silent wedge.
    let capability_lease_ref =
        match execute_authority_gate(&body, &goal_ref, &target_workspace, &goal) {
            Ok(lease) => lease,
            Err(challenge) => {
                if let Err((rcode, rmsg)) =
                    release_lifecycle_reservation(&st.data_dir, &id, &op_token, "draft")
                {
                    return bad(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "goal_run_release_failed",
                        &format!("the start authority gate refused AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
                    );
                }
                return (StatusCode::FORBIDDEN, Json(challenge));
            }
        };

    // Refresh live facts and admit each implementer invocation (fail-closed per role; a
    // rejected role becomes an explicit failed invocation + blocker, the run continues).
    let profiles = live_profiles(&st).await;
    let (route_ref, route_state, _, _) = route_fact(
        &st,
        run.pointer("/role_topology/model_route_ref").and_then(Value::as_str),
    );
    let kernel = RuntimeKernelService::new();
    let empty = Vec::new();
    let cells = run
        .get("context_cells")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .clone();
    let goal_run_id = text(&run, "goal_run_id").to_string();

    let mut admitted_plans: Vec<InvocationPlan> = Vec::new();
    let mut invocations: Vec<Value> = Vec::new();
    for cell in cells.iter().filter(|c| text(c, "role") == "implementer") {
        let role_key = text(cell, "role_key").to_string();
        let profile_ref = text(cell, "harness_ref").to_string();
        let harness = text(cell, "harness").to_string();
        let invocation_ref = format!("harness_invocation://hi_{goal_run_id}_{role_key}");
        let brief_ref = format!("task_brief://tb_{goal_run_id}_{role_key}");
        let fact = profiles
            .iter()
            .find(|p| text(p, "profile_ref") == profile_ref)
            .map(|p| fact_from_profile(p, &route_ref, &route_state))
            .unwrap_or(Value::Null);
        let mut request = fact.clone();
        if let Some(object) = request.as_object_mut() {
            object.insert("goal_ref".into(), json!(goal_ref));
            object.insert("role".into(), json!("implementer"));
            object.insert("task_brief_ref".into(), json!(brief_ref));
            object.insert("context_cell_ref".into(), json!(text(cell, "context_cell_id")));
            object.insert(
                "session_ref".into(),
                json!(format!("session:goalrun-{goal_run_id}-{role_key}")),
            );
            object.insert("invocation_ref".into(), json!(invocation_ref));
        }
        // Attach the harness-scoped MemoryProjection when the IOI Agent lane created one
        // (matched by goal_run_ref + harness ref; absent = no projection, honest empty).
        let projection = read_record_dir(&st.data_dir, "memory-projections")
            .into_iter()
            .find(|p| {
                text(p, "goal_run_ref") == goal_ref && text(p, "harness_profile_ref") == profile_ref
            });
        match kernel.admit_goal_run_harness_invocation(&request, &iso_now()) {
            Ok(_admitted) => admitted_plans.push(InvocationPlan {
                role_key,
                profile_ref,
                harness,
                cell_ref: text(cell, "context_cell_id").to_string(),
                brief_ref,
                invocation_ref,
                objective: goal.clone(),
                memory_projection_ref: projection
                    .as_ref()
                    .map(|p| text(p, "projection_ref").to_string())
                    .unwrap_or_default(),
                projection_summary: projection
                    .as_ref()
                    .map(|p| text(p, "projection_summary").to_string())
                    .unwrap_or_default(),
            }),
            Err(error) => {
                // Explicit partial: the role is recorded as a failed invocation with the
                // planner's reason — never silently dropped.
                invocations.push(json!({
                    "schema_version": INVOCATION_SCHEMA_VERSION,
                    "goal_run_id": goal_run_id,
                    "goal_ref": goal_ref,
                    "harness_invocation_id": invocation_ref,
                    "role_key": role_key,
                    "harness_ref": profile_ref,
                    "harness": harness,
                    "status": "failed",
                    "implementation_result": {
                        "implementation_result_id": format!("implementation_result://ir_{goal_run_id}_{role_key}"),
                        "status": "failed",
                        "failure_kind": error.code,
                        "summary": error.message,
                        "changed_files": [],
                        "candidate_artifact_refs": [],
                    },
                    "blocker": { "reason_code": error.code, "message": error.message, "details": error.details },
                    "started_at": iso_now(),
                    "finished_at": iso_now(),
                }));
            }
        }
    }
    if admitted_plans.is_empty() && invocations.is_empty() {
        // Refused with no durable side effect — release the reservation (draft is re-runnable).
        if let Err((rcode, rmsg)) =
            release_lifecycle_reservation(&st.data_dir, &id, &op_token, "draft")
        {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_release_failed",
                &format!("the start refused (no implementer cells) AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
            );
        }
        return bad(
            StatusCode::CONFLICT,
            "goal_run_no_implementer_cells",
            "This GoalRun has no implementer context cells.",
        );
    }

    // Bounded parallel execution (budget ≤ 2, planner-enforced at create).
    let mut executed: Vec<Value> = match admitted_plans.len() {
        0 => Vec::new(),
        1 => {
            let plan = admitted_plans.remove(0);
            vec![
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                )
                .await,
            ]
        }
        _ => {
            let plan_b = admitted_plans.remove(1);
            let plan_a = admitted_plans.remove(0);
            let (a, b) = tokio::join!(
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan_a,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                ),
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan_b,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                )
            );
            vec![a, b]
        }
    };
    invocations.append(&mut executed);
    invocations.sort_by(|a, b| text(a, "role_key").cmp(text(b, "role_key")));

    // Conductor-run deterministic VerifierPath over each candidate (report ⇔ disk truth).
    let mut verification_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let role_key = text(invocation, "role_key");
        let verification_id = format!("gv_{}_{}", safe(&goal_run_id), role_key);
        let workspace = text(invocation, "candidate_workspace_root");
        let changed: Vec<&str> = invocation
            .pointer("/implementation_result/changed_files")
            .and_then(Value::as_array)
            .map(|files| files.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let completed = text(invocation, "status") == "completed";
        let mut checks: Vec<Value> = vec![json!({
            "check": "invocation_completed_exit_zero",
            "pass": completed,
        })];
        let mut files_real = completed && !changed.is_empty();
        if completed {
            for file in &changed {
                // Containment is part of the verdict (#72 round 5 finding 1): a path that
                // escapes its workspace never verifies, so it can never be selected for the
                // reconcile copy pipeline.
                let real = match contained_rel_path(file) {
                    Ok(rel) => {
                        let path = std::path::Path::new(workspace).join(rel);
                        path.exists()
                            && std::fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false)
                    }
                    Err(_) => false,
                };
                checks.push(json!({ "check": "reported_file_exists_with_content", "file": file, "pass": real }));
                files_real &= real;
            }
            checks.push(json!({ "check": "workspace_mutation_reported", "pass": !changed.is_empty() }));
        }
        let verdict = completed && files_real;
        let verification = json!({
            "verification_id": verification_id,
            "verification_ref": format!("agentgres://goal-run-verification/{verification_id}"),
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "harness_invocation_ref": text(invocation, "harness_invocation_id"),
            "implementation_result_ref": invocation
                .pointer("/implementation_result/implementation_result_id")
                .cloned()
                .unwrap_or(Value::Null),
            "verifier_path_ref": format!("verifier_path://vp_{goal_run_id}"),
            "verification_kind": "deterministic",
            "verdict": if verdict { "pass" } else { "fail" },
            "checks": checks,
            "verified_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        });
        // CHECKED persist (#72 round 4 finding 2): a ref is bound ONLY after its record is
        // durable — a failed side-record write refuses typed with recovery state, never a 200
        // over nonexistent records.
        if let Err(e) = persist_record(&st.data_dir, VERIFICATION_KIND, &verification_id, &verification) {
            return start_evidence_abort(&st.data_dir, &goal_run_id, &op_token, VERIFICATION_KIND, &verification_id, &format!("{e}"), &invocations);
        }
        verification_refs.push(format!("agentgres://goal-run-verification/{verification_id}"));
    }

    // Persist invocation records + update the run (checked, same discipline).
    let mut invocation_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let record_id = format!(
            "{}_{}",
            safe(&goal_run_id),
            text(invocation, "role_key")
        );
        if let Err(e) = persist_record(&st.data_dir, INVOCATION_KIND, &record_id, invocation) {
            return start_evidence_abort(&st.data_dir, &goal_run_id, &op_token, INVOCATION_KIND, &record_id, &format!("{e}"), &invocations);
        }
        invocation_refs.push(text(invocation, "harness_invocation_id").to_string());
    }
    let blockers: Vec<Value> = invocations
        .iter()
        .filter(|invocation| text(invocation, "status") != "completed")
        .filter_map(|invocation| invocation.get("blocker").cloned().or_else(|| {
            Some(json!({
                "reason_code": invocation.pointer("/implementation_result/failure_kind").cloned().unwrap_or(json!("failed")),
                "message": invocation.pointer("/implementation_result/summary").cloned().unwrap_or(json!("")),
                "role_key": text(invocation, "role_key"),
            }))
        }))
        .collect();
    let any_verified = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .iter()
        .any(|v| text(v, "goal_ref") == goal_ref && text(v, "verdict") == "pass");
    let partial = !blockers.is_empty();
    // FINALIZATION (#72 rounds 2 + 3): the lifecycle fields this handler OWNS merge onto the
    // LATEST record through the shared CAS seam (a stale-snapshot persist would erase the room
    // plane's reciprocal stamp), and the commit is TOKEN-GUARDED — it lands only while this
    // request still holds its reservation. A seam failure is a typed 5xx, never a 200: the
    // reservation (status `starting` + token) is preserved DELIBERATELY, because releasing to
    // `draft` after the wallet crossing would re-open the run to a duplicate wallet-gated start.
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str)
                != Some(op_token.as_str())
            {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "start finalization no longer holds the reservation token — refusing to commit".to_string(),
                ));
            }
            Ok(())
        },
        |object| {
            object.insert("status".into(), json!("active"));
            object.insert("active_loop_phase".into(), json!("verify"));
            object.insert(
                "continuation_state".into(),
                json!(if any_verified { "verifying" } else { "blocked" }),
            );
            object.insert("invocation_refs".into(), json!(invocation_refs));
            object.insert("verification_refs".into(), json!(verification_refs));
            object.insert("blockers".into(), json!(blockers));
            object.insert("partial_result".into(), json!(partial));
            object.insert("capability_lease_ref".into(), json!(capability_lease_ref));
            object.insert("updated_at".into(), json!(iso_now()));
            object.remove("lifecycle_op");
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => {
            return bad(
                seam_status(&code),
                "goal_run_finalize_failed",
                &format!("start executed but its finalization did not commit ({code}: {msg}); invocation and verification records are durable and the run remains reserved (`starting`) — no duplicate start is possible; recover via the token-addressed lifecycle-recovery transition"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "goal_run": run,
            "invocations": invocations,
            "partial_result": partial,
            "blockers": run.get("blockers").cloned().unwrap_or(json!([])),
        })),
    )
}

// ---------------------------------------------------------------------------
// reconcile — the ONLY lane into the target workspace
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_run_reconcile(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // OPERATION RESERVATION (#72 round 3 finding 2): reconcile is one-shot — `active ->
    // reconciling` is reserved atomically with a fresh operation token BEFORE any await, so of
    // two simultaneous reconciles exactly one wins; the loser sees `reconciling` in the SAME
    // CAS predicate and refuses typed. Finalization commits only while it still holds this
    // token, and every refusal/rollback path releases the reservation back to `active`.
    let op_token = format!("lop_{:x}", nanos());
    let reserved_at = iso_now();
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if text(fresh, "status") != "active" {
                return Err((
                    "goal_run_not_reconcilable".to_string(),
                    "Reconciliation applies to a started (active) GoalRun exactly once.".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!("reconciling"));
            obj.insert(
                "lifecycle_op".into(),
                json!({
                    "op": "reconcile",
                    "token": op_token.clone(),
                    "reserved_at": reserved_at,
                    "from_status": "active",
                    // The attempt this reservation is executing (#72 round 6 finding 2): crash
                    // recovery binds to it, retains it, and receipts it — never orphans it.
                    "attempt_ref": format!("reconciliation_result://rc_{}_{}", safe(&id), safe(&op_token)),
                }),
            );
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal_run_id = text(&run, "goal_run_id").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    let invocations: Vec<Value> = read_record_dir(&st.data_dir, INVOCATION_KIND)
        .into_iter()
        .filter(|invocation| text(invocation, "goal_ref") == goal_ref)
        .collect();
    let verifications: Vec<Value> = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .into_iter()
        .filter(|verification| text(verification, "goal_ref") == goal_ref)
        .collect();
    let verdict_of = |invocation: &Value| -> bool {
        verifications.iter().any(|verification| {
            verification
                .get("harness_invocation_ref")
                .and_then(Value::as_str)
                == invocation.get("harness_invocation_id").and_then(Value::as_str)
                && text(verification, "verdict") == "pass"
        })
    };
    let mut passed: Vec<&Value> = invocations.iter().filter(|i| verdict_of(i)).collect();
    passed.sort_by(|a, b| text(a, "role_key").cmp(text(b, "role_key")));
    let result_ref = |invocation: &Value| -> String {
        invocation
            .pointer("/implementation_result/implementation_result_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let changed_of = |invocation: &Value| -> Vec<String> {
        invocation
            .pointer("/implementation_result/changed_files")
            .and_then(Value::as_array)
            .map(|files| files.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };

    // Deterministic strategy selection.
    let (merge_strategy, selected, reason_code): (&str, Vec<&Value>, String) = if passed.is_empty()
    {
        ("none_blocked", Vec::new(), "no_verified_candidate".to_string())
    } else if passed.len() >= 2 {
        let files_a = changed_of(passed[0]);
        let files_b = changed_of(passed[1]);
        let disjoint = files_a.iter().all(|f| !files_b.contains(f));
        if disjoint {
            (
                "merge_disjoint",
                vec![passed[0], passed[1]],
                "all_candidates_verified_disjoint".to_string(),
            )
        } else {
            (
                "select_single_best",
                vec![passed[0]],
                "overlapping_candidates_first_verified_selected".to_string(),
            )
        }
    } else {
        (
            "select_single_best",
            vec![passed[0]],
            "single_verified_candidate".to_string(),
        )
    };
    let selected_refs: Vec<String> = selected.iter().map(|i| result_ref(i)).collect();
    let rejected_refs: Vec<String> = invocations
        .iter()
        .filter(|i| !selected_refs.contains(&result_ref(i)))
        .map(|i| result_ref(i))
        .filter(|r| !r.is_empty())
        .collect();
    let verifier_evidence_refs: Vec<String> = verifications
        .iter()
        .map(|v| text(v, "verification_ref").to_string())
        .collect();

    let kernel = RuntimeKernelService::new();
    let admission = match kernel.admit_goal_run_reconciliation(
        &json!({
            "goal_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "verifier_evidence_refs": verifier_evidence_refs,
            "reason_code": reason_code,
            "receipt_required": true,
        }),
        &iso_now(),
    ) {
        Ok(admitted) => admitted,
        Err(error) => {
            // Admission refused with nothing persisted — release the reservation so the run
            // stays exactly retryable; a failed release is a typed 5xx, never a silent wedge.
            if let Err((rcode, rmsg)) =
                release_lifecycle_reservation(&st.data_dir, &goal_run_id, &op_token, "active")
            {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "goal_run_release_failed",
                    &format!("reconciliation admission refused AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
                );
            }
            return kernel_err(error);
        }
    };

    // DECLARE-BEFORE-DO OUTPUT COMMIT (#72 rounds 4 + 5). Order: VALIDATE + STAGE the selected
    // candidate outputs into a plane-owned staging area (no target-workspace effect), persist
    // the PRE-OUTPUT receipt, persist the operation record (`status: committing`), and only
    // then commit staged outputs into the target under a crash-durable per-file WAL journal.
    // Failures BEFORE the commit clean up completely — "nothing changed" is literally true,
    // target included. From the moment output MAY have reached the target, NOTHING is deleted:
    // failures update the operation record to a recovery status, preserve the receipt AND the
    // staged attempt, and the run retains every attempt ref.
    //
    // ATTEMPT-SCOPED IDENTITY (#72 round 5 finding 2): the operation record and its receipt are
    // keyed by (goal run, operation token) — every attempt is APPEND-ONLY; a retry mints a new
    // attempt identity and can never overwrite a failed attempt's evidence.
    let attempt_id = format!("{}_{}", safe(&goal_run_id), safe(&op_token));
    let reconciliation_id = format!("rc_{attempt_id}");
    let staging_root = std::path::Path::new(&st.data_dir)
        .join(STAGING_KIND)
        .join(&attempt_id);
    // CONTAINMENT (#72 round 5 finding 1): the target root must resolve canonically, every
    // declared path must be a plain relative path, aliases may not collide, the candidate
    // source must resolve inside its candidate workspace, and the target ancestry must not
    // escape through a pre-existing symlink — all proven BEFORE any receipt or effect.
    let (canon_target, target_root_fd) = if selected.is_empty() {
        // A blocked reconciliation (no verified candidate) commits nothing — no target
        // resolution is required to record that truth.
        (std::path::PathBuf::new(), None)
    } else {
        match std::path::Path::new(&target_workspace)
            .canonicalize()
            .and_then(|p| nofollow::open_root(&p).map(|fd| (p, fd)))
        {
            // The target root fd is PINNED here (#72 round 6 finding 3): every commit descends
            // from this descriptor, so a later swap of the root path cannot redirect writes.
            Ok((p, fd)) => (p, Some(fd)),
            Err(e) => {
                return reconcile_abort(
                    &st.data_dir,
                    &goal_run_id,
                    &op_token,
                    "goal_run_target_workspace_invalid",
                    &format!("target workspace '{target_workspace}' does not resolve/pin ({e}); nothing was written"),
                    &[],
                );
            }
        }
    };
    let mut planned_files: Vec<(String, std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    let mut planned_set: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut escape_errors: Vec<String> = Vec::new();
    let mut collision_errors: Vec<String> = Vec::new();
    let mut staging_errors: Vec<String> = Vec::new();
    for invocation in &selected {
        let candidate_workspace = text(invocation, "candidate_workspace_root");
        // The candidate root is PINNED once; every source byte is read through NOFOLLOW
        // descriptor walks from it (#72 round 6 finding 3) — validation and read are the SAME
        // syscall, so no swap window exists between them.
        let candidate_root = nofollow::open_root(std::path::Path::new(candidate_workspace)).ok();
        for file in changed_of(invocation) {
            let rel = match contained_rel_path(&file) {
                Ok(rel) => rel,
                Err(reason) => {
                    escape_errors.push(reason);
                    continue;
                }
            };
            if !planned_set.insert(rel.clone()) {
                collision_errors.push(format!("'{}' is declared more than once — normalized-alias collisions never race last-write-wins", rel.display()));
                continue;
            }
            if let Err(reason) = symlink_contained(&canon_target, &rel) {
                escape_errors.push(format!("target: {reason}"));
                continue;
            }
            let Some(candidate_root) = candidate_root.as_ref() else {
                staging_errors.push(format!("{file}: candidate workspace '{candidate_workspace}' does not resolve/pin"));
                continue;
            };
            let bytes = match nofollow::read_contained(candidate_root, &rel) {
                Ok(bytes) => bytes,
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) => {
                    escape_errors.push(format!("candidate: '{}' walks through a symlink/non-directory component ({e}) — descriptor-relative reads never follow it", rel.display()));
                    continue;
                }
                Err(e) => {
                    staging_errors.push(format!("{file}: candidate source read failed ({e})"));
                    continue;
                }
            };
            let staged = staging_root.join(&rel);
            if let Some(parent) = staged.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    staging_errors.push(format!("{file}: {e}"));
                    continue;
                }
            }
            match std::fs::write(&staged, &bytes) {
                Ok(()) => planned_files.push((file.clone(), staged, rel)),
                Err(e) => staging_errors.push(format!("{file}: {e}")),
            }
        }
    }
    for (code, errors) in [
        ("goal_run_output_path_escape", &escape_errors),
        ("goal_run_output_path_collision", &collision_errors),
        ("goal_run_output_staging_failed", &staging_errors),
    ] {
        if !errors.is_empty() {
            let _ = std::fs::remove_dir_all(&staging_root);
            return reconcile_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                code,
                &format!("output validation/staging refused ({}); no receipt was written and the target workspace was NOT touched", errors.join("; ")),
                &[],
            );
        }
    }
    let planned_list: Vec<String> = planned_files.iter().map(|(f, _, _)| f.clone()).collect();

    let receipt_ref = format!("receipt://hypervisor/goal-run-reconciliation/{attempt_id}");
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.goal-run.reconcile",
        "receipt_type": "orchestration_decision",
        "goal_run_ref": goal_ref,
        "orchestration_policy": "parallel_implement_reconcile",
        "merge_strategy": merge_strategy,
        "selected_materialization": "multi_harness_attempt",
        "selected_candidate_refs": selected_refs,
        "rejected_candidate_refs": rejected_refs,
        "selected_harness_refs": selected.iter().map(|i| text(i, "harness_ref")).collect::<Vec<_>>(),
        "selected_model_route_refs": selected.iter().map(|i| text(i, "model_route_ref")).collect::<Vec<_>>(),
        "verifier_evidence_refs": verifier_evidence_refs,
        "final_changed_files": planned_list,
        "attempt_token": op_token,
        "output_commit_policy": "staged_pre_receipt: this receipt precedes ANY target-workspace effect; the attempt-scoped operation record write-ahead-journals the per-file commit",
        "reason_codes": [reason_code],
        "admission_id": text(&admission, "admission_id"),
        "capability_lease_ref": run.get("capability_lease_ref").cloned().unwrap_or(Value::Null),
        "target_session_ref": text(&run, "target_session_ref"),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    // CHECKED pre-output persist: the target is still untouched, so cleanup + release keeps
    // "nothing changed" literally true.
    if let Err(e) = persist_record_durable(&st.data_dir, "receipts", &receipt_ref, &receipt) {
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_reconcile_receipt_persist_failed",
            &format!("the reconciliation receipt write did not commit ({e}); the target workspace was NOT touched"),
            &[],
        );
    }

    // Operation record, BEFORE any target effect: `committing` + the planned commit.
    let blocked = merge_strategy == "none_blocked";
    let base_record = |status: &str, final_files: &[String], journal: &[Value], copy_errors: &[String], transcript: &Option<String>, state_root: &str| {
        json!({
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "reconciliation_result_id": format!("reconciliation_result://{reconciliation_id}"),
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "verifier_evidence_refs": verifier_evidence_refs,
            "planned_changed_files": planned_list,
            "final_changed_files": final_files,
            "commit_journal": journal,
            "copy_errors": copy_errors,
            "attempt_token": op_token,
            "staging_root": staging_root.display().to_string(),
            "final_receipt_refs": [receipt_ref],
            "transcript_run_ref": transcript,
            "state_root": state_root,
            "reason_code": reason_code,
            "admission_id": text(&admission, "admission_id"),
            "status": status,
            "reconciled_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        })
    };
    let committing = base_record("committing", &[], &[], &[], &None, "");
    if let Err(e) = persist_record_durable(&st.data_dir, RECONCILIATION_KIND, &reconciliation_id, &committing) {
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_reconciliation_persist_failed",
            &format!("the reconciliation operation record did not commit ({e}); the target workspace was NOT touched"),
            &[("receipts", receipt_ref.as_str())],
        );
    }

    // COMMIT staged outputs → target workspace under a CRASH-DURABLE WAL (#72 round 5 finding
    // 3): each file gets a durable `applying` journal entry BEFORE its content moves, the move
    // itself is target-local-tmp + fsync + atomic rename + parent fsync, and the applied
    // content hash lands durably AFTER. A crash at any instant leaves (a) every destination
    // either absent or complete — never truncated — and (b) a durable journal naming exactly
    // which file was in flight. From here on the receipt and the operation record are NEVER
    // deleted, and the staged attempt is PRESERVED until terminal success.
    let mut commit_journal: Vec<Value> = Vec::new();
    let mut final_changed_files: Vec<String> = Vec::new();
    let mut copy_errors: Vec<String> = Vec::new();
    for (file, staged, rel) in &planned_files {
        commit_journal.push(json!({ "file": file, "phase": "applying", "at": iso_now() }));
        if let Err(e) = persist_record_durable(
            &st.data_dir,
            RECONCILIATION_KIND,
            &reconciliation_id,
            &base_record("committing", &final_changed_files, &commit_journal, &copy_errors, &None, ""),
        ) {
            commit_journal.pop();
            let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &copy_errors, &None, "");
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                "goal_run_commit_journal_persist_failed",
                &format!("the write-ahead journal entry for '{file}' did not commit ({e}); '{file}' was NOT applied"),
            );
        }
        commit_journal.pop();
        let Some(target_root_fd) = target_root_fd.as_ref() else {
            copy_errors.push(format!("{file}: no pinned target root (planned files with an empty selection is a bug)"));
            commit_journal.push(json!({ "file": file, "applied": false, "error": "no pinned target root", "at": iso_now() }));
            continue;
        };
        match commit_one(staged, target_root_fd, rel) {
            Ok((bytes, sha)) => {
                final_changed_files.push(file.clone());
                commit_journal.push(json!({ "file": file, "applied": true, "bytes": bytes, "sha256": sha, "at": iso_now() }));
            }
            Err(e) => {
                copy_errors.push(format!("{file}: {e}"));
                commit_journal.push(json!({ "file": file, "applied": false, "error": e, "at": iso_now() }));
            }
        }
        if let Err(e) = persist_record_durable(
            &st.data_dir,
            RECONCILIATION_KIND,
            &reconciliation_id,
            &base_record("committing", &final_changed_files, &commit_journal, &copy_errors, &None, ""),
        ) {
            let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &copy_errors, &None, "");
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                "goal_run_commit_journal_persist_failed",
                &format!("the applied-journal entry for '{file}' did not commit ({e})"),
            );
        }
    }
    if !copy_errors.is_empty() {
        let preserved = base_record("failed_partial_commit", &final_changed_files, &commit_journal, &copy_errors, &None, "");
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &preserved,
            "goal_run_output_commit_failed",
            &format!("the output commit failed partway ({}); the journal records exactly what reached the target and the staged attempt is preserved", copy_errors.join("; ")),
        );
    }

    let conductor_ref = run
        .pointer("/role_topology/conductor_ref")
        .and_then(Value::as_str)
        .unwrap_or("harness-profile:hp_hypervisor_worker")
        .to_string();
    let transcript_run = super::harness_routes::post_op_transcript(
        &st.base_url,
        "goal_run_reconciliation",
        &conductor_ref,
        &json!({
            "goal_run_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "final_changed_files": final_changed_files,
            "reason_code": reason_code,
            "receipt_ref": receipt_ref,
            "verifier_evidence_refs": verifier_evidence_refs,
        }),
    )
    .await;
    let state_root = match &transcript_run {
        Some(run_id) => self_get(&format!(
            "{}/v1/hypervisor/agent-run-transcripts/{run_id}",
            st.base_url
        ))
        .await
        .and_then(|body| {
            body.pointer("/run/state_root")
                .or_else(|| body.get("state_root"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default(),
        None => String::new(),
    };

    // Final operation-record update: the commit journal, transcript evidence, and terminal
    // status land on the SAME record id. Post-effect failure preserves everything (#72 round 4).
    let reconciliation = base_record(
        if blocked { "blocked" } else { "complete" },
        &final_changed_files,
        &commit_journal,
        &[],
        &transcript_run,
        &state_root,
    );
    if let Err(e) = persist_record_durable(&st.data_dir, RECONCILIATION_KIND, &reconciliation_id, &reconciliation) {
        let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &[], &transcript_run, &state_root);
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &preserved,
            "goal_run_reconciliation_finalize_failed",
            &format!("the committed outputs are in the target but the operation record's final update did not commit ({e})"),
        );
    }

    // FINALIZATION (#72 rounds 2-4): merge ONLY the reconciliation-owned fields onto the
    // LATEST record via the shared CAS seam — a concurrent reciprocal room stamp survives — and
    // commit TOKEN-GUARDED: only while this request still holds its reservation. A failure here
    // is POST-EFFECT: the receipt, the operation record (updated to a recovery status with its
    // journal), and the transcript are all PRESERVED; only the reservation is released so the
    // idempotent reconcile can be retried. Nothing is deleted.
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str)
                != Some(op_token.as_str())
            {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "reconcile finalization no longer holds the reservation token — refusing to commit".to_string(),
                ));
            }
            Ok(())
        },
        |object| {
            object.insert("status".into(), json!(if blocked { "blocked" } else { "complete" }));
            object.insert(
                "continuation_state".into(),
                json!(if blocked { "blocked" } else { "complete" }),
            );
            object.insert("active_loop_phase".into(), json!("continue_or_close"));
            object.insert(
                "reconciliation_ref".into(),
                json!(format!("reconciliation_result://{reconciliation_id}")),
            );
            // APPEND-ONLY attempt retention (#72 round 5 finding 2): the successful attempt
            // joins the same list every failed attempt joined — nothing is ever superseded away.
            let mut attempts: Vec<Value> = object
                .get("reconciliation_attempt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let attempt_ref = format!("reconciliation_result://{reconciliation_id}");
            if !attempts.iter().any(|a| a.as_str() == Some(attempt_ref.as_str())) {
                attempts.push(json!(attempt_ref));
            }
            object.insert("reconciliation_attempt_refs".into(), Value::Array(attempts));
            object.insert("final_changed_files".into(), json!(reconciliation["final_changed_files"]));
            object.insert("updated_at".into(), json!(iso_now()));
            object.remove("lifecycle_op");
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => {
            let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &[], &transcript_run, &state_root);
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                "goal_run_finalize_failed",
                &format!("the outputs and their evidence are durable but the GoalRun finalization did not commit ({code}: {msg})"),
            );
        }
    };
    // TERMINAL SUCCESS: only now is the staged attempt released (#72 round 5 finding 3 —
    // staging is preserved through every failure and crash as the immutable declared input).
    let _ = std::fs::remove_dir_all(&staging_root);

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": run, "reconciliation": reconciliation })),
    )
}

// ---------------------------------------------------------------------------
// lifecycle-recovery — the token-addressed, receipted reservation recovery
// ---------------------------------------------------------------------------

/// Wallet capability scopes a lifecycle-recovery grant must carry (#72 round 5 finding 4).
const RECOVERY_AUTHORITY_SCOPES: &[&str] = &["goal_run_lifecycle_recovery"];

/// Daemon-derived POLICY hash for a recovery grant: the stable identity of "recover THIS run's
/// lifecycle under THESE scopes".
fn recovery_policy_hash(goal_run_id: &str) -> String {
    sha256_canonical(&json!({
        "domain": "hypervisor.goal-run.lifecycle-recovery.policy.v1",
        "goal_run_id": goal_run_id,
        "scopes": RECOVERY_AUTHORITY_SCOPES,
    }))
}

/// Daemon-derived REQUEST hash: binds the grant to THIS reservation token, THIS resolution, and
/// the hash of THE failure evidence being resolved — a grant can never be replayed against a
/// different reservation, a different resolution, or after the reservation's evidence changed.
fn recovery_request_hash(goal_run_id: &str, token: &str, resolution: &str, failure_hash: &str) -> String {
    sha256_canonical(&json!({
        "domain": "hypervisor.goal-run.lifecycle-recovery.request.v1",
        "goal_run_id": goal_run_id,
        "op_token": token,
        "resolution": resolution,
        "failure_hash": failure_hash,
        "scopes": RECOVERY_AUTHORITY_SCOPES,
    }))
}

/// POST /v1/hypervisor/goal-runs/:id/lifecycle-recovery (#72 rounds 4 + 5): the recovery
/// contract for a durable lifecycle reservation — a crash after `draft -> starting` /
/// `active -> reconciling`, or a deliberately retained failed-start reservation, is resolved by
/// an EXPLICIT governed transition, never by a blind expiry. The token is the ADDRESS (proof
/// the caller read the durable reservation); the AUTHORITY is a verified wallet capability
/// grant bound to {run, token, resolution, failure evidence hash} (finding 4 — a token-only
/// release could re-open a wallet-crossed start to any reader). Release, receipt persistence,
/// and exact rollback all execute inside ONE GoalRun mutation critical section (finding 5 — no
/// concurrent reservation can interleave with the release and be clobbered by the rollback).
/// `resolution: "release"` restores the reservation's recorded `from_status`; the receipt binds
/// the acting identity, its grant, and every hash it was verified against.
pub(crate) async fn handle_goal_run_lifecycle_recovery(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(token) = body.get("op_token").and_then(Value::as_str).map(str::to_string) else {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_recovery_token_required",
            "`op_token` is required — recovery is token-addressed to the durable reservation (read the run record first)",
        );
    };
    let resolution = body.get("resolution").and_then(Value::as_str).unwrap_or("");
    if resolution != "release" {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_recovery_resolution_invalid",
            "`resolution` must be \"release\" (restore the reservation's from_status and consume the token); richer resolutions are named gaps, not silent defaults",
        );
    }
    // Read the CURRENT reservation (pre-gate snapshot) to derive the authority binding facts.
    let Some(snapshot) = read_record_dir(&st.data_dir, GOAL_RUN_KIND)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some(id.as_str()))
    else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    let snapshot_op = snapshot.get("lifecycle_op").cloned().unwrap_or(Value::Null);
    if snapshot_op.get("token").and_then(Value::as_str) != Some(token.as_str()) {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_operation_conflict",
            "no durable reservation carries this token — recovery is addressed to the CURRENT reservation",
        );
    }
    // AUTHORITY, not just address (#72 round 5 finding 4): the token proves the caller READ the
    // durable state; releasing a reservation — which can re-open a wallet-crossed start — is a
    // GOVERNED crossing requiring a wallet capability grant bound to this exact run, token,
    // resolution, and the hash of the failure evidence being resolved. The failure hash covers
    // the RESERVATION AND ITS ATTEMPT (#72 round 6 finding 2): the attempt-scoped operation
    // record — WAL journal, planned files, staging root, target effects — is part of what the
    // authority is deciding over, so a grant is bound to that exact evidence.
    let attempt_ref = snapshot_op
        .get("attempt_ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    let attempt_record = read_attempt_record(&st.data_dir, attempt_ref.as_deref());
    let failure_hash = sha256_canonical(&json!({
        "lifecycle_op": snapshot_op,
        "attempt_record": attempt_record,
    }));
    let policy_hash = recovery_policy_hash(&id);
    let request_hash = recovery_request_hash(&id, &token, resolution, &failure_hash);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let grant_value = body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null);
    let binding = if grant_value.is_null() {
        Err("a wallet_approval_grant is required".to_string())
    } else {
        verify_wallet_approval_grant_binding(&grant_value, Some(now_ms), Some(&policy_hash), Some(&request_hash))
    };
    let binding = match binding {
        Ok(binding) => binding,
        Err(reason) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "reason": "recovery_authority_required",
                    "message": format!("Releasing a lifecycle reservation is a governed recovery decision ({reason}). Bind a wallet grant to policy_hash {policy_hash} + request_hash {request_hash}."),
                    "required_scopes": RECOVERY_AUTHORITY_SCOPES,
                    "approval": { "policy_hash": policy_hash, "request_hash": request_hash },
                    "failure_hash": failure_hash,
                    "runtimeTruthSource": "daemon-runtime",
                })),
            );
        }
    };
    let acting_authority_id = grant_value.get("authority_id").cloned().unwrap_or(Value::Null);

    // ONE CRITICAL SECTION (#72 round 5 finding 5) RUNNING A DURABLE INTENT TRANSACTION (#72
    // round 6 finding 4): under the GoalRun mutation lock — so no operation can interleave —
    // the transaction is (1) CAS re-verification (token AND the attempt-covering failure hash,
    // recomputed from durable state), (2) durable RECOVERY-INTENT write (the run keeps its
    // reservation; the intent seals the full receipt and release facts), (3) durable receipt
    // persist, (4) durable release. A crash between ANY of those steps leaves a state the boot
    // completer finishes FORWARD deterministically — nothing is guessed at restart, and a
    // synchronous receipt failure rolls the intent back exactly. No .await under the lock.
    let _guard = GOAL_RUN_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(prior) = read_record_dir(&st.data_dir, GOAL_RUN_KIND)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some(id.as_str()))
    else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    let prior_op = prior.get("lifecycle_op").cloned().unwrap_or(Value::Null);
    let prior_attempt = read_attempt_record(&st.data_dir, prior_op.get("attempt_ref").and_then(Value::as_str));
    let recomputed_hash = sha256_canonical(&json!({
        "lifecycle_op": prior_op,
        "attempt_record": prior_attempt,
    }));
    if prior_op.get("token").and_then(Value::as_str) != Some(token.as_str())
        || recomputed_hash != failure_hash
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_operation_conflict",
            "the reservation or its attempt evidence changed between the authority gate and the release — re-read the run and re-challenge",
        );
    }
    if prior.get("recovery_intent").is_some() {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_recovery_in_flight",
            "a durable recovery intent already exists for this run — the boot completer (or the original request) finishes it deterministically",
        );
    }
    let prior_status = prior.get("status").and_then(Value::as_str).unwrap_or("").to_string();
    let restored_status = prior_op
        .get("from_status")
        .and_then(Value::as_str)
        .unwrap_or("draft")
        .to_string();
    let receipt_id = format!(
        "receipt://hypervisor/goal-run-lifecycle-recovery/{}_{}",
        safe(&id),
        safe(&token)
    );
    let receipt = json!({
        "id": receipt_id,
        "kind": "hypervisor.goal-run.lifecycle-recovery",
        "receipt_type": "GoalRunLifecycleRecoveryReceipt",
        "goal_run_id": id,
        "op": prior_op.get("op").cloned().unwrap_or(Value::Null),
        "op_token": token,
        "reservation": prior_op,
        // The crashed/failed attempt this recovery resolves (#72 round 6 finding 2): bound by
        // REF and by the hash the authority grant was verified against.
        "attempt_ref": attempt_ref.clone(),
        "reserved_status": prior_status,
        "restored_status": restored_status,
        "resolution": "release",
        // The acting identity and its authority (#72 round 5 finding 4) — who decided, under
        // what verified grant, bound to which policy/request/failure hashes.
        "acting_authority_id": acting_authority_id,
        "authority_grant_ref": binding.grant_ref,
        "authority_provider_ref": binding.provider_ref,
        "authority_grant_hash": binding.hash,
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "failure_hash": failure_hash,
        "required_scopes": RECOVERY_AUTHORITY_SCOPES,
        "consequential_execution_note": "releasing after a consequential execution (e.g. a completed wallet crossing) is an explicit governed decision recorded by this receipt — re-running the operation performs a NEW crossing",
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    // (2) DURABLE INTENT: the run still holds its reservation; the intent seals everything the
    // completer needs — receipt content included — before any observable transition.
    let mut with_intent = prior.clone();
    if let Some(obj) = with_intent.as_object_mut() {
        obj.insert(
            "recovery_intent".into(),
            json!({
                "op_token": token,
                "resolution": "release",
                "restored_status": restored_status,
                "attempt_ref": attempt_ref,
                "receipt_id": receipt_id,
                "receipt": receipt,
                "at": iso_now(),
            }),
        );
    }
    if let Err(e) = persist_goal_run_atomic(&st.data_dir, &id, &with_intent) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_persist_failed",
            &format!("the recovery intent did not commit ({e}) — the reservation is unchanged"),
        );
    }
    // DELIBERATE TEST KILL POINT (#72 round 6 finding 4): absent env = no effect. Crashing here
    // — after the GoalRun replacement, before receipt persistence — leaves ONLY the durable
    // intent; the boot completer must finish the transaction deterministically.
    if std::env::var("IOI_TEST_KILL_AFTER_RECOVERY_INTENT").ok().as_deref() == Some("1") {
        std::process::abort();
    }
    // (3) Durable receipt. A synchronous failure rolls the intent back EXACTLY (the reservation
    // survives untouched) inside the same critical section.
    if let Err(e) = persist_record_durable(&st.data_dir, "receipts", &receipt_id, &receipt) {
        return match persist_goal_run_atomic(&st.data_dir, &id, &prior) {
            Ok(()) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_recovery_receipt_persist_failed",
                &format!("the recovery receipt did not persist ({e}); the intent was rolled back EXACTLY inside the same critical section — nothing changed"),
            ),
            Err(re) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_rollback_failed",
                &format!("the recovery receipt did not persist ({e}) AND the intent rollback failed ({re}) — the boot completer will finish the durable intent deterministically"),
            ),
        };
    }
    // (4) Durable release: restore from_status, RETAIN the crashed attempt ref, consume the
    // reservation and the intent.
    let released = build_released_run(&prior, &with_intent["recovery_intent"]);
    if let Err(e) = persist_goal_run_atomic(&st.data_dir, &id, &released) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_recovery_finalize_failed",
            &format!("the release did not commit ({e}); the durable intent and its receipt are in place — the boot completer finishes this transaction deterministically at restart"),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": released, "recovery_receipt": receipt })),
    )
}

/// Resolve the attempt-scoped operation record a reservation names (Null when absent).
fn read_attempt_record(data_dir: &str, attempt_ref: Option<&str>) -> Value {
    let Some(aref) = attempt_ref else { return Value::Null };
    read_record_dir(data_dir, RECONCILIATION_KIND)
        .into_iter()
        .find(|rec| rec.get("reconciliation_result_id").and_then(Value::as_str) == Some(aref))
        .unwrap_or(Value::Null)
}

/// Apply a sealed recovery intent to its run: restore `from_status`, RETAIN the crashed attempt
/// ref append-only, consume the reservation and the intent.
fn build_released_run(prior: &Value, intent: &Value) -> Value {
    let mut released = prior.clone();
    if let Some(obj) = released.as_object_mut() {
        obj.insert(
            "status".into(),
            json!(intent.get("restored_status").and_then(Value::as_str).unwrap_or("draft")),
        );
        obj.insert("updated_at".into(), json!(iso_now()));
        if let Some(aref) = intent.get("attempt_ref").and_then(Value::as_str) {
            let mut attempts: Vec<Value> = obj
                .get("reconciliation_attempt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !attempts.iter().any(|a| a.as_str() == Some(aref)) {
                attempts.push(json!(aref));
            }
            obj.insert("reconciliation_attempt_refs".into(), Value::Array(attempts));
        }
        obj.remove("lifecycle_op");
        obj.remove("recovery_intent");
    }
    released
}

/// BOOT COMPLETER (#72 round 6 finding 4): a crash between the durable recovery intent and its
/// terminal release leaves `recovery_intent` on the run record. Restart finishes the
/// transaction FORWARD deterministically — persist the intent's sealed receipt (idempotent),
/// then apply the release (restore from_status, retain the crashed attempt ref, consume the
/// reservation and intent). Nothing is guessed: every fact was sealed into the intent before
/// the first observable transition. A persist failure leaves the intent for the next boot.
pub(crate) fn complete_recovery_intents(data_dir: &str) {
    let _guard = GOAL_RUN_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    for run in read_record_dir(data_dir, GOAL_RUN_KIND) {
        let Some(intent) = run.get("recovery_intent").cloned() else { continue };
        let goal_run_id = run.get("goal_run_id").and_then(Value::as_str).unwrap_or("").to_string();
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent.get("receipt_id").and_then(Value::as_str).unwrap_or("").to_string();
        if receipt.is_null() || receipt_id.is_empty() || goal_run_id.is_empty() {
            eprintln!("goal-run recovery completer: malformed intent on '{goal_run_id}' — left in place for manual repair");
            continue;
        }
        if let Err(e) = persist_record_durable(data_dir, "receipts", &receipt_id, &receipt) {
            eprintln!("goal-run recovery completer: receipt persist failed for '{goal_run_id}' ({e}) — intent retained, retried next boot");
            continue;
        }
        let released = build_released_run(&run, &intent);
        if let Err(e) = persist_goal_run_atomic(data_dir, &goal_run_id, &released) {
            eprintln!("goal-run recovery completer: release persist failed for '{goal_run_id}' ({e}) — intent retained, retried next boot");
            continue;
        }
        eprintln!("goal-run recovery completer: finished the interrupted recovery for '{goal_run_id}' (receipt '{receipt_id}')");
    }
}

// ---------------------------------------------------------------------------
// events — the run's normalized HarnessAdapterEvent stream + invocation records
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_run_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(run) = load(&st, GOAL_RUN_KIND, &id) else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    let goal_ref = text(&run, "goal_ref");
    let mut events: Vec<Value> = read_record_dir(&st.data_dir, "harness-adapter-events")
        .into_iter()
        .filter(|event| text(event, "goal_run_ref") == goal_ref)
        .collect();
    events.sort_by_key(|event| {
        (
            text(event, "harness_invocation_ref").to_string(),
            event.get("sequence").and_then(Value::as_u64).unwrap_or(0),
        )
    });
    let invocations: Vec<Value> = read_record_dir(&st.data_dir, INVOCATION_KIND)
        .into_iter()
        .filter(|invocation| text(invocation, "goal_ref") == goal_ref)
        .collect();
    let verifications: Vec<Value> = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .into_iter()
        .filter(|verification| text(verification, "goal_ref") == goal_ref)
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "goal_ref": goal_ref,
            "events": events,
            "invocations": invocations,
            "verifications": verifications,
        })),
    )
}

#[cfg(test)]
mod goal_run_seam_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-goalrun-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(dir.join(GOAL_RUN_KIND)).unwrap();
        dir
    }

    fn plant(dir: &std::path::Path, file: &str, record: &Value) {
        std::fs::write(
            dir.join(GOAL_RUN_KIND).join(file),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn guarded_seam_distinguishes_not_found_refusal_and_persist_failure() {
        // #72 round 3 finding 1: the seam's outcomes are TYPED and distinct — a caller can no
        // longer collapse "record missing" and "write failed" into one silent lane.
        let dir = temp_dir("lanes");
        let data_dir = dir.to_str().unwrap();
        let seed = json!({ "goal_run_id": "gr_a", "status": "active", "normalized_goal": "x" });
        // The record lives in seed.json; the seam's atomic write targets gr_a.json — the two
        // names differ deliberately so a destination blocker can fail ONLY the persist step.
        plant(&dir, "seed.json", &seed);

        // Lane 1: unknown run — typed not-found, nothing else.
        let (code, _) = update_goal_run_guarded(data_dir, "gr_missing", |_| Ok(()), |_| {}).unwrap_err();
        assert_eq!(code, "goal_run_not_found");

        // Lane 2: predicate refusal — propagated verbatim, the mutation NEVER runs.
        let mut mutated = false;
        let (code, msg) = update_goal_run_guarded(
            data_dir,
            "gr_a",
            |_| Err(("goal_run_not_reconcilable".to_string(), "state precheck refused".to_string())),
            |_| mutated = true,
        )
        .unwrap_err();
        assert_eq!(code, "goal_run_not_reconcilable");
        assert_eq!(msg, "state precheck refused");
        assert!(!mutated, "the CAS predicate gates the mutation");

        // Lane 3: persist failure — a non-empty directory blocks the atomic rename destination.
        let blocker = dir.join(GOAL_RUN_KIND).join("gr_a.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let before = std::fs::read(dir.join(GOAL_RUN_KIND).join("seed.json")).unwrap();
        let (code, _) = update_goal_run_guarded(data_dir, "gr_a", |_| Ok(()), |obj| {
            obj.insert("status".into(), json!("complete"));
        })
        .unwrap_err();
        assert_eq!(code, "goal_run_persist_failed", "a write failure is its OWN typed lane");
        assert_eq!(
            std::fs::read(dir.join(GOAL_RUN_KIND).join("seed.json")).unwrap(),
            before,
            "the durable record is byte-for-byte unchanged after a failed persist"
        );
        let leaks: Vec<String> = std::fs::read_dir(dir.join(GOAL_RUN_KIND))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(leaks.is_empty(), "no temporary artifact survives: {leaks:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn contained_rel_path_rejects_every_escape_shape() {
        // #72 round 5 finding 1: traversal, absolute, current-dir, and empty declarations never
        // reach a workspace join.
        assert_eq!(contained_rel_path("out.txt").unwrap(), std::path::PathBuf::from("out.txt"));
        assert_eq!(contained_rel_path("nested/dir/out.txt").unwrap(), std::path::PathBuf::from("nested/dir/out.txt"));
        // An interior `./` NORMALIZES (the alias then collides with its plain form in the
        // planned set); leading `./`, parent traversal, absolute, and empty all REFUSE.
        assert_eq!(contained_rel_path("a/./b.txt").unwrap(), std::path::PathBuf::from("a/b.txt"));
        for escape in ["../escape.txt", "a/../../b.txt", "a/../b.txt", "/etc/passwd", "./a.txt", "", "  "] {
            assert!(contained_rel_path(escape).is_err(), "'{escape}' must refuse");
        }
    }

    #[test]
    fn symlink_containment_catches_a_symlinked_ancestor_without_mutating_anything() {
        let dir = temp_dir("symlink");
        let root = dir.join("target-root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();
        let canon_root = root.canonicalize().unwrap();
        let err = symlink_contained(&canon_root, std::path::Path::new("sub/x.txt")).unwrap_err();
        assert!(err.contains("symlinked ancestor"), "{err}");
        // A brand-new (not yet existing) subtree is fine — it cannot be a symlink.
        symlink_contained(&canon_root, std::path::Path::new("fresh/depth/x.txt")).unwrap();
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "the check wrote NOTHING outside");
        assert!(!root.join("fresh").exists(), "the check wrote NOTHING inside either");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_one_is_atomic_hashed_and_symlink_safe() {
        let dir = temp_dir("commit-one");
        let root = dir.join("target-root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let staged = dir.join("staged.txt");
        std::fs::write(&staged, b"FULL_CONTENT").unwrap();
        let root_fd = nofollow::open_root(&root).unwrap();
        // Happy path: full content lands, the applied hash is the content hash, no tmp survives.
        let (bytes, sha) = commit_one(&staged, &root_fd, std::path::Path::new("deep/out.txt")).unwrap();
        assert_eq!(bytes, 12);
        assert_eq!(sha, sha256_hex(b"FULL_CONTENT"));
        assert_eq!(std::fs::read(root.join("deep/out.txt")).unwrap(), b"FULL_CONTENT");
        let leaks: Vec<String> = std::fs::read_dir(root.join("deep")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.contains(".wal-tmp-")).collect();
        assert!(leaks.is_empty(), "no wal-tmp survives: {leaks:?}");
        // Symlink belt (now descriptor-relative, #72 round 6): a symlinked parent component
        // refuses AT THE OPEN and writes nothing outside.
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = commit_one(&staged, &root_fd, std::path::Path::new("link/out.txt")).unwrap_err();
        assert!(err.contains("pinned parent walk refused"), "{err}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "zero external mutation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_persist_fails_typed_at_write_rename_and_dirsync_boundaries() {
        // #72 round 6 finding 1: the durable helper reports Ok ONLY when tmp-write, fsync,
        // rename, and the DIRECTORY fsync all succeeded; each boundary failure is an Err with
        // no torn record and no tmp leak.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("durable");
        let data_dir = dir.to_str().unwrap();
        let fam = dir.join("evidence");
        std::fs::create_dir_all(&fam).unwrap();
        // Happy path first.
        persist_record_durable(data_dir, "evidence", "rec_a", &json!({ "v": 1 })).unwrap();
        assert_eq!(read_record_dir(data_dir, "evidence").pop().unwrap()["v"], json!(1));
        // WRITE boundary: read/exec-only family dir refuses the tmp create; nothing changes.
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(persist_record_durable(data_dir, "evidence", "rec_a", &json!({ "v": 2 })).is_err());
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read_record_dir(data_dir, "evidence").pop().unwrap()["v"], json!(1), "the old record survives a write-boundary failure untouched");
        // RENAME boundary: a non-empty directory blocks the destination; tmp is cleaned.
        let blocker = fam.join("rec_b.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        assert!(persist_record_durable(data_dir, "evidence", "rec_b", &json!({ "v": 3 })).is_err());
        let leaks: Vec<String> = std::fs::read_dir(&fam).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.contains(".tmp-")).collect();
        assert!(leaks.is_empty(), "no tmp survives a rename-boundary failure: {leaks:?}");
        // DIR-SYNC boundary: write+exec-only (no read) lets tmp-write and rename succeed but the
        // checked directory fsync cannot open the dir — the helper FAILS CLOSED rather than
        // report unconfirmed durability as success.
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o333)).unwrap();
        let r = persist_record_durable(data_dir, "evidence", "rec_c", &json!({ "v": 4 }));
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.is_err(), "an unconfirmed rename durability is a FAILED persist, never a shrug");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nofollow_walks_refuse_symlinks_at_use_time_and_pinned_fds_survive_swaps() {
        // #72 round 6 finding 3: enforcement happens AT the open (O_NOFOLLOW, descriptor-
        // relative), not in a check before it — and a pinned root fd keeps writing into the
        // ORIGINAL directory even when its path is swapped to a symlink afterwards.
        let dir = temp_dir("nofollow");
        let root = dir.join("root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("real/inside.txt"), b"INSIDE").unwrap();
        std::fs::write(outside.join("loot.txt"), b"LOOT").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let root_fd = nofollow::open_root(&root).unwrap();
        // Reads: a symlink component refuses at USE time; a legitimate path reads fine.
        assert_eq!(nofollow::read_contained(&root_fd, std::path::Path::new("real/inside.txt")).unwrap(), b"INSIDE");
        let err = nofollow::read_contained(&root_fd, std::path::Path::new("link/loot.txt")).unwrap_err();
        assert!(matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)), "{err}");
        // SWAP LANE (source/target parent swap): pin the root fd, then swap the root path to a
        // symlink pointing outside — the pinned fd still resolves to the ORIGINAL directory.
        let staged = dir.join("staged.txt");
        std::fs::write(&staged, b"PAYLOAD").unwrap();
        let moved = dir.join("root-moved");
        std::fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        let (bytes, _) = commit_one(&staged, &root_fd, std::path::Path::new("swapped/out.txt")).unwrap();
        assert_eq!(bytes, 7);
        assert_eq!(std::fs::read(moved.join("swapped/out.txt")).unwrap(), b"PAYLOAD", "the write followed the PINNED fd, not the swapped path");
        assert!(!outside.join("swapped").exists() && !outside.join("out.txt").exists(), "the symlinked path received NOTHING");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_completer_finishes_a_sealed_recovery_intent_forward() {
        // #72 round 6 finding 4: everything the completer needs was sealed into the intent
        // before the first observable transition — restart persists the receipt, releases the
        // run, and RETAINS the crashed attempt ref (finding 2).
        let dir = temp_dir("completer");
        let data_dir = dir.to_str().unwrap();
        let receipt = json!({ "id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_i_t1", "receipt_type": "GoalRunLifecycleRecoveryReceipt", "goal_run_id": "gr_i", "failure_hash": "sha256:abc" });
        plant(&dir, "gr_i.json", &json!({
            "goal_run_id": "gr_i",
            "status": "reconciling",
            "lifecycle_op": { "op": "reconcile", "token": "t1", "from_status": "active", "attempt_ref": "reconciliation_result://rc_gr_i_t1" },
            "recovery_intent": { "op_token": "t1", "resolution": "release", "restored_status": "active", "attempt_ref": "reconciliation_result://rc_gr_i_t1", "receipt_id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_i_t1", "receipt": receipt, "at": "2026-01-01T00:00:00Z" }
        }));
        complete_recovery_intents(data_dir);
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(run["status"], json!("active"), "released to the intent's from_status");
        assert!(run.get("lifecycle_op").is_none() && run.get("recovery_intent").is_none(), "reservation and intent consumed");
        assert_eq!(run["reconciliation_attempt_refs"], json!(["reconciliation_result://rc_gr_i_t1"]), "the crashed attempt ref is RETAINED");
        let persisted_receipt = read_record_dir(data_dir, "receipts").pop().expect("the sealed receipt was persisted");
        assert_eq!(persisted_receipt["receipt_type"], json!("GoalRunLifecycleRecoveryReceipt"));
        // Idempotent: a second boot pass changes nothing.
        complete_recovery_intents(data_dir);
        assert_eq!(read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap()["reconciliation_attempt_refs"], json!(["reconciliation_result://rc_gr_i_t1"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserve_abort_updates_the_operation_record_and_never_deletes_evidence() {
        // #72 round 4 finding 1: once output MAY have reached the target, the abort lane
        // UPDATES the operation record to a recovery status (journal preserved), releases the
        // reservation, and deletes NOTHING — receipt included.
        let dir = temp_dir("preserve");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_p.json", &json!({ "goal_run_id": "gr_p", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tp", "from_status": "active" } }));
        std::fs::create_dir_all(dir.join(RECONCILIATION_KIND)).unwrap();
        std::fs::write(dir.join("receipts_marker"), b"x").unwrap();
        let preserved = json!({ "reconciliation_result_id": "reconciliation_result://rc_gr_p", "status": "failed_partial_commit", "commit_journal": [{ "file": "a.txt", "applied": true }], "final_receipt_refs": ["receipt://hypervisor/goal-run-reconciliation/gr_p"] });
        let (status, body) = reconcile_preserve_abort(data_dir, "gr_p", "tp", "rc_gr_p", &preserved, "goal_run_output_commit_failed", "half the files landed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_output_commit_failed"));
        let record = read_record_dir(data_dir, RECONCILIATION_KIND).pop().expect("the operation record is PRESERVED");
        assert_eq!(record["status"], json!("failed_partial_commit"));
        assert_eq!(record["commit_journal"][0]["applied"], json!(true), "the journal survives as evidence");
        assert_eq!(record["recovery"]["code"], json!("goal_run_output_commit_failed"), "the recovery lane is recorded ON the evidence");
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(run["status"], json!("active"), "the reservation was released for an idempotent retry");
        assert!(run.get("lifecycle_op").is_none());
        assert_eq!(
            run["reconciliation_attempt_refs"],
            json!(["reconciliation_result://rc_gr_p"]),
            "the FAILED attempt's ref is retained append-only on the run (#72 round 5 finding 2)"
        );
        // Bookkeeping failure lane: a blocked record family escalates to rollback_failed while
        // STILL deleting nothing.
        plant(&dir, "gr_q.json", &json!({ "goal_run_id": "gr_q", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tq", "from_status": "active" } }));
        let blocker = dir.join(RECONCILIATION_KIND).join("rc_gr_q.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let (status, body) = reconcile_preserve_abort(data_dir, "gr_q", "tq", "rc_gr_q", &preserved, "goal_run_output_commit_failed", "half the files landed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_rollback_failed"));
        assert!(std::fs::read(dir.join("receipts_marker")).is_ok(), "nothing was deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_evidence_abort_marks_the_reservation_recovery_required_with_executed_evidence() {
        // #72 round 4 finding 2: a side-record persist failure after the wallet crossing keeps
        // the reservation (no duplicate crossing), embeds the failure + executed-invocation
        // evidence durably on the run record, and binds NO refs.
        let dir = temp_dir("evidence");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_e.json", &json!({ "goal_run_id": "gr_e", "status": "starting", "lifecycle_op": { "op": "start", "token": "te", "from_status": "draft" } }));
        let executed = vec![json!({ "harness_invocation_id": "harness_invocation://hi_gr_e_a", "role_key": "a", "status": "failed" })];
        let (status, body) = start_evidence_abort(data_dir, "gr_e", "te", VERIFICATION_KIND, "gv_gr_e_a", "read-only dir", &executed);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_side_record_persist_failed"));
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(run["status"], json!("starting"), "the reservation is KEPT — releasing would re-open a duplicate wallet crossing");
        assert_eq!(run["lifecycle_op"]["phase"], json!("recovery_required"));
        assert_eq!(run["lifecycle_op"]["token"], json!("te"), "the token survives for the recovery transition");
        assert_eq!(run["lifecycle_op"]["failure"]["family"], json!(VERIFICATION_KIND));
        assert_eq!(run["lifecycle_op"]["executed_invocations"][0]["harness_invocation_id"], json!("harness_invocation://hi_gr_e_a"), "the executed work is durable attempt evidence");
        assert!(run.get("invocation_refs").is_none() && run.get("verification_refs").is_none(), "no dangling refs were bound");
        // Wrong-token marking refuses without touching the record.
        let (_, body) = start_evidence_abort(data_dir, "gr_e", "wrong", VERIFICATION_KIND, "gv", "x", &executed);
        assert_eq!(body.0["error"]["code"], json!("goal_run_rollback_failed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn operation_reservation_admits_exactly_one_winner_and_finalizes_by_token() {
        // #72 round 3 finding 2: `active -> reconciling` is an atomic CAS reservation — of two
        // concurrent reconciles exactly one wins; finalization commits only under the winner's
        // token; release restores the exact pre-reservation lifecycle state.
        let dir = temp_dir("reserve");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_b.json", &json!({ "goal_run_id": "gr_b", "status": "active" }));
        let reserve = |token: &str| {
            let token = token.to_string();
            update_goal_run_guarded(
                data_dir,
                "gr_b",
                |fresh| {
                    if fresh.get("status").and_then(Value::as_str) != Some("active") {
                        return Err((
                            "goal_run_not_reconcilable".to_string(),
                            "not active".to_string(),
                        ));
                    }
                    Ok(())
                },
                move |obj| {
                    obj.insert("status".into(), json!("reconciling"));
                    obj.insert("lifecycle_op".into(), json!({ "op": "reconcile", "token": token }));
                },
            )
        };
        assert!(reserve("t1").is_ok(), "the first reservation wins");
        let (code, _) = reserve("t2").unwrap_err();
        assert_eq!(code, "goal_run_not_reconcilable", "the second request loses the SAME CAS it would have raced");

        // Finalization compares the token INSIDE the seam: a foreign token refuses.
        let finalize = |token: &str| {
            let token = token.to_string();
            update_goal_run_guarded(
                data_dir,
                "gr_b",
                move |fresh| {
                    if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token.as_str()) {
                        return Err(("goal_run_operation_conflict".to_string(), "token mismatch".to_string()));
                    }
                    Ok(())
                },
                |obj| {
                    obj.insert("status".into(), json!("complete"));
                    obj.remove("lifecycle_op");
                },
            )
        };
        let (code, _) = finalize("t2").unwrap_err();
        assert_eq!(code, "goal_run_operation_conflict");
        let committed = finalize("t1").unwrap();
        assert_eq!(committed["status"], json!("complete"));
        assert!(committed.get("lifecycle_op").is_none(), "the reservation is consumed by the commit");

        // Release restores the reserved status exactly and consumes the token.
        plant(&dir, "gr_c.json", &json!({ "goal_run_id": "gr_c", "status": "active" }));
        let hold = update_goal_run_guarded(data_dir, "gr_c", |_| Ok(()), |obj| {
            obj.insert("status".into(), json!("reconciling"));
            obj.insert("lifecycle_op".into(), json!({ "op": "reconcile", "token": "t3" }));
        });
        assert!(hold.is_ok());
        release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap();
        let restored = read_record_dir(data_dir, GOAL_RUN_KIND)
            .into_iter()
            .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some("gr_c"))
            .unwrap();
        assert_eq!(restored["status"], json!("active"), "release restores the pre-reservation status");
        assert!(restored.get("lifecycle_op").is_none(), "release consumes the reservation");
        let (code, _) = release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap_err();
        assert_eq!(code, "goal_run_operation_conflict", "a consumed token releases nothing twice");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
