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
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine as _;
use ioi_services::agentic::runtime::kernel::{
    agentgres_admission::StorageBackendWriteProposal,
    runtime_goal_pursuit::{GoalPursuitCore, GoalPursuitError, WorkLifecycleCore},
    RuntimeKernelService,
};
use ioi_services::wallet_network::ApprovalGrantConsumptionReceipt;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use super::lifecycle_routes::{
    execute_authority_gate, resolve_adapter_driver, run_host_spawn_lane,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

const GOAL_RUN_KIND: &str = "goal-runs";
const GOAL_RUN_ACTIVATION_KIND: &str = "goal-run-activations";
const GOAL_RUN_ACTIVATION_CONTROL_KIND: &str = "goal-run-activation-controls";
const GOAL_RUN_ACTIVATION_SOURCE_KIND: &str = "ioi-ai-goal-drafts";
const GOAL_RUN_ACTIVATION_AUTHORITY_KIND: &str = "goal-run-activation-authority-decisions";
const GOAL_RUN_ACTIVATION_AUTHORIZED_AUTHORITY_KIND: &str =
    "goal-run-activation-authorized-authority-decisions";
const GOAL_RUN_ACTIVATION_REVIEW_KIND: &str = "goal-run-activation-review-receipts";
const GOAL_RUN_ACTIVATION_RECEIPT_KIND: &str = "goal-run-activation-receipts";
const GOAL_RUN_ADMISSION_RECEIPT_KIND: &str = "goal-run-admission-receipts";
const GOAL_RUN_PROFILE_REVISION_KIND: &str = "goal-run-profile-revisions";
const GOAL_RUN_ADMISSION_POLICY_REVISION_KIND: &str = "goal-run-admission-policy-revisions";
const GOAL_RUN_RESOLVED_COMPONENT_KIND: &str = "goal-run-resolved-component-revisions";
const GOAL_RUN_EXECUTION_CEILING_REVISION_KIND: &str = "goal-run-execution-ceiling-revisions";
const GOAL_RUN_ADMITTED_STATE_KIND: &str = "goal-run-activation-admitted-states";

const GOAL_RUN_ACTIVATION_SCHEMA_VERSION: &str = "ioi.goal-run-activation.v1";
const GOAL_RUN_ACTIVATION_DRAFT_REQUEST_SCHEMA_VERSION: &str =
    "ioi.goal-run-activation-draft-request.v1";
const GOAL_RUN_ACTIVATION_SUBMIT_REQUEST_SCHEMA_VERSION: &str =
    "ioi.goal-run-activation-submit-request.v1";
const BUILTIN_GENERIC_ADAPTIVE_PROFILE_KEY: &str = "generic-adaptive-release-v1";
const BUILTIN_BOUNDED_ADMISSION_POLICY_KEY: &str = "bounded-direct-release-v1";
const BUILTIN_ZERO_EXECUTION_CEILING_KEY: &str = "ioi-goal-draft-zero-release-v1";
const GOAL_RUN_ACTIVATION_RECEIPT_TYPE: &str = "goal_run_activation";
const GOAL_RUN_ACTIVATION_RECEIPT_PROFILE: &str =
    "schema://ioi/applications/ioi-ai/goal-run-activation-receipt/v1";
const GOAL_RUN_CREATE_AUTHORITY_SCOPE: &str = "scope:goal.run.create";
const M4_HOSTED_COLLECTIVE_POLICY_REF: &str = "policy://ioi/m4/hosted-only";
const OUTCOME_ROOM_PACKAGE_REF: &str = "package://ioi/outcome-room";
const ADMISSION_FACT_RESOLUTION_SCHEMA: &str = "ioi.goal-run-admission-runtime-fact-resolution.v1";
// Live compatibility migration for superseded WorkResult contracts was deleted under ADR 0022.

/// GoalRun record mutation lock (#72 review round 2). LOCK ORDERING (fixed, documented):
/// ROOM_MUTATION_LOCK — when held — is always acquired BEFORE this lock; no .await ever executes
/// under it (update_goal_run_guarded's predicate and closure are synchronous).
pub(crate) static GOAL_RUN_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// Room-owned WorkResult convergence acquires this lock while the caller already holds the
/// OutcomeRoom mutation lock. It serializes the canonical HarnessInvocation backlink and keeps
/// the fixed lock order `ROOM_MUTATION_LOCK -> INVOCATION_MUTATION_LOCK ->
/// GOAL_RUN_MUTATION_LOCK`. No `.await` executes while it is held.
static INVOCATION_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// Serializes the two-record Goal Chat draft/activation intake and the submit/admit crossing.
/// No `.await` occurs while this lock is held. The lock makes the idempotency-key lookup and
/// body-swap refusal atomic with respect to every writer in this module.
static GOAL_RUN_ACTIVATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Distinct durable-persist failure OUTCOMES (#72 round 7 finding 1): the two failure classes
/// have OPPOSITE truthful handling and must never be conflated.
// The typed atomic-replacement writer and its outcome now live in the SHARED durable-fs
// core (#73) — extracted verbatim from this plane (#72 rounds 6-8).
use super::durable_fs::{persist_record_durable, PersistFailure};

/// ATOMIC-DURABLE replacement for the mutable goal-run record — the durable helper over the
/// goal-run family (reservations, recovery intents, and releases order-depend on durability).
fn persist_goal_run_atomic(
    data_dir: &str,
    goal_run_id: &str,
    record: &Value,
) -> Result<(), PersistFailure> {
    persist_record_durable(data_dir, GOAL_RUN_KIND, goal_run_id, record)
}

// Descriptor-relative, symlink-refusing filesystem walks now live in the SHARED durable-fs
// core (#73) — extracted verbatim from this plane's `nofollow` module (#72 rounds 6-7).
use super::durable_fs as nofollow_fs;

/// A typed seam refusal: (code, message). Codes are wire-facing.
pub(crate) type SeamErr = (String, String);

/// A SUCCESSFUL seam mutation with its durability posture (#72 round 8 finding 1): the outcome
/// is preserved STRUCTURALLY across plane boundaries so every consumer chooses forward
/// completion, recovery intent, or rollback based on VISIBILITY — a visible-but-unconfirmed
/// mutation must never be handled as "absent".
#[derive(Debug)]
pub(crate) enum MutationOutcome {
    /// Renamed AND the directory fsync confirmed — fully durable.
    Durable(Value),
    /// Renamed into visibility but the directory fsync failed: the record IS what readers see;
    /// only its crash-durability is unconfirmed.
    VisibleUnconfirmed(Value, String),
}

impl MutationOutcome {
    pub(crate) fn record(&self) -> &Value {
        match self {
            MutationOutcome::Durable(v) | MutationOutcome::VisibleUnconfirmed(v, _) => v,
        }
    }
    pub(crate) fn into_record(self) -> Value {
        match self {
            MutationOutcome::Durable(v) | MutationOutcome::VisibleUnconfirmed(v, _) => v,
        }
    }
    pub(crate) fn durable(&self) -> bool {
        matches!(self, MutationOutcome::Durable(_))
    }
}

/// Require crash-durable publication before a caller retires an enclosing recovery intent.
/// A renamed record is already visible, so it cannot be rolled back or treated as absent; the
/// only safe response is a typed retryable refusal while the retained intent drives convergence.
pub(crate) fn require_durable_mutation(
    outcome: MutationOutcome,
    refusal_code: &str,
    subject: &str,
) -> Result<Value, SeamErr> {
    match outcome {
        MutationOutcome::Durable(record) => Ok(record),
        MutationOutcome::VisibleUnconfirmed(_, detail) => Err((
            refusal_code.to_owned(),
            format!(
                "{subject} is visible, but crash durability is unconfirmed; retain the recovery intent and converge before reporting success ({detail})"
            ),
        )),
    }
}

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
) -> Result<MutationOutcome, SeamErr> {
    let _guard = GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let Some(mut fresh) = load_goal_run_by_id_strict(data_dir, goal_run_id).map_err(|message| {
        (
            "goal_run_registry_unreadable".to_string(),
            format!("GoalRun mutation cannot resolve strict owner truth ({message})"),
        )
    })?
    else {
        return Err((
            "goal_run_not_found".to_string(),
            format!("no durable GoalRun record '{goal_run_id}'"),
        ));
    };
    let goal_ref = fresh.get("goal_ref").and_then(Value::as_str).unwrap_or("");
    super::attempt_finding_routes::refuse_external_mutation_if_reserved(
        data_dir,
        goal_ref,
        "goal_run_mutation_in_flight",
    )
    .map_err(|(code, message)| (code, message))?;
    expect(&fresh)?;
    if let Some(obj) = fresh.as_object_mut() {
        mutate(obj);
    }
    match persist_goal_run_atomic(data_dir, goal_run_id, &fresh) {
        Ok(()) => Ok(MutationOutcome::Durable(fresh)),
        // #72 rounds 7 + 8 finding 1: the mutation is VISIBLE; only its durability is
        // unconfirmed. That is a SUCCESS variant, not an error — consumers must never handle a
        // visible mutation as absent, so the outcome crosses the seam structurally.
        Err(PersistFailure::RenamedDurabilityUnconfirmed(e)) => Ok(MutationOutcome::VisibleUnconfirmed(
            fresh,
            format!("directory fsync failed ({e}) — the record is visible, its crash-durability is unconfirmed"),
        )),
        Err(PersistFailure::NotCommitted(e)) => Err((
            "goal_run_persist_failed".to_string(),
            format!("the GoalRun record write did not commit ({e}) — the durable record is unchanged"),
        )),
    }
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
) -> Result<MutationOutcome, SeamErr> {
    update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "lifecycle reservation token mismatch — another operation owns this run"
                        .to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!(restore_status));
            obj.remove("lifecycle_op");
        },
    )
}

/// HTTP status for a seam/lifecycle refusal code — persistence and rollback lanes are 5xx
/// (infrastructure truth), a missing run is 404, every state/token refusal is a 409 conflict.
fn seam_status(code: &str) -> StatusCode {
    if (code.starts_with("work_result_payload_")
        && (code.contains("unavailable")
            || code.contains("unreadable")
            || code.contains("unresolved")
            || code.contains("unconfirmed")))
        || (code.starts_with("outcome_room_information_flow_label")
            && (code.contains("unreadable") || code.contains("unresolved")))
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    match code {
        "goal_run_not_found" => StatusCode::NOT_FOUND,
        "goal_run_persist_failed"
        | "goal_run_registry_unreadable"
        | "goal_run_persist_durability_unconfirmed"
        | "goal_run_finalize_failed"
        | "goal_run_rollback_failed"
        | "goal_run_release_failed" => StatusCode::INTERNAL_SERVER_ERROR,
        "outcome_room_child_pending_recovery"
        | "outcome_room_owner_publication_registry_unreadable"
        | "outcome_room_invocation_backlink_durability_unconfirmed"
        | "outcome_room_owner_goal_backlink_durability_unconfirmed" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
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
) -> (StatusCode, Json<Value>) {
    // #72 round 8 finding 2: this lane deletes NOTHING — it exists only for failures where no
    // durable artifact was admitted at all, so record removal (and its non-durable unlink
    // hazard) has been eliminated from the transaction entirely.
    let mut failures: Vec<String> = Vec::new();
    if let Err((rcode, rmsg)) =
        release_lifecycle_reservation(data_dir, goal_run_id, token, "active")
    {
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
            &format!(
                "{detail} AND rollback was incomplete ({}) — manual repair required",
                failures.join(", ")
            ),
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
    if let Err(f) =
        persist_record_durable(data_dir, RECONCILIATION_KIND, reconciliation_id, &preserved)
    {
        // A visible-but-unconfirmed update is NOT an incomplete rollback — the recovery state
        // is readable; only its durability is unconfirmed (#72 round 7 finding 1).
        if !f.visible() {
            failures.push(format!(
                "operation-record update ({RECONCILIATION_KIND}/{reconciliation_id}: {})",
                f.detail()
            ));
        }
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
                    "lifecycle reservation token mismatch — another operation owns this run"
                        .to_string(),
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
            if !attempts
                .iter()
                .any(|a| a.as_str() == Some(attempt_ref.as_str()))
            {
                attempts.push(json!(attempt_ref));
            }
            obj.insert("reconciliation_attempt_refs".into(), Value::Array(attempts));
        },
    );
    if let Err((rcode, rmsg)) = released {
        failures.push(format!("reservation release ({rcode}: {rmsg})"));
    }
    let status = preserved_record
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("recovery_required");
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
const ROOM_INFORMATION_FLOW_LABEL_DOMAIN: &str = "outcome-room-information-flow-labels";
const ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN: &str =
    "outcome-room-result-payload-write-admissions";
const ROOM_RESULT_PAYLOAD_BYTES_KIND: &str = "outcome-room-result-payload-bytes";
const ROOM_COMPONENT_RESOLUTION_DOMAIN: &str = "outcome-room-component-resolution-snapshots";
const ROOM_CONDUCTOR_VERIFICATION_DOMAIN: &str = "outcome-room-conductor-verification-evidence";
const INFORMATION_FLOW_LABEL_CONTRACT: &str = "schema://ioi/foundations/information-flow-label/v1";
const STORAGE_BACKEND_WRITE_ADMISSION_CONTRACT: &str =
    "schema://ioi/components/agentgres/storage-backend-write-admission/v1";
const RECEIPT_ENVELOPE_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";

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
        return Err(format!(
            "'{file}' is absolute — outputs are declared relative to their workspace root"
        ));
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
        return Err(format!(
            "'{}' escapes the workspace through a symlinked ancestor ('{}' resolves outside)",
            rel.display(),
            probe.display()
        ));
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
/// A per-file commit failure with the SAME two-outcome honesty as record persistence (#72
/// round 7 finding 1): `NotApplied` = the destination provably did not change;
/// `AppliedDurabilityUnconfirmed` = the COMPLETE destination is visible (rename landed) but the
/// parent-directory fsync failed — the journal must say unknown-but-possibly-applied, never
/// `applied: false`.
#[derive(Debug)]
enum CommitFailure {
    NotApplied(String),
    AppliedDurabilityUnconfirmed {
        bytes: u64,
        sha256: String,
        error: String,
    },
}

fn commit_one(
    staged: &std::path::Path,
    target_root: &std::fs::File,
    rel: &std::path::Path,
) -> Result<(u64, String), CommitFailure> {
    use std::io::Write;
    use CommitFailure::NotApplied;
    let parent = nofollow_fs::pin_parent(target_root, rel, true)
        .map_err(|e| NotApplied(format!("'{}': pinned parent walk refused ({e}) — a symlinked or swapped ancestor never redirects a write", rel.display())))?;
    let file_name = rel
        .file_name()
        .ok_or_else(|| NotApplied("destination has no file name".to_string()))?;
    let bytes =
        std::fs::read(staged).map_err(|e| NotApplied(format!("staged read failed ({e})")))?;
    let sha = sha256_hex(&bytes);
    let tmp_name = std::ffi::OsString::from(format!(
        ".{}.wal-tmp-{:x}",
        file_name.to_string_lossy(),
        nanos()
    ));
    let write_result = (|| -> std::io::Result<()> {
        let mut f = nofollow_fs::create_file_at(&parent, &tmp_name)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    if let Err(e) = write_result {
        let _ = nofollow_fs::unlink_at(&parent, &tmp_name);
        return Err(NotApplied(format!("temporary write failed ({e})")));
    }
    if let Err(e) = nofollow_fs::rename_at(&parent, &tmp_name, file_name) {
        let _ = nofollow_fs::unlink_at(&parent, &tmp_name);
        return Err(NotApplied(format!("atomic rename failed ({e})")));
    }
    if let Err(e) = parent.sync_all() {
        return Err(CommitFailure::AppliedDurabilityUnconfirmed {
            bytes: bytes.len() as u64,
            sha256: sha,
            error: format!("parent directory sync failed ({e})"),
        });
    }
    Ok((bytes.len() as u64, sha))
}

/// Bounded intake (#72 round 7 finding 4): hard limits on what one reconcile attempt may pull
/// from candidate workspaces — refusals are typed, never truncated silently.
const MAX_OUTPUT_FILES: usize = 256;
const MAX_OUTPUT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ATTEMPT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Read one declared output set through a pinned workspace descriptor and return the exact,
/// bounded byte facts in deterministic path order. This is used both at invocation completion
/// (before the durable receipt is published) and at WorkResult normalization; any later byte,
/// path, symlink, or file-kind substitution therefore fails closed.
fn bounded_workspace_output_file_facts(
    workspace: &str,
    changed_files: &[Value],
) -> Result<Vec<Value>, SeamErr> {
    if changed_files.len() > MAX_OUTPUT_FILES {
        return Err((
            "work_result_output_truth_unresolved".into(),
            format!(
                "the invocation declares {} output files; the bounded limit is {MAX_OUTPUT_FILES}",
                changed_files.len()
            ),
        ));
    }
    let workspace_root =
        nofollow_fs::open_dir_pinned(std::path::Path::new(workspace)).map_err(|error| {
            (
                "work_result_output_truth_unreadable".into(),
                format!("candidate workspace cannot be pinned ({error})"),
            )
        })?;
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0u64;
    let mut output_files = Vec::with_capacity(changed_files.len());
    for value in changed_files {
        let file = value.as_str().ok_or_else(|| {
            (
                "work_result_output_truth_unresolved".into(),
                "the invocation changed-file set contains a non-string entry".into(),
            )
        })?;
        let rel = contained_rel_path(file).map_err(|error| {
            (
                "work_result_output_truth_unresolved".into(),
                format!("changed-file path is not contained ({error})"),
            )
        })?;
        if !seen.insert(rel.clone()) {
            return Err((
                "work_result_output_truth_unresolved".into(),
                format!("changed-file path '{}' is duplicated", rel.display()),
            ));
        }
        let remaining = MAX_ATTEMPT_TOTAL_BYTES.saturating_sub(total_bytes);
        let budget = MAX_OUTPUT_FILE_BYTES.min(remaining);
        let bytes =
            nofollow_fs::read_contained(&workspace_root, &rel, budget).map_err(|error| {
                (
                    "work_result_output_truth_unreadable".into(),
                    format!(
                        "changed-file '{}' cannot be read exactly ({error:?})",
                        rel.display()
                    ),
                )
            })?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        output_files.push(json!({
            "relative_path":rel.to_string_lossy(),
            "sha256":sha256_hex(&bytes),
            "bytes":bytes.len(),
        }));
    }
    output_files
        .sort_by(|left, right| text(left, "relative_path").cmp(text(right, "relative_path")));
    Ok(output_files)
}

/// DURABLE staging write (#72 round 7 finding 2): tmp sibling → file fsync → rename → fsync of
/// every directory in the freshly created chain up to the data dir. The staged attempt is the
/// immutable declared input a crash-recovery validates against — it must actually survive the
/// crash, not merely exist in the page cache.
fn stage_one(
    data_dir: &str,
    staging_root: &std::path::Path,
    rel: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    let staged = staging_root.join(rel);
    let parent = staged
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| staging_root.to_path_buf());
    std::fs::create_dir_all(&parent)?;
    let tmp = parent.join(format!(".stage-tmp-{:x}", nanos()));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, &staged) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let stop = std::path::Path::new(data_dir);
    let mut d = parent.clone();
    loop {
        std::fs::File::open(&d)?.sync_all()?;
        if d == stop {
            break;
        }
        match d.parent() {
            Some(p) => d = p.to_path_buf(),
            None => break,
        }
    }
    Ok(staged)
}

const GOAL_RUN_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run.v1";
const CANONICAL_GOAL_RUN_SCHEMA_VERSION: &str = "ioi.goal-run.v1";
const INVOCATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-invocation.v1";
const RECONCILIATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-reconciliation.v1";

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// The receipts family keys files by the FULL receipt ref, sanitized. This normalization was
/// the durable writer's own until #73; the shared core now REJECTS unsafe ids instead of
/// normalizing them, so the ref→file-key mapping is THIS plane's explicit naming policy — the
/// on-disk filenames are byte-for-byte what they always were.
fn receipt_file_key(receipt_ref: &str) -> String {
    receipt_ref.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
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

type HttpRefusal = (StatusCode, Json<Value>);

fn bad_with_details(status: StatusCode, code: &str, message: &str, details: Value) -> HttpRefusal {
    (
        status,
        Json(json!({
            "ok": false,
            "error": { "code": code, "message": message, "details": details }
        })),
    )
}

/// Conversation-draft GoalRuns deliberately admit durable intent without execution capacity or a
/// result lane. Enforce that owner truth after authorization and before parsing or mutating any
/// WorkResult/OutcomeDelta state.
pub(crate) fn refuse_result_write_for_zero_execution_goal(goal_run: &Value) -> Option<HttpRefusal> {
    if text(goal_run, "origin_surface") != "ioi_goal_chat" {
        return None;
    }
    let total = goal_run
        .pointer("/declared_invocation_budget/max_total_invocations")
        .and_then(Value::as_u64);
    let parallel = goal_run
        .pointer("/declared_invocation_budget/max_parallel_invocations")
        .and_then(Value::as_u64);
    let ceiling_ref = goal_run
        .get("goal_run_execution_ceiling_revision_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let ceiling_hash = goal_run
        .get("goal_run_execution_ceiling_content_hash")
        .and_then(Value::as_str)
        .unwrap_or("");
    if total != Some(0)
        || parallel != Some(0)
        || !ceiling_ref
            .starts_with("goal-run-execution-ceiling://ioi-goal-draft-zero/revision/sha256:")
        || !ceiling_ref.ends_with(ceiling_hash)
    {
        return Some(bad(
            StatusCode::CONFLICT,
            "goal_run_execution_bounds_integrity_failure",
            "The ioi_goal_draft GoalRun no longer retains its exact zero-execution ceiling and declared budget.",
        ));
    }
    Some(bad_with_details(
        StatusCode::UNPROCESSABLE_ENTITY,
        "goal_run_execution_budget_exhausted",
        "This admitted GoalRun is intentionally resultless and has zero invocation capacity.",
        json!({
            "goal_run_ref": goal_run.get("goal_ref"),
            "goal_run_execution_ceiling_revision_ref": ceiling_ref,
            "declared_invocation_budget": goal_run.get("declared_invocation_budget"),
            "effects_started": false
        }),
    ))
}

fn durable_write(
    data_dir: &str,
    family: &str,
    key: &str,
    value: &Value,
) -> Result<(), HttpRefusal> {
    match persist_record_durable(data_dir, family, key, value) {
        Ok(()) => Ok(()),
        Err(PersistFailure::NotCommitted(error)) => Err(bad_with_details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_activation_persist_failed",
            "The activation crossing did not durably commit; no success is reported.",
            json!({ "family": family, "error": error.to_string() }),
        )),
        Err(PersistFailure::RenamedDurabilityUnconfirmed(error)) => Err(bad_with_details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_activation_persist_durability_unconfirmed",
            "The activation record is visible but its crash durability is unconfirmed; retry the same idempotent request.",
            json!({ "family": family, "error": error.to_string() }),
        )),
    }
}

fn closed_request(value: &Value, allowed: &[&str], code: &str) -> Result<(), HttpRefusal> {
    let Some(object) = value.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            code,
            "The request body must be a closed JSON object.",
        ));
    };
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(bad_with_details(
            StatusCode::BAD_REQUEST,
            code,
            "Unknown activation request fields fail closed.",
            json!({ "field": unknown }),
        ));
    }
    Ok(())
}

fn bounded_idempotency_key(value: &Value) -> Result<String, HttpRefusal> {
    let key = value
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if !(8..=200).contains(&key.len()) || key.chars().any(char::is_control) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_idempotency_key_invalid",
            "idempotency_key must contain 8..200 non-control characters.",
        ));
    }
    Ok(key.to_string())
}

fn bounded_constraints(value: &Value) -> Result<Vec<Value>, HttpRefusal> {
    let constraints = match value.get("constraints") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) if items.len() <= 64 => items.clone(),
        _ => {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_activation_constraints_invalid",
                "constraints must be an array with at most 64 bounded strings.",
            ))
        }
    };
    if constraints.iter().any(|item| {
        item.as_str()
            .map(|text| text.trim().is_empty() || text.len() > 4096)
            .unwrap_or(true)
    }) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_constraints_invalid",
            "Every constraint must be a non-empty string of at most 4096 bytes.",
        ));
    }
    Ok(constraints)
}

fn activation_principal(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<(String, String), HttpRefusal> {
    let posture = super::lifecycle_routes::deployment_auth_posture(&st.data_dir, headers);
    let resolved = super::lifecycle_routes::resolve_principal(&st.data_dir, headers);
    if posture == "exposed_untrusted" {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "goal_run_activation_authenticated_principal_required",
            "An exposed deployment cannot admit Goal Chat activation without enforced identity.",
        ));
    }
    if let Some(principal) = resolved {
        let principal_id = text(&principal, "principal_id");
        if principal_id.is_empty() {
            return Err(bad(
                StatusCode::UNAUTHORIZED,
                "goal_run_activation_principal_unresolved",
                "The authenticated session did not resolve a principal identity.",
            ));
        }
        return Ok((
            format!("user://{principal_id}"),
            "authenticated_session".to_string(),
        ));
    }
    if super::lifecycle_routes::auth_enforced(&st.data_dir, headers) {
        return Err(bad(
            StatusCode::UNAUTHORIZED,
            "goal_run_activation_authentication_required",
            "Authentication is required before a Goal Chat activation may be drafted or reviewed.",
        ));
    }
    Ok((
        "user://local-operator".to_string(),
        "local_development_operator".to_string(),
    ))
}

fn global_truth_reader(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Option<String>, HttpRefusal> {
    match super::lifecycle_routes::deployment_auth_posture(&st.data_dir, headers) {
        "local_development" => Ok(None),
        "exposed_untrusted" => Err(bad(
            StatusCode::FORBIDDEN,
            "goal_run_global_truth_exposed_untrusted_refused",
            "Global GoalRun truth is unavailable on an exposed deployment without enforced identity.",
        )),
        _ => {
            let principal = super::lifecycle_routes::resolve_principal(&st.data_dir, headers)
                .ok_or_else(|| {
                    bad(
                        StatusCode::UNAUTHORIZED,
                        "goal_run_global_truth_authentication_required",
                        "Authentication is required before reading global GoalRun truth.",
                    )
                })?;
            let principal_id = text(&principal, "principal_id");
            if principal_id.is_empty() {
                return Err(bad(
                    StatusCode::UNAUTHORIZED,
                    "goal_run_global_truth_principal_unresolved",
                    "The authenticated request did not resolve a principal identity.",
                ));
            }
            Ok(Some(format!("user://{principal_id}")))
        }
    }
}

fn authorize_resolved_goal_run_mutation(
    resolved_reader: Option<&str>,
    goal_run: &Value,
) -> Result<(), HttpRefusal> {
    if resolved_reader.is_some_and(|owner_ref| {
        goal_run.get("owner_ref").and_then(Value::as_str) != Some(owner_ref)
    }) {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "goal_run_mutation_owner_mismatch",
            "The authenticated principal does not own this GoalRun and cannot mutate its result truth.",
        ));
    }
    Ok(())
}

fn missing_goal_run_mutation_refusal(resolved_reader: Option<&str>) -> HttpRefusal {
    if resolved_reader.is_some() {
        return bad(
            StatusCode::FORBIDDEN,
            "goal_run_mutation_owner_mismatch",
            "The authenticated principal does not own this GoalRun and cannot mutate its result truth.",
        );
    }
    bad(
        StatusCode::NOT_FOUND,
        "goal_run_not_found",
        "Unknown GoalRun.",
    )
}

fn fence_pending_room_projection(data_dir: &str) -> Result<(), HttpRefusal> {
    super::outcome_room_system_routes::refuse_while_any_intent_pending(data_dir).map_err(
        |(code, message)| {
            eprintln!("GoalRun pending-room refusal: {code} ({message})");
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                &code,
                "GoalRun truth is unavailable while a room transaction requires recovery.",
            )
        },
    )
}

fn resolve_activation_project(
    _data_dir: &str,
    requested: Option<&Value>,
) -> Result<Value, HttpRefusal> {
    let Some(requested) = requested.filter(|value| !value.is_null()) else {
        return Ok(Value::Null);
    };
    let Some(project_ref) = requested.as_str() else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_project_ref_invalid",
            "project_ref must be null or a canonical project:// reference.",
        ));
    };
    if !project_ref.starts_with("project://") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_project_ref_invalid",
            "project_ref must be null or a canonical project:// reference.",
        ));
    }
    Err(bad_with_details(
        StatusCode::UNPROCESSABLE_ENTITY,
        "goal_run_activation_project_binding_deferred",
        "Non-null project binding is deferred until the project owner exposes one strict canonical project:// identity and lookup contract; this activation remains project-neutral.",
        json!({ "project_ref": project_ref }),
    ))
}

fn activation_ref(id: &str) -> String {
    format!("goal-run-activation://{id}")
}

fn activation_key_from_ref(reference: &str) -> Option<&str> {
    reference
        .strip_prefix("goal-run-activation://")
        .filter(|tail| {
            !tail.is_empty()
                && tail.len() <= 160
                && tail.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

fn sealed(mut record: Value) -> Value {
    let root = sha256_canonical(&record);
    if let Some(object) = record.as_object_mut() {
        object.insert("receipt_root".into(), json!(root));
    }
    record
}

fn sealed_record_is_intact(record: &Value) -> bool {
    let claimed = text(record, "receipt_root").to_string();
    if claimed.is_empty() {
        return false;
    }
    let mut material = record.clone();
    material
        .as_object_mut()
        .is_some_and(|object| object.remove("receipt_root").is_some())
        && sha256_canonical(&material) == claimed
}

#[derive(Clone)]
struct ActivationProfileResolution {
    profile: Value,
    policy: Value,
    component: Value,
    execution_ceiling: Value,
    profile_key: String,
    policy_key: String,
    component_key: String,
    execution_ceiling_key: String,
}

fn activation_record_strict(
    data_dir: &str,
    family: &str,
    key: &str,
) -> Result<Option<Value>, HttpRefusal> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_registry_unreadable",
                "A daemon-owned activation registry cannot be pinned.",
                json!({ "family": family, "error": error.to_string() }),
            ))
        }
    };
    let name = format!("{key}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(Some((_file, bytes))) => bytes,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_registry_unreadable",
                "A daemon-owned activation record cannot be read through the strict boundary.",
                json!({ "family": family, "key": key, "error": error.to_string() }),
            ))
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_registry_unreadable",
            "A daemon-owned activation record is malformed.",
            json!({ "family": family, "key": key, "error": error.to_string() }),
        )
    })
}

fn required_activation_record(
    data_dir: &str,
    family: &str,
    key: &str,
    missing_code: &str,
    missing_message: &str,
) -> Result<Value, HttpRefusal> {
    activation_record_strict(data_dir, family, key)?
        .ok_or_else(|| bad(StatusCode::CONFLICT, missing_code, missing_message))
}

/// Resolve only the single deterministic activation slot needed for authorization. Handlers call
/// this before loading control, source, authority, receipt, state, or GoalRun bytes, so a caller
/// cannot use a deep projection as an owner-existence oracle.
fn activation_for_preauthorization(
    data_dir: &str,
    id: &str,
    conceal_missing: bool,
) -> Result<Value, HttpRefusal> {
    if activation_key_from_ref(&activation_ref(id)).is_none() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_id_invalid",
            "The activation id is not a bounded canonical identifier.",
        ));
    }
    activation_record_strict(data_dir, GOAL_RUN_ACTIVATION_KIND, id)?.ok_or_else(|| {
        if conceal_missing {
            bad(
                StatusCode::FORBIDDEN,
                "goal_run_activation_projection_owner_mismatch",
                "The authenticated principal does not own this activation.",
            )
        } else {
            bad(
                StatusCode::NOT_FOUND,
                "goal_run_activation_not_found",
                "Unknown GoalRun activation.",
            )
        }
    })
}

fn require_activation_owner(activation: &Value, principal_ref: &str) -> Result<(), HttpRefusal> {
    if activation
        .pointer("/source_context/source_owner_ref")
        .and_then(Value::as_str)
        != Some(principal_ref)
        || activation
            .get("requesting_principal_ref")
            .and_then(Value::as_str)
            != Some(principal_ref)
    {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "goal_run_activation_projection_owner_mismatch",
            "The authenticated principal does not own this activation.",
        ));
    }
    Ok(())
}

fn persist_immutable_activation_record(
    data_dir: &str,
    family: &str,
    key: &str,
    record: &Value,
) -> Result<(), HttpRefusal> {
    if let Some(existing) = activation_record_strict(data_dir, family, key)? {
        if existing != *record {
            return Err(bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_immutable_release_conflict",
                "An immutable daemon-owned activation release key already contains different bytes.",
                json!({ "family": family, "key": key }),
            ));
        }
    }
    durable_write(data_dir, family, key, record)
}

fn release_material(record: &Value, domain: &str, kind: &str) -> Result<Value, HttpRefusal> {
    let mut body = record.as_object().cloned().ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "goal_run_activation_release_invalid",
            "A daemon-owned activation release must be a closed object.",
        )
    })?;
    for field in [
        "revision_ref",
        "policy_ref",
        "content_hash",
        "registry_status",
        "registry_lifecycle_ref",
    ] {
        body.remove(field);
    }
    Ok(json!({ "domain": domain, "kind": kind, "body": body }))
}

fn verify_content_addressed_release(
    record: &Value,
    ref_field: &str,
    expected_prefix: &str,
    domain: &str,
    kind: &str,
) -> Result<(), HttpRefusal> {
    if text(record, "registry_status") != "released" {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_profile_not_released",
            "New GoalRun admission requires a released immutable definition.",
        ));
    }
    let recomputed = sha256_canonical(&release_material(record, domain, kind)?);
    if text(record, "content_hash") != recomputed
        || text(record, ref_field) != format!("{expected_prefix}{recomputed}")
    {
        return Err(bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_profile_integrity_failure",
            "A daemon-owned immutable definition no longer reproduces its content address.",
            json!({ "ref_field": ref_field, "recomputed_content_hash": recomputed }),
        ));
    }
    Ok(())
}

fn execution_ceiling_commitment(record: &Value) -> Value {
    json!({
        "domain": "ioi.goal-run-execution-ceiling-release-jcs-sha256.v1",
        "schema_version": record.get("schema_version").cloned().unwrap_or(Value::Null),
        "goal_run_execution_ceiling_id": record.get("goal_run_execution_ceiling_id").cloned().unwrap_or(Value::Null),
        "owner_ref": record.get("owner_ref").cloned().unwrap_or(Value::Null),
        "max_total_invocations": record.get("max_total_invocations").cloned().unwrap_or(Value::Null),
        "max_parallel_invocations": record.get("max_parallel_invocations").cloned().unwrap_or(Value::Null)
    })
}

fn zero_execution_ceiling() -> Result<Value, HttpRefusal> {
    let mut record = json!({
        "schema_version": "ioi.goal-run-execution-ceiling.v1",
        "goal_run_execution_ceiling_id": "goal-run-execution-ceiling://ioi-goal-draft-zero",
        "revision_ref": Value::Null,
        "content_hash": Value::Null,
        "owner_ref": "system://ioi",
        "max_total_invocations": 0,
        "max_parallel_invocations": 0,
        "registry_status": "released"
    });
    let content_hash = sha256_canonical(&execution_ceiling_commitment(&record));
    record["content_hash"] = json!(content_hash);
    record["revision_ref"] = json!(format!(
        "goal-run-execution-ceiling://ioi-goal-draft-zero/revision/{}",
        text(&record, "content_hash")
    ));
    validate_zero_execution_ceiling(&record)?;
    Ok(record)
}

fn validate_zero_execution_ceiling(record: &Value) -> Result<(), HttpRefusal> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        "schema://ioi/applications/ioi-ai/goal-run-execution-ceiling/v1",
        record,
    )
    .map_err(|error| {
        bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_execution_ceiling_contract_invalid",
            "The immutable GoalRun execution ceiling does not satisfy its registered contract.",
            json!({ "error": error }),
        )
    })?;
    let recomputed = sha256_canonical(&execution_ceiling_commitment(record));
    if text(record, "content_hash") != recomputed
        || text(record, "revision_ref")
            != format!("goal-run-execution-ceiling://ioi-goal-draft-zero/revision/{recomputed}")
        || record.get("max_total_invocations").and_then(Value::as_u64) != Some(0)
        || record
            .get("max_parallel_invocations")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_execution_ceiling_integrity_failure",
            "The M4 ioi_goal_draft ceiling must remain the exact immutable zero-execution release.",
        ));
    }
    Ok(())
}

fn activation_component_from_profile(source: &Value) -> Result<Value, HttpRefusal> {
    let source_ref = text(source, "profile_ref");
    let harness = text(source, "harness");
    let execution_wiring = source
        .pointer("/adapter/execution_wiring")
        .and_then(Value::as_str)
        .unwrap_or("");
    if source_ref.is_empty() || harness.is_empty() || execution_wiring.is_empty() {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_harness_profile_unresolved",
            "The daemon could not freeze an actual harness-profile definition for this GoalRun profile.",
        ));
    }
    let mut record = json!({
        "schema_version": "ioi.goal-run-resolved-component-revision.v1",
        "component_kind": "harness_profile",
        "source_profile_ref": source_ref,
        "harness": harness,
        "adapter": source.get("adapter").cloned().unwrap_or(Value::Null),
        "capabilities": source.get("capabilities").cloned().unwrap_or_else(|| json!({})),
        "model_binding": source.get("model_binding").cloned().unwrap_or_else(|| json!({})),
        "runtime_eligibility_claimed": false,
        "registry_lifecycle_ref": Value::Null,
        "registry_status": "released"
    });
    let hash = sha256_canonical(&release_material(
        &record,
        "ioi.goal-run-resolved-component-revision-jcs-sha256.v1",
        "harness_profile",
    )?);
    record["content_hash"] = json!(hash);
    record["revision_ref"] = json!(format!(
        "harness-profile://daemon-resolved/{}/revision/{}",
        safe(harness),
        text(&record, "content_hash")
    ));
    Ok(record)
}

fn activation_policy(component: &Value) -> Result<Value, HttpRefusal> {
    let receipt_type = std::env::var("IOI_TEST_GOAL_RUN_ACTIVATION_RECEIPT_TYPE")
        .unwrap_or_else(|_| GOAL_RUN_ACTIVATION_RECEIPT_TYPE.to_string());
    let mut record = json!({
        "schema_version": "ioi.goal-run-admission-policy.v1",
        "allowed_source_kinds": ["ioi_goal_draft"],
        "allowed_result_profiles": ["research"],
        "allowed_managed_execution_modes": ["standard"],
        "allowed_contributor_scopes": ["my_workers"],
        "allowed_authority_scopes": ["scope:goal.run.create"],
        "allowed_primitive_capability_refs": [],
        "direct_path_requirements": {
            "requires_system_membership": false,
            "requires_shared_frontier": false,
            "requires_outcome_room": false,
            "requires_collective_scheduling": false,
            "policy_requires_system_path": false
        },
        "resolved_component_revision_refs": [component.get("revision_ref").cloned().unwrap_or(Value::Null)],
        "receipt_registry": [{
            "boundary_event": "activation",
            "receipt_type": receipt_type,
            "receipt_profile_ref": GOAL_RUN_ACTIVATION_RECEIPT_PROFILE,
            "required": true
        }],
        "registry_lifecycle_ref": Value::Null,
        "registry_status": "released"
    });
    let hash = sha256_canonical(&release_material(
        &record,
        "ioi.goal-run-admission-policy-jcs-sha256.v1",
        "goal_run_admission",
    )?);
    record["content_hash"] = json!(hash);
    record["policy_ref"] = json!(format!(
        "orchestration-policy://bounded-goal-run-admission/revision/{}",
        text(&record, "content_hash")
    ));
    Ok(record)
}

fn activation_profile(
    policy: &Value,
    component: &Value,
    execution_ceiling: &Value,
) -> Result<Value, HttpRefusal> {
    let mut record = json!({
        "schema_version": "ioi.goal-run-profile.v1",
        "goal_run_profile_id": "goal-run-profile://generic-adaptive",
        "version": "1",
        "predecessor_revision_ref": Value::Null,
        "owner_ref": "system://ioi",
        "display_name": "Generic adaptive",
        "description": "A bounded single-subject profile whose admission dependencies are frozen from daemon-owned releases.",
        "applicable_goal_class_refs": ["schema://ioi/ioi-ai/goal-draft/v1"],
        "compatible_domain_object_schema_refs": ["schema://ioi/foundations/work-result/v3"],
        "orchestration_policy_ref": policy.get("policy_ref").cloned().unwrap_or(Value::Null),
        "constraint_derivation_policy_refs": ["policy://ioi/goal-run/source-derived-constraints/v1"],
        "workflow_template_revision_refs": [],
        "role_topology_requirement_refs": [],
        "harness_requirement_refs": [],
        "pinned_harness_profile_revision_refs": [component.get("revision_ref").cloned().unwrap_or(Value::Null)],
        "skill_requirement_refs": [],
        "pinned_skill_manifest_revision_refs": [],
        "worker_requirement_refs": [],
        "model_route_requirement_refs": [],
        "service_requirement_refs": [],
        "runtime_tool_contract_requirement_refs": [],
        "primitive_capability_requirements": [],
        "context_requirement_profile_refs": [],
        "input_contract_ref": "schema://ioi/ioi-ai/goal-draft/v1",
        "output_contract_ref": "schema://ioi/foundations/work-result/v3",
        "acceptance_contract_refs": [],
        "verifier_requirement_refs": [],
        "budget_time_and_resource_ceiling_refs": [execution_ceiling.get("revision_ref").cloned().unwrap_or(Value::Null)],
        "stop_policy_ref": "policy://ioi/goal-run/bounded-stop/v1",
        "recovery_policy_ref": "policy://ioi/goal-run/bounded-recovery/v1",
        "escalation_policy_ref": "policy://ioi/goal-run/bounded-escalation/v1",
        "learning_boundary_requirement_ref": Value::Null,
        "pinned_learning_boundary_profile_ref": Value::Null,
        "allowed_override_schema_ref": Value::Null,
        "compatibility_refs": [],
        "provenance_refs": [component.get("source_profile_ref").cloned().unwrap_or(Value::Null)],
        "evaluation_and_benchmark_refs": [],
        "promotion_policy_ref": Value::Null,
        "revocation_and_recall_policy_ref": Value::Null,
        "registry_lifecycle_ref": Value::Null,
        "registry_status": "released"
    });
    let hash = sha256_canonical(&release_material(
        &record,
        "ioi.goal-run-profile-release-jcs-sha256.v1",
        "goal_run_profile",
    )?);
    record["content_hash"] = json!(hash);
    record["revision_ref"] = json!(format!(
        "goal-run-profile://generic-adaptive/revision/{}",
        text(&record, "content_hash")
    ));
    Ok(record)
}

fn validate_activation_receipt_registry(policy: &Value) -> Result<(), HttpRefusal> {
    let entries = policy
        .get("receipt_registry")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_registry_missing",
                "The admitted policy has no typed receipt registry.",
            )
        })?;
    if entries.is_empty() {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_receipt_registry_missing",
            "The admitted policy has no typed receipt registry entries.",
        ));
    }
    for entry in entries {
        if text(entry, "receipt_type") != GOAL_RUN_ACTIVATION_RECEIPT_TYPE
            || text(entry, "receipt_profile_ref") != GOAL_RUN_ACTIVATION_RECEIPT_PROFILE
            || text(entry, "boundary_event") != "activation"
            || entry.get("required").and_then(Value::as_bool) != Some(true)
        {
            return Err(bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_activation_receipt_obligation_type_unregistered",
                "The admitted policy names a receipt obligation not registered for this bounded activation slice.",
                json!({ "entry": entry }),
            ));
        }
    }
    Ok(())
}

async fn ensure_activation_profile(
    st: &DaemonState,
) -> Result<ActivationProfileResolution, HttpRefusal> {
    // Both registries are proved before any activation-family record is persisted. In
    // particular, do not let seed reconciliation overwrite a malformed canonical slot and then
    // present the repaired projection as the fact that authorized activation.
    super::model_routes::strict_routes_seeded(&st.data_dir).map_err(|detail| {
        bad_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "goal_run_activation_model_route_registry_unreadable",
            "The complete model-route registry cannot be strictly resolved before activation persistence.",
            json!({ "detail": detail }),
        )
    })?;
    let profiles = super::harness_routes::live_profiles_strict(st).map_err(|detail| {
        bad_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "goal_run_activation_harness_registry_unreadable",
            "The complete live harness-profile registry cannot be strictly resolved before activation persistence.",
            json!({ "detail": detail }),
        )
    })?;
    let source = super::harness_routes::unique_profile_by_harness(&profiles, "hypervisor_worker")
        .map_err(|detail| {
            bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_harness_profile_unresolved",
                "Exactly one daemon-owned Hypervisor worker profile must be available to freeze into the selected GoalRun profile.",
                json!({ "detail": detail }),
            )
        })?;
    let component = activation_component_from_profile(source)?;
    let component_hash = text(&component, "content_hash");
    let component_key = format!(
        "grc_{}",
        component_hash
            .strip_prefix("sha256:")
            .unwrap_or(component_hash)
    );
    persist_immutable_activation_record(
        &st.data_dir,
        GOAL_RUN_RESOLVED_COMPONENT_KIND,
        &component_key,
        &component,
    )?;
    let execution_ceiling = zero_execution_ceiling()?;
    persist_immutable_activation_record(
        &st.data_dir,
        GOAL_RUN_EXECUTION_CEILING_REVISION_KIND,
        BUILTIN_ZERO_EXECUTION_CEILING_KEY,
        &execution_ceiling,
    )?;
    let policy = activation_policy(&component)?;
    persist_immutable_activation_record(
        &st.data_dir,
        GOAL_RUN_ADMISSION_POLICY_REVISION_KIND,
        BUILTIN_BOUNDED_ADMISSION_POLICY_KEY,
        &policy,
    )?;
    validate_activation_receipt_registry(&policy)?;
    let profile = activation_profile(&policy, &component, &execution_ceiling)?;
    persist_immutable_activation_record(
        &st.data_dir,
        GOAL_RUN_PROFILE_REVISION_KIND,
        BUILTIN_GENERIC_ADAPTIVE_PROFILE_KEY,
        &profile,
    )?;
    Ok(ActivationProfileResolution {
        profile,
        policy,
        component,
        execution_ceiling,
        profile_key: BUILTIN_GENERIC_ADAPTIVE_PROFILE_KEY.to_string(),
        policy_key: BUILTIN_BOUNDED_ADMISSION_POLICY_KEY.to_string(),
        component_key,
        execution_ceiling_key: BUILTIN_ZERO_EXECUTION_CEILING_KEY.to_string(),
    })
}

fn load_activation_profile(
    data_dir: &str,
    control: &Value,
) -> Result<ActivationProfileResolution, HttpRefusal> {
    let required = |path: &str| {
        control
            .pointer(path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                bad_with_details(
                    StatusCode::CONFLICT,
                    "goal_run_activation_profile_resolution_missing",
                    "The activation control does not retain its exact profile-resolution coordinate.",
                    json!({ "path": path }),
                )
            })
    };
    let profile_key = required("/resolved_profile/profile_key")?;
    let policy_key = required("/resolved_profile/policy_key")?;
    let component_key = required("/resolved_profile/component_key")?;
    let execution_ceiling_key = required("/resolved_profile/execution_ceiling_key")?;
    let profile = activation_record_strict(data_dir, GOAL_RUN_PROFILE_REVISION_KIND, &profile_key)?
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "goal_run_activation_profile_missing",
                "The exact daemon-owned GoalRunProfile release is missing.",
            )
        })?;
    let policy = activation_record_strict(
        data_dir,
        GOAL_RUN_ADMISSION_POLICY_REVISION_KIND,
        &policy_key,
    )?
    .ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "goal_run_activation_policy_missing",
            "The exact daemon-owned GoalRun admission policy release is missing.",
        )
    })?;
    let component =
        activation_record_strict(data_dir, GOAL_RUN_RESOLVED_COMPONENT_KIND, &component_key)?
            .ok_or_else(|| {
                bad(
                    StatusCode::CONFLICT,
                    "goal_run_activation_component_missing",
                    "The exact daemon-resolved profile component is missing.",
                )
            })?;
    let execution_ceiling = activation_record_strict(
        data_dir,
        GOAL_RUN_EXECUTION_CEILING_REVISION_KIND,
        &execution_ceiling_key,
    )?
    .ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "goal_run_execution_ceiling_missing",
            "The exact immutable GoalRun execution-ceiling release is missing.",
        )
    })?;
    verify_content_addressed_release(
        &profile,
        "revision_ref",
        "goal-run-profile://generic-adaptive/revision/",
        "ioi.goal-run-profile-release-jcs-sha256.v1",
        "goal_run_profile",
    )?;
    verify_content_addressed_release(
        &policy,
        "policy_ref",
        "orchestration-policy://bounded-goal-run-admission/revision/",
        "ioi.goal-run-admission-policy-jcs-sha256.v1",
        "goal_run_admission",
    )?;
    let harness = text(&component, "harness");
    verify_content_addressed_release(
        &component,
        "revision_ref",
        &format!(
            "harness-profile://daemon-resolved/{}/revision/",
            safe(harness)
        ),
        "ioi.goal-run-resolved-component-revision-jcs-sha256.v1",
        "harness_profile",
    )?;
    validate_activation_receipt_registry(&policy)?;
    validate_zero_execution_ceiling(&execution_ceiling)?;
    if control
        .pointer("/resolved_profile/revision_ref")
        .and_then(Value::as_str)
        != profile.get("revision_ref").and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/content_hash")
            .and_then(Value::as_str)
            != profile.get("content_hash").and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/policy_ref")
            .and_then(Value::as_str)
            != policy.get("policy_ref").and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/policy_content_hash")
            .and_then(Value::as_str)
            != policy.get("content_hash").and_then(Value::as_str)
        || profile.get("orchestration_policy_ref") != policy.get("policy_ref")
        || profile
            .get("pinned_harness_profile_revision_refs")
            .and_then(Value::as_array)
            .map(|refs| {
                refs.as_slice()
                    != [component
                        .get("revision_ref")
                        .cloned()
                        .unwrap_or(Value::Null)]
            })
            .unwrap_or(true)
        || control
            .pointer("/resolved_profile/component_ref")
            .and_then(Value::as_str)
            != component.get("revision_ref").and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/component_content_hash")
            .and_then(Value::as_str)
            != component.get("content_hash").and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/execution_ceiling_revision_ref")
            .and_then(Value::as_str)
            != execution_ceiling
                .get("revision_ref")
                .and_then(Value::as_str)
        || control
            .pointer("/resolved_profile/execution_ceiling_content_hash")
            .and_then(Value::as_str)
            != execution_ceiling
                .get("content_hash")
                .and_then(Value::as_str)
        || profile
            .get("budget_time_and_resource_ceiling_refs")
            .and_then(Value::as_array)
            .map(|refs| {
                refs.as_slice()
                    != [execution_ceiling
                        .get("revision_ref")
                        .cloned()
                        .unwrap_or(Value::Null)]
            })
            .unwrap_or(true)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_profile_resolution_changed",
            "The retained profile, policy, or resolved component no longer matches the draft-time closure.",
        ));
    }
    Ok(ActivationProfileResolution {
        profile,
        policy,
        component,
        execution_ceiling,
        profile_key,
        policy_key,
        component_key,
        execution_ceiling_key,
    })
}

fn policy_bool(policy: &Value, field: &str) -> Result<bool, HttpRefusal> {
    policy
        .pointer(&format!("/direct_path_requirements/{field}"))
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_policy_incomplete",
                "The admitted path policy lacks a required boolean predicate.",
                json!({ "field": field }),
            )
        })
}

fn activation_admission_material(
    data_dir: &str,
    resolved: &ActivationProfileResolution,
    activation: &Value,
    goal_draft: &Value,
    authority_decision: &Value,
    goal_ref: &str,
    activation_id: &str,
    effective_constraint_hash: &str,
) -> Result<(Value, Value), HttpRefusal> {
    let source_kind = activation
        .pointer("/source_context/source_kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let result_profile = text(goal_draft, "result_profile");
    let allowed = |field: &str, value: &str| {
        resolved
            .policy
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|entry| entry.as_str() == Some(value)))
    };
    let requires_room = source_kind == "outcome_room_claim"
        || policy_bool(&resolved.policy, "requires_outcome_room")?;
    let requires_frontier =
        requires_room || policy_bool(&resolved.policy, "requires_shared_frontier")?;
    let requires_collective = text(goal_draft, "contributor_scope") != "my_workers"
        || policy_bool(&resolved.policy, "requires_collective_scheduling")?;
    let requires_system = requires_room
        || requires_frontier
        || requires_collective
        || policy_bool(&resolved.policy, "requires_system_membership")?;
    let profile_capabilities = resolved
        .profile
        .get("primitive_capability_requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let allowed_capabilities = resolved
        .policy
        .get("allowed_primitive_capability_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let capabilities_fit = profile_capabilities
        .iter()
        .all(|required| allowed_capabilities.contains(required));
    let authority_scope = text(authority_decision, "required_scope");
    let authority_fits = text(authority_decision, "decision") == "authorized_for_explicit_review"
        && authority_decision
            .get("admission_bearing")
            .and_then(Value::as_bool)
            == Some(true)
        && authority_decision.get("non_grant").and_then(Value::as_bool) == Some(false)
        && !text(authority_decision, "grant_ref").is_empty()
        && !text(authority_decision, "authority_admission_intent_ref").is_empty()
        && allowed("allowed_authority_scopes", authority_scope);
    let risk_fits = allowed("allowed_source_kinds", source_kind)
        && allowed("allowed_result_profiles", result_profile)
        && allowed(
            "allowed_managed_execution_modes",
            text(goal_draft, "managed_execution_mode"),
        )
        && allowed(
            "allowed_contributor_scopes",
            text(goal_draft, "contributor_scope"),
        );
    let system_states = super::substrate_store::read_required_all(
        data_dir,
        super::system_activation_routes::STATE_DIR,
    )
    .map_err(|error| {
        bad_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "goal_run_activation_system_registry_unreadable",
            "The required System owner projection cannot be resolved; System-path availability is not inferred as false.",
            json!({ "detail": error.to_string() }),
        )
    })?;
    let system_path_available = system_states
        .iter()
        .any(|state| matches!(text(state, "status"), "active" | "activated"));
    let path_request = json!({
        "goal_run_ref": goal_ref,
        "requested_path": "auto",
        "goal_run_profile_revision_ref": resolved.profile.get("revision_ref"),
        "goal_run_profile_content_hash": resolved.profile.get("content_hash"),
        "goal_run_execution_ceiling_revision_ref": resolved.execution_ceiling.get("revision_ref"),
        "goal_run_execution_ceiling_content_hash": resolved.execution_ceiling.get("content_hash"),
        "goal_run_execution_ceiling": resolved.execution_ceiling.clone(),
        "declared_invocation_budget": {
            "max_total_invocations": 0,
            "max_parallel_invocations": 0
        },
        "effective_constraint_hash": effective_constraint_hash,
        "result_profile": result_profile,
        "policy_refs": [resolved.policy.get("policy_ref").cloned().unwrap_or(Value::Null)],
        "authority_refs": [authority_decision.get("decision_ref").cloned().unwrap_or(Value::Null)],
        "capability_requirement_refs": profile_capabilities,
        "runtime_facts": {
            "single_bounded_work_subject": source_kind == "ioi_goal_draft"
                && !text(goal_draft, "goal_text").trim().is_empty(),
            "requires_system_membership": requires_system,
            "requires_shared_frontier": requires_frontier,
            "requires_outcome_room": requires_room,
            "requires_collective_scheduling": requires_collective,
            "capabilities_fit_single_execution": capabilities_fit,
            "authority_fits_single_execution": authority_fits,
            "risk_and_isolation_fit_single_execution": risk_fits,
            "has_unresolved_system_dependency": false,
            "policy_requires_system_path": policy_bool(&resolved.policy, "policy_requires_system_path")?,
            "system_path_available": system_path_available
        }
    });
    let component_ref = resolved
        .component
        .get("revision_ref")
        .cloned()
        .unwrap_or(Value::Null);
    let component_hash = resolved
        .component
        .get("content_hash")
        .cloned()
        .unwrap_or(Value::Null);
    let component_ref_text = component_ref.as_str().unwrap_or("");
    let mut component_hashes = serde_json::Map::new();
    component_hashes.insert(component_ref_text.to_string(), component_hash);
    component_hashes.insert(
        text(&resolved.execution_ceiling, "revision_ref").to_string(),
        resolved
            .execution_ceiling
            .get("content_hash")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let definition_resolution = json!({
        "goal_run_ref": goal_ref,
        "goal_run_profile_revision_ref": resolved.profile.get("revision_ref"),
        "goal_run_profile_content_hash": resolved.profile.get("content_hash"),
        "goal_run_execution_ceiling_revision_ref": resolved.execution_ceiling.get("revision_ref"),
        "goal_run_execution_ceiling_content_hash": resolved.execution_ceiling.get("content_hash"),
        "declared_invocation_budget": {
            "max_total_invocations": 0,
            "max_parallel_invocations": 0
        },
        "admitted_override_set_ref": Value::Null,
        "admitted_override_set_hash": Value::Null,
        "workflow_template_revision_refs": [],
        "skill_manifest_revision_refs": [],
        "active_skill_entry_refs": [],
        "harness_profile_revision_refs": [component_ref.clone()],
        "runtime_tool_contract_refs": [],
        "effective_constraint_envelope_ref": format!("constraint://goal-run-activation/{activation_id}"),
        "effective_constraint_envelope_hash": effective_constraint_hash,
        "orchestration_policy_ref": resolved.policy.get("policy_ref"),
        "orchestration_policy_version_or_hash": resolved.policy.get("content_hash"),
        "resolved_skill_bindings": [],
        "component_hashes": component_hashes,
        "role_topology_requirement_refs": resolved.profile.get("role_topology_requirement_refs"),
        "worker_model_service_and_verifier_requirement_refs": [],
        "primitive_capability_requirement_refs": resolved.profile.get("primitive_capability_requirements"),
        "unresolved_late_binding_requirement_refs": []
    });
    Ok((path_request, definition_resolution))
}

fn activation_receipt_obligations(
    policy: &Value,
    activation_id: &str,
    activation_ref: &str,
    source_ref: &str,
    authority_decision_ref: &str,
    admission_decision_ref: &str,
    goal_ref: &str,
    profile_revision_ref: &str,
    component_snapshot_ref: &str,
) -> Result<Vec<Value>, HttpRefusal> {
    validate_activation_receipt_registry(policy)?;
    let entries = policy
        .get("receipt_registry")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut bound_facts = vec![
        activation_ref.to_string(),
        source_ref.to_string(),
        authority_decision_ref.to_string(),
        admission_decision_ref.to_string(),
        goal_ref.to_string(),
        profile_revision_ref.to_string(),
        component_snapshot_ref.to_string(),
    ];
    bound_facts.sort();
    bound_facts.dedup();
    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            json!({
                "obligation_id": format!("receipt-obligation://goal-run-activation/{activation_id}/{index}"),
                "boundary_event": entry.get("boundary_event").cloned().unwrap_or(Value::Null),
                "receipt_type": entry.get("receipt_type").cloned().unwrap_or(Value::Null),
                "receipt_profile_ref": entry.get("receipt_profile_ref").cloned().unwrap_or(Value::Null),
                "bound_fact_requirement_refs": bound_facts,
                "required": entry.get("required").cloned().unwrap_or(json!(false))
            })
        })
        .collect())
}

fn validate_activation_receipt_discharge(
    obligations: &[Value],
    receipt: &Value,
) -> Result<Value, HttpRefusal> {
    let attested = receipt
        .get("attested_boundary_fact_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut discharged = Vec::new();
    for obligation in obligations {
        if obligation.get("required").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let receipt_type_matches = obligation.get("receipt_type") == receipt.get("receipt_type");
        let profile_matches =
            obligation.get("receipt_profile_ref") == receipt.get("receipt_profile_ref");
        let facts_covered = obligation
            .get("bound_fact_requirement_refs")
            .and_then(Value::as_array)
            .is_some_and(|facts| facts.iter().all(|fact| attested.contains(fact)));
        if !receipt_type_matches || !profile_matches || !facts_covered {
            return Err(bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_obligation_undischarged",
                "A required typed receipt obligation is not discharged by the emitted receipt and its exact attested facts.",
                json!({
                    "obligation_id": obligation.get("obligation_id"),
                    "receipt_type_matches": receipt_type_matches,
                    "receipt_profile_matches": profile_matches,
                    "bound_facts_covered": facts_covered
                }),
            ));
        }
        discharged.push(json!({
            "obligation_id": obligation.get("obligation_id"),
            "receipt_ref": receipt.get("receipt_ref"),
            "receipt_type": receipt.get("receipt_type"),
            "discharged": true
        }));
    }
    Ok(json!({
        "all_required_discharged": discharged.len()
            == obligations
                .iter()
                .filter(|entry| entry.get("required").and_then(Value::as_bool) == Some(true))
                .count(),
        "discharges": discharged
    }))
}

fn activation_state_commitment(record: &Value) -> Value {
    let mut state = record.clone();
    state["state_root"] = Value::Null;
    state["state_root_ref"] = Value::Null;
    state
}

fn activation_state_key(root: &str) -> Option<String> {
    root.strip_prefix("sha256:")
        .filter(|tail| {
            tail.len() == 64
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .map(|tail| format!("gras_{tail}"))
}

fn admit_activation_state(
    data_dir: &str,
    activation_ref: &str,
    source_context_hash: &str,
    principal_ref: &str,
    authority_decision_ref: &str,
    goal_ref: &str,
    profile: &Value,
    resolution: &Value,
    decision: &Value,
    obligations: &[Value],
    admitted_at: &str,
    non_grants: &Value,
) -> Result<Value, HttpRefusal> {
    let goal_id = goal_ref.strip_prefix("goal://").unwrap_or("");
    let mut record = json!({
        "schema_version": "ioi.goal-run-admitted-state.v1",
        "state_root_ref": Value::Null,
        "state_root": Value::Null,
        "goal_run_ref": goal_ref,
        "activation_ref": activation_ref,
        "source_context_hash": source_context_hash,
        "requesting_principal_ref": principal_ref,
        "authority_decision_ref": authority_decision_ref,
        "goal_run_profile_revision_ref": profile.get("revision_ref").cloned().unwrap_or(Value::Null),
        "goal_run_profile_content_hash": profile.get("content_hash").cloned().unwrap_or(Value::Null),
        "goal_run_execution_ceiling_revision_ref": resolution.get("goal_run_execution_ceiling_revision_ref").cloned().unwrap_or(Value::Null),
        "goal_run_execution_ceiling_content_hash": resolution.get("goal_run_execution_ceiling_content_hash").cloned().unwrap_or(Value::Null),
        "declared_invocation_budget": resolution.get("declared_invocation_budget").cloned().unwrap_or(Value::Null),
        "admitted_override_set_ref": resolution.pointer("/resolution_receipt/admitted_override_set_ref").cloned().unwrap_or(Value::Null),
        "admitted_override_set_hash": resolution.pointer("/resolution_receipt/admitted_override_set_hash").cloned().unwrap_or(Value::Null),
        "resolved_component_set_snapshot_ref": resolution.get("resolved_component_set_snapshot_ref").cloned().unwrap_or(Value::Null),
        "resolved_component_set_hash": resolution.get("resolved_component_set_hash").cloned().unwrap_or(Value::Null),
        "profile_resolution_receipt_ref": resolution.get("resolution_receipt_ref").cloned().unwrap_or(Value::Null),
        "admission_decision_ref": decision.get("decision_ref").cloned().unwrap_or(Value::Null),
        "admission_receipt_ref": decision.get("decision_receipt_ref").cloned().unwrap_or(Value::Null),
        "receipt_obligations": obligations,
        "admitted_at": admitted_at,
        "non_grants": non_grants
    });
    let root = sha256_canonical(&activation_state_commitment(&record));
    let Some(key) = activation_state_key(&root) else {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_activation_state_root_invalid",
            "The daemon failed to derive a canonical admitted state root.",
        ));
    };
    let root_ref = format!("agentgres://state-root/goal-run/{goal_id}/{root}");
    record["state_root"] = json!(root);
    record["state_root_ref"] = json!(root_ref);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        "schema://ioi/applications/ioi-ai/goal-run-admitted-state/v1",
        &record,
    )
    .map_err(|error| {
        bad_with_details(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_state_contract_invalid",
            "The daemon-produced admitted state does not satisfy its registered contract.",
            json!({ "error": error }),
        )
    })?;
    super::substrate_store::admit_required(data_dir, GOAL_RUN_ADMITTED_STATE_KIND, &key, &record)
        .map_err(|error| {
        bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_state_admission_failed",
            "The GoalRun admitted-state operation did not cross the required Agentgres boundary.",
            json!({ "key": key, "error": error.to_string() }),
        )
    })?;
    durable_write(data_dir, GOAL_RUN_ADMITTED_STATE_KIND, &key, &record)?;
    super::substrate_store::verify_required_exact(
        data_dir,
        GOAL_RUN_ADMITTED_STATE_KIND,
        &key,
        &record,
    )
    .map_err(|error| {
        bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_state_admission_unproven",
            "The exact admitted-state operation cannot be reconstructed from Agentgres.",
            json!({ "key": key, "error": error.to_string() }),
        )
    })?;
    Ok(record)
}

fn load_activation_state(data_dir: &str, root_ref: &str) -> Result<Value, HttpRefusal> {
    let root = root_ref.rsplit('/').next().unwrap_or("");
    let key = activation_state_key(root).ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "goal_run_activation_state_root_invalid",
            "The retained admitted-state ref is not content-addressed.",
        )
    })?;
    let record = activation_record_strict(data_dir, GOAL_RUN_ADMITTED_STATE_KIND, &key)?
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "goal_run_activation_state_evidence_missing",
                "The GoalRun names an admitted state root without its local owner-plane evidence.",
            )
        })?;
    if text(&record, "state_root_ref") != root_ref
        || text(&record, "state_root") != root
        || sha256_canonical(&activation_state_commitment(&record)) != root
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_state_integrity_failure",
            "The retained admitted-state evidence no longer reproduces its root.",
        ));
    }
    super::substrate_store::verify_required_exact(
        data_dir,
        GOAL_RUN_ADMITTED_STATE_KIND,
        &key,
        &record,
    )
    .map_err(|error| {
        bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_state_backing_missing",
            "The retained state-root string has no exact Agentgres operation behind it.",
            json!({ "key": key, "error": error.to_string() }),
        )
    })?;
    Ok(record)
}

#[derive(Clone)]
struct GoalRunActivationBinding {
    activation_ref: String,
    source_ref: String,
    source_owner_ref: String,
    project_ref: Value,
    review_decision_ref: String,
    activation_receipt_ref: String,
    admitted_state_root_ref: String,
    receipt_obligations: Vec<Value>,
    definition_resolution: Value,
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

fn pursuit_err(error: GoalPursuitError) -> (StatusCode, Json<Value>) {
    bad(
        StatusCode::UNPROCESSABLE_ENTITY,
        error.code(),
        error.message(),
    )
}

fn strict_goal_run_census(data_dir: &str) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, GOAL_RUN_KIND) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("GoalRun registry cannot be pinned ({error})")),
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("GoalRun registry cannot be enumerated ({error})"))?;
    names.sort();
    let mut records = Vec::with_capacity(names.len());
    let mut refs = std::collections::BTreeSet::new();
    for name in names {
        let tail = name
            .strip_suffix(".json")
            .ok_or_else(|| format!("GoalRun registry contains unexpected occupant '{name}'"))?;
        if tail.is_empty()
            || tail.len() > 160
            || !tail.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            return Err(format!("GoalRun slot '{name}' has an invalid storage key"));
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => return Err(format!("GoalRun slot '{name}' vanished after enumeration")),
            Err(error) => return Err(format!("GoalRun slot '{name}' is unreadable ({error})")),
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("GoalRun slot '{name}' is malformed ({error})"))?;
        if record.get("goal_run_id").and_then(Value::as_str) != Some(tail) {
            return Err(format!(
                "GoalRun slot '{name}' fails storage-key identity binding"
            ));
        }
        let goal_ref = record
            .get("goal_ref")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("goal://") && value.len() <= 320)
            .ok_or_else(|| format!("GoalRun slot '{name}' lacks a canonical goal_ref"))?;
        if !refs.insert(goal_ref.to_string()) {
            return Err(format!("GoalRun ref '{goal_ref}' resolves more than once"));
        }
        records.push(record);
    }
    Ok(records)
}

fn load_goal_run_by_id_strict(data_dir: &str, goal_run_id: &str) -> Result<Option<Value>, String> {
    if goal_run_id.is_empty()
        || goal_run_id.len() > 160
        || !goal_run_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err("GoalRun id must be a bounded storage identity".into());
    }
    Ok(strict_goal_run_census(data_dir)?
        .into_iter()
        .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id)))
}

pub(crate) fn load_goal_run(st: &DaemonState, goal_run_id: &str) -> Result<Option<Value>, String> {
    load_goal_run_by_id_strict(&st.data_dir, goal_run_id)
}

fn goal_run_registry_refusal(error: String) -> HttpRefusal {
    eprintln!("GoalRun registry refusal: {error}");
    bad(
        StatusCode::INTERNAL_SERVER_ERROR,
        "goal_run_registry_unreadable",
        "GoalRun truth cannot be resolved from the complete strict registry census.",
    )
}

fn load_goal_run_for_http(data_dir: &str, goal_run_id: &str) -> Result<Option<Value>, HttpRefusal> {
    load_goal_run_by_id_strict(data_dir, goal_run_id).map_err(goal_run_registry_refusal)
}

/// Strict GoalRun resolver by its canonical `goal://` coordinate. Every registry slot is read
/// through the pinned/no-follow boundary so unreadable, malformed, or identity-swapped state is
/// uncertainty rather than absence.
pub(crate) fn load_goal_run_strict(
    data_dir: &str,
    goal_ref: &str,
) -> Result<Option<Value>, String> {
    if !goal_ref
        .strip_prefix("goal://")
        .is_some_and(|tail| !tail.is_empty() && tail.len() <= 160 && !tail.contains(".."))
    {
        return Err("GoalRun ref must be a bounded canonical goal:// identity".into());
    }
    let mut found = None;
    for record in strict_goal_run_census(data_dir)? {
        if record.get("goal_ref").and_then(Value::as_str) == Some(goal_ref) {
            if found.is_some() {
                return Err(format!("GoalRun ref '{goal_ref}' resolves more than once"));
            }
            found = Some(record);
        }
    }
    Ok(found)
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

/// Self-POST carrying the per-boot internal dispatch token (#240 lane, extended by the #246
/// session-write gate): candidate-session creates run inside spawned invocation workers with no
/// caller HeaderMap in scope, so they cross the identity-gated Session family as the daemon's
/// OWN dispatch. The token lives only in process memory and is never emitted in any response;
/// a caller-supplied value can never match it. The goal-run start handler that authorizes the
/// invocation remains a pinned admission-evidence open lead — when IT gains identity, the
/// resolved principal should thread through here instead.
async fn self_post_internal_dispatch(st: &DaemonState, url: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(url)
        .header("x-ioi-internal-dispatch", &st.internal_dispatch_token)
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
pub(crate) fn route_fact(
    st: &DaemonState,
    explicit_ref: Option<&str>,
) -> (String, String, String, String) {
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
        None => (
            String::new(),
            "unresolved".into(),
            String::new(),
            String::new(),
        ),
    }
}

pub(crate) async fn live_profiles(st: &DaemonState) -> Vec<Value> {
    self_get(&format!(
        "{}/v1/hypervisor/harness-profiles?live=1",
        st.base_url
    ))
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

fn admission_policy_refs(request: &Value) -> Vec<Value> {
    request
        .get("policy_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn policy_requests_hosted_collective(request: &Value) -> bool {
    admission_policy_refs(request)
        .iter()
        .any(|reference| reference.as_str() == Some(M4_HOSTED_COLLECTIVE_POLICY_REF))
}

fn direct_runtime_facts(request: &Value) -> Value {
    let capabilities_fit = request
        .get("capability_requirement_refs")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    json!({
        "single_bounded_work_subject": true,
        "requires_system_membership": false,
        "requires_shared_frontier": false,
        "requires_outcome_room": false,
        "requires_collective_scheduling": false,
        "capabilities_fit_single_execution": capabilities_fit,
        "authority_fits_single_execution": true,
        "risk_and_isolation_fit_single_execution": true,
        "has_unresolved_system_dependency": false,
        "policy_requires_system_path": false,
        "system_path_available": false
    })
}

fn install_daemon_runtime_facts(request: &mut Value, derived: &Value) -> Result<(), HttpRefusal> {
    if request
        .get("runtime_facts")
        .is_some_and(|claimed| !claimed.is_null() && claimed != derived)
    {
        return Err(bad_with_details(
            StatusCode::UNPROCESSABLE_ENTITY,
            "admission_fact_substitution_refused",
            "Caller-supplied admission facts differ from the daemon-resolved live facts.",
            json!({
                "caller_runtime_facts": request.get("runtime_facts"),
                "daemon_runtime_facts": derived
            }),
        ));
    }
    request["runtime_facts"] = derived.clone();
    Ok(())
}

fn select_goal_run_topology(
    kernel: &RuntimeKernelService,
    profiles: &[Value],
    route_ref: &str,
    route_state: &str,
    goal_ref: &str,
) -> Result<Value, HttpRefusal> {
    let conductor =
        match super::harness_routes::unique_profile_by_harness(profiles, "hypervisor_worker") {
            Ok(profile) => fact_from_profile(profile, route_ref, route_state),
            Err(detail) => {
                return Err(bad_with_details(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "goal_run_conductor_profile_unresolved",
                    "Exactly one Hypervisor worker profile is required for the conductor role.",
                    json!({ "detail": detail }),
                ))
            }
        };
    let mut implementer_candidates = Vec::with_capacity(2);
    for harness in ["opencode", "deepseek_tui"] {
        let profile = match super::harness_routes::unique_profile_by_harness(profiles, harness) {
            Ok(profile) => profile,
            Err(detail) => {
                return Err(bad_with_details(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "goal_run_implementer_profile_unresolved",
                    "Each required implementer harness must resolve exactly one profile.",
                    json!({ "harness": harness, "detail": detail }),
                ))
            }
        };
        implementer_candidates.push(fact_from_profile(profile, route_ref, route_state));
    }
    kernel
        .select_goal_run_role_topology(&json!({
            "goal_ref": goal_ref,
            "conductor": conductor,
            "implementer_candidates": implementer_candidates,
        }))
        .map_err(kernel_err)
}

fn admission_fact_resolution(
    target_system_id: Option<&str>,
    system_graph: Option<&Value>,
    topology: Option<&Value>,
    policy_refs: &[Value],
    runtime_facts: &Value,
    resolved_at: &str,
) -> Value {
    let system_evidence = system_graph.map_or(Value::Null, |graph| {
        let chain = &graph["autonomous_system_chain"];
        json!({
            "system_id": chain.get("system_id").cloned().unwrap_or(Value::Null),
            "package_id": chain.get("package_id").cloned().unwrap_or(Value::Null),
            "genesis_ref": chain.get("genesis_ref").cloned().unwrap_or(Value::Null),
            "constitution_ref": chain.get("constitution_ref").cloned().unwrap_or(Value::Null),
            "chain_root": chain.get("chain_root").cloned().unwrap_or(Value::Null),
            "latest_state_root": chain.get("latest_state_root").cloned().unwrap_or(Value::Null),
            "latest_receipt_root": chain.get("latest_receipt_root").cloned().unwrap_or(Value::Null)
        })
    });
    let topology_evidence = topology.map_or(Value::Null, |selected| {
        json!({
            "topology_hash": sha256_canonical(selected),
            "conductor_ref": selected.get("conductor_ref").cloned().unwrap_or(Value::Null),
            "implementer_refs": selected.get("implementer_refs").cloned().unwrap_or_else(|| json!([])),
            "verifier_ref": selected.get("verifier_ref").cloned().unwrap_or(Value::Null)
        })
    });
    let mut resolution = json!({
        "schema_version": ADMISSION_FACT_RESOLUTION_SCHEMA,
        "resolver": "hypervisor_daemon",
        "target_system_id": target_system_id.map_or(Value::Null, |value| json!(value)),
        "policy_refs": policy_refs,
        "system_evidence": system_evidence,
        "topology_evidence": topology_evidence,
        "runtime_facts": runtime_facts,
        "resolved_at": resolved_at,
        "resolution_root": Value::Null
    });
    let root = sha256_canonical(&json!({
        "domain": "ioi.goal-run-admission-runtime-fact-resolution-jcs-sha256.v1",
        "resolution": resolution
    }));
    resolution["resolution_root"] = json!(root);
    resolution
}

pub(crate) fn verify_collective_admission_fact_resolution(
    goal_run: &Value,
    system_graph: &Value,
) -> Result<(), String> {
    let resolution = goal_run
        .get("admission_path_fact_resolution")
        .filter(|value| value.is_object())
        .ok_or_else(|| "GoalRun has no daemon-owned admission fact resolution".to_string())?;
    if resolution.get("schema_version").and_then(Value::as_str)
        != Some(ADMISSION_FACT_RESOLUTION_SCHEMA)
        || resolution.get("resolver").and_then(Value::as_str) != Some("hypervisor_daemon")
    {
        return Err("GoalRun admission fact resolution has an unknown owner or schema".to_string());
    }
    let mut root_material = resolution.clone();
    root_material["resolution_root"] = Value::Null;
    let expected_root = sha256_canonical(&json!({
        "domain": "ioi.goal-run-admission-runtime-fact-resolution-jcs-sha256.v1",
        "resolution": root_material
    }));
    if resolution.get("resolution_root").and_then(Value::as_str) != Some(expected_root.as_str()) {
        return Err("GoalRun admission fact resolution root does not recompute".to_string());
    }
    let chain = &system_graph["autonomous_system_chain"];
    let target_system_id = chain.get("system_id").and_then(Value::as_str).unwrap_or("");
    if resolution.get("target_system_id").and_then(Value::as_str) != Some(target_system_id)
        || chain.get("package_id").and_then(Value::as_str) != Some(OUTCOME_ROOM_PACKAGE_REF)
    {
        return Err("GoalRun admission facts do not bind this OutcomeRoom System".to_string());
    }
    for field in [
        "system_id",
        "package_id",
        "genesis_ref",
        "constitution_ref",
        "chain_root",
        "latest_state_root",
        "latest_receipt_root",
    ] {
        if resolution.pointer(&format!("/system_evidence/{field}")) != chain.get(field) {
            return Err(format!(
                "GoalRun admission System evidence changed at '{field}'"
            ));
        }
    }
    let topology = goal_run
        .get("role_topology")
        .filter(|value| value.is_object())
        .ok_or_else(|| "GoalRun has no admitted role topology".to_string())?;
    let implementers = topology
        .get("implementer_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "GoalRun topology omits implementer refs".to_string())?;
    let topology_hash = sha256_canonical(topology);
    if implementers.len() < 2
        || resolution
            .pointer("/topology_evidence/topology_hash")
            .and_then(Value::as_str)
            != Some(topology_hash.as_str())
        || resolution.pointer("/topology_evidence/implementer_refs")
            != topology.get("implementer_refs")
    {
        return Err("GoalRun collective topology evidence is absent or changed".to_string());
    }
    if resolution.get("runtime_facts") != goal_run.pointer("/admission_path_decision/runtime_facts")
    {
        return Err(
            "GoalRun admission decision facts differ from their owner resolution".to_string(),
        );
    }
    for field in [
        "requires_system_membership",
        "requires_shared_frontier",
        "requires_outcome_room",
        "requires_collective_scheduling",
        "policy_requires_system_path",
        "system_path_available",
    ] {
        if resolution.pointer(&format!("/runtime_facts/{field}")) != Some(&json!(true)) {
            return Err(format!(
                "GoalRun collective fact '{field}' is not resolved true"
            ));
        }
    }
    Ok(())
}

pub(crate) async fn handle_goal_runs_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let (owner_ref, _) = match activation_principal(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body
        .get("owner_ref")
        .filter(|value| !value.is_null())
        .and_then(Value::as_str)
        .is_some_and(|claimed| claimed != owner_ref)
    {
        return bad(
            StatusCode::FORBIDDEN,
            "goal_run_owner_substitution_refused",
            "GoalRun owner identity is daemon-derived from the authenticated principal.",
        );
    }
    body["owner_ref"] = json!(owner_ref);
    let goal = text(&body, "goal").trim().to_string();
    if goal.len() < 4 {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_goal_required",
            "A bounded normalized goal is required.",
        );
    }
    let direct_origin_surface = match body.get("origin_surface") {
        None | Some(Value::Null) => "api".to_string(),
        Some(Value::String(origin))
            if matches!(origin.as_str(), "api" | "hypervisor_new_session") =>
        {
            origin.clone()
        }
        Some(Value::String(origin)) => {
            return bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_activation_required_for_origin",
                "A GoalRun claiming an originating context must be admitted through a typed GoalRunActivationEnvelope.",
                json!({ "origin_surface": origin }),
            )
        }
        Some(_) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_origin_surface_invalid",
                "origin_surface must be a source-neutral string value.",
            )
        }
    };
    body["origin_surface"] = json!(direct_origin_surface);
    let goal_run_id = format!("gr_{:x}", nanos());
    let goal_ref = format!("goal://{goal_run_id}");
    let kernel = RuntimeKernelService::new();

    // Callers request a path and provide immutable definition coordinates; runtime facts are
    // daemon-owned. Exact legacy echoes remain accepted only when byte-equal to the derived
    // facts, while any attempted substitution refuses before identity persistence.
    let mut path_decision: Option<Value> = None;
    let mut path_fact_resolution: Option<Value> = None;
    let mut deferred_system_path_request: Option<Value> = None;
    if let Some(mut path_request) = body.get("admission_path_request").cloned() {
        let Some(path_object) = path_request.as_object_mut() else {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_admission_path_request_invalid",
                "admission_path_request must be a closed object.",
            );
        };
        const PATH_REQUEST_FIELDS: &[&str] = &[
            "requested_path",
            "goal_run_profile_revision_ref",
            "goal_run_profile_content_hash",
            "effective_constraint_hash",
            "result_profile",
            "policy_refs",
            "authority_refs",
            "capability_requirement_refs",
            "runtime_facts",
        ];
        if let Some(unknown) = path_object
            .keys()
            .find(|key| !PATH_REQUEST_FIELDS.contains(&key.as_str()))
        {
            return bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_admission_path_request_unknown_field",
                "Unknown admission-path request fields fail closed.",
                json!({ "field": unknown }),
            );
        }
        path_object.insert("goal_run_ref".into(), json!(goal_ref));
        let requested_system_path = text(&path_request, "requested_path") == "system_bound"
            || policy_requests_hosted_collective(&path_request)
            || body
                .get("target_system_id")
                .is_some_and(|value| !value.is_null());
        if requested_system_path {
            deferred_system_path_request = Some(path_request);
        } else {
            let facts = direct_runtime_facts(&path_request);
            if let Err(response) = install_daemon_runtime_facts(&mut path_request, &facts) {
                return response;
            }
            let decided_at = iso_now();
            let resolution = admission_fact_resolution(
                None,
                None,
                None,
                &admission_policy_refs(&path_request),
                &facts,
                &decided_at,
            );
            let decision = match kernel.select_goal_run_admission_path(&path_request, &decided_at) {
                Ok(decision) => decision,
                Err(error) => return kernel_err(error),
            };
            if text(&decision, "decision") != "direct_non_system" {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(
                        json!({"ok":false,"error":{"code":"goal_run_admission_refused","message":"The daemon-derived direct-path facts did not admit a direct GoalRun.","details":decision}}),
                    ),
                );
            }
            return create_direct_goal_run(
                &st,
                &body,
                &goal_run_id,
                &goal_ref,
                &goal,
                &decision,
                None,
                Some(&resolution),
            );
        }
    }

    let session_ref = text(&body, "session_ref").to_string();
    let target_session = match super::lifecycle_routes::load_session_record_strict(
        &st,
        &session_ref,
    ) {
        Ok(Some(session)) => session,
        Ok(None) => return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_target_session_unresolved",
            "A GoalRun binds to an existing session (its workspace is the reconciliation target).",
        ),
        Err(message) => {
            return bad_with_details(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_target_session_unreadable",
                "The target Session owner record cannot be strictly resolved.",
                json!({ "error": message }),
            )
        }
    };
    if target_session.get("owner_ref").and_then(Value::as_str) != Some(owner_ref.as_str()) {
        return bad(
            StatusCode::FORBIDDEN,
            "goal_run_target_session_owner_mismatch",
            "The authenticated GoalRun owner does not own the target Session/workspace.",
        );
    }
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

    // Preflight retained registry bytes without seed reconciliation or runnability-probe writes.
    // A caller-owned runtime-fact substitution, missing System, wrong package, or ineligible
    // topology must refuse against this exact census before any live-fact persistence occurs.
    let preflight_profiles =
        match super::harness_routes::existing_profiles_strict(&st) {
            Ok(profiles) => profiles,
            Err(detail) => return bad_with_details(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_harness_registry_unreadable",
                "The complete retained harness-profile registry cannot preflight GoalRun creation.",
                json!({ "detail": detail }),
            ),
        };
    let (preflight_route_ref, preflight_route_state, preflight_model_id, preflight_route_base_url) =
        match super::model_routes::existing_route_fact_strict(
            &st.data_dir,
            body.get("model_route_ref").and_then(Value::as_str),
        ) {
            Ok(fact) => fact,
            Err(detail) => {
                return bad_with_details(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "goal_run_model_route_registry_unreadable",
                    "The complete retained model-route registry cannot preflight GoalRun creation.",
                    json!({ "detail": detail }),
                )
            }
        };
    let preflight_topology = match select_goal_run_topology(
        &kernel,
        &preflight_profiles,
        &preflight_route_ref,
        &preflight_route_state,
        &goal_ref,
    ) {
        Ok(selected) => selected,
        Err(response) => return response,
    };
    if let Some(mut path_request) = deferred_system_path_request {
        let target_system_id = body
            .get("target_system_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("system://") && value.len() <= 320)
            .unwrap_or("");
        if target_system_id.is_empty() {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_target_system_required",
                "A requested System-bound GoalRun must name one exact target_system_id for daemon resolution.",
            );
        }
        let graph = match super::system_activation_routes::load_active_system_graph(
            &st.data_dir,
            target_system_id,
        ) {
            Ok(graph) => graph,
            Err((code, message)) => {
                let mut unavailable_facts = json!({
                    "single_bounded_work_subject": true,
                    "requires_system_membership": true,
                    "requires_shared_frontier": policy_requests_hosted_collective(&path_request),
                    "requires_outcome_room": policy_requests_hosted_collective(&path_request),
                    "requires_collective_scheduling": policy_requests_hosted_collective(&path_request),
                    "capabilities_fit_single_execution": false,
                    "authority_fits_single_execution": true,
                    "risk_and_isolation_fit_single_execution": true,
                    "has_unresolved_system_dependency": true,
                    "policy_requires_system_path": true,
                    "system_path_available": false
                });
                if let Err(response) =
                    install_daemon_runtime_facts(&mut path_request, &unavailable_facts)
                {
                    return response;
                }
                unavailable_facts["system_path_available"] = json!(false);
                return bad_with_details(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "goal_run_target_system_unresolved",
                    "The exact requested System is not an active, reconstructable bounded System.",
                    json!({ "owner_error_code": code, "owner_error": message }),
                );
            }
        };
        if graph
            .pointer("/autonomous_system_chain/package_id")
            .and_then(Value::as_str)
            != Some(OUTCOME_ROOM_PACKAGE_REF)
        {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_target_system_package_mismatch",
                "The M4 hosted collective policy requires an active OutcomeRoom package System.",
            );
        }
        let implementer_count = preflight_topology
            .get("implementer_refs")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let collective_topology = implementer_count >= 2;
        let facts = json!({
            "single_bounded_work_subject": !collective_topology,
            "requires_system_membership": true,
            "requires_shared_frontier": true,
            "requires_outcome_room": true,
            "requires_collective_scheduling": collective_topology,
            "capabilities_fit_single_execution": false,
            "authority_fits_single_execution": true,
            "risk_and_isolation_fit_single_execution": true,
            "has_unresolved_system_dependency": false,
            "policy_requires_system_path": true,
            "system_path_available": true
        });
        if let Err(response) = install_daemon_runtime_facts(&mut path_request, &facts) {
            return response;
        }
        if !collective_topology {
            return bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_collective_topology_unresolved",
                "The hosted collective path requires at least two daemon-admitted implementer contexts.",
                json!({ "implementer_count": implementer_count }),
            );
        }
        let decided_at = iso_now();
        let decision = match kernel.select_goal_run_admission_path(&path_request, &decided_at) {
            Ok(decision) => decision,
            Err(error) => return kernel_err(error),
        };
        if text(&decision, "decision") != "system_bound_required" {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({"ok":false,"error":{"code":"goal_run_admission_refused","message":"The daemon did not admit the requested System-bound path.","details":decision}}),
                ),
            );
        }
        path_fact_resolution = Some(admission_fact_resolution(
            Some(target_system_id),
            Some(&graph),
            Some(&preflight_topology),
            &admission_policy_refs(&path_request),
            &facts,
            &decided_at,
        ));
        path_decision = Some(decision);
    }
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

    // Only an otherwise admissible request may refresh retained runnability/seed facts. Reprove
    // the exact routing/topology tuple afterward; a concurrent or probe-derived change refuses
    // before GoalRun identity persistence instead of silently changing the reviewed decision.
    let profiles = match super::harness_routes::live_profiles_strict(&st) {
        Ok(profiles) => profiles,
        Err(detail) => {
            return bad_with_details(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_harness_registry_unreadable",
                "The complete live harness-profile registry cannot authorize GoalRun creation.",
                json!({ "detail": detail }),
            )
        }
    };
    let (route_ref, route_state, model_id, route_base_url) =
        match super::model_routes::route_fact_strict(
            &st.data_dir,
            body.get("model_route_ref").and_then(Value::as_str),
        ) {
            Ok(fact) => fact,
            Err(detail) => {
                return bad_with_details(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "goal_run_model_route_registry_unreadable",
                    "The complete model-route registry cannot authorize GoalRun creation.",
                    json!({ "detail": detail }),
                )
            }
        };
    let topology =
        match select_goal_run_topology(&kernel, &profiles, &route_ref, &route_state, &goal_ref) {
            Ok(selected) => selected,
            Err(response) => return response,
        };
    if route_ref != preflight_route_ref
        || route_state != preflight_route_state
        || model_id != preflight_model_id
        || route_base_url != preflight_route_base_url
        || topology != preflight_topology
    {
        return bad_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "goal_run_live_fact_changed_after_preflight",
            "Retained routing or role-topology facts changed while live probes were reconciled; retry against one stable census.",
            json!({
                "preflight": {
                    "route_ref": preflight_route_ref,
                    "route_state": preflight_route_state,
                    "model_id": preflight_model_id,
                    "route_base_url": preflight_route_base_url,
                    "topology": preflight_topology,
                },
                "live": {
                    "route_ref": route_ref,
                    "route_state": route_state,
                    "model_id": model_id,
                    "route_base_url": route_base_url,
                    "topology": topology,
                }
            }),
        );
    }

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
        "context_cell_id": format!("context-cell://cc_{goal_run_id}_conductor"),
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
        let cell_ref = format!("context-cell://cc_{goal_run_id}_{role_key}");
        let lease_ref = format!("context-lease://cl_{goal_run_id}_{role_key}");
        let brief_ref = format!("task-brief://tb_{goal_run_id}_{role_key}");
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
            "from_context_cell_ref": format!("context-cell://cc_{goal_run_id}_conductor"),
            "to_context_cell_ref": cell_ref,
            "handoff_kind": "task_brief",
            "payload_ref": brief_ref,
            "context_lease_refs": [lease_ref],
            "status": "sent",
        }));
    }
    context_cells.push(json!({
        "context_cell_id": format!("context-cell://cc_{goal_run_id}_verifier"),
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
        "owner_ref": owner_ref,
        "origin_surface": "api",
        "normalized_goal": goal,
        "target_session_ref": session_ref,
        "target_workspace_root": target_workspace,
        "project_ref": project_ref,
        "orchestration_policy": "parallel_implement_reconcile",
        "max_parallel_invocations": 2,
        "role_topology": topology,
        "role_topology_ref": format!("role-topology://rt_{goal_run_id}"),
        "grounding_loop": {
            "goal_loop_id": format!("goal-loop://gl_{goal_run_id}"),
            "goal_ref": goal_ref,
            "conductor_context_cell_ref": format!("context-cell://cc_{goal_run_id}_conductor"),
            "loop_iteration": 0,
            "phase": "receive_intent",
            "escalation_state": "none",
        },
        "context_cells": context_cells,
        "context_leases": context_leases,
        "task_briefs": task_briefs,
        "handoffs": handoffs,
        "verifier_path": {
            "verifier_path_id": format!("verifier-path://vp_{goal_run_id}"),
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
        "admission_path_decision": path_decision,
        "admission_path_fact_resolution": path_fact_resolution,
        "admission_path_status": if path_decision.is_some() { "system_bound" } else { "legacy_system_bound_first_cut" },
        "target_system_id": body.get("target_system_id").cloned().unwrap_or(Value::Null),
        // Optional launch-policy provenance (IOI Agent lane) — advanced/proof metadata only.
        "policy_ref": body.get("policy_ref").cloned().unwrap_or(Value::Null),
        "invocation_refs": [],
        "verification_refs": [],
        "reconciliation_ref": Value::Null,
        "blockers": [],
        "active_loop_phase": "receive_intent",
        "continuation_state": "open",
        "status": "draft",
        // Durable goal identity records HOW it was authorized: `explicit_activation`
        // means typed activation evidence crossed admission; otherwise this is a
        // direct substrate creation. There is no legacy lane (ADR 0022 Decision 2).
        "creation_provenance": if body.get("activation_evidence").is_some() {
            "explicit_activation"
        } else {
            "direct_substrate_activation"
        },
        "activation_evidence": body.get("activation_evidence").cloned().unwrap_or(Value::Null),
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(failure) = persist_goal_run_atomic(&st.data_dir, &goal_run_id, &record) {
        return match failure {
            PersistFailure::NotCommitted(error) => bad_with_details(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_persist_failed",
                "The system-bound GoalRun did not commit; no creation success is reported.",
                json!({ "error": error.to_string() }),
            ),
            PersistFailure::RenamedDurabilityUnconfirmed(error) => bad_with_details(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_persist_durability_unconfirmed",
                "The system-bound GoalRun is visible but crash durability is unconfirmed; retry instead of assuming creation.",
                json!({ "error": error.to_string() }),
            ),
        };
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "goal_run": record })),
    )
}

fn create_direct_goal_run(
    st: &DaemonState,
    body: &Value,
    goal_run_id: &str,
    goal_ref: &str,
    normalized_goal: &str,
    decision: &Value,
    activation: Option<&GoalRunActivationBinding>,
    fact_resolution: Option<&Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut resolution_request) = body.get("definition_resolution").cloned() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_definition_resolution_required",
            "Direct admission requires an exact definition-resolution request.",
        );
    };
    let Some(resolution_object) = resolution_request.as_object_mut() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_definition_resolution_invalid",
            "definition_resolution must be an object.",
        );
    };
    resolution_object.insert("goal_run_ref".into(), json!(goal_ref));
    resolution_object.insert(
        "goal_run_profile_revision_ref".into(),
        decision
            .get("goal_run_profile_revision_ref")
            .cloned()
            .unwrap_or(Value::Null),
    );
    resolution_object.insert(
        "goal_run_profile_content_hash".into(),
        decision
            .get("goal_run_profile_content_hash")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let resolution = if let Some(binding) = activation {
        binding.definition_resolution.clone()
    } else {
        match GoalPursuitCore.resolve_definitions(&resolution_request, &iso_now()) {
            Ok(resolution) => resolution,
            Err(error) => return pursuit_err(error),
        }
    };
    if activation.is_some()
        && (decision.get("goal_run_execution_ceiling_revision_ref")
            != resolution.get("goal_run_execution_ceiling_revision_ref")
            || decision.get("goal_run_execution_ceiling_content_hash")
                != resolution.get("goal_run_execution_ceiling_content_hash")
            || decision.get("declared_invocation_budget")
                != resolution.get("declared_invocation_budget")
            || resolution
                .pointer("/declared_invocation_budget/max_total_invocations")
                .and_then(Value::as_u64)
                != Some(0)
            || resolution
                .pointer("/declared_invocation_budget/max_parallel_invocations")
                .and_then(Value::as_u64)
                != Some(0)
            || !resolution
                .pointer("/resolution_receipt/admitted_override_set_ref")
                .is_some_and(Value::is_null)
            || !resolution
                .pointer("/resolution_receipt/admitted_override_set_hash")
                .is_some_and(Value::is_null))
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_bounds_resolution_changed",
            "The activation path and definition-resolution closure do not retain one exact zero-execution budget and null override tuple.",
        );
    }
    if persist_record(
        &st.data_dir,
        "goal-run-component-snapshots",
        goal_run_id,
        resolution
            .get("resolved_component_set")
            .unwrap_or(&Value::Null),
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_component_snapshot_persist_failed",
            "The exact resolved component snapshot did not persist.",
        );
    }
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1",
            resolution.get("resolution_receipt").unwrap_or(&Value::Null),
        )
    {
        return bad_with_details(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_resolution_receipt_contract_invalid",
            "The generated profile-resolution receipt does not satisfy its registered contract.",
            json!({ "error": error }),
        );
    }
    if persist_record(
        &st.data_dir,
        "goal-run-profile-resolution-receipts",
        goal_run_id,
        resolution.get("resolution_receipt").unwrap_or(&Value::Null),
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_resolution_receipt_persist_failed",
            "The profile-resolution receipt did not persist.",
        );
    }
    let selected_skills: Vec<Value> = resolution_request
        .get("resolved_skill_bindings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|binding| {
            json!({
                "skill_entry_ref":binding.get("skill_entry_ref"),
                "skill_entry_binding_revision_ref":binding.get("skill_entry_binding_revision_ref"),
                "skill_entry_binding_hash":binding.get("skill_entry_binding_hash"),
                "skill_revision_ref":binding.get("skill_manifest_revision_ref"),
                "manifest_content_hash":binding.get("skill_manifest_content_hash"),
                "inclusion_basis_refs":[]
            })
        })
        .collect();
    let active_skill_snapshot = json!({
        "schema_version":"ioi.active-skill-set-snapshot.v1",
        "active_skill_set_snapshot_id":resolution.get("active_skill_set_snapshot_ref"),
        "work_subject_ref":goal_ref,
        "selected_skills":selected_skills,
        "excluded_candidates":[],
        "compatibility_and_evaluation_result_refs":[],
        "active_set_hash":resolution.get("active_skill_set_hash"),
        "resolved_runtime_tool_contracts":resolution.pointer("/resolution_receipt/resolved_runtime_tool_contracts").cloned().unwrap_or_else(|| json!([])),
        "context_lease_refs":[],
        "resolution_receipt_ref":resolution.get("resolution_receipt_ref"),
        "registry_lifecycle_ref":Value::Null,
        "registry_status":"active"
    });
    if persist_record(
        &st.data_dir,
        "active-skill-set-snapshots",
        goal_run_id,
        &active_skill_snapshot,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_active_skill_snapshot_persist_failed",
            "The exact active skill-set snapshot did not persist.",
        );
    }
    let now = iso_now();
    let mut lifecycle = WorkLifecycleCore::default();
    let mut genesis_evidence_refs =
        vec![decision.get("decision_ref").cloned().unwrap_or(Value::Null)];
    let mut genesis_receipt_refs = vec![decision
        .get("decision_receipt_ref")
        .cloned()
        .unwrap_or(Value::Null)];
    let mut active_evidence_refs = vec![
        decision.get("decision_ref").cloned().unwrap_or(Value::Null),
        resolution
            .get("resolved_component_set_snapshot_ref")
            .cloned()
            .unwrap_or(Value::Null),
    ];
    let mut active_receipt_refs = vec![
        decision
            .get("decision_receipt_ref")
            .cloned()
            .unwrap_or(Value::Null),
        resolution
            .get("resolution_receipt_ref")
            .cloned()
            .unwrap_or(Value::Null),
    ];
    if let Some(binding) = activation {
        genesis_evidence_refs.push(json!(binding.activation_ref.clone()));
        genesis_receipt_refs.push(json!(binding.review_decision_ref.clone()));
        active_evidence_refs.push(json!(binding.activation_ref.clone()));
        active_receipt_refs.push(json!(binding.activation_receipt_ref.clone()));
    }
    let lifecycle_genesis = match lifecycle.append(
        &json!({
                "object_kind":"goal_run",
                "object_ref":goal_ref,
                "from_phase":null,
                "to_phase":"draft",
                "expected_head":null,
                "idempotency_key":format!("{goal_run_id}:create"),
                "authority_class":"daemon",
                "authority_ref":"authority://hypervisor-daemon",
                "evidence_refs": genesis_evidence_refs,
                "receipt_refs": genesis_receipt_refs
        }),
        nanos() as u64,
    ) {
        Ok(record) => record,
        Err(error) => return pursuit_err(error),
    };
    let lifecycle_id = format!("{goal_run_id}_lifecycle_1");
    if persist_record(
        &st.data_dir,
        "work-lifecycle-records",
        &lifecycle_id,
        &lifecycle_genesis,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_lifecycle_persist_failed",
            "The direct GoalRun lifecycle genesis did not persist.",
        );
    }
    let lifecycle_active = match lifecycle.append(
        &json!({
            "object_kind":"goal_run",
            "object_ref":goal_ref,
            "from_phase":"draft",
            "to_phase":"active",
            "expected_head":lifecycle.head(goal_ref),
            "idempotency_key":format!("{goal_run_id}:activate"),
            "authority_class":"goal_kernel",
            "authority_ref":"authority://hypervisor-daemon/goal-kernel",
            "evidence_refs": active_evidence_refs,
            "receipt_refs": active_receipt_refs
        }),
        nanos() as u64,
    ) {
        Ok(record) => record,
        Err(error) => return pursuit_err(error),
    };
    let lifecycle_active_id = format!("{goal_run_id}_lifecycle_2");
    if persist_record(
        &st.data_dir,
        "work-lifecycle-records",
        &lifecycle_active_id,
        &lifecycle_active,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_lifecycle_persist_failed",
            "The direct GoalRun activation record did not persist.",
        );
    }
    let mut record_receipt_refs = vec![
        decision
            .get("decision_receipt_ref")
            .cloned()
            .unwrap_or(Value::Null),
        resolution
            .get("resolution_receipt_ref")
            .cloned()
            .unwrap_or(Value::Null),
    ];
    let mut receipt_obligations = vec![
        json!({
            "obligation_id": format!("receipt-obligation://goal-run/{goal_run_id}/admission"),
            "boundary_event":"admission",
            "receipt_type":"goal_run_admission_path_decision",
            "receipt_profile_ref":"schema://ioi/applications/ioi-ai/goal-run-admission-path-decision/v1",
            "bound_fact_requirement_refs":[
                decision.get("decision_ref").cloned().unwrap_or(Value::Null),
                goal_ref
            ],
            "required":true
        }),
        json!({
            "obligation_id": format!("receipt-obligation://goal-run/{goal_run_id}/close-or-escalate"),
            "boundary_event":"close_or_escalate",
            "receipt_type":"work_result",
            "receipt_profile_ref":"schema://ioi/foundations/work-result/v3",
            "bound_fact_requirement_refs":[goal_ref],
            "required":true
        }),
    ];
    if let Some(binding) = activation {
        record_receipt_refs.push(json!(binding.review_decision_ref.clone()));
        record_receipt_refs.push(json!(binding.activation_receipt_ref.clone()));
        receipt_obligations = binding.receipt_obligations.clone();
    }
    let mut record = json!({
        "schema_version": CANONICAL_GOAL_RUN_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "owner_ref": body.get("owner_ref").cloned().unwrap_or_else(|| json!("user://current")),
        "origin_surface": body.get("origin_surface").cloned().unwrap_or_else(|| json!("api")),
        "normalized_goal": normalized_goal,
        "goal_run_profile_revision_ref": decision.get("goal_run_profile_revision_ref"),
        "goal_run_profile_content_hash": decision.get("goal_run_profile_content_hash"),
        "resolved_component_set_snapshot_ref": resolution.get("resolved_component_set_snapshot_ref"),
        "resolved_component_set_hash": resolution.get("resolved_component_set_hash"),
        "active_skill_set_snapshot_ref": resolution.get("active_skill_set_snapshot_ref"),
        "active_skill_set_hash": resolution.get("active_skill_set_hash"),
        "goal_run_profile_resolution_receipt_ref": resolution.get("resolution_receipt_ref"),
        "admission_path_decision": decision,
        "admission_path_fact_resolution": fact_resolution.cloned().unwrap_or(Value::Null),
        "admission_path_status": "direct_non_system",
        "target_system_id": Value::Null,
        "result_profile": decision.get("result_profile"),
        "activation_ref": Value::Null,
        "source_context_binding": {"target_session_ref":Value::Null,"project_ref":Value::Null},
        "outcome_room_ref": Value::Null,
        "room_participant_lease_ref": Value::Null,
        "frontier_item_refs": [],
        "work_claim_refs": [],
        "constraint_refs": body.get("constraint_refs").cloned().unwrap_or_else(|| json!([])),
        "context_cell_refs": [],
        "context_lease_refs": [],
        "runtime_assignment_refs": [],
        "attempt_refs": [],
        "work_result_refs": [],
        "finding_refs": [],
        "receipt_refs": record_receipt_refs,
        "receipt_obligations": receipt_obligations,
        "admitted_state_root_ref": activation
            .map(|binding| json!(binding.admitted_state_root_ref.clone()))
            .unwrap_or_else(|| json!(format!("agentgres://state-root/goal-run/{goal_run_id}"))),
        "authority_scope_refs": body.get("authority_scope_refs").cloned().unwrap_or_else(|| json!([])),
        "active_loop_phase": "receive_intent",
        "continuation_state": "open",
        "status": "active",
        "lifecycle_head": lifecycle_active.get("resulting_head"),
        "lifecycle_record_refs": [lifecycle_genesis.get("record_id"), lifecycle_active.get("record_id")],
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource":"daemon-runtime"
    });
    if let Some(binding) = activation {
        record["owner_ref"] = json!(binding.source_owner_ref.clone());
        record["origin_surface"] = json!("ioi_goal_chat");
        record["activation_ref"] = json!(binding.activation_ref.clone());
        record["source_context_binding"] = json!({
            "target_session_ref": Value::Null,
            "project_ref": binding.project_ref.clone()
        });
        record["user_intent_ref"] = json!(binding.source_ref.clone());
        record["creation_provenance"] = json!("goal_run_activation_envelope");
        record["goal_run_execution_ceiling_revision_ref"] = resolution
            .get("goal_run_execution_ceiling_revision_ref")
            .cloned()
            .unwrap_or(Value::Null);
        record["goal_run_execution_ceiling_content_hash"] = resolution
            .get("goal_run_execution_ceiling_content_hash")
            .cloned()
            .unwrap_or(Value::Null);
        record["declared_invocation_budget"] = resolution
            .get("declared_invocation_budget")
            .cloned()
            .unwrap_or(Value::Null);
        record["admitted_override_set_ref"] = resolution
            .pointer("/resolution_receipt/admitted_override_set_ref")
            .cloned()
            .unwrap_or(Value::Null);
        record["admitted_override_set_hash"] = resolution
            .pointer("/resolution_receipt/admitted_override_set_hash")
            .cloned()
            .unwrap_or(Value::Null);
    }
    if activation.is_some() {
        if let Err(error) =
            ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                "schema://ioi/applications/ioi-ai/goal-run/v1",
                &record,
            )
        {
            return bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_contract_invalid",
                "The generated activation-backed GoalRun does not satisfy its registered contract.",
                json!({ "error": error }),
            );
        }
    }
    let persisted = if activation.is_some() {
        persist_goal_run_atomic(&st.data_dir, goal_run_id, &record)
            .map_err(|error| format!("{error:?}"))
    } else {
        persist_record(&st.data_dir, GOAL_RUN_KIND, goal_run_id, &record)
            .map_err(|error| error.to_string())
    };
    if persisted.is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_persist_failed",
            "The direct GoalRun record did not persist.",
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({"ok":true,"goal_run":record,"definition_resolution":resolution})),
    )
}

fn activation_projection(st: &DaemonState, id: &str, replayed: bool) -> Result<Value, HttpRefusal> {
    if activation_key_from_ref(&activation_ref(id)).is_none() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_id_invalid",
            "The activation id is not a bounded canonical identifier.",
        ));
    }
    let reference = activation_ref(id);
    let activation = activation_for_preauthorization(&st.data_dir, id, false)?;
    let control = required_activation_record(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        id,
        "goal_run_activation_control_missing",
        "The durable activation exists without its daemon-owned control record.",
    )?;
    let resolved_profile = load_activation_profile(&st.data_dir, &control)?;
    if activation
        .get("requested_goal_run_profile_revision_ref")
        .and_then(Value::as_str)
        != resolved_profile
            .profile
            .get("revision_ref")
            .and_then(Value::as_str)
        || activation
            .get("requested_goal_run_profile_content_hash")
            .and_then(Value::as_str)
            != resolved_profile
                .profile
                .get("content_hash")
                .and_then(Value::as_str)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_profile_resolution_changed",
            "The activation no longer binds its exact immutable GoalRunProfile closure.",
        ));
    }
    let source_ref = activation
        .pointer("/source_context/source_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let goal_draft = required_activation_record(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_SOURCE_KIND,
        &safe(source_ref),
        "goal_run_activation_source_missing",
        "The activation source draft is not durably resolvable.",
    )?;
    if text(&goal_draft, "draft_intent_ref") != source_ref {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_source_identity_failure",
            "The activation source slot does not bind its deterministic draft identity.",
        ));
    }
    let source_hash = sha256_canonical(&goal_draft);
    if control.get("source_hash").and_then(Value::as_str) != Some(source_hash.as_str()) {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_source_integrity_failure",
            "The retained Goal Chat draft no longer matches the source admitted by the activation control.",
        ));
    }
    let authority_request = required_activation_record(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_AUTHORITY_KIND,
        id,
        "goal_run_activation_authority_decision_missing",
        "The activation cannot replay its daemon-resolved principal/scope decision.",
    )?;
    if text(&authority_request, "activation_ref") != reference {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_authority_identity_failure",
            "The authority slot does not bind this activation identity.",
        ));
    }
    let authority_hash = sha256_canonical(&authority_request);
    if control
        .get("authority_decision_hash")
        .and_then(Value::as_str)
        != Some(authority_hash.as_str())
        || activation
            .get("authority_decision_ref")
            .and_then(Value::as_str)
            != authority_request
                .get("decision_ref")
                .and_then(Value::as_str)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_authority_integrity_failure",
            "The daemon-resolved activation authority decision changed or no longer matches its reference.",
        ));
    }
    let authority_decision = if let Some(expected_hash) = control
        .get("authorized_authority_decision_hash")
        .and_then(Value::as_str)
    {
        let authorized = required_activation_record(
            &st.data_dir,
            GOAL_RUN_ACTIVATION_AUTHORIZED_AUTHORITY_KIND,
            id,
            "goal_run_activation_authorized_authority_missing",
            "The activation control names consumed authority without its exact decision record.",
        )?;
        if sha256_canonical(&authorized) != expected_hash
            || text(&authorized, "activation_ref") != reference
            || authorized.get("decision_ref") != authority_request.get("decision_ref")
            || authorized.get("principal_ref") != authority_request.get("principal_ref")
            || authorized.get("admission_bearing").and_then(Value::as_bool) != Some(true)
            || authorized.get("non_grant").and_then(Value::as_bool) != Some(false)
            || text(&authorized, "grant_ref").is_empty()
            || text(&authorized, "authority_admission_intent_ref").is_empty()
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_authorized_authority_integrity_failure",
                "Consumed activation authority no longer matches its retained request and control commitment.",
            ));
        }
        authorized
    } else {
        authority_request
    };
    let current_hash = sha256_canonical(&activation);
    let expected_hash_field = match text(&activation, "status") {
        "draft" => "draft_activation_hash",
        "submitted" => "submitted_activation_hash",
        "admitted" => "admitted_activation_hash",
        _ => "current_activation_hash",
    };
    if control.get(expected_hash_field).and_then(Value::as_str) != Some(current_hash.as_str()) {
        return Err(bad_with_details(
            StatusCode::CONFLICT,
            "goal_run_activation_integrity_failure",
            "The activation bytes do not match the daemon-retained state commitment.",
            json!({ "status": text(&activation, "status"), "expected_hash_field": expected_hash_field }),
        ));
    }
    if text(&activation, "status") == "admitted"
        && (authority_decision
            .get("admission_bearing")
            .and_then(Value::as_bool)
            != Some(true)
            || text(&authority_decision, "decision") != "authorized_for_explicit_review")
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "goal_run_activation_authority_admission_missing",
            "An admitted activation must replay the exact consumed, admission-bearing authority decision.",
        ));
    }
    let goal_run = if let Some(goal_ref) = activation
        .get("admitted_goal_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        load_goal_run_strict(&st.data_dir, goal_ref).map_err(|error| {
            bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_activation_goal_registry_unreadable",
                "The admitted GoalRun cannot be resolved through its strict owner registry.",
                json!({ "error": error }),
            )
        })?
    } else {
        None
    };
    let mut admitted_state = Value::Null;
    let mut receipt_obligation_discharge = Value::Null;
    if text(&activation, "status") == "admitted" {
        if let Some(run) = goal_run.as_ref() {
            if let Err(error) =
                ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                    "schema://ioi/applications/ioi-ai/goal-run/v1",
                    run,
                )
            {
                return Err(bad_with_details(
                    StatusCode::CONFLICT,
                    "goal_run_activation_goal_contract_invalid",
                    "The replayed activation-backed GoalRun no longer satisfies its registered contract.",
                    json!({ "error": error }),
                ));
            }
        }
        let bound = goal_run
            .as_ref()
            .and_then(|run| run.get("activation_ref"))
            .and_then(Value::as_str);
        if bound != Some(reference.as_str()) {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_goal_binding_missing",
                "An admitted activation must replay its exact GoalRun binding.",
            ));
        }
        let run = goal_run
            .as_ref()
            .expect("admitted GoalRun binding was checked");
        let root_ref = text(run, "admitted_state_root_ref");
        if root_ref.is_empty()
            || control
                .get("admitted_state_root_ref")
                .and_then(Value::as_str)
                != Some(root_ref)
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_state_binding_missing",
                "The admitted GoalRun and activation control do not bind one exact state root.",
            ));
        }
        admitted_state = load_activation_state(&st.data_dir, root_ref)?;
        let state_matches = admitted_state.get("goal_run_ref") == run.get("goal_ref")
            && admitted_state.get("activation_ref") == run.get("activation_ref")
            && admitted_state.get("source_context_hash") == control.get("source_hash")
            && admitted_state.get("requesting_principal_ref") == run.get("owner_ref")
            && admitted_state.get("authority_decision_ref")
                == activation.get("authority_decision_ref")
            && admitted_state.get("goal_run_profile_revision_ref")
                == run.get("goal_run_profile_revision_ref")
            && admitted_state.get("goal_run_profile_content_hash")
                == run.get("goal_run_profile_content_hash")
            && admitted_state.get("goal_run_execution_ceiling_revision_ref")
                == run.get("goal_run_execution_ceiling_revision_ref")
            && admitted_state.get("goal_run_execution_ceiling_content_hash")
                == run.get("goal_run_execution_ceiling_content_hash")
            && admitted_state.get("declared_invocation_budget")
                == run.get("declared_invocation_budget")
            && admitted_state.get("admitted_override_set_ref")
                == run.get("admitted_override_set_ref")
            && admitted_state.get("admitted_override_set_hash")
                == run.get("admitted_override_set_hash")
            && admitted_state.get("resolved_component_set_snapshot_ref")
                == run.get("resolved_component_set_snapshot_ref")
            && admitted_state.get("resolved_component_set_hash")
                == run.get("resolved_component_set_hash")
            && admitted_state.get("profile_resolution_receipt_ref")
                == run.get("goal_run_profile_resolution_receipt_ref")
            && admitted_state.get("receipt_obligations") == run.get("receipt_obligations");
        if !state_matches {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_state_binding_changed",
                "The admitted-state root no longer binds the exact GoalRun admission closure.",
            ));
        }
        if run.get("goal_run_execution_ceiling_revision_ref")
            != resolved_profile.execution_ceiling.get("revision_ref")
            || run.get("goal_run_execution_ceiling_content_hash")
                != resolved_profile.execution_ceiling.get("content_hash")
            || run
                .pointer("/declared_invocation_budget/max_total_invocations")
                .and_then(Value::as_u64)
                != Some(0)
            || run
                .pointer("/declared_invocation_budget/max_parallel_invocations")
                .and_then(Value::as_u64)
                != Some(0)
            || !run
                .get("admitted_override_set_ref")
                .is_some_and(Value::is_null)
            || !run
                .get("admitted_override_set_hash")
                .is_some_and(Value::is_null)
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_bounds_binding_changed",
                "The replayed GoalRun no longer binds its exact zero-execution ceiling, declared budget, and null override tuple.",
            ));
        }
        let resolution_receipt = required_activation_record(
            &st.data_dir,
            "goal-run-profile-resolution-receipts",
            text(run, "goal_run_id"),
            "goal_run_profile_resolution_receipt_missing",
            "The admitted GoalRun cannot replay its exact profile-resolution receipt.",
        )?;
        if let Err(error) =
            ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
                "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1",
                &resolution_receipt,
            )
        {
            return Err(bad_with_details(
                StatusCode::CONFLICT,
                "goal_run_profile_resolution_receipt_contract_invalid",
                "The replayed profile-resolution receipt no longer satisfies its registered contract.",
                json!({ "error": error }),
            ));
        }
        if resolution_receipt.get("goal_run_execution_ceiling_revision_ref")
            != run.get("goal_run_execution_ceiling_revision_ref")
            || resolution_receipt.get("goal_run_execution_ceiling_content_hash")
                != run.get("goal_run_execution_ceiling_content_hash")
            || resolution_receipt.get("declared_invocation_budget")
                != run.get("declared_invocation_budget")
            || resolution_receipt.get("admitted_override_set_ref")
                != run.get("admitted_override_set_ref")
            || resolution_receipt.get("admitted_override_set_hash")
                != run.get("admitted_override_set_hash")
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_profile_resolution_bounds_changed",
                "The profile-resolution receipt no longer binds the GoalRun execution ceiling, declared budget, and override tuple.",
            ));
        }
        let activation_receipt_ref = text(&activation, "activation_receipt_ref");
        let activation_receipt = required_activation_record(
            &st.data_dir,
            GOAL_RUN_ACTIVATION_RECEIPT_KIND,
            &receipt_file_key(activation_receipt_ref),
            "goal_run_activation_receipt_missing",
            "The admitted GoalRun cannot replay its typed activation receipt.",
        )?;
        if text(&activation_receipt, "activation_ref") != reference
            || text(&activation_receipt, "receipt_ref") != activation_receipt_ref
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_identity_failure",
                "The activation receipt slot does not bind its activation and receipt identities.",
            ));
        }
        if activation_receipt.get("admitted_state_root_ref") != admitted_state.get("state_root_ref")
            || activation_receipt.get("goal_run_profile_revision_ref")
                != admitted_state.get("goal_run_profile_revision_ref")
            || activation_receipt.get("goal_run_profile_content_hash")
                != admitted_state.get("goal_run_profile_content_hash")
            || activation_receipt.get("resolved_component_set_snapshot_ref")
                != admitted_state.get("resolved_component_set_snapshot_ref")
            || activation_receipt.get("resolved_component_set_hash")
                != admitted_state.get("resolved_component_set_hash")
            || activation_receipt.get("profile_resolution_receipt_ref")
                != admitted_state.get("profile_resolution_receipt_ref")
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_binding_changed",
                "The typed activation receipt no longer covers the admitted GoalRun state.",
            ));
        }
        let obligations = run
            .get("receipt_obligations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                bad(
                    StatusCode::CONFLICT,
                    "goal_run_activation_receipt_obligations_missing",
                    "The admitted GoalRun does not retain typed receipt obligations.",
                )
            })?;
        receipt_obligation_discharge =
            validate_activation_receipt_discharge(obligations, &activation_receipt)?;
        if control.get("receipt_obligation_discharge") != Some(&receipt_obligation_discharge) {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_discharge_changed",
                "The replayed typed receipt discharge no longer matches its retained commitment.",
            ));
        }
    }
    let receipt = |family: &str, receipt_ref: &str| -> Result<Value, HttpRefusal> {
        if receipt_ref.is_empty() {
            return Ok(Value::Null);
        }
        let record = required_activation_record(
            &st.data_dir,
            family,
            &receipt_file_key(receipt_ref),
            "goal_run_activation_receipt_missing",
            "A retained activation receipt reference has no exact strict-registry record.",
        )?;
        if text(&record, "activation_ref") != reference
            || text(&record, "receipt_ref") != receipt_ref
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "goal_run_activation_receipt_identity_failure",
                "An activation receipt slot does not bind its activation and receipt identities.",
            ));
        }
        Ok(record)
    };
    let review_receipt = receipt(
        GOAL_RUN_ACTIVATION_REVIEW_KIND,
        text(&control, "review_decision_ref"),
    )?;
    let admission_receipt = receipt(
        GOAL_RUN_ADMISSION_RECEIPT_KIND,
        text(&control, "admission_receipt_ref"),
    )?;
    let activation_receipt = receipt(
        GOAL_RUN_ACTIVATION_RECEIPT_KIND,
        text(&control, "activation_receipt_ref"),
    )?;
    Ok(json!({
        "ok": true,
        "activation": activation,
        "activation_hash": current_hash,
        "goal_draft": goal_draft,
        "authority_decision": authority_decision,
        "resolved_profile": resolved_profile.profile,
        "admission_policy": resolved_profile.policy,
        "goal_run_execution_ceiling": resolved_profile.execution_ceiling,
        "goal_run": goal_run.unwrap_or(Value::Null),
        "admitted_state": admitted_state,
        "receipt_obligation_discharge": receipt_obligation_discharge,
        "receipts": {
            "review": review_receipt,
            "admission": admission_receipt,
            "activation": activation_receipt
        },
        "replayed": replayed
    }))
}

/// POST /v1/goal-orchestration/goal-run-activations
///
/// Product code supplies goal text and an idempotency key only. Identity, source coordinate,
/// GoalRunProfile revision/hash, runtime admission facts, and authority posture are resolved by
/// the daemon and retained before the user is allowed to review/submit the activation.
pub(crate) async fn handle_goal_run_activation_draft(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(response) = closed_request(
        &body,
        &[
            "schema_version",
            "goal_text",
            "constraints",
            "project_ref",
            "result_profile",
            "idempotency_key",
        ],
        "goal_run_activation_draft_request_invalid",
    ) {
        return response;
    }
    if text(&body, "schema_version") != GOAL_RUN_ACTIVATION_DRAFT_REQUEST_SCHEMA_VERSION {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_draft_schema_invalid",
            "The activation draft request must declare ioi.goal-run-activation-draft-request.v1.",
        );
    }
    let goal_text = text(&body, "goal_text").trim().to_string();
    if !(4..=32_768).contains(&goal_text.len()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_goal_invalid",
            "goal_text must contain 4..32768 bytes.",
        );
    }
    let idempotency_key = match bounded_idempotency_key(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let constraints = match bounded_constraints(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result_profile = body
        .get("result_profile")
        .and_then(Value::as_str)
        .unwrap_or("research");
    if result_profile != "research" {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_result_profile_unsupported",
            "This bounded activation cut resolves only the admitted research result profile.",
        );
    }
    let (principal_ref, principal_resolution_source) = match activation_principal(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let project_ref = match resolve_activation_project(&st.data_dir, body.get("project_ref")) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let resolved_profile = match ensure_activation_profile(&st).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let normalized_request = json!({
        "schema_version": GOAL_RUN_ACTIVATION_DRAFT_REQUEST_SCHEMA_VERSION,
        "goal_text": goal_text,
        "constraints": constraints,
        "project_ref": project_ref,
        "result_profile": result_profile,
        "idempotency_key": idempotency_key,
        "resolved_principal_ref": principal_ref
    });
    let request_hash = sha256_canonical(&normalized_request);
    let idempotency_subject_hash = sha256_canonical(&json!({
        "principal_ref": principal_ref,
        "idempotency_key": idempotency_key
    }));
    let digest = idempotency_subject_hash
        .strip_prefix("sha256:")
        .unwrap_or(&idempotency_subject_hash);
    let id = format!("gra_{}", &digest[..24.min(digest.len())]);
    let reference = activation_ref(&id);
    let source_ref = format!("intent://ioi-ai/{id}");
    let constraint_ref = format!("constraint://goal-run-activation/{id}");
    let authority_decision_ref =
        format!("approval://goal-run-activation/{id}/principal-scope-resolution");
    let effective_constraint_hash = sha256_canonical(&json!({
        "constraints": normalized_request["constraints"],
        "project_ref": normalized_request["project_ref"],
        "managed_execution_mode": "standard",
        "goal_execution_policy": "auto"
    }));
    let goal_draft = json!({
        "schema_version": "ioi.ioi-ai.goal-draft.v1",
        "object_class": "IoiAiGoalDraft",
        "draft_intent_ref": source_ref,
        "user_ref": principal_ref,
        "project_ref": project_ref,
        "goal_text": normalized_request["goal_text"],
        "constraints": normalized_request["constraints"],
        "result_profile": result_profile,
        "privacy_posture_ref": Value::Null,
        "authority_context_ref": Value::Null,
        "managed_execution_mode": "standard",
        "goal_execution_policy": "auto",
        "contributor_scope": "my_workers",
        "placement_policy_ref": Value::Null,
        "work_credit_budget_ref": Value::Null,
        "network_goal_budget_ref": Value::Null,
        "draft_status": "ready_for_admission"
    });
    let authority_decision = sealed(json!({
        "schema_version": "ioi.goal-run-activation-authority-request.v1",
        "decision_ref": authority_decision_ref,
        "activation_ref": reference,
        "principal_ref": principal_ref,
        "principal_resolution_source": principal_resolution_source,
        "deployment_posture": super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers),
        "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE,
        "decision": "authority_required",
        "admission_bearing": false,
        "non_grant": true,
        "grant_ref": Value::Null,
        "authority_admission_intent_ref": Value::Null,
        "expires_at": Value::Null,
        "revocation_epoch": Value::Null,
        "non_grants": {
            "authority_widening": "none",
            "context_declassification": "none",
            "room_membership": "none",
            "budget_creation": "none"
        },
        "decided_at": iso_now()
    }));
    let activation = json!({
        "schema_version": GOAL_RUN_ACTIVATION_SCHEMA_VERSION,
        "activation_id": reference,
        "activation_mode": "create",
        "source_context": {
            "source_kind": "ioi_goal_draft",
            "source_ref": source_ref,
            "source_owner_ref": principal_ref
        },
        "requested_goal_run_profile_revision_ref": resolved_profile.profile.get("revision_ref").cloned().unwrap_or(Value::Null),
        "requested_goal_run_profile_content_hash": resolved_profile.profile.get("content_hash").cloned().unwrap_or(Value::Null),
        "existing_goal_ref": Value::Null,
        "normalized_intent_ref": source_ref,
        "carried_context_refs": [],
        "requested_constraint_refs": if constraints.is_empty() { Vec::<Value>::new() } else { vec![json!(constraint_ref)] },
        "requesting_principal_ref": principal_ref,
        "authority_decision_ref": authority_decision_ref,
        "review_requirement": "explicit_user",
        "review_decision_ref": Value::Null,
        "idempotency_key": idempotency_key,
        "admission_decision_ref": Value::Null,
        "admitted_goal_ref": Value::Null,
        "activation_receipt_ref": Value::Null,
        "refusal_reason_code": Value::Null,
        "expires_at": Value::Null,
        "status": "draft",
        "non_grants": {
            "authority_widening": "none",
            "context_declassification": "none",
            "room_membership": "none",
            "budget_creation": "none"
        }
    });
    let source_hash = sha256_canonical(&goal_draft);
    let draft_activation_hash = sha256_canonical(&activation);
    let control = json!({
        "schema_version": "ioi.goal-run-activation-control.v1",
        "activation_ref": reference,
        "request_hash": request_hash,
        "idempotency_subject_hash": idempotency_subject_hash,
        "source_hash": source_hash,
        "authority_decision_hash": sha256_canonical(&authority_decision),
        "draft_activation_hash": draft_activation_hash,
        "effective_constraint_hash": effective_constraint_hash,
        "resolved_profile": {
            "revision_ref": resolved_profile.profile.get("revision_ref").cloned().unwrap_or(Value::Null),
            "content_hash": resolved_profile.profile.get("content_hash").cloned().unwrap_or(Value::Null),
            "profile_key": resolved_profile.profile_key,
            "policy_ref": resolved_profile.policy.get("policy_ref").cloned().unwrap_or(Value::Null),
            "policy_content_hash": resolved_profile.policy.get("content_hash").cloned().unwrap_or(Value::Null),
            "policy_key": resolved_profile.policy_key,
            "component_ref": resolved_profile.component.get("revision_ref").cloned().unwrap_or(Value::Null),
            "component_content_hash": resolved_profile.component.get("content_hash").cloned().unwrap_or(Value::Null),
            "component_key": resolved_profile.component_key,
            "execution_ceiling_revision_ref": resolved_profile.execution_ceiling.get("revision_ref").cloned().unwrap_or(Value::Null),
            "execution_ceiling_content_hash": resolved_profile.execution_ceiling.get("content_hash").cloned().unwrap_or(Value::Null),
            "execution_ceiling_key": resolved_profile.execution_ceiling_key,
            "resolution_owner": "hypervisor_daemon_release_registry"
        },
        "principal_resolution": {
            "principal_ref": principal_ref,
            "source": principal_resolution_source,
            "deployment_posture": super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers),
            "required_scope": "scope:goal.run.create",
            "non_grant": true
        },
        "status": "draft",
        "created_at": iso_now()
    });

    let _guard = GOAL_RUN_ACTIVATION_LOCK.lock().await;
    let existing_control =
        match activation_record_strict(&st.data_dir, GOAL_RUN_ACTIVATION_CONTROL_KIND, &id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    if let Some(existing_control) = existing_control {
        if text(&existing_control, "activation_ref") != reference {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_control_identity_failure",
                "The deterministic activation control slot carries a different identity.",
            );
        }
        if text(&existing_control, "request_hash") != request_hash {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_idempotency_body_conflict",
                "The same principal/idempotency_key was reused with changed activation material.",
            );
        }
        // A prior attempt may have observed the control after rename but before its directory
        // durability barrier. Re-persisting the byte-identical control on the same-key retry is
        // the certification step; never turn mere visibility into a successful draft replay.
        if let Err(response) = durable_write(
            &st.data_dir,
            GOAL_RUN_ACTIVATION_CONTROL_KIND,
            &id,
            &existing_control,
        ) {
            return response;
        }
        return match activation_projection(&st, &id, true) {
            Ok(projection) => (StatusCode::OK, Json(projection)),
            Err(response) => response,
        };
    }
    let existing_activation =
        match activation_record_strict(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id) {
            Ok(value) => value,
            Err(response) => return response,
        };
    if let Some(existing) = existing_activation {
        if text(&existing, "activation_id") != reference {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_identity_failure",
                "The deterministic activation slot carries a different identity.",
            );
        }
        if sha256_canonical(&existing) != draft_activation_hash {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_uncontrolled_state_conflict",
                "A conflicting activation occupies the deterministic idempotency slot.",
            );
        }
    }
    let source_key = safe(&source_ref);
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_SOURCE_KIND,
        &source_key,
        &goal_draft,
    ) {
        return response;
    }
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_AUTHORITY_KIND,
        &id,
        &authority_decision,
    ) {
        return response;
    }
    if let Err(response) = durable_write(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id, &activation) {
        return response;
    }
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        &id,
        &control,
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "goal_draft": goal_draft,
            "authority_decision": authority_decision,
            "activation": activation,
            "activation_hash": draft_activation_hash,
            "resolved_profile": control.get("resolved_profile").cloned().unwrap_or(Value::Null),
            "replayed": false
        })),
    )
}

/// GET /v1/goal-orchestration/goal-run-activations/:id — durable replay projection.
pub(crate) async fn handle_goal_run_activation_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let (principal_ref, _) = match activation_principal(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let conceal_missing = super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers)
        != "local_development";
    let activation = match activation_for_preauthorization(&st.data_dir, &id, conceal_missing) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = require_activation_owner(&activation, &principal_ref) {
        return response;
    }
    let projection = match activation_projection(&st, &id, true) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let owner_matches = projection
        .pointer("/activation/source_context/source_owner_ref")
        .and_then(Value::as_str)
        == Some(principal_ref.as_str())
        && projection
            .pointer("/activation/requesting_principal_ref")
            .and_then(Value::as_str)
            == Some(principal_ref.as_str())
        && projection
            .pointer("/goal_draft/user_ref")
            .and_then(Value::as_str)
            == Some(principal_ref.as_str())
        && projection
            .pointer("/authority_decision/principal_ref")
            .and_then(Value::as_str)
            == Some(principal_ref.as_str());
    if !owner_matches {
        return bad(
            StatusCode::FORBIDDEN,
            "goal_run_activation_projection_owner_mismatch",
            "The authenticated principal does not own this activation projection.",
        );
    }
    (StatusCode::OK, Json(projection))
}

/// POST /v1/goal-orchestration/goal-run-activations/:id/submit
///
/// The explicit user-review crossing. The request can approve only the exact retained draft hash;
/// principal, source, profile, admission facts, receipts, GoalRun id, state root, and lifecycle
/// head are all daemon-derived. A retry converges on the same activation and GoalRun.
pub(crate) async fn handle_goal_run_activation_submit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(response) = closed_request(
        &body,
        &[
            "schema_version",
            "expected_activation_hash",
            "review_decision",
            "wallet_approval_grant",
        ],
        "goal_run_activation_submit_request_invalid",
    ) {
        return response;
    }
    if text(&body, "schema_version") != GOAL_RUN_ACTIVATION_SUBMIT_REQUEST_SCHEMA_VERSION {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_submit_schema_invalid",
            "The activation submit request must declare ioi.goal-run-activation-submit-request.v1.",
        );
    }
    if text(&body, "review_decision") != "approve" {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_explicit_user_review_required",
            "GoalRun activation requires an explicit approve decision over the exact retained draft.",
        );
    }
    let expected_activation_hash = text(&body, "expected_activation_hash");
    if !expected_activation_hash
        .strip_prefix("sha256:")
        .is_some_and(|hex| {
            hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
        })
    {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_expected_hash_invalid",
            "expected_activation_hash must be a sha256 commitment.",
        );
    }
    let (principal_ref, principal_resolution_source) = match activation_principal(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let reference = activation_ref(&id);
    if activation_key_from_ref(&reference).is_none() {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_activation_id_invalid",
            "The activation id is not a bounded canonical identifier.",
        );
    }
    let conceal_missing = super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers)
        != "local_development";
    let preauthorized_activation =
        match activation_for_preauthorization(&st.data_dir, &id, conceal_missing) {
            Ok(value) => value,
            Err(response) => return response,
        };
    if let Err(response) = require_activation_owner(&preauthorized_activation, &principal_ref) {
        return response;
    }
    let _guard = GOAL_RUN_ACTIVATION_LOCK.lock().await;
    let mut activation = match activation_record_strict(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id)
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return bad(
                StatusCode::NOT_FOUND,
                "goal_run_activation_not_found",
                "Unknown GoalRun activation.",
            )
        }
        Err(response) => return response,
    };
    if activation != preauthorized_activation {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_changed_after_authorization",
            "The activation changed after owner authorization; review the current bytes.",
        );
    }
    let mut control =
        match activation_record_strict(&st.data_dir, GOAL_RUN_ACTIVATION_CONTROL_KIND, &id) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return bad(
                    StatusCode::CONFLICT,
                    "goal_run_activation_control_missing",
                    "The durable activation exists without its daemon-owned control record.",
                )
            }
            Err(response) => return response,
        };
    if text(&activation, "activation_id") != reference
        || text(&control, "activation_ref") != reference
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_storage_identity_failure",
            "Activation or control bytes do not bind their deterministic storage identity.",
        );
    }
    if text(&control, "draft_activation_hash") != expected_activation_hash {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_stale_draft",
            "The reviewed activation hash does not match the daemon-retained draft.",
        );
    }
    if activation
        .pointer("/source_context/source_owner_ref")
        .and_then(Value::as_str)
        != Some(principal_ref.as_str())
        || text(&activation, "requesting_principal_ref") != principal_ref
    {
        return bad(
            StatusCode::FORBIDDEN,
            "goal_run_activation_reviewer_owner_mismatch",
            "Only the daemon-resolved source owner may explicitly review this activation.",
        );
    }
    let source_ref = activation
        .pointer("/source_context/source_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let goal_draft = match activation_record_strict(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_SOURCE_KIND,
        &safe(&source_ref),
    ) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_source_missing",
                "The retained Goal Chat source is missing; admission fails closed.",
            )
        }
        Err(response) => return response,
    };
    if text(&goal_draft, "draft_intent_ref") != source_ref
        || text(&goal_draft, "user_ref") != principal_ref
        || control.get("source_hash").and_then(Value::as_str)
            != Some(sha256_canonical(&goal_draft).as_str())
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_source_integrity_failure",
            "The retained Goal Chat source or owner no longer matches the admitted draft commitment.",
        );
    }
    let authority_request =
        match activation_record_strict(&st.data_dir, GOAL_RUN_ACTIVATION_AUTHORITY_KIND, &id) {
            Ok(Some(value)) => value,
            Ok(None) => return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_authority_decision_missing",
                "The daemon-resolved principal/scope request is missing; admission fails closed.",
            ),
            Err(response) => return response,
        };
    let authority_decision_ref = text(&authority_request, "decision_ref").to_string();
    if text(&authority_request, "activation_ref") != reference
        || text(&authority_request, "principal_ref") != principal_ref
        || text(&activation, "authority_decision_ref") != authority_decision_ref
        || control
            .get("authority_decision_hash")
            .and_then(Value::as_str)
            != Some(sha256_canonical(&authority_request).as_str())
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_authority_integrity_failure",
            "The retained principal/scope decision changed or no longer binds the activation owner.",
        );
    }
    if goal_draft
        .get("project_ref")
        .is_some_and(|value| !value.is_null())
    {
        if let Err(response) =
            resolve_activation_project(&st.data_dir, goal_draft.get("project_ref"))
        {
            return response;
        }
    }
    if text(&activation, "status") == "admitted" {
        let admitted_hash = sha256_canonical(&activation);
        if control
            .get("admitted_activation_hash")
            .and_then(Value::as_str)
            != Some(admitted_hash.as_str())
        {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_integrity_failure",
                "The admitted activation no longer matches its daemon-retained commitment.",
            );
        }
        // A visible-but-unconfirmed final activation is left with the durable control in
        // `activation_commit_pending`. The same submit certifies the exact activation bytes,
        // then seals the control. Replaying an already-admitted crossing also re-certifies the
        // two byte-identical records rather than treating cache visibility as crash durability.
        if let Err(response) =
            durable_write(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id, &activation)
        {
            return response;
        }
        control["status"] = json!("admitted");
        if let Err(response) = durable_write(
            &st.data_dir,
            GOAL_RUN_ACTIVATION_CONTROL_KIND,
            &id,
            &control,
        ) {
            return response;
        }
        return match activation_projection(&st, &id, true) {
            Ok(projection) => (StatusCode::OK, Json(projection)),
            Err(response) => response,
        };
    }
    if !matches!(text(&activation, "status"), "draft" | "submitted") {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_not_submittable",
            "Only a draft or recovery-pending submitted activation may be admitted.",
        );
    }
    let current_hash = sha256_canonical(&activation);
    let expected_current_hash = if text(&activation, "status") == "draft" {
        control.get("draft_activation_hash")
    } else {
        control.get("submitted_activation_hash")
    }
    .and_then(Value::as_str);
    if expected_current_hash != Some(current_hash.as_str()) {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_integrity_failure",
            "The activation state changed outside the daemon-owned admission crossing.",
        );
    }
    let resolved_profile = match load_activation_profile(&st.data_dir, &control) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if activation
        .get("requested_goal_run_profile_revision_ref")
        .and_then(Value::as_str)
        != resolved_profile
            .profile
            .get("revision_ref")
            .and_then(Value::as_str)
        || activation
            .get("requested_goal_run_profile_content_hash")
            .and_then(Value::as_str)
            != resolved_profile
                .profile
                .get("content_hash")
                .and_then(Value::as_str)
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_profile_resolution_changed",
            "The requested profile no longer matches the daemon-resolved immutable profile closure.",
        );
    }
    let effective_constraint_hash = sha256_canonical(&json!({
        "constraints": goal_draft.get("constraints").cloned().unwrap_or_else(|| json!([])),
        "project_ref": goal_draft.get("project_ref").cloned().unwrap_or(Value::Null),
        "managed_execution_mode": text(&goal_draft, "managed_execution_mode"),
        "goal_execution_policy": text(&goal_draft, "goal_execution_policy")
    }));
    if text(&control, "effective_constraint_hash") != effective_constraint_hash {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_activation_constraint_resolution_changed",
            "The source constraints no longer resolve to the retained daemon commitment.",
        );
    }
    let authority_policy_hash = sha256_canonical(&json!({
        "domain": "ioi.goal-run-activation-authority-policy.v1",
        "activation_ref": reference,
        "principal_ref": principal_ref,
        "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE,
        "goal_run_profile_revision_ref": resolved_profile.profile.get("revision_ref"),
        "goal_run_profile_content_hash": resolved_profile.profile.get("content_hash"),
        "admission_policy_ref": resolved_profile.policy.get("policy_ref"),
        "admission_policy_content_hash": resolved_profile.policy.get("content_hash")
    }));
    let authority_request_hash = sha256_canonical(&json!({
        "domain": "ioi.goal-run-activation-authority-request.v1",
        "activation_ref": reference,
        "reviewed_activation_hash": expected_activation_hash,
        "source_context_hash": sha256_canonical(&goal_draft),
        "effective_constraint_hash": effective_constraint_hash,
        "principal_ref": principal_ref,
        "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE
    }));
    let authority_effect = json!({
        "activation_ref": reference,
        "activation_mode": activation.get("activation_mode").cloned().unwrap_or(Value::Null),
        "source_context_ref": source_ref,
        "source_context_hash": sha256_canonical(&goal_draft),
        "reviewed_activation_hash": expected_activation_hash,
        "principal_ref": principal_ref,
        "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE,
        "goal_run_profile_revision_ref": resolved_profile.profile.get("revision_ref").cloned().unwrap_or(Value::Null),
        "goal_run_profile_content_hash": resolved_profile.profile.get("content_hash").cloned().unwrap_or(Value::Null),
        "effective_constraint_hash": effective_constraint_hash
    });
    let grant_value = body
        .get("wallet_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let admitted_authority =
        match super::governed_authority::authorize_deployment_grant_for_idempotent_recovery(
            &st.data_dir,
            &grant_value,
            GOAL_RUN_CREATE_AUTHORITY_SCOPE,
            &authority_policy_hash,
            &authority_request_hash,
            &reference,
            "goal-run-activation",
            1,
            &authority_effect,
        )
        .await
        {
            Ok(value) => value,
            Err((status, Json(challenge))) => {
                return (
                    status,
                    Json(json!({
                        "ok": false,
                        "error": {
                            "code": "goal_run_activation_authority_required",
                            "message": "GoalRun admission requires a current wallet-owned grant over the exact reviewed activation.",
                            "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE,
                            "approval": {
                                "policy_hash": authority_policy_hash,
                                "request_hash": authority_request_hash
                            },
                            "authority_challenge": challenge
                        }
                    })),
                )
            }
        };
    if let Err(error) =
        super::governed_authority::revalidate_admission_receipt(&st.data_dir, &admitted_authority)
            .await
    {
        return bad_with_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "goal_run_activation_authority_revalidation_failed",
            "The consumed activation authority could not be revalidated against current wallet truth.",
            json!({ "error": error }),
        );
    }
    let canonical_grant = &admitted_authority.authorized.evidence.wallet_approval_grant;
    let candidate_authority_decision = sealed(json!({
        "schema_version": "ioi.goal-run-activation-authority-decision.v1",
        "decision_ref": authority_decision_ref,
        "activation_ref": reference,
        "principal_ref": principal_ref,
        "principal_resolution_source": principal_resolution_source,
        "deployment_posture": super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers),
        "required_scope": GOAL_RUN_CREATE_AUTHORITY_SCOPE,
        "decision": "authorized_for_explicit_review",
        "admission_bearing": true,
        "non_grant": false,
        "grant_ref": admitted_authority.authorized.evidence.grant_ref,
        "authority_admission_intent_ref": admitted_authority.admission_intent_ref,
        "policy_hash": admitted_authority.authorized.evidence.policy_hash,
        "request_hash": admitted_authority.authorized.evidence.request_hash,
        "effect_hash": admitted_authority.authorized.evidence.effect_hash,
        "authority_binding": admitted_authority.authorized.evidence.authority_binding,
        "resolved_at_ms": admitted_authority.authorized.resolved_at_ms,
        "expires_at": canonical_grant.get("expires_at").cloned().unwrap_or(Value::Null),
        "revocation_epoch": canonical_grant.get("revocation_epoch").cloned().unwrap_or(Value::Null),
        "non_grants": {
            "authority_widening": "none",
            "context_declassification": "none",
            "room_membership": "none",
            "budget_creation": "none"
        },
        "decided_at_ms": admitted_authority.authorized.resolved_at_ms
    }));
    let authority_decision = match activation_record_strict(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_AUTHORIZED_AUTHORITY_KIND,
        &id,
    ) {
        Err(response) => return response,
        Ok(Some(retained)) => {
            let stable_fields = [
                "schema_version",
                "decision_ref",
                "activation_ref",
                "principal_ref",
                "principal_resolution_source",
                "deployment_posture",
                "required_scope",
                "decision",
                "admission_bearing",
                "non_grant",
                "grant_ref",
                "authority_admission_intent_ref",
                "policy_hash",
                "request_hash",
                "effect_hash",
                "authority_binding",
                "expires_at",
                "revocation_epoch",
                "non_grants",
            ];
            let stable_matches = stable_fields
                .iter()
                .all(|field| retained.get(*field) == candidate_authority_decision.get(*field));
            let committed_hash_matches = control
                .get("authorized_authority_decision_hash")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .is_none_or(|expected| sha256_canonical(&retained) == expected);
            if !sealed_record_is_intact(&retained) || !stable_matches || !committed_hash_matches {
                return bad(
                    StatusCode::CONFLICT,
                    "goal_run_activation_authorized_authority_integrity_failure",
                    "The retained consumed authority decision does not match the freshly revalidated exact grant/effect tuple.",
                );
            }
            retained
        }
        Ok(None) => {
            if control
                .get("authorized_authority_decision_hash")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                return bad(
                    StatusCode::CONFLICT,
                    "goal_run_activation_authorized_authority_missing",
                    "The activation control commits a consumed authority decision whose strict record is missing.",
                );
            }
            candidate_authority_decision
        }
    };
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_AUTHORIZED_AUTHORITY_KIND,
        &id,
        &authority_decision,
    ) {
        return response;
    }
    control["authorized_authority_decision_hash"] = json!(sha256_canonical(&authority_decision));
    control["authority_admission_intent_ref"] = authority_decision
        .get("authority_admission_intent_ref")
        .cloned()
        .unwrap_or(Value::Null);
    let goal_run_id = format!("gr_{}", id.trim_start_matches("gra_"));
    let goal_ref = format!("goal://{goal_run_id}");
    let (path_request, definition_resolution_request) = match activation_admission_material(
        &st.data_dir,
        &resolved_profile,
        &activation,
        &goal_draft,
        &authority_decision,
        &goal_ref,
        &id,
        &effective_constraint_hash,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Anchor the explicit-review instant before minting any receipt. Every retry then rebuilds
    // the same admission decision and the same sealed receipt bytes. If this anchor is merely
    // visible but durability-unconfirmed, the route refuses and the retry re-certifies it.
    let reviewed_at = control
        .get("reviewed_at")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(iso_now);
    control["reviewed_at"] = json!(reviewed_at);
    control["status"] = json!("review_committed");
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        &id,
        &control,
    ) {
        return response;
    }
    let decision = match RuntimeKernelService::new()
        .select_goal_run_admission_path(&path_request, &reviewed_at)
    {
        Ok(value) if text(&value, "decision") == "direct_non_system" => value,
        Ok(value) => {
            return bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "goal_run_activation_admission_refused",
                "The daemon did not admit the bounded direct GoalRun path.",
                value,
            )
        }
        Err(error) => return kernel_err(error),
    };
    let definition_resolution =
        match GoalPursuitCore.resolve_definitions(&definition_resolution_request, &reviewed_at) {
            Ok(value) => value,
            Err(error) => return pursuit_err(error),
        };
    let review_decision_ref = format!("receipt://goal-run-activation/{id}/explicit-user-review");
    let activation_receipt_ref = format!("receipt://goal-run-activation/{id}/admission");
    let receipt_obligations = match activation_receipt_obligations(
        &resolved_profile.policy,
        &id,
        &reference,
        &source_ref,
        &authority_decision_ref,
        text(&decision, "decision_ref"),
        &goal_ref,
        text(&resolved_profile.profile, "revision_ref"),
        text(
            &definition_resolution,
            "resolved_component_set_snapshot_ref",
        ),
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let receipt_obligations_hash = sha256_canonical(&json!({
        "domain": "ioi.goal-run-receipt-obligations-jcs-sha256.v1",
        "receipt_obligations": receipt_obligations
    }));
    let admitted_state = match admit_activation_state(
        &st.data_dir,
        &reference,
        &sha256_canonical(&goal_draft),
        &principal_ref,
        &authority_decision_ref,
        &goal_ref,
        &resolved_profile.profile,
        &definition_resolution,
        &decision,
        &receipt_obligations,
        &reviewed_at,
        activation.get("non_grants").unwrap_or(&Value::Null),
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let admitted_state_root_ref = text(&admitted_state, "state_root_ref").to_string();
    let mut attested_boundary_fact_refs: Vec<String> = receipt_obligations
        .iter()
        .flat_map(|obligation| {
            obligation
                .get("bound_fact_requirement_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
        })
        .chain([
            review_decision_ref.clone(),
            text(&decision, "decision_receipt_ref").to_string(),
            admitted_state_root_ref.clone(),
            text(&definition_resolution, "resolution_receipt_ref").to_string(),
        ])
        .filter(|reference| !reference.is_empty())
        .collect();
    attested_boundary_fact_refs.sort();
    attested_boundary_fact_refs.dedup();
    let review_receipt = sealed(json!({
        "schema_version": "ioi.goal-run-activation-review-receipt.v1",
        "receipt_ref": review_decision_ref,
        "receipt_type": "explicit_user_review",
        "activation_ref": reference,
        "reviewed_activation_hash": expected_activation_hash,
        "reviewer_principal_ref": principal_ref,
        "principal_resolution_source": principal_resolution_source,
        "deployment_posture": super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers),
        "required_scope": "scope:goal.run.create",
        "decision": "approve",
        "authority_decision_ref": authority_decision_ref,
        "reviewed_at": reviewed_at,
        "non_grants": activation.get("non_grants").cloned().unwrap_or(Value::Null)
    }));
    let admission_receipt = sealed(json!({
        "schema_version": "ioi.goal-run-admission-receipt.v1",
        "receipt_ref": decision.get("decision_receipt_ref").cloned().unwrap_or(Value::Null),
        "receipt_type": "goal_run_admission_path_decision",
        "activation_ref": reference,
        "goal_run_ref": goal_ref,
        "decision": decision,
        "decision_hash": sha256_canonical(&decision),
        "admitted_at": reviewed_at
    }));
    let activation_receipt = sealed(json!({
        "schema_version": "ioi.goal-run-activation-receipt.v1",
        "receipt_id": activation_receipt_ref,
        "receipt_ref": activation_receipt_ref,
        "receipt_type": GOAL_RUN_ACTIVATION_RECEIPT_TYPE,
        "receipt_profile_ref": GOAL_RUN_ACTIVATION_RECEIPT_PROFILE,
        "activation_ref": reference,
        "activation_mode": activation.get("activation_mode").cloned().unwrap_or(Value::Null),
        "source_context": activation.get("source_context").cloned().unwrap_or(Value::Null),
        "draft_activation_hash": expected_activation_hash,
        "source_context_hash": sha256_canonical(&goal_draft),
        "requesting_principal_ref": principal_ref,
        "authority_decision_ref": authority_decision_ref,
        "review_decision_ref": review_decision_ref,
        "admission_decision_ref": decision.get("decision_ref").cloned().unwrap_or(Value::Null),
        "admission_receipt_ref": decision.get("decision_receipt_ref").cloned().unwrap_or(Value::Null),
        "admitted_goal_ref": goal_ref,
        "existing_goal_ref": activation.get("existing_goal_ref").cloned().unwrap_or(Value::Null),
        "goal_run_profile_revision_ref": resolved_profile.profile.get("revision_ref").cloned().unwrap_or(Value::Null),
        "goal_run_profile_content_hash": resolved_profile.profile.get("content_hash").cloned().unwrap_or(Value::Null),
        "resolved_component_set_snapshot_ref": definition_resolution.get("resolved_component_set_snapshot_ref").cloned().unwrap_or(Value::Null),
        "resolved_component_set_hash": definition_resolution.get("resolved_component_set_hash").cloned().unwrap_or(Value::Null),
        "profile_resolution_receipt_ref": definition_resolution.get("resolution_receipt_ref").cloned().unwrap_or(Value::Null),
        "receipt_obligations_hash": receipt_obligations_hash,
        "attested_boundary_fact_refs": attested_boundary_fact_refs,
        "admitted_state_root_ref": admitted_state_root_ref,
        "admitted_at": reviewed_at,
        "non_grants": activation.get("non_grants").cloned().unwrap_or(Value::Null)
    }));
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            GOAL_RUN_ACTIVATION_RECEIPT_PROFILE,
            &activation_receipt,
        )
    {
        return bad_with_details(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_activation_receipt_contract_invalid",
            "The daemon-produced activation receipt does not satisfy its registered profile.",
            json!({ "error": error }),
        );
    }
    let receipt_obligation_discharge =
        match validate_activation_receipt_discharge(&receipt_obligations, &activation_receipt) {
            Ok(value) => value,
            Err(response) => return response,
        };

    activation["review_decision_ref"] = json!(review_decision_ref);
    activation["status"] = json!("submitted");
    let submitted_activation_hash = sha256_canonical(&activation);
    control["submitted_activation_hash"] = json!(submitted_activation_hash);
    control["authority_decision_ref"] = json!(authority_decision_ref);
    control["review_decision_ref"] = json!(review_decision_ref);
    control["admission_decision_ref"] =
        decision.get("decision_ref").cloned().unwrap_or(Value::Null);
    control["admission_receipt_ref"] = decision
        .get("decision_receipt_ref")
        .cloned()
        .unwrap_or(Value::Null);
    control["activation_receipt_ref"] = json!(activation_receipt_ref);
    control["admitted_state_root_ref"] = json!(admitted_state_root_ref);
    control["admitted_state_key"] =
        json!(activation_state_key(text(&admitted_state, "state_root"))
            .expect("admitted state root was validated before control persistence"));
    control["receipt_obligations_hash"] = json!(receipt_obligations_hash);
    control["receipt_obligation_discharge"] = receipt_obligation_discharge;
    control["status"] = json!("submitting");
    control["submitted_at"] = json!(reviewed_at);

    for (family, key, value) in [
        (
            GOAL_RUN_ACTIVATION_REVIEW_KIND,
            receipt_file_key(&review_decision_ref),
            &review_receipt,
        ),
        (
            GOAL_RUN_ADMISSION_RECEIPT_KIND,
            receipt_file_key(text(&decision, "decision_receipt_ref")),
            &admission_receipt,
        ),
        (
            GOAL_RUN_ACTIVATION_RECEIPT_KIND,
            receipt_file_key(&activation_receipt_ref),
            &activation_receipt,
        ),
    ] {
        if let Err(response) = durable_write(&st.data_dir, family, &key, value) {
            return response;
        }
    }
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        &id,
        &control,
    ) {
        return response;
    }
    if let Err(response) = durable_write(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id, &activation) {
        return response;
    }

    let existing_goal = match load_goal_run_for_http(&st.data_dir, &goal_run_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let goal_run = if let Some(existing) = existing_goal {
        if existing.get("activation_ref").and_then(Value::as_str) != Some(reference.as_str()) {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_activation_goal_identity_conflict",
                "The deterministic GoalRun identity is occupied by a different activation.",
            );
        }
        if let Err(failure) = persist_goal_run_atomic(&st.data_dir, &goal_run_id, &existing) {
            return match failure {
                PersistFailure::NotCommitted(error) => bad_with_details(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "goal_run_activation_goal_persist_failed",
                    "The admitted GoalRun could not be re-certified on the idempotent retry.",
                    json!({ "error": error.to_string() }),
                ),
                PersistFailure::RenamedDurabilityUnconfirmed(error) => bad_with_details(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "goal_run_activation_goal_persist_durability_unconfirmed",
                    "The admitted GoalRun is visible but its crash durability remains unconfirmed.",
                    json!({ "error": error.to_string() }),
                ),
            };
        }
        existing
    } else {
        let create_body = json!({
            "goal": text(&goal_draft, "goal_text"),
            "owner_ref": principal_ref,
            "origin_surface": "ioi_goal_chat",
            "authority_scope_refs": ["scope:goal.run.create"],
            "constraint_refs": activation.get("requested_constraint_refs").cloned().unwrap_or_else(|| json!([])),
            "definition_resolution": definition_resolution_request
        });
        let binding = GoalRunActivationBinding {
            activation_ref: reference.clone(),
            source_ref: source_ref.clone(),
            source_owner_ref: principal_ref.clone(),
            project_ref: goal_draft
                .get("project_ref")
                .cloned()
                .unwrap_or(Value::Null),
            review_decision_ref: review_decision_ref.clone(),
            activation_receipt_ref: activation_receipt_ref.clone(),
            admitted_state_root_ref: admitted_state_root_ref.clone(),
            receipt_obligations: receipt_obligations.clone(),
            definition_resolution: definition_resolution.clone(),
        };
        let (status, Json(response)) = create_direct_goal_run(
            &st,
            &create_body,
            &goal_run_id,
            &goal_ref,
            text(&goal_draft, "goal_text"),
            &decision,
            Some(&binding),
            None,
        );
        if status != StatusCode::CREATED {
            return (status, Json(response));
        }
        response.get("goal_run").cloned().unwrap_or(Value::Null)
    };

    activation["admission_decision_ref"] =
        decision.get("decision_ref").cloned().unwrap_or(Value::Null);
    activation["admitted_goal_ref"] = json!(goal_ref);
    activation["activation_receipt_ref"] = json!(activation_receipt_ref);
    activation["status"] = json!("admitted");
    let admitted_activation_hash = sha256_canonical(&activation);
    control["admitted_activation_hash"] = json!(admitted_activation_hash);
    control["admitted_goal_ref"] = json!(goal_ref);
    control["status"] = json!("activation_commit_pending");
    control["admitted_at"] = json!(reviewed_at);
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        &id,
        &control,
    ) {
        return response;
    }
    // Commit the recovery control before exposing the admitted activation. If the second write
    // fails, the still-submitted activation continues to match `submitted_activation_hash` and a
    // same-body retry can complete. The opposite order could expose `status=admitted` without an
    // `admitted_activation_hash`, making the durable partial state neither replayable nor
    // self-healing.
    if let Err(response) = durable_write(&st.data_dir, GOAL_RUN_ACTIVATION_KIND, &id, &activation) {
        return response;
    }
    control["status"] = json!("admitted");
    if let Err(response) = durable_write(
        &st.data_dir,
        GOAL_RUN_ACTIVATION_CONTROL_KIND,
        &id,
        &control,
    ) {
        return response;
    }
    match activation_projection(&st, &id, false) {
        Ok(mut projection) => {
            projection["goal_run"] = goal_run;
            (StatusCode::CREATED, Json(projection))
        }
        Err(response) => response,
    }
}

pub(crate) async fn handle_goal_runs_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let mut runs = match strict_goal_run_census(&st.data_dir) {
        Ok(value) => value,
        Err(error) => return goal_run_registry_refusal(error),
    };
    if let Some(owner_ref) = reader {
        runs.retain(|run| run.get("owner_ref").and_then(Value::as_str) == Some(owner_ref.as_str()));
    }
    if let Some(session) = query.get("session") {
        runs.retain(|run| text(run, "target_session_ref") == session);
    }
    runs.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_runs": runs })),
    )
}

pub(crate) async fn handle_goal_run_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let response = match load_goal_run_for_http(&st.data_dir, &id) {
        Err(response) => return response,
        Ok(run) => match run {
            Some(run)
                if reader.as_deref().is_none_or(|owner_ref| {
                    run.get("owner_ref").and_then(Value::as_str) == Some(owner_ref)
                }) =>
            {
                (StatusCode::OK, Json(json!({ "ok": true, "goal_run": run })))
            }
            Some(_) => bad(
                StatusCode::FORBIDDEN,
                "goal_run_global_truth_owner_mismatch",
                "The authenticated principal does not own this GoalRun.",
            ),
            None if reader.is_some() => bad(
                StatusCode::FORBIDDEN,
                "goal_run_global_truth_owner_mismatch",
                "The authenticated principal does not own this GoalRun.",
            ),
            None => bad(
                StatusCode::NOT_FOUND,
                "goal_run_not_found",
                "Unknown GoalRun.",
            ),
        },
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    response
}

/// Enumerate one owner family through pinned, no-follow descriptors. An unreadable slot,
/// malformed JSON, duplicate identity, or non-JSON occupant is uncertainty, never absence.
/// Room result admission authorizes a durable cross-object mutation, so the permissive legacy
/// `read_record_dir` helper is not an admissible authority source here.
fn strict_json_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, SeamErr> {
    let directory = match nofollow_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err((
                "work_result_runtime_truth_unreadable".into(),
                format!("runtime-truth family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = nofollow_fs::enumerate_pinned(&directory).map_err(|error| {
        (
            "work_result_runtime_truth_unreadable".into(),
            format!("runtime-truth family '{family}' cannot be enumerated ({error})"),
        )
    })?;
    names.sort();
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        let Some(key) = name.strip_suffix(".json") else {
            return Err((
                "work_result_runtime_truth_unreadable".into(),
                format!("runtime-truth family '{family}' contains unexpected occupant '{name}'"),
            ));
        };
        let Some((_file, bytes)) =
            nofollow_fs::read_slot_strict(&directory, &name).map_err(|error| {
                (
                    "work_result_runtime_truth_unreadable".into(),
                    format!("runtime-truth slot '{family}/{name}' is unreadable ({error})"),
                )
            })?
        else {
            return Err((
                "work_result_runtime_truth_unreadable".into(),
                format!("runtime-truth slot '{family}/{name}' disappeared during resolution"),
            ));
        };
        let record = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
            (
                "work_result_runtime_truth_unreadable".into(),
                format!("runtime-truth slot '{family}/{name}' is malformed ({error})"),
            )
        })?;
        records.push((key.to_owned(), record));
    }
    Ok(records)
}

fn strict_unique_by_identity(
    data_dir: &str,
    family: &str,
    identity_field: &str,
    identity: &str,
) -> Result<(String, Value), SeamErr> {
    let mut matches = strict_json_family(data_dir, family)?
        .into_iter()
        .filter(|(_, record)| record.get(identity_field).and_then(Value::as_str) == Some(identity))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err((
            "work_result_runtime_truth_unresolved".into(),
            format!(
                "runtime-truth family '{family}' resolves {} records for {identity_field}='{identity}'; exactly one is required",
                matches.len()
            ),
        ));
    }
    Ok(matches.remove(0))
}

#[derive(Debug, Clone)]
struct ResultPayloadCustody {
    artifact_ref: String,
    payload_ref: String,
    content_hash: String,
    size_bytes: u64,
    admission_key: String,
    admission: Value,
    bundle: Value,
    bytes: Vec<u8>,
    implementation_result: Value,
    captured_output_file_facts: Value,
    captured_output_file_facts_hash: String,
    receipt_refs: Vec<String>,
}

#[derive(Debug, Clone)]
struct DurableInformationFlowLabel {
    key: String,
    record: Value,
}

fn jcs_hash(value: &Value, code: &str) -> Result<String, SeamErr> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        (
            code.to_owned(),
            format!("canonical JSON encoding failed ({error})"),
        )
    })?;
    Ok(sha256_hex(&bytes))
}

fn rooted_runtime_record(
    domain: &str,
    root_field: &str,
    mut record: Value,
) -> Result<Value, SeamErr> {
    let object = record.as_object_mut().ok_or_else(|| {
        (
            "work_result_runtime_proof_invalid".into(),
            format!("runtime proof for '{domain}' is not an object"),
        )
    })?;
    object.insert(root_field.to_owned(), Value::Null);
    let root = jcs_hash(
        &json!({ "domain": domain, "record": record }),
        "work_result_runtime_proof_hash_failed",
    )?;
    record[root_field] = json!(root);
    Ok(record)
}

fn verify_rooted_runtime_record(
    domain: &str,
    root_field: &str,
    record: &Value,
) -> Result<String, SeamErr> {
    let expected = record
        .get(root_field)
        .and_then(Value::as_str)
        .filter(|value| {
            value.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex.chars().all(|character| {
                        character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                    })
            })
        })
        .ok_or_else(|| {
            (
                "work_result_runtime_proof_unsealed".into(),
                format!("runtime proof for '{domain}' lacks its canonical '{root_field}'"),
            )
        })?
        .to_owned();
    let mut material = record.clone();
    let object = material.as_object_mut().ok_or_else(|| {
        (
            "work_result_runtime_proof_invalid".into(),
            format!("runtime proof for '{domain}' is not an object"),
        )
    })?;
    object.insert(root_field.to_owned(), Value::Null);
    let actual = jcs_hash(
        &json!({ "domain": domain, "record": material }),
        "work_result_runtime_proof_hash_failed",
    )?;
    if actual != expected {
        return Err((
            "work_result_runtime_proof_substituted".into(),
            format!("runtime proof for '{domain}' no longer reproduces '{root_field}'"),
        ));
    }
    Ok(expected)
}

fn room_dependency_key(family: &str, prefix: &str, record: &Value) -> Result<String, SeamErr> {
    let root = jcs_hash(
        &json!({
            "domain":"ioi.outcome-room-runtime-dependency-record-jcs-sha256.v1",
            "record_family":family,
            "record":record,
        }),
        "outcome_room_runtime_dependency_hash_failed",
    )?;
    Ok(format!(
        "{prefix}{}",
        root.strip_prefix("sha256:").unwrap_or_default()
    ))
}

fn canonical_payload_ref(content_hash: &str, size_bytes: u64) -> Result<String, SeamErr> {
    let hash = content_hash
        .strip_prefix("sha256:")
        .filter(|tail| {
            tail.len() == 64
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| {
            (
                "work_result_payload_hash_invalid".into(),
                "result bundle content hash is not canonical sha256".into(),
            )
        })?;
    Ok(format!(
        "payload://outcome-room/work-result-bundle/sha256/{hash}/bytes/{size_bytes}"
    ))
}

fn parse_payload_ref(reference: &str) -> Result<(&str, u64), SeamErr> {
    let tail = reference
        .strip_prefix("payload://outcome-room/work-result-bundle/sha256/")
        .ok_or_else(|| {
            (
                "work_result_payload_ref_invalid".into(),
                "the storage admission does not carry the M4 bounded result-bundle payload ref"
                    .into(),
            )
        })?;
    let (hash, size) = tail.split_once("/bytes/").ok_or_else(|| {
        (
            "work_result_payload_ref_invalid".into(),
            "the result-bundle payload ref omits its exact byte length".into(),
        )
    })?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || size.is_empty()
        || !size.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err((
            "work_result_payload_ref_invalid".into(),
            "the result-bundle payload ref contains a non-canonical hash or size".into(),
        ));
    }
    let size_bytes = size.parse::<u64>().map_err(|_| {
        (
            "work_result_payload_ref_invalid".into(),
            "the result-bundle payload byte length does not fit the portable integer domain".into(),
        )
    })?;
    if size_bytes == 0 || size_bytes > MAX_ATTEMPT_TOTAL_BYTES {
        return Err((
            "work_result_payload_size_refused".into(),
            format!(
                "result-bundle payload size {size_bytes} is outside the bounded 1..={MAX_ATTEMPT_TOTAL_BYTES} byte domain"
            ),
        ));
    }
    Ok((hash, size_bytes))
}

fn payload_storage_object_ref(hash: &str) -> String {
    format!("storage://hypervisor/outcome-room-result-payloads/sha256/{hash}")
}

fn payload_bytes_name(hash: &str) -> String {
    format!("{hash}.jcs.json")
}

/// Pin the data root and the payload family as one descriptor-bound custody boundary. Creation
/// is relative to the already-pinned data root; a symlink or non-directory occupant is refused.
/// Keeping both descriptors lets every caller prove that the family name still resolves to the
/// directory it used after its durability/read barrier.
fn pin_payload_custody_directory(
    data_dir: &str,
    create: bool,
) -> std::io::Result<(std::fs::File, std::fs::File)> {
    let root = nofollow_fs::open_dir_pinned(std::path::Path::new(data_dir))?;
    let directory = match nofollow_fs::open_dir_at(&root, ROOM_RESULT_PAYLOAD_BYTES_KIND) {
        Ok(directory) => directory,
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            nofollow_fs::mkdir_at(&root, ROOM_RESULT_PAYLOAD_BYTES_KIND)?;
            root.sync_all()?;
            nofollow_fs::open_dir_at(&root, ROOM_RESULT_PAYLOAD_BYTES_KIND)?
        }
        Err(error) => return Err(error),
    };
    Ok((root, directory))
}

/// The bounded, no-follow payload-slot reader. The returned file descriptor is the exact inode
/// whose bytes were read; callers use it for same-inode certification after fsync. A file that
/// grows after fstat is still bounded and refused rather than exhausting daemon memory.
fn read_payload_slot_bounded(
    directory: &std::fs::File,
    name: &str,
) -> std::io::Result<Option<(std::fs::File, Vec<u8>)>> {
    use std::io::Read;
    let file = match nofollow_fs::open_file_at(directory, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload slot '{name}' is occupied by a non-regular file"),
        ));
    }
    if metadata.len() > MAX_ATTEMPT_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "payload slot '{name}' exceeds the bounded custody limit ({})",
                metadata.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut reader = file.try_clone()?.take(MAX_ATTEMPT_TOTAL_BYTES + 1);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ATTEMPT_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload slot '{name}' grew beyond the bounded custody limit"),
        ));
    }
    Ok(Some((file, bytes)))
}

fn certify_payload_custody_directory(
    root: &std::fs::File,
    directory: &std::fs::File,
) -> std::io::Result<()> {
    let canonical = nofollow_fs::open_dir_at(root, ROOM_RESULT_PAYLOAD_BYTES_KIND)?;
    if !nofollow_fs::same_inode(&canonical, directory)? {
        return Err(std::io::Error::other(
            "payload custody directory was replaced during descriptor-bound use",
        ));
    }
    Ok(())
}

fn live_bundle_file_entries(
    workspace: &str,
    captured_file_facts: &Value,
) -> Result<Vec<Value>, SeamErr> {
    let facts = captured_file_facts.as_array().ok_or_else(|| {
        (
            "work_result_output_truth_unresolved".into(),
            "the invocation receipt output-file facts are not an array".into(),
        )
    })?;
    if facts.is_empty() || facts.len() > MAX_OUTPUT_FILES {
        return Err((
            "work_result_output_truth_unresolved".into(),
            format!("the result bundle requires 1..={MAX_OUTPUT_FILES} captured files"),
        ));
    }
    let workspace_root =
        nofollow_fs::open_dir_pinned(std::path::Path::new(workspace)).map_err(|error| {
            (
                "work_result_output_truth_unreadable".into(),
                format!("candidate workspace cannot be pinned ({error})"),
            )
        })?;
    let mut seen = BTreeSet::new();
    let mut prior_path: Option<String> = None;
    let mut total_bytes = 0u64;
    let mut entries = Vec::with_capacity(facts.len());
    for fact in facts {
        let relative_path = fact
            .get("relative_path")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "work_result_output_truth_unresolved".into(),
                    "a captured output-file fact omits its relative path".into(),
                )
            })?;
        let rel = contained_rel_path(relative_path).map_err(|message| {
            (
                "work_result_output_truth_unresolved".into(),
                format!("captured output path is not contained ({message})"),
            )
        })?;
        let normalized = rel.to_string_lossy().to_string();
        if normalized != relative_path
            || !seen.insert(normalized.clone())
            || prior_path
                .as_ref()
                .is_some_and(|prior| prior.as_str() >= normalized.as_str())
        {
            return Err((
                "work_result_output_truth_unresolved".into(),
                "captured output paths are not unique normalized strict lexical order".into(),
            ));
        }
        prior_path = Some(normalized.clone());
        let expected_hash = fact.get("sha256").and_then(Value::as_str).ok_or_else(|| {
            (
                "work_result_output_truth_unresolved".into(),
                "a captured output-file fact omits its sha256".into(),
            )
        })?;
        let expected_size = fact.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
            (
                "work_result_output_truth_unresolved".into(),
                "a captured output-file fact omits its byte length".into(),
            )
        })?;
        if expected_size > MAX_OUTPUT_FILE_BYTES
            || total_bytes.saturating_add(expected_size) > MAX_ATTEMPT_TOTAL_BYTES
        {
            return Err((
                "work_result_payload_size_refused".into(),
                "captured output bytes exceed the bounded result-payload custody limits".into(),
            ));
        }
        let bytes = nofollow_fs::read_contained(&workspace_root, &rel, expected_size).map_err(
            |error| match error {
                nofollow_fs::ReadRefusal::TooLarge(actual_size) => (
                    "work_result_output_truth_diverged".into(),
                    format!(
                        "changed-file '{normalized}' grew to {actual_size} bytes after the durable invocation receipt declared {expected_size} bytes"
                    ),
                ),
                other => (
                    "work_result_output_truth_unreadable".into(),
                    format!("changed-file '{normalized}' cannot be read exactly ({other:?})"),
                ),
            },
        )?;
        if bytes.len() as u64 != expected_size || sha256_hex(&bytes) != expected_hash {
            return Err((
                "work_result_output_truth_diverged".into(),
                format!(
                    "changed-file '{normalized}' bytes no longer match the durable invocation receipt"
                ),
            ));
        }
        total_bytes = total_bytes.saturating_add(expected_size);
        entries.push(json!({
            "relative_path":normalized,
            "sha256":expected_hash,
            "size_bytes":expected_size,
            "content_base64":base64::engine::general_purpose::STANDARD.encode(bytes),
        }));
    }
    Ok(entries)
}

fn validate_result_bundle(
    bytes: &[u8],
    artifact_ref: &str,
    expected_implementation_result: &Value,
    captured_output_file_facts: &Value,
    captured_output_file_facts_hash: &str,
) -> Result<Value, SeamErr> {
    let bundle: Value = serde_json::from_slice(bytes).map_err(|error| {
        (
            "work_result_payload_unreadable".into(),
            format!("the admitted result bundle is not JSON ({error})"),
        )
    })?;
    let object = bundle.as_object().ok_or_else(|| {
        (
            "work_result_payload_substituted".into(),
            "the admitted result bundle is not a closed object".into(),
        )
    })?;
    let expected_fields = [
        "schema_version",
        "artifact_ref",
        "implementation_result",
        "output_file_facts_hash",
        "files",
    ];
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
        || bundle.get("schema_version").and_then(Value::as_str)
            != Some("ioi.outcome-room-result-payload-bundle.v1")
        || bundle.get("artifact_ref").and_then(Value::as_str) != Some(artifact_ref)
        || bundle.get("implementation_result") != Some(expected_implementation_result)
        || bundle.get("output_file_facts_hash").and_then(Value::as_str)
            != Some(captured_output_file_facts_hash)
    {
        return Err((
            "work_result_payload_substituted".into(),
            "the admitted result bundle does not bind the exact artifact, ImplementationResult, and invocation-receipt facts".into(),
        ));
    }
    let facts = captured_output_file_facts.as_array().ok_or_else(|| {
        (
            "work_result_output_truth_unresolved".into(),
            "the durable invocation output facts are malformed".into(),
        )
    })?;
    let entries = bundle
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                "work_result_payload_substituted".into(),
                "the admitted result bundle omits its file bytes".into(),
            )
        })?;
    if entries.len() != facts.len() || entries.is_empty() || entries.len() > MAX_OUTPUT_FILES {
        return Err((
            "work_result_payload_substituted".into(),
            "the admitted result bundle file census differs from the invocation receipt".into(),
        ));
    }
    let mut total_bytes = 0u64;
    for (entry, fact) in entries.iter().zip(facts) {
        let Some(entry_object) = entry.as_object() else {
            return Err((
                "work_result_payload_substituted".into(),
                "a result bundle file entry is not an object".into(),
            ));
        };
        if entry_object.len() != 4
            || ["relative_path", "sha256", "size_bytes", "content_base64"]
                .iter()
                .any(|field| !entry_object.contains_key(*field))
            || entry.get("relative_path") != fact.get("relative_path")
            || entry.get("sha256") != fact.get("sha256")
            || entry.get("size_bytes") != fact.get("bytes")
        {
            return Err((
                "work_result_payload_substituted".into(),
                "a result bundle file identity, hash, or size differs from the invocation receipt"
                    .into(),
            ));
        }
        let relative_path = entry
            .get("relative_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if contained_rel_path(relative_path)
            .map(|path| path.to_string_lossy() != relative_path)
            .unwrap_or(true)
        {
            return Err((
                "work_result_payload_substituted".into(),
                "a result bundle path is not normalized and contained".into(),
            ));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(
                entry
                    .get("content_base64")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
            .map_err(|_| {
                (
                    "work_result_payload_substituted".into(),
                    "a result bundle file is not canonical base64".into(),
                )
            })?;
        let size = entry
            .get("size_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let expected_hash = entry
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if size > MAX_OUTPUT_FILE_BYTES
            || decoded.len() as u64 != size
            || sha256_hex(&decoded) != expected_hash
            || base64::engine::general_purpose::STANDARD.encode(&decoded)
                != entry
                    .get("content_base64")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
        {
            return Err((
                "work_result_payload_substituted".into(),
                "a result bundle file fails exact byte/hash/size reconstruction".into(),
            ));
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_ATTEMPT_TOTAL_BYTES {
            return Err((
                "work_result_payload_size_refused".into(),
                "the result bundle expands beyond the bounded attempt byte limit".into(),
            ));
        }
    }
    let canonical = serde_jcs::to_vec(&bundle).map_err(|error| {
        (
            "work_result_payload_unreadable".into(),
            format!("the admitted result bundle cannot be canonically encoded ({error})"),
        )
    })?;
    if canonical != bytes {
        return Err((
            "work_result_payload_substituted".into(),
            "the admitted result bundle bytes are not their canonical JCS representation".into(),
        ));
    }
    Ok(bundle)
}

fn storage_write_admission(
    artifact_ref: &str,
    payload_ref: &str,
    content_hash: &str,
    receipt_refs: &[String],
) -> Result<(String, Value), SeamErr> {
    let (hash, _) = parse_payload_ref(payload_ref)?;
    let proposal = StorageBackendWriteProposal {
        schema_version: "ioi.storage_backend_write_admission.v1".to_owned(),
        storage_backend_ref: "storage://hypervisor/local-disk/outcome-room-result-payloads/v1"
            .to_owned(),
        object_ref: payload_storage_object_ref(hash),
        content_hash: content_hash.to_owned(),
        artifact_refs: vec![artifact_ref.to_owned()],
        payload_refs: vec![payload_ref.to_owned()],
        receipt_refs: receipt_refs.to_vec(),
    };
    let record = RuntimeKernelService::new()
        .admit_storage_backend_write(&proposal)
        .map_err(|error| {
            (
                "work_result_payload_write_admission_refused".into(),
                format!("the storage-write admission core refused result custody ({error:?})"),
            )
        })?;
    let record = serde_json::to_value(record).map_err(|error| {
        (
            "work_result_payload_write_admission_invalid".into(),
            format!("the storage-write admission record did not serialize ({error})"),
        )
    })?;
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        STORAGE_BACKEND_WRITE_ADMISSION_CONTRACT,
        &record,
    )
    .map_err(|error| {
        (
            "work_result_payload_write_admission_invalid".into(),
            format!("the registered storage-write contract rejected its producer ({error})"),
        )
    })?;
    let key = room_dependency_key(
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
        "orpwa_",
        &record,
    )?;
    Ok((key, record))
}

fn payload_write_admission_evidence_ref(admission: &Value) -> Result<String, SeamErr> {
    let admission_hash = admission
        .get("admission_hash")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|value| {
            value.len() == 64
                && value.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
        .ok_or_else(|| {
            (
                "work_result_payload_write_admission_invalid".into(),
                "the storage-write admission lacks its canonical admission hash".into(),
            )
        })?;
    Ok(format!(
        "evidence://storage-backend-write-admission/{admission_hash}"
    ))
}

fn build_live_payload_custody(
    workspace: &str,
    artifact_ref: &str,
    implementation_result: &Value,
    captured_output_file_facts: &Value,
    captured_output_file_facts_hash: &str,
    receipt_refs: &[String],
) -> Result<ResultPayloadCustody, SeamErr> {
    let entries = live_bundle_file_entries(workspace, captured_output_file_facts)?;
    let bundle = json!({
        "schema_version":"ioi.outcome-room-result-payload-bundle.v1",
        "artifact_ref":artifact_ref,
        "implementation_result":implementation_result,
        "output_file_facts_hash":captured_output_file_facts_hash,
        "files":entries,
    });
    let bytes = serde_jcs::to_vec(&bundle).map_err(|error| {
        (
            "work_result_payload_unreadable".into(),
            format!("the result bundle could not be canonically encoded ({error})"),
        )
    })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ATTEMPT_TOTAL_BYTES {
        return Err((
            "work_result_payload_size_refused".into(),
            "the canonical result bundle is outside the bounded custody byte limit".into(),
        ));
    }
    let content_hash = sha256_hex(&bytes);
    let size_bytes = bytes.len() as u64;
    let payload_ref = canonical_payload_ref(&content_hash, size_bytes)?;
    let (admission_key, admission) =
        storage_write_admission(artifact_ref, &payload_ref, &content_hash, receipt_refs)?;
    Ok(ResultPayloadCustody {
        artifact_ref: artifact_ref.to_owned(),
        payload_ref,
        content_hash,
        size_bytes,
        admission_key,
        admission,
        bundle,
        bytes,
        implementation_result: implementation_result.clone(),
        captured_output_file_facts: captured_output_file_facts.clone(),
        captured_output_file_facts_hash: captured_output_file_facts_hash.to_owned(),
        receipt_refs: receipt_refs.to_vec(),
    })
}

fn validate_storage_write_admission(
    artifact_ref: &str,
    admission: &Value,
    expected_receipt_refs: &[String],
) -> Result<(String, String, u64), SeamErr> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        STORAGE_BACKEND_WRITE_ADMISSION_CONTRACT,
        admission,
    )
    .map_err(|error| {
        (
            "work_result_payload_write_admission_invalid".into(),
            format!("stored payload admission violates its registered contract ({error})"),
        )
    })?;
    let artifacts = admission
        .get("artifact_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                "work_result_payload_write_admission_invalid".into(),
                "stored payload admission omits artifact refs".into(),
            )
        })?;
    let payloads = admission
        .get("payload_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                "work_result_payload_write_admission_invalid".into(),
                "stored payload admission omits payload refs".into(),
            )
        })?;
    if artifacts.as_slice() != [json!(artifact_ref)] || payloads.len() != 1 {
        return Err((
            "work_result_payload_mapping_substituted".into(),
            "the storage admission does not bind exactly one requested artifact ref to one opaque payload ref".into(),
        ));
    }
    let payload_ref = payloads[0].as_str().unwrap_or_default();
    let (hash, size_bytes) = parse_payload_ref(payload_ref)?;
    let content_hash = admission
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if content_hash != format!("sha256:{hash}")
        || admission.get("storage_backend_ref").and_then(Value::as_str)
            != Some("storage://hypervisor/local-disk/outcome-room-result-payloads/v1")
        || admission.get("object_ref").and_then(Value::as_str)
            != Some(payload_storage_object_ref(hash).as_str())
        || admission.get("receipt_refs").and_then(Value::as_array)
            != Some(
                &expected_receipt_refs
                    .iter()
                    .map(|reference| json!(reference))
                    .collect::<Vec<_>>(),
            )
    {
        return Err((
            "work_result_payload_write_admission_substituted".into(),
            "the storage admission changed the exact hash, size-bearing payload ref, storage object, or receipt closure".into(),
        ));
    }
    let (_, expected) = storage_write_admission(
        artifact_ref,
        payload_ref,
        content_hash,
        expected_receipt_refs,
    )?;
    if expected != *admission {
        return Err((
            "work_result_payload_write_admission_substituted".into(),
            "the persisted storage admission does not reproduce through the Rust admission core"
                .into(),
        ));
    }
    Ok((payload_ref.to_owned(), content_hash.to_owned(), size_bytes))
}

fn persist_immutable_payload_bytes(
    data_dir: &str,
    payload_ref: &str,
    bytes: &[u8],
) -> Result<(), SeamErr> {
    use std::io::Write;
    let (hash, size_bytes) = parse_payload_ref(payload_ref)?;
    if bytes.len() as u64 != size_bytes || sha256_hex(bytes) != format!("sha256:{hash}") {
        return Err((
            "work_result_payload_bytes_substituted".into(),
            "the bytes proposed for custody do not match the admitted payload hash and size".into(),
        ));
    }
    let (root, directory) = pin_payload_custody_directory(data_dir, true).map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("result payload custody directory cannot be pinned ({error})"),
        )
    })?;
    let target = payload_bytes_name(hash);

    let certify_existing = |occupant: std::fs::File, existing: Vec<u8>| -> Result<(), SeamErr> {
        if existing != bytes {
            return Err((
                "work_result_payload_bytes_substituted".into(),
                "the immutable result payload key already contains different bytes".into(),
            ));
        }
        occupant.sync_all().map_err(|error| {
            (
                "work_result_payload_persist_failed".into(),
                format!("existing result payload durability is unconfirmed ({error})"),
            )
        })?;
        directory.sync_all().map_err(|error| {
            (
                "work_result_payload_persist_failed".into(),
                format!("result payload directory durability is unconfirmed ({error})"),
            )
        })?;
        root.sync_all().map_err(|error| {
            (
                "work_result_payload_persist_failed".into(),
                format!("result payload family-entry durability is unconfirmed ({error})"),
            )
        })?;
        certify_payload_custody_directory(&root, &directory).map_err(|error| {
            (
                "work_result_payload_bytes_substituted".into(),
                format!("result payload custody directory changed during commit ({error})"),
            )
        })?;
        let (reopened, on_disk) = read_payload_slot_bounded(&directory, &target)
            .map_err(|error| {
                (
                    "work_result_payload_bytes_substituted".into(),
                    format!("result payload cannot be re-certified ({error})"),
                )
            })?
            .ok_or_else(|| {
                (
                    "work_result_payload_bytes_substituted".into(),
                    "result payload vanished during post-commit certification".into(),
                )
            })?;
        if !nofollow_fs::same_inode(&occupant, &reopened).unwrap_or(false) || on_disk != bytes {
            return Err((
                "work_result_payload_bytes_substituted".into(),
                "result payload name no longer resolves to the certified inode and bytes".into(),
            ));
        }
        certify_payload_custody_directory(&root, &directory).map_err(|error| {
            (
                "work_result_payload_bytes_substituted".into(),
                format!(
                    "result payload custody directory changed during final certification ({error})"
                ),
            )
        })?;
        Ok(())
    };

    match read_payload_slot_bounded(&directory, &target) {
        Ok(Some((occupant, existing))) => return certify_existing(occupant, existing),
        Ok(None) => {}
        Err(error) => {
            return Err((
                "work_result_payload_bytes_substituted".into(),
                format!("result payload slot cannot be safely inspected ({error})"),
            ))
        }
    }

    let mut staged = nofollow_fs::open_tmpfile_at(&directory).map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("anonymous result payload staging failed ({error})"),
        )
    })?;
    staged.write_all(bytes).map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("anonymous result payload write failed ({error})"),
        )
    })?;
    staged.sync_all().map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("anonymous result payload durability is unconfirmed ({error})"),
        )
    })?;
    if let Err(error) = nofollow_fs::link_tmpfile_at(&staged, &directory, &target) {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return match read_payload_slot_bounded(&directory, &target) {
                Ok(Some((occupant, existing))) => certify_existing(occupant, existing),
                Ok(None) => Err((
                    "work_result_payload_persist_failed".into(),
                    "result payload slot raced from occupied to absent; nothing was certified"
                        .into(),
                )),
                Err(read_error) => Err((
                    "work_result_payload_bytes_substituted".into(),
                    format!("racing result payload occupant cannot be certified ({read_error})"),
                )),
            };
        }
        return Err((
            "work_result_payload_persist_failed".into(),
            format!("immutable result payload link commit failed ({error})"),
        ));
    }
    directory.sync_all().map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("result payload directory durability is unconfirmed ({error})"),
        )
    })?;
    root.sync_all().map_err(|error| {
        (
            "work_result_payload_persist_failed".into(),
            format!("result payload family-entry durability is unconfirmed ({error})"),
        )
    })?;
    certify_payload_custody_directory(&root, &directory).map_err(|error| {
        (
            "work_result_payload_bytes_substituted".into(),
            format!("result payload custody directory changed during commit ({error})"),
        )
    })?;
    let (reopened, on_disk) = read_payload_slot_bounded(&directory, &target)
        .map_err(|error| {
            (
                "work_result_payload_bytes_substituted".into(),
                format!("new result payload cannot be re-certified ({error})"),
            )
        })?
        .ok_or_else(|| {
            (
                "work_result_payload_bytes_substituted".into(),
                "new result payload vanished during post-commit certification".into(),
            )
        })?;
    if !nofollow_fs::same_inode(&staged, &reopened).unwrap_or(false) || on_disk != bytes {
        return Err((
            "work_result_payload_bytes_substituted".into(),
            "new result payload name does not resolve to the committed inode and bytes".into(),
        ));
    }
    certify_payload_custody_directory(&root, &directory).map_err(|error| {
        (
            "work_result_payload_bytes_substituted".into(),
            format!(
                "result payload custody directory changed during final certification ({error})"
            ),
        )
    })?;
    Ok(())
}

fn resolve_payload_custody(
    data_dir: &str,
    artifact_ref: &str,
    expected_implementation_result: &Value,
    captured_output_file_facts: &Value,
    captured_output_file_facts_hash: &str,
    expected_receipt_refs: &[String],
) -> Result<ResultPayloadCustody, SeamErr> {
    let admissions = super::substrate_store::read_required_all(
        data_dir,
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
    )
    .map_err(|error| {
        (
            "work_result_payload_write_admission_unreadable".into(),
            format!("payload write admissions cannot be projected ({error})"),
        )
    })?;
    let mut matches = admissions
        .into_iter()
        .filter(|record| {
            record
                .get("artifact_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(artifact_ref))
                })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err((
            "work_result_payload_write_admission_unresolved".into(),
            format!(
                "artifact '{artifact_ref}' resolves {} storage-write admissions; exactly one is required",
                matches.len()
            ),
        ));
    }
    let admission = matches.remove(0);
    let admission_key = room_dependency_key(
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
        "orpwa_",
        &admission,
    )?;
    super::substrate_store::verify_required_exact(
        data_dir,
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
        &admission_key,
        &admission,
    )
    .map_err(|error| {
        (
            "work_result_payload_write_admission_unresolved".into(),
            format!("payload write admission is not exact durable Agentgres truth ({error})"),
        )
    })?;
    let (payload_ref, content_hash, size_bytes) =
        validate_storage_write_admission(artifact_ref, &admission, expected_receipt_refs)?;
    let (hash, _) = parse_payload_ref(&payload_ref)?;
    let (root, directory) = pin_payload_custody_directory(data_dir, false).map_err(|error| {
        (
            "work_result_payload_unavailable".into(),
            format!("admitted result payload custody directory is unavailable ({error})"),
        )
    })?;
    let target = payload_bytes_name(hash);
    let (_payload, bytes) = read_payload_slot_bounded(&directory, &target)
        .map_err(|error| {
            (
                "work_result_payload_unavailable".into(),
                format!("admitted result payload bytes cannot be safely read ({error})"),
            )
        })?
        .ok_or_else(|| {
            (
                "work_result_payload_unavailable".into(),
                "admitted result payload bytes are absent".into(),
            )
        })?;
    certify_payload_custody_directory(&root, &directory).map_err(|error| {
        (
            "work_result_payload_unavailable".into(),
            format!("result payload custody directory changed during read ({error})"),
        )
    })?;
    if bytes.len() as u64 != size_bytes || sha256_hex(&bytes) != content_hash {
        return Err((
            "work_result_payload_bytes_substituted".into(),
            "admitted result payload file hash or size differs from its storage admission".into(),
        ));
    }
    let bundle = validate_result_bundle(
        &bytes,
        artifact_ref,
        expected_implementation_result,
        captured_output_file_facts,
        captured_output_file_facts_hash,
    )?;
    Ok(ResultPayloadCustody {
        artifact_ref: artifact_ref.to_owned(),
        payload_ref,
        content_hash,
        size_bytes,
        admission_key,
        admission,
        bundle,
        bytes,
        implementation_result: expected_implementation_result.clone(),
        captured_output_file_facts: captured_output_file_facts.clone(),
        captured_output_file_facts_hash: captured_output_file_facts_hash.to_owned(),
        receipt_refs: expected_receipt_refs.to_vec(),
    })
}

fn information_flow_label_identity_material(record: &Value) -> Result<Value, SeamErr> {
    let mut material = record.clone();
    let label_ref = material
        .get("label_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    material["label_ref"] = Value::Null;
    let closure = material
        .get("derivation_closure_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|value| value.as_str() != Some(label_ref.as_str()))
        .collect::<Vec<_>>();
    material["derivation_closure_refs"] = Value::Array(closure);
    Ok(json!({
        "domain":"ioi.outcome-room-information-flow-label-ref-jcs-sha256.v1",
        "label":material,
    }))
}

fn build_result_information_flow_label(
    room: &Value,
    content_hash: &str,
) -> Result<DurableInformationFlowLabel, SeamErr> {
    let profile_ref = room
        .get("privacy_policy_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("policy://"))
        .ok_or_else(|| {
            (
                "work_result_information_flow_profile_unresolved".into(),
                "OutcomeRoom privacy policy does not resolve a canonical information-flow profile"
                    .into(),
            )
        })?;
    let mut record = json!({
        "schema_version":"ioi.foundations.information-flow-label.v1",
        "label_ref":Value::Null,
        "profile_ref":profile_ref,
        "content_hash":content_hash,
        "origin":"tool_output",
        "integrity":"untrusted",
        "confidentiality":"private",
        "instruction_authority":"none",
        "egress_policy":{
            "mode":"deny",
            "allowed_destination_patterns":[],
            "allowed_data_classes":[],
        },
        "purpose":"outcome-room-work-result",
        "retention":{
            "max_seconds":9007199254740991u64,
            "disposition":"retain_under_policy",
        },
        "derivation_kind":"direct",
        "derivation_parent_refs":[],
        "derivation_closure_refs":[],
    });
    let identity = jcs_hash(
        &information_flow_label_identity_material(&record)?,
        "work_result_information_flow_label_hash_failed",
    )?;
    let label_ref = format!(
        "ifc-label://outcome-room/work-result/{}",
        identity.strip_prefix("sha256:").unwrap_or_default()
    );
    record["label_ref"] = json!(label_ref);
    record["derivation_closure_refs"] = json!([label_ref]);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        INFORMATION_FLOW_LABEL_CONTRACT,
        &record,
    )
    .map_err(|error| {
        (
            "work_result_information_flow_label_invalid".into(),
            format!("the registered InformationFlowLabel contract rejected its producer ({error})"),
        )
    })?;
    let key = room_dependency_key(ROOM_INFORMATION_FLOW_LABEL_DOMAIN, "orifl_", &record)?;
    Ok(DurableInformationFlowLabel { key, record })
}

fn resolve_information_flow_label(
    data_dir: &str,
    label_ref: &str,
    resolving: &mut BTreeSet<String>,
) -> Result<Value, SeamErr> {
    if !resolving.insert(label_ref.to_owned()) {
        return Err((
            "outcome_room_information_flow_label_cycle".into(),
            format!("information-flow label closure contains a cycle at '{label_ref}'"),
        ));
    }
    let records =
        super::substrate_store::read_required_all(data_dir, ROOM_INFORMATION_FLOW_LABEL_DOMAIN)
            .map_err(|error| {
                (
                    "outcome_room_information_flow_label_unreadable".into(),
                    format!("durable information-flow labels cannot be projected ({error})"),
                )
            })?;
    let mut matches = records
        .into_iter()
        .filter(|record| record.get("label_ref").and_then(Value::as_str) == Some(label_ref))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        resolving.remove(label_ref);
        return Err((
            "outcome_room_information_flow_label_unresolved".into(),
            format!(
                "label '{label_ref}' resolves {} durable records; exactly one is required",
                matches.len()
            ),
        ));
    }
    let record = matches.remove(0);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        INFORMATION_FLOW_LABEL_CONTRACT,
        &record,
    )
    .map_err(|error| {
        (
            "outcome_room_information_flow_label_invalid".into(),
            format!("label '{label_ref}' violates its registered contract ({error})"),
        )
    })?;
    let key = room_dependency_key(ROOM_INFORMATION_FLOW_LABEL_DOMAIN, "orifl_", &record)?;
    super::substrate_store::verify_required_exact(
        data_dir,
        ROOM_INFORMATION_FLOW_LABEL_DOMAIN,
        &key,
        &record,
    )
    .map_err(|error| {
        (
            "outcome_room_information_flow_label_unresolved".into(),
            format!("label '{label_ref}' is not exact durable Agentgres truth ({error})"),
        )
    })?;
    let expected_identity = jcs_hash(
        &information_flow_label_identity_material(&record)?,
        "outcome_room_information_flow_label_hash_failed",
    )?;
    let expected_ref = format!(
        "ifc-label://outcome-room/work-result/{}",
        expected_identity
            .strip_prefix("sha256:")
            .unwrap_or_default()
    );
    if expected_ref != label_ref
        || [
            "origin",
            "integrity",
            "confidentiality",
            "instruction_authority",
        ]
        .iter()
        .any(|field| record.get(*field).and_then(Value::as_str) == Some("unknown"))
    {
        resolving.remove(label_ref);
        return Err((
            "outcome_room_information_flow_label_substituted".into(),
            "information-flow label identity does not recompute or carries an unknown trust axis"
                .into(),
        ));
    }
    let parents = record
        .get("derivation_parent_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if parents.len() > 64 {
        resolving.remove(label_ref);
        return Err((
            "outcome_room_information_flow_label_closure_refused".into(),
            "information-flow label has more than 64 direct parents".into(),
        ));
    }
    let mut expected_closure = BTreeSet::from([label_ref.to_owned()]);
    for parent in parents {
        let parent_ref = parent.as_str().ok_or_else(|| {
            (
                "outcome_room_information_flow_label_closure_refused".into(),
                "information-flow label contains a non-string parent ref".into(),
            )
        })?;
        let parent_record = resolve_information_flow_label(data_dir, parent_ref, resolving)?;
        expected_closure.insert(parent_ref.to_owned());
        for ancestor in parent_record
            .get("derivation_closure_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let ancestor = ancestor.as_str().ok_or_else(|| {
                (
                    "outcome_room_information_flow_label_closure_refused".into(),
                    "parent information-flow closure contains a non-string ref".into(),
                )
            })?;
            expected_closure.insert(ancestor.to_owned());
        }
    }
    let actual_closure = record
        .get("derivation_closure_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let expected_closure_values = expected_closure
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    resolving.remove(label_ref);
    if actual_closure != expected_closure_values {
        return Err((
            "outcome_room_information_flow_label_closure_substituted".into(),
            "information-flow label does not carry the exact sorted transitive parent closure"
                .into(),
        ));
    }
    Ok(record)
}

fn resolve_information_flow_label_set(data_dir: &str, refs: &Value) -> Result<Vec<Value>, SeamErr> {
    let refs = refs.as_array().ok_or_else(|| {
        (
            "outcome_room_information_flow_labels_unresolved".into(),
            "room owner record does not carry an information-flow label array".into(),
        )
    })?;
    if refs.is_empty() || refs.len() > 64 {
        return Err((
            "outcome_room_information_flow_labels_unresolved".into(),
            "room owner record requires 1..=64 information-flow labels".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    let mut resolved = Vec::with_capacity(refs.len());
    for reference in refs {
        let reference = reference.as_str().ok_or_else(|| {
            (
                "outcome_room_information_flow_labels_unresolved".into(),
                "room owner record contains a non-string information-flow label ref".into(),
            )
        })?;
        if !unique.insert(reference.to_owned()) {
            return Err((
                "outcome_room_information_flow_labels_unresolved".into(),
                "room owner record contains a duplicate information-flow label ref".into(),
            ));
        }
        resolved.push(resolve_information_flow_label(
            data_dir,
            reference,
            &mut BTreeSet::new(),
        )?);
    }
    Ok(resolved)
}

#[derive(Debug)]
struct DerivedInvocationWorkResult {
    invocation_key: String,
    prior_invocation: Value,
    successor_invocation: Value,
    work_result: Value,
    payload_custody: ResultPayloadCustody,
    information_flow_label: DurableInformationFlowLabel,
    component_resolution_snapshot_key: String,
    component_resolution_snapshot: Value,
    conductor_verification_evidence_key: String,
    conductor_verification_evidence: Value,
    authority_admission_receipt_key: String,
    authority_admission_receipt: Value,
}

fn room_result_request_invocation_ref(body: &Value) -> Result<String, HttpRefusal> {
    let Some(object) = body.as_object() else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "work_result_invalid",
            "A room WorkResult request must be a closed object.",
        ));
    };
    for field in object.keys() {
        if field != "invocation_or_run_ref" {
            return Err(bad_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "work_result_runtime_field_plane_owned",
                "Room WorkResult identity, payload, status, outcome, evidence, producer, and lineage are derived from durable invocation truth; callers may name only the invocation.",
                json!({ "field": field }),
            ));
        }
    }
    let invocation_ref = object
        .get("invocation_or_run_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !invocation_ref.starts_with("harness-invocation://")
        || invocation_ref.len() > 500
        || invocation_ref.chars().any(char::is_whitespace)
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "work_result_invocation_ref_required",
            "A room WorkResult request must name one canonical harness-invocation:// ref.",
        ));
    }
    Ok(invocation_ref.to_owned())
}

fn verify_wallet_consumption_receipt(
    authority_admission: &Value,
) -> Result<(ApprovalGrantConsumptionReceipt, String), SeamErr> {
    let receipt: ApprovalGrantConsumptionReceipt = serde_json::from_value(
        authority_admission
            .get("wallet_consumption_receipt")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| {
        (
            "work_result_invocation_authority_unresolved".into(),
            format!("the retained wallet consumption receipt is malformed ({error})"),
        )
    })?;
    if receipt.schema_version != 1 || receipt.receipt_hash == [0u8; 32] {
        return Err((
            "work_result_invocation_authority_unresolved".into(),
            "the retained wallet consumption receipt has an unsupported version or empty hash"
                .into(),
        ));
    }
    let mut material = serde_json::to_value(&receipt).map_err(|error| {
        (
            "work_result_invocation_authority_unresolved".into(),
            format!("the wallet consumption receipt cannot be serialized ({error})"),
        )
    })?;
    material["receipt_hash"] = json!(vec![0u8; 32]);
    let encoded = serde_jcs::to_vec(&material).map_err(|error| {
        (
            "work_result_invocation_authority_unresolved".into(),
            format!("the wallet consumption receipt cannot be canonicalized ({error})"),
        )
    })?;
    let actual = Sha256::digest(encoded);
    if actual[..] != receipt.receipt_hash[..] {
        return Err((
            "work_result_invocation_authority_substituted".into(),
            "the retained wallet consumption receipt hash does not match its exact content".into(),
        ));
    }
    let consumption_id = authority_admission
        .get("consumption_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if consumption_id != hex::encode(receipt.consumption_id)
        || authority_admission
            .pointer("/commitment/required_scope")
            .and_then(Value::as_str)
            != Some(receipt.principal_authority.required_scope.as_str())
    {
        return Err((
            "work_result_invocation_authority_substituted".into(),
            "the authority intent, wallet consumption identity, and principal scope are detached"
                .into(),
        ));
    }
    Ok((
        receipt.clone(),
        format!("sha256:{}", hex::encode(receipt.receipt_hash)),
    ))
}

fn build_authority_admission_receipt(
    authority_admission_ref: &str,
    authority_admission: &Value,
    invocation_receipt: &Value,
    invocation_ref: &str,
    goal_ref: &str,
) -> Result<(String, String, Value), SeamErr> {
    let (_wallet_receipt, wallet_receipt_hash) =
        verify_wallet_consumption_receipt(authority_admission)?;
    let authority_root = jcs_hash(
        &json!({
            "domain":"ioi.goal-run-invocation-authority-admission-jcs-sha256.v1",
            "authority_admission_ref":authority_admission_ref,
            "authority_admission":authority_admission,
        }),
        "work_result_invocation_authority_hash_failed",
    )?;
    let authority_tail = authority_root.trim_start_matches("sha256:");
    let receipt_ref = format!("receipt://goal-run-invocation-authority/{authority_tail}");
    let required_scope = authority_admission
        .pointer("/commitment/required_scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let timestamp = invocation_receipt
        .get("started_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let receipt = json!({
        "receipt_id":receipt_ref,
        "receipt_type":"goal_run_invocation_authority_admission",
        "receipt_profile_ref":"schema://ioi/foundations/receipt-envelope/v1",
        "attested_boundary_fact_refs":[goal_ref,invocation_ref,required_scope],
        "claim_scope_ref":Value::Null,
        "run_id":Value::Null,
        "task_id":Value::Null,
        "actor_id":"runtime://hypervisor-daemon",
        "input_hash":authority_root,
        "output_hash":wallet_receipt_hash,
        "authority_grant_id":Value::Null,
        "primitive_capabilities":[],
        "authority_scopes":[required_scope],
        "artifact_refs":[],
        "evidence_bundle_refs":[],
        "verification_ref":Value::Null,
        "acceptance_ref":Value::Null,
        "adjudication_ref":Value::Null,
        "settlement_ref":Value::Null,
        "timestamp":timestamp,
        "signature":Value::Null,
        "public_commitment_ref":format!("commitment://goal-run-invocation-authority/{authority_tail}"),
    });
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        RECEIPT_ENVELOPE_CONTRACT,
        &receipt,
    )
    .map_err(|error| {
        (
            "work_result_invocation_authority_receipt_invalid".into(),
            format!("the derived authority receipt violates ReceiptEnvelope ({error})"),
        )
    })?;
    let key = receipt_file_key(&receipt_ref);
    Ok((receipt_ref, key, receipt))
}

fn component_resolution_snapshot(
    goal_run_id: &str,
    invocation_ref: &str,
    invocation_receipt: &Value,
) -> Result<(String, String, Value), SeamErr> {
    let receipt_ref = invocation_receipt
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let receipt_root = verify_rooted_runtime_record(
        "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
        "receipt_root",
        invocation_receipt,
    )?;
    let material = json!({
        "schema_version":"ioi.goal-run-invocation-component-resolution-snapshot.v1",
        "source_invocation_ref":invocation_ref,
        "source_invocation_receipt_ref":receipt_ref,
        "source_invocation_receipt_root":receipt_root,
        "session_ref":invocation_receipt.get("session_ref"),
        "harness_ref":invocation_receipt.get("harness_profile_ref"),
        "harness_kind":invocation_receipt.get("harness"),
        "model_route_ref":invocation_receipt.get("model_route_ref"),
        "model_route_binding_id":invocation_receipt.get("model_route_binding_id"),
        "model_route_binding_receipt_ref":invocation_receipt.get("model_route_binding_receipt_ref"),
        "model_id":invocation_receipt.get("model_id"),
        "model_route_base_url":invocation_receipt.get("model_route_base_url"),
        "model_route_execution_endpoint":invocation_receipt.get("model_route_execution_endpoint"),
        "command_contract_ref":invocation_receipt.get("command_contract_ref"),
    });
    let snapshot_hash = jcs_hash(
        &json!({
            "domain":"ioi.goal-run-invocation-component-resolution-snapshot-jcs-sha256.v1",
            "snapshot":material,
        }),
        "work_result_component_resolution_hash_failed",
    )?;
    let snapshot_ref = format!(
        "artifact://goal-run/{}/invocation/{}/resolved-components/{}",
        safe(goal_run_id),
        hex::encode(Sha256::digest(invocation_ref.as_bytes())),
        snapshot_hash.trim_start_matches("sha256:")
    );
    let snapshot = json!({
        "schema_version":"ioi.goal-run-invocation-component-resolution-snapshot.v1",
        "snapshot_ref":snapshot_ref,
        "snapshot_hash":snapshot_hash,
        "source_invocation_ref":invocation_ref,
        "source_invocation_receipt_ref":receipt_ref,
        "source_invocation_receipt_root":receipt_root,
        "session_ref":invocation_receipt.get("session_ref"),
        "harness_ref":invocation_receipt.get("harness_profile_ref"),
        "harness_kind":invocation_receipt.get("harness"),
        "model_route_ref":invocation_receipt.get("model_route_ref"),
        "model_route_binding_id":invocation_receipt.get("model_route_binding_id"),
        "model_route_binding_receipt_ref":invocation_receipt.get("model_route_binding_receipt_ref"),
        "model_id":invocation_receipt.get("model_id"),
        "model_route_base_url":invocation_receipt.get("model_route_base_url"),
        "model_route_execution_endpoint":invocation_receipt.get("model_route_execution_endpoint"),
        "command_contract_ref":invocation_receipt.get("command_contract_ref"),
    });
    let key = room_dependency_key(ROOM_COMPONENT_RESOLUTION_DOMAIN, "orcps_", &snapshot)?;
    Ok((snapshot_ref, key, snapshot))
}

fn verify_component_resolution_snapshot(snapshot: &Value) -> Result<(), SeamErr> {
    let mut material = snapshot.clone();
    let object = material.as_object_mut().ok_or_else(|| {
        (
            "work_result_component_resolution_snapshot_invalid".into(),
            "component-resolution snapshot is not an object".into(),
        )
    })?;
    let snapshot_ref = object
        .remove("snapshot_ref")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let expected_hash = object
        .remove("snapshot_hash")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let actual_hash = jcs_hash(
        &json!({
            "domain":"ioi.goal-run-invocation-component-resolution-snapshot-jcs-sha256.v1",
            "snapshot":material,
        }),
        "work_result_component_resolution_hash_failed",
    )?;
    if actual_hash != expected_hash
        || !snapshot_ref.ends_with(expected_hash.trim_start_matches("sha256:"))
    {
        return Err((
            "work_result_component_resolution_snapshot_substituted".into(),
            "component-resolution snapshot identity and content hash do not reproduce".into(),
        ));
    }
    Ok(())
}

fn conductor_verification_evidence(
    goal_run_id: &str,
    invocation_ref: &str,
    invocation_receipt: &Value,
    verification: &Value,
) -> Result<(String, String, Value), SeamErr> {
    let verification_root = verify_rooted_runtime_record(
        "ioi.goal-run-conductor-verification-jcs-sha256.v1",
        "verification_root",
        verification,
    )?;
    let receipt_root = verify_rooted_runtime_record(
        "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
        "receipt_root",
        invocation_receipt,
    )?;
    let material = json!({
        "schema_version":"ioi.goal-run-conductor-verification-evidence.v1",
        "goal_run_id":goal_run_id,
        "harness_invocation_ref":invocation_ref,
        "verification_ref":verification.get("verification_ref"),
        "verification_root":verification_root,
        "invocation_receipt_ref":invocation_receipt.get("id"),
        "invocation_receipt_root":receipt_root,
        "verification":verification,
    });
    let evidence_hash = jcs_hash(
        &json!({
            "domain":"ioi.goal-run-conductor-verification-evidence-jcs-sha256.v1",
            "evidence":material,
        }),
        "work_result_verification_evidence_hash_failed",
    )?;
    let evidence_ref = format!(
        "evidence://goal-run/{}/verification/{}",
        safe(goal_run_id),
        evidence_hash.trim_start_matches("sha256:")
    );
    let evidence = json!({
        "schema_version":"ioi.goal-run-conductor-verification-evidence.v1",
        "evidence_ref":evidence_ref,
        "evidence_hash":evidence_hash,
        "goal_run_id":goal_run_id,
        "harness_invocation_ref":invocation_ref,
        "verification_ref":verification.get("verification_ref"),
        "verification_root":verification_root,
        "invocation_receipt_ref":invocation_receipt.get("id"),
        "invocation_receipt_root":receipt_root,
        "verification":verification,
    });
    let key = room_dependency_key(ROOM_CONDUCTOR_VERIFICATION_DOMAIN, "orcve_", &evidence)?;
    Ok((evidence_ref, key, evidence))
}

fn verify_conductor_verification_evidence(evidence: &Value) -> Result<(), SeamErr> {
    let mut material = evidence.clone();
    let object = material.as_object_mut().ok_or_else(|| {
        (
            "work_result_verification_evidence_invalid".into(),
            "conductor-verification evidence is not an object".into(),
        )
    })?;
    let evidence_ref = object
        .remove("evidence_ref")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let expected_hash = object
        .remove("evidence_hash")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let actual_hash = jcs_hash(
        &json!({
            "domain":"ioi.goal-run-conductor-verification-evidence-jcs-sha256.v1",
            "evidence":material,
        }),
        "work_result_verification_evidence_hash_failed",
    )?;
    if actual_hash != expected_hash
        || !evidence_ref.ends_with(expected_hash.trim_start_matches("sha256:"))
    {
        return Err((
            "work_result_verification_evidence_substituted".into(),
            "conductor-verification evidence identity and content hash do not reproduce".into(),
        ));
    }
    Ok(())
}

/// Resolve the execution-side candidate facts without pretending that they are the canonical
/// software result. Before WorkResult convergence these facts live under the deliberately
/// non-canonical `implementation_result_candidate` key. After convergence the same execution
/// tuple is retained as provenance on the canonical ImplementationResult so recovery can replay
/// from sealed truth without consulting mutable workspace state.
fn invocation_execution_facts(invocation: &Value) -> Option<&serde_json::Map<String, Value>> {
    invocation
        .get("implementation_result_candidate")
        .and_then(Value::as_object)
        .or_else(|| {
            invocation
                .get("execution_provenance")
                .and_then(Value::as_object)
        })
        .or_else(|| {
            invocation
                .get("implementation_result")
                .and_then(Value::as_object)
        })
}

fn invocation_result_candidate_ref(invocation: &Value) -> Option<&str> {
    invocation
        .pointer("/implementation_result_candidate/candidate_ref")
        .or_else(|| invocation.pointer("/execution_provenance/source_candidate_ref"))
        .or_else(|| invocation.pointer("/implementation_result/source_candidate_ref"))
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("implementation-result-candidate://"))
}

fn invocation_changed_files(invocation: &Value) -> Vec<Value> {
    invocation_execution_facts(invocation)
        .and_then(|facts| facts.get("changed_files"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn invocation_candidate_artifact_refs(invocation: &Value) -> Vec<Value> {
    invocation_execution_facts(invocation)
        .and_then(|facts| {
            facts
                .get("candidate_artifact_refs")
                .or_else(|| facts.get("artifact_refs"))
        })
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn invocation_receipt_ref(invocation: &Value) -> Option<&str> {
    let embedded = invocation
        .pointer("/execution_receipt/id")
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("receipt://"));
    let projected = invocation_execution_facts(invocation)
        .and_then(|facts| facts.get("receipt_refs"))
        .and_then(Value::as_array)
        .and_then(|refs| refs.first())
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("receipt://"));
    match (embedded, projected) {
        (Some(left), Some(right)) if left == right => Some(left),
        _ => None,
    }
}

fn validate_invocation_execution_binding(
    data_dir: &str,
    invocation: &Value,
    receipt: &Value,
    require_current_route: bool,
) -> Result<(), SeamErr> {
    verify_rooted_runtime_record(
        "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
        "receipt_root",
        receipt,
    )?;
    if invocation.get("execution_receipt") != Some(receipt) {
        return Err((
            "work_result_invocation_receipt_substituted".into(),
            "the durable invocation receipt differs from the exact receipt embedded by the execution owner"
                .into(),
        ));
    }
    let implementation = invocation_execution_facts(invocation).ok_or_else(|| {
        (
            "work_result_invocation_truth_unresolved".into(),
            "the invocation lacks its execution candidate or converged ImplementationResult facts"
                .into(),
        )
    })?;
    let top_level_pairs = [
        ("role_key", "role_key"),
        ("harness", "harness"),
        ("harness_ref", "harness_profile_ref"),
        ("model_route_ref", "model_route_ref"),
        ("model_route_binding_id", "model_route_binding_id"),
        (
            "model_route_binding_receipt_ref",
            "model_route_binding_receipt_ref",
        ),
        ("model_id", "model_id"),
        ("model_route_base_url", "model_route_base_url"),
        (
            "model_route_execution_endpoint",
            "model_route_execution_endpoint",
        ),
        ("session_ref", "session_ref"),
    ];
    if receipt.get("kind").and_then(Value::as_str) != Some("hypervisor.goal-run.invoke")
        || receipt.get("runtimeTruthSource").and_then(Value::as_str) != Some("daemon-runtime")
        || receipt.get("harness_invocation_ref") != invocation.get("harness_invocation_id")
        || receipt.get("goal_run_ref") != invocation.get("goal_ref")
        || top_level_pairs
            .iter()
            .any(|(invocation_field, receipt_field)| {
                invocation.get(*invocation_field) != receipt.get(*receipt_field)
            })
        || implementation.get("goal_ref") != invocation.get("goal_ref")
        || implementation.get("harness_invocation_ref") != invocation.get("harness_invocation_id")
        || implementation.get("harness_profile_ref") != receipt.get("harness_profile_ref")
        || implementation.get("model_route_ref") != receipt.get("model_route_ref")
        || implementation.get("model_route_binding_id") != receipt.get("model_route_binding_id")
        || implementation.get("model_route_binding_receipt_ref")
            != receipt.get("model_route_binding_receipt_ref")
        || implementation.get("model_id") != receipt.get("model_id")
        || implementation.get("model_route_base_url") != receipt.get("model_route_base_url")
        || implementation.get("model_route_execution_endpoint")
            != receipt.get("model_route_execution_endpoint")
        || implementation.get("command_contract_ref") != receipt.get("command_contract_ref")
        || implementation.get("receipt_refs").and_then(Value::as_array)
            != Some(&vec![receipt.get("id").cloned().unwrap_or(Value::Null)])
    {
        return Err((
            "work_result_invocation_component_binding_substituted".into(),
            "invocation, execution-result facts, and sealed receipt do not carry one byte-exact execution/component tuple"
                .into(),
        ));
    }
    let session_ref = receipt
        .get("session_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (_, session) = strict_unique_by_identity(data_dir, "sessions", "session_ref", session_ref)?;
    let binding_id = receipt
        .get("model_route_binding_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (_, binding) = strict_unique_by_identity(
        data_dir,
        "model-route-session-bindings",
        "binding_id",
        binding_id,
    )?;
    let mut binding_material = binding.clone();
    let retained_binding_root = binding_material
        .as_object_mut()
        .and_then(|object| object.remove("binding_root"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let actual_binding_root = jcs_hash(
        &binding_material,
        "work_result_model_route_binding_hash_failed",
    )?;
    let binding_receipt_ref = binding
        .get("receipt_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (_, binding_receipt) = strict_unique_by_identity(
        data_dir,
        "model-route-registry-receipts",
        "receipt_ref",
        binding_receipt_ref,
    )?;
    let binding_pairs = [
        "binding_id",
        "session_ref",
        "route_ref",
        "model_id",
        "base_url",
        "execution_endpoint",
        "harness_binding_ref",
        "admission_id",
    ];
    if session.get("model_route_binding") != Some(&binding)
        || retained_binding_root != actual_binding_root
        || binding.get("session_ref").and_then(Value::as_str) != Some(session_ref)
        || binding.get("binding_id").and_then(Value::as_str) != Some(binding_id)
        || binding.get("route_ref") != receipt.get("model_route_ref")
        || binding.get("receipt_ref") != receipt.get("model_route_binding_receipt_ref")
        || binding.get("model_id") != receipt.get("model_id")
        || binding.get("base_url") != receipt.get("model_route_base_url")
        || binding.get("execution_endpoint") != receipt.get("model_route_execution_endpoint")
        || binding_receipt.get("outcome").and_then(Value::as_str) != Some("ok")
        || binding_receipt.get("op").and_then(Value::as_str) != Some("bind_session_route")
        || binding_receipt.get("receipt_ref") != binding.get("receipt_ref")
        || binding_pairs
            .iter()
            .any(|field| binding_receipt.get(*field) != binding.get(*field))
    {
        return Err((
            "work_result_model_route_binding_substituted".into(),
            "Session, retained route binding, binding receipt, invocation, and invocation receipt do not resolve one exact component tuple"
                .into(),
        ));
    }
    if require_current_route {
        let resolved = super::model_routes::resolve_session_route_binding_strict(
            data_dir,
            session_ref,
            receipt.get("model_route_ref").and_then(Value::as_str),
            Some(binding_id),
        )
        .map_err(|message| {
            (
                "work_result_model_route_binding_unresolved".into(),
                format!(
                    "the just-completed Session route binding cannot be re-resolved ({message})"
                ),
            )
        })?;
        if Some(resolved.route_ref.as_str())
            != receipt.get("model_route_ref").and_then(Value::as_str)
            || Some(resolved.binding_id.as_str())
                != receipt
                    .get("model_route_binding_id")
                    .and_then(Value::as_str)
            || Some(resolved.receipt_ref.as_str())
                != receipt
                    .get("model_route_binding_receipt_ref")
                    .and_then(Value::as_str)
            || Some(resolved.model_id.as_str()) != receipt.get("model_id").and_then(Value::as_str)
            || Some(resolved.base_url.as_str())
                != receipt.get("model_route_base_url").and_then(Value::as_str)
            || Some(resolved.execution_endpoint.as_str())
                != receipt
                    .get("model_route_execution_endpoint")
                    .and_then(Value::as_str)
        {
            return Err((
                "work_result_model_route_binding_substituted".into(),
                "the current strict Session route resolver returned a different component tuple"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_conductor_verification(
    goal_run_id: &str,
    goal_ref: &str,
    invocation: &Value,
    receipt: &Value,
    verification: &Value,
) -> Result<(), SeamErr> {
    verify_rooted_runtime_record(
        "ioi.goal-run-conductor-verification-jcs-sha256.v1",
        "verification_root",
        verification,
    )?;
    let role_key = receipt
        .get("role_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_id = format!("gv_{}_{}", safe(goal_run_id), role_key);
    let expected_ref = format!("agentgres://goal-run-verification/{expected_id}");
    let expected_path = format!("verifier-path://vp_{goal_run_id}");
    let changed_files = receipt
        .get("files_written")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let output_facts = receipt
        .pointer("/output_file_facts/files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut expected_checks = vec![json!({
        "check":"invocation_execution_succeeded_exit_zero",
        "pass":true,
    })];
    for file in &changed_files {
        expected_checks.push(json!({
            "check":"reported_file_exists_with_content",
            "file":file,
            "pass":true,
        }));
    }
    expected_checks.push(json!({"check":"workspace_mutation_reported","pass":true}));
    let output_paths = output_facts
        .iter()
        .map(|fact| fact.get("relative_path").cloned().unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    if changed_files.is_empty()
        || output_paths != changed_files
        || output_facts
            .iter()
            .any(|fact| fact.get("bytes").and_then(Value::as_u64).unwrap_or(0) == 0)
        || verification.get("verification_id").and_then(Value::as_str) != Some(expected_id.as_str())
        || verification.get("verification_ref").and_then(Value::as_str)
            != Some(expected_ref.as_str())
        || verification.get("goal_run_id").and_then(Value::as_str) != Some(goal_run_id)
        || verification.get("goal_ref").and_then(Value::as_str) != Some(goal_ref)
        || verification.get("harness_invocation_ref") != invocation.get("harness_invocation_id")
        || verification
            .get("implementation_result_candidate_ref")
            .and_then(Value::as_str)
            != invocation_result_candidate_ref(invocation)
        || verification
            .get("verifier_path_ref")
            .and_then(Value::as_str)
            != Some(expected_path.as_str())
        || verification
            .get("verification_kind")
            .and_then(Value::as_str)
            != Some("deterministic")
        || verification.get("verdict").and_then(Value::as_str) != Some("pass")
        || verification.get("checks").and_then(Value::as_array) != Some(&expected_checks)
        || verification
            .get("runtimeTruthSource")
            .and_then(Value::as_str)
            != Some("daemon-runtime")
        || verification
            .get("verified_at")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err((
            "work_result_verification_truth_substituted".into(),
            "the sealed conductor verification does not reproduce the exact successful execution candidate, output-file fact set, deterministic checks, and verifier path"
                .into(),
        ));
    }
    Ok(())
}

/// Resolve the exact successful-but-preterminal invocation, conductor verification, invocation
/// receipt, and candidate-workspace bytes, then construct the only WorkResult those facts permit.
/// The caller supplies no result claim fields. `result_payload_ref` commits the successor
/// ImplementationResult after its reciprocal WorkResult backlink is inserted. An invocation never
/// becomes `completed` merely because its adapter process exited successfully.
fn derive_invocation_work_result(
    data_dir: &str,
    goal_run: &Value,
    invocation_ref: &str,
    verify_live_workspace: bool,
) -> Result<DerivedInvocationWorkResult, SeamErr> {
    let goal_ref = text(goal_run, "goal_ref");
    let goal_run_id = text(goal_run, "goal_run_id");
    let room_ref = text(goal_run, "outcome_room_ref");
    let system_id = text(goal_run, "target_system_id");
    if goal_ref.is_empty()
        || goal_run_id.is_empty()
        || room_ref.is_empty()
        || !system_id.starts_with("system://")
    {
        return Err((
            "work_result_runtime_goal_binding_unresolved".into(),
            "room WorkResult normalization requires one exact System-bound GoalRun membership"
                .into(),
        ));
    }
    let room = super::outcome_room_routes::resolve_room_strict(data_dir, room_ref)
        .map_err(|error| {
            (
                "work_result_runtime_room_unreadable".into(),
                format!("OutcomeRoom truth cannot be resolved ({error})"),
            )
        })?
        .ok_or_else(|| {
            (
                "work_result_runtime_room_unresolved".into(),
                "the GoalRun's reciprocal OutcomeRoom is absent".into(),
            )
        })?;
    if room.get("system_id").and_then(Value::as_str) != Some(system_id)
        || !room
            .get("member_goal_run_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(goal_ref)))
    {
        return Err((
            "work_result_runtime_system_binding_diverged".into(),
            "OutcomeRoom, System, and GoalRun reciprocal membership do not resolve exactly".into(),
        ));
    }

    let (invocation_key, invocation) = strict_unique_by_identity(
        data_dir,
        INVOCATION_KIND,
        "harness_invocation_id",
        invocation_ref,
    )?;
    if text(&invocation, "goal_ref") != goal_ref
        || text(&invocation, "goal_run_id") != goal_run_id
        || text(&invocation, "status") != "waiting_on_conductor"
        || invocation
            .pointer("/implementation_result_candidate/execution_succeeded")
            .and_then(Value::as_bool)
            != Some(true)
        || invocation.get("implementation_result").is_some()
        || invocation
            .get("work_result_ref")
            .is_some_and(|value| !value.is_null())
    {
        return Err((
            "work_result_invocation_truth_unresolved".into(),
            "the named invocation is not one successful, unbound, waiting-on-conductor invocation for this exact GoalRun".into(),
        ));
    }
    let implementation_result_candidate_ref = invocation_result_candidate_ref(&invocation)
        .ok_or_else(|| {
            (
                "work_result_implementation_result_candidate_unresolved".into(),
                "the waiting invocation lacks its exact non-canonical result-candidate identity"
                    .into(),
            )
        })?;
    let verification_matches = strict_json_family(data_dir, VERIFICATION_KIND)?
        .into_iter()
        .filter(|(_, record)| {
            record.get("harness_invocation_ref").and_then(Value::as_str) == Some(invocation_ref)
        })
        .collect::<Vec<_>>();
    if verification_matches.len() != 1 {
        return Err((
            "work_result_verification_truth_unresolved".into(),
            format!(
                "the invocation resolves {} conductor verifications; exactly one is required",
                verification_matches.len()
            ),
        ));
    }
    let verification = &verification_matches[0].1;
    let verification_ref = verification
        .get("verification_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let verification_checks = verification.get("checks").and_then(Value::as_array);
    if text(verification, "goal_ref") != goal_ref
        || verification
            .get("implementation_result_candidate_ref")
            .and_then(Value::as_str)
            != Some(implementation_result_candidate_ref)
        || text(verification, "verdict") != "pass"
        || verification_checks.is_none_or(|checks| {
            checks.is_empty()
                || checks
                    .iter()
                    .any(|check| check.get("pass").and_then(Value::as_bool) != Some(true))
        })
        || !verification_ref.starts_with("agentgres://")
    {
        return Err((
            "work_result_verification_truth_unresolved".into(),
            "the exact conductor verification is absent, failed, stale, or detached".into(),
        ));
    }

    let receipt_ref = invocation_receipt_ref(&invocation).ok_or_else(|| {
        (
            "work_result_invocation_receipt_unresolved".into(),
            "the waiting invocation lacks one exact embedded and projected runtime receipt".into(),
        )
    })?;
    let (_, receipt) = strict_unique_by_identity(data_dir, "receipts", "id", receipt_ref)?;
    validate_invocation_execution_binding(data_dir, &invocation, &receipt, verify_live_workspace)?;
    let authority_admission_ref = text(&receipt, "capability_lease_ref");
    let authority_admission_tail = authority_admission_ref
        .strip_prefix("authority-admission-intents/")
        .filter(|tail| tail.starts_with("aai_") && tail.len() <= 160)
        .ok_or_else(|| {
            (
                "work_result_invocation_authority_unresolved".into(),
                "the invocation receipt lacks its exact authority-admission intent".into(),
            )
        })?;
    let (_, authority_admission) = strict_unique_by_identity(
        data_dir,
        "authority-admission-intents",
        "intent_id",
        authority_admission_tail,
    )?;
    let (
        authority_admission_receipt_ref,
        authority_admission_receipt_key,
        authority_admission_receipt,
    ) = build_authority_admission_receipt(
        authority_admission_ref,
        &authority_admission,
        &receipt,
        invocation_ref,
        goal_ref,
    )?;
    let changed_files = invocation_changed_files(&invocation);
    let candidate_artifact_refs = invocation_candidate_artifact_refs(&invocation);
    if receipt.get("harness_invocation_ref") != invocation.get("harness_invocation_id")
        || receipt.get("goal_run_ref") != invocation.get("goal_ref")
        || receipt.get("files_written") != Some(&Value::Array(changed_files.clone()))
        || text(&receipt, "exit_status") != "success"
        || receipt.get("exit_code").and_then(Value::as_i64) != Some(0)
        || goal_run.get("capability_lease_ref") != receipt.get("capability_lease_ref")
        || text(&authority_admission, "status") != "consumed"
        || authority_admission
            .pointer("/commitment/subject_ref")
            .and_then(Value::as_str)
            != Some(goal_ref)
        || authority_admission
            .pointer("/commitment/required_scope")
            .and_then(Value::as_str)
            != Some("scope:hypervisor.live-route.session-execute")
        || authority_admission
            .pointer("/wallet_consumption_receipt/consumption_id")
            .is_none_or(Value::is_null)
        || text(&authority_admission, "final_invoker_status") != "admitted"
    {
        return Err((
            "work_result_invocation_receipt_unresolved".into(),
            "the invocation receipt is missing, unsuccessful, or detached from output and consumed authority truth".into(),
        ));
    }
    if changed_files.is_empty()
        || changed_files.len() > MAX_OUTPUT_FILES
        || candidate_artifact_refs.len() != changed_files.len()
        || candidate_artifact_refs.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|reference| !reference.starts_with("artifact://goal-run/"))
        })
    {
        return Err((
            "work_result_output_truth_unresolved".into(),
            "a completed software WorkResult requires a non-empty bounded changed-file set with one exact candidate artifact ref per file".into(),
        ));
    }
    let captured_output_file_facts = receipt
        .get("output_file_facts")
        .cloned()
        .unwrap_or(Value::Null);
    let captured_output_file_facts_hash = sha256_canonical(&captured_output_file_facts);
    let captured_files = captured_output_file_facts
        .get("files")
        .and_then(Value::as_array);
    let mut expected_paths = changed_files
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| {
                    (
                        "work_result_output_truth_unresolved".into(),
                        "the changed-file set contains a non-string path".into(),
                    )
                })
                .and_then(|path| {
                    contained_rel_path(path)
                        .map(|relative| relative.to_string_lossy().to_string())
                        .map_err(|message| ("work_result_output_truth_unresolved".into(), message))
                })
        })
        .collect::<Result<Vec<_>, SeamErr>>()?;
    expected_paths.sort();
    let captured_bytes = captured_files
        .into_iter()
        .flatten()
        .filter_map(|fact| fact.get("bytes").and_then(Value::as_u64))
        .sum::<u64>();
    let captured_is_exact = captured_output_file_facts
        .get("domain")
        .and_then(Value::as_str)
        == Some("ioi.harness-invocation-output-file-facts-jcs-sha256.v1")
        && captured_files.is_some_and(|files| {
            files.len() == expected_paths.len()
                && files
                    .iter()
                    .zip(&expected_paths)
                    .all(|(fact, expected_path)| {
                        fact.get("relative_path").and_then(Value::as_str)
                            == Some(expected_path.as_str())
                            && fact
                                .get("sha256")
                                .and_then(Value::as_str)
                                .is_some_and(|hash| {
                                    hash.strip_prefix("sha256:").is_some_and(|hex| {
                                        hex.len() == 64
                                            && hex
                                                .chars()
                                                .all(|character| character.is_ascii_hexdigit())
                                    })
                                })
                            && fact
                                .get("bytes")
                                .and_then(Value::as_u64)
                                .is_some_and(|bytes| bytes <= MAX_OUTPUT_FILE_BYTES)
                    })
        })
        && captured_bytes <= MAX_ATTEMPT_TOTAL_BYTES
        && receipt
            .get("output_file_facts_hash")
            .and_then(Value::as_str)
            == Some(captured_output_file_facts_hash.as_str());
    if !captured_is_exact {
        return Err((
            "work_result_output_truth_unresolved".into(),
            "the durable invocation receipt does not carry one exact, bounded output-byte fact set"
                .into(),
        ));
    }
    validate_conductor_verification(goal_run_id, goal_ref, &invocation, &receipt, verification)?;
    let output_files = captured_output_file_facts
        .get("files")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let output_facts = json!({
        "domain":"ioi.harness-invocation-output-facts-jcs-sha256.v1",
        "harness_invocation_ref":invocation_ref,
        "implementation_result_ref":format!("implementation_result://ir_{}_{}", goal_run_id, text(&invocation, "role_key")),
        "verification_ref":verification_ref,
        "invocation_receipt_ref":receipt_ref,
        "workspace_ref":invocation.pointer("/implementation_result_candidate/workspace_ref").cloned().unwrap_or(Value::Null),
        "files":output_files,
    });
    let output_commitment = sha256_canonical(&output_facts);
    let invocation_hash = hex::encode(Sha256::digest(invocation_ref.as_bytes()));
    let result_ref = format!(
        "work-result://goal-run/{}/invocation/{invocation_hash}",
        safe(goal_run_id)
    );
    let implementation_result_ref = format!(
        "implementation_result://ir_{}_{}",
        goal_run_id,
        text(&invocation, "role_key")
    );
    let implementation_result = json!({
        "implementation_result_id":implementation_result_ref,
        "work_subject_ref":goal_ref,
        "harness_invocation_ref":invocation_ref,
        "handoff_ref":Value::Null,
        "work_result_ref":result_ref,
        "attempt_ref":Value::Null,
        "status":"completed",
        "changed_file_refs":candidate_artifact_refs,
        "patch_refs":[],
        "test_result_refs":[receipt_ref],
        "blocker_refs":[],
        "decision_request_refs":[],
        "artifact_refs":candidate_artifact_refs,
        "receipt_refs":[receipt_ref],
        "summary_ref":Value::Null,
        "next_recommended_handoff_kind":"review",
    });
    let mut successor = invocation.clone();
    successor["status"] = json!("completed");
    successor["work_result_ref"] = json!(result_ref);
    successor["profile_result_ref"] = json!(implementation_result_ref);
    let mut execution_provenance = successor
        .as_object_mut()
        .expect("validated invocation object")
        .remove("implementation_result_candidate")
        .expect("validated execution-result candidate");
    let execution_provenance_object = execution_provenance
        .as_object_mut()
        .expect("validated execution-result candidate object");
    let source_candidate_ref = execution_provenance_object
        .remove("candidate_ref")
        .unwrap_or(Value::Null);
    execution_provenance_object.insert("source_candidate_ref".into(), source_candidate_ref);
    execution_provenance_object.insert("output_commitment".into(), json!(output_commitment));
    execution_provenance_object.insert("output_facts".into(), output_facts.clone());
    successor["execution_provenance"] = execution_provenance;
    successor["implementation_result"] = implementation_result.clone();
    let implementation_result_hash = sha256_canonical(&implementation_result);
    let result_payload_ref = format!(
        "artifact://goal-run/{}/invocation/{invocation_hash}/implementation-result/{}",
        safe(goal_run_id),
        implementation_result_hash.trim_start_matches("sha256:")
    );
    let mut payload_receipt_refs = vec![
        receipt_ref.to_owned(),
        authority_admission_receipt_ref.clone(),
    ];
    payload_receipt_refs.sort();
    payload_receipt_refs.dedup();
    let payload_custody = if verify_live_workspace {
        build_live_payload_custody(
            text(&invocation, "candidate_workspace_root"),
            &result_payload_ref,
            &implementation_result,
            captured_output_file_facts
                .get("files")
                .unwrap_or(&Value::Null),
            &captured_output_file_facts_hash,
            &payload_receipt_refs,
        )?
    } else {
        resolve_payload_custody(
            data_dir,
            &result_payload_ref,
            &implementation_result,
            captured_output_file_facts
                .get("files")
                .unwrap_or(&Value::Null),
            &captured_output_file_facts_hash,
            &payload_receipt_refs,
        )?
    };
    let information_flow_label =
        build_result_information_flow_label(&room, &payload_custody.content_hash)?;
    let information_flow_label_ref = information_flow_label
        .record
        .get("label_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let payload_write_admission_ref =
        payload_write_admission_evidence_ref(&payload_custody.admission)?;
    let (
        component_resolution_snapshot_ref,
        component_resolution_snapshot_key,
        component_resolution_snapshot,
    ) = component_resolution_snapshot(goal_run_id, invocation_ref, &receipt)?;
    let component_hash = component_resolution_snapshot
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let (
        verification_evidence_ref,
        conductor_verification_evidence_key,
        conductor_verification_evidence,
    ) = conductor_verification_evidence(goal_run_id, invocation_ref, &receipt, verification)?;
    let result = json!({
        "schema_version":"ioi.foundations.work-result.v3",
        "work_result_id":result_ref,
        "work_subject_ref":goal_ref,
        "system_binding":Value::Null,
        "produced_by_ref":system_id,
        "submitted_by_ref":system_id,
        "operator_and_affiliation_refs":[goal_run.get("owner_ref").cloned().unwrap_or(Value::Null)],
        "invocation_or_run_ref":invocation_ref,
        "result_profile":"software_implementation",
        "result_profile_ref":"profile://ioi/software-implementation/implementation-result-payload/v1",
        "result_payload_ref":result_payload_ref,
        "producer_component_resolution":{
            "resolved_component_set_snapshot_ref":component_resolution_snapshot_ref,
            "resolved_component_set_hash":component_hash,
            "component_resolution_receipt_ref":receipt_ref,
            "resolver_kind":"harness_profile",
            "resolver_revision_ref":format!("harness-profile://daemon-invocation/{}/revision/{}", safe(text(&receipt,"harness_profile_ref")), component_hash.trim_start_matches("sha256:")),
            "resolver_content_hash":component_hash,
        },
        "declared_method_and_lineage_refs":[result_payload_ref],
        "information_flow_label_refs":[information_flow_label_ref],
        "outcome_class":"positive",
        "status":"completed",
        "outcome_delta_refs":[],
        "observation_refs":[],
        "claim_refs":[verification_evidence_ref],
        "uncertainty":{
            "acceptance_not_implied":true,
            "scope":"successful invocation output and deterministic conductor checks only"
        },
        "supporting_evidence_refs":[receipt_ref,result_payload_ref,verification_evidence_ref,authority_admission_receipt_ref,payload_write_admission_ref],
        "contradicting_evidence_refs":[],
        "artifact_receipt_and_trace_refs":[receipt_ref,result_payload_ref,authority_admission_receipt_ref],
        "resource_and_cost_refs":[],
        "authority_and_policy_refs":[authority_admission_receipt_ref],
        "blocker_and_decision_request_refs":[],
        "verifier_refs":[verification.get("verifier_path_ref").cloned().unwrap_or(Value::Null)],
        "license_disclosure_retention_and_export_refs":room.get("artifact_license_rights_retention_and_export_policy_refs").cloned().unwrap_or_else(|| json!([])),
        "reproduction_state":"unreviewed",
        "reproduction_refs":[receipt_ref],
        "acceptance_ref":Value::Null,
        "review_refs":[],
        "supersedes_work_result_ref":Value::Null,
        "superseded_by_ref":Value::Null,
        "summary_ref":Value::Null,
        "next_action":"review",
    });
    Ok(DerivedInvocationWorkResult {
        invocation_key,
        prior_invocation: invocation,
        successor_invocation: successor,
        work_result: result,
        payload_custody,
        information_flow_label,
        component_resolution_snapshot_key,
        component_resolution_snapshot,
        conductor_verification_evidence_key,
        conductor_verification_evidence,
        authority_admission_receipt_key,
        authority_admission_receipt,
    })
}

/// Retained inside the room child intent before any runtime dependency is admitted. The bundle is
/// deliberately self-contained: restart recovery can reconstruct the immutable payload bytes and
/// every exact Agentgres/receipt dependency without consulting a mutable workspace.
fn room_result_runtime_dependency_intent(
    derived: &DerivedInvocationWorkResult,
) -> Result<Value, SeamErr> {
    let custody = &derived.payload_custody;
    if serde_jcs::to_vec(&custody.bundle).ok().as_deref() != Some(custody.bytes.as_slice()) {
        return Err((
            "work_result_payload_custody_substituted".into(),
            "the derived result bundle is not its byte-exact canonical representation".into(),
        ));
    }
    Ok(json!({
        "schema_version":"ioi.outcome-room-work-result-runtime-dependencies.v1",
        "work_result_ref":derived.work_result.get("work_result_id").cloned().unwrap_or(Value::Null),
        "payload_custody":{
            "admission_key":custody.admission_key,
            "admission":custody.admission,
            "bundle":custody.bundle,
        },
        "information_flow_label":{
            "key":derived.information_flow_label.key,
            "record":derived.information_flow_label.record,
        },
        "component_resolution_snapshot":{
            "key":derived.component_resolution_snapshot_key,
            "record":derived.component_resolution_snapshot,
        },
        "conductor_verification_evidence":{
            "key":derived.conductor_verification_evidence_key,
            "record":derived.conductor_verification_evidence,
        },
        "authority_admission_receipt":{
            "key":derived.authority_admission_receipt_key,
            "record":derived.authority_admission_receipt,
        },
    }))
}

fn closed_dependency_entry<'a>(
    intent: &'a Value,
    field: &str,
) -> Result<(&'a str, &'a Value), SeamErr> {
    let entry = intent
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            (
                "work_result_runtime_dependency_intent_invalid".into(),
                format!("retained runtime dependency '{field}' is not an object"),
            )
        })?;
    if entry.len() != 2 || !entry.contains_key("key") || !entry.contains_key("record") {
        return Err((
            "work_result_runtime_dependency_intent_invalid".into(),
            format!("retained runtime dependency '{field}' is not a closed key/record pair"),
        ));
    }
    let key = entry.get("key").and_then(Value::as_str).ok_or_else(|| {
        (
            "work_result_runtime_dependency_intent_invalid".into(),
            format!("retained runtime dependency '{field}' has no string key"),
        )
    })?;
    Ok((key, entry.get("record").unwrap_or(&Value::Null)))
}

fn invocation_proof_records_for_work_result(
    data_dir: &str,
    work_result: &Value,
) -> Result<(Value, Value, Value, String, Value), SeamErr> {
    let invocation_ref = text(work_result, "invocation_or_run_ref");
    let (_, invocation) = strict_unique_by_identity(
        data_dir,
        INVOCATION_KIND,
        "harness_invocation_id",
        invocation_ref,
    )?;
    let receipt_ref = invocation_receipt_ref(&invocation).unwrap_or_default();
    let (_, receipt) = strict_unique_by_identity(data_dir, "receipts", "id", receipt_ref)?;
    validate_invocation_execution_binding(data_dir, &invocation, &receipt, false)?;
    let mut verifications = strict_json_family(data_dir, VERIFICATION_KIND)?
        .into_iter()
        .filter(|(_, record)| {
            record.get("harness_invocation_ref").and_then(Value::as_str) == Some(invocation_ref)
        })
        .collect::<Vec<_>>();
    if verifications.len() != 1 {
        return Err((
            "work_result_verification_truth_unresolved".into(),
            format!(
                "the WorkResult invocation resolves {} conductor verifications; exactly one is required",
                verifications.len()
            ),
        ));
    }
    let verification = verifications.remove(0).1;
    validate_conductor_verification(
        text(&invocation, "goal_run_id"),
        text(&invocation, "goal_ref"),
        &invocation,
        &receipt,
        &verification,
    )?;
    let authority_ref = text(&receipt, "capability_lease_ref").to_owned();
    let authority_key = authority_ref
        .strip_prefix("authority-admission-intents/")
        .filter(|tail| tail.starts_with("aai_") && tail.len() <= 160)
        .ok_or_else(|| {
            (
                "work_result_invocation_authority_unresolved".into(),
                "the WorkResult invocation receipt lacks its authority-admission intent".into(),
            )
        })?;
    let (_, authority) = strict_unique_by_identity(
        data_dir,
        "authority-admission-intents",
        "intent_id",
        authority_key,
    )?;
    Ok((invocation, receipt, verification, authority_ref, authority))
}

fn expected_room_result_runtime_dependency_intent(
    data_dir: &str,
    room: &Value,
    work_result: &Value,
    bundle: &Value,
) -> Result<Value, SeamErr> {
    let artifact_ref = text(work_result, "result_payload_ref");
    let (implementation_result, file_facts, file_facts_hash, receipt_refs) =
        expected_payload_inputs_for_work_result(data_dir, work_result)?;
    let bytes = serde_jcs::to_vec(bundle).map_err(|error| {
        (
            "work_result_payload_unreadable".into(),
            format!("retained result bundle cannot be canonicalized ({error})"),
        )
    })?;
    validate_result_bundle(
        &bytes,
        artifact_ref,
        &implementation_result,
        &file_facts,
        &file_facts_hash,
    )?;
    let content_hash = sha256_hex(&bytes);
    let payload_ref = canonical_payload_ref(&content_hash, bytes.len() as u64)?;
    let (admission_key, admission) =
        storage_write_admission(artifact_ref, &payload_ref, &content_hash, &receipt_refs)?;
    let label = build_result_information_flow_label(room, &content_hash)?;
    let (invocation, receipt, verification, authority_ref, authority) =
        invocation_proof_records_for_work_result(data_dir, work_result)?;
    let (authority_receipt_ref, authority_receipt_key, authority_receipt) =
        build_authority_admission_receipt(
            &authority_ref,
            &authority,
            &receipt,
            text(work_result, "invocation_or_run_ref"),
            text(work_result, "work_subject_ref"),
        )?;
    let (component_ref, component_key, component) = component_resolution_snapshot(
        text(&invocation, "goal_run_id"),
        text(work_result, "invocation_or_run_ref"),
        &receipt,
    )?;
    verify_component_resolution_snapshot(&component)?;
    let (evidence_ref, evidence_key, evidence) = conductor_verification_evidence(
        text(&invocation, "goal_run_id"),
        text(work_result, "invocation_or_run_ref"),
        &receipt,
        &verification,
    )?;
    verify_conductor_verification_evidence(&evidence)?;
    let write_evidence_ref = payload_write_admission_evidence_ref(&admission)?;
    let component_resolution = work_result
        .get("producer_component_resolution")
        .unwrap_or(&Value::Null);
    let supporting = work_result
        .get("supporting_evidence_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let expected_supporting = vec![
        receipt.get("id").cloned().unwrap_or(Value::Null),
        json!(artifact_ref),
        json!(evidence_ref),
        json!(authority_receipt_ref),
        json!(write_evidence_ref),
    ];
    if component_resolution
        .get("resolved_component_set_snapshot_ref")
        .and_then(Value::as_str)
        != Some(component_ref.as_str())
        || component_resolution.get("resolved_component_set_hash") != component.get("snapshot_hash")
        || component_resolution.get("component_resolution_receipt_ref") != receipt.get("id")
        || work_result.get("claim_refs").and_then(Value::as_array)
            != Some(&vec![json!(evidence_ref)])
        || work_result
            .get("authority_and_policy_refs")
            .and_then(Value::as_array)
            != Some(&vec![json!(authority_receipt_ref)])
        || supporting != expected_supporting
        || work_result
            .get("information_flow_label_refs")
            .and_then(Value::as_array)
            != Some(&vec![label
                .record
                .get("label_ref")
                .cloned()
                .unwrap_or(Value::Null)])
    {
        return Err((
            "work_result_runtime_dependency_binding_substituted".into(),
            "WorkResult does not bind the exact payload, component snapshot, conductor evidence, authority receipt, and information-flow label closure"
                .into(),
        ));
    }
    Ok(json!({
        "schema_version":"ioi.outcome-room-work-result-runtime-dependencies.v1",
        "work_result_ref":work_result.get("work_result_id").cloned().unwrap_or(Value::Null),
        "payload_custody":{
            "admission_key":admission_key,
            "admission":admission,
            "bundle":bundle,
        },
        "information_flow_label":{"key":label.key,"record":label.record},
        "component_resolution_snapshot":{"key":component_key,"record":component},
        "conductor_verification_evidence":{"key":evidence_key,"record":evidence},
        "authority_admission_receipt":{"key":authority_receipt_key,"record":authority_receipt},
    }))
}

/// Validate the complete dependency bundle while it is still only retained intent. This function
/// is side-effect free and is the admission precondition used before the child intent is written.
pub(crate) fn validate_room_owner_runtime_dependency_intent(
    data_dir: &str,
    room: &Value,
    work_result: &Value,
    dependency_intent: &Value,
) -> Result<(), SeamErr> {
    let object = dependency_intent.as_object().ok_or_else(|| {
        (
            "work_result_runtime_dependency_intent_invalid".into(),
            "retained WorkResult runtime dependencies are not an object".into(),
        )
    })?;
    let expected_fields = [
        "schema_version",
        "work_result_ref",
        "payload_custody",
        "information_flow_label",
        "component_resolution_snapshot",
        "conductor_verification_evidence",
        "authority_admission_receipt",
    ];
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
        || dependency_intent
            .get("schema_version")
            .and_then(Value::as_str)
            != Some("ioi.outcome-room-work-result-runtime-dependencies.v1")
        || dependency_intent.get("work_result_ref") != work_result.get("work_result_id")
    {
        return Err((
            "work_result_runtime_dependency_intent_invalid".into(),
            "retained WorkResult runtime dependencies are not the closed v1 intent for this WorkResult"
                .into(),
        ));
    }
    let payload = dependency_intent
        .get("payload_custody")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            (
                "work_result_runtime_dependency_intent_invalid".into(),
                "retained payload custody is not an object".into(),
            )
        })?;
    if payload.len() != 3
        || !payload.contains_key("admission_key")
        || !payload.contains_key("admission")
        || !payload.contains_key("bundle")
        || payload
            .get("admission_key")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err((
            "work_result_runtime_dependency_intent_invalid".into(),
            "retained payload custody is not a closed admission-key/admission/bundle triple".into(),
        ));
    }
    for field in [
        "information_flow_label",
        "component_resolution_snapshot",
        "conductor_verification_evidence",
        "authority_admission_receipt",
    ] {
        let _ = closed_dependency_entry(dependency_intent, field)?;
    }
    // Validate the WorkResult's invocation-derived artifact identity before any retained
    // dependency can be converged. This is deliberately side-effect free: recovery must reject
    // a self-consistently re-rooted owner/operation substitution without rewriting its intent or
    // admitting any payload, label, component, verification, or authority records first.
    let _ = expected_payload_inputs_for_work_result(data_dir, work_result)?;
    let expected = expected_room_result_runtime_dependency_intent(
        data_dir,
        room,
        work_result,
        payload.get("bundle").unwrap_or(&Value::Null),
    )?;
    if expected != *dependency_intent {
        return Err((
            "work_result_runtime_dependency_intent_substituted".into(),
            "retained WorkResult runtime dependencies do not reproduce from the exact invocation, Session/model binding, authority, verification, and payload bytes"
                .into(),
        ));
    }
    Ok(())
}

fn admit_exact_required_dependency(
    data_dir: &str,
    family: &str,
    key: &str,
    record: &Value,
    code: &str,
) -> Result<(), SeamErr> {
    super::substrate_store::admit_required(data_dir, family, key, record).map_err(|error| {
        (
            code.to_owned(),
            format!("required runtime dependency '{family}/{key}' was not admitted ({error})"),
        )
    })?;
    super::substrate_store::verify_required_exact(data_dir, family, key, record).map_err(
        |error| {
            (
                code.to_owned(),
                format!(
                    "required runtime dependency '{family}/{key}' is not exact durable truth ({error})"
                ),
            )
        },
    )?;
    Ok(())
}

fn persist_exact_authority_receipt(
    data_dir: &str,
    key: &str,
    receipt: &Value,
) -> Result<(), SeamErr> {
    let receipt_ref = receipt
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let family = strict_json_family(data_dir, "receipts")?;
    let keyed = family.iter().find(|(record_key, _)| record_key == key);
    if keyed.is_some_and(|(_, record)| record != receipt) {
        return Err((
            "work_result_invocation_authority_receipt_substituted".into(),
            "the authority receipt's durable key is occupied by different bytes".into(),
        ));
    }
    let matches = family
        .iter()
        .filter(|(_, record)| record.get("receipt_id").and_then(Value::as_str) == Some(receipt_ref))
        .collect::<Vec<_>>();
    if matches.len() > 1
        || matches
            .first()
            .is_some_and(|(_, record)| *record != *receipt)
    {
        return Err((
            "work_result_invocation_authority_receipt_substituted".into(),
            "the authority receipt identity resolves divergent or duplicate durable bytes".into(),
        ));
    }
    if matches.is_empty() {
        persist_record_durable(data_dir, "receipts", key, receipt).map_err(|failure| {
            (
                "work_result_invocation_authority_receipt_persist_failed".into(),
                format!(
                    "the authority receipt did not durably commit ({})",
                    failure.detail()
                ),
            )
        })?;
    }
    let (resolved_key, resolved) =
        strict_unique_by_identity(data_dir, "receipts", "receipt_id", receipt_ref)?;
    if resolved_key != key || resolved != *receipt {
        return Err((
            "work_result_invocation_authority_receipt_substituted".into(),
            "the authority receipt did not re-resolve from its exact durable key and bytes".into(),
        ));
    }
    Ok(())
}

/// Idempotently converge the dependencies named by a retained room child intent. A failure leaves
/// that intent in place, so every admitted side effect remains attributable and restart-recoverable.
pub(crate) fn converge_room_owner_runtime_dependencies(
    data_dir: &str,
    room: &Value,
    work_result: &Value,
    dependency_intent: &Value,
) -> Result<(), SeamErr> {
    validate_room_owner_runtime_dependency_intent(data_dir, room, work_result, dependency_intent)?;
    let payload = dependency_intent
        .get("payload_custody")
        .and_then(Value::as_object)
        .expect("validated payload custody");
    let admission_key = payload
        .get("admission_key")
        .and_then(Value::as_str)
        .expect("validated admission key");
    let admission = payload.get("admission").expect("validated admission");
    let bundle = payload.get("bundle").expect("validated bundle");
    admit_exact_required_dependency(
        data_dir,
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
        admission_key,
        admission,
        "work_result_payload_write_admission_failed",
    )?;
    let payload_ref = admission
        .get("payload_refs")
        .and_then(Value::as_array)
        .and_then(|refs| refs.first())
        .and_then(Value::as_str)
        .unwrap_or_default();
    let bundle_bytes = serde_jcs::to_vec(bundle).map_err(|error| {
        (
            "work_result_payload_unreadable".into(),
            format!("retained result bundle cannot be canonicalized ({error})"),
        )
    })?;
    persist_immutable_payload_bytes(data_dir, payload_ref, &bundle_bytes)?;

    for (field, family, code) in [
        (
            "information_flow_label",
            ROOM_INFORMATION_FLOW_LABEL_DOMAIN,
            "work_result_information_flow_label_admission_failed",
        ),
        (
            "component_resolution_snapshot",
            ROOM_COMPONENT_RESOLUTION_DOMAIN,
            "work_result_component_resolution_snapshot_admission_failed",
        ),
        (
            "conductor_verification_evidence",
            ROOM_CONDUCTOR_VERIFICATION_DOMAIN,
            "work_result_verification_evidence_admission_failed",
        ),
    ] {
        let (key, record) = closed_dependency_entry(dependency_intent, field)?;
        admit_exact_required_dependency(data_dir, family, key, record, code)?;
    }
    let (authority_key, authority_receipt) =
        closed_dependency_entry(dependency_intent, "authority_admission_receipt")?;
    persist_exact_authority_receipt(data_dir, authority_key, authority_receipt)?;
    validate_work_result_runtime_dependencies(data_dir, room, work_result)
}

fn expected_payload_inputs_for_work_result(
    data_dir: &str,
    work_result: &Value,
) -> Result<(Value, Value, String, Vec<String>), SeamErr> {
    let invocation_ref = text(work_result, "invocation_or_run_ref");
    let work_result_ref = text(work_result, "work_result_id");
    let work_subject_ref = text(work_result, "work_subject_ref");
    let (_, invocation) = strict_unique_by_identity(
        data_dir,
        INVOCATION_KIND,
        "harness_invocation_id",
        invocation_ref,
    )?;
    if invocation
        .get("work_result_ref")
        .and_then(Value::as_str)
        .is_some_and(|reference| reference != work_result_ref)
        || invocation
            .pointer("/implementation_result/work_result_ref")
            .and_then(Value::as_str)
            .is_some_and(|reference| reference != work_result_ref)
    {
        return Err((
            "work_result_payload_invocation_substituted".into(),
            "the payload's HarnessInvocation carries a different WorkResult backlink".into(),
        ));
    }
    let implementation_result_ref = format!(
        "implementation_result://ir_{}_{}",
        text(&invocation, "goal_run_id"),
        text(&invocation, "role_key")
    );
    if text(&invocation, "goal_run_id").is_empty()
        || text(&invocation, "role_key").is_empty()
        || invocation_result_candidate_ref(&invocation).is_none()
    {
        return Err((
            "work_result_payload_invocation_unresolved".into(),
            "the payload's HarnessInvocation omits its deterministic result-candidate identity"
                .into(),
        ));
    }
    let verification_matches = strict_json_family(data_dir, VERIFICATION_KIND)?
        .into_iter()
        .filter(|(_, record)| {
            record.get("harness_invocation_ref").and_then(Value::as_str) == Some(invocation_ref)
        })
        .collect::<Vec<_>>();
    if verification_matches.len() != 1 {
        return Err((
            "work_result_payload_verification_unresolved".into(),
            "the payload's HarnessInvocation does not resolve one conductor verification".into(),
        ));
    }
    let verification = &verification_matches[0].1;
    let _verification_ref = verification
        .get("verification_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("agentgres://"))
        .ok_or_else(|| {
            (
                "work_result_payload_verification_unresolved".into(),
                "the payload's conductor verification identity is not canonical".into(),
            )
        })?;
    let receipt_ref = invocation_receipt_ref(&invocation).ok_or_else(|| {
        (
            "work_result_payload_receipt_unresolved".into(),
            "the payload's HarnessInvocation omits its runtime receipt".into(),
        )
    })?;
    let (_, receipt) = strict_unique_by_identity(data_dir, "receipts", "id", receipt_ref)?;
    validate_invocation_execution_binding(data_dir, &invocation, &receipt, false)?;
    validate_conductor_verification(
        text(&invocation, "goal_run_id"),
        text(&invocation, "goal_ref"),
        &invocation,
        &receipt,
        verification,
    )?;
    let captured_output_file_facts = receipt
        .get("output_file_facts")
        .cloned()
        .unwrap_or(Value::Null);
    let captured_output_file_facts_hash = sha256_canonical(&captured_output_file_facts);
    if receipt
        .get("output_file_facts_hash")
        .and_then(Value::as_str)
        != Some(captured_output_file_facts_hash.as_str())
    {
        return Err((
            "work_result_payload_receipt_substituted".into(),
            "the payload's invocation receipt output-file facts do not recompute".into(),
        ));
    }
    let candidate_artifact_refs = invocation_candidate_artifact_refs(&invocation);
    let implementation_result = json!({
        "implementation_result_id":implementation_result_ref,
        "work_subject_ref":work_subject_ref,
        "harness_invocation_ref":invocation_ref,
        "handoff_ref":Value::Null,
        "work_result_ref":work_result_ref,
        "attempt_ref":Value::Null,
        "status":"completed",
        "changed_file_refs":candidate_artifact_refs,
        "patch_refs":[],
        "test_result_refs":[receipt_ref],
        "blocker_refs":[],
        "decision_request_refs":[],
        "artifact_refs":candidate_artifact_refs,
        "receipt_refs":[receipt_ref],
        "summary_ref":Value::Null,
        "next_recommended_handoff_kind":"review",
    });
    if let Some(retained) = invocation.get("implementation_result") {
        if retained != &implementation_result
            || text(&invocation, "status") != "completed"
            || invocation.get("work_result_ref").and_then(Value::as_str) != Some(work_result_ref)
            || invocation.get("profile_result_ref").and_then(Value::as_str)
                != Some(implementation_result_ref.as_str())
        {
            return Err((
                "work_result_payload_invocation_substituted".into(),
                "the completed HarnessInvocation does not retain the exact canonical ImplementationResult and reciprocal refs".into(),
            ));
        }
    } else if text(&invocation, "status") != "waiting_on_conductor"
        || invocation
            .pointer("/implementation_result_candidate/execution_succeeded")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err((
            "work_result_payload_invocation_unresolved".into(),
            "the HarnessInvocation is neither a successful waiting candidate nor its exact completed successor".into(),
        ));
    }

    let result_payload_ref = text(work_result, "result_payload_ref");
    let implementation_result_hash = sha256_canonical(&implementation_result);
    if !result_payload_ref.starts_with("artifact://")
        || !result_payload_ref.ends_with(
            implementation_result_hash
                .strip_prefix("sha256:")
                .unwrap_or_default(),
        )
    {
        return Err((
            "work_result_payload_artifact_substituted".into(),
            "WorkResult artifact identity does not bind the exact successor ImplementationResult"
                .into(),
        ));
    }
    let authority_receipt_ref = work_result
        .get("authority_and_policy_refs")
        .and_then(Value::as_array)
        .and_then(|refs| refs.first())
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("receipt://"))
        .ok_or_else(|| {
            (
                "work_result_payload_authority_receipt_unresolved".into(),
                "WorkResult payload does not bind its exact authority-admission receipt".into(),
            )
        })?;
    let mut receipt_refs = vec![receipt_ref.to_owned(), authority_receipt_ref.to_owned()];
    receipt_refs.sort();
    receipt_refs.dedup();
    Ok((
        implementation_result,
        captured_output_file_facts
            .get("files")
            .cloned()
            .unwrap_or(Value::Null),
        captured_output_file_facts_hash,
        receipt_refs,
    ))
}

fn validate_work_result_runtime_dependencies(
    data_dir: &str,
    room: &Value,
    work_result: &Value,
) -> Result<(), SeamErr> {
    let artifact_ref = text(work_result, "result_payload_ref");
    let (implementation_result, captured_file_facts, captured_facts_hash, receipt_refs) =
        expected_payload_inputs_for_work_result(data_dir, work_result)?;
    let custody = resolve_payload_custody(
        data_dir,
        artifact_ref,
        &implementation_result,
        &captured_file_facts,
        &captured_facts_hash,
        &receipt_refs,
    )?;
    let expected_write_evidence = payload_write_admission_evidence_ref(&custody.admission)?;
    let write_evidence_count = work_result
        .get("supporting_evidence_refs")
        .and_then(Value::as_array)
        .map(|references| {
            references
                .iter()
                .filter(|reference| reference.as_str() == Some(expected_write_evidence.as_str()))
                .count()
        })
        .unwrap_or(0);
    if write_evidence_count != 1 {
        return Err((
            "work_result_payload_write_evidence_unresolved".into(),
            "WorkResult must bind exactly one canonical evidence:// ref for its exact durable storage-write admission".into(),
        ));
    }
    let expected_label = build_result_information_flow_label(room, &custody.content_hash)?;
    let expected_label_ref = expected_label
        .record
        .get("label_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let refs = work_result
        .get("information_flow_label_refs")
        .cloned()
        .unwrap_or(Value::Null);
    if refs.as_array() != Some(&vec![json!(expected_label_ref)]) {
        return Err((
            "work_result_information_flow_label_set_substituted".into(),
            "M4 WorkResult must carry exactly its byte-bound daemon-produced InformationFlowLabel"
                .into(),
        ));
    }
    let labels = resolve_information_flow_label_set(data_dir, &refs)?;
    if labels.as_slice() != [expected_label.record]
        || labels[0].get("content_hash").and_then(Value::as_str)
            != Some(custody.content_hash.as_str())
    {
        return Err((
            "work_result_information_flow_label_substituted".into(),
            "resolved WorkResult label does not bind the exact admitted result-bundle bytes".into(),
        ));
    }
    let dependency_intent = expected_room_result_runtime_dependency_intent(
        data_dir,
        room,
        work_result,
        &custody.bundle,
    )?;
    validate_room_owner_runtime_dependency_intent(data_dir, room, work_result, &dependency_intent)?;
    let (payload_key, payload_record) = {
        let payload = dependency_intent
            .get("payload_custody")
            .and_then(Value::as_object)
            .expect("locally produced dependency intent");
        (
            payload
                .get("admission_key")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            payload.get("admission").unwrap_or(&Value::Null),
        )
    };
    super::substrate_store::verify_required_exact(
        data_dir,
        ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
        payload_key,
        payload_record,
    )
    .map_err(|error| {
        (
            "work_result_payload_write_admission_unconfirmed".into(),
            format!("payload write admission does not resolve exact durable truth ({error})"),
        )
    })?;
    for (field, family, identity_field) in [
        (
            "component_resolution_snapshot",
            ROOM_COMPONENT_RESOLUTION_DOMAIN,
            "snapshot_ref",
        ),
        (
            "conductor_verification_evidence",
            ROOM_CONDUCTOR_VERIFICATION_DOMAIN,
            "evidence_ref",
        ),
    ] {
        let (key, record) = closed_dependency_entry(&dependency_intent, field)?;
        let identity = record
            .get(identity_field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        let matches = super::substrate_store::read_required_all(data_dir, family)
            .map_err(|error| {
                (
                    "work_result_runtime_dependency_unreadable".into(),
                    format!("required dependency family '{family}' cannot be read ({error})"),
                )
            })?
            .into_iter()
            .filter(|candidate| {
                candidate.get(identity_field).and_then(Value::as_str) == Some(identity)
            })
            .collect::<Vec<_>>();
        if matches.as_slice() != [record.clone()] {
            return Err((
                "work_result_runtime_dependency_substituted".into(),
                format!(
                    "required dependency '{field}' resolves {} records instead of one exact record",
                    matches.len()
                ),
            ));
        }
        super::substrate_store::verify_required_exact(data_dir, family, key, record).map_err(
            |error| {
                (
                    "work_result_runtime_dependency_unconfirmed".into(),
                    format!("required dependency '{field}' is not exact durable truth ({error})"),
                )
            },
        )?;
    }
    let (authority_key, authority_receipt) =
        closed_dependency_entry(&dependency_intent, "authority_admission_receipt")?;
    let authority_ref = authority_receipt
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (resolved_key, resolved_authority) =
        strict_unique_by_identity(data_dir, "receipts", "receipt_id", authority_ref)?;
    if resolved_key != authority_key || resolved_authority != *authority_receipt {
        return Err((
            "work_result_invocation_authority_receipt_substituted".into(),
            "the WorkResult authority admission receipt does not resolve from its exact durable key and bytes"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_room_owner_runtime_dependencies(
    data_dir: &str,
    room: &Value,
    owner_record: &Value,
) -> Result<(), SeamErr> {
    match owner_record.get("schema_version").and_then(Value::as_str) {
        Some("ioi.foundations.work-result.v3") => {
            validate_work_result_runtime_dependencies(data_dir, room, owner_record)
        }
        Some("ioi.foundations.outcome-delta.v3") => {
            resolve_information_flow_label_set(
                data_dir,
                owner_record
                    .get("information_flow_label_refs")
                    .unwrap_or(&Value::Null),
            )?;
            Ok(())
        }
        _ => Err((
            "outcome_room_owner_record_contract_unavailable".into(),
            "runtime dependency validation owns only room WorkResult and OutcomeDelta v3".into(),
        )),
    }
}

fn admitted_matches_derived_runtime_result(admitted: &Value, derived: &Value) -> bool {
    let mut normalized = admitted.clone();
    normalized["system_binding"] = Value::Null;
    normalized == *derived
}

/// Complete the reciprocal `HarnessInvocation.work_result_ref` edge while the OutcomeRoom child
/// intent is still retained. On replay an already-stamped invocation is accepted only when its
/// sealed admitted-WorkResult root and every exact ref match; mutable workspace bytes are never
/// reinterpreted after the canonical result has been sealed.
fn converge_invocation_work_result(
    data_dir: &str,
    admitted_object: &Value,
) -> Result<Value, SeamErr> {
    let _guard = INVOCATION_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let invocation_ref = text(admitted_object, "invocation_or_run_ref");
    let work_result_ref = text(admitted_object, "work_result_id");
    if !invocation_ref.starts_with("harness-invocation://")
        || !work_result_ref.starts_with("work-result://")
    {
        return Err((
            "outcome_room_invocation_backlink_invalid".into(),
            "room WorkResult lacks exact invocation/result identities".into(),
        ));
    }
    let (invocation_key, current) = strict_unique_by_identity(
        data_dir,
        INVOCATION_KIND,
        "harness_invocation_id",
        invocation_ref,
    )?;
    let admitted_root = sha256_canonical(admitted_object);
    if current
        .get("work_result_ref")
        .and_then(Value::as_str)
        .is_some()
    {
        let mut sealed_invocation = current.clone();
        sealed_invocation
            .as_object_mut()
            .expect("invocation record is an object")
            .remove("work_result_derivation");
        let sealed_invocation_root = sha256_canonical(&sealed_invocation);
        let exact = current.get("work_result_ref").and_then(Value::as_str) == Some(work_result_ref)
            && current
                .pointer("/implementation_result/work_result_ref")
                .and_then(Value::as_str)
                == Some(work_result_ref)
            && current.get("profile_result_ref")
                == current.pointer("/implementation_result/implementation_result_id")
            && current
                .pointer("/work_result_derivation/admitted_work_result_root")
                .and_then(Value::as_str)
                == Some(admitted_root.as_str())
            && current.pointer("/work_result_derivation/result_payload_ref")
                == admitted_object.get("result_payload_ref")
            && current.pointer("/work_result_derivation/outcome_room_ref")
                == admitted_object.pointer("/system_binding/parent_scope_ref")
            && current
                .pointer("/work_result_derivation/invocation_successor_root")
                .and_then(Value::as_str)
                == Some(sealed_invocation_root.as_str());
        return if exact {
            Ok(current)
        } else {
            Err((
                "outcome_room_invocation_backlink_diverged".into(),
                "HarnessInvocation already carries a different or detached WorkResult backlink"
                    .into(),
            ))
        };
    }
    let goal_ref = text(admitted_object, "work_subject_ref");
    let goal_run = load_goal_run_strict(data_dir, goal_ref)
        .map_err(|error| ("outcome_room_invocation_goal_unreadable".into(), error))?
        .ok_or_else(|| {
            (
                "outcome_room_invocation_goal_unresolved".into(),
                "the invocation's GoalRun is absent during backlink convergence".into(),
            )
        })?;
    let mut derived = derive_invocation_work_result(data_dir, &goal_run, invocation_ref, false)?;
    if derived.invocation_key != invocation_key
        || derived.prior_invocation != current
        || !admitted_matches_derived_runtime_result(admitted_object, &derived.work_result)
    {
        return Err((
            "outcome_room_invocation_result_substitution".into(),
            "admitted WorkResult bytes differ from the daemon-derived invocation result".into(),
        ));
    }
    let invocation_successor_root = sha256_canonical(&derived.successor_invocation);
    derived.successor_invocation["work_result_derivation"] = json!({
        "schema_version":"ioi.harness-invocation-work-result-derivation.v1",
        "work_result_ref":work_result_ref,
        "outcome_room_ref":admitted_object.pointer("/system_binding/parent_scope_ref").cloned().unwrap_or(Value::Null),
        "result_payload_ref":admitted_object.get("result_payload_ref").cloned().unwrap_or(Value::Null),
        "admitted_work_result_root":admitted_root,
        "invocation_successor_root":invocation_successor_root,
    });
    match persist_record_durable(
        data_dir,
        INVOCATION_KIND,
        &invocation_key,
        &derived.successor_invocation,
    ) {
        Ok(()) => Ok(derived.successor_invocation),
        Err(failure) => Err((
            "outcome_room_invocation_backlink_durability_unconfirmed".into(),
            format!(
                "the reciprocal HarnessInvocation backlink did not durably converge ({}); retain the room child intent",
                failure.detail()
            ),
        )),
    }
}

/// Admit and retain one generic WorkResult for a direct or System-bound GoalRun.
pub(crate) async fn handle_goal_run_result_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Resolve deployment posture and caller identity before touching GoalRun or joined room
    // truth. Missing, malformed, pending, and existing records are not anonymous oracles.
    let resolved_reader = match global_truth_reader(&st, &headers) {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    let Some(goal_run) = (match load_goal_run_for_http(&st.data_dir, &id) {
        Ok(value) => value,
        Err(response) => return response,
    }) else {
        return missing_goal_run_mutation_refusal(resolved_reader.as_deref());
    };
    if let Err(response) =
        authorize_resolved_goal_run_mutation(resolved_reader.as_deref(), &goal_run)
    {
        return response;
    }
    if let Some(response) = refuse_result_write_for_zero_execution_goal(&goal_run) {
        return response;
    }
    let room_ref = text(&goal_run, "outcome_room_ref").to_string();
    let Some(object) = body.as_object_mut() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "work_result_invalid",
            "WorkResult request must be an object.",
        );
    };
    if !room_ref.is_empty() {
        let invocation_ref = match room_result_request_invocation_ref(&body) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let derived =
            match derive_invocation_work_result(&st.data_dir, &goal_run, &invocation_ref, true) {
                Ok(value) => value,
                Err((code, message)) => return bad(seam_status(&code), &code, &message),
            };
        let runtime_dependencies = match room_result_runtime_dependency_intent(&derived) {
            Ok(value) => value,
            Err((code, message)) => return bad(seam_status(&code), &code, &message),
        };
        if let Err((code, message)) = super::outcome_room_system_routes::preflight_owner_publication(
            &st.data_dir,
            &derived.work_result,
        ) {
            return bad(seam_status(&code), &code, &message);
        }
        let room_admission = match super::outcome_room_system_routes::admit_persisted_owner_record(
            &st.data_dir,
            &room_ref,
            &derived.work_result,
            Some(&runtime_dependencies),
        ) {
            Ok(value) => value,
            Err((code, message)) => return bad(seam_status(&code), &code, &message),
        };
        // The private room seam constructs and bounds the exact final HTTP envelope before any
        // child/dependency/owner effect. Do not wrap or duplicate it here after commit: even a
        // small post-effect wrapper could push a near-limit response past the selected M4 bound.
        // Callers follow the refs-only convergence summary through the canonical owner GETs.
        return (StatusCode::CREATED, Json(room_admission));
    }
    for plane_owned in [
        "goal_run_ref",
        "outcome_room_ref",
        "room_admission",
        "system_binding",
    ] {
        if object
            .get(plane_owned)
            .is_some_and(|value| !value.is_null())
        {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "work_result_plane_owned_field_refused",
                &format!("`{plane_owned}` is derived by the GoalRun/OutcomeRoom owner planes."),
            );
        }
    }
    object.insert(
        "work_subject_ref".into(),
        goal_run.get("goal_ref").cloned().unwrap_or(Value::Null),
    );
    // The daemon owns producer truth. A caller-supplied producer resolution is never
    // preserved: it could otherwise substitute an unobserved component set for the
    // exact profile-resolution closure admitted on this direct GoalRun.
    object.insert("producer_component_resolution".into(), json!({
        "resolved_component_set_snapshot_ref": goal_run.get("resolved_component_set_snapshot_ref").cloned().unwrap_or(Value::Null),
        "resolved_component_set_hash": goal_run.get("resolved_component_set_hash").cloned().unwrap_or(Value::Null),
        "component_resolution_receipt_ref": goal_run.get("goal_run_profile_resolution_receipt_ref").cloned().unwrap_or(Value::Null),
        "resolver_kind": "harness_profile",
        "resolver_revision_ref": goal_run.get("goal_run_profile_revision_ref").cloned().unwrap_or(Value::Null),
        "resolver_content_hash": goal_run.get("goal_run_profile_content_hash").cloned().unwrap_or(Value::Null)
    }));
    let admitted_at = iso_now();
    let admitted = match GoalPursuitCore.admit_work_result(&body, &admitted_at) {
        Ok(admitted) => admitted,
        Err(error) => return pursuit_err(error),
    };
    let result = admitted.get("work_result").cloned().unwrap_or(Value::Null);
    let result_ref = text(&result, "work_result_id").to_string();
    match super::work_result_routes::load_work_result_strict(&st.data_dir, &result_ref) {
        Ok(Some(_)) => {
            return bad(
                StatusCode::CONFLICT,
                "work_result_identity_already_exists",
                "The WorkResult identity already resolves in the live versioned registry.",
            )
        }
        Ok(None) => {}
        Err(message) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "work_result_registry_unreadable",
                &format!(
                    "The complete versioned WorkResult registry cannot be resolved ({message})."
                ),
            )
        }
    }
    let result_receipt_ref = admitted
        .get("admission_receipt_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let result_receipt = receipt_envelope(
        &result_receipt_ref,
        "work_result_admission",
        &result_ref,
        text(&goal_run, "goal_ref"),
        admitted
            .get("work_result_hash")
            .and_then(Value::as_str)
            .unwrap_or(""),
        result
            .get("result_payload_ref")
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
        &admitted_at,
    );
    let key = super::work_result_routes::goal_run_work_truth_record_key(&result_ref);
    if persist_record(
        &st.data_dir,
        super::work_result_routes::RESULT_DIR,
        &key,
        &result,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "work_result_persist_failed",
            "The admitted WorkResult did not persist.",
        );
    }
    if result_receipt_ref.is_empty()
        || persist_record(
            &st.data_dir,
            "receipts",
            &receipt_file_key(&result_receipt_ref),
            &result_receipt,
        )
        .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "work_result_receipt_persist_failed",
            "The admitted WorkResult receipt did not persist; no GoalRun completion is reported.",
        );
    }
    let updated = update_goal_run_guarded(
        &st.data_dir,
        &id,
        |_| Ok(()),
        |obj| {
            let mut refs = obj
                .get("work_result_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !refs
                .iter()
                .any(|value| value.as_str() == Some(result_ref.as_str()))
            {
                refs.push(json!(result_ref));
            }
            obj.insert("work_result_refs".into(), Value::Array(refs));
            let mut receipt_refs = obj
                .get("receipt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !receipt_refs
                .iter()
                .any(|value| value.as_str() == Some(result_receipt_ref.as_str()))
            {
                receipt_refs.push(json!(result_receipt_ref));
            }
            obj.insert("receipt_refs".into(), Value::Array(receipt_refs));
            obj.insert("updated_at".into(), json!(iso_now()));
        },
    );
    if let Err((code, message)) = updated {
        return bad(seam_status(&code), &code, &message);
    }
    (
        StatusCode::CREATED,
        Json(
            json!({"ok":true,"admission":admitted,"work_result_receipt":result_receipt,"goal_run":updated.unwrap().into_record()}),
        ),
    )
}

/// Canonical ReceiptEnvelope for the direct GoalRun result/delta lane. The receipt attests
/// admission only; it never implies verification, acceptance, or execution of a proposed delta.
fn receipt_envelope(
    receipt_ref: &str,
    receipt_type: &str,
    subject_ref: &str,
    goal_ref: &str,
    output_hash: &str,
    artifact_refs: Vec<&str>,
    timestamp: &str,
) -> Value {
    json!({
        "receipt_id": receipt_ref,
        "receipt_type": receipt_type,
        "receipt_profile_ref": "schema://ioi/foundations/receipt-envelope/v1",
        "attested_boundary_fact_refs": [subject_ref, goal_ref],
        "claim_scope_ref": Value::Null,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-daemon",
        "output_hash": output_hash,
        "authority_grant_id": Value::Null,
        "primitive_capabilities": [],
        "authority_scopes": [],
        "artifact_refs": artifact_refs,
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": timestamp,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
    })
}

fn room_owner_record_is_exact_or_successor(existing: &Value, expected: &Value) -> bool {
    if existing == expected {
        return true;
    }
    if expected.get("schema_version").and_then(Value::as_str)
        != Some("ioi.foundations.work-result.v3")
    {
        return false;
    }
    let expected_refs = expected
        .get("outcome_delta_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let existing_refs = existing
        .get("outcome_delta_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !expected_refs
        .iter()
        .all(|reference| existing_refs.contains(reference))
    {
        return false;
    }
    let mut normalized = existing.clone();
    normalized["outcome_delta_refs"] = Value::Array(expected_refs);
    normalized == *expected
}

/// Collision-free durable slot for a canonical room-owner identity. Unlike lossy punctuation
/// replacement, the full URI participates in the key and two distinct identities cannot alias.
pub(crate) fn room_owner_record_key(identity: &str) -> String {
    format!(
        "room_owner_{}",
        hex::encode(Sha256::digest(identity.as_bytes()))
    )
}

fn publish_room_owner_record_exact(
    data_dir: &str,
    family: &str,
    identity_field: &str,
    identity: &str,
    expected: &Value,
) -> Result<Value, SeamErr> {
    let registry = match family {
        super::work_result_routes::RESULT_DIR => {
            super::work_result_routes::list_work_results_strict(data_dir)
        }
        super::work_result_routes::DELTA_DIR => {
            super::work_result_routes::list_outcome_deltas_strict(data_dir)
        }
        _ => Err(format!("unsupported room owner registry '{family}'")),
    }
    .map_err(|message| {
        (
            "outcome_room_owner_registry_unreadable".into(),
            format!("complete versioned owner registry cannot be resolved ({message})"),
        )
    })?;
    let matches = registry
        .into_iter()
        .filter(|record| record.get(identity_field).and_then(Value::as_str) == Some(identity))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err((
            "outcome_room_owner_registry_diverged".into(),
            format!("owner registry resolves duplicate identity '{identity}'"),
        ));
    }
    if let Some(existing) = matches.into_iter().next() {
        if room_owner_record_is_exact_or_successor(&existing, expected) {
            return Ok(existing);
        }
        return Err((
            "outcome_room_owner_registry_diverged".into(),
            format!("owner registry identity '{identity}' contains divergent bytes"),
        ));
    }
    persist_record_durable(data_dir, family, &room_owner_record_key(identity), expected).map_err(
        |failure| {
            (
                "outcome_room_owner_registry_persist_failed".into(),
                format!(
                    "room-admitted owner record '{identity}' did not durably publish ({})",
                    failure.detail()
                ),
            )
        },
    )?;
    let published = match family {
        super::work_result_routes::RESULT_DIR => {
            super::work_result_routes::load_work_result_strict(data_dir, identity)
        }
        super::work_result_routes::DELTA_DIR => {
            super::work_result_routes::load_outcome_delta_strict(data_dir, identity)
        }
        _ => unreachable!("family was validated above"),
    }
    .map_err(|message| {
        (
            "outcome_room_owner_registry_unreadable".into(),
            format!("published owner record cannot be resolved exactly ({message})"),
        )
    })?
    .ok_or_else(|| {
        (
            "outcome_room_owner_registry_persist_failed".into(),
            "published owner record is absent on strict post-write resolution".into(),
        )
    })?;
    if published != *expected {
        return Err((
            "outcome_room_owner_registry_diverged".into(),
            "published owner record differs from the exact admitted bytes".into(),
        ));
    }
    Ok(published)
}

/// Converge the owner-plane half of a room child commit. The room plane calls this while holding
/// its mutation lock and retains its private intent until this function confirms both the exact
/// admitted object and every owner backlink. Replays accept the exact prior state or an append-only
/// successor, while any byte substitution fails closed.
pub(crate) fn converge_room_owner_backlinks(
    data_dir: &str,
    admitted_object: &Value,
    room_admission_receipt_ref: &str,
) -> Result<Value, SeamErr> {
    if !room_admission_receipt_ref.starts_with("receipt://") {
        return Err((
            "outcome_room_owner_receipt_ref_invalid".into(),
            "room admission receipt ref must be canonical".into(),
        ));
    }
    let schema = text(admitted_object, "schema_version");
    let system_binding = admitted_object
        .get("system_binding")
        .unwrap_or(&Value::Null);
    let room_ref = system_binding
        .get("parent_scope_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if room_ref.is_empty()
        || system_binding.get("schema_version").and_then(Value::as_str)
            != Some("ioi.foundations.system-scoped-object-binding.v1")
        || system_binding
            .get("parent_scope_ref")
            .and_then(Value::as_str)
            != Some(room_ref)
    {
        return Err((
            "outcome_room_owner_admission_binding_invalid".into(),
            "owner object does not carry the exact SystemScopedObjectBinding".into(),
        ));
    }
    let (family, identity_field, identity, goal_ref, proposer) = match schema {
        "ioi.foundations.work-result.v3" => (
            super::work_result_routes::RESULT_DIR,
            "work_result_id",
            text(admitted_object, "work_result_id").to_string(),
            text(admitted_object, "work_subject_ref").to_string(),
            None,
        ),
        "ioi.foundations.outcome-delta.v3" => (
            super::work_result_routes::DELTA_DIR,
            "outcome_delta_id",
            text(admitted_object, "outcome_delta_id").to_string(),
            String::new(),
            Some(text(admitted_object, "proposed_by_ref").to_string()),
        ),
        _ => {
            return Err((
                "outcome_room_owner_record_contract_unavailable".into(),
                "only room-scoped WorkResult v3 and OutcomeDelta v3 records may converge".into(),
            ))
        }
    };
    if identity.is_empty() {
        return Err((
            "outcome_room_owner_record_identity_missing".into(),
            "room-admitted owner record lacks its canonical identity".into(),
        ));
    }
    let published = publish_room_owner_record_exact(
        data_dir,
        family,
        identity_field,
        &identity,
        admitted_object,
    )?;
    let harness_invocation = if schema == "ioi.foundations.work-result.v3" {
        Some(converge_invocation_work_result(data_dir, admitted_object)?)
    } else {
        None
    };
    let (goal_ref, work_result) = if let Some(proposer) = proposer {
        let mut result = super::work_result_routes::load_work_result_strict(data_dir, &proposer)
            .map_err(|message| {
                (
                    "outcome_room_owner_registry_unreadable".into(),
                    format!("OutcomeDelta proposer registry cannot be resolved ({message})"),
                )
            })?
            .ok_or_else(|| {
                (
                    "outcome_room_delta_work_result_unresolved".into(),
                    "OutcomeDelta proposer does not resolve to one exact owner WorkResult".into(),
                )
            })?;
        if result.get("schema_version").and_then(Value::as_str)
            != Some("ioi.foundations.work-result.v3")
        {
            return Err((
                "outcome_room_delta_work_result_contract_mismatch".into(),
                "OutcomeDelta proposer is not the current room WorkResult contract".into(),
            ));
        }
        if result
            .pointer("/system_binding/parent_scope_ref")
            .and_then(Value::as_str)
            != Some(room_ref)
        {
            return Err((
                "outcome_room_delta_work_result_room_mismatch".into(),
                "OutcomeDelta proposer belongs to a different room".into(),
            ));
        }
        let goal_ref = text(&result, "work_subject_ref").to_string();
        let refs = result
            .get_mut("outcome_delta_refs")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                (
                    "outcome_room_delta_backlink_invalid".into(),
                    "WorkResult lacks its append-only OutcomeDelta backlink list".into(),
                )
            })?;
        if !refs
            .iter()
            .any(|reference| reference.as_str() == Some(identity.as_str()))
        {
            refs.push(json!(identity));
        }
        persist_record_durable(
            data_dir,
            super::work_result_routes::RESULT_DIR,
            &room_owner_record_key(&proposer),
            &result,
        )
        .map_err(|failure| {
            (
                "outcome_room_delta_backlink_persist_failed".into(),
                format!(
                    "WorkResult backlink did not durably converge ({})",
                    failure.detail()
                ),
            )
        })?;
        (goal_ref, Some(result))
    } else {
        (goal_ref, Some(published.clone()))
    };
    let goal_id = goal_ref.strip_prefix("goal://").ok_or_else(|| {
        (
            "outcome_room_owner_goal_ref_invalid".into(),
            "room-admitted owner record lacks a canonical GoalRun ref".into(),
        )
    })?;
    let backlink_updated_at = admitted_object
        .pointer("/system_binding/updated_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                "outcome_room_owner_admission_timestamp_missing".into(),
                "room-admitted owner record lacks its receipt-bound update timestamp".into(),
            )
        })?
        .to_string();
    let updated = update_goal_run_guarded(
        data_dir,
        goal_id,
        |fresh| {
            if text(fresh, "goal_ref") != goal_ref || text(fresh, "outcome_room_ref") != room_ref {
                return Err((
                    "outcome_room_owner_goal_binding_diverged".into(),
                    "GoalRun no longer carries the reciprocal room membership".into(),
                ));
            }
            Ok(())
        },
        |run| {
            if schema == "ioi.foundations.work-result.v3" {
                let refs = run
                    .entry("work_result_refs")
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .expect("GoalRun work_result_refs is canonical");
                if !refs
                    .iter()
                    .any(|reference| reference.as_str() == Some(identity.as_str()))
                {
                    refs.push(json!(identity));
                }
            }
            let receipts = run
                .entry("receipt_refs")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("GoalRun receipt_refs is canonical");
            if !receipts
                .iter()
                .any(|reference| reference.as_str() == Some(room_admission_receipt_ref))
            {
                receipts.push(json!(room_admission_receipt_ref));
            }
            run.insert("updated_at".into(), json!(backlink_updated_at));
        },
    )?;
    let updated = require_durable_mutation(
        updated,
        "outcome_room_owner_goal_backlink_durability_unconfirmed",
        "The reciprocal GoalRun owner backlink",
    )?;
    Ok(json!({
        "owner_record": published,
        "work_result": work_result.unwrap_or(Value::Null),
        "harness_invocation": harness_invocation.unwrap_or(Value::Null),
        "goal_run": updated,
        "room_admission_receipt_ref": room_admission_receipt_ref
    }))
}

fn work_result_goal_ref_for_delta_binding(work_result: &Value) -> Option<&str> {
    work_result.get("work_subject_ref").and_then(Value::as_str)
}

/// POST /v1/goal-orchestration/goal-runs/:id/outcome-deltas — admit a proposed direct-lane
/// OutcomeDelta against one WorkResult already bound to this GoalRun. Identity, subject, inherited
/// information-flow labels, status, effect posture, and receipt are plane-owned. This route never
/// materializes a room and never executes or accepts the proposed effect.
pub(crate) async fn handle_goal_run_outcome_delta_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let resolved_reader = match global_truth_reader(&st, &headers) {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    let Some(goal_run) = (match load_goal_run_for_http(&st.data_dir, &id) {
        Ok(value) => value,
        Err(response) => return response,
    }) else {
        return missing_goal_run_mutation_refusal(resolved_reader.as_deref());
    };
    if let Err(response) =
        authorize_resolved_goal_run_mutation(resolved_reader.as_deref(), &goal_run)
    {
        return response;
    }
    if let Some(response) = refuse_result_write_for_zero_execution_goal(&goal_run) {
        return response;
    }
    let room_ref = text(&goal_run, "outcome_room_ref").to_string();
    let Some(object) = body.as_object_mut() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "outcome_delta_invalid",
            "OutcomeDelta request must be an object.",
        );
    };
    if object.contains_key("inherited_information_flow_label_refs") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "outcome_delta_noncanonical_field_refused",
            "`inherited_information_flow_label_refs` is not a durable OutcomeDelta field; inheritance is checked against the bound WorkResult and retained only in the complete `information_flow_label_refs` set.",
        );
    }
    for plane_owned in [
        "outcome_delta_id",
        "work_subject_ref",
        "outcome_room_ref",
        "room_admission",
        "system_binding",
        "status",
        "effect_executed",
        "acceptance_granted",
        "admission_receipt_ref",
    ] {
        if object
            .get(plane_owned)
            .map(|value| !value.is_null())
            .unwrap_or(false)
        {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "outcome_delta_plane_owned_field_refused",
                &format!("`{plane_owned}` is owned by the GoalRun admission plane."),
            );
        }
    }
    let proposed_by_ref = object
        .get("proposed_by_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !proposed_by_ref.starts_with("work-result://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "outcome_delta_work_result_required",
            "`proposed_by_ref` must name a WorkResult already bound to this GoalRun.",
        );
    }
    let mut work_result =
        match super::work_result_routes::load_work_result_strict(&st.data_dir, &proposed_by_ref) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "outcome_delta_work_result_unbound",
                    "The proposed WorkResult does not resolve.",
                )
            }
            Err(message) => {
                return bad(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "work_result_registry_unreadable",
                    &format!(
                    "The complete versioned WorkResult registry cannot be resolved ({message})."
                ),
                )
            }
        };
    let expected_result_schema = "ioi.foundations.work-result.v3";
    if work_result.get("schema_version").and_then(Value::as_str) != Some(expected_result_schema) {
        return bad(
            StatusCode::CONFLICT,
            "outcome_delta_work_result_contract_mismatch",
            "The proposed WorkResult belongs to a different live contract generation.",
        );
    }
    let work_result_storage_key =
        match super::work_result_routes::resolve_work_result_storage_key_strict(
            &st.data_dir,
            &proposed_by_ref,
        ) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "outcome_delta_work_result_unbound",
                    "The proposed WorkResult storage slot does not resolve.",
                )
            }
            Err(message) => {
                return bad(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "work_result_registry_unreadable",
                    &format!("The WorkResult storage slot cannot be resolved ({message})."),
                )
            }
        };
    let result_is_bound = goal_run
        .get("work_result_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|value| value.as_str() == Some(proposed_by_ref.as_str()))
        });
    let goal_ref = text(&goal_run, "goal_ref").to_string();
    // The substrate-generic WorkResult binds its application owner through work_subject_ref.
    let result_goal_ref = work_result_goal_ref_for_delta_binding(&work_result).unwrap_or("");
    if !result_is_bound || result_goal_ref != goal_ref {
        return bad(
            StatusCode::CONFLICT,
            "outcome_delta_cross_goal_refused",
            "The proposed WorkResult is not bound to this exact GoalRun.",
        );
    }
    let inherited_labels = work_result
        .get("information_flow_label_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let declared_labels = object
        .get("information_flow_label_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let inherited_refs = inherited_labels
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let inherited_set = inherited_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let declared_set = declared_labels
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if inherited_labels.is_empty()
        || inherited_set.len() != inherited_labels.len()
        || declared_set.len() != declared_labels.len()
        || !inherited_set.is_subset(&declared_set)
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "outcome_delta_information_flow_label_inheritance_required",
            "OutcomeDelta must explicitly carry every exact parent WorkResult information-flow label; inherited labels are not silently repaired.",
        );
    }
    let delta_ref = format!("outcome-delta://goal-run/{id}/{:x}", nanos());
    object.insert("outcome_delta_id".into(), json!(delta_ref));
    object.insert("work_subject_ref".into(), json!(goal_ref));
    object.insert("room_admission".into(), Value::Null);
    object.insert(
        "information_flow_label_refs".into(),
        Value::Array(declared_labels),
    );
    let admitted = match GoalPursuitCore.admit_outcome_delta(&body, &inherited_refs) {
        Ok(admitted) => admitted,
        Err(error) => return pursuit_err(error),
    };
    let mut delta = admitted
        .get("outcome_delta")
        .cloned()
        .unwrap_or(Value::Null);
    if !room_ref.is_empty() {
        delta
            .as_object_mut()
            .expect("GoalPursuitCore OutcomeDelta is an object")
            .remove("room_admission");
        delta
            .as_object_mut()
            .expect("GoalPursuitCore OutcomeDelta is an object")
            .remove("outcome_room_ref");
        delta["system_binding"] = Value::Null;
        delta["schema_version"] = json!("ioi.foundations.outcome-delta.v3");
        let room_admission = match super::outcome_room_system_routes::admit_persisted_owner_record(
            &st.data_dir,
            &room_ref,
            &delta,
            None,
        ) {
            Ok(value) => value,
            Err((code, message)) => return bad(seam_status(&code), &code, &message),
        };
        // As with the WorkResult route, this is already the exact pre-effect-bounded HTTP
        // envelope. The delta nonclaims and refs-only convergence summary are produced inside the
        // private room seam; owner records are re-read through their canonical projections.
        return (StatusCode::CREATED, Json(room_admission));
    }
    match super::work_result_routes::load_outcome_delta_strict(&st.data_dir, &delta_ref) {
        Ok(Some(_)) => {
            return bad(
                StatusCode::CONFLICT,
                "outcome_delta_identity_already_exists",
                "The OutcomeDelta identity already resolves in the live versioned registry.",
            )
        }
        Ok(None) => {}
        Err(message) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "outcome_delta_registry_unreadable",
                &format!(
                    "The complete versioned OutcomeDelta registry cannot be resolved ({message})."
                ),
            )
        }
    }
    let admitted_at = iso_now();
    let receipt_ref = format!("receipt://outcome-delta/{}/admission", safe(&delta_ref));
    let artifact_refs: Vec<&str> = delta
        .get("payload_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("artifact://"))
        .into_iter()
        .collect();
    let receipt = receipt_envelope(
        &receipt_ref,
        "outcome_delta_admission",
        &delta_ref,
        &goal_ref,
        admitted
            .get("outcome_delta_hash")
            .and_then(Value::as_str)
            .unwrap_or(""),
        artifact_refs,
        &admitted_at,
    );
    if persist_record(
        &st.data_dir,
        super::work_result_routes::DELTA_DIR,
        &super::work_result_routes::goal_run_work_truth_record_key(&delta_ref),
        &delta,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "outcome_delta_persist_failed",
            "The admitted OutcomeDelta did not persist.",
        );
    }
    if persist_record(
        &st.data_dir,
        "receipts",
        &receipt_file_key(&receipt_ref),
        &receipt,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "outcome_delta_receipt_persist_failed",
            "The admitted OutcomeDelta receipt did not persist; no completion is reported.",
        );
    }
    if let Some(result_object) = work_result.as_object_mut() {
        let mut refs = result_object
            .get("outcome_delta_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        refs.push(json!(delta_ref));
        result_object.insert("outcome_delta_refs".into(), Value::Array(refs));
    }
    if persist_record(
        &st.data_dir,
        super::work_result_routes::RESULT_DIR,
        &work_result_storage_key,
        &work_result,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "outcome_delta_backlink_persist_failed",
            "The WorkResult backlink did not persist; no GoalRun completion is reported.",
        );
    }
    let updated = update_goal_run_guarded(
        &st.data_dir,
        &id,
        |_| Ok(()),
        |run| {
            let mut receipt_refs = run
                .get("receipt_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            receipt_refs.push(json!(receipt_ref));
            run.insert("receipt_refs".into(), Value::Array(receipt_refs));
            run.insert("updated_at".into(), json!(admitted_at));
        },
    );
    let goal_run = match updated {
        Ok(value) => value.into_record(),
        Err((code, message)) => return bad(seam_status(&code), &code, &message),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "admission": admitted,
            "outcome_delta_receipt": receipt,
            "work_result": work_result,
            "goal_run": goal_run,
            "effect_executed": false,
            "acceptance_granted": false,
        })),
    )
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
                    "the reservation token changed while marking the start for recovery"
                        .to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            let mut op = obj
                .get("lifecycle_op")
                .cloned()
                .unwrap_or_else(|| json!({}));
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
/// spawn → events/receipt/transcript → non-canonical result candidate. A successful adapter
/// exit returns `waiting_on_conductor`; only WorkResult convergence can materialize the canonical
/// ImplementationResult and transition the invocation to `completed`. Failure is explicit.
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
            "blocker": { "reason_code": failure_kind, "message": message },
            "started_at": started_at,
            "finished_at": iso_now(),
        })
    };

    // Isolated candidate session (its workspace IS the candidate namespace). The Session family
    // is identity-gated (#246); this spawned worker crosses as the daemon's own dispatch.
    let (status, created) = self_post_internal_dispatch(
        &st,
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
                created
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
            &candidate_session_ref,
            "",
        );
    }
    let session_record =
        match super::lifecycle_routes::load_session_record_strict(&st, &candidate_session_ref) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return fail(
                    "candidate_session_record_missing",
                    "candidate session record not persisted".into(),
                    &candidate_session_ref,
                    "",
                )
            }
            Err(detail) => {
                return fail(
                    "candidate_session_record_unreadable",
                    format!("candidate Session cannot be strictly resolved ({detail})"),
                    &candidate_session_ref,
                    "",
                )
            }
        };
    let workspace = text(&session_record, "workspace_root").to_string();

    // The M4 GoalRun lane has no env fallback. Session creation durably binds one exact route;
    // invocation re-proves the complete binding census and consumes precisely the retained model
    // and endpoint. Missing/malformed/duplicate or stale facts refuse before driver resolution and
    // before host spawn.
    let retained_binding_id = session_record
        .pointer("/model_route_binding/binding_id")
        .and_then(Value::as_str);
    let retained_route_ref = session_record
        .pointer("/model_route_binding/route_ref")
        .and_then(Value::as_str);
    if retained_binding_id.is_none() || retained_route_ref != Some(route_ref.as_str()) {
        return fail(
            "candidate_session_model_route_binding_missing",
            "candidate Session does not retain the exact requested model-route binding".to_string(),
            &candidate_session_ref,
            &workspace,
        );
    }
    let bound_route = match super::model_routes::resolve_session_route_binding_strict(
        &st.data_dir,
        &candidate_session_ref,
        Some(&route_ref),
        retained_binding_id,
    ) {
        Ok(binding) => binding,
        Err(detail) => {
            return fail(
                "candidate_session_model_route_binding_unreadable",
                format!("candidate Session model-route binding refused ({detail})"),
                &candidate_session_ref,
                &workspace,
            )
        }
    };

    let driver = match resolve_adapter_driver(
        &session_record,
        &bound_route.model_id,
        &workspace,
        Some(&bound_route.execution_endpoint),
    ) {
        Ok(Some(driver)) => driver,
        Ok(None) => {
            return fail(
                "adapter_driver_unresolved",
                "implementer session has no wired adapter driver".into(),
                &candidate_session_ref,
                &workspace,
            )
        }
        Err((reason, message)) => return fail(reason, message, &candidate_session_ref, &workspace),
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
    let outcome = run_host_spawn_lane(
        &argv,
        &workspace,
        &delivered_objective,
        Some(&bound_route.execution_endpoint),
    )
    .await;

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
        .map(|file| {
            format!(
                "artifact://goal-run/{}/{}/{}",
                goal_run_id, plan.role_key, file
            )
        })
        .collect();
    let changed_file_values = outcome
        .files_written
        .iter()
        .map(|file| json!(file))
        .collect::<Vec<_>>();
    let output_file_facts =
        match bounded_workspace_output_file_facts(&workspace, &changed_file_values) {
            Ok(files) => json!({
                "domain":"ioi.harness-invocation-output-file-facts-jcs-sha256.v1",
                "files":files,
            }),
            Err((code, message)) => {
                return fail(&code, message, &candidate_session_ref, &workspace)
            }
        };
    let output_file_facts_hash = sha256_canonical(&output_file_facts);
    let shim = argv
        .iter()
        .find(|arg| arg.ends_with("-driver.mjs"))
        .cloned()
        .unwrap_or_default();
    let command_contract_ref = format!("command-contract://harness-shim/{}", safe(&shim));

    // Invocation receipt (admitted authority named).
    let receipt_ref = format!(
        "receipt://hypervisor/goal-run-invocation/{}_{}",
        safe(&goal_run_id),
        plan.role_key
    );
    let receipt = match rooted_runtime_record(
        "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
        "receipt_root",
        json!({
            "id": receipt_ref,
            "receipt_root":Value::Null,
            "kind": "hypervisor.goal-run.invoke",
            "goal_run_ref": goal_ref,
            "harness_invocation_ref": plan.invocation_ref,
            "role_key": plan.role_key,
            "harness": plan.harness,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": bound_route.route_ref,
            "model_route_binding_id": bound_route.binding_id,
            "model_route_binding_receipt_ref": bound_route.receipt_ref,
            "model_id": bound_route.model_id,
            "model_route_base_url": bound_route.base_url,
            "model_route_execution_endpoint": bound_route.execution_endpoint,
            "session_ref": candidate_session_ref,
            "command_contract_ref":command_contract_ref,
            "exit_status": exit_status,
            "exit_code": outcome.exit_code,
            "files_written": outcome.files_written,
            "output_file_facts": output_file_facts,
            "output_file_facts_hash": output_file_facts_hash,
            "adapter_event_refs": adapter_event_refs,
            "capability_lease_ref": capability_lease_ref,
            "started_at": started_at,
            "finished_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        }),
    ) {
        Ok(receipt) => receipt,
        Err((code, message)) => return fail(&code, message, &candidate_session_ref, &workspace),
    };
    if let Err(failure) = persist_record_durable(
        &st.data_dir,
        "receipts",
        &receipt_file_key(&receipt_ref),
        &receipt,
    ) {
        return fail(
            "invocation_receipt_persist_failed",
            format!(
                "the adapter execution cannot become a waiting-on-conductor candidate because its runtime receipt is not durably confirmed ({})",
                failure.detail()
            ),
            &candidate_session_ref,
            &workspace,
        );
    }

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
            "model_route_ref": bound_route.route_ref,
            "model_route_binding_id": bound_route.binding_id,
            "model_route_binding_receipt_ref": bound_route.receipt_ref,
            "model_id": bound_route.model_id,
            "model_route_base_url": bound_route.base_url,
            "model_route_execution_endpoint": bound_route.execution_endpoint,
            "exit_status": exit_status,
            "files_written": outcome.files_written,
            "adapter_event_count": outcome.adapter_events.len(),
            "adapter_result": outcome.implementation_result,
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

    let failure_kind = if outcome.timed_out {
        "timeout"
    } else if outcome.spawn_error.is_some() {
        "spawn_error"
    } else {
        "exit_nonzero"
    };
    let mut invocation = json!({
        "schema_version": INVOCATION_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "harness_invocation_id": plan.invocation_ref,
        "role_key": plan.role_key,
        "context_cell_ref": plan.cell_ref,
        "task_brief_ref": plan.brief_ref,
        "harness_ref": plan.profile_ref,
        "harness": plan.harness,
        "model_route_ref": bound_route.route_ref,
        "model_route_binding_id": bound_route.binding_id,
        "model_route_binding_receipt_ref": bound_route.receipt_ref,
        "model_id": bound_route.model_id,
        "model_route_base_url": bound_route.base_url,
        "model_route_execution_endpoint": bound_route.execution_endpoint,
        "session_ref": candidate_session_ref,
        "candidate_workspace_root": workspace,
        "status": if outcome.ok { "waiting_on_conductor" } else { "failed" },
        "adapter_event_refs": adapter_event_refs,
        "adapter_event_count": outcome.adapter_events.len(),
        "memory_projection_ref": plan.memory_projection_ref,
        // Projection of the receipt just durably committed above. This is not a second receipt;
        // it lets product/operator proof compare the declared invocation facts with the exact
        // durable effect receipt without trusting a free-floating ref.
        "execution_receipt": receipt,
        "started_at": started_at,
        "finished_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    if outcome.ok {
        invocation["implementation_result_candidate"] = json!({
            "candidate_ref": format!("implementation-result-candidate://ir_{}_{}", goal_run_id, plan.role_key),
            "execution_succeeded":true,
            "goal_ref": goal_ref,
            "harness_invocation_ref": plan.invocation_ref,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": bound_route.route_ref,
            "model_route_binding_id": bound_route.binding_id,
            "model_route_binding_receipt_ref": bound_route.receipt_ref,
            "model_id": bound_route.model_id,
            "model_route_base_url": bound_route.base_url,
            "model_route_execution_endpoint": bound_route.execution_endpoint,
            "memory_projection_ref": plan.memory_projection_ref,
            "command_contract_ref": command_contract_ref,
            "workspace_ref": format!("workspace://goal-run/{}/{}", goal_run_id, plan.role_key),
            "workspace_root": workspace,
            "candidate_artifact_refs": candidate_artifact_refs,
            "changed_files": outcome.files_written,
            "summary": outcome.summary,
            "receipt_refs": [receipt_ref],
            "transcript_run_ref": transcript_run,
            "state_root": state_root,
            "driver_result": outcome.implementation_result,
        });
    } else {
        invocation["blocker"] = json!({
            "reason_code":failure_kind,
            "message":outcome.summary,
            "receipt_ref":receipt_ref,
        });
    }
    invocation
}

pub(crate) async fn handle_goal_run_start(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let resolved_reader = match global_truth_reader(&st, &headers) {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    let Some(owner_snapshot) = (match load_goal_run_for_http(&st.data_dir, &id) {
        Ok(value) => value,
        Err(response) => return response,
    }) else {
        return missing_goal_run_mutation_refusal(resolved_reader.as_deref());
    };
    if let Err(response) =
        authorize_resolved_goal_run_mutation(resolved_reader.as_deref(), &owner_snapshot)
    {
        return response;
    }
    if text(&owner_snapshot, "origin_surface") == "ioi_goal_chat" {
        let total = owner_snapshot
            .pointer("/declared_invocation_budget/max_total_invocations")
            .and_then(Value::as_u64);
        let parallel = owner_snapshot
            .pointer("/declared_invocation_budget/max_parallel_invocations")
            .and_then(Value::as_u64);
        let ceiling_ref = owner_snapshot
            .get("goal_run_execution_ceiling_revision_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ceiling_hash = owner_snapshot
            .get("goal_run_execution_ceiling_content_hash")
            .and_then(Value::as_str)
            .unwrap_or("");
        if total != Some(0)
            || parallel != Some(0)
            || !ceiling_ref
                .starts_with("goal-run-execution-ceiling://ioi-goal-draft-zero/revision/sha256:")
            || !ceiling_ref.ends_with(ceiling_hash)
        {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_execution_bounds_integrity_failure",
                "The ioi_goal_draft GoalRun no longer retains its exact zero-execution ceiling and declared budget.",
            );
        }
        return bad_with_details(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_execution_budget_exhausted",
            "This admitted GoalRun is intentionally resultless and has zero invocation capacity.",
            json!({
                "goal_run_ref": owner_snapshot.get("goal_ref"),
                "goal_run_execution_ceiling_revision_ref": ceiling_ref,
                "declared_invocation_budget": owner_snapshot.get("declared_invocation_budget"),
                "effects_started": false
            }),
        );
    }
    if text(&owner_snapshot, "status") != "draft" {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_already_started",
            "This GoalRun has already been started.",
        );
    }
    // Resolve every registry occupant and the exact retained route BEFORE reserving the GoalRun,
    // crossing wallet authority, creating a candidate Session, or spawning a harness.
    let start_profiles = match super::harness_routes::live_profiles_strict(&st) {
        Ok(profiles) => profiles,
        Err(detail) => {
            return bad_with_details(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_start_harness_registry_unreadable",
                "The complete live harness-profile registry cannot authorize GoalRun start.",
                json!({ "detail": detail }),
            )
        }
    };
    let start_route_fact =
        match super::model_routes::route_fact_strict(
            &st.data_dir,
            owner_snapshot
                .pointer("/role_topology/model_route_ref")
                .and_then(Value::as_str),
        ) {
            Ok(fact) => fact,
            Err(detail) => return bad_with_details(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_start_model_route_registry_unreadable",
                "The exact retained model route cannot be strictly resolved before GoalRun start.",
                json!({ "detail": detail }),
            ),
        };
    let authorized_owner = owner_snapshot
        .get("owner_ref")
        .cloned()
        .unwrap_or(Value::Null);
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
            if fresh.get("owner_ref") != Some(&authorized_owner) {
                return Err((
                    "goal_run_mutation_owner_changed".to_string(),
                    "GoalRun ownership changed after lifecycle authorization.".to_string(),
                ));
            }
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
        // DURABLE REQUIRED before any authority or effect boundary (#72 round 9 finding 1): a
        // wallet crossing or harness effect must never rest on a reservation a crash can
        // un-happen — the later token-CAS would prevent finalization but could not undo the
        // external work nor stop a duplicate retry. The visible reservation stays for the
        // token-addressed recovery transition; if the crash loses it, nothing happened at all.
        Ok(MutationOutcome::Durable(run)) => run,
        Ok(MutationOutcome::VisibleUnconfirmed(_, note)) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_reservation_durability_unconfirmed",
                &format!("the start reservation is visible but not durably confirmed ({note}); NO wallet, harness, or filesystem effect was performed — release the visible reservation via the token-addressed lifecycle-recovery transition and retry"),
            );
        }
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal = text(&run, "normalized_goal").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    // Wallet authority gate — one admitted crossing covers the run's bounded invocations; the
    // lease ref is named on every invocation receipt. 403 challenge shape identical to execute.
    // A refusal here happened before any side effect: release the reservation so the draft is
    // exactly re-runnable; a failed release is itself a typed 5xx, never a silent wedge.
    let capability_lease_ref = match execute_authority_gate(
        &st.data_dir,
        &body,
        &goal_ref,
        &target_workspace,
        &goal,
    )
    .await
    {
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
    let profiles = start_profiles;
    let (route_ref, route_state, _, _) = start_route_fact;
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
        let invocation_ref = format!("harness-invocation://hi_{goal_run_id}_{role_key}");
        let brief_ref = format!("task-brief://tb_{goal_run_id}_{role_key}");
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
            object.insert(
                "context_cell_ref".into(),
                json!(text(cell, "context_cell_id")),
            );
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
        let changed_values = invocation_changed_files(invocation);
        let changed: Vec<&str> = changed_values.iter().filter_map(Value::as_str).collect();
        let execution_succeeded = text(invocation, "status") == "waiting_on_conductor"
            && invocation
                .pointer("/implementation_result_candidate/execution_succeeded")
                .and_then(Value::as_bool)
                == Some(true)
            && invocation
                .pointer("/execution_receipt/exit_status")
                .and_then(Value::as_str)
                == Some("success")
            && invocation
                .pointer("/execution_receipt/exit_code")
                .and_then(Value::as_i64)
                == Some(0);
        let mut checks: Vec<Value> = vec![json!({
            "check": "invocation_execution_succeeded_exit_zero",
            "pass": execution_succeeded,
        })];
        let mut files_real = execution_succeeded && !changed.is_empty();
        if execution_succeeded {
            for file in &changed {
                // Containment is part of the verdict (#72 round 5 finding 1): a path that
                // escapes its workspace never verifies, so it can never be selected for the
                // reconcile copy pipeline.
                let real = match contained_rel_path(file) {
                    Ok(rel) => {
                        let path = std::path::Path::new(workspace).join(rel);
                        path.exists()
                            && std::fs::metadata(&path)
                                .map(|m| m.len() > 0)
                                .unwrap_or(false)
                    }
                    Err(_) => false,
                };
                checks.push(json!({ "check": "reported_file_exists_with_content", "file": file, "pass": real }));
                files_real &= real;
            }
            checks.push(
                json!({ "check": "workspace_mutation_reported", "pass": !changed.is_empty() }),
            );
        }
        let verdict = execution_succeeded && files_real;
        let verification = match rooted_runtime_record(
            "ioi.goal-run-conductor-verification-jcs-sha256.v1",
            "verification_root",
            json!({
                "verification_id": verification_id,
                "verification_ref": format!("agentgres://goal-run-verification/{verification_id}"),
                "verification_root":Value::Null,
                "goal_run_id": goal_run_id,
                "goal_ref": goal_ref,
                "harness_invocation_ref": text(invocation, "harness_invocation_id"),
                "implementation_result_candidate_ref": invocation_result_candidate_ref(invocation),
                "verifier_path_ref": format!("verifier-path://vp_{goal_run_id}"),
                "verification_kind": "deterministic",
                "verdict": if verdict { "pass" } else { "fail" },
                "checks": checks,
                "verified_at": iso_now(),
                "runtimeTruthSource": "daemon-runtime",
            }),
        ) {
            Ok(verification) => verification,
            Err((code, message)) => {
                return start_evidence_abort(
                    &st.data_dir,
                    &goal_run_id,
                    &op_token,
                    VERIFICATION_KIND,
                    &verification_id,
                    &format!("{code}: {message}"),
                    &invocations,
                )
            }
        };
        // CHECKED persist (#72 round 4 finding 2): a ref is bound ONLY after its record is
        // durable — a failed side-record write refuses typed with recovery state, never a 200
        // over nonexistent records.
        if let Err(e) = persist_record_durable(
            &st.data_dir,
            VERIFICATION_KIND,
            &verification_id,
            &verification,
        ) {
            return start_evidence_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                VERIFICATION_KIND,
                &verification_id,
                &e.detail(),
                &invocations,
            );
        }
        verification_refs.push(format!(
            "agentgres://goal-run-verification/{verification_id}"
        ));
    }

    // Persist invocation records + update the run (checked, same discipline).
    let mut invocation_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let record_id = format!("{}_{}", safe(&goal_run_id), text(invocation, "role_key"));
        if let Err(e) =
            persist_record_durable(&st.data_dir, INVOCATION_KIND, &record_id, invocation)
        {
            return start_evidence_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                INVOCATION_KIND,
                &record_id,
                &e.detail(),
                &invocations,
            );
        }
        invocation_refs.push(text(invocation, "harness_invocation_id").to_string());
    }
    let blockers: Vec<Value> = invocations
        .iter()
        .filter(|invocation| text(invocation, "status") == "failed")
        .filter_map(|invocation| {
            invocation.get("blocker").cloned().or_else(|| {
                Some(json!({
                    "reason_code":"failed",
                    "message":"the invocation failed without structured blocker evidence",
                    "role_key": text(invocation, "role_key"),
                }))
            })
        })
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
                    "start finalization no longer holds the reservation token — refusing to commit"
                        .to_string(),
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
        // FORWARD on visible-unconfirmed (#72 round 8 finding 1): the run is visibly active; if
        // a crash reverts it the reservation reappears and the token-addressed recovery
        // transition resolves it — never reported as "not started" while readers see `active`.
        Ok(outcome) => outcome.into_record(),
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
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let resolved_reader = match global_truth_reader(&st, &headers) {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    let Some(owner_snapshot) = (match load_goal_run_for_http(&st.data_dir, &id) {
        Ok(value) => value,
        Err(response) => return response,
    }) else {
        return missing_goal_run_mutation_refusal(resolved_reader.as_deref());
    };
    if let Err(response) =
        authorize_resolved_goal_run_mutation(resolved_reader.as_deref(), &owner_snapshot)
    {
        return response;
    }
    let authorized_owner = owner_snapshot
        .get("owner_ref")
        .cloned()
        .unwrap_or(Value::Null);
    // OPERATION RESERVATION (#72 round 3 finding 2): reconcile is one-shot — `active ->
    // reconciling` is reserved atomically with a stable operation token BEFORE any await, so of
    // two simultaneous reconciles exactly one wins; the loser sees `reconciling` in the SAME
    // CAS predicate and refuses typed. Finalization commits only while it still holds this
    // token, and every refusal/rollback path releases the reservation back to `active`.
    // The authority challenge and its authorized retry MUST hash the same logical effect. A
    // client idempotency key therefore derives one bounded opaque token; alternatively the
    // caller may echo the token returned by an earlier challenge. The token grants no authority
    // by itself — it is merely part of the wallet-bound request hash and the CAS reservation.
    let requested_operation_token = body
        .get("operation_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if requested_operation_token.is_some_and(|token| {
        !token.starts_with("lop_")
            || token.len() > 96
            || !token
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    }) {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_reconcile_operation_token_invalid",
            "operation_token must be the bounded opaque lop_ token returned by this route.",
        );
    }
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if idempotency_key
        .is_some_and(|key| !(8..=200).contains(&key.len()) || key.chars().any(char::is_control))
    {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_reconcile_idempotency_key_invalid",
            "idempotency_key must contain 8..200 non-control characters.",
        );
    }
    let derived_operation_token = idempotency_key.map(|key| {
        let hash = sha256_canonical(&json!({
            "domain": "hypervisor.goal-run.reconcile.operation.v1",
            "goal_run_id": id,
            "idempotency_key": key
        }));
        format!(
            "lop_{}",
            hash.strip_prefix("sha256:")
                .unwrap_or(&hash)
                .chars()
                .take(32)
                .collect::<String>()
        )
    });
    if let (Some(echoed), Some(derived)) = (requested_operation_token, &derived_operation_token) {
        if echoed != derived {
            return bad(
                StatusCode::CONFLICT,
                "goal_run_reconcile_operation_identity_conflict",
                "operation_token does not match the logical attempt selected by idempotency_key.",
            );
        }
    }
    let op_token = derived_operation_token
        .or_else(|| requested_operation_token.map(str::to_string))
        .unwrap_or_else(|| format!("lop_{:x}", nanos()));
    let reserved_at = iso_now();
    // Membership seals one room head against one exact GoalRun predecessor and then stamps the
    // reciprocal GoalRun under the fixed ROOM -> GOAL lock order. Reconcile must reserve its
    // lifecycle successor under that same outer room lock or it can invalidate membership's
    // already-admitted dual-head CAS between room admission and the GoalRun stamp. Hold only for
    // this synchronous reservation; no await crosses the guard.
    let room_guard = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if fresh.get("owner_ref") != Some(&authorized_owner) {
                return Err((
                    "goal_run_mutation_owner_changed".to_string(),
                    "GoalRun ownership changed after lifecycle authorization.".to_string(),
                ));
            }
            if text(fresh, "status") != "active" {
                return Err((
                    "goal_run_not_reconcilable".to_string(),
                    "Reconciliation applies to a started (active) GoalRun exactly once."
                        .to_string(),
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
        // DURABLE REQUIRED before any effect boundary (#72 round 9 finding 1): reconcile writes
        // receipts, records, and target files — none may rest on a crash-revertible
        // reservation, or a lost rename re-opens the one-shot to a duplicate retry.
        Ok(MutationOutcome::Durable(run)) => run,
        Ok(MutationOutcome::VisibleUnconfirmed(_, note)) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_reservation_durability_unconfirmed",
                &format!("the reconcile reservation is visible but not durably confirmed ({note}); NO receipt, record, or target effect was performed — release the visible reservation via the token-addressed lifecycle-recovery transition and retry"),
            );
        }
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    drop(room_guard);
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
                == invocation
                    .get("harness_invocation_id")
                    .and_then(Value::as_str)
                && text(verification, "verdict") == "pass"
        })
    };
    let mut passed: Vec<&Value> = invocations.iter().filter(|i| verdict_of(i)).collect();
    passed.sort_by(|a, b| text(a, "role_key").cmp(text(b, "role_key")));
    let result_ref = |invocation: &Value| -> String {
        invocation_result_candidate_ref(invocation)
            .or_else(|| {
                invocation
                    .pointer("/implementation_result/implementation_result_id")
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .to_string()
    };
    let changed_of = |invocation: &Value| -> Vec<String> {
        invocation_changed_files(invocation)
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };

    // Deterministic strategy selection.
    let (merge_strategy, selected, reason_code): (&str, Vec<&Value>, String) = if passed.is_empty()
    {
        (
            "none_blocked",
            Vec::new(),
            "no_verified_candidate".to_string(),
        )
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

    // Reconciliation is its own target-workspace effect. The authority used to start the
    // implementer batch is evidence for that earlier operation only; it is never a standing
    // lease for this later commit. Consume a separately bound use after the durable operation
    // reservation and deterministic selection, but before staging or target-workspace writes.
    let authority_effect = json!({
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "operation_token": op_token,
        "target_workspace_root": target_workspace,
        "merge_strategy": merge_strategy,
        "selected_candidate_refs": selected_refs,
        "rejected_candidate_refs": rejected_refs,
        "verifier_evidence_refs": verifier_evidence_refs,
        "kernel_admission": admission,
    });
    let policy_hash = sha256_canonical(&json!({
        "domain": "hypervisor.goal-run.reconcile.policy.v1",
        "goal_run_id": goal_run_id,
        "scope": "scope:hypervisor.live-route.goalrun-reconcile",
    }));
    let request_hash = sha256_canonical(&json!({
        "domain": "hypervisor.goal-run.reconcile.request.v1",
        "effect": authority_effect,
    }));
    let grant = body
        .get("wallet_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let admitted = super::governed_authority::authorize_deployment_grant(
        &st.data_dir,
        &grant,
        "scope:hypervisor.live-route.goalrun-reconcile",
        &policy_hash,
        &request_hash,
        &format!("goal-run:{goal_run_id}"),
        "reconcile",
        1,
        &authority_effect,
    )
    .await;
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err((_status, Json(challenge))) => {
            if let Err((rcode, rmsg)) =
                release_lifecycle_reservation(&st.data_dir, &id, &op_token, "active")
            {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "goal_run_release_failed",
                    &format!("reconciliation authority refused AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
                );
            }
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "reason": "reconciliation_authority_required",
                    "operation_token": op_token,
                    "approval": {
                        "policy_hash": policy_hash,
                        "request_hash": request_hash,
                        "operation_token": op_token
                    },
                    "authority_challenge": challenge,
                    "runtimeTruthSource": "daemon-runtime",
                })),
            );
        }
    };
    if let Err(reason) =
        super::governed_authority::revalidate_admission_receipt(&st.data_dir, &admitted).await
    {
        return reconcile_abort(
            &st.data_dir,
            &id,
            &op_token,
            "reconciliation_authority_receipt_unavailable",
            &reason,
        );
    }

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
            .and_then(|p| nofollow_fs::open_dir_pinned(&p).map(|fd| (p, fd)))
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
                );
            }
        }
    };
    // BOUNDED INTAKE (#72 round 7 finding 4): the declared file COUNT refuses before any read;
    // per-file and per-attempt byte budgets are enforced by fstat before bytes move.
    let declared_count: usize = selected.iter().map(|i| changed_of(i).len()).sum();
    if declared_count > MAX_OUTPUT_FILES {
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_output_too_many_files",
            &format!("{declared_count} declared output files exceed the per-attempt limit of {MAX_OUTPUT_FILES}; nothing was read or written"),
        );
    }
    let mut planned_files: Vec<(String, std::path::PathBuf, std::path::PathBuf, String, u64)> =
        Vec::new();
    let mut planned_set: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    let mut total_bytes: u64 = 0;
    let mut escape_errors: Vec<String> = Vec::new();
    let mut collision_errors: Vec<String> = Vec::new();
    let mut bound_errors: Vec<(&str, String)> = Vec::new();
    let mut staging_errors: Vec<String> = Vec::new();
    for invocation in &selected {
        let candidate_workspace = text(invocation, "candidate_workspace_root");
        // The candidate root is PINNED once; every source byte is read through NOFOLLOW
        // descriptor walks from it (#72 round 6 finding 3) — validation and read are the SAME
        // syscall, so no swap window exists between them.
        let candidate_root =
            nofollow_fs::open_dir_pinned(std::path::Path::new(candidate_workspace)).ok();
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
                staging_errors.push(format!(
                    "{file}: candidate workspace '{candidate_workspace}' does not resolve/pin"
                ));
                continue;
            };
            let remaining = MAX_ATTEMPT_TOTAL_BYTES.saturating_sub(total_bytes);
            let budget = MAX_OUTPUT_FILE_BYTES.min(remaining);
            let bytes = match nofollow_fs::read_contained(candidate_root, &rel, budget) {
                Ok(bytes) => bytes,
                Err(nofollow_fs::ReadRefusal::Escape(e)) => {
                    escape_errors.push(format!("candidate: '{}' walks through a symlink/non-directory component ({e}) — descriptor-relative reads never follow it", rel.display()));
                    continue;
                }
                Err(nofollow_fs::ReadRefusal::NotRegular(kind)) => {
                    bound_errors.push(("goal_run_output_file_not_regular", format!("'{}' is not a regular file ({kind}) — FIFOs, devices, and sockets never enter an output commit", rel.display())));
                    continue;
                }
                Err(nofollow_fs::ReadRefusal::TooLarge(size)) => {
                    let code = if size > MAX_OUTPUT_FILE_BYTES {
                        "goal_run_output_file_too_large"
                    } else {
                        "goal_run_output_attempt_too_large"
                    };
                    bound_errors.push((code, format!("'{}' ({size} bytes) exceeds the byte budget (file limit {MAX_OUTPUT_FILE_BYTES}, attempt limit {MAX_ATTEMPT_TOTAL_BYTES})", rel.display())));
                    continue;
                }
                Err(nofollow_fs::ReadRefusal::Io(e)) => {
                    staging_errors.push(format!("{file}: candidate source read failed ({e})"));
                    continue;
                }
            };
            total_bytes += bytes.len() as u64;
            let sha = sha256_hex(&bytes);
            // DURABLE staging (#72 round 7 finding 2): the staged attempt must survive a host
            // crash exactly as declared — atomic write, file fsync, directory-chain fsync.
            match stage_one(&st.data_dir, &staging_root, &rel, &bytes) {
                Ok(staged) => {
                    planned_files.push((file.clone(), staged, rel, sha, bytes.len() as u64))
                }
                Err(e) => staging_errors.push(format!("{file}: durable staging failed ({e})")),
            }
        }
    }
    let bound_code: &str = bound_errors
        .first()
        .map(|(c, _)| *c)
        .unwrap_or("goal_run_output_bounds");
    let bound_msgs: Vec<String> = bound_errors.iter().map(|(_, m)| m.clone()).collect();
    for (code, errors) in [
        ("goal_run_output_path_escape", &escape_errors),
        ("goal_run_output_path_collision", &collision_errors),
        (bound_code, &bound_msgs),
        ("goal_run_output_staging_failed", &staging_errors),
    ] {
        if !errors.is_empty() {
            // CLASSIFIED — rollback/cleanup: plane-owned staging scratch; every failure lane deliberately PRESERVES staging as the immutable declared input (#72 r5 f3), and on terminal success no truth claim rests on the directory being gone.
            let _ = std::fs::remove_dir_all(&staging_root);
            return reconcile_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                code,
                &format!("output validation/staging refused ({}); no receipt was written and the target workspace was NOT touched", errors.join("; ")),
            );
        }
    }
    let planned_list: Vec<String> = planned_files
        .iter()
        .map(|(f, _, _, _, _)| f.clone())
        .collect();
    // The staged manifest binds per-file hashes + sizes into the PRE-OUTPUT receipt (#72 round
    // 7 finding 2): a restart validates the surviving staged bytes against exactly this.
    let staged_manifest: Vec<Value> = planned_files
        .iter()
        .map(|(f, _, _, sha, len)| json!({ "file": f, "sha256": sha, "bytes": len }))
        .collect();

    let receipt_ref = format!("receipt://hypervisor/goal-run-reconciliation/{attempt_id}");
    // The attempt-scoped operation record builder — defined BEFORE anything persists, because
    // the DECLARED record is now the first durable artifact (#72 round 8 finding 2).
    let blocked = merge_strategy == "none_blocked";
    let base_record = |status: &str,
                       final_files: &[String],
                       journal: &[Value],
                       copy_errors: &[String],
                       transcript: &Option<String>,
                       state_root: &str| {
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
            "staged_output_manifest": staged_manifest,
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

    // ATTEMPT DECLARATION FIRST (#72 round 8 finding 2): the operation record (status
    // `declared`, manifest included) is durable BEFORE the receipt, so any receipt-state
    // uncertainty always has a resolving attempt record and a retained backlink — a visible
    // receipt can never be orphaned. From this point the transaction DELETES NOTHING: every
    // refusal preserves the declared attempt and appends its ref on release.
    let declared = base_record("declared", &[], &[], &[], &None, "");
    if let Err(f) = persist_record_durable(
        &st.data_dir,
        RECONCILIATION_KIND,
        &reconciliation_id,
        &declared,
    ) {
        if f.visible() {
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &base_record("aborted_before_output_admission", &[], &[], &[], &None, ""),
                "goal_run_reconciliation_durability_unconfirmed",
                &format!("the attempt declaration is {}; the declared attempt and its staging are preserved, the target workspace was NOT touched", f.detail()),
            );
        }
        // CLASSIFIED — rollback/cleanup: plane-owned staging scratch; every failure lane deliberately PRESERVES staging as the immutable declared input (#72 r5 f3), and on terminal success no truth claim rests on the directory being gone.
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_reconciliation_persist_failed",
            &format!("the attempt declaration is {}; no receipt was written and the target workspace was NOT touched", f.detail()),
        );
    }

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
        "staged_output_manifest": staged_manifest,
        "attempt_token": op_token,
        "output_commit_policy": "declared_then_receipted: the attempt declaration precedes this receipt, this receipt precedes ANY target-workspace effect, and the attempt-scoped operation record write-ahead-journals the per-file commit",
        "reason_codes": [reason_code],
        "admission_id": text(&admission, "admission_id"),
        "capability_lease_ref": run.get("capability_lease_ref").cloned().unwrap_or(Value::Null),
        "target_session_ref": text(&run, "target_session_ref"),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    // Receipt second (#72 round 8 finding 2): EITHER failure class now aborts WITH a resolving
    // attempt record and a retained backlink — nothing is ever deleted, so the non-durable
    // unlink lane no longer exists in this transaction at all.
    if let Err(f) = persist_record_durable(
        &st.data_dir,
        "receipts",
        &receipt_file_key(&receipt_ref),
        &receipt,
    ) {
        let (code, note) = if f.visible() {
            ("goal_run_reconcile_receipt_durability_unconfirmed", "the VISIBLE receipt, the declared attempt record, and the staged manifest are all preserved and linked")
        } else {
            ("goal_run_reconcile_receipt_persist_failed", "no receipt was admitted; the declared attempt record and its staging are preserved and linked")
        };
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &base_record("aborted_before_output_admission", &[], &[], &[], &None, ""),
            code,
            &format!(
                "the reconciliation receipt is {}; {note}; the target workspace was NOT touched",
                f.detail()
            ),
        );
    }

    // Operation record advances to `committing` before any target effect.
    let committing = base_record("committing", &[], &[], &[], &None, "");
    if let Err(f) = persist_record_durable(
        &st.data_dir,
        RECONCILIATION_KIND,
        &reconciliation_id,
        &committing,
    ) {
        let code = if f.visible() {
            "goal_run_reconciliation_durability_unconfirmed"
        } else {
            "goal_run_reconciliation_persist_failed"
        };
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &base_record("aborted_before_output_admission", &[], &[], &[], &None, ""),
            code,
            &format!("the committing transition is {}; the declared attempt, its receipt, and its staging are preserved and linked; the target workspace was NOT touched", f.detail()),
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
    for (file, staged, rel, _sha, _len) in &planned_files {
        commit_journal.push(json!({ "file": file, "phase": "applying", "at": iso_now() }));
        if let Err(f) = persist_record_durable(
            &st.data_dir,
            RECONCILIATION_KIND,
            &reconciliation_id,
            &base_record(
                "committing",
                &final_changed_files,
                &commit_journal,
                &copy_errors,
                &None,
                "",
            ),
        ) {
            commit_journal.pop();
            let preserved = base_record(
                "recovery_required",
                &final_changed_files,
                &commit_journal,
                &copy_errors,
                &None,
                "",
            );
            let code = if f.visible() {
                "goal_run_commit_journal_durability_unconfirmed"
            } else {
                "goal_run_commit_journal_persist_failed"
            };
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                code,
                &format!(
                    "the write-ahead journal entry for '{file}' is {}; '{file}' was NOT applied",
                    f.detail()
                ),
            );
        }
        commit_journal.pop();
        let Some(target_root_fd) = target_root_fd.as_ref() else {
            copy_errors.push(format!(
                "{file}: no pinned target root (planned files with an empty selection is a bug)"
            ));
            commit_journal.push(json!({ "file": file, "applied": false, "error": "no pinned target root", "at": iso_now() }));
            continue;
        };
        match commit_one(staged, target_root_fd, rel) {
            Ok((bytes, sha)) => {
                final_changed_files.push(file.clone());
                commit_journal.push(json!({ "file": file, "applied": true, "bytes": bytes, "sha256": sha, "at": iso_now() }));
            }
            Err(CommitFailure::NotApplied(e)) => {
                copy_errors.push(format!("{file}: {e}"));
                commit_journal
                    .push(json!({ "file": file, "applied": false, "error": e, "at": iso_now() }));
            }
            Err(CommitFailure::AppliedDurabilityUnconfirmed {
                bytes,
                sha256,
                error,
            }) => {
                // #72 round 7 finding 1: the COMPLETE destination is visible — the journal
                // records unknown-but-possibly-applied, NEVER `applied: false`.
                copy_errors.push(format!("{file}: applied (visible) but {error}"));
                commit_journal.push(json!({ "file": file, "applied": "unknown", "possibly_applied": true, "bytes": bytes, "sha256": sha256, "error": error, "at": iso_now() }));
            }
        }
        if let Err(f) = persist_record_durable(
            &st.data_dir,
            RECONCILIATION_KIND,
            &reconciliation_id,
            &base_record(
                "committing",
                &final_changed_files,
                &commit_journal,
                &copy_errors,
                &None,
                "",
            ),
        ) {
            let preserved = base_record(
                "recovery_required",
                &final_changed_files,
                &commit_journal,
                &copy_errors,
                &None,
                "",
            );
            let code = if f.visible() {
                "goal_run_commit_journal_durability_unconfirmed"
            } else {
                "goal_run_commit_journal_persist_failed"
            };
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                code,
                &format!("the applied-journal entry for '{file}' is {}", f.detail()),
            );
        }
    }
    if !copy_errors.is_empty() {
        let preserved = base_record(
            "failed_partial_commit",
            &final_changed_files,
            &commit_journal,
            &copy_errors,
            &None,
            "",
        );
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
    if let Err(f) = persist_record_durable(
        &st.data_dir,
        RECONCILIATION_KIND,
        &reconciliation_id,
        &reconciliation,
    ) {
        let preserved = base_record(
            "recovery_required",
            &final_changed_files,
            &commit_journal,
            &[],
            &transcript_run,
            &state_root,
        );
        let code = if f.visible() {
            "goal_run_reconciliation_finalize_durability_unconfirmed"
        } else {
            "goal_run_reconciliation_finalize_failed"
        };
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &preserved,
            code,
            &format!("the committed outputs are in the target but the operation record's final update is {}", f.detail()),
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
            object.insert(
                "status".into(),
                json!(if blocked { "blocked" } else { "complete" }),
            );
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
            if !attempts
                .iter()
                .any(|a| a.as_str() == Some(attempt_ref.as_str()))
            {
                attempts.push(json!(attempt_ref));
            }
            object.insert("reconciliation_attempt_refs".into(), Value::Array(attempts));
            object.insert(
                "final_changed_files".into(),
                json!(reconciliation["final_changed_files"]),
            );
            object.insert("updated_at".into(), json!(iso_now()));
            object.remove("lifecycle_op");
        },
    ) {
        // FORWARD on visible-unconfirmed (#72 round 8 finding 1): the run visibly completed; a
        // crash-revert resurfaces the reservation, which the recovery transition resolves.
        Ok(outcome) => outcome.into_record(),
        Err((code, msg)) => {
            let preserved = base_record(
                "recovery_required",
                &final_changed_files,
                &commit_journal,
                &[],
                &transcript_run,
                &state_root,
            );
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
    // CLASSIFIED — rollback/cleanup: plane-owned staging scratch; every failure lane deliberately PRESERVES staging as the immutable declared input (#72 r5 f3), and on terminal success no truth claim rests on the directory being gone.
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
fn recovery_request_hash(
    goal_run_id: &str,
    token: &str,
    resolution: &str,
    failure_hash: &str,
) -> String {
    sha256_canonical(&json!({
        "domain": "hypervisor.goal-run.lifecycle-recovery.request.v1",
        "goal_run_id": goal_run_id,
        "op_token": token,
        "resolution": resolution,
        "failure_hash": failure_hash,
        "scopes": RECOVERY_AUTHORITY_SCOPES,
    }))
}

/// POST /v1/goal-orchestration/goal-runs/:id/lifecycle-recovery (#72 rounds 4 + 5): the recovery
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
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let resolved_reader = match global_truth_reader(&st, &headers) {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    let Some(token) = body
        .get("op_token")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
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
    let snapshot = match load_goal_run_by_id_strict(&st.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => return missing_goal_run_mutation_refusal(resolved_reader.as_deref()),
        Err(message) => {
            eprintln!("GoalRun registry refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_registry_unreadable",
                "GoalRun truth cannot be resolved from the complete strict registry census.",
            );
        }
    };
    if let Err(response) =
        authorize_resolved_goal_run_mutation(resolved_reader.as_deref(), &snapshot)
    {
        return response;
    }
    // No ambient administrator/delegate lane is inferred here. Until canon names a recovery
    // delegation contract, the authenticated owner plus the separately consumed wallet grant
    // are both required.
    let authorized_owner = snapshot.get("owner_ref").cloned().unwrap_or(Value::Null);
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
    // LIVE staged-evidence validation (#72 round 8 finding 3): the authority decides over the
    // reservation, the attempt record, AND the actual staged bytes — bound together into the
    // failure hash the grant must carry.
    let staging_validation = validate_staged_manifest(&attempt_record);
    let failure_hash = sha256_canonical(&json!({
        "lifecycle_op": snapshot_op,
        "attempt_record": attempt_record,
        "staging_validation": staging_validation,
    }));
    let policy_hash = recovery_policy_hash(&id);
    let request_hash = recovery_request_hash(&id, &token, resolution, &failure_hash);
    let grant_value = body
        .get("wallet_approval_grant")
        .cloned()
        .unwrap_or(Value::Null);
    let admitted = if grant_value.is_null() {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": {"message": "a wallet_approval_grant is required"}})),
        ))
    } else {
        super::governed_authority::authorize_deployment_grant(
            &st.data_dir,
            &grant_value,
            "scope:hypervisor.live-route.goalrun-lifecycle-recovery",
            &policy_hash,
            &request_hash,
            &format!("goal-run:{id}"),
            "lifecycle-recovery",
            1,
            &json!({
                "goal_run_id": id,
                "operation_token": token,
                "resolution": resolution,
                "failure_hash": failure_hash,
                "staging_validation": staging_validation,
            }),
        )
        .await
    };
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err((_status, Json(challenge))) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "reason": "recovery_authority_required",
                    "message": format!("Releasing a lifecycle reservation requires independently resolved and consumed owner authority ({challenge}). Bind a wallet grant to policy_hash {policy_hash} + request_hash {request_hash}."),
                    "required_scopes": RECOVERY_AUTHORITY_SCOPES,
                    "approval": { "policy_hash": policy_hash, "request_hash": request_hash },
                    "failure_hash": failure_hash,
                    "staging_validation": staging_validation,
                    "runtimeTruthSource": "daemon-runtime",
                })),
            );
        }
    };
    if let Err(reason) =
        super::governed_authority::revalidate_admission_receipt(&st.data_dir, &admitted).await
    {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery_authority_receipt_unavailable",
            &reason,
        );
    }
    let acting_authority_id = admitted.authorized.evidence.acting_authority_id.clone();
    let authority_grant_ref = admitted.authorized.evidence.grant_ref.clone();
    let authority_grant_hash = sha256_canonical(&grant_value);

    // ONE CRITICAL SECTION (#72 round 5 finding 5) RUNNING A DURABLE INTENT TRANSACTION (#72
    // round 6 finding 4): under the GoalRun mutation lock — so no operation can interleave —
    // the transaction is (1) CAS re-verification (token AND the attempt-covering failure hash,
    // recomputed from durable state), (2) durable RECOVERY-INTENT write (the run keeps its
    // reservation; the intent seals the full receipt and release facts), (3) durable receipt
    // persist, (4) durable release. A crash between ANY of those steps leaves a state the boot
    // completer finishes FORWARD deterministically — nothing is guessed at restart, and a
    // synchronous receipt failure rolls the intent back exactly. No .await under the lock.
    let _guard = GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let prior = match load_goal_run_by_id_strict(&st.data_dir, &id) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return bad(
                StatusCode::NOT_FOUND,
                "goal_run_not_found",
                "Unknown GoalRun.",
            )
        }
        Err(message) => {
            eprintln!("GoalRun registry refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_registry_unreadable",
                "GoalRun truth cannot be resolved from the complete strict registry census.",
            );
        }
    };
    if prior.get("owner_ref") != Some(&authorized_owner) {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_mutation_owner_changed",
            "GoalRun ownership changed after lifecycle-recovery authorization.",
        );
    }
    let prior_op = prior.get("lifecycle_op").cloned().unwrap_or(Value::Null);
    let prior_attempt = read_attempt_record(
        &st.data_dir,
        prior_op.get("attempt_ref").and_then(Value::as_str),
    );
    // Re-validate the STAGED BYTES under the lock (#72 round 8 finding 3): a staged file
    // mutated or deleted after the challenge changes this hash and forces a new challenge
    // carrying the damaged-state facts.
    let lock_staging_validation = validate_staged_manifest(&prior_attempt);
    let recomputed_hash = sha256_canonical(&json!({
        "lifecycle_op": prior_op,
        "attempt_record": prior_attempt,
        "staging_validation": lock_staging_validation,
    }));
    if prior_op.get("token").and_then(Value::as_str) != Some(token.as_str())
        || recomputed_hash != failure_hash
    {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_operation_conflict",
            "the reservation, its attempt evidence, or its STAGED BYTES changed between the authority gate and the release — re-read the run and re-challenge (the new challenge carries the damaged-state facts)",
        );
    }
    if prior.get("recovery_intent").is_some() {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_recovery_in_flight",
            "a durable recovery intent already exists for this run — the boot completer (or the original request) finishes it deterministically",
        );
    }
    let prior_status = prior
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
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
    // A crash BEFORE any attempt record was admitted (#72 round 7 finding 3): the recovery
    // CREATES the attempt record it is about to retain, so no released ref ever dangles. Built
    // BEFORE the receipt so the receipt can bind the record's canonical hash (#72 round 8
    // finding 4); sealed into the intent — the boot completer replays it only after validation.
    let aborted_attempt_record: Value = if attempt_ref.is_some() && prior_attempt.is_null() {
        let aref = attempt_ref.clone().unwrap_or_default();
        json!({
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "reconciliation_result_id": aref,
            "goal_run_id": id,
            "goal_ref": prior.get("goal_ref").cloned().unwrap_or(Value::Null),
            "status": "aborted_before_output_admission",
            "attempt_token": token,
            "planned_changed_files": [],
            "staged_output_manifest": [],
            "final_changed_files": [],
            "commit_journal": [],
            "copy_errors": [],
            "final_receipt_refs": [receipt_id],
            "reason_code": "recovery_release_before_any_output_admission",
            "reconciled_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        })
    } else {
        Value::Null
    };
    let aborted_attempt_record_hash: Value = if aborted_attempt_record.is_null() {
        Value::Null
    } else {
        json!(sha256_canonical(&aborted_attempt_record))
    };
    let receipt = json!({
        "id": receipt_id,
        "kind": "hypervisor.goal-run.lifecycle-recovery",
        "receipt_type": "GoalRunLifecycleRecoveryReceipt",
        "goal_run_id": id,
        "op": prior_op.get("op").cloned().unwrap_or(Value::Null),
        "op_token": token,
        "reservation": prior_op,
        // The crashed/failed attempt this recovery resolves (#72 round 6 finding 2): bound by
        // REF and by the hash the authority grant was verified against. When the crash happened
        // BEFORE any attempt record was admitted, this recovery CREATES the
        // aborted_before_output_admission record so every retained ref resolves (#72 round 7
        // finding 3).
        "attempt_ref": attempt_ref.clone(),
        "attempt_resolution": if attempt_ref.is_none() { "no_attempt" } else if prior_attempt.is_null() { "aborted_before_output_admission" } else { "resolved" },
        "aborted_attempt_record_hash": aborted_attempt_record_hash,
        "reserved_status": prior_status,
        "restored_status": restored_status,
        "resolution": "release",
        // The acting identity and its authority (#72 round 5 finding 4) — who decided, under
        // what verified grant, bound to which policy/request/failure hashes.
        "acting_authority_id": acting_authority_id,
        "authority_grant_ref": authority_grant_ref,
        "authority_provider_ref": "wallet.network",
        "authority_grant_hash": authority_grant_hash,
        "admission_intent_ref": admitted.admission_intent_ref,
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "failure_hash": failure_hash,
        "staging_validation": lock_staging_validation,
        "staging_validated_at": iso_now(),
        "required_scopes": RECOVERY_AUTHORITY_SCOPES,
        "consequential_execution_note": "releasing after a consequential execution (e.g. a completed wallet crossing) is an explicit governed decision recorded by this receipt — re-running the operation performs a NEW crossing",
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    // (2) DURABLE INTENT: the run still holds its reservation; the intent seals everything the
    // completer needs — receipt content, its hash, and any aborted-attempt record — before any
    // observable transition (#72 round 7 finding 5: replay VALIDATES against these seals).
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
                "receipt_hash": sha256_canonical(&receipt),
                "aborted_attempt_record": aborted_attempt_record,
                // Sealed like the receipt (#72 round 8 finding 4): replay validates the hash
                // and every binding before persisting the synthetic record.
                "aborted_attempt_record_hash": receipt["aborted_attempt_record_hash"].clone(),
                "at": iso_now(),
            }),
        );
    }
    if let Err(f) = persist_goal_run_atomic(&st.data_dir, &id, &with_intent) {
        if !f.visible() {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_persist_failed",
                &format!(
                    "the recovery intent is {} — the reservation is unchanged",
                    f.detail()
                ),
            );
        }
        // DURABLE INTENT REQUIRED before any evidence lands (#72 round 9 finding 2): if the
        // receipt were written now and a crash lost the unconfirmed intent, the completer would
        // have nothing to replay against orphaned evidence. The visible intent stays put — if
        // it turns out durable, the boot completer finishes it; if the crash loses it, the
        // reservation stands and nothing else ever happened.
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_recovery_intent_durability_unconfirmed",
            &format!("the recovery intent is {}; no receipt or record was written — a restart either completes the intent (if it proved durable) or leaves the reservation intact", f.detail()),
        );
    }
    // DELIBERATE TEST KILL POINT (#72 round 6 finding 4): absent env = no effect. Crashing here
    // — after the GoalRun replacement, before receipt persistence — leaves ONLY the durable
    // intent; the boot completer must finish the transaction deterministically.
    if std::env::var("IOI_TEST_KILL_AFTER_RECOVERY_INTENT")
        .ok()
        .as_deref()
        == Some("1")
    {
        std::process::abort();
    }
    // (3) Durable receipt REQUIRED (#72 round 9 finding 2): a NOT-COMMITTED failure rolls the
    // intent back EXACTLY (the reservation survives untouched); a visible-but-unconfirmed
    // receipt KEEPS THE DURABLE INTENT and refuses typed — the completer re-persists the
    // sealed receipt (byte-exact) at restart and finishes. The intent is never consumed while
    // any piece of its evidence is unconfirmed.
    if let Err(f) = persist_record_durable(
        &st.data_dir,
        "receipts",
        &receipt_file_key(&receipt_id),
        &receipt,
    ) {
        if f.visible() {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_recovery_receipt_durability_unconfirmed",
                &format!("the recovery receipt is {}; the DURABLE intent is retained — a restart re-persists the sealed receipt and completes the release", f.detail()),
            );
        }
        let detail = f.detail();
        return match persist_goal_run_atomic(&st.data_dir, &id, &prior) {
            Ok(()) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_recovery_receipt_persist_failed",
                &format!("the recovery receipt is {detail}; the intent was rolled back EXACTLY inside the same critical section — nothing changed"),
            ),
            Err(re) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_rollback_failed",
                &format!("the recovery receipt is {detail} AND the intent rollback failed ({}) — the boot completer will finish the durable intent deterministically", re.detail()),
            ),
        };
    }
    // (3b) The aborted-attempt record, when this recovery must create one — every retained
    // attempt ref RESOLVES (#72 round 7 finding 3). Post-receipt failure leaves the intent for
    // the completer; nothing is deleted.
    if !aborted_attempt_record.is_null() {
        let record_tail = attempt_ref
            .as_deref()
            .and_then(|r| r.strip_prefix("reconciliation_result://"))
            .unwrap_or_default()
            .to_string();
        if let Err(f) = persist_record_durable(
            &st.data_dir,
            RECONCILIATION_KIND,
            &record_tail,
            &aborted_attempt_record,
        ) {
            let code = if f.visible() {
                "goal_run_recovery_attempt_record_durability_unconfirmed"
            } else {
                "goal_run_recovery_finalize_failed"
            };
            // Either way the DURABLE intent (and durable receipt) stand; the release has NOT
            // consumed them — restart validates the seals and finishes deterministically
            // (#72 round 9 finding 2: the intent outlives every unconfirmed piece of evidence).
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                code,
                &format!("the aborted-attempt record is {}; the durable intent and receipt stand — a restart finishes this transaction deterministically", f.detail()),
            );
        }
    }
    // (4) Durable release: restore from_status, RETAIN the (now resolving) attempt ref, consume
    // the reservation and the intent.
    let released = build_released_run(&prior, &with_intent["recovery_intent"]);
    match persist_goal_run_atomic(&st.data_dir, &id, &released) {
        Ok(()) => {}
        Err(f) if f.visible() => {
            // The release is VISIBLE; if a crash reverts it the durable intent re-releases at
            // boot. Converged either way — reported with the durability caveat, deleted never.
        }
        Err(f) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_recovery_finalize_failed",
                &format!("the release is {}; the durable intent and its receipt are in place — the boot completer finishes this transaction deterministically at restart", f.detail()),
            );
        }
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": released, "recovery_receipt": receipt })),
    )
}

/// LIVE validation of the staged attempt input against its durable manifest (#72 round 8
/// finding 3): re-hash every staged file under the attempt's staging root and compare with the
/// manifest sealed at staging time. DETERMINISTIC (no timestamps, sorted mismatches) so it can
/// be bound into the recovery failure_hash — a staged file that changes or disappears between
/// challenge and release changes the hash and forces a re-challenge carrying the damaged-state
/// facts.
fn validate_staged_manifest(attempt_record: &Value) -> Value {
    let manifest = attempt_record
        .get("staged_output_manifest")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let staging_root = attempt_record
        .get("staging_root")
        .and_then(Value::as_str)
        .unwrap_or("");
    if attempt_record.is_null() || staging_root.is_empty() {
        return json!({ "validated": Value::Null, "checked": 0, "mismatches": [] });
    }
    let mut mismatches: Vec<Value> = Vec::new();
    for entry in &manifest {
        let file = entry.get("file").and_then(Value::as_str).unwrap_or("");
        let expected_sha = entry.get("sha256").and_then(Value::as_str).unwrap_or("");
        let expected_bytes = entry.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        let staged_path = match contained_rel_path(file) {
            Ok(rel) => std::path::Path::new(staging_root).join(rel),
            Err(_) => {
                mismatches.push(json!({ "file": file, "state": "invalid_path" }));
                continue;
            }
        };
        match std::fs::read(&staged_path) {
            Ok(bytes) => {
                let actual_sha = sha256_hex(&bytes);
                if actual_sha != expected_sha || bytes.len() as u64 != expected_bytes {
                    mismatches.push(json!({ "file": file, "state": "mismatched", "expected_sha256": expected_sha, "actual_sha256": actual_sha, "expected_bytes": expected_bytes, "actual_bytes": bytes.len() as u64 }));
                }
            }
            Err(_) => {
                mismatches.push(json!({ "file": file, "state": "missing", "expected_sha256": expected_sha, "expected_bytes": expected_bytes }));
            }
        }
    }
    mismatches.sort_by_key(|m| {
        m.get("file")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    });
    json!({ "validated": mismatches.is_empty(), "checked": manifest.len(), "mismatches": mismatches })
}

/// Resolve the attempt-scoped operation record a reservation names (Null when absent).
fn read_attempt_record(data_dir: &str, attempt_ref: Option<&str>) -> Value {
    let Some(aref) = attempt_ref else {
        return Value::Null;
    };
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
            json!(intent
                .get("restored_status")
                .and_then(Value::as_str)
                .unwrap_or("draft")),
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
    let _guard = GOAL_RUN_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for run in read_record_dir(data_dir, GOAL_RUN_KIND) {
        let Some(intent) = run.get("recovery_intent").cloned() else {
            continue;
        };
        let goal_run_id = run
            .get("goal_run_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // REPLAY VALIDATION (#72 round 7 finding 5): the embedded intent is only executed when
        // every seal checks out against the durable reservation — schema, token equality,
        // resolution, restored status vs from_status, attempt consistency, receipt identity,
        // and the receipt hash. Anything inconsistent is LEFT IN PLACE for manual repair;
        // replay never manufactures or overwrites evidence.
        let receipt = intent.get("receipt").cloned().unwrap_or(Value::Null);
        let receipt_id = intent
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let op = run.get("lifecycle_op").cloned().unwrap_or(Value::Null);
        let intent_token = intent.get("op_token").and_then(Value::as_str).unwrap_or("");
        let intent_attempt = intent.get("attempt_ref").and_then(Value::as_str);
        let mut violations: Vec<&str> = Vec::new();
        if goal_run_id.is_empty() || receipt.is_null() || receipt_id.is_empty() {
            violations.push("schema (goal_run_id/receipt/receipt_id)");
        }
        if intent.get("resolution").and_then(Value::as_str) != Some("release") {
            violations.push("resolution");
        }
        if intent_token.is_empty() || op.get("token").and_then(Value::as_str) != Some(intent_token)
        {
            violations.push("token vs lifecycle_op");
        }
        if intent.get("restored_status").and_then(Value::as_str)
            != op.get("from_status").and_then(Value::as_str)
        {
            violations.push("restored_status vs from_status");
        }
        if intent_attempt != op.get("attempt_ref").and_then(Value::as_str) {
            violations.push("attempt_ref vs lifecycle_op");
        }
        if receipt.get("id").and_then(Value::as_str) != Some(receipt_id.as_str())
            || receipt.get("goal_run_id").and_then(Value::as_str) != Some(goal_run_id.as_str())
            || receipt.get("op_token").and_then(Value::as_str) != Some(intent_token)
        {
            violations.push("receipt identity");
        }
        if intent.get("receipt_hash").and_then(Value::as_str)
            != Some(sha256_canonical(&receipt).as_str())
        {
            violations.push("receipt hash");
        }
        if !violations.is_empty() {
            eprintln!("goal-run recovery completer: intent on '{goal_run_id}' fails validation ({}) — left in place for manual repair", violations.join(", "));
            continue;
        }
        // A pre-existing receipt must be BYTE-EXACT (canonically identical) — conflicting
        // evidence is never overwritten.
        let receipt_tail: String = receipt_id.replace(
            |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
            "_",
        );
        let existing_receipt_path = std::path::Path::new(data_dir)
            .join("receipts")
            .join(format!("{receipt_tail}.json"));
        if existing_receipt_path.exists() {
            let existing: Value = std::fs::read(&existing_receipt_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null);
            if serde_json::to_vec(&existing).unwrap_or_default()
                != serde_json::to_vec(&receipt).unwrap_or_default()
            {
                eprintln!("goal-run recovery completer: a DIFFERENT receipt already exists at '{receipt_id}' for '{goal_run_id}' — conflicting evidence is never overwritten; left for manual repair");
                continue;
            }
        } else if let Err(f) = persist_record_durable(
            data_dir,
            "receipts",
            &receipt_file_key(&receipt_id),
            &receipt,
        ) {
            // DURABLE required (#72 round 9 finding 2): a visible-unconfirmed receipt must not
            // let the release consume the intent — retained, retried next boot either way.
            eprintln!("goal-run recovery completer: receipt persist for '{goal_run_id}' is {} — intent retained, retried next boot", f.detail());
            continue;
        }
        // Replay the sealed aborted-attempt record (#72 rounds 7 + 8 findings 3 + 4) so the
        // retained attempt ref resolves after a crash between receipt and record — but ONLY
        // after validating its seal: canonical hash, record identity, goal/token equality, and
        // receipt binding. A pre-existing record must be byte-exact; conflicting evidence is
        // never overwritten and a broken seal leaves the intent for manual repair.
        let aborted = intent
            .get("aborted_attempt_record")
            .cloned()
            .unwrap_or(Value::Null);
        if !aborted.is_null() {
            let sealed_hash = intent
                .get("aborted_attempt_record_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            let mut record_violations: Vec<&str> = Vec::new();
            if sealed_hash.is_empty() || sha256_canonical(&aborted) != sealed_hash {
                record_violations.push("record hash");
            }
            if aborted
                .get("reconciliation_result_id")
                .and_then(Value::as_str)
                != intent_attempt
            {
                record_violations.push("record identity vs attempt_ref");
            }
            if aborted.get("goal_run_id").and_then(Value::as_str) != Some(goal_run_id.as_str()) {
                record_violations.push("goal_run_id");
            }
            if aborted.get("attempt_token").and_then(Value::as_str) != Some(intent_token) {
                record_violations.push("attempt_token");
            }
            let receipt_bound = aborted
                .get("final_receipt_refs")
                .and_then(Value::as_array)
                .map(|a| a.iter().any(|r| r.as_str() == Some(receipt_id.as_str())))
                .unwrap_or(false);
            if !receipt_bound {
                record_violations.push("receipt binding");
            }
            if aborted.get("status").and_then(Value::as_str)
                != Some("aborted_before_output_admission")
            {
                record_violations.push("status");
            }
            if !record_violations.is_empty() {
                eprintln!("goal-run recovery completer: the sealed aborted-attempt record for '{goal_run_id}' fails validation ({}) — intent left in place for manual repair", record_violations.join(", "));
                continue;
            }
            let already = read_attempt_record(data_dir, intent_attempt);
            if !already.is_null() {
                if serde_json::to_vec(&already).unwrap_or_default()
                    != serde_json::to_vec(&aborted).unwrap_or_default()
                {
                    eprintln!("goal-run recovery completer: a DIFFERENT attempt record already exists at '{}' for '{goal_run_id}' — conflicting evidence is never overwritten; left for manual repair", intent_attempt.unwrap_or(""));
                    continue;
                }
            } else {
                let record_tail = intent_attempt
                    .and_then(|r| r.strip_prefix("reconciliation_result://"))
                    .unwrap_or_default()
                    .to_string();
                if let Err(f) =
                    persist_record_durable(data_dir, RECONCILIATION_KIND, &record_tail, &aborted)
                {
                    // DURABLE required before the intent is consumed (#72 round 9 finding 2).
                    eprintln!("goal-run recovery completer: aborted-attempt record persist for '{goal_run_id}' is {} — intent retained, retried next boot", f.detail());
                    continue;
                }
            }
        }
        let released = build_released_run(&run, &intent);
        match persist_goal_run_atomic(data_dir, &goal_run_id, &released) {
            Ok(()) => {}
            Err(f) if f.visible() => {}
            Err(f) => {
                eprintln!("goal-run recovery completer: release persist for '{goal_run_id}' is {} — intent retained, retried next boot", f.detail());
                continue;
            }
        }
        eprintln!("goal-run recovery completer: finished the interrupted recovery for '{goal_run_id}' (receipt '{receipt_id}')");
    }
}

// ---------------------------------------------------------------------------
// events — the run's normalized HarnessAdapterEvent stream + invocation records
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_run_events(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let reader = match global_truth_reader(&st, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let _room_scope = super::outcome_room_routes::ROOM_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
    let run = match load_goal_run_by_id_strict(&st.data_dir, &id) {
        Ok(Some(run))
            if reader.as_deref().is_none_or(|owner_ref| {
                run.get("owner_ref").and_then(Value::as_str) == Some(owner_ref)
            }) =>
        {
            run
        }
        Ok(Some(_)) => {
            return bad(
                StatusCode::FORBIDDEN,
                "goal_run_global_truth_owner_mismatch",
                "The authenticated principal does not own this GoalRun.",
            )
        }
        Ok(None) if reader.is_some() => {
            return bad(
                StatusCode::FORBIDDEN,
                "goal_run_global_truth_owner_mismatch",
                "The authenticated principal does not own this GoalRun.",
            )
        }
        Ok(None) => {
            return bad(
                StatusCode::NOT_FOUND,
                "goal_run_not_found",
                "Unknown GoalRun.",
            )
        }
        Err(message) => {
            eprintln!("GoalRun registry refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_registry_unreadable",
                "GoalRun truth cannot be resolved from the complete strict registry census.",
            );
        }
    };
    let goal_ref = text(&run, "goal_ref");
    let mut events: Vec<Value> = match strict_json_family(&st.data_dir, "harness-adapter-events") {
        Ok(records) => records
            .into_iter()
            .map(|(_, record)| record)
            .filter(|event| text(event, "goal_run_ref") == goal_ref)
            .collect(),
        Err((_, message)) => {
            eprintln!("GoalRun event source refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_event_truth_unreadable",
                "GoalRun event truth cannot be resolved from the complete strict source census.",
            );
        }
    };
    events.sort_by_key(|event| {
        (
            text(event, "harness_invocation_ref").to_string(),
            event.get("sequence").and_then(Value::as_u64).unwrap_or(0),
        )
    });
    let invocations: Vec<Value> = match strict_json_family(&st.data_dir, INVOCATION_KIND) {
        Ok(records) => records
            .into_iter()
            .map(|(_, record)| record)
            .filter(|invocation| text(invocation, "goal_ref") == goal_ref)
            .collect(),
        Err((_, message)) => {
            eprintln!("GoalRun invocation source refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_event_truth_unreadable",
                "GoalRun event truth cannot be resolved from the complete strict source census.",
            );
        }
    };
    let verifications: Vec<Value> = match strict_json_family(&st.data_dir, VERIFICATION_KIND) {
        Ok(records) => records
            .into_iter()
            .map(|(_, record)| record)
            .filter(|verification| text(verification, "goal_ref") == goal_ref)
            .collect(),
        Err((_, message)) => {
            eprintln!("GoalRun verification source refusal: {message}");
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "goal_run_event_truth_unreadable",
                "GoalRun event truth cannot be resolved from the complete strict source census.",
            );
        }
    };
    if let Err(response) = fence_pending_room_projection(&st.data_dir) {
        return response;
    }
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

    fn current_hosted_work_result(identity: &str, subject: &str) -> Value {
        let mut record: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/work-result-v3/positive-hosted-admitted.json"
        )))
        .unwrap();
        record["work_result_id"] = json!(identity);
        record["work_subject_ref"] = json!(subject);
        record
    }

    fn plant(dir: &std::path::Path, file: &str, record: &Value) {
        std::fs::write(
            dir.join(GOAL_RUN_KIND).join(file),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }

    fn family_bytes(
        dir: &std::path::Path,
        family: &str,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut records = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(dir.join(family)) {
            for entry in entries.flatten() {
                records.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
        records
    }

    #[test]
    fn resolved_goal_run_mutation_principal_is_compared_without_a_second_identity_lookup() {
        let goal_run = json!({
            "goal_run_id":"gr_auth_order",
            "owner_ref":"user://owner"
        });
        authorize_resolved_goal_run_mutation(None, &goal_run)
            .expect("the explicit loopback local-operator lane remains available");
        authorize_resolved_goal_run_mutation(Some("user://owner"), &goal_run)
            .expect("the exact resolved owner may mutate");
        let refusal = authorize_resolved_goal_run_mutation(Some("user://outsider"), &goal_run)
            .expect_err("a different resolved principal must fail closed");
        assert_eq!(refusal.0, StatusCode::FORBIDDEN);
        let Json(body) = refusal.1;
        assert_eq!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("goal_run_mutation_owner_mismatch")
        );
    }

    #[test]
    fn delta_binding_uses_the_generic_work_subject() {
        let result = json!({
            "work_subject_ref":"goal://gr_subject",
        });
        assert_eq!(
            work_result_goal_ref_for_delta_binding(&result),
            Some("goal://gr_subject")
        );
        assert_eq!(work_result_goal_ref_for_delta_binding(&json!({})), None);
    }

    #[test]
    fn non_null_activation_project_is_typed_deferred_without_registry_mutation() {
        let directory = temp_dir("activation-project-deferred");
        let before = family_bytes(&directory, "projects");
        let refusal = resolve_activation_project(
            directory.to_str().unwrap(),
            Some(&json!("project://workspace-one")),
        )
        .unwrap_err();
        assert_eq!(refusal.0, StatusCode::UNPROCESSABLE_ENTITY);
        let Json(body) = &refusal.1;
        assert_eq!(
            body.pointer("/error/code").and_then(Value::as_str),
            Some("goal_run_activation_project_binding_deferred")
        );
        assert_eq!(family_bytes(&directory, "projects"), before);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn room_owner_publication_refuses_incomplete_or_ambiguous_versioned_registry_without_mutation()
    {
        let candidate_ref = "work-result://goal-run/gr-room/invocation/candidate";
        let candidate = current_hosted_work_result(candidate_ref, "goal://room");

        let malformed_dir = temp_dir("room-owner-malformed-registry");
        std::fs::create_dir_all(malformed_dir.join(super::super::work_result_routes::RESULT_DIR))
            .unwrap();
        std::fs::write(
            malformed_dir
                .join(super::super::work_result_routes::RESULT_DIR)
                .join("malformed.json"),
            b"{not-json",
        )
        .unwrap();
        let malformed_before =
            family_bytes(&malformed_dir, super::super::work_result_routes::RESULT_DIR);
        let (code, _) = publish_room_owner_record_exact(
            malformed_dir.to_str().unwrap(),
            super::super::work_result_routes::RESULT_DIR,
            "work_result_id",
            candidate_ref,
            &candidate,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_owner_registry_unreadable");
        assert_eq!(
            family_bytes(&malformed_dir, super::super::work_result_routes::RESULT_DIR,),
            malformed_before
        );

        let relocated_dir = temp_dir("room-owner-relocated-registry");
        let relocated_ref = "work-result://goal-run/gr-room/invocation/relocated";
        persist_record(
            relocated_dir.to_str().unwrap(),
            super::super::work_result_routes::RESULT_DIR,
            "wrong_tail",
            &current_hosted_work_result(relocated_ref, "goal://room"),
        )
        .unwrap();
        let relocated_before =
            family_bytes(&relocated_dir, super::super::work_result_routes::RESULT_DIR);
        let (code, _) = publish_room_owner_record_exact(
            relocated_dir.to_str().unwrap(),
            super::super::work_result_routes::RESULT_DIR,
            "work_result_id",
            candidate_ref,
            &candidate,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_owner_registry_unreadable");
        assert_eq!(
            family_bytes(&relocated_dir, super::super::work_result_routes::RESULT_DIR,),
            relocated_before
        );

        let duplicate_dir = temp_dir("room-owner-duplicate-registry");
        let m3_ref = "work-result://research/duplicate";
        let m3 = current_hosted_work_result(m3_ref, "goal://room");
        for key in [
            super::super::work_result_routes::goal_run_work_truth_record_key(m3_ref),
            safe(m3_ref),
        ] {
            persist_record(
                duplicate_dir.to_str().unwrap(),
                super::super::work_result_routes::RESULT_DIR,
                &key,
                &m3,
            )
            .unwrap();
        }
        let duplicate_before =
            family_bytes(&duplicate_dir, super::super::work_result_routes::RESULT_DIR);
        let (code, _) = publish_room_owner_record_exact(
            duplicate_dir.to_str().unwrap(),
            super::super::work_result_routes::RESULT_DIR,
            "work_result_id",
            candidate_ref,
            &candidate,
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_owner_registry_unreadable");
        assert_eq!(
            family_bytes(&duplicate_dir, super::super::work_result_routes::RESULT_DIR,),
            duplicate_before
        );

        for dir in [malformed_dir, relocated_dir, duplicate_dir] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    fn m4_test_payload_custody(
        dir: &std::path::Path,
        tag: &str,
        artifact_ref: &str,
        output: &[u8],
    ) -> ResultPayloadCustody {
        let workspace = dir.join(format!("workspace-{tag}"));
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("result.txt"), output).unwrap();
        let captured_file_facts = json!([{
            "relative_path":"result.txt",
            "sha256":sha256_hex(output),
            "bytes":output.len(),
        }]);
        let captured_facts_hash = sha256_canonical(&captured_file_facts);
        let implementation_result = json!({
            "implementation_result_id":format!("implementation_result://ioi/m4/{tag}"),
            "status":"completed",
        });
        build_live_payload_custody(
            workspace.to_str().unwrap(),
            artifact_ref,
            &implementation_result,
            &captured_file_facts,
            &captured_facts_hash,
            &[format!("receipt://ioi/m4/{tag}")],
        )
        .unwrap()
    }

    fn admit_m4_test_payload_custody(data_dir: &str, custody: &ResultPayloadCustody) {
        super::super::substrate_store::admit_required(
            data_dir,
            ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
            &custody.admission_key,
            &custody.admission,
        )
        .unwrap();
        persist_immutable_payload_bytes(data_dir, &custody.payload_ref, &custody.bytes).unwrap();
    }

    fn resolve_m4_test_payload_custody(
        data_dir: &str,
        custody: &ResultPayloadCustody,
    ) -> Result<ResultPayloadCustody, SeamErr> {
        resolve_payload_custody(
            data_dir,
            &custody.artifact_ref,
            &custody.implementation_result,
            &custody.captured_output_file_facts,
            &custody.captured_output_file_facts_hash,
            &custody.receipt_refs,
        )
    }

    #[test]
    fn m4_runtime_dependency_resolvers_refuse_missing_duplicate_and_substituted_truth() {
        let artifact_ref = "artifact://ioi/m4/runtime-dependency-test";

        // A byte bundle alone is not custody: its exact StorageBackendWriteAdmission must exist.
        let missing_admission_dir = temp_dir("m4-missing-payload-admission");
        let missing_admission =
            m4_test_payload_custody(&missing_admission_dir, "missing", artifact_ref, b"alpha");
        let (code, _) = resolve_m4_test_payload_custody(
            missing_admission_dir.to_str().unwrap(),
            &missing_admission,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_payload_write_admission_unresolved");

        // Two immutable admissions that both claim the same outward artifact are ambiguous even
        // when each record and byte object is independently exact.
        let duplicate_admission_dir = temp_dir("m4-duplicate-payload-admission");
        let duplicate_a =
            m4_test_payload_custody(&duplicate_admission_dir, "duplicate-a", artifact_ref, b"a");
        let duplicate_b =
            m4_test_payload_custody(&duplicate_admission_dir, "duplicate-b", artifact_ref, b"b");
        let duplicate_data_dir = duplicate_admission_dir.to_str().unwrap();
        admit_m4_test_payload_custody(duplicate_data_dir, &duplicate_a);
        admit_m4_test_payload_custody(duplicate_data_dir, &duplicate_b);
        let (code, _) =
            resolve_m4_test_payload_custody(duplicate_data_dir, &duplicate_a).unwrap_err();
        assert_eq!(code, "work_result_payload_write_admission_unresolved");

        // A content-addressed Agentgres record is still refused when its core admission fields no
        // longer reproduce the canonical StorageBackendWriteAdmission.
        let substituted_admission_dir = temp_dir("m4-substituted-payload-admission");
        let substituted = m4_test_payload_custody(
            &substituted_admission_dir,
            "substituted",
            artifact_ref,
            b"substituted",
        );
        let mut forged_admission = substituted.admission.clone();
        forged_admission["storage_backend_ref"] =
            json!("storage://hypervisor/foreign/result-payloads/v1");
        let forged_key = room_dependency_key(
            ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
            "orpwa_",
            &forged_admission,
        )
        .unwrap();
        let substituted_data_dir = substituted_admission_dir.to_str().unwrap();
        super::super::substrate_store::admit_required(
            substituted_data_dir,
            ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
            &forged_key,
            &forged_admission,
        )
        .unwrap();
        persist_immutable_payload_bytes(
            substituted_data_dir,
            &substituted.payload_ref,
            &substituted.bytes,
        )
        .unwrap();
        let (code, _) =
            resolve_m4_test_payload_custody(substituted_data_dir, &substituted).unwrap_err();
        assert_eq!(code, "work_result_payload_write_admission_substituted");

        // A family-name symlink can never redirect an immutable payload write. The writer pins
        // data_dir first, opens/creates the family relative to that fd with O_NOFOLLOW, and
        // leaves the foreign directory byte-for-byte untouched.
        let family_symlink_dir = temp_dir("m4-payload-family-symlink");
        let family_symlink_custody = m4_test_payload_custody(
            &family_symlink_dir,
            "family-symlink",
            artifact_ref,
            b"family-symlink-refusal",
        );
        let foreign_family = family_symlink_dir.join("foreign-payload-family");
        std::fs::create_dir_all(&foreign_family).unwrap();
        std::fs::write(foreign_family.join("sentinel"), b"foreign-family-unchanged").unwrap();
        std::os::unix::fs::symlink(
            &foreign_family,
            family_symlink_dir.join(ROOM_RESULT_PAYLOAD_BYTES_KIND),
        )
        .unwrap();
        let (code, _) = persist_immutable_payload_bytes(
            family_symlink_dir.to_str().unwrap(),
            &family_symlink_custody.payload_ref,
            &family_symlink_custody.bytes,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_payload_persist_failed");
        assert_eq!(
            std::fs::read(foreign_family.join("sentinel")).unwrap(),
            b"foreign-family-unchanged"
        );
        assert_eq!(std::fs::read_dir(&foreign_family).unwrap().count(), 1);

        // A payload-slot symlink is also uncertainty, never admitted custody. Even when the
        // foreign target happens to contain the expected bytes, O_NOFOLLOW refuses the name.
        let slot_symlink_dir = temp_dir("m4-payload-slot-symlink");
        let slot_symlink_custody = m4_test_payload_custody(
            &slot_symlink_dir,
            "slot-symlink",
            artifact_ref,
            b"slot-symlink-refusal",
        );
        let slot_symlink_data_dir = slot_symlink_dir.to_str().unwrap();
        super::super::substrate_store::admit_required(
            slot_symlink_data_dir,
            ROOM_RESULT_PAYLOAD_WRITE_ADMISSION_DOMAIN,
            &slot_symlink_custody.admission_key,
            &slot_symlink_custody.admission,
        )
        .unwrap();
        std::fs::create_dir_all(slot_symlink_dir.join(ROOM_RESULT_PAYLOAD_BYTES_KIND)).unwrap();
        let foreign_slot = slot_symlink_dir.join("foreign-payload-bytes");
        std::fs::write(&foreign_slot, &slot_symlink_custody.bytes).unwrap();
        let (slot_hash, _) = parse_payload_ref(&slot_symlink_custody.payload_ref).unwrap();
        std::os::unix::fs::symlink(
            &foreign_slot,
            slot_symlink_dir
                .join(ROOM_RESULT_PAYLOAD_BYTES_KIND)
                .join(payload_bytes_name(slot_hash)),
        )
        .unwrap();
        let (code, _) =
            resolve_m4_test_payload_custody(slot_symlink_data_dir, &slot_symlink_custody)
                .unwrap_err();
        assert_eq!(code, "work_result_payload_unavailable");

        // A pinned family fd continues to read its original inode if the path is exchanged, and
        // the canonical-entry certifier independently catches that exchange. No read follows the
        // replacement symlink into the foreign directory.
        let directory_swap_dir = temp_dir("m4-payload-directory-swap");
        let directory_swap_custody = m4_test_payload_custody(
            &directory_swap_dir,
            "directory-swap",
            artifact_ref,
            b"descriptor-bound-original",
        );
        persist_immutable_payload_bytes(
            directory_swap_dir.to_str().unwrap(),
            &directory_swap_custody.payload_ref,
            &directory_swap_custody.bytes,
        )
        .unwrap();
        {
            let (root, pinned) =
                pin_payload_custody_directory(directory_swap_dir.to_str().unwrap(), false).unwrap();
            let retired_family = directory_swap_dir.join("retired-payload-family");
            std::fs::rename(
                directory_swap_dir.join(ROOM_RESULT_PAYLOAD_BYTES_KIND),
                &retired_family,
            )
            .unwrap();
            let foreign_swap_family = directory_swap_dir.join("foreign-swap-family");
            std::fs::create_dir_all(&foreign_swap_family).unwrap();
            let (swap_hash, _) = parse_payload_ref(&directory_swap_custody.payload_ref).unwrap();
            let swap_name = payload_bytes_name(swap_hash);
            std::fs::write(
                foreign_swap_family.join(&swap_name),
                b"foreign-substitution",
            )
            .unwrap();
            std::os::unix::fs::symlink(
                &foreign_swap_family,
                directory_swap_dir.join(ROOM_RESULT_PAYLOAD_BYTES_KIND),
            )
            .unwrap();
            let (_, pinned_bytes) = read_payload_slot_bounded(&pinned, &swap_name)
                .unwrap()
                .unwrap();
            assert_eq!(pinned_bytes, directory_swap_custody.bytes);
            assert!(certify_payload_custody_directory(&root, &pinned).is_err());
            assert_eq!(
                std::fs::read(foreign_swap_family.join(&swap_name)).unwrap(),
                b"foreign-substitution"
            );
        }

        let room = json!({"privacy_policy_ref":"policy://ioi/m4/private"});
        let content_hash = sha256_hex(b"exact admitted output bytes");
        let expected_label = build_result_information_flow_label(&room, &content_hash).unwrap();
        let expected_label_ref = expected_label.record["label_ref"].as_str().unwrap();

        // A WorkResult label ref is not evidence unless exactly one durable Agentgres label
        // resolves it.
        let missing_label_dir = temp_dir("m4-missing-information-flow-label");
        let (code, _) = resolve_information_flow_label(
            missing_label_dir.to_str().unwrap(),
            expected_label_ref,
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_information_flow_label_unresolved");

        // Retaining the old ref while falsely changing tool output to model output is a provenance
        // substitution, even if the forged record itself occupies its own exact content key.
        let substituted_label_dir = temp_dir("m4-substituted-information-flow-label");
        let mut forged_label = expected_label.record.clone();
        forged_label["origin"] = json!("model_output");
        let forged_label_key =
            room_dependency_key(ROOM_INFORMATION_FLOW_LABEL_DOMAIN, "orifl_", &forged_label)
                .unwrap();
        super::super::substrate_store::admit_required(
            substituted_label_dir.to_str().unwrap(),
            ROOM_INFORMATION_FLOW_LABEL_DOMAIN,
            &forged_label_key,
            &forged_label,
        )
        .unwrap();
        let (code, _) = resolve_information_flow_label(
            substituted_label_dir.to_str().unwrap(),
            expected_label_ref,
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(code, "outcome_room_information_flow_label_substituted");

        // A child label whose identity binds one real parent must also carry that parent's exact
        // transitive closure. Omitting it is independently refused after both records resolve.
        let closure_dir = temp_dir("m4-substituted-information-flow-closure");
        let closure_data_dir = closure_dir.to_str().unwrap();
        super::super::substrate_store::admit_required(
            closure_data_dir,
            ROOM_INFORMATION_FLOW_LABEL_DOMAIN,
            &expected_label.key,
            &expected_label.record,
        )
        .unwrap();
        let mut child =
            build_result_information_flow_label(&room, &sha256_hex(b"derived exact output bytes"))
                .unwrap()
                .record;
        child["derivation_kind"] = json!("join");
        child["derivation_parent_refs"] = json!([expected_label_ref]);
        child["label_ref"] = Value::Null;
        child["derivation_closure_refs"] = json!([]);
        let child_identity = jcs_hash(
            &information_flow_label_identity_material(&child).unwrap(),
            "m4_test_information_flow_label_hash_failed",
        )
        .unwrap();
        let child_ref = format!(
            "ifc-label://outcome-room/work-result/{}",
            child_identity.strip_prefix("sha256:").unwrap()
        );
        child["label_ref"] = json!(child_ref);
        child["derivation_closure_refs"] = json!([child_ref]);
        let child_key =
            room_dependency_key(ROOM_INFORMATION_FLOW_LABEL_DOMAIN, "orifl_", &child).unwrap();
        super::super::substrate_store::admit_required(
            closure_data_dir,
            ROOM_INFORMATION_FLOW_LABEL_DOMAIN,
            &child_key,
            &child,
        )
        .unwrap();
        let (code, _) = resolve_information_flow_label(
            closure_data_dir,
            child["label_ref"].as_str().unwrap(),
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(
            code,
            "outcome_room_information_flow_label_closure_substituted"
        );

        // Invocation, embedded receipt, Session binding, binding receipt, conductor verification,
        // component snapshot, and durable authority receipt must all resolve byte-exactly. Each
        // independently substituted lane is refused while its durable source remains recoverable.
        let authenticity_dir = temp_dir("m4-work-result-authenticity");
        let authenticity_data_dir = authenticity_dir.to_str().unwrap();
        let receipt_id = "receipt://ioi/m4/authenticity";
        let invocation_ref = "harness-invocation://ioi/m4/authenticity";
        let session_ref = "session://ioi/m4/authenticity";
        let binding_id = "model-route-binding://ioi/m4/authenticity";
        let binding_receipt_ref = "receipt://ioi/m4/model-route-binding";
        let mut invocation_receipt = json!({
            "receipt_root":Value::Null,
            "id":receipt_id,
            "kind":"hypervisor.goal-run.invoke",
            "runtimeTruthSource":"daemon-runtime",
            "harness_invocation_ref":invocation_ref,
            "goal_run_ref":"goal://ioi/m4/authenticity",
            "role_key":"implementer_a",
            "harness":"codex",
            "harness_profile_ref":"harness-profile://ioi/codex",
            "model_route_ref":"model-route://ioi/m4/authenticity",
            "model_route_binding_id":binding_id,
            "model_route_binding_receipt_ref":binding_receipt_ref,
            "model_id":"model://ioi/m4/authenticity",
            "model_route_base_url":"https://model.invalid/v1",
            "model_route_execution_endpoint":"https://model.invalid/v1/responses",
            "session_ref":session_ref,
            "command_contract_ref":"contract://ioi/m4/command/v1",
            "files_written":["result.txt"],
            "output_file_facts":{
                "files":[{"relative_path":"result.txt","sha256":sha256_hex(b"result"),"bytes":6}]
            },
        });
        invocation_receipt = rooted_runtime_record(
            "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
            "receipt_root",
            invocation_receipt,
        )
        .unwrap();
        let implementation_result_candidate = json!({
            "candidate_ref":"implementation-result-candidate://ioi/m4/authenticity",
            "execution_succeeded":true,
            "goal_ref":"goal://ioi/m4/authenticity",
            "harness_invocation_ref":invocation_ref,
            "harness_profile_ref":"harness-profile://ioi/codex",
            "model_route_ref":"model-route://ioi/m4/authenticity",
            "model_route_binding_id":binding_id,
            "model_route_binding_receipt_ref":binding_receipt_ref,
            "model_id":"model://ioi/m4/authenticity",
            "model_route_base_url":"https://model.invalid/v1",
            "model_route_execution_endpoint":"https://model.invalid/v1/responses",
            "command_contract_ref":"contract://ioi/m4/command/v1",
            "changed_files":["result.txt"],
            "candidate_artifact_refs":["artifact://goal-run/gr_authenticity/implementer_a/result.txt"],
            "receipt_refs":[receipt_id],
        });
        let invocation = json!({
            "harness_invocation_id":invocation_ref,
            "goal_run_id":"gr_authenticity",
            "goal_ref":"goal://ioi/m4/authenticity",
            "role_key":"implementer_a",
            "harness":"codex",
            "harness_ref":"harness-profile://ioi/codex",
            "model_route_ref":"model-route://ioi/m4/authenticity",
            "model_route_binding_id":binding_id,
            "model_route_binding_receipt_ref":binding_receipt_ref,
            "model_id":"model://ioi/m4/authenticity",
            "model_route_base_url":"https://model.invalid/v1",
            "model_route_execution_endpoint":"https://model.invalid/v1/responses",
            "session_ref":session_ref,
            "status":"waiting_on_conductor",
            "implementation_result_candidate":implementation_result_candidate,
            "execution_receipt":invocation_receipt,
        });
        let mut binding = json!({
            "binding_id":binding_id,
            "session_ref":session_ref,
            "route_ref":"model-route://ioi/m4/authenticity",
            "receipt_ref":binding_receipt_ref,
            "model_id":"model://ioi/m4/authenticity",
            "base_url":"https://model.invalid/v1",
            "execution_endpoint":"https://model.invalid/v1/responses",
            "harness_binding_ref":"harness-binding://ioi/m4/authenticity",
            "admission_id":"model-route-admission://ioi/m4/authenticity",
        });
        binding["binding_root"] =
            json!(jcs_hash(&binding, "m4_test_model_route_binding_hash_failed").unwrap());
        let session = json!({"session_ref":session_ref,"model_route_binding":binding});
        let binding_receipt = json!({
            "outcome":"ok",
            "op":"bind_session_route",
            "receipt_ref":binding_receipt_ref,
            "binding_id":binding_id,
            "session_ref":session_ref,
            "route_ref":"model-route://ioi/m4/authenticity",
            "model_id":"model://ioi/m4/authenticity",
            "base_url":"https://model.invalid/v1",
            "execution_endpoint":"https://model.invalid/v1/responses",
            "harness_binding_ref":"harness-binding://ioi/m4/authenticity",
            "admission_id":"model-route-admission://ioi/m4/authenticity",
        });
        persist_record(authenticity_data_dir, "sessions", "session_auth", &session).unwrap();
        persist_record(
            authenticity_data_dir,
            "model-route-session-bindings",
            "binding_auth",
            &binding,
        )
        .unwrap();
        persist_record(
            authenticity_data_dir,
            "model-route-registry-receipts",
            "binding_receipt_auth",
            &binding_receipt,
        )
        .unwrap();
        validate_invocation_execution_binding(
            authenticity_data_dir,
            &invocation,
            &invocation_receipt,
            false,
        )
        .unwrap();

        let mut external_receipt_substitution = invocation_receipt.clone();
        external_receipt_substitution["model_id"] = json!("model://substituted");
        external_receipt_substitution = rooted_runtime_record(
            "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
            "receipt_root",
            external_receipt_substitution,
        )
        .unwrap();
        let (code, _) = validate_invocation_execution_binding(
            authenticity_data_dir,
            &invocation,
            &external_receipt_substitution,
            false,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_invocation_receipt_substituted");

        let mut substituted_session = session.clone();
        substituted_session["model_route_binding"]["model_id"] = json!("model://substituted");
        persist_record(
            authenticity_data_dir,
            "sessions",
            "session_auth",
            &substituted_session,
        )
        .unwrap();
        let (code, _) = validate_invocation_execution_binding(
            authenticity_data_dir,
            &invocation,
            &invocation_receipt,
            false,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_model_route_binding_substituted");
        persist_record(authenticity_data_dir, "sessions", "session_auth", &session).unwrap();

        let expected_checks = json!([
            {"check":"invocation_execution_succeeded_exit_zero","pass":true},
            {"check":"reported_file_exists_with_content","file":"result.txt","pass":true},
            {"check":"workspace_mutation_reported","pass":true}
        ]);
        let mut verification = json!({
            "verification_root":Value::Null,
            "verification_id":"gv_gr_authenticity_implementer_a",
            "verification_ref":"agentgres://goal-run-verification/gv_gr_authenticity_implementer_a",
            "goal_run_id":"gr_authenticity",
            "goal_ref":"goal://ioi/m4/authenticity",
            "harness_invocation_ref":invocation_ref,
            "implementation_result_candidate_ref":"implementation-result-candidate://ioi/m4/authenticity",
            "verifier_path_ref":"verifier-path://vp_gr_authenticity",
            "verification_kind":"deterministic",
            "verdict":"pass",
            "checks":expected_checks,
            "runtimeTruthSource":"daemon-runtime",
            "verified_at":"2026-07-30T00:00:00Z",
        });
        verification = rooted_runtime_record(
            "ioi.goal-run-conductor-verification-jcs-sha256.v1",
            "verification_root",
            verification,
        )
        .unwrap();
        validate_conductor_verification(
            "gr_authenticity",
            "goal://ioi/m4/authenticity",
            &invocation,
            &invocation_receipt,
            &verification,
        )
        .unwrap();
        let mut substituted_verification = verification.clone();
        substituted_verification["checks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"check":"unbacked_claim","pass":true}));
        substituted_verification = rooted_runtime_record(
            "ioi.goal-run-conductor-verification-jcs-sha256.v1",
            "verification_root",
            substituted_verification,
        )
        .unwrap();
        let (code, _) = validate_conductor_verification(
            "gr_authenticity",
            "goal://ioi/m4/authenticity",
            &invocation,
            &invocation_receipt,
            &substituted_verification,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_verification_truth_substituted");

        let (_, snapshot_key, snapshot) =
            component_resolution_snapshot("gr_authenticity", invocation_ref, &invocation_receipt)
                .unwrap();
        verify_component_resolution_snapshot(&snapshot).unwrap();
        admit_exact_required_dependency(
            authenticity_data_dir,
            ROOM_COMPONENT_RESOLUTION_DOMAIN,
            &snapshot_key,
            &snapshot,
            "work_result_component_resolution_snapshot_admission_failed",
        )
        .expect("the exact component-resolution snapshot must cross required Agentgres admission");
        let mut substituted_snapshot = snapshot.clone();
        substituted_snapshot["model_id"] = json!("model://substituted");
        let (code, _) = verify_component_resolution_snapshot(&substituted_snapshot).unwrap_err();
        assert_eq!(
            code,
            "work_result_component_resolution_snapshot_substituted"
        );

        let (_, evidence_key, evidence) = conductor_verification_evidence(
            "gr_authenticity",
            invocation_ref,
            &invocation_receipt,
            &verification,
        )
        .unwrap();
        verify_conductor_verification_evidence(&evidence).unwrap();
        admit_exact_required_dependency(
            authenticity_data_dir,
            ROOM_CONDUCTOR_VERIFICATION_DOMAIN,
            &evidence_key,
            &evidence,
            "work_result_verification_evidence_admission_failed",
        )
        .expect(
            "the exact conductor-verification evidence must cross required Agentgres admission",
        );
        let mut substituted_evidence = evidence.clone();
        substituted_evidence["verification"]["verdict"] = json!("substituted");
        let (code, _) = verify_conductor_verification_evidence(&substituted_evidence).unwrap_err();
        assert_eq!(code, "work_result_verification_evidence_substituted");

        let authority_receipt = json!({
            "receipt_id":"receipt://goal-run-invocation-authority/authenticity",
            "receipt_type":"goal_run_invocation_authority_admission"
        });
        let authority_key = receipt_file_key(authority_receipt["receipt_id"].as_str().unwrap());
        persist_exact_authority_receipt(authenticity_data_dir, &authority_key, &authority_receipt)
            .unwrap();
        let mut substituted_authority = authority_receipt.clone();
        substituted_authority["receipt_type"] = json!("substituted");
        let (code, _) = persist_exact_authority_receipt(
            authenticity_data_dir,
            &authority_key,
            &substituted_authority,
        )
        .unwrap_err();
        assert_eq!(code, "work_result_invocation_authority_receipt_substituted");
        let (_, retained_authority) = strict_unique_by_identity(
            authenticity_data_dir,
            "receipts",
            "receipt_id",
            authority_receipt["receipt_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(retained_authority, authority_receipt);

        for dir in [
            missing_admission_dir,
            duplicate_admission_dir,
            substituted_admission_dir,
            family_symlink_dir,
            slot_symlink_dir,
            directory_swap_dir,
            missing_label_dir,
            substituted_label_dir,
            closure_dir,
            authenticity_dir,
        ] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn guarded_seam_distinguishes_not_found_refusal_and_persist_failure() {
        // #72 round 3 finding 1: the seam's outcomes are TYPED and distinct — a caller can no
        // longer collapse "record missing" and "write failed" into one silent lane.
        let dir = temp_dir("lanes");
        let data_dir = dir.to_str().unwrap();
        let seed = json!({ "goal_run_id": "gr_a", "goal_ref": "goal://gr_a", "status": "active", "normalized_goal": "x" });
        plant(&dir, "gr_a.json", &seed);

        // Lane 1: unknown run — typed not-found, nothing else.
        let (code, _) =
            update_goal_run_guarded(data_dir, "gr_missing", |_| Ok(()), |_| {}).unwrap_err();
        assert_eq!(code, "goal_run_not_found");

        // Lane 2: predicate refusal — propagated verbatim, the mutation NEVER runs.
        let mut mutated = false;
        let (code, msg) = update_goal_run_guarded(
            data_dir,
            "gr_a",
            |_| {
                Err((
                    "goal_run_not_reconcilable".to_string(),
                    "state precheck refused".to_string(),
                ))
            },
            |_| mutated = true,
        )
        .unwrap_err();
        assert_eq!(code, "goal_run_not_reconcilable");
        assert_eq!(msg, "state precheck refused");
        assert!(!mutated, "the CAS predicate gates the mutation");

        // Lane 3: persist failure — the registry remains readable but refuses creation of the
        // atomic replacement temporary file.
        let family = dir.join(GOAL_RUN_KIND);
        let before = std::fs::read(family.join("gr_a.json")).unwrap();
        let mut permissions = std::fs::metadata(&family).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o500);
        std::fs::set_permissions(&family, permissions).unwrap();
        let (code, _) = update_goal_run_guarded(
            data_dir,
            "gr_a",
            |_| Ok(()),
            |obj| {
                obj.insert("status".into(), json!("complete"));
            },
        )
        .unwrap_err();
        let mut permissions = std::fs::metadata(&family).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
        std::fs::set_permissions(&family, permissions).unwrap();
        assert_eq!(
            code, "goal_run_persist_failed",
            "a write failure is its OWN typed lane"
        );
        assert_eq!(
            std::fs::read(family.join("gr_a.json")).unwrap(),
            before,
            "the durable record is byte-for-byte unchanged after a failed persist"
        );
        let leaks: Vec<String> = std::fs::read_dir(dir.join(GOAL_RUN_KIND))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            leaks.is_empty(),
            "no temporary artifact survives: {leaks:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guarded_seam_refuses_duplicate_or_unreadable_goalrun_registry_truth() {
        let dir = temp_dir("strict-registry");
        let data_dir = dir.to_str().unwrap();
        plant(
            &dir,
            "gr_a.json",
            &json!({ "goal_run_id": "gr_a", "goal_ref": "goal://shared", "status": "active" }),
        );
        plant(
            &dir,
            "gr_b.json",
            &json!({ "goal_run_id": "gr_b", "goal_ref": "goal://shared", "status": "active" }),
        );
        let (code, message) =
            update_goal_run_guarded(data_dir, "gr_a", |_| Ok(()), |_| {}).unwrap_err();
        assert_eq!(code, "goal_run_registry_unreadable");
        assert!(message.contains("resolves more than once"), "{message}");

        std::fs::remove_file(dir.join(GOAL_RUN_KIND).join("gr_b.json")).unwrap();
        std::fs::write(dir.join(GOAL_RUN_KIND).join("corrupt.json"), b"{not-json").unwrap();
        let (code, message) =
            update_goal_run_guarded(data_dir, "gr_a", |_| Ok(()), |_| {}).unwrap_err();
        assert_eq!(code, "goal_run_registry_unreadable");
        assert!(message.contains("malformed"), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enclosing_recovery_intent_requires_crash_durable_goalrun_mutation() {
        let record = json!({ "goal_run_id": "gr_room", "status": "active" });
        assert_eq!(
            require_durable_mutation(
                MutationOutcome::Durable(record.clone()),
                "room_goal_durability_unconfirmed",
                "room GoalRun backlink",
            )
            .unwrap(),
            record
        );
        let (code, message) = require_durable_mutation(
            MutationOutcome::VisibleUnconfirmed(record, "forced directory fsync fault".into()),
            "room_goal_durability_unconfirmed",
            "room GoalRun backlink",
        )
        .unwrap_err();
        assert_eq!(code, "room_goal_durability_unconfirmed");
        assert!(message.contains("retain the recovery intent"), "{message}");
        assert!(
            message.contains("forced directory fsync fault"),
            "{message}"
        );
    }

    #[test]
    fn contained_rel_path_rejects_every_escape_shape() {
        // #72 round 5 finding 1: traversal, absolute, current-dir, and empty declarations never
        // reach a workspace join.
        assert_eq!(
            contained_rel_path("out.txt").unwrap(),
            std::path::PathBuf::from("out.txt")
        );
        assert_eq!(
            contained_rel_path("nested/dir/out.txt").unwrap(),
            std::path::PathBuf::from("nested/dir/out.txt")
        );
        // An interior `./` NORMALIZES (the alias then collides with its plain form in the
        // planned set); leading `./`, parent traversal, absolute, and empty all REFUSE.
        assert_eq!(
            contained_rel_path("a/./b.txt").unwrap(),
            std::path::PathBuf::from("a/b.txt")
        );
        for escape in [
            "../escape.txt",
            "a/../../b.txt",
            "a/../b.txt",
            "/etc/passwd",
            "./a.txt",
            "",
            "  ",
        ] {
            assert!(
                contained_rel_path(escape).is_err(),
                "'{escape}' must refuse"
            );
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
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "the check wrote NOTHING outside"
        );
        assert!(
            !root.join("fresh").exists(),
            "the check wrote NOTHING inside either"
        );
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
        let root_fd = nofollow_fs::open_dir_pinned(&root).unwrap();
        // Happy path: full content lands, the applied hash is the content hash, no tmp survives.
        let (bytes, sha) =
            commit_one(&staged, &root_fd, std::path::Path::new("deep/out.txt")).unwrap();
        assert_eq!(bytes, 12);
        assert_eq!(sha, sha256_hex(b"FULL_CONTENT"));
        assert_eq!(
            std::fs::read(root.join("deep/out.txt")).unwrap(),
            b"FULL_CONTENT"
        );
        let leaks: Vec<String> = std::fs::read_dir(root.join("deep"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".wal-tmp-"))
            .collect();
        assert!(leaks.is_empty(), "no wal-tmp survives: {leaks:?}");
        // Symlink belt (now descriptor-relative, #72 round 6): a symlinked parent component
        // refuses AT THE OPEN and writes nothing outside.
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err = commit_one(&staged, &root_fd, std::path::Path::new("link/out.txt")).unwrap_err();
        assert!(
            matches!(&err, CommitFailure::NotApplied(m) if m.contains("pinned parent walk refused")),
            "{err:?}"
        );
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "zero external mutation"
        );
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
        assert_eq!(
            read_record_dir(data_dir, "evidence").pop().unwrap()["v"],
            json!(1)
        );
        // WRITE boundary: read/exec-only family dir refuses the tmp create; nothing changes.
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(persist_record_durable(data_dir, "evidence", "rec_a", &json!({ "v": 2 })).is_err());
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            read_record_dir(data_dir, "evidence").pop().unwrap()["v"],
            json!(1),
            "the old record survives a write-boundary failure untouched"
        );
        // RENAME boundary: a non-empty directory blocks the destination; tmp is cleaned.
        let blocker = fam.join("rec_b.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        assert!(persist_record_durable(data_dir, "evidence", "rec_b", &json!({ "v": 3 })).is_err());
        let leaks: Vec<String> = std::fs::read_dir(&fam)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            leaks.is_empty(),
            "no tmp survives a rename-boundary failure: {leaks:?}"
        );
        // DIR-SYNC boundary: write+exec-only (no read) lets tmp-write and rename succeed but the
        // checked directory fsync cannot open the dir — the helper FAILS CLOSED rather than
        // report unconfirmed durability as success.
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o333)).unwrap();
        let r = persist_record_durable(data_dir, "evidence", "rec_c", &json!({ "v": 4 }));
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            r.is_err(),
            "an unconfirmed rename durability is a FAILED persist, never a shrug"
        );
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
        let root_fd = nofollow_fs::open_dir_pinned(&root).unwrap();
        // Reads: a symlink component refuses at USE time; a legitimate path reads fine.
        assert_eq!(
            nofollow_fs::read_contained(&root_fd, std::path::Path::new("real/inside.txt"), 1 << 20)
                .unwrap(),
            b"INSIDE"
        );
        let err =
            nofollow_fs::read_contained(&root_fd, std::path::Path::new("link/loot.txt"), 1 << 20)
                .unwrap_err();
        assert!(
            matches!(err, nofollow_fs::ReadRefusal::Escape(_)),
            "{err:?}"
        );
        // SWAP LANE (source/target parent swap): pin the root fd, then swap the root path to a
        // symlink pointing outside — the pinned fd still resolves to the ORIGINAL directory.
        let staged = dir.join("staged.txt");
        std::fs::write(&staged, b"PAYLOAD").unwrap();
        let moved = dir.join("root-moved");
        std::fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        let (bytes, _) =
            commit_one(&staged, &root_fd, std::path::Path::new("swapped/out.txt")).unwrap();
        assert_eq!(bytes, 7);
        assert_eq!(
            std::fs::read(moved.join("swapped/out.txt")).unwrap(),
            b"PAYLOAD",
            "the write followed the PINNED fd, not the swapped path"
        );
        assert!(
            !outside.join("swapped").exists() && !outside.join("out.txt").exists(),
            "the symlinked path received NOTHING"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_persist_dirsync_failure_reports_visible_and_leaves_the_new_record() {
        // #72 round 7 finding 1: a post-rename directory-sync failure is
        // RenamedDurabilityUnconfirmed — the NEW record is already visible and must be readable,
        // never rolled back "as absent".
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dirsync");
        let data_dir = dir.to_str().unwrap();
        let fam = dir.join("evidence");
        std::fs::create_dir_all(&fam).unwrap();
        persist_record_durable(data_dir, "evidence", "rec", &json!({ "v": 1 })).unwrap();
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o333)).unwrap();
        let f =
            persist_record_durable(data_dir, "evidence", "rec", &json!({ "v": 2 })).unwrap_err();
        std::fs::set_permissions(&fam, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            f.visible(),
            "a post-rename dir-sync failure is VISIBLE, not NotCommitted"
        );
        assert!(matches!(f, PersistFailure::RenamedDurabilityUnconfirmed(_)));
        // The rename already replaced the record — v:2 is what a reader sees.
        assert_eq!(
            read_record_dir(data_dir, "evidence").pop().unwrap()["v"],
            json!(2),
            "the RENAMED record is visible; it was NOT rolled back as absent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_read_refuses_fifo_and_oversize_without_blocking() {
        // #72 round 7 finding 4: a FIFO opens (O_NONBLOCK) but refuses NotRegular — the daemon
        // never blocks; an oversize regular file refuses TooLarge before the bytes are taken.
        let dir = temp_dir("bounded");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let root_fd = nofollow_fs::open_dir_pinned(&root).unwrap();
        // FIFO
        let fifo = std::ffi::CString::new(root.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) },
            0,
            "mkfifo failed"
        );
        let err = nofollow_fs::read_contained(&root_fd, std::path::Path::new("pipe"), 1 << 20)
            .unwrap_err();
        assert!(
            matches!(err, nofollow_fs::ReadRefusal::NotRegular(_)),
            "{err:?}"
        );
        // Oversize regular file
        std::fs::write(root.join("big.bin"), vec![0u8; 4096]).unwrap();
        let err = nofollow_fs::read_contained(&root_fd, std::path::Path::new("big.bin"), 1024)
            .unwrap_err();
        assert!(
            matches!(err, nofollow_fs::ReadRefusal::TooLarge(4096)),
            "{err:?}"
        );
        // A within-budget regular file reads fine.
        assert_eq!(
            nofollow_fs::read_contained(&root_fd, std::path::Path::new("big.bin"), 8192)
                .unwrap()
                .len(),
            4096
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn completer_rejects_a_tampered_receipt_hash_and_leaves_the_intent() {
        // #72 round 7 finding 5: replay validates the receipt hash; a mismatch is left in place,
        // never executed.
        let dir = temp_dir("completer-reject");
        let data_dir = dir.to_str().unwrap();
        let receipt = json!({ "id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_r_t1", "receipt_type": "GoalRunLifecycleRecoveryReceipt", "goal_run_id": "gr_r", "op_token": "t1" });
        plant(
            &dir,
            "gr_r.json",
            &json!({
                "goal_run_id": "gr_r",
                "status": "reconciling",
                "lifecycle_op": { "op": "reconcile", "token": "t1", "from_status": "active", "attempt_ref": Value::Null },
                "recovery_intent": { "op_token": "t1", "resolution": "release", "restored_status": "active", "attempt_ref": Value::Null, "receipt_id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_r_t1", "receipt": receipt, "receipt_hash": "sha256:deadbeef", "aborted_attempt_record": Value::Null, "at": "2026-01-01T00:00:00Z" }
            }),
        );
        complete_recovery_intents(data_dir);
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(
            run["status"],
            json!("reconciling"),
            "a hash-mismatched intent is NOT executed"
        );
        assert!(
            run.get("recovery_intent").is_some(),
            "the intent is left in place for manual repair"
        );
        assert!(
            read_record_dir(data_dir, "receipts").is_empty(),
            "no receipt was manufactured"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_staged_manifest_detects_mutation_and_loss_deterministically() {
        // #72 round 8 finding 3: the live staging validation is deterministic (hash-bindable)
        // and names exactly what changed or vanished.
        let dir = temp_dir("manifest");
        let staging = dir.join("stage");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("a.txt"), b"ALPHA").unwrap();
        std::fs::write(staging.join("b.txt"), b"BETA").unwrap();
        let record = json!({
            "staging_root": staging.display().to_string(),
            "staged_output_manifest": [
                { "file": "a.txt", "sha256": sha256_hex(b"ALPHA"), "bytes": 5 },
                { "file": "b.txt", "sha256": sha256_hex(b"BETA"), "bytes": 4 },
            ],
        });
        let ok = validate_staged_manifest(&record);
        assert_eq!(ok["validated"], json!(true));
        let h1 = sha256_canonical(&ok);
        assert_eq!(
            h1,
            sha256_canonical(&validate_staged_manifest(&record)),
            "deterministic across runs"
        );
        std::fs::write(staging.join("a.txt"), b"TAMPERED").unwrap();
        std::fs::remove_file(staging.join("b.txt")).unwrap();
        let bad = validate_staged_manifest(&record);
        assert_eq!(bad["validated"], json!(false));
        assert_eq!(bad["mismatches"][0]["file"], json!("a.txt"));
        assert_eq!(bad["mismatches"][0]["state"], json!("mismatched"));
        assert_eq!(bad["mismatches"][1]["state"], json!("missing"));
        assert_ne!(
            h1,
            sha256_canonical(&bad),
            "damage changes the bindable hash — a stale grant can never release over it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn completer_rejects_a_mutated_attempt_record_even_with_a_valid_receipt_hash() {
        // #72 round 8 finding 4 — the reviewer's exact probe: mutate ONLY the synthetic
        // record's reconciliation_result_id while the receipt hash stays valid; replay must
        // leave the intent untouched and persist nothing.
        let dir = temp_dir("completer-record");
        let data_dir = dir.to_str().unwrap();
        let receipt = json!({ "id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_m_t1", "receipt_type": "GoalRunLifecycleRecoveryReceipt", "goal_run_id": "gr_m", "op_token": "t1" });
        let mut aborted = json!({
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "reconciliation_result_id": "reconciliation_result://rc_gr_m_t1",
            "goal_run_id": "gr_m",
            "status": "aborted_before_output_admission",
            "attempt_token": "t1",
            "final_receipt_refs": ["receipt://hypervisor/goal-run-lifecycle-recovery/gr_m_t1"],
        });
        let sealed_hash = sha256_canonical(&aborted);
        // MUTATE only the record identity — the hash seal no longer matches.
        aborted["reconciliation_result_id"] = json!("reconciliation_result://rc_gr_OTHER_t1");
        plant(
            &dir,
            "gr_m.json",
            &json!({
                "goal_run_id": "gr_m",
                "status": "reconciling",
                "lifecycle_op": { "op": "reconcile", "token": "t1", "from_status": "active", "attempt_ref": "reconciliation_result://rc_gr_m_t1" },
                "recovery_intent": {
                    "op_token": "t1", "resolution": "release", "restored_status": "active",
                    "attempt_ref": "reconciliation_result://rc_gr_m_t1",
                    "receipt_id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_m_t1",
                    "receipt": receipt, "receipt_hash": sha256_canonical(&receipt),
                    "aborted_attempt_record": aborted, "aborted_attempt_record_hash": sealed_hash,
                    "at": "2026-01-01T00:00:00Z",
                }
            }),
        );
        complete_recovery_intents(data_dir);
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(
            run["status"],
            json!("reconciling"),
            "a mutated attempt record is NOT executed"
        );
        assert!(
            run.get("recovery_intent").is_some(),
            "the intent is left in place for manual repair"
        );
        assert!(
            read_record_dir(data_dir, RECONCILIATION_KIND).is_empty(),
            "no attempt record was manufactured"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_completer_finishes_a_sealed_recovery_intent_forward() {
        // #72 round 6 finding 4: everything the completer needs was sealed into the intent
        // before the first observable transition — restart persists the receipt, releases the
        // run, and RETAINS the crashed attempt ref (finding 2).
        let dir = temp_dir("completer");
        let data_dir = dir.to_str().unwrap();
        // A fully-sealed, VALID intent (#72 round 7 finding 5): the completer validates every
        // seal, so the fixture must be internally consistent — receipt identity, token, status,
        // attempt ref, and the receipt hash all agree.
        let receipt = json!({ "id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_i_t1", "receipt_type": "GoalRunLifecycleRecoveryReceipt", "goal_run_id": "gr_i", "op_token": "t1", "failure_hash": "sha256:abc" });
        let receipt_hash = sha256_canonical(&receipt);
        // Plant the attempt record so its ref resolves (finding 3).
        std::fs::create_dir_all(dir.join(RECONCILIATION_KIND)).unwrap();
        std::fs::write(dir.join(RECONCILIATION_KIND).join("rc_gr_i_t1.json"), serde_json::to_vec(&json!({ "reconciliation_result_id": "reconciliation_result://rc_gr_i_t1", "goal_run_id": "gr_i", "status": "failed_partial_commit" })).unwrap()).unwrap();
        plant(
            &dir,
            "gr_i.json",
            &json!({
                "goal_run_id": "gr_i",
                "status": "reconciling",
                "lifecycle_op": { "op": "reconcile", "token": "t1", "from_status": "active", "attempt_ref": "reconciliation_result://rc_gr_i_t1" },
                "recovery_intent": { "op_token": "t1", "resolution": "release", "restored_status": "active", "attempt_ref": "reconciliation_result://rc_gr_i_t1", "receipt_id": "receipt://hypervisor/goal-run-lifecycle-recovery/gr_i_t1", "receipt": receipt, "receipt_hash": receipt_hash, "aborted_attempt_record": Value::Null, "at": "2026-01-01T00:00:00Z" }
            }),
        );
        complete_recovery_intents(data_dir);
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(
            run["status"],
            json!("active"),
            "released to the intent's from_status"
        );
        assert!(
            run.get("lifecycle_op").is_none() && run.get("recovery_intent").is_none(),
            "reservation and intent consumed"
        );
        assert_eq!(
            run["reconciliation_attempt_refs"],
            json!(["reconciliation_result://rc_gr_i_t1"]),
            "the crashed attempt ref is RETAINED"
        );
        let persisted_receipt = read_record_dir(data_dir, "receipts")
            .pop()
            .expect("the sealed receipt was persisted");
        assert_eq!(
            persisted_receipt["receipt_type"],
            json!("GoalRunLifecycleRecoveryReceipt")
        );
        // Idempotent: a second boot pass changes nothing.
        complete_recovery_intents(data_dir);
        assert_eq!(
            read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap()["reconciliation_attempt_refs"],
            json!(["reconciliation_result://rc_gr_i_t1"])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserve_abort_updates_the_operation_record_and_never_deletes_evidence() {
        // #72 round 4 finding 1: once output MAY have reached the target, the abort lane
        // UPDATES the operation record to a recovery status (journal preserved), releases the
        // reservation, and deletes NOTHING — receipt included.
        let dir = temp_dir("preserve");
        let data_dir = dir.to_str().unwrap();
        plant(
            &dir,
            "gr_p.json",
            &json!({ "goal_run_id": "gr_p", "goal_ref": "goal://gr_p", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tp", "from_status": "active" } }),
        );
        std::fs::create_dir_all(dir.join(RECONCILIATION_KIND)).unwrap();
        std::fs::write(dir.join("receipts_marker"), b"x").unwrap();
        let preserved = json!({ "reconciliation_result_id": "reconciliation_result://rc_gr_p", "status": "failed_partial_commit", "commit_journal": [{ "file": "a.txt", "applied": true }], "final_receipt_refs": ["receipt://hypervisor/goal-run-reconciliation/gr_p"] });
        let (status, body) = reconcile_preserve_abort(
            data_dir,
            "gr_p",
            "tp",
            "rc_gr_p",
            &preserved,
            "goal_run_output_commit_failed",
            "half the files landed",
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body.0["error"]["code"],
            json!("goal_run_output_commit_failed")
        );
        let record = read_record_dir(data_dir, RECONCILIATION_KIND)
            .pop()
            .expect("the operation record is PRESERVED");
        assert_eq!(record["status"], json!("failed_partial_commit"));
        assert_eq!(
            record["commit_journal"][0]["applied"],
            json!(true),
            "the journal survives as evidence"
        );
        assert_eq!(
            record["recovery"]["code"],
            json!("goal_run_output_commit_failed"),
            "the recovery lane is recorded ON the evidence"
        );
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(
            run["status"],
            json!("active"),
            "the reservation was released for an idempotent retry"
        );
        assert!(run.get("lifecycle_op").is_none());
        assert_eq!(
            run["reconciliation_attempt_refs"],
            json!(["reconciliation_result://rc_gr_p"]),
            "the FAILED attempt's ref is retained append-only on the run (#72 round 5 finding 2)"
        );
        // Bookkeeping failure lane: a blocked record family escalates to rollback_failed while
        // STILL deleting nothing.
        plant(
            &dir,
            "gr_q.json",
            &json!({ "goal_run_id": "gr_q", "goal_ref": "goal://gr_q", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tq", "from_status": "active" } }),
        );
        let blocker = dir.join(RECONCILIATION_KIND).join("rc_gr_q.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let (status, body) = reconcile_preserve_abort(
            data_dir,
            "gr_q",
            "tq",
            "rc_gr_q",
            &preserved,
            "goal_run_output_commit_failed",
            "half the files landed",
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_rollback_failed"));
        assert!(
            std::fs::read(dir.join("receipts_marker")).is_ok(),
            "nothing was deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_evidence_abort_marks_the_reservation_recovery_required_with_executed_evidence() {
        // #72 round 4 finding 2: a side-record persist failure after the wallet crossing keeps
        // the reservation (no duplicate crossing), embeds the failure + executed-invocation
        // evidence durably on the run record, and binds NO refs.
        let dir = temp_dir("evidence");
        let data_dir = dir.to_str().unwrap();
        plant(
            &dir,
            "gr_e.json",
            &json!({ "goal_run_id": "gr_e", "goal_ref": "goal://gr_e", "status": "starting", "lifecycle_op": { "op": "start", "token": "te", "from_status": "draft" } }),
        );
        let executed = vec![
            json!({ "harness_invocation_id": "harness-invocation://hi_gr_e_a", "role_key": "a", "status": "failed" }),
        ];
        let (status, body) = start_evidence_abort(
            data_dir,
            "gr_e",
            "te",
            VERIFICATION_KIND,
            "gv_gr_e_a",
            "read-only dir",
            &executed,
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body.0["error"]["code"],
            json!("goal_run_side_record_persist_failed")
        );
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(
            run["status"],
            json!("starting"),
            "the reservation is KEPT — releasing would re-open a duplicate wallet crossing"
        );
        assert_eq!(run["lifecycle_op"]["phase"], json!("recovery_required"));
        assert_eq!(
            run["lifecycle_op"]["token"],
            json!("te"),
            "the token survives for the recovery transition"
        );
        assert_eq!(
            run["lifecycle_op"]["failure"]["family"],
            json!(VERIFICATION_KIND)
        );
        assert_eq!(
            run["lifecycle_op"]["executed_invocations"][0]["harness_invocation_id"],
            json!("harness-invocation://hi_gr_e_a"),
            "the executed work is durable attempt evidence"
        );
        assert!(
            run.get("invocation_refs").is_none() && run.get("verification_refs").is_none(),
            "no dangling refs were bound"
        );
        // Wrong-token marking refuses without touching the record.
        let (_, body) = start_evidence_abort(
            data_dir,
            "gr_e",
            "wrong",
            VERIFICATION_KIND,
            "gv",
            "x",
            &executed,
        );
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
        plant(
            &dir,
            "gr_b.json",
            &json!({ "goal_run_id": "gr_b", "goal_ref": "goal://gr_b", "status": "active" }),
        );
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
                    obj.insert(
                        "lifecycle_op".into(),
                        json!({ "op": "reconcile", "token": token }),
                    );
                },
            )
        };
        assert!(reserve("t1").is_ok(), "the first reservation wins");
        let (code, _) = reserve("t2").unwrap_err();
        assert_eq!(
            code, "goal_run_not_reconcilable",
            "the second request loses the SAME CAS it would have raced"
        );

        // Finalization compares the token INSIDE the seam: a foreign token refuses.
        let finalize = |token: &str| {
            let token = token.to_string();
            update_goal_run_guarded(
                data_dir,
                "gr_b",
                move |fresh| {
                    if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str)
                        != Some(token.as_str())
                    {
                        return Err((
                            "goal_run_operation_conflict".to_string(),
                            "token mismatch".to_string(),
                        ));
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
        let committed = finalize("t1").unwrap().into_record();
        assert_eq!(committed["status"], json!("complete"));
        assert!(
            committed.get("lifecycle_op").is_none(),
            "the reservation is consumed by the commit"
        );

        // Release restores the reserved status exactly and consumes the token.
        plant(
            &dir,
            "gr_c.json",
            &json!({ "goal_run_id": "gr_c", "goal_ref": "goal://gr_c", "status": "active" }),
        );
        let hold = update_goal_run_guarded(
            data_dir,
            "gr_c",
            |_| Ok(()),
            |obj| {
                obj.insert("status".into(), json!("reconciling"));
                obj.insert(
                    "lifecycle_op".into(),
                    json!({ "op": "reconcile", "token": "t3" }),
                );
            },
        );
        assert!(hold.is_ok());
        release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap();
        let restored = read_record_dir(data_dir, GOAL_RUN_KIND)
            .into_iter()
            .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some("gr_c"))
            .unwrap();
        assert_eq!(
            restored["status"],
            json!("active"),
            "release restores the pre-reservation status"
        );
        assert!(
            restored.get("lifecycle_op").is_none(),
            "release consumes the reservation"
        );
        let (code, _) =
            release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap_err();
        assert_eq!(
            code, "goal_run_operation_conflict",
            "a consumed token releases nothing twice"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn room_result_request_is_a_closed_invocation_selector() {
        let invocation_ref = "harness-invocation://m4-runtime-proof";
        assert_eq!(
            room_result_request_invocation_ref(&json!({
                "invocation_or_run_ref": invocation_ref,
            }))
            .unwrap(),
            invocation_ref
        );

        for field in [
            "work_result_id",
            "result_payload_ref",
            "outcome_class",
            "status",
            "produced_by_ref",
            "room_admission",
        ] {
            let mut request = json!({ "invocation_or_run_ref": invocation_ref });
            request[field] = json!("caller-substitution");
            let (status, body) = room_result_request_invocation_ref(&request).unwrap_err();
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
            assert_eq!(
                body.0.pointer("/error/code").and_then(Value::as_str),
                Some("work_result_runtime_field_plane_owned"),
                "{field}"
            );
        }

        let (status, body) = room_result_request_invocation_ref(&json!({})).unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body.0.pointer("/error/code").and_then(Value::as_str),
            Some("work_result_invocation_ref_required")
        );
    }

    #[test]
    fn invocation_output_facts_bind_exact_workspace_bytes() {
        let dir = temp_dir("invocation-output-facts");
        let output = dir.join("result.txt");
        std::fs::write(&output, b"bounded room load proven").unwrap();
        let declared = vec![json!("result.txt")];
        let before = bounded_workspace_output_file_facts(dir.to_str().unwrap(), &declared)
            .expect("initial output facts");
        assert_eq!(before[0]["bytes"], json!(24));
        assert_eq!(
            before[0]["sha256"],
            json!(sha256_hex(b"bounded room load proven"))
        );

        std::fs::write(&output, b"substituted after receipt").unwrap();
        let (code, detail) = live_bundle_file_entries(dir.to_str().unwrap(), &json!(before))
            .expect_err("post-receipt file growth must be a typed byte-divergence refusal");
        assert_eq!(code, "work_result_output_truth_diverged");
        assert!(detail.contains("grew to"));
        let after = bounded_workspace_output_file_facts(dir.to_str().unwrap(), &declared)
            .expect("mutated output facts");
        assert_ne!(
            sha256_canonical(&json!(before)),
            sha256_canonical(&json!(after)),
            "post-completion byte substitution must change the receipted fact root"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admitted_state_root_is_the_complete_nulled_record_not_a_private_wrapper() {
        let record = json!({
            "schema_version": "ioi.goal-run-admitted-state.v1",
            "state_root_ref": "agentgres://state-root/goal-run/gr_test/sha256:placeholder",
            "state_root": "sha256:placeholder",
            "goal_run_ref": "goal://gr_test",
            "activation_ref": "goal-run-activation://gra_test",
            "source_context_hash": format!("sha256:{}", "a".repeat(64)),
            "requesting_principal_ref": "user://local-operator",
            "authority_decision_ref": "approval://goal-run-activation/gra_test/principal-scope-resolution",
            "goal_run_profile_revision_ref": "goal-run-profile://generic-adaptive/revision/1",
            "goal_run_profile_content_hash": format!("sha256:{}", "b".repeat(64)),
            "resolved_component_set_snapshot_ref": "artifact://goal-run/gr_test/resolved-components",
            "resolved_component_set_hash": format!("sha256:{}", "c".repeat(64)),
            "profile_resolution_receipt_ref": "receipt://goal-run/gr_test/profile-resolution",
            "admission_decision_ref": "decision://goal-run/gr_test/direct",
            "admission_receipt_ref": "receipt://goal-run/gr_test/direct-admission",
            "receipt_obligations": [],
            "admitted_at": "2026-07-30T16:00:00Z",
            "non_grants": {
                "authority_widening": "none",
                "context_declassification": "none",
                "room_membership": "none",
                "budget_creation": "none"
            }
        });
        let committed = activation_state_commitment(&record);
        assert_eq!(committed["state_root"], Value::Null);
        assert_eq!(committed["state_root_ref"], Value::Null);
        assert_eq!(committed["goal_run_ref"], record["goal_run_ref"]);
        assert!(committed.get("domain").is_none());
        assert!(committed.get("state").is_none());
        let root = sha256_canonical(&committed);
        let mut tampered = record.clone();
        tampered["source_context_hash"] = json!(format!("sha256:{}", "d".repeat(64)));
        assert_ne!(
            root,
            sha256_canonical(&activation_state_commitment(&tampered))
        );
    }
}
