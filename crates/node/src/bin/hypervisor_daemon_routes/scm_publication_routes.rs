//! Source-control publication plane: the governed route over the registered
//! `ScmPublicationEffect` contract
//! (`schema://ioi/components/connectors-tools/scm-publication-effect/v1`).
//!
//! `POST /v1/hypervisor/environments/:id/scm/publish` is rebuilt here. The
//! defect it replaces accepted a caller-supplied `remote_url`, staged the whole
//! workspace with `git add -A`, pushed `--force` with no expected-head
//! comparison, dropped every persist result, and returned `"ok": true` even
//! when the pull request had failed.
//!
//! What stands in its place:
//!
//! * the destination is resolved from an ADMITTED connector binding whose
//!   revision hash recomputes — caller text never names a remote;
//! * the change set is the enumerated, proposal-bound file set, and every
//!   declared path's bytes are re-digested out of the workspace before the
//!   commit is built, so a whole-workspace stage is not merely rejected: there
//!   is nothing to stage from;
//! * the remote head advances only under an expected-head compare-and-swap
//!   against a head this daemon observed; a stale or unobservable head refuses
//!   and never overwrites;
//! * publication and review request are two separately receipted sub-effects,
//!   BOTH persisted and read back before any outcome is reported, and
//!   `overall_outcome` is derived from both, so success over a failed review
//!   request has no construction path;
//! * every durable write is checked — locally, through the Agentgres
//!   required-admission boundary, and by a strict read-back — and a failed
//!   write is an error outcome, never `ok: true`;
//! * the idempotency key recomputes over the bound material, so an exact
//!   replay converges onto the prior effect instead of crossing twice.
//!
//! The whole git/host surface sits behind [`ScmRemotePort`], so every refusal
//! branch is exercisable without a network, a credential, or a repository.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use ioi_types::app::scm_publication::{
    build_converged_replay_effect, build_scm_publication_effect, build_scm_publication_receipt,
    compile_scm_publication, scm_destination_binding_hash, scm_publication_artifact_root,
    scm_publication_proposal_commitment, verify_scm_publication_effect, ObservedTargetRef,
    ScmPublicationOutcome, ScmPublicationServerTruth, ScmPublicationSubEffects,
    ScmPublicationSubmission, ScmReviewRequestOutcome, SCM_CHANGE_SET_KIND,
    SCM_DESTINATION_BINDING_FAMILY, SCM_DESTINATION_BINDING_SCHEMA_VERSION,
    SCM_PUBLICATION_EFFECT_FAMILY, SCM_PUBLICATION_PROPOSAL_FAMILY,
    SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION, SCM_PUBLICATION_RECEIPT_FAMILY,
    SCM_REFUSAL_AMBIGUOUS_DESTINATION_BINDING_REF, SCM_REFUSAL_AMBIGUOUS_PROPOSAL_REF,
};

use super::governed_authority::{
    SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE, SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE,
};
use super::lifecycle_routes::{authorize_capability_lease, CapabilityLeaseRequest};
use super::system_activation_routes::{load_local, persist_local};
use super::{AppError, DaemonState};

type VErr = (String, String);

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_owned(), message.into())
}

/// Refusal code carried by a publication that failed the compare-and-swap.
pub(crate) const REFUSAL_EXPECTED_HEAD_MOVED: &str = "expected-target-head-moved";
/// Refusal code carried when the target ref appeared under a must-not-exist
/// precondition.
pub(crate) const REFUSAL_TARGET_REF_EXISTS: &str = "target-ref-already-exists";
/// Refusal code carried when the workspace bytes do not match the proposal.
pub(crate) const REFUSAL_CONTENT_DIGEST_MISMATCH: &str = "change-set-content-digest-mismatch";
/// Refusal code carried when the remote rejected the review request.
pub(crate) const REFUSAL_REVIEW_REQUEST_REJECTED: &str = "review-request-rejected-by-remote";
const SCM_PUBLICATION_OPERATION_FAMILY: &str = "scm-publication-operations";
const SCM_PUBLICATION_EFFECT_V2_CONTRACT: &str =
    "schema://ioi/components/connectors-tools/scm-publication-effect/v2";
static SCM_PUBLICATION_OPERATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SCM_DESTINATION_SCOPE_KIND: &str = "scm-destination-binding";
const SCM_PROPOSAL_SCOPE_KIND: &str = "scm-publication-proposal";
const SCM_CALLER_IDEMPOTENCY_DOMAIN: &str = "ioi.scm-publication-caller-idempotency.v1";

// =====================================================================
// The remote boundary
// =====================================================================

/// What the daemon asks the remote to observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeadObservationRequest<'a> {
    /// Remote destination, from the admitted binding only.
    pub(crate) remote_url: &'a str,
    /// The canonical target ref being advanced.
    pub(crate) target_ref: &'a str,
    /// The canonical base ref the change set was computed onto.
    pub(crate) base_ref: &'a str,
}

/// What the daemon observed. `target` distinguishes "absent" from "could not
/// be observed" so an unobservable head can never become an unconditional
/// advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedHeads {
    /// The observed state of the target ref.
    pub(crate) target: ObservedTargetRef,
    /// The observed head of the base ref.
    pub(crate) base_head: String,
}

/// A compare-and-swap advance of one target ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetRefAdvanceRequest<'a> {
    /// Remote destination, from the admitted binding only.
    pub(crate) remote_url: &'a str,
    /// The canonical target ref being advanced.
    pub(crate) target_ref: &'a str,
    /// The revision the change set was computed onto.
    pub(crate) base_revision_id: &'a str,
    /// The exact head the advance was computed against; `None` means the ref
    /// must not exist.
    pub(crate) expected_target_head: Option<&'a str>,
    /// The enumerated, proposal-bound rows to apply. Nothing outside these
    /// rows can reach the remote.
    pub(crate) files: &'a Value,
    /// The workspace the declared post-image bytes are read from.
    pub(crate) workspace_root: &'a str,
    /// A human title for the commit.
    pub(crate) title: &'a str,
    /// The already-created, operation-bound revision. Dispatch may push only
    /// this frozen object; retries never manufacture a fresh child commit.
    pub(crate) intended_revision_id: &'a str,
}

/// Local, observation-independent preparation of the exact revision later
/// offered to the remote compare-and-swap.
pub(crate) struct TargetRevisionPreparationRequest<'a> {
    pub(crate) base_revision_id: &'a str,
    pub(crate) files: &'a Value,
    pub(crate) workspace_root: &'a str,
    pub(crate) title: &'a str,
    pub(crate) authored_at: &'a str,
}

/// The honest result of one attempted advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetRefAdvanceOutcome {
    /// The target ref now stands at this revision.
    Advanced {
        /// The revision the advance produced.
        resulting_revision_id: String,
    },
    /// Nothing landed; the crossing failed closed on this named code.
    Refused {
        /// The named refusal code.
        refusal_code: String,
        /// The operator-facing detail.
        detail: String,
    },
}

/// A review request from the advanced target ref onto the base ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewRequestOpenRequest<'a> {
    /// Remote destination, from the admitted binding only.
    pub(crate) remote_url: &'a str,
    /// The advanced target ref.
    pub(crate) target_ref: &'a str,
    /// The base ref the review targets.
    pub(crate) base_ref: &'a str,
    /// A human title for the review request.
    pub(crate) title: &'a str,
}

/// The honest result of one attempted review request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewRequestOpenOutcome {
    /// A review request was opened; this is its locator.
    Opened {
        /// Where the review request lives.
        review_request_url: String,
    },
    /// The remote refused or errored. This is its own terminal outcome and is
    /// never absorbed into the publication receipt.
    Failed {
        /// The named refusal code.
        refusal_code: String,
        /// The operator-facing detail.
        detail: String,
    },
}

/// The remote source-control boundary. Every remote effect the plane can have
/// crosses exactly these methods, so the whole decision path is
/// exercisable against a scripted port.
pub(crate) trait ScmRemotePort {
    /// Prepare the frozen revision locally. This has no remote effect.
    fn prepare_target_revision(
        &self,
        request: &TargetRevisionPreparationRequest<'_>,
    ) -> Result<String, String>;
    /// Observe the current target and base heads.
    fn observe_heads(&self, request: &HeadObservationRequest<'_>) -> Result<ObservedHeads, String>;
    /// Advance the target ref under the expected-head compare-and-swap. An
    /// implementation may never overwrite: a moved head is a refusal.
    fn advance_target_ref(&self, request: &TargetRefAdvanceRequest<'_>) -> TargetRefAdvanceOutcome;
    /// Open a review request onto the base ref.
    fn open_review_request(
        &self,
        request: &ReviewRequestOpenRequest<'_>,
    ) -> ReviewRequestOpenOutcome;
}

// =====================================================================
// The real git port
// =====================================================================

/// The production port: git plumbing against the binding's remote.
///
/// The advance is a compare-and-swap in two independent ways, and neither is
/// an overwrite. The new commit is built with the observed expected head as
/// its parent, so the update is a fast-forward; and the push carries the
/// expected object id as a lease, so git itself refuses if the remote is no
/// longer at that head. No code path here passes `--force`, and the effect
/// record has no field through which one could be requested.
pub(crate) struct GitProcessScmPort;

fn git(dir: &str, args: &[&str]) -> (bool, String) {
    match std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
    {
        Ok(output) => (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(error) => (false, error.to_string()),
    }
}

/// The remote-side ref name a canonical `scm-ref://<repo>/heads/<leaf>` maps to.
fn remote_ref_name(canonical: &str) -> Option<String> {
    let tail = canonical.strip_prefix("scm-ref://")?;
    let (_repository, path) = tail.split_once("/heads/")?;
    (!path.is_empty()).then(|| format!("refs/heads/{path}"))
}

fn prepare_git_revision(request: &TargetRevisionPreparationRequest<'_>) -> Result<String, String> {
    let parent = request
        .base_revision_id
        .strip_prefix("scm-revision:")
        .ok_or_else(|| "the proposal base revision is not canonical".to_owned())?;
    let workspace = request.workspace_root;
    let staging = format!("{workspace}/.ioi-scm-publication-index");
    let _ = std::fs::remove_file(&staging);
    let index_env = |args: &[&str]| -> (bool, String) {
        match std::process::Command::new("git")
            .arg("-C")
            .arg(workspace)
            .env("GIT_INDEX_FILE", &staging)
            .env("GIT_AUTHOR_DATE", request.authored_at)
            .env("GIT_COMMITTER_DATE", request.authored_at)
            .args(args)
            .output()
        {
            Ok(output) => (
                output.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ),
            Err(error) => (false, error.to_string()),
        }
    };
    if !git(
        workspace,
        &["cat-file", "-e", &format!("{parent}^{{commit}}")],
    )
    .0
    {
        return Err(
            "the proposal base revision is not present in the admitted workspace".to_owned(),
        );
    }
    if !index_env(&["read-tree", parent]).0 {
        return Err("the proposal base tree could not be read".to_owned());
    }
    for row in request.files.as_array().into_iter().flatten() {
        let path = row.get("path").and_then(Value::as_str).unwrap_or_default();
        let kind = row
            .get("change_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (ok, out) = match kind {
            "removed" => index_env(&["update-index", "--force-remove", path]),
            _ => index_env(&["update-index", "--add", path]),
        };
        if !ok {
            let _ = std::fs::remove_file(&staging);
            return Err(format!("declared row '{path}' could not be staged ({out})"));
        }
    }
    let (wrote, tree) = index_env(&["write-tree"]);
    if !wrote {
        let _ = std::fs::remove_file(&staging);
        return Err("the enumerated change set produced no tree".to_owned());
    }
    let tree = tree.trim().to_owned();
    let (committed, commit) = index_env(&[
        "-c",
        "user.email=hypervisor@ioi.local",
        "-c",
        "user.name=Hypervisor",
        "commit-tree",
        &tree,
        "-p",
        parent,
        "-m",
        request.title,
    ]);
    let _ = std::fs::remove_file(&staging);
    if !committed {
        return Err("the enumerated change set produced no commit".to_owned());
    }
    Ok(format!("scm-revision:{}", commit.trim()))
}

impl ScmRemotePort for GitProcessScmPort {
    fn prepare_target_revision(
        &self,
        request: &TargetRevisionPreparationRequest<'_>,
    ) -> Result<String, String> {
        prepare_git_revision(request)
    }

    fn observe_heads(&self, request: &HeadObservationRequest<'_>) -> Result<ObservedHeads, String> {
        let target = remote_ref_name(request.target_ref)
            .ok_or_else(|| format!("'{}' is not a canonical target ref", request.target_ref))?;
        let base = remote_ref_name(request.base_ref)
            .ok_or_else(|| format!("'{}' is not a canonical base ref", request.base_ref))?;
        let observe = |reference: &str| -> Result<Option<String>, String> {
            let (ok, out) = git(
                ".",
                &["ls-remote", "--exit-code", request.remote_url, reference],
            );
            if !ok {
                // `--exit-code` reports 2 for "no matching ref"; any other
                // failure is an unobservable remote, never an absent ref.
                return if out.trim().is_empty() {
                    Ok(None)
                } else {
                    Err(out.trim().to_owned())
                };
            }
            Ok(out
                .split_whitespace()
                .next()
                .filter(|sha| sha.len() >= 40)
                .map(|sha| format!("scm-revision:{sha}")))
        };
        let base_head = match observe(&base) {
            Ok(Some(head)) => head,
            Ok(None) => {
                return Err(format!(
                    "the base ref '{base}' does not exist on the remote"
                ))
            }
            Err(error) => return Err(error),
        };
        let target = match observe(&target) {
            Ok(Some(head)) => ObservedTargetRef::Present(head),
            Ok(None) => ObservedTargetRef::Absent,
            // An unobservable target ref stays UNOBSERVED. The compiler turns
            // that into a named refusal; it never becomes an advance.
            Err(_) => ObservedTargetRef::Unobserved,
        };
        Ok(ObservedHeads { target, base_head })
    }

    fn advance_target_ref(&self, request: &TargetRefAdvanceRequest<'_>) -> TargetRefAdvanceOutcome {
        let Some(remote_ref) = remote_ref_name(request.target_ref) else {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_EXPECTED_HEAD_MOVED.to_owned(),
                detail: "the target ref is not canonical".to_owned(),
            };
        };
        let Some(parent) = request
            .expected_target_head
            .or(Some(request.base_revision_id))
            .and_then(|revision| revision.strip_prefix("scm-revision:"))
            .map(str::to_owned)
        else {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_EXPECTED_HEAD_MOVED.to_owned(),
                detail: "no canonical parent revision was resolved".to_owned(),
            };
        };
        let Some(commit) = request.intended_revision_id.strip_prefix("scm-revision:") else {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
                detail: "the prepared intended revision is not canonical".to_owned(),
            };
        };
        let workspace = request.workspace_root;
        // The lease IS the compare-and-swap: git refuses unless the remote ref
        // still stands at the observed head. Absent that match nothing moves.
        let lease = match request.expected_target_head {
            Some(_) => format!("--force-with-lease={remote_ref}:{parent}"),
            None => format!("--force-with-lease={remote_ref}:"),
        };
        let (pushed, push_out) = git(
            workspace,
            &[
                "push",
                &lease,
                request.remote_url,
                &format!("{commit}:{remote_ref}"),
            ],
        );
        if !pushed {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: if request.expected_target_head.is_some() {
                    REFUSAL_EXPECTED_HEAD_MOVED.to_owned()
                } else {
                    REFUSAL_TARGET_REF_EXISTS.to_owned()
                },
                detail: push_out.lines().rev().take(3).collect::<Vec<_>>().join(" "),
            };
        }
        TargetRefAdvanceOutcome::Advanced {
            resulting_revision_id: request.intended_revision_id.to_owned(),
        }
    }

    fn open_review_request(
        &self,
        request: &ReviewRequestOpenRequest<'_>,
    ) -> ReviewRequestOpenOutcome {
        // A review request is a HOST-API effect, not a git effect. Until a
        // connector-declared review surface is bound, the honest answer is a
        // named failure carried as its own receipted sub-effect — never an
        // omission inside the publication receipt, and never a silent success.
        ReviewRequestOpenOutcome::Failed {
            refusal_code: REFUSAL_REVIEW_REQUEST_REJECTED.to_owned(),
            detail: format!(
                "no admitted review surface is bound for '{}' ({} onto {})",
                request.remote_url, request.target_ref, request.base_ref
            ),
        }
    }
}

// =====================================================================
// Durable plane
// =====================================================================

fn artifact_tail(prefix: &str, record: &Value) -> Result<String, VErr> {
    let root = scm_publication_artifact_root(record)
        .map_err(|error| verr("scm_publication_artifact_invalid", error))?;
    let encoded = root.strip_prefix("sha256:").ok_or_else(|| {
        verr(
            "scm_publication_artifact_invalid",
            "artifact root is not a digest",
        )
    })?;
    Ok(format!("{prefix}{encoded}"))
}

fn family_prefix(family: &str) -> Result<&'static str, VErr> {
    Ok(match family {
        SCM_DESTINATION_BINDING_FAMILY => "scmdb_",
        SCM_PUBLICATION_PROPOSAL_FAMILY => "scmpp_",
        SCM_PUBLICATION_EFFECT_FAMILY => "scmpe_",
        SCM_PUBLICATION_RECEIPT_FAMILY => "scmpr_",
        SCM_PUBLICATION_OPERATION_FAMILY => "scmop_",
        other => {
            return Err(verr(
                "scm_publication_artifact_invalid",
                format!("'{other}' is not a publication-plane family"),
            ))
        }
    })
}

/// Persist one publication-plane record and PROVE it landed.
///
/// Nothing here discards a write result. The local durable write is checked,
/// the Agentgres required admission is checked, and the record is read back
/// from BOTH the local slot and the strict substrate projection and compared
/// byte for byte. Any failure returns an error outcome; there is no path on
/// which a caller is told a write succeeded that did not.
pub(crate) fn persist_publication_record(
    data_dir: &str,
    family: &str,
    record: &Value,
) -> Result<String, VErr> {
    let prefix = family_prefix(family)?;
    let tail = artifact_tail(prefix, record)?;
    persist_local(data_dir, family, &tail, record).map_err(|(code, message)| {
        verr(
            "scm_publication_persist_failed",
            format!("'{family}/{tail}' was not committed ({code}: {message})"),
        )
    })?;
    let local = load_local(data_dir, family, &tail)
        .map_err(|(code, message)| {
            verr(
                "scm_publication_persist_failed",
                format!("'{family}/{tail}' could not be read back ({code}: {message})"),
            )
        })?
        .ok_or_else(|| {
            verr(
                "scm_publication_persist_failed",
                format!("'{family}/{tail}' vanished immediately after commit"),
            )
        })?;
    if &local != record {
        return Err(verr(
            "scm_publication_persist_failed",
            format!("'{family}/{tail}' diverged from the record that was written"),
        ));
    }
    super::substrate_store::admit_required(data_dir, family, &tail, record).map_err(|error| {
        verr(
            "scm_publication_agentgres_admission_failed",
            format!("required admission for '{family}/{tail}' failed ({error})"),
        )
    })?;
    super::substrate_store::verify_required_exact(data_dir, family, &tail, record).map_err(
        |error| {
            verr(
                "scm_publication_persist_failed",
                format!("'{family}/{tail}' did not converge in the substrate ({error})"),
            )
        },
    )?;
    Ok(tail)
}

/// Enumerate one publication-plane family from the durable substrate. The
/// whole plane rebuilds from these reads, so a restart loses no projection it
/// cannot reconstruct byte-exactly.
pub(crate) fn read_publication_family(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    family_prefix(family)?;
    super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
        verr(
            "scm_publication_source_incomplete",
            format!("substrate census for '{family}' failed ({error})"),
        )
    })
}

/// The exact durable truth one publication compiles against.
pub(crate) struct ScmPublicationSource {
    /// The admitted destination binding.
    pub(crate) binding: Value,
    /// The bound proposal.
    pub(crate) proposal: Value,
    /// Every effect this estate has already committed.
    pub(crate) prior_effects: Vec<Value>,
}

/// How one logical ref resolves inside a content-addressed family.
enum PinnedRecord {
    /// Every admitted record carrying the ref pins the same revision.
    Resolved(Box<Value>),
    /// No admitted record carries the ref.
    Absent,
    /// Several admitted records carry the ref under DIFFERENT revisions.
    Ambiguous {
        /// How many admitted records carry the ref.
        records: usize,
        /// How many distinct revisions those records pin.
        revisions: usize,
    },
}

/// Resolve one logical ref to the single revision a publication may compile
/// against.
///
/// Every family in this plane is content-addressed, so a logical ref is NOT a
/// key: a rebound destination or a revised proposal is a second admitted record
/// carrying the same ref. Taking the first match would make resolution follow
/// directory iteration order and let a publication silently compile against a
/// stale revision.
///
/// The plane already names an exact revision — the content commitment the
/// effect pins (`destination_binding_hash`, `proposal_hash`) — so resolution is
/// BY that revision: a ref is resolvable exactly when every record carrying it
/// pins the same one, and the matches are ordered by it so the answer never
/// depends on read order. When the records disagree the identity names more
/// than one revision, and there is no caller-supplied selector to fall back on
/// (INV-37: caller text never chooses which server truth applies), so the
/// crossing refuses BY NAME and names the collision instead of guessing.
fn resolve_pinned_revision(
    records: Vec<Value>,
    ref_field: &str,
    revision_field: &str,
    wanted: &str,
) -> PinnedRecord {
    let mut matched: Vec<((String, String), Value)> = records
        .into_iter()
        .filter(|record| record.get(ref_field).and_then(Value::as_str) == Some(wanted))
        .map(|record| {
            let revision = record
                .get(revision_field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            // Content address breaks ties, so even two records that pin the
            // same revision resolve to the same one on every read.
            let address = scm_publication_artifact_root(&record).unwrap_or_default();
            ((revision, address), record)
        })
        .collect();
    if matched.is_empty() {
        return PinnedRecord::Absent;
    }
    matched.sort_by(|left, right| left.0.cmp(&right.0));
    let mut revisions: Vec<String> = matched
        .iter()
        .map(|((revision, _), _)| revision.clone())
        .collect();
    revisions.dedup();
    if revisions.len() > 1 {
        return PinnedRecord::Ambiguous {
            records: matched.len(),
            revisions: revisions.len(),
        };
    }
    PinnedRecord::Resolved(Box::new(matched.remove(0).1))
}

/// Load the plane source for one submission, or fail closed by name.
pub(crate) fn load_publication_source(
    data_dir: &str,
    destination_binding_ref: &str,
    proposal_ref: &str,
) -> Result<ScmPublicationSource, VErr> {
    let binding = match resolve_pinned_revision(
        read_publication_family(data_dir, SCM_DESTINATION_BINDING_FAMILY)?,
        "destination_binding_ref",
        "destination_binding_hash",
        destination_binding_ref,
    ) {
        PinnedRecord::Resolved(record) => *record,
        PinnedRecord::Absent => {
            return Err(verr(
                "scm_publication_binding_not_admitted",
                format!("no admitted destination binding '{destination_binding_ref}' exists"),
            ))
        }
        PinnedRecord::Ambiguous { records, revisions } => {
            return Err(verr(
                "scm_publication_binding_ambiguous",
                format!(
                    "{SCM_REFUSAL_AMBIGUOUS_DESTINATION_BINDING_REF}: \
                     '{destination_binding_ref}' is carried by {records} admitted records pinning \
                     {revisions} different destination_binding_hash revisions; this estate will \
                     not guess which revision a publication resolves through"
                ),
            ))
        }
    };
    let proposal = match resolve_pinned_revision(
        read_publication_family(data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY)?,
        "proposal_ref",
        "proposal_hash",
        proposal_ref,
    ) {
        PinnedRecord::Resolved(record) => *record,
        PinnedRecord::Absent => {
            return Err(verr(
                "scm_publication_proposal_not_found",
                format!("no bound proposal '{proposal_ref}' exists"),
            ))
        }
        PinnedRecord::Ambiguous { records, revisions } => {
            return Err(verr(
                "scm_publication_proposal_ambiguous",
                format!(
                    "{SCM_REFUSAL_AMBIGUOUS_PROPOSAL_REF}: '{proposal_ref}' is carried by \
                     {records} admitted records pinning {revisions} different proposal_hash \
                     revisions; this estate will not guess which revision a publication compiles \
                     against"
                ),
            ))
        }
    };
    // `prior_effects` is deliberately the WHOLE family, not a lookup: the
    // compiler needs every committed effect to decide convergence, and it
    // matches them on the recomputed idempotency key (content, not a logical
    // ref) with a deterministic sort. There is no first-match hazard there.
    let prior_effects = read_publication_family(data_dir, SCM_PUBLICATION_EFFECT_FAMILY)?;
    Ok(ScmPublicationSource {
        binding,
        proposal,
        prior_effects,
    })
}

/// The authority the crossing presented, resolved before the plan compiles.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PublicationAuthority {
    /// Presented grants.
    pub(crate) grant_refs: Vec<String>,
    /// Consumed scopes.
    pub(crate) scope_refs: Vec<String>,
    /// Issued lease.
    pub(crate) capability_lease_ref: String,
    /// Admission receipt of the crossing. This is the wallet-owned admission identity, so the
    /// authority owner can resolve the exact consumption this effect was admitted under.
    pub(crate) admission_receipt_ref: String,
    /// The effect hash the authority owner actually consumed. Binding it into the Prepared
    /// commitment is what makes the published effect provably the admitted one.
    pub(crate) admission_effect_hash: String,
    /// Durable authority-owner claim coordinates. They stay outside the registered effect's
    /// closed authority object, but are retained in Prepared so a later daemon process can settle
    /// the exact claim after remote convergence is observed.
    pub(crate) final_invocation_claim_ref: Option<String>,
    pub(crate) final_invocation_claim_id: Option<String>,
}

/// What one executed publication reports back.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScmPublicationReport {
    /// The committed effect.
    pub(crate) effect: Value,
    /// The two persisted sub-effect receipts.
    pub(crate) receipts: Vec<Value>,
    /// The derived overall outcome.
    pub(crate) overall_outcome: String,
    /// Whether this submission converged onto a prior effect instead of
    /// crossing to the remote a second time.
    pub(crate) converged: bool,
}

/// Re-digest every declared post-image out of the workspace. The proposal
/// declares the bytes; this proves the workspace still holds exactly those
/// bytes before anything is committed. A whole-workspace stage is not
/// rejected here — it has no representation to reject, because only enumerated
/// rows are ever read.
fn verify_change_set_against_workspace(workspace_root: &str, files: &Value) -> Result<(), String> {
    use sha2::Digest as _;
    for row in files.as_array().into_iter().flatten() {
        let path = row.get("path").and_then(Value::as_str).unwrap_or_default();
        let kind = row
            .get("change_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let declared = row.get("content_digest").and_then(Value::as_str);
        let full = std::path::Path::new(workspace_root).join(path);
        match (kind, declared) {
            ("removed", _) => {
                if full.exists() {
                    return Err(format!("'{path}' is declared removed but is present"));
                }
            }
            (_, Some(expected)) => {
                let bytes = std::fs::read(&full)
                    .map_err(|error| format!("'{path}' could not be read ({error})"))?;
                let observed = format!("sha256:{:x}", sha2::Sha256::digest(&bytes));
                if observed != expected {
                    return Err(format!(
                        "'{path}' holds {observed}, the proposal committed to {expected}"
                    ));
                }
            }
            _ => return Err(format!("'{path}' declares no post-image digest")),
        }
    }
    Ok(())
}

fn v2_commitment(material: &Value) -> Result<String, VErr> {
    let bytes = serde_jcs::to_vec(material)
        .map_err(|error| verr("scm_publication_artifact_invalid", error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn v2_operation_identity(
    source: &ScmPublicationSource,
    submission: &ScmPublicationSubmission,
    title: &str,
    intended_revision_id: &str,
) -> Result<Value, VErr> {
    let proposal_ref = source.proposal["proposal_ref"].clone();
    let proposal_hash = source.proposal["proposal_hash"].clone();
    let base_revision_id = source.proposal["base_revision_id"].clone();
    let files = source.proposal["files"].clone();
    let admitted_at = source
        .proposal
        .get("admitted_at")
        .and_then(Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z");
    let file_set_digest = v2_commitment(&json!({
        "domain": "ioi.scm-publication-operation-file-set-jcs-sha256.v2",
        "proposal_ref": proposal_ref,
        "proposal_hash": proposal_hash,
        "base_revision_id": base_revision_id,
        "files": files,
    }))?;
    let commit_message_digest = v2_commitment(&json!({
        "domain": "ioi.scm-publication-commit-message-jcs-sha256.v2",
        "message": title,
    }))?;
    let authorship_commitment = v2_commitment(&json!({
        "domain": "ioi.scm-publication-authorship-jcs-sha256.v2",
        "name": "Hypervisor",
        "email": "hypervisor@ioi.local",
    }))?;
    let metadata_digest = v2_commitment(&json!({
        "domain": "ioi.scm-publication-frozen-commit-metadata-jcs-sha256.v2",
        "commit_message_digest": commit_message_digest,
        "authorship_commitment": authorship_commitment,
        "authored_at": admitted_at,
        "commit_timestamp": admitted_at,
    }))?;
    let namespace = source.binding["target_ref_namespace"]
        .as_str()
        .unwrap_or_default();
    Ok(json!({
        "work_run_ref": submission.work_run_ref,
        "proposal_ref": source.proposal["proposal_ref"],
        "proposal_hash": source.proposal["proposal_hash"],
        "connector_ref": source.binding["connector_ref"],
        "connector_revision_hash": source.binding["connector_revision_hash"],
        "destination_binding_ref": source.binding["destination_binding_ref"],
        "destination_binding_hash": source.binding["destination_binding_hash"],
        "repository_ref": source.binding["repository_ref"],
        "target_ref": format!("{namespace}{}", submission.target_ref_name),
        "base_ref": source.binding["base_ref"],
        "base_revision_id": source.proposal["base_revision_id"],
        "change_set_kind": SCM_CHANGE_SET_KIND,
        "files": source.proposal["files"],
        "file_set_digest": file_set_digest,
        "review_intent": if submission.review_request_requested { "requested" } else { "not_requested" },
        "frozen_commit_metadata": {
            "commit_message_digest": commit_message_digest,
            "authorship_commitment": authorship_commitment,
            "authored_at": admitted_at,
            "commit_timestamp": admitted_at,
            "metadata_digest": metadata_digest,
        },
        "intended_revision_id": intended_revision_id,
    }))
}

fn v2_operation_key(identity: &Value) -> Result<String, VErr> {
    v2_commitment(&json!({
        "domain": "ioi.scm-publication-operation-identity-jcs-sha256.v2",
        "identity": identity,
    }))
}

fn v2_cas_fingerprint(
    operation_key: &str,
    precondition: &str,
    expected_target_head: &Value,
    base_revision_id: &Value,
) -> Result<String, VErr> {
    v2_commitment(&json!({
        "domain": "ioi.scm-publication-attempt-cas-jcs-sha256.v2",
        "operation_key": operation_key,
        "target_ref_precondition": precondition,
        "expected_target_head": expected_target_head,
        "base_revision_id": base_revision_id,
    }))
}

fn v2_review_operation_key(
    operation_key: &str,
    review_intent: &str,
    target_ref: &Value,
) -> Result<String, VErr> {
    v2_commitment(&json!({
        "domain": "ioi.scm-review-request-operation-jcs-sha256.v2",
        "publication_operation_key": operation_key,
        "review_intent": review_intent,
        "target_ref": target_ref,
    }))
}

fn operation_tail(operation_key: &str) -> String {
    operation_key
        .trim_start_matches("sha256:")
        .chars()
        .take(48)
        .collect()
}

fn bounded_caller_idempotency_key(body: &Value) -> Result<String, VErr> {
    let key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !(8..=200).contains(&key.len()) || key.chars().any(char::is_control) {
        return Err(verr(
            "scm_publication_idempotency_key_invalid",
            "idempotency_key must contain 8..200 non-control characters",
        ));
    }
    Ok(key.to_owned())
}

fn caller_idempotency_hash(principal_ref: &str, key: &str) -> Result<String, VErr> {
    v2_commitment(&json!({
        "domain": SCM_CALLER_IDEMPOTENCY_DOMAIN,
        "principal_ref": principal_ref,
        "idempotency_key": key,
    }))
}

/// Reserve one caller key for one observation-independent operation identity. The key is scoped
/// to the authenticated principal and retained only as a hash. Same key + same operation is an
/// exact replay; same key + changed material is a conflict before authority or remote contact.
fn claim_caller_idempotency(
    data_dir: &str,
    principal_ref: &str,
    key: &str,
    operation_key: &str,
    now: &str,
) -> Result<(), VErr> {
    let key_hash = caller_idempotency_hash(principal_ref, key)?;
    let claims = read_publication_family(data_dir, SCM_PUBLICATION_OPERATION_FAMILY)?
        .into_iter()
        .filter(|record| {
            record.get("state").and_then(Value::as_str) == Some("caller_idempotency_claimed")
                && record
                    .pointer("/caller_idempotency/key_hash")
                    .and_then(Value::as_str)
                    == Some(key_hash.as_str())
        })
        .collect::<Vec<_>>();
    if claims
        .iter()
        .any(|record| record.get("operation_key").and_then(Value::as_str) != Some(operation_key))
    {
        return Err(verr(
            "scm_publication_idempotency_body_conflict",
            "the authenticated principal reused this idempotency_key for changed publication material",
        ));
    }
    if !claims.is_empty() {
        return Ok(());
    }
    persist_publication_record(
        data_dir,
        SCM_PUBLICATION_OPERATION_FAMILY,
        &json!({
            "schema_version": "ioi.scm-publication-operation-state.v2",
            "operation_key": operation_key,
            "state": "caller_idempotency_claimed",
            "caller_idempotency": {
                "principal_ref": principal_ref,
                "key_hash": key_hash,
                "request_hash": operation_key,
            },
            "claimed_at": now,
        }),
    )?;
    Ok(())
}

fn terminal_operation_report(
    data_dir: &str,
    operation_key: &str,
) -> Result<Option<ScmPublicationReport>, VErr> {
    let mut terminals = read_publication_family(data_dir, SCM_PUBLICATION_OPERATION_FAMILY)?
        .into_iter()
        .filter(|record| {
            record.get("operation_key").and_then(Value::as_str) == Some(operation_key)
                && record.get("state").and_then(Value::as_str) == Some("terminal")
        })
        .collect::<Vec<_>>();
    terminals.sort_by_key(|record| {
        record
            .get("committed_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    let Some(record) = terminals.pop() else {
        return Ok(None);
    };
    let effect = record.get("terminal_effect").cloned().ok_or_else(|| {
        verr(
            "scm_publication_operation_corrupt",
            "terminal operation has no effect",
        )
    })?;
    let mut receipts = Vec::new();
    for kind in ["scm_publication", "scm_review_request"] {
        if effect
            .pointer(if kind == "scm_publication" {
                "/effects/publication/receipt_ref"
            } else {
                "/effects/review_request/receipt_ref"
            })
            .and_then(Value::as_str)
            .is_some()
        {
            receipts.push(
                build_scm_publication_receipt(
                    &effect,
                    kind,
                    effect["committed_at"].as_str().unwrap_or_default(),
                )
                .map_err(|error| verr("scm_publication_artifact_invalid", error))?,
            );
        }
    }
    Ok(Some(ScmPublicationReport {
        overall_outcome: effect["overall_outcome"]
            .as_str()
            .unwrap_or("reconciliation_required")
            .to_owned(),
        effect,
        receipts,
        converged: true,
    }))
}

/// A `prepared` operation with no terminal sibling means a dispatch window was entered and never
/// closed — the daemon died between persisting the Prepared record and recording the outcome.
/// The remote may or may not carry the effect, so re-entry must NOT dispatch again. The operation
/// is reported as requiring reconciliation until an operator or a reconciler resolves the remote
/// truth. Returning `Ok(None)` means there is no unresolved dispatch window.
fn unresolved_prepared_operation(
    data_dir: &str,
    operation_key: &str,
) -> Result<Option<Value>, VErr> {
    let family = read_publication_family(data_dir, SCM_PUBLICATION_OPERATION_FAMILY)?;
    let matching = family
        .iter()
        .filter(|record| record.get("operation_key").and_then(Value::as_str) == Some(operation_key))
        .collect::<Vec<_>>();
    if matching
        .iter()
        .any(|record| record.get("state").and_then(Value::as_str) == Some("terminal"))
    {
        return Ok(None);
    }
    Ok(matching
        .into_iter()
        .find(|record| record.get("state").and_then(Value::as_str) == Some("prepared"))
        .cloned())
}

fn prepared_operation_record(data_dir: &str, operation_key: &str) -> Result<Option<Value>, VErr> {
    Ok(
        read_publication_family(data_dir, SCM_PUBLICATION_OPERATION_FAMILY)?
            .into_iter()
            .find(|record| {
                record.get("operation_key").and_then(Value::as_str) == Some(operation_key)
                    && record.get("state").and_then(Value::as_str) == Some("prepared")
            }),
    )
}

fn persist_prepared_v2(
    data_dir: &str,
    identity: &Value,
    operation_key: &str,
    authority: &PublicationAuthority,
    observed: &ObservedHeads,
    now: &str,
) -> Result<Value, VErr> {
    let operation_tag = operation_tail(operation_key);
    let (precondition, expected_target_head) = match &observed.target {
        ObservedTargetRef::Present(head) => ("expected_head", json!(head)),
        ObservedTargetRef::Absent => ("must_not_exist", Value::Null),
        ObservedTargetRef::Unobserved => {
            return Err(verr(
                "scm_publication_remote_unobservable",
                "target head could not be observed",
            ));
        }
    };
    let observation_ref = format!("evidence://ioi/hypervisor/scm/head-observation/{operation_tag}");
    let cas_fingerprint = v2_cas_fingerprint(
        operation_key,
        precondition,
        &expected_target_head,
        &identity["base_revision_id"],
    )?;
    let operation = json!({
        "operation_ref": format!("scm-publication-operation://ioi/hypervisor/{operation_tag}"),
        "operation_key": operation_key,
        "operation_key_domain": "excludes_observed_remote_state",
        "identity": identity,
    });
    let authority_value = json!({
        "authority_grant_refs": authority.grant_refs,
        "authority_scope_refs": authority.scope_refs,
        "capability_lease_ref": authority.capability_lease_ref,
        "admission_receipt_ref": authority.admission_receipt_ref,
    });
    let prepared_hash = v2_commitment(&json!({
        "domain": "ioi.scm-publication-prepared-jcs-sha256.v2",
        "operation": operation,
        "authority": authority_value,
        "admission_effect_hash": authority.admission_effect_hash,
        "cas_fingerprint": cas_fingerprint,
    }))?;
    let preparation = json!({
        "prepared_record_ref": format!("scm-publication-prepared://ioi/hypervisor/{operation_tag}"),
        "prepared_record_hash": prepared_hash,
        "prepared_persisted_at": now,
        "persistence_order": "prepared_persisted_before_remote_effect",
        "prepared_persistence_evidence_ref": format!("receipt://ioi/hypervisor/scm/prepared/{operation_tag}"),
    });
    let prepared_record = json!({
        "schema_version": "ioi.scm-publication-operation-state.v2",
        "operation_key": operation_key,
        "state": "prepared",
        "operation": operation,
        "authority": authority_value,
        "admission_effect_hash": authority.admission_effect_hash,
        "authority_claim": {
            "reference": authority.final_invocation_claim_ref,
            "claim_id": authority.final_invocation_claim_id,
            "effect_hash": authority.admission_effect_hash,
            "invoker_label": "scm.publication.advance-target-ref",
        },
        "preparation": preparation,
        "frozen_cas": {
            "target_ref_precondition": precondition,
            "expected_target_head": expected_target_head,
            "base_head": observed.base_head,
            "observed_at": now,
            "observation_evidence_ref": observation_ref,
            "fingerprint": cas_fingerprint,
        },
        "frozen_cas_fingerprint": cas_fingerprint,
        "prepared_at": now,
    });
    persist_publication_record(data_dir, SCM_PUBLICATION_OPERATION_FAMILY, &prepared_record)?;
    Ok(prepared_record)
}

fn commit_v2_terminal_effect(
    data_dir: &str,
    operation_key: &str,
    effect: Value,
    now: &str,
    converged: bool,
) -> Result<ScmPublicationReport, VErr> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        SCM_PUBLICATION_EFFECT_V2_CONTRACT,
        &effect,
    )
    .map_err(|error| verr("scm_publication_artifact_invalid", error))?;
    let mut receipts = Vec::new();
    for kind in ["scm_publication", "scm_review_request"] {
        if effect
            .pointer(if kind == "scm_publication" {
                "/effects/publication/receipt_ref"
            } else {
                "/effects/review_request/receipt_ref"
            })
            .and_then(Value::as_str)
            .is_some()
        {
            let receipt = build_scm_publication_receipt(&effect, kind, now)
                .map_err(|error| verr("scm_publication_artifact_invalid", error))?;
            persist_publication_record(data_dir, SCM_PUBLICATION_RECEIPT_FAMILY, &receipt)?;
            receipts.push(receipt);
        }
    }
    persist_publication_record(data_dir, SCM_PUBLICATION_EFFECT_FAMILY, &effect)?;
    persist_publication_record(
        data_dir,
        SCM_PUBLICATION_OPERATION_FAMILY,
        &json!({
            "schema_version": "ioi.scm-publication-operation-state.v2",
            "operation_key": operation_key,
            "state": "terminal",
            "terminal_effect": effect,
            "committed_at": now,
        }),
    )?;
    Ok(ScmPublicationReport {
        overall_outcome: effect["overall_outcome"]
            .as_str()
            .unwrap_or("reconciliation_required")
            .to_owned(),
        effect,
        receipts,
        converged,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_scm_publication_v2<P: ScmRemotePort>(
    data_dir: &str,
    port: &P,
    workspace_root: &str,
    source: &ScmPublicationSource,
    submission: &ScmPublicationSubmission,
    authority: &PublicationAuthority,
    title: &str,
    now: &str,
    identity: Value,
    operation_key: String,
) -> Result<ScmPublicationReport, VErr> {
    let operation_tag = operation_tail(&operation_key);
    let target_ref = identity["target_ref"].as_str().unwrap_or_default();
    let base_ref = identity["base_ref"].as_str().unwrap_or_default();
    let remote_url = source.binding["remote_url"].as_str().unwrap_or_default();
    let observed = port
        .observe_heads(&HeadObservationRequest {
            remote_url,
            target_ref,
            base_ref,
        })
        .map_err(|error| verr("scm_publication_remote_unobservable", error))?;
    let prepared_record = persist_prepared_v2(
        data_dir,
        &identity,
        &operation_key,
        authority,
        &observed,
        now,
    )?;
    let precondition = prepared_record
        .pointer("/frozen_cas/target_ref_precondition")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_target_head = prepared_record["frozen_cas"]["expected_target_head"].clone();
    let observation_ref = prepared_record["frozen_cas"]["observation_evidence_ref"]
        .as_str()
        .unwrap_or_default();
    let cas_fingerprint = prepared_record["frozen_cas_fingerprint"]
        .as_str()
        .unwrap_or_default();
    let operation = prepared_record["operation"].clone();
    let authority_value = prepared_record["authority"].clone();
    let preparation = prepared_record["preparation"].clone();
    let prepared_hash = preparation["prepared_record_hash"]
        .as_str()
        .unwrap_or_default();

    let base_revision = identity["base_revision_id"].as_str().unwrap_or_default();
    let moved_from_base = expected_target_head
        .as_str()
        .is_some_and(|head| head != base_revision);
    let intended_revision = identity["intended_revision_id"]
        .as_str()
        .unwrap_or_default();
    let files = &identity["files"];
    let (advance, remote_invoked, resolution, reconciliation_code) = if moved_from_base {
        (
            TargetRefAdvanceOutcome::Refused {
                refusal_code: "frozen-cas-precondition-diverged".to_owned(),
                detail: "the observed target is not the operation's frozen base".to_owned(),
            },
            false,
            "reconciliation_required",
            Some("frozen-cas-precondition-diverged"),
        )
    } else {
        match verify_change_set_against_workspace(workspace_root, files) {
            Ok(()) => (
                port.advance_target_ref(&TargetRefAdvanceRequest {
                    remote_url,
                    target_ref,
                    base_revision_id: base_revision,
                    expected_target_head: expected_target_head.as_str(),
                    files,
                    workspace_root,
                    title,
                    intended_revision_id: intended_revision,
                }),
                true,
                "first_dispatch",
                None,
            ),
            Err(detail) => (
                TargetRefAdvanceOutcome::Refused {
                    refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
                    detail,
                },
                false,
                "first_dispatch",
                None,
            ),
        }
    };

    let (
        publication_outcome,
        publication_code,
        review_outcome,
        review_code,
        review_invoked,
        overall,
        resulting,
    ) = match advance {
        TargetRefAdvanceOutcome::Refused { refusal_code, .. }
            if resolution == "reconciliation_required" =>
        {
            (
                "reconciliation_required",
                Some(refusal_code),
                "not_attempted",
                None,
                false,
                "reconciliation_required",
                Value::Null,
            )
        }
        TargetRefAdvanceOutcome::Refused { refusal_code, .. } => (
            "refused",
            Some(refusal_code),
            "not_attempted",
            None,
            false,
            "refused",
            Value::Null,
        ),
        TargetRefAdvanceOutcome::Advanced {
            resulting_revision_id,
        } => {
            if resulting_revision_id != intended_revision {
                return Err(verr(
                    "scm_publication_fresh_child_refused",
                    "remote port returned a revision other than the frozen intended revision",
                ));
            }
            if !submission.review_request_requested {
                (
                    "published",
                    None,
                    "not_requested",
                    None,
                    false,
                    "published_review_request_not_requested",
                    json!({"revision_id": resulting_revision_id, "target_head": resulting_revision_id}),
                )
            } else {
                match port.open_review_request(&ReviewRequestOpenRequest {
                    remote_url,
                    target_ref,
                    base_ref,
                    title,
                }) {
                    ReviewRequestOpenOutcome::Opened { .. } => (
                        "published",
                        None,
                        "opened",
                        None,
                        true,
                        "published_with_review_request",
                        json!({"revision_id": resulting_revision_id, "target_head": resulting_revision_id}),
                    ),
                    ReviewRequestOpenOutcome::Failed { refusal_code, .. } => (
                        "published",
                        None,
                        "failed",
                        Some(refusal_code),
                        true,
                        "review_request_failed",
                        json!({"revision_id": resulting_revision_id, "target_head": resulting_revision_id}),
                    ),
                }
            }
        }
    };
    let publication_receipt_ref =
        format!("receipt://ioi/hypervisor/scm/publication/{operation_tag}");
    let review_receipt_ref = matches!(review_outcome, "opened" | "failed")
        .then(|| format!("receipt://ioi/hypervisor/scm/review/{operation_tag}"));
    let review_intent = identity["review_intent"]
        .as_str()
        .unwrap_or("not_requested");
    let review_key =
        v2_review_operation_key(&operation_key, review_intent, &identity["target_ref"])?;
    let attempt = json!({
        "publication_attempt_ref": format!("scm-publication-attempt://ioi/hypervisor/{operation_tag}-1"),
        "attempt_number": 1,
        "cas": {
            "mechanism": "expected_head_compare_and_swap",
            "remote_update_mode": "expected_head_advance_or_refuse",
            "stale_head_disposition": "refuse_never_overwrite",
            "target_ref_precondition": precondition,
            "expected_target_head": expected_target_head,
            "observed_at": now,
            "observation_evidence_ref": observation_ref,
        },
        "cas_fingerprint": cas_fingerprint,
        "frozen_cas_fingerprint": cas_fingerprint,
        "dispatch": {
            "prepared_record_hash": prepared_hash,
            "dispatch_observation": if remote_invoked { "proven_present" } else { "proven_absent" },
            "dispatch_evidence_refs": [format!("evidence://ioi/hypervisor/scm/dispatch/{operation_tag}")],
        },
    });
    let recovery = json!({
        "resolution_disposition": resolution,
        "remote_effect_invoked": remote_invoked,
        "remote_convergence": if resulting.is_null() { if resolution == "reconciliation_required" { "diverged" } else { "unobserved" } } else { "matches_intended_revision" },
        "precondition_recheck": if moved_from_base { "moved" } else { "holds" },
        "prior_terminal_effect_ref": Value::Null,
        "prior_terminal_effect_hash": Value::Null,
        "reconciliation_code": reconciliation_code,
        "recovery_evidence_refs": [format!("evidence://ioi/hypervisor/scm/recovery/{operation_tag}")],
    });
    let effects = json!({
        "publication": {
            "effect_kind": "scm_publication",
            "outcome": publication_outcome,
            "receipt_ref": publication_receipt_ref,
            "refusal_code": publication_code,
            "evidence_refs": [format!("evidence://ioi/hypervisor/scm/publication/{operation_tag}")],
        },
        "review_request": {
            "effect_kind": "scm_review_request",
            "outcome": review_outcome,
            "receipt_ref": review_receipt_ref,
            "refusal_code": review_code,
            "evidence_refs": if review_invoked { vec![format!("evidence://ioi/hypervisor/scm/review/{operation_tag}")] } else { Vec::<String>::new() },
            "reconciliation": {
                "operation_key": review_key,
                "resolution_disposition": if review_intent == "not_requested" { "not_engaged" } else { resolution },
                "remote_effect_invoked": review_invoked,
                "reconciliation_code": Value::Null,
            },
        },
    });
    let effect_id = format!("scm-publication-effect://ioi/hypervisor/{operation_tag}-terminal");
    let mut effect = json!({
        "schema_version": "ioi.scm-publication-effect.v2",
        "publication_effect_id": effect_id,
        "publication_effect_hash": Value::Null,
        "execution_semantics": "at_most_once_execution_plus_reconciliation",
        "operation": operation,
        "authority": authority_value,
        "preparation": preparation,
        "attempt": attempt,
        "recovery": recovery,
        "outcome": { "resulting_revision": resulting, "proof_ref": format!("receipt://ioi/hypervisor/scm/proof/{operation_tag}") },
        "effects": effects,
        "overall_outcome": overall,
        "nonclaims": ["grants_no_authority", "no_remote_acceptance_beyond_receipt_evidence", "asserts_no_review_approval", "asserts_no_exactly_once_execution"],
        "committed_at": now,
    });
    effect["publication_effect_hash"] = json!(v2_commitment(&json!({
        "domain": "ioi.scm-publication-effect-commitment-jcs-sha256.v2",
        "schema_version": effect["schema_version"],
        "publication_effect_id": effect["publication_effect_id"],
        "execution_semantics": effect["execution_semantics"],
        "operation": effect["operation"],
        "authority": effect["authority"],
        "preparation": effect["preparation"],
        "attempt": effect["attempt"],
        "recovery": effect["recovery"],
        "outcome": effect["outcome"],
        "effects": effect["effects"],
        "overall_outcome": effect["overall_outcome"],
        "nonclaims": effect["nonclaims"],
        "committed_at": effect["committed_at"],
    }))?);
    commit_v2_terminal_effect(data_dir, &operation_key, effect, now, false)
}

/// Resolve a crash window from the durable Prepared record and remote truth. This path never calls
/// `advance_target_ref` or `open_review_request`: convergence is recovered when the target already
/// equals the frozen intended revision; every other uncertain disposition becomes a terminal,
/// named reconciliation result. A later operator workflow may supersede that result, but a retry
/// cannot create a fresh commit or review request.
fn reconcile_prepared_operation<P: ScmRemotePort>(
    data_dir: &str,
    port: &P,
    source: &ScmPublicationSource,
    prepared: &Value,
    now: &str,
) -> Result<ScmPublicationReport, VErr> {
    if prepared.get("state").and_then(Value::as_str) != Some("prepared") {
        return Err(verr(
            "scm_publication_operation_corrupt",
            "reconciliation requires one durable Prepared operation",
        ));
    }
    let operation = prepared.get("operation").cloned().ok_or_else(|| {
        verr(
            "scm_publication_operation_corrupt",
            "Prepared carries no operation",
        )
    })?;
    let identity = operation.get("identity").cloned().ok_or_else(|| {
        verr(
            "scm_publication_operation_corrupt",
            "Prepared carries no operation identity",
        )
    })?;
    let operation_key = operation
        .get("operation_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if operation_key.is_empty() || v2_operation_key(&identity)? != operation_key {
        return Err(verr(
            "scm_publication_operation_corrupt",
            "Prepared operation key does not recompute",
        ));
    }
    if identity.get("destination_binding_hash") != source.binding.get("destination_binding_hash")
        || identity.get("proposal_hash") != source.proposal.get("proposal_hash")
    {
        return Err(verr(
            "scm_publication_operation_corrupt",
            "Prepared source revisions no longer resolve to their admitted bytes",
        ));
    }
    let frozen = prepared.get("frozen_cas").ok_or_else(|| {
        verr(
            "scm_publication_operation_corrupt",
            "Prepared carries no frozen compare-and-swap",
        )
    })?;
    let precondition = frozen
        .get("target_ref_precondition")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_target_head = frozen
        .get("expected_target_head")
        .cloned()
        .unwrap_or(Value::Null);
    let frozen_fingerprint = frozen
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if frozen_fingerprint.is_empty()
        || v2_cas_fingerprint(
            operation_key,
            precondition,
            &expected_target_head,
            &identity["base_revision_id"],
        )? != frozen_fingerprint
        || prepared
            .get("frozen_cas_fingerprint")
            .and_then(Value::as_str)
            != Some(frozen_fingerprint)
    {
        return Err(verr(
            "scm_publication_operation_corrupt",
            "Prepared frozen compare-and-swap does not recompute",
        ));
    }
    let target_ref = identity["target_ref"].as_str().unwrap_or_default();
    let base_ref = identity["base_ref"].as_str().unwrap_or_default();
    let remote_url = source.binding["remote_url"].as_str().unwrap_or_default();
    let observed = port
        .observe_heads(&HeadObservationRequest {
            remote_url,
            target_ref,
            base_ref,
        })
        .map_err(|error| verr("scm_publication_remote_unobservable", error))?;
    let intended_revision = identity["intended_revision_id"]
        .as_str()
        .unwrap_or_default();
    let converged = matches!(
        &observed.target,
        ObservedTargetRef::Present(head) if head == intended_revision
    );
    let precondition_holds = match (&observed.target, precondition) {
        (ObservedTargetRef::Absent, "must_not_exist") => true,
        (ObservedTargetRef::Present(head), "expected_head") => {
            expected_target_head.as_str() == Some(head.as_str())
        }
        _ => false,
    };
    let (resolution, remote_convergence, precondition_recheck, reconciliation_code) = if converged {
        (
            "recovered_converged_remote",
            "matches_intended_revision",
            "holds",
            None,
        )
    } else if matches!(observed.target, ObservedTargetRef::Unobserved) {
        (
            "reconciliation_required",
            "unobserved",
            "unobserved",
            Some("remote-head-unobservable"),
        )
    } else if precondition_holds {
        (
            "reconciliation_required",
            "unobserved",
            "holds",
            Some("dispatch-disposition-indeterminate"),
        )
    } else {
        (
            "reconciliation_required",
            "diverged",
            "moved",
            Some("moved-head-ambiguity"),
        )
    };
    let review_intent = identity["review_intent"]
        .as_str()
        .unwrap_or("not_requested");
    let operation_tag = operation_tail(operation_key);
    let review_key =
        v2_review_operation_key(operation_key, review_intent, &identity["target_ref"])?;
    let (
        publication_outcome,
        publication_code,
        review_outcome,
        review_receipt_ref,
        review_code,
        review_resolution,
        overall,
        resulting,
    ) = if converged {
        if review_intent == "not_requested" {
            (
                "published",
                None,
                "not_requested",
                None,
                None,
                "not_engaged",
                "published_review_request_not_requested",
                json!({"revision_id": intended_revision, "target_head": intended_revision}),
            )
        } else {
            (
                "published",
                None,
                "reconciliation_required",
                Some(format!(
                    "receipt://ioi/hypervisor/scm/review/{operation_tag}"
                )),
                Some("review-request-dispatch-ambiguous"),
                "reconciliation_required",
                "published_review_request_reconciliation_required",
                json!({"revision_id": intended_revision, "target_head": intended_revision}),
            )
        }
    } else {
        (
            "reconciliation_required",
            reconciliation_code,
            "not_attempted",
            None,
            None,
            "not_engaged",
            "reconciliation_required",
            Value::Null,
        )
    };
    let attempt = json!({
        "publication_attempt_ref": format!("scm-publication-attempt://ioi/hypervisor/{operation_tag}-2"),
        "attempt_number": 2,
        "cas": {
            "mechanism": "expected_head_compare_and_swap",
            "remote_update_mode": "expected_head_advance_or_refuse",
            "stale_head_disposition": "refuse_never_overwrite",
            "target_ref_precondition": precondition,
            "expected_target_head": expected_target_head,
            "observed_at": frozen.get("observed_at").cloned().unwrap_or(Value::Null),
            "observation_evidence_ref": frozen.get("observation_evidence_ref").cloned().unwrap_or(Value::Null),
        },
        "cas_fingerprint": frozen_fingerprint,
        "frozen_cas_fingerprint": frozen_fingerprint,
        "dispatch": {
            "prepared_record_hash": prepared["preparation"]["prepared_record_hash"],
            "dispatch_observation": "indeterminate",
            "dispatch_evidence_refs": [format!("evidence://ioi/hypervisor/scm/dispatch-recovery/{operation_tag}")],
        },
    });
    let effects = json!({
        "publication": {
            "effect_kind": "scm_publication",
            "outcome": publication_outcome,
            "receipt_ref": format!("receipt://ioi/hypervisor/scm/publication/{operation_tag}"),
            "refusal_code": publication_code,
            "evidence_refs": [format!("evidence://ioi/hypervisor/scm/publication-recovery/{operation_tag}")],
        },
        "review_request": {
            "effect_kind": "scm_review_request",
            "outcome": review_outcome,
            "receipt_ref": review_receipt_ref,
            "refusal_code": review_code,
            "evidence_refs": if review_outcome == "reconciliation_required" { vec![format!("evidence://ioi/hypervisor/scm/review-recovery/{operation_tag}")] } else { Vec::<String>::new() },
            "reconciliation": {
                "operation_key": review_key,
                "resolution_disposition": review_resolution,
                "remote_effect_invoked": false,
                "reconciliation_code": if review_outcome == "reconciliation_required" { Some("review-request-dispatch-ambiguous") } else { None },
            },
        },
    });
    let mut effect = json!({
        "schema_version": "ioi.scm-publication-effect.v2",
        "publication_effect_id": format!("scm-publication-effect://ioi/hypervisor/{operation_tag}-terminal"),
        "publication_effect_hash": Value::Null,
        "execution_semantics": "at_most_once_execution_plus_reconciliation",
        "operation": operation,
        "authority": prepared["authority"],
        "preparation": prepared["preparation"],
        "attempt": attempt,
        "recovery": {
            "resolution_disposition": resolution,
            "remote_effect_invoked": false,
            "remote_convergence": remote_convergence,
            "precondition_recheck": precondition_recheck,
            "prior_terminal_effect_ref": Value::Null,
            "prior_terminal_effect_hash": Value::Null,
            "reconciliation_code": reconciliation_code,
            "recovery_evidence_refs": [format!("evidence://ioi/hypervisor/scm/recovery-probe/{operation_tag}")],
        },
        "outcome": {
            "resulting_revision": resulting,
            "proof_ref": format!("receipt://ioi/hypervisor/scm/proof/{operation_tag}"),
        },
        "effects": effects,
        "overall_outcome": overall,
        "nonclaims": ["grants_no_authority", "no_remote_acceptance_beyond_receipt_evidence", "asserts_no_review_approval", "asserts_no_exactly_once_execution"],
        "committed_at": now,
    });
    effect["publication_effect_hash"] = json!(v2_commitment(&json!({
        "domain": "ioi.scm-publication-effect-commitment-jcs-sha256.v2",
        "schema_version": effect["schema_version"],
        "publication_effect_id": effect["publication_effect_id"],
        "execution_semantics": effect["execution_semantics"],
        "operation": effect["operation"],
        "authority": effect["authority"],
        "preparation": effect["preparation"],
        "attempt": effect["attempt"],
        "recovery": effect["recovery"],
        "outcome": effect["outcome"],
        "effects": effect["effects"],
        "overall_outcome": effect["overall_outcome"],
        "nonclaims": effect["nonclaims"],
        "committed_at": effect["committed_at"],
    }))?);
    commit_v2_terminal_effect(data_dir, operation_key, effect, now, true)
}

/// Execute one publication submission end to end against durable truth and a
/// remote port.
///
/// Order: resolve trusted inputs → observe heads → compile (total, named
/// refusals) → converge a replay or cross once → build the effect with a
/// DERIVED overall outcome → persist and verify the effect and BOTH receipts →
/// only then report.
pub(crate) fn execute_scm_publication<P: ScmRemotePort>(
    data_dir: &str,
    port: &P,
    workspace_root: &str,
    submission: &ScmPublicationSubmission,
    authority: &PublicationAuthority,
    title: &str,
    now: &str,
) -> Result<ScmPublicationReport, VErr> {
    let source = load_publication_source(
        data_dir,
        &submission.destination_binding_ref,
        &submission.proposal_ref,
    )?;

    let target_leaf = submission.target_ref_name.trim();
    let namespace = source
        .binding
        .get("target_ref_namespace")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let base_ref = source
        .binding
        .get("base_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let remote_url = source
        .binding
        .get("remote_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let probe_target_ref = format!("{namespace}{target_leaf}");

    let observed = port
        .observe_heads(&HeadObservationRequest {
            remote_url: &remote_url,
            target_ref: &probe_target_ref,
            base_ref: &base_ref,
        })
        .map_err(|error| {
            verr(
                "scm_publication_remote_unobservable",
                format!("the remote heads could not be observed ({error})"),
            )
        })?;

    let observation_evidence_ref = format!(
        "evidence://{}/scm/head-observation/{}",
        source
            .binding
            .get("repository_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim_start_matches("repository://"),
        observation_tail(&observed, &probe_target_ref)
    );

    let truth = ScmPublicationServerTruth {
        destination_binding: &source.binding,
        proposal: &source.proposal,
        observed_target_ref: observed.target.clone(),
        observed_base_head: &observed.base_head,
        observed_at: now,
        observation_evidence_ref: &observation_evidence_ref,
        authority_grant_refs: &authority.grant_refs,
        authority_scope_refs: &authority.scope_refs,
        capability_lease_ref: &authority.capability_lease_ref,
        admission_receipt_ref: &authority.admission_receipt_ref,
        prior_effects: &source.prior_effects,
    };

    let compiled = compile_scm_publication(&truth, submission).map_err(|verdict| {
        verr(
            "scm_publication_refused",
            format!(
                "{}: {}",
                verdict.refusal_dimension.unwrap_or("unnamed"),
                verdict.refusal_reason.unwrap_or_default()
            ),
        )
    })?;

    // An exact resubmission converges onto the prior effect: no second remote
    // crossing, no second receipt, and a record that is byte-identical on
    // every further replay.
    if compiled.submission_disposition == "converged_replay" {
        let artifacts = build_converged_replay_effect(&compiled, now).map_err(refusal_err)?;
        let receipts = persist_effect_graph(data_dir, &artifacts.effect, now)?;
        return Ok(ScmPublicationReport {
            effect: artifacts.effect,
            receipts,
            overall_outcome: artifacts.overall_outcome.as_str().to_owned(),
            converged: true,
        });
    }

    let files = compiled.change_set_without_result["files"].clone();
    let intended_revision = port
        .prepare_target_revision(&TargetRevisionPreparationRequest {
            base_revision_id: &compiled.base_revision_id,
            files: &files,
            workspace_root,
            title,
            authored_at: now,
        })
        .map_err(|detail| verr("scm_publication_prepare_failed", detail))?;
    let advance = match verify_change_set_against_workspace(workspace_root, &files) {
        Ok(()) => port.advance_target_ref(&TargetRefAdvanceRequest {
            remote_url: &compiled.remote_url,
            target_ref: &compiled.target_ref,
            base_revision_id: &compiled.base_revision_id,
            expected_target_head: compiled.expected_target_head.as_deref(),
            files: &files,
            workspace_root,
            title,
            intended_revision_id: &intended_revision,
        }),
        Err(detail) => TargetRefAdvanceOutcome::Refused {
            refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
            detail,
        },
    };

    let sub_effects = match advance {
        TargetRefAdvanceOutcome::Refused {
            refusal_code,
            detail: _,
        } => ScmPublicationSubEffects {
            publication_outcome: ScmPublicationOutcome::Refused,
            publication_receipt_ref: compiled
                .publication_receipt_ref(ScmPublicationOutcome::Refused),
            publication_refusal_code: Some(refusal_code),
            publication_evidence_refs: vec![compiled.publication_evidence_ref()],
            review_request_outcome: ScmReviewRequestOutcome::NotAttempted,
            review_request_receipt_ref: None,
            review_request_refusal_code: None,
            review_request_evidence_refs: Vec::new(),
            resulting_revision_id: None,
            proof_ref: compiled.compare_and_swap_proof_ref(),
        },
        TargetRefAdvanceOutcome::Advanced {
            resulting_revision_id,
        } => {
            let (review_outcome, review_receipt, review_code, review_evidence) =
                if !compiled.review_request_requested {
                    (
                        ScmReviewRequestOutcome::NotRequested,
                        None,
                        None,
                        Vec::new(),
                    )
                } else {
                    match port.open_review_request(&ReviewRequestOpenRequest {
                        remote_url: &compiled.remote_url,
                        target_ref: &compiled.target_ref,
                        base_ref: &compiled.base_ref,
                        title,
                    }) {
                        ReviewRequestOpenOutcome::Opened { .. } => (
                            ScmReviewRequestOutcome::Opened,
                            Some(compiled.review_request_receipt_ref()),
                            None,
                            vec![compiled.review_request_evidence_ref()],
                        ),
                        ReviewRequestOpenOutcome::Failed { refusal_code, .. } => (
                            ScmReviewRequestOutcome::Failed,
                            Some(compiled.review_request_receipt_ref()),
                            Some(refusal_code),
                            vec![compiled.review_request_evidence_ref()],
                        ),
                    }
                };
            ScmPublicationSubEffects {
                publication_outcome: ScmPublicationOutcome::Published,
                publication_receipt_ref: compiled
                    .publication_receipt_ref(ScmPublicationOutcome::Published),
                publication_refusal_code: None,
                publication_evidence_refs: vec![compiled.publication_evidence_ref()],
                review_request_outcome: review_outcome,
                review_request_receipt_ref: review_receipt,
                review_request_refusal_code: review_code,
                review_request_evidence_refs: review_evidence,
                resulting_revision_id: Some(resulting_revision_id),
                proof_ref: compiled.compare_and_swap_proof_ref(),
            }
        }
    };

    let artifacts =
        build_scm_publication_effect(&compiled, &sub_effects, now).map_err(refusal_err)?;
    let receipts = persist_effect_graph(data_dir, &artifacts.effect, now)?;
    Ok(ScmPublicationReport {
        effect: artifacts.effect,
        receipts,
        overall_outcome: artifacts.overall_outcome.as_str().to_owned(),
        converged: false,
    })
}

fn observation_tail(observed: &ObservedHeads, target_ref: &str) -> String {
    let state = match &observed.target {
        ObservedTargetRef::Absent => "absent".to_owned(),
        ObservedTargetRef::Unobserved => "unobserved".to_owned(),
        ObservedTargetRef::Present(head) => head.replace("scm-revision:", ""),
    };
    let digest = ioi_types::app::scm_publication::scm_publication_artifact_root(&json!({
        "target_ref": target_ref,
        "target_state": state,
        "base_head": observed.base_head,
    }))
    .unwrap_or_default();
    digest
        .trim_start_matches("sha256:")
        .chars()
        .take(24)
        .collect()
}

fn refusal_err(verdict: ioi_types::app::scm_publication::ScmPublicationVerdict) -> VErr {
    verr(
        "scm_publication_refused",
        format!(
            "{}: {}",
            verdict.refusal_dimension.unwrap_or("unnamed"),
            verdict.refusal_reason.unwrap_or_default()
        ),
    )
}

/// Persist the effect and BOTH sub-effect receipts, verifying each write, and
/// re-adjudicate the effect after the round trip. Nothing is reported to a
/// caller until every one of these writes has been proven durable.
fn persist_effect_graph(data_dir: &str, effect: &Value, now: &str) -> Result<Vec<Value>, VErr> {
    let mut receipts = Vec::with_capacity(2);
    for kind in ["scm_publication", "scm_review_request"] {
        // A sub-effect with no receipt of its own (a not-requested or
        // not-attempted review request) has nothing to receipt; the effect
        // still records its outcome.
        let has_receipt = effect
            .pointer(&format!(
                "/effects/{}/receipt_ref",
                if kind == "scm_publication" {
                    "publication"
                } else {
                    "review_request"
                }
            ))
            .and_then(Value::as_str)
            .is_some();
        if !has_receipt {
            continue;
        }
        let receipt = build_scm_publication_receipt(effect, kind, now)
            .map_err(|error| verr("scm_publication_artifact_invalid", error))?;
        persist_publication_record(data_dir, SCM_PUBLICATION_RECEIPT_FAMILY, &receipt)?;
        receipts.push(receipt);
    }
    let tail = persist_publication_record(data_dir, SCM_PUBLICATION_EFFECT_FAMILY, effect)?;
    // Read the effect back out of the durable plane and re-adjudicate it: the
    // record a caller is told about is the record that landed.
    let stored = load_local(data_dir, SCM_PUBLICATION_EFFECT_FAMILY, &tail)
        .map_err(|(code, message)| {
            verr(
                "scm_publication_persist_failed",
                format!("the committed effect could not be read back ({code}: {message})"),
            )
        })?
        .ok_or_else(|| {
            verr(
                "scm_publication_persist_failed",
                "the committed effect vanished after commit",
            )
        })?;
    let verdict = verify_scm_publication_effect(&stored);
    if !verdict.admitted {
        return Err(refusal_err(verdict));
    }
    Ok(receipts)
}

// =====================================================================
// Admission routes for the plane's trusted inputs
// =====================================================================

fn status_for(code: &str) -> StatusCode {
    match code {
        "scm_publication_binding_not_admitted" | "scm_publication_proposal_not_found" => {
            StatusCode::NOT_FOUND
        }
        // An identity that names several admitted revisions is a conflict in
        // the estate's own records, not a missing record.
        "scm_publication_binding_ambiguous"
        | "scm_publication_proposal_ambiguous"
        | "scm_publication_refused"
        | "scm_publication_artifact_invalid"
        | "scm_publication_artifact_ref_conflict"
        | "scm_publication_idempotency_body_conflict" => StatusCode::CONFLICT,
        "scm_publication_idempotency_key_invalid" => StatusCode::BAD_REQUEST,
        "scm_publication_remote_unobservable" => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn fail(error: VErr) -> (StatusCode, Json<Value>) {
    let (code, message) = error;
    (
        status_for(&code),
        Json(json!({ "ok": false, "reason": code, "message": message, "fail_closed": true })),
    )
}

fn scope_fail(error: super::substrate_store::RequestScopeRefusal) -> (StatusCode, Json<Value>) {
    use super::substrate_store::RequestScopeRefusal;
    let status = match error {
        RequestScopeRefusal::AuthenticationRequired
        | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
        RequestScopeRefusal::TenantAuthorityRequired
        | RequestScopeRefusal::ResourceScopeRequired
        | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(json!({
            "ok": false,
            "reason": error.code(),
            "message": error.message(),
            "fail_closed": true,
        })),
    )
}

pub(crate) fn request_identity(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<super::substrate_store::RequestIdentity, (StatusCode, Json<Value>)> {
    super::substrate_store::resolve_request_identity(data_dir, headers).map_err(scope_fail)
}

fn requested_owner_ref(
    body: &Value,
    identity: &super::substrate_store::RequestIdentity,
) -> Result<String, (StatusCode, Json<Value>)> {
    let owner_ref = body
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if owner_ref.is_empty()
        || owner_ref.len() > 500
        || owner_ref.chars().any(char::is_whitespace)
        || !(owner_ref.starts_with("org://") || owner_ref.starts_with("project://"))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "reason": "scm_publication_owner_ref_invalid",
                "message": "owner_ref must name one canonical org:// or project:// tenant",
                "fail_closed": true,
            })),
        ));
    }
    if !identity.authorizes_tenant(owner_ref) {
        return Err(scope_fail(
            super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired,
        ));
    }
    Ok(owner_ref.to_owned())
}

fn bind_publication_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    resource_kind: &str,
    resource_ref: &str,
    owner_ref: &str,
    idempotency_key: &str,
) -> Result<super::substrate_store::RequestResourceScope, (StatusCode, Json<Value>)> {
    super::substrate_store::bind_request_resource_scope(
        data_dir,
        identity,
        resource_kind,
        resource_ref,
        owner_ref,
        owner_ref,
        idempotency_key,
    )
    .map_err(scope_fail)
}

fn authorize_publication_source_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    source: &ScmPublicationSource,
) -> Result<String, (StatusCode, Json<Value>)> {
    let binding_ref = source.binding["destination_binding_ref"]
        .as_str()
        .unwrap_or_default();
    let proposal_ref = source.proposal["proposal_ref"].as_str().unwrap_or_default();
    let binding_owner = source.binding["owner_ref"].as_str().unwrap_or_default();
    let proposal_owner = source.proposal["owner_ref"].as_str().unwrap_or_default();
    if binding_owner.is_empty() || binding_owner != proposal_owner {
        return Err(scope_fail(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let binding_scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        SCM_DESTINATION_SCOPE_KIND,
        binding_ref,
        Some(binding_owner),
    )
    .map_err(scope_fail)?;
    let proposal_scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        SCM_PROPOSAL_SCOPE_KIND,
        proposal_ref,
        Some(proposal_owner),
    )
    .map_err(scope_fail)?;
    if binding_scope.owner_ref != proposal_scope.owner_ref {
        return Err(scope_fail(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    Ok(binding_scope.owner_ref)
}

async fn settle_prepared_authority_from_remote_truth(
    data_dir: &str,
    prepared: &Value,
    report: &ScmPublicationReport,
) -> Result<(), String> {
    let claim = prepared
        .get("authority_claim")
        .ok_or_else(|| "Prepared carries no authority claim coordinates".to_string())?;
    let coordinate = |field: &str| {
        claim
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Prepared authority claim carries no '{field}'"))
    };
    let reference = coordinate("reference")?;
    let claim_id = coordinate("claim_id")?;
    let effect_hash = coordinate("effect_hash")?;
    let invoker_label = coordinate("invoker_label")?;
    let resolution = report
        .effect
        .pointer("/recovery/resolution_disposition")
        .and_then(Value::as_str)
        .unwrap_or("reconciliation_required");
    let publication_outcome = report
        .effect
        .pointer("/effects/publication/outcome")
        .and_then(Value::as_str)
        .unwrap_or("reconciliation_required");
    let remote_invoked = report
        .effect
        .pointer("/recovery/remote_effect_invoked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if publication_outcome == "published"
        || remote_invoked
        || resolution == "recovered_converged_remote"
    {
        super::governed_authority::reconcile_final_invocation_as_invoked(
            data_dir,
            reference,
            claim_id,
            effect_hash,
            invoker_label,
            &report.overall_outcome,
        )
        .await
    } else if publication_outcome == "refused" {
        let reason = report
            .effect
            .pointer("/effects/publication/refusal_code")
            .and_then(Value::as_str)
            .unwrap_or("pre-dispatch-refusal");
        super::governed_authority::reconcile_final_invocation_as_refused(
            data_dir,
            reference,
            claim_id,
            effect_hash,
            invoker_label,
            reason,
        )
        .await
    } else {
        let reason = report
            .effect
            .pointer("/recovery/reconciliation_code")
            .and_then(Value::as_str)
            .unwrap_or("prepared-dispatch-disposition-indeterminate");
        super::governed_authority::mark_final_invocation_reconciliation_required(
            data_dir,
            reference,
            claim_id,
            effect_hash,
            invoker_label,
            reason,
        )
        .await
    }
}

fn bounded_resource_ref(body: &Value, field: &str, prefix: &str) -> Result<String, VErr> {
    let value = body.get(field).and_then(Value::as_str).unwrap_or_default();
    if value.len() > 500
        || !value.starts_with(prefix)
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(verr(
            "scm_publication_artifact_invalid",
            format!("{field} must be one bounded canonical {prefix} reference"),
        ));
    }
    Ok(value.to_owned())
}

fn immutable_admission_view(record: &Value, hash_field: &str) -> Value {
    let mut material = record.as_object().cloned().unwrap_or_default();
    material.remove(hash_field);
    material.remove("admitted_at");
    Value::Object(material)
}

/// Logical admission refs are immutable. This makes an exact HTTP retry converge to the admitted
/// bytes instead of manufacturing a second timestamped revision, while a changed body fails before
/// it can poison resolution with two revisions carrying the same ref.
fn converge_admission_by_ref(
    data_dir: &str,
    family: &str,
    ref_field: &str,
    hash_field: &str,
    candidate: &Value,
) -> Result<Option<Value>, VErr> {
    let wanted = candidate
        .get(ref_field)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut existing = read_publication_family(data_dir, family)?
        .into_iter()
        .filter(|record| record.get(ref_field).and_then(Value::as_str) == Some(wanted))
        .collect::<Vec<_>>();
    if existing.is_empty() {
        return Ok(None);
    }
    let candidate_view = immutable_admission_view(candidate, hash_field);
    if existing
        .iter()
        .any(|record| immutable_admission_view(record, hash_field) != candidate_view)
    {
        return Err(verr(
            "scm_publication_artifact_ref_conflict",
            format!("{ref_field} '{wanted}' is already bound to different admitted material"),
        ));
    }
    existing.sort_by_key(|record| scm_publication_artifact_root(record).unwrap_or_default());
    Ok(existing.into_iter().next())
}

/// POST /v1/hypervisor/scm-destination-bindings — admit one destination
/// binding. The binding, not the caller, is what a later publication resolves
/// its remote from.
pub(crate) async fn handle_destination_binding_admit(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match request_identity(&state.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let owner_ref = match requested_owner_ref(&body, &identity) {
        Ok(owner_ref) => owner_ref,
        Err(response) => return response,
    };
    let idempotency_key = match bounded_caller_idempotency_key(&body) {
        Ok(key) => key,
        Err(error) => return fail(error),
    };
    let destination_binding_ref = match bounded_resource_ref(
        &body,
        "destination_binding_ref",
        "scm-destination-binding://",
    ) {
        Ok(reference) => reference,
        Err(error) => return fail(error),
    };
    let scope = match bind_publication_scope(
        &state.data_dir,
        &identity,
        SCM_DESTINATION_SCOPE_KIND,
        &destination_binding_ref,
        &owner_ref,
        &idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let mut record = json!({
        "schema_version": SCM_DESTINATION_BINDING_SCHEMA_VERSION,
        "destination_binding_ref": destination_binding_ref,
        "destination_binding_hash": Value::Null,
        "connector_ref": body.get("connector_ref").cloned().unwrap_or(Value::Null),
        "connector_revision_hash": body.get("connector_revision_hash").cloned().unwrap_or(Value::Null),
        "repository_ref": body.get("repository_ref").cloned().unwrap_or(Value::Null),
        "base_ref": body.get("base_ref").cloned().unwrap_or(Value::Null),
        "target_ref_namespace": body.get("target_ref_namespace").cloned().unwrap_or(Value::Null),
        "remote_url": body.get("remote_url").cloned().unwrap_or(Value::Null),
        "admission_receipt_ref": body.get("admission_receipt_ref").cloned().unwrap_or(Value::Null),
        "owner_ref": owner_ref,
        "principal_ref": identity.principal_ref,
        "request_scope_ref": scope.correlation_ref,
        "admitted_at": super::iso_now(),
    });
    let hash = match scm_destination_binding_hash(&record) {
        Ok(hash) => hash,
        Err(error) => return fail(verr("scm_publication_artifact_invalid", error)),
    };
    record["destination_binding_hash"] = json!(hash);
    match converge_admission_by_ref(
        &state.data_dir,
        SCM_DESTINATION_BINDING_FAMILY,
        "destination_binding_ref",
        "destination_binding_hash",
        &record,
    ) {
        Ok(Some(existing)) => {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "converged": true, "destination_binding": existing })),
            );
        }
        Ok(None) => {}
        Err(error) => return fail(error),
    }
    match persist_publication_record(&state.data_dir, SCM_DESTINATION_BINDING_FAMILY, &record) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "destination_binding": record })),
        ),
        Err(error) => fail(error),
    }
}

/// GET /v1/hypervisor/scm-destination-bindings — the admitted bindings.
pub(crate) async fn handle_destination_binding_list(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match request_identity(&state.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let visible = match super::substrate_store::authorized_request_resource_refs(
        &state.data_dir,
        &identity,
        SCM_DESTINATION_SCOPE_KIND,
    ) {
        Ok(refs) => refs,
        Err(error) => return scope_fail(error),
    };
    match read_publication_family(&state.data_dir, SCM_DESTINATION_BINDING_FAMILY) {
        Ok(rows) => {
            let rows = rows
                .into_iter()
                .filter(|record| {
                    record
                        .get("destination_binding_ref")
                        .and_then(Value::as_str)
                        .is_some_and(|reference| visible.contains(reference))
                })
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "destination_bindings": rows })),
            )
        }
        Err(error) => fail(error),
    }
}

/// POST /v1/hypervisor/scm-publication-proposals — admit one enumerated,
/// proposal-bound change set. A whole-workspace snapshot has no admitted
/// shape here, so nothing downstream can express one.
pub(crate) async fn handle_publication_proposal_admit(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match request_identity(&state.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let owner_ref = match requested_owner_ref(&body, &identity) {
        Ok(owner_ref) => owner_ref,
        Err(response) => return response,
    };
    let idempotency_key = match bounded_caller_idempotency_key(&body) {
        Ok(key) => key,
        Err(error) => return fail(error),
    };
    match admit_publication_proposal(
        &state.data_dir,
        &identity,
        &owner_ref,
        &idempotency_key,
        &body,
    ) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "proposal": record })),
        ),
        Err(response) => response,
    }
}

pub(crate) fn admit_publication_proposal(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    owner_ref: &str,
    idempotency_key: &str,
    body: &Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    if !identity.authorizes_tenant(owner_ref) {
        return Err(scope_fail(
            super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired,
        ));
    }
    let proposal_ref = bounded_resource_ref(body, "proposal_ref", "proposal://").map_err(fail)?;
    let scope = bind_publication_scope(
        data_dir,
        identity,
        SCM_PROPOSAL_SCOPE_KIND,
        &proposal_ref,
        owner_ref,
        idempotency_key,
    )?;
    let mut record = json!({
        "schema_version": SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION,
        "proposal_ref": proposal_ref,
        "proposal_hash": Value::Null,
        "change_set_kind": SCM_CHANGE_SET_KIND,
        "base_revision_id": body.get("base_revision_id").cloned().unwrap_or(Value::Null),
        "files": body.get("files").cloned().unwrap_or(json!([])),
        "work_run_ref": body.get("work_run_ref").cloned().unwrap_or(Value::Null),
        "owner_ref": owner_ref,
        "principal_ref": identity.principal_ref,
        "request_scope_ref": scope.correlation_ref,
        "admitted_at": super::iso_now(),
    });
    let commitment = scm_publication_proposal_commitment(&record)
        .map_err(|error| fail(verr("scm_publication_artifact_invalid", error)))?;
    record["proposal_hash"] = json!(commitment);
    if let Some(existing) = converge_admission_by_ref(
        data_dir,
        SCM_PUBLICATION_PROPOSAL_FAMILY,
        "proposal_ref",
        "proposal_hash",
        &record,
    )
    .map_err(fail)?
    {
        return Ok(existing);
    }
    persist_publication_record(data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY, &record).map_err(fail)?;
    Ok(record)
}

/// GET /v1/hypervisor/scm-publication-effects — every committed effect,
/// rebuilt from the durable plane.
pub(crate) async fn handle_publication_effect_list(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match request_identity(&state.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let visible = match super::substrate_store::authorized_request_resource_refs(
        &state.data_dir,
        &identity,
        SCM_DESTINATION_SCOPE_KIND,
    ) {
        Ok(refs) => refs,
        Err(error) => return scope_fail(error),
    };
    match read_publication_family(&state.data_dir, SCM_PUBLICATION_EFFECT_FAMILY) {
        Ok(rows) => {
            let rows = rows
                .into_iter()
                .filter(|record| {
                    record
                        .pointer("/operation/identity/destination_binding_ref")
                        .or_else(|| record.pointer("/destination/destination_binding_ref"))
                        .and_then(Value::as_str)
                        .is_some_and(|reference| visible.contains(reference))
                })
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "publication_effects": rows })),
            )
        }
        Err(error) => fail(error),
    }
}

// =====================================================================
// The publication route
// =====================================================================

fn submission_from_body(body: &Value) -> ScmPublicationSubmission {
    let text = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    ScmPublicationSubmission {
        proposal_ref: text("proposal_ref"),
        work_run_ref: text("work_run_ref"),
        destination_binding_ref: text("destination_binding_ref"),
        target_ref_name: {
            let named = text("target_ref_name");
            if named.is_empty() {
                text("branch")
            } else {
                named
            }
        },
        review_request_requested: body
            .get("open_review_request")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // Every legacy or attempted-defect field is CAPTURED, so it earns its
        // own named refusal rather than being silently ignored.
        requested_remote_update_mode: body
            .get("remote_update_mode")
            .and_then(Value::as_str)
            .map(str::to_owned),
        force_requested: body.get("force").and_then(Value::as_bool).unwrap_or(false),
        caller_supplied_remote: body
            .get("remote_url")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        requested_change_set_kind: body
            .get("change_set_kind")
            .and_then(Value::as_str)
            .map(str::to_owned),
        asserted_submission_disposition: body
            .get("submission_disposition")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// POST /v1/hypervisor/environments/:id/scm/publish — the wallet-authorized
/// publication crossing, rebuilt against the registered contract.
pub(crate) async fn handle_scm_publish(
    State(state): State<Arc<DaemonState>>,
    AxumPath(environment_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let request_identity = match request_identity(&state.data_dir, &headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if let Err(AppError(status, message)) = super::environment_routes::authorize_environment_owner(
        &state.data_dir,
        &headers,
        &environment_id,
    ) {
        return (
            status,
            Json(json!({ "ok": false, "error": { "code": message } })),
        );
    }
    let Some(environment) = super::read_record_dir(&state.data_dir, "environments")
        .into_iter()
        .find(|record| record["id"].as_str() == Some(environment_id.as_str()))
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "environment not found" })),
        );
    };
    let Some(workspace_root) = environment["status"]["workspace_root"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "reason": "workspace not started", "fail_closed": true })),
        );
    };
    let submission = submission_from_body(&body);
    if submission.destination_binding_ref.is_empty() || submission.proposal_ref.is_empty() {
        return fail(verr(
            "scm_publication_refused",
            "a publication names an admitted destination binding and a bound proposal",
        ));
    }

    // Resolve the binding BEFORE authority so the crossing is scoped to the
    // exact admitted destination, never to caller text.
    let source = match load_publication_source(
        &state.data_dir,
        &submission.destination_binding_ref,
        &submission.proposal_ref,
    ) {
        Ok(source) => source,
        Err(error) => return fail(error),
    };
    let owner_ref =
        match authorize_publication_source_scope(&state.data_dir, &request_identity, &source) {
            Ok(owner_ref) => owner_ref,
            Err(response) => return response,
        };
    let caller_idempotency_key = match bounded_caller_idempotency_key(&body) {
        Ok(key) => key,
        Err(error) => return fail(error),
    };
    let connector_id = source
        .binding
        .get("connector_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_start_matches("connector://")
        .to_owned();
    let remote_url = source
        .binding
        .get("remote_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Hypervisor publication")
        .to_owned();
    let proposal_files = &source.proposal["files"];
    if let Err(detail) = verify_change_set_against_workspace(&workspace_root, proposal_files) {
        return fail(verr(REFUSAL_CONTENT_DIGEST_MISMATCH, detail));
    }
    let authored_at = source
        .proposal
        .get("admitted_at")
        .and_then(Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z");
    let intended_revision =
        match GitProcessScmPort.prepare_target_revision(&TargetRevisionPreparationRequest {
            base_revision_id: source.proposal["base_revision_id"]
                .as_str()
                .unwrap_or_default(),
            files: proposal_files,
            workspace_root: &workspace_root,
            title: &title,
            authored_at,
        }) {
            Ok(revision) => revision,
            Err(detail) => return fail(verr("scm_publication_prepare_failed", detail)),
        };
    let identity = match v2_operation_identity(&source, &submission, &title, &intended_revision) {
        Ok(identity) => identity,
        Err(error) => return fail(error),
    };
    let operation_key = match v2_operation_key(&identity) {
        Ok(key) => key,
        Err(error) => return fail(error),
    };
    // The operation lock spans replay resolution, authority consumption,
    // Prepared persistence, and dispatch. A duplicate can therefore neither
    // consume twice nor reach a second final invocation.
    let _operation_guard = SCM_PUBLICATION_OPERATION_LOCK.lock().await;
    if let Err(error) = claim_caller_idempotency(
        &state.data_dir,
        &request_identity.principal_ref,
        &caller_idempotency_key,
        &operation_key,
        &super::iso_now(),
    ) {
        return fail(error);
    }
    match terminal_operation_report(&state.data_dir, &operation_key) {
        Ok(Some(report)) => {
            let prepared = match prepared_operation_record(&state.data_dir, &operation_key) {
                Ok(Some(prepared)) => prepared,
                Ok(None) => {
                    return fail(verr(
                        "scm_publication_operation_corrupt",
                        "terminal operation has no durable Prepared predecessor",
                    ));
                }
                Err(error) => return fail(error),
            };
            if let Err(reason) =
                settle_prepared_authority_from_remote_truth(&state.data_dir, &prepared, &report)
                    .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "ok": false,
                        "overall_outcome": "reconciliation_required",
                        "converged": false,
                        "reason": format!("terminal publication exists but its exact authority claim is not settled: {reason}"),
                        "authority_usage_disposition": "spent_not_refunded",
                        "publication_effect": report.effect,
                        "receipts": report.receipts,
                    })),
                );
            }
            let landed = matches!(
                report.overall_outcome.as_str(),
                "published_with_review_request" | "published_review_request_not_requested"
            );
            return (
                if landed {
                    StatusCode::OK
                } else {
                    StatusCode::CONFLICT
                },
                Json(json!({
                    "ok": landed,
                    "overall_outcome": report.overall_outcome,
                    "converged": true,
                    "recovery_disposition": "replayed_terminal_result",
                    "publication_effect": report.effect,
                    "receipts": report.receipts,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return fail(error),
    }
    // A Prepared record with no terminal sibling is an unclosed dispatch window. Reconcile it from
    // remote truth without calling either final invoker a second time.
    match unresolved_prepared_operation(&state.data_dir, &operation_key) {
        Ok(Some(prepared)) => {
            let report = match reconcile_prepared_operation(
                &state.data_dir,
                &GitProcessScmPort,
                &source,
                &prepared,
                &super::iso_now(),
            ) {
                Ok(report) => report,
                Err(error) => return fail(error),
            };
            if let Err(reason) =
                settle_prepared_authority_from_remote_truth(&state.data_dir, &prepared, &report)
                    .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "ok": false,
                        "overall_outcome": "reconciliation_required",
                        "converged": false,
                        "reason": format!("remote truth was committed but the exact authority claim was not settled: {reason}"),
                        "authority_usage_disposition": "spent_not_refunded",
                        "publication_effect": report.effect,
                        "receipts": report.receipts,
                    })),
                );
            }
            let landed = matches!(
                report.overall_outcome.as_str(),
                "published_with_review_request" | "published_review_request_not_requested"
            );
            return (
                if landed {
                    StatusCode::OK
                } else {
                    StatusCode::CONFLICT
                },
                Json(json!({
                    "ok": landed,
                    "overall_outcome": report.overall_outcome,
                    "converged": report.converged,
                    "recovery_disposition": report.effect.pointer("/recovery/resolution_disposition").cloned().unwrap_or(Value::Null),
                    "operation_key": operation_key,
                    "prepared_record_ref": prepared.pointer("/preparation/prepared_record_ref").cloned().unwrap_or(Value::Null),
                    "authority_usage_disposition": "spent_not_refunded",
                    "publication_effect": report.effect,
                    "receipts": report.receipts,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return fail(error),
    }
    let requires_credential = remote_url.starts_with("https://");
    let scopes = vec![
        SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE.to_owned(),
        SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE.to_owned(),
    ];
    let lease_request = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_owned(),
        backing_provider: if requires_credential {
            format!("scm:connector:{connector_id}")
        } else {
            "none".to_owned()
        },
        allowed_tools: vec!["scm.publish".to_owned()],
        resource_refs: vec![
            submission.destination_binding_ref.clone(),
            environment_id.clone(),
        ],
        scopes: scopes.clone(),
        policy_domain: "hypervisor.scm.publication.policy.v1".to_owned(),
        request_domain: "hypervisor.scm.publication.request.v1".to_owned(),
        // Exact-effect binding: authority is consumed for THIS publication operation — this
        // proposal, onto this target ref, producing this frozen intended revision — not for
        // "some scm.publish against this binding". The operation key deliberately excludes
        // observed remote state, which the frozen CAS precondition covers separately.
        request_facets: json!({
            "environment_id": environment_id,
            "owner_ref": owner_ref,
            "principal_ref": request_identity.principal_ref,
            "caller_idempotency_hash": caller_idempotency_hash(&request_identity.principal_ref, &caller_idempotency_key).unwrap_or_default(),
            "destination_binding_ref": submission.destination_binding_ref,
            "proposal_ref": submission.proposal_ref,
            "target_ref_name": submission.target_ref_name,
            "operation_key": operation_key,
            "base_revision_id": identity["base_revision_id"],
            "intended_revision_id": identity["intended_revision_id"],
            "review_request_requested": submission.review_request_requested,
        }),
        credential_connector_id: Some(connector_id.clone()),
        credential_store: "scm-credentials".to_owned(),
        credential_required: requires_credential,
        github_host_fallback: remote_url.contains("github.com"),
        receipt_required: true,
        revocation_ref: format!("scm-connectors/{connector_id}/credential"),
        authority_reason: "scm_publish_authority_required".to_owned(),
        grant_value: body
            .get("wallet_portable_authority_grant_hash")
            .filter(|value| !value.is_null())
            .or_else(|| body.get("wallet_approval_grant"))
            .cloned()
            .unwrap_or(Value::Null),
        standing_draw: None,
    };
    let lease = match authorize_capability_lease(&state, &lease_request).await {
        Ok(lease) => lease,
        Err((code, challenge)) => return (code, Json(challenge)),
    };
    let lease_id = lease
        .descriptor
        .get("lease_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // The admission receipt the invoker records is the wallet-owned identity the authority owner
    // can resolve — never a reference synthesized from the lease id.
    let (admitted_grant_ref, admission_intent_ref, admission_effect_hash) = match &lease.admitted {
        super::lifecycle_routes::CapabilityAuthorityAdmission::Exact(admitted) => (
            format!("grant://{}", admitted.authorized.evidence.grant_ref),
            admitted.admission_intent_ref.clone(),
            admitted.authorized.evidence.effect_hash.clone(),
        ),
        super::lifecycle_routes::CapabilityAuthorityAdmission::Portable(admitted) => (
            admitted.consumption_receipt.authority_grant_ref.clone(),
            admitted.admission_intent_ref.clone(),
            admitted.effect_hash.clone(),
        ),
        super::lifecycle_routes::CapabilityAuthorityAdmission::Standing(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "ok": false,
                    "code": "scm_publication_standing_authority_not_supported",
                    "message": "SCM publication requires exact-request or exact-effect portable authority"
                })),
            );
        }
    };
    let mut authority = PublicationAuthority {
        grant_refs: vec![admitted_grant_ref],
        scope_refs: scopes,
        capability_lease_ref: format!("lease://{lease_id}"),
        admission_receipt_ref: format!("receipt://{admission_intent_ref}"),
        admission_effect_hash,
        final_invocation_claim_ref: None,
        final_invocation_claim_id: None,
    };
    // Claim the one final invocation before any remote effect. The claim is durable, so a crash
    // inside the dispatch window is recoverable as Unknown rather than replayable.
    let claim_result = match &lease.admitted {
        super::lifecycle_routes::CapabilityAuthorityAdmission::Exact(admitted) => {
            super::governed_authority::claim_final_invocation(
                &state.data_dir,
                admitted,
                "scm.publication.advance-target-ref",
            )
            .await
        }
        super::lifecycle_routes::CapabilityAuthorityAdmission::Portable(admitted) => {
            super::governed_authority::claim_portable_final_invocation(
                &state.data_dir,
                admitted,
                "scm.publication.advance-target-ref",
            )
            .await
        }
        super::lifecycle_routes::CapabilityAuthorityAdmission::Standing(_) => {
            unreachable!("standing admission was refused before publication claim")
        }
    };
    let claim = match claim_result {
        Ok(claim) => claim,
        Err(reason) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": false,
                    "overall_outcome": "reconciliation_required",
                    "converged": false,
                    "reason": reason,
                    "authority_usage_disposition": "spent_not_refunded",
                })),
            );
        }
    };
    authority.final_invocation_claim_ref = Some(claim.reference().to_owned());
    authority.final_invocation_claim_id = Some(claim.claim_id().to_owned());
    let first_execution = execute_scm_publication_v2(
        &state.data_dir,
        &GitProcessScmPort,
        &workspace_root,
        &source,
        &submission,
        &authority,
        &title,
        &super::iso_now(),
        identity,
        operation_key.clone(),
    );
    // If anything failed after Prepared became durable, probe the frozen remote truth instead of
    // calling the port again or falsely settling the claim as a pre-dispatch refusal.
    let mut prepared_dispatch_window = false;
    let executed = match first_execution {
        Ok(report) => Ok(report),
        Err(first_error) => match unresolved_prepared_operation(&state.data_dir, &operation_key) {
            Ok(Some(prepared)) => {
                prepared_dispatch_window = true;
                reconcile_prepared_operation(
                    &state.data_dir,
                    &GitProcessScmPort,
                    &source,
                    &prepared,
                    &super::iso_now(),
                )
            }
            Ok(None) => Err(first_error),
            Err(recovery_error) => {
                // Failure to inspect the durable operation plane cannot prove dispatch absent.
                prepared_dispatch_window = true;
                Err(recovery_error)
            }
        },
    };
    let settlement = match &executed {
        Ok(report)
            if report
                .effect
                .pointer("/effects/publication/outcome")
                .and_then(Value::as_str)
                == Some("reconciliation_required") =>
        {
            super::governed_authority::mark_final_invocation_reconciliation_required(
                &state.data_dir,
                claim.reference(),
                claim.claim_id(),
                claim.effect_hash(),
                "scm.publication.advance-target-ref",
                report
                    .effect
                    .pointer("/recovery/reconciliation_code")
                    .and_then(Value::as_str)
                    .unwrap_or("prepared-dispatch-disposition-indeterminate"),
            )
            .await
        }
        Ok(report)
            if report
                .effect
                .pointer("/effects/publication/outcome")
                .and_then(Value::as_str)
                == Some("refused")
                && report
                    .effect
                    .pointer("/recovery/remote_effect_invoked")
                    .and_then(Value::as_bool)
                    == Some(false) =>
        {
            super::governed_authority::refuse_final_invocation(
                &state.data_dir,
                &claim,
                report
                    .effect
                    .pointer("/effects/publication/refusal_code")
                    .and_then(Value::as_str)
                    .unwrap_or("pre-dispatch-refusal"),
            )
            .await
        }
        Ok(report) => {
            super::governed_authority::complete_final_invocation(
                &state.data_dir,
                &claim,
                &report.overall_outcome,
            )
            .await
        }
        Err(error) if prepared_dispatch_window => {
            super::governed_authority::mark_final_invocation_reconciliation_required(
                &state.data_dir,
                claim.reference(),
                claim.claim_id(),
                claim.effect_hash(),
                "scm.publication.advance-target-ref",
                &error.0,
            )
            .await
        }
        Err(error) => {
            super::governed_authority::refuse_final_invocation(&state.data_dir, &claim, &error.0)
                .await
        }
    };
    if let Err(reason) = settlement {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "overall_outcome": "reconciliation_required",
                "converged": false,
                "reason": format!("the final invocation ran but its disposition was not durably settled: {reason}"),
                "authority_usage_disposition": "spent_not_refunded",
            })),
        );
    }
    match executed {
        Ok(report) => {
            // `ok` follows the DERIVED overall outcome. A refused publication
            // and a failed review request are honest outcomes, not successes.
            let landed = matches!(
                report.overall_outcome.as_str(),
                "published_with_review_request" | "published_review_request_not_requested"
            );
            (
                if landed {
                    StatusCode::OK
                } else {
                    StatusCode::CONFLICT
                },
                Json(json!({
                    "ok": landed,
                    "overall_outcome": report.overall_outcome,
                    "converged": report.converged,
                    "publication_effect": report.effect,
                    "receipts": report.receipts,
                })),
            )
        }
        Err(error) => fail(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::scm_publication::{
        scm_publication_effect_commitment, SCM_PUBLICATION_EFFECT_CONTRACT,
    };
    use std::cell::RefCell;

    fn digest(seed: u8) -> String {
        format!("sha256:{}", format!("{seed:02x}").repeat(32))
    }

    fn revision(seed: u8) -> String {
        format!("scm-revision:{}", format!("{seed:02x}").repeat(20))
    }

    struct ScriptedPort {
        observed: ObservedHeads,
        advance: TargetRefAdvanceOutcome,
        review: ReviewRequestOpenOutcome,
        crossings: RefCell<u32>,
    }

    impl ScriptedPort {
        fn landing() -> Self {
            Self {
                observed: ObservedHeads {
                    target: ObservedTargetRef::Present(revision(0x22)),
                    base_head: revision(0x11),
                },
                advance: TargetRefAdvanceOutcome::Advanced {
                    resulting_revision_id: revision(0x33),
                },
                review: ReviewRequestOpenOutcome::Opened {
                    review_request_url: "https://remote.example/reviews/1".to_owned(),
                },
                crossings: RefCell::new(0),
            }
        }
    }

    impl ScmRemotePort for ScriptedPort {
        fn prepare_target_revision(
            &self,
            _request: &TargetRevisionPreparationRequest<'_>,
        ) -> Result<String, String> {
            Ok(match &self.advance {
                TargetRefAdvanceOutcome::Advanced {
                    resulting_revision_id,
                } => resulting_revision_id.clone(),
                TargetRefAdvanceOutcome::Refused { .. } => revision(0x44),
            })
        }

        fn observe_heads(
            &self,
            _request: &HeadObservationRequest<'_>,
        ) -> Result<ObservedHeads, String> {
            Ok(self.observed.clone())
        }

        fn advance_target_ref(
            &self,
            _request: &TargetRefAdvanceRequest<'_>,
        ) -> TargetRefAdvanceOutcome {
            *self.crossings.borrow_mut() += 1;
            self.advance.clone()
        }

        fn open_review_request(
            &self,
            _request: &ReviewRequestOpenRequest<'_>,
        ) -> ReviewRequestOpenOutcome {
            self.review.clone()
        }
    }

    struct Plane {
        _dir: tempfile::TempDir,
        data_dir: String,
        workspace: String,
    }

    fn seeded_plane() -> Plane {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().join("state").to_str().unwrap().to_owned();
        let workspace = dir.path().join("workspace").to_str().unwrap().to_owned();
        std::fs::create_dir_all(&data_dir).expect("state dir");
        std::fs::create_dir_all(format!("{workspace}/crates/node/src")).expect("workspace");
        std::fs::write(format!("{workspace}/crates/node/src/lib.rs"), b"shipped\n")
            .expect("workspace file");

        let mut binding = json!({
            "schema_version": SCM_DESTINATION_BINDING_SCHEMA_VERSION,
            "destination_binding_ref":
                "scm-destination-binding://acme/hypervisor/revision/0001",
            "destination_binding_hash": Value::Null,
            "connector_ref": "connector://acme/scm/primary",
            "connector_revision_hash": digest(0x0a),
            "repository_ref": "repository://acme/hypervisor",
            "base_ref": "scm-ref://acme/hypervisor/heads/integration",
            "target_ref_namespace": "scm-ref://acme/hypervisor/heads/",
            "remote_url": "file:///srv/remotes/hypervisor.git",
            "admission_receipt_ref": "receipt://acme/scm-publication/admission/0001",
        });
        binding["destination_binding_hash"] =
            json!(scm_destination_binding_hash(&binding).expect("binding hash"));
        persist_publication_record(&data_dir, SCM_DESTINATION_BINDING_FAMILY, &binding)
            .expect("binding admits");

        let content = format!("sha256:{:x}", {
            use sha2::Digest as _;
            sha2::Sha256::digest(b"shipped\n")
        });
        let mut proposal = json!({
            "schema_version": SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION,
            "proposal_ref": "proposal://acme/hypervisor/change/0001",
            "proposal_hash": Value::Null,
            "change_set_kind": SCM_CHANGE_SET_KIND,
            "base_revision_id": revision(0x11),
            "files": [{
                "path": "crates/node/src/lib.rs",
                "change_kind": "modified",
                "content_digest": content,
                "proposal_ref": "proposal://acme/hypervisor/change/0001",
            }],
        });
        proposal["proposal_hash"] =
            json!(scm_publication_proposal_commitment(&proposal).expect("proposal commitment"));
        persist_publication_record(&data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY, &proposal)
            .expect("proposal admits");

        Plane {
            _dir: dir,
            data_dir,
            workspace,
        }
    }

    fn submission() -> ScmPublicationSubmission {
        ScmPublicationSubmission {
            proposal_ref: "proposal://acme/hypervisor/change/0001".to_owned(),
            work_run_ref: "work-run://acme/hypervisor/0001".to_owned(),
            destination_binding_ref: "scm-destination-binding://acme/hypervisor/revision/0001"
                .to_owned(),
            target_ref_name: "proposal-0001".to_owned(),
            review_request_requested: true,
            ..ScmPublicationSubmission::default()
        }
    }

    fn authority() -> PublicationAuthority {
        PublicationAuthority {
            grant_refs: vec!["grant://acme/wallet-network/scm-publication/0001".to_owned()],
            scope_refs: vec![
                SCM_PUBLICATION_ADVANCE_TARGET_REF_SCOPE.to_owned(),
                SCM_PUBLICATION_OPEN_REVIEW_REQUEST_SCOPE.to_owned(),
            ],
            capability_lease_ref: "lease://acme/scm-publication/0001".to_owned(),
            admission_receipt_ref: "receipt://authority-admission-intents/aai_0001".to_owned(),
            admission_effect_hash: "sha256:0001".to_owned(),
            final_invocation_claim_ref: None,
            final_invocation_claim_id: None,
        }
    }

    fn run(
        plane: &Plane,
        port: &ScriptedPort,
        submission: &ScmPublicationSubmission,
    ) -> Result<ScmPublicationReport, VErr> {
        execute_scm_publication(
            &plane.data_dir,
            port,
            &plane.workspace,
            submission,
            &authority(),
            "Ship the rebuilt publication route",
            "2026-07-29T09:14:31Z",
        )
    }

    #[test]
    fn positive_ladder_publishes_and_persists_both_receipts() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let report = run(&plane, &port, &submission()).expect("the bound publication lands");
        assert_eq!(report.overall_outcome, "published_with_review_request");
        assert!(!report.converged);
        assert_eq!(report.receipts.len(), 2, "both sub-effects are receipted");
        assert_ne!(
            report.receipts[0]["receipt_ref"], report.receipts[1]["receipt_ref"],
            "one receipt never stands for both sub-effects"
        );
        validate_contract(&report.effect);
        assert!(verify_scm_publication_effect(&report.effect).admitted);

        // Both receipts and the effect are durable and re-readable.
        let receipts =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_RECEIPT_FAMILY).unwrap();
        assert_eq!(receipts.len(), 2);
        let effects =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_EFFECT_FAMILY).unwrap();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0], report.effect);
    }

    #[test]
    fn v2_operation_persists_prepared_before_one_dispatch_and_replays_terminal() {
        let plane = seeded_plane();
        let submission = submission();
        let source = load_publication_source(
            &plane.data_dir,
            &submission.destination_binding_ref,
            &submission.proposal_ref,
        )
        .expect("source");
        let port = ScriptedPort {
            observed: ObservedHeads {
                target: ObservedTargetRef::Present(revision(0x11)),
                base_head: revision(0x11),
            },
            advance: TargetRefAdvanceOutcome::Advanced {
                resulting_revision_id: revision(0x33),
            },
            review: ReviewRequestOpenOutcome::Opened {
                review_request_url: "https://remote.example/reviews/1".to_owned(),
            },
            crossings: RefCell::new(0),
        };
        let identity = v2_operation_identity(
            &source,
            &submission,
            "Ship the rebuilt publication route",
            &revision(0x33),
        )
        .expect("identity");
        let key = v2_operation_key(&identity).expect("key");
        let report = execute_scm_publication_v2(
            &plane.data_dir,
            &port,
            &plane.workspace,
            &source,
            &submission,
            &authority(),
            "Ship the rebuilt publication route",
            "2026-07-29T09:14:31Z",
            identity,
            key.clone(),
        )
        .expect("v2 publication");
        assert_eq!(
            report.effect["schema_version"],
            "ioi.scm-publication-effect.v2"
        );
        assert_eq!(report.overall_outcome, "published_with_review_request");
        assert_eq!(*port.crossings.borrow(), 1);
        let replay = terminal_operation_report(&plane.data_dir, &key)
            .expect("terminal lookup")
            .expect("terminal record");
        assert!(replay.converged);
        assert_eq!(replay.effect, report.effect);
        assert_eq!(*port.crossings.borrow(), 1, "replay never dispatches");
    }

    #[test]
    fn an_unclosed_prepared_dispatch_window_is_reconciliation_not_a_second_dispatch() {
        let plane = seeded_plane();
        let port = ScriptedPort {
            observed: ObservedHeads {
                target: ObservedTargetRef::Present(revision(0x11)),
                base_head: revision(0x11),
            },
            advance: TargetRefAdvanceOutcome::Advanced {
                resulting_revision_id: revision(0x33),
            },
            review: ReviewRequestOpenOutcome::Opened {
                review_request_url: "https://remote.example/reviews/1".to_owned(),
            },
            crossings: RefCell::new(0),
        };
        let source =
            load_publication_source(&plane.data_dir, SEEDED_BINDING_REF, SEEDED_PROPOSAL_REF)
                .expect("publication source");
        let submission = submission();
        let identity = v2_operation_identity(
            &source,
            &submission,
            "Ship the rebuilt publication route",
            &revision(0x33),
        )
        .expect("identity");
        let key = v2_operation_key(&identity).expect("key");

        // No operation state at all: nothing is unresolved, the caller may dispatch.
        assert!(unresolved_prepared_operation(&plane.data_dir, &key)
            .expect("prepared lookup")
            .is_none());

        // Simulate a crash inside the dispatch window: Prepared is on disk, no terminal follows.
        let operation_tag = operation_tail(&key);
        persist_publication_record(
            &plane.data_dir,
            SCM_PUBLICATION_OPERATION_FAMILY,
            &json!({
                "schema_version": "ioi.scm-publication-operation-state.v2",
                "operation_key": key,
                "state": "prepared",
                "operation": {
                    "operation_ref": format!("scm-publication-operation://ioi/hypervisor/{operation_tag}"),
                    "operation_key": key,
                    "operation_key_domain": "excludes_observed_remote_state",
                    "identity": identity,
                },
                "authority": {
                    "authority_grant_refs": authority().grant_refs,
                    "authority_scope_refs": authority().scope_refs,
                    "capability_lease_ref": authority().capability_lease_ref,
                    "admission_receipt_ref": authority().admission_receipt_ref,
                },
                "admission_effect_hash": authority().admission_effect_hash,
                "preparation": {
                    "prepared_record_ref": format!("scm-publication-prepared://ioi/hypervisor/{operation_tag}"),
                    "prepared_record_hash": "sha256:unclosed",
                    "prepared_persisted_at": "2026-07-30T00:00:00Z",
                    "persistence_order": "prepared_persisted_before_remote_effect",
                    "prepared_persistence_evidence_ref": format!("receipt://ioi/hypervisor/scm/prepared/{operation_tag}"),
                },
                "frozen_cas_fingerprint": "sha256:unclosed",
                "prepared_at": "2026-07-30T00:00:00Z",
            }),
        )
        .expect("prepared record persists");

        let unresolved = unresolved_prepared_operation(&plane.data_dir, &key)
            .expect("prepared lookup")
            .expect("the unclosed dispatch window is visible to re-entry");
        assert_eq!(unresolved["state"], json!("prepared"));
        assert_eq!(
            *port.crossings.borrow(),
            0,
            "discovering an unclosed window performs no remote crossing"
        );

        // Once a terminal outcome exists for the same operation, the window is closed and
        // replay resolves through the terminal report instead of reporting reconciliation.
        let report = execute_scm_publication_v2(
            &plane.data_dir,
            &port,
            &plane.workspace,
            &source,
            &submission,
            &authority(),
            "Ship the rebuilt publication route",
            "2026-07-30T00:00:01Z",
            v2_operation_identity(
                &source,
                &submission,
                "Ship the rebuilt publication route",
                &revision(0x33),
            )
            .expect("identity"),
            key.clone(),
        )
        .expect("v2 publication");
        assert_eq!(report.overall_outcome, "published_with_review_request");
        assert!(unresolved_prepared_operation(&plane.data_dir, &key)
            .expect("prepared lookup")
            .is_none());
    }

    #[test]
    fn the_prepared_commitment_binds_the_consumed_admission_effect_hash() {
        let plane = seeded_plane();
        let port = ScriptedPort {
            observed: ObservedHeads {
                target: ObservedTargetRef::Present(revision(0x11)),
                base_head: revision(0x11),
            },
            advance: TargetRefAdvanceOutcome::Advanced {
                resulting_revision_id: revision(0x33),
            },
            review: ReviewRequestOpenOutcome::Opened {
                review_request_url: "https://remote.example/reviews/1".to_owned(),
            },
            crossings: RefCell::new(0),
        };
        let source =
            load_publication_source(&plane.data_dir, SEEDED_BINDING_REF, SEEDED_PROPOSAL_REF)
                .expect("publication source");
        let submission = submission();
        let title = "Ship the rebuilt publication route";
        let make_identity = || {
            v2_operation_identity(&source, &submission, title, &revision(0x33)).expect("identity")
        };
        let key = v2_operation_key(&make_identity()).expect("key");

        let mut divergent = authority();
        divergent.admission_effect_hash = "sha256:a-different-consumed-effect".to_owned();
        let baseline = execute_scm_publication_v2(
            &plane.data_dir,
            &port,
            &plane.workspace,
            &source,
            &submission,
            &authority(),
            title,
            "2026-07-30T00:00:00Z",
            make_identity(),
            key.clone(),
        )
        .expect("v2 publication");

        let other_plane = seeded_plane();
        let other_port = ScriptedPort {
            observed: ObservedHeads {
                target: ObservedTargetRef::Present(revision(0x11)),
                base_head: revision(0x11),
            },
            advance: TargetRefAdvanceOutcome::Advanced {
                resulting_revision_id: revision(0x33),
            },
            review: ReviewRequestOpenOutcome::Opened {
                review_request_url: "https://remote.example/reviews/1".to_owned(),
            },
            crossings: RefCell::new(0),
        };
        let other_source = load_publication_source(
            &other_plane.data_dir,
            SEEDED_BINDING_REF,
            SEEDED_PROPOSAL_REF,
        )
        .expect("publication source");
        let shifted = execute_scm_publication_v2(
            &other_plane.data_dir,
            &other_port,
            &other_plane.workspace,
            &other_source,
            &submission,
            &divergent,
            title,
            "2026-07-30T00:00:00Z",
            make_identity(),
            key,
        )
        .expect("v2 publication");

        let baseline_prepared = baseline.effect["preparation"]["prepared_record_hash"]
            .as_str()
            .expect("prepared hash");
        let shifted_prepared = shifted.effect["preparation"]["prepared_record_hash"]
            .as_str()
            .expect("prepared hash");
        assert_ne!(
            baseline_prepared, shifted_prepared,
            "a different consumed admission effect must produce a different Prepared commitment"
        );
    }

    fn validate_contract(effect: &Value) {
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            SCM_PUBLICATION_EFFECT_CONTRACT,
            effect,
        )
        .expect("the committed effect satisfies the registered contract");
    }

    #[test]
    fn review_request_failure_is_never_reported_as_success() {
        let plane = seeded_plane();
        let mut port = ScriptedPort::landing();
        port.review = ReviewRequestOpenOutcome::Failed {
            refusal_code: REFUSAL_REVIEW_REQUEST_REJECTED.to_owned(),
            detail: "the remote rejected the review request".to_owned(),
        };
        let report = run(&plane, &port, &submission()).expect("a failed review request is honest");
        assert_eq!(report.overall_outcome, "review_request_failed");
        assert_eq!(
            report.effect["effects"]["review_request"]["refusal_code"],
            json!(REFUSAL_REVIEW_REQUEST_REJECTED)
        );
        assert_eq!(
            report.effect["effects"]["publication"]["outcome"],
            json!("published")
        );
        validate_contract(&report.effect);
        assert_eq!(report.receipts.len(), 2, "the failure is receipted too");
    }

    #[test]
    fn a_moved_remote_head_refuses_and_advances_nothing() {
        let plane = seeded_plane();
        let mut port = ScriptedPort::landing();
        port.advance = TargetRefAdvanceOutcome::Refused {
            refusal_code: REFUSAL_EXPECTED_HEAD_MOVED.to_owned(),
            detail: "the remote head moved".to_owned(),
        };
        let report = run(&plane, &port, &submission()).expect("an honest refusal is representable");
        assert_eq!(report.overall_outcome, "refused");
        assert_eq!(
            report.effect["change_set"]["resulting_revision_id"],
            Value::Null
        );
        assert_eq!(
            report.effect["remote_cas"]["resulting_target_head"],
            Value::Null
        );
        assert_eq!(
            report.effect["effects"]["publication"]["refusal_code"],
            json!(REFUSAL_EXPECTED_HEAD_MOVED)
        );
        validate_contract(&report.effect);
    }

    #[test]
    fn an_unobservable_remote_head_refuses_by_name() {
        let plane = seeded_plane();
        let mut port = ScriptedPort::landing();
        port.observed.target = ObservedTargetRef::Unobserved;
        let error = run(&plane, &port, &submission()).expect_err("no advance without a head");
        assert_eq!(error.0, "scm_publication_refused");
        assert!(
            error.1.starts_with("absent_expected_head:"),
            "the caller receives the named refusal, not a generic failure: {}",
            error.1
        );
        assert_eq!(*port.crossings.borrow(), 0, "nothing crossed to the remote");
    }

    #[test]
    fn a_base_head_that_moved_refuses_stale_expected_head_by_name() {
        let plane = seeded_plane();
        let mut port = ScriptedPort::landing();
        port.observed.base_head = revision(0x44);
        let error = run(&plane, &port, &submission()).expect_err("a stale base refuses");
        assert!(error.1.starts_with("stale_expected_head:"), "{}", error.1);
        assert_eq!(*port.crossings.borrow(), 0);
    }

    #[test]
    fn a_caller_supplied_remote_refuses_unbound_destination_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let mut attempt = submission();
        attempt.caller_supplied_remote = Some("https://evil.example/target.git".to_owned());
        let error = run(&plane, &port, &attempt).expect_err("free caller text names no remote");
        assert!(error.1.starts_with("unbound_destination:"), "{}", error.1);
        assert_eq!(*port.crossings.borrow(), 0);
    }

    #[test]
    fn a_forced_overwrite_refuses_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let mut attempt = submission();
        attempt.force_requested = true;
        let error = run(&plane, &port, &attempt).expect_err("force has no representation");
        assert!(
            error.1.starts_with("remote_overwrite_requested:"),
            "{}",
            error.1
        );
        assert_eq!(*port.crossings.borrow(), 0);
    }

    #[test]
    fn a_whole_workspace_stage_refuses_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let mut attempt = submission();
        attempt.requested_change_set_kind = Some("whole_workspace_snapshot".to_owned());
        let error = run(&plane, &port, &attempt).expect_err("a workspace snapshot is not a set");
        assert!(
            error.1.starts_with("whole_workspace_change_set:"),
            "{}",
            error.1
        );
        assert_eq!(*port.crossings.borrow(), 0);
    }

    #[test]
    fn a_replay_assertion_without_a_prior_effect_refuses_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let mut attempt = submission();
        attempt.asserted_submission_disposition = Some("converged_replay".to_owned());
        let error = run(&plane, &port, &attempt).expect_err("no prior effect exists");
        assert!(
            error.1.starts_with("replay_without_prior_effect:"),
            "{}",
            error.1
        );
        assert_eq!(*port.crossings.borrow(), 0);
    }

    #[test]
    fn workspace_bytes_that_left_the_proposal_refuse_and_never_cross() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        std::fs::write(
            format!("{}/crates/node/src/lib.rs", plane.workspace),
            b"something else entirely\n",
        )
        .unwrap();
        let report = run(&plane, &port, &submission()).expect("the drift is an honest refusal");
        assert_eq!(report.overall_outcome, "refused");
        assert_eq!(
            report.effect["effects"]["publication"]["refusal_code"],
            json!(REFUSAL_CONTENT_DIGEST_MISMATCH)
        );
        assert_eq!(
            *port.crossings.borrow(),
            0,
            "drifted bytes never reach the remote"
        );
    }

    #[test]
    fn an_exact_replay_converges_instead_of_crossing_twice() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let first = run(&plane, &port, &submission()).expect("first admission lands");
        assert_eq!(*port.crossings.borrow(), 1);

        let replay = run(&plane, &port, &submission()).expect("the exact resubmission converges");
        assert!(replay.converged);
        assert_eq!(
            *port.crossings.borrow(),
            1,
            "a replay performs NO second remote crossing"
        );
        assert_eq!(
            replay.effect["idempotency"]["submission_disposition"],
            json!("converged_replay")
        );
        assert_eq!(
            replay.effect["idempotency"]["prior_effect_ref"],
            first.effect["publication_effect_id"]
        );
        assert_eq!(
            replay.effect["idempotency"]["idempotency_key"],
            first.effect["idempotency"]["idempotency_key"]
        );
        assert_eq!(
            replay.effect["effects"]["publication"]["receipt_ref"],
            first.effect["effects"]["publication"]["receipt_ref"],
            "a replay mints no second receipt"
        );
        validate_contract(&replay.effect);

        // A third submission converges onto the byte-identical replay record.
        let again = run(&plane, &port, &submission()).expect("convergence is stable");
        assert_eq!(again.effect, replay.effect);
        assert_eq!(*port.crossings.borrow(), 1);
        let effects =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_EFFECT_FAMILY).unwrap();
        assert_eq!(effects.len(), 2, "one admission plus one convergent replay");
    }

    #[test]
    fn an_idempotency_key_claimed_over_changed_material_refuses_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let mine = run(&plane, &port, &submission()).expect("first admission lands");
        // A DIFFERENT submission's effect, hand-stamped with this submission's
        // key, is a claim over changed material and refuses.
        let mut other = submission();
        other.target_ref_name = "proposal-0002".to_owned();
        let other_report = run(&plane, &port, &other).expect("the other submission lands");
        let mut forged = other_report.effect.clone();
        forged["idempotency"]["idempotency_key"] =
            mine.effect["idempotency"]["idempotency_key"].clone();
        forged["publication_effect_hash"] =
            json!(scm_publication_effect_commitment(&forged).unwrap());
        persist_publication_record(&plane.data_dir, SCM_PUBLICATION_EFFECT_FAMILY, &forged)
            .expect("the forged record is stored to be adjudicated");
        let error = run(&plane, &port, &submission()).expect_err("the claim cannot stand");
        assert!(
            error
                .1
                .starts_with("idempotency_key_reuse_over_changed_material:"),
            "{}",
            error.1
        );
    }

    #[test]
    fn a_detached_prior_commitment_refuses_by_name() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let first = run(&plane, &port, &submission()).expect("first admission lands");
        let mut tampered = first.effect.clone();
        tampered["publication_effect_hash"] = json!(digest(0x55));
        persist_publication_record(&plane.data_dir, SCM_PUBLICATION_EFFECT_FAMILY, &tampered)
            .expect("the tampered record is stored to be adjudicated");
        let error = run(&plane, &port, &submission()).expect_err("a detached commitment refuses");
        assert!(
            error.1.starts_with("detached_content_commitment:"),
            "{}",
            error.1
        );
    }

    #[test]
    fn the_plane_rebuilds_from_durable_records_after_a_restart() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        let report = run(&plane, &port, &submission()).expect("first admission lands");

        // Drop every in-process substrate handle, exactly as a restart does,
        // then rebuild the whole plane from the durable records alone.
        super::super::substrate_store::reset_handle_for_test();

        let bindings =
            read_publication_family(&plane.data_dir, SCM_DESTINATION_BINDING_FAMILY).unwrap();
        let proposals =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY).unwrap();
        let effects =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_EFFECT_FAMILY).unwrap();
        let receipts =
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_RECEIPT_FAMILY).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(proposals.len(), 1);
        assert_eq!(effects, vec![report.effect.clone()]);
        assert_eq!(receipts.len(), 2);
        assert!(verify_scm_publication_effect(&effects[0]).admitted);
        validate_contract(&effects[0]);

        // And the rebuilt plane still converges the exact resubmission rather
        // than crossing again: idempotency survives the restart.
        let replay = run(&plane, &port, &submission()).expect("the rebuilt plane converges");
        assert!(replay.converged);
        assert_eq!(*port.crossings.borrow(), 1);
    }

    #[test]
    fn a_failed_durable_write_is_never_reported_as_success() {
        let plane = seeded_plane();
        let port = ScriptedPort::landing();
        // Occupy the effect family's slot with a regular file so the durable
        // write cannot commit. The route this replaces dropped exactly this
        // result (`let _ = persist_record(...)`) and returned `ok: true`
        // anyway; here the failed write IS the outcome.
        std::fs::write(
            std::path::Path::new(&plane.data_dir).join(SCM_PUBLICATION_EFFECT_FAMILY),
            b"not a family directory",
        )
        .expect("occupy the family slot");
        let error =
            run(&plane, &port, &submission()).expect_err("a failed durable write is an error");
        assert_eq!(error.0, "scm_publication_persist_failed");
        assert_eq!(
            status_for(&error.0),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed write is never a success status"
        );
        assert_eq!(
            *port.crossings.borrow(),
            1,
            "the crossing happened; the estate refuses to CLAIM it landed durably"
        );
    }

    // ---- an ambiguous source identity is refused, never guessed ----------
    //
    // Both families are content-addressed, so a logical ref is not a key: a
    // rebinding or a revised proposal is a SECOND admitted record carrying the
    // same ref. Resolving to whichever record was read first would let a
    // publication compile against a stale revision under an identity the caller
    // believes is exact.

    const SEEDED_BINDING_REF: &str = "scm-destination-binding://acme/hypervisor/revision/0001";
    const SEEDED_PROPOSAL_REF: &str = "proposal://acme/hypervisor/change/0001";

    /// Admit a SECOND destination-binding revision under the seeded ref.
    fn admit_rebound_destination(plane: &Plane, remote_url: &str) {
        let mut binding = json!({
            "schema_version": SCM_DESTINATION_BINDING_SCHEMA_VERSION,
            "destination_binding_ref": SEEDED_BINDING_REF,
            "destination_binding_hash": Value::Null,
            "connector_ref": "connector://acme/scm/primary",
            "connector_revision_hash": digest(0x0a),
            "repository_ref": "repository://acme/hypervisor",
            "base_ref": "scm-ref://acme/hypervisor/heads/integration",
            "target_ref_namespace": "scm-ref://acme/hypervisor/heads/",
            "remote_url": remote_url,
            "admission_receipt_ref": "receipt://acme/scm-publication/admission/0002",
        });
        binding["destination_binding_hash"] =
            json!(scm_destination_binding_hash(&binding).expect("binding hash"));
        persist_publication_record(&plane.data_dir, SCM_DESTINATION_BINDING_FAMILY, &binding)
            .expect("the second binding revision admits");
    }

    /// Admit a SECOND proposal revision under the seeded ref.
    fn admit_revised_proposal(plane: &Plane, path: &str) {
        let mut proposal = json!({
            "schema_version": SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION,
            "proposal_ref": SEEDED_PROPOSAL_REF,
            "proposal_hash": Value::Null,
            "change_set_kind": SCM_CHANGE_SET_KIND,
            "base_revision_id": revision(0x11),
            "files": [{
                "path": path,
                "change_kind": "modified",
                "content_digest": digest(0x5e),
                "proposal_ref": SEEDED_PROPOSAL_REF,
            }],
        });
        proposal["proposal_hash"] =
            json!(scm_publication_proposal_commitment(&proposal).expect("proposal commitment"));
        persist_publication_record(&plane.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY, &proposal)
            .expect("the second proposal revision admits");
    }

    #[test]
    fn two_destination_binding_revisions_under_one_ref_refuse_by_name() {
        let plane = seeded_plane();
        admit_rebound_destination(&plane, "file:///srv/remotes/somewhere-else.git");
        let port = ScriptedPort::landing();
        let error = run(&plane, &port, &submission())
            .expect_err("an ambiguous destination identity is never resolved");
        assert_eq!(error.0, "scm_publication_binding_ambiguous");
        assert!(
            error
                .1
                .starts_with(&format!("{SCM_REFUSAL_AMBIGUOUS_DESTINATION_BINDING_REF}:")),
            "the refusal leads with its registered dimension: {}",
            error.1
        );
        assert!(
            error.1.contains(SEEDED_BINDING_REF) && error.1.contains("2 admitted records"),
            "the refusal names the ref and the collision size: {}",
            error.1
        );
        assert_eq!(status_for(&error.0), StatusCode::CONFLICT);
        assert_eq!(
            *port.crossings.borrow(),
            0,
            "nothing crosses to a remote the estate could not resolve exactly"
        );
    }

    #[test]
    fn two_proposal_revisions_under_one_ref_refuse_by_name() {
        let plane = seeded_plane();
        admit_revised_proposal(&plane, "crates/node/src/other.rs");
        let port = ScriptedPort::landing();
        let error = run(&plane, &port, &submission())
            .expect_err("an ambiguous proposal identity is never resolved");
        assert_eq!(error.0, "scm_publication_proposal_ambiguous");
        assert!(
            error
                .1
                .starts_with(&format!("{SCM_REFUSAL_AMBIGUOUS_PROPOSAL_REF}:")),
            "the refusal leads with its registered dimension: {}",
            error.1
        );
        assert!(
            error.1.contains(SEEDED_PROPOSAL_REF) && error.1.contains("2 admitted records"),
            "the refusal names the ref and the collision size: {}",
            error.1
        );
        assert_eq!(status_for(&error.0), StatusCode::CONFLICT);
        assert_eq!(
            *port.crossings.borrow(),
            0,
            "no bytes cross while the estate cannot say which revision they are"
        );
    }

    #[test]
    fn both_new_ambiguity_dimensions_are_registered_and_distinct() {
        for dimension in [
            SCM_REFUSAL_AMBIGUOUS_DESTINATION_BINDING_REF,
            SCM_REFUSAL_AMBIGUOUS_PROPOSAL_REF,
        ] {
            assert!(
                ioi_types::app::scm_publication::SCM_PUBLICATION_REFUSAL_DIMENSIONS
                    .contains(&dimension),
                "{dimension} must be a declared dimension of the plane"
            );
        }
        assert_ne!(
            SCM_REFUSAL_AMBIGUOUS_DESTINATION_BINDING_REF,
            SCM_REFUSAL_AMBIGUOUS_PROPOSAL_REF
        );
    }

    #[test]
    fn one_admitted_revision_resolves_and_a_missing_one_still_refuses_not_found() {
        let plane = seeded_plane();
        let source =
            load_publication_source(&plane.data_dir, SEEDED_BINDING_REF, SEEDED_PROPOSAL_REF)
                .expect("a single admitted revision resolves exactly as before");
        assert_eq!(
            source.binding["destination_binding_ref"],
            json!(SEEDED_BINDING_REF)
        );
        assert_eq!(source.proposal["proposal_ref"], json!(SEEDED_PROPOSAL_REF));

        let missing_binding = load_publication_source(
            &plane.data_dir,
            "scm-destination-binding://acme/hypervisor/revision/never",
            SEEDED_PROPOSAL_REF,
        )
        .err()
        .expect("an unadmitted binding is still a not-found refusal");
        assert_eq!(missing_binding.0, "scm_publication_binding_not_admitted");
        assert_eq!(status_for(&missing_binding.0), StatusCode::NOT_FOUND);

        let missing_proposal = load_publication_source(
            &plane.data_dir,
            SEEDED_BINDING_REF,
            "proposal://acme/hypervisor/change/never",
        )
        .err()
        .expect("an unbound proposal is still a not-found refusal");
        assert_eq!(missing_proposal.0, "scm_publication_proposal_not_found");
        assert_eq!(status_for(&missing_proposal.0), StatusCode::NOT_FOUND);
    }

    #[test]
    fn one_revision_recorded_twice_is_not_ambiguous() {
        // `proposal_hash` commits to the declared material only, so a record
        // that differs solely in a field OUTSIDE that commitment is the same
        // revision recorded twice — one revision, so it resolves rather than
        // refusing, and the publication still lands.
        let plane = seeded_plane();
        let seeded = read_publication_family(&plane.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY)
            .expect("the seeded proposal reads back")
            .into_iter()
            .next()
            .expect("one seeded proposal");
        let mut restated = seeded.clone();
        restated["work_run_ref"] = json!("work-run://acme/hypervisor/0001");
        assert_eq!(
            scm_publication_proposal_commitment(&restated).expect("commitment"),
            seeded["proposal_hash"].as_str().expect("seeded hash"),
            "the restated record pins the same revision"
        );
        persist_publication_record(&plane.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY, &restated)
            .expect("the restated record admits as its own artifact");
        assert_eq!(
            read_publication_family(&plane.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY)
                .expect("both records read back")
                .len(),
            2,
            "two durable records now carry the one proposal ref"
        );

        let port = ScriptedPort::landing();
        let report =
            run(&plane, &port, &submission()).expect("one revision recorded twice still resolves");
        assert_eq!(report.overall_outcome, "published_with_review_request");
        assert_eq!(
            report.effect["work_subject"]["proposal_hash"], seeded["proposal_hash"],
            "the effect pins the one revision both records carry"
        );
    }

    #[test]
    fn the_remote_ref_mapping_is_bounded_to_the_binding_namespace() {
        assert_eq!(
            remote_ref_name("scm-ref://acme/hypervisor/heads/proposal-0001").as_deref(),
            Some("refs/heads/proposal-0001")
        );
        assert_eq!(remote_ref_name("scm-ref://acme/hypervisor/heads/"), None);
        assert_eq!(remote_ref_name("refs/heads/main"), None);
    }
}
