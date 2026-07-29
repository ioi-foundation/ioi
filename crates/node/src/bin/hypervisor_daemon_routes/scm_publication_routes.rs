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
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

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
use super::DaemonState;

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
/// crosses exactly these three methods, so the whole decision path is
/// exercisable against a scripted port.
pub(crate) trait ScmRemotePort {
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

impl ScmRemotePort for GitProcessScmPort {
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
        let workspace = request.workspace_root;
        // Stage EXACTLY the enumerated rows. There is no `git add -A` here and
        // no path that reaches the index without a proposal row behind it.
        let staging = format!("{workspace}/.ioi-scm-publication-index");
        let _ = std::fs::remove_file(&staging);
        let index_env = |args: &[&str]| -> (bool, String) {
            match std::process::Command::new("git")
                .arg("-C")
                .arg(workspace)
                .env("GIT_INDEX_FILE", &staging)
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
        let (fetched, fetch_out) = git(
            workspace,
            &[
                "fetch",
                "--no-tags",
                request.remote_url,
                &format!("{parent}"),
            ],
        );
        if !fetched {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_EXPECTED_HEAD_MOVED.to_owned(),
                detail: format!("the expected parent revision is not reachable ({fetch_out})"),
            };
        }
        if !index_env(&["read-tree", &parent]).0 {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_EXPECTED_HEAD_MOVED.to_owned(),
                detail: "the expected parent tree could not be read".to_owned(),
            };
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
                return TargetRefAdvanceOutcome::Refused {
                    refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
                    detail: format!("declared row '{path}' could not be staged ({out})"),
                };
            }
        }
        let (wrote, tree) = index_env(&["write-tree"]);
        if !wrote {
            let _ = std::fs::remove_file(&staging);
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
                detail: "the enumerated change set produced no tree".to_owned(),
            };
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
            &parent,
            "-m",
            request.title,
        ]);
        let _ = std::fs::remove_file(&staging);
        if !committed {
            return TargetRefAdvanceOutcome::Refused {
                refusal_code: REFUSAL_CONTENT_DIGEST_MISMATCH.to_owned(),
                detail: "the enumerated change set produced no commit".to_owned(),
            };
        }
        let commit = commit.trim().to_owned();
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
            resulting_revision_id: format!("scm-revision:{commit}"),
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
    /// Admission receipt of the crossing.
    pub(crate) admission_receipt_ref: String,
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
    let advance = match verify_change_set_against_workspace(workspace_root, &files) {
        Ok(()) => port.advance_target_ref(&TargetRefAdvanceRequest {
            remote_url: &compiled.remote_url,
            target_ref: &compiled.target_ref,
            base_revision_id: &compiled.base_revision_id,
            expected_target_head: compiled.expected_target_head.as_deref(),
            files: &files,
            workspace_root,
            title,
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
        | "scm_publication_artifact_invalid" => StatusCode::CONFLICT,
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

/// POST /v1/hypervisor/scm-destination-bindings — admit one destination
/// binding. The binding, not the caller, is what a later publication resolves
/// its remote from.
pub(crate) async fn handle_destination_binding_admit(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut record = json!({
        "schema_version": SCM_DESTINATION_BINDING_SCHEMA_VERSION,
        "destination_binding_ref": body.get("destination_binding_ref").cloned().unwrap_or(Value::Null),
        "destination_binding_hash": Value::Null,
        "connector_ref": body.get("connector_ref").cloned().unwrap_or(Value::Null),
        "connector_revision_hash": body.get("connector_revision_hash").cloned().unwrap_or(Value::Null),
        "repository_ref": body.get("repository_ref").cloned().unwrap_or(Value::Null),
        "base_ref": body.get("base_ref").cloned().unwrap_or(Value::Null),
        "target_ref_namespace": body.get("target_ref_namespace").cloned().unwrap_or(Value::Null),
        "remote_url": body.get("remote_url").cloned().unwrap_or(Value::Null),
        "admission_receipt_ref": body.get("admission_receipt_ref").cloned().unwrap_or(Value::Null),
        "admitted_at": super::iso_now(),
    });
    let hash = match scm_destination_binding_hash(&record) {
        Ok(hash) => hash,
        Err(error) => return fail(verr("scm_publication_artifact_invalid", error)),
    };
    record["destination_binding_hash"] = json!(hash);
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
) -> (StatusCode, Json<Value>) {
    match read_publication_family(&state.data_dir, SCM_DESTINATION_BINDING_FAMILY) {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "destination_bindings": rows })),
        ),
        Err(error) => fail(error),
    }
}

/// POST /v1/hypervisor/scm-publication-proposals — admit one enumerated,
/// proposal-bound change set. A whole-workspace snapshot has no admitted
/// shape here, so nothing downstream can express one.
pub(crate) async fn handle_publication_proposal_admit(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut record = json!({
        "schema_version": SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION,
        "proposal_ref": body.get("proposal_ref").cloned().unwrap_or(Value::Null),
        "proposal_hash": Value::Null,
        "change_set_kind": SCM_CHANGE_SET_KIND,
        "base_revision_id": body.get("base_revision_id").cloned().unwrap_or(Value::Null),
        "files": body.get("files").cloned().unwrap_or(json!([])),
        "work_run_ref": body.get("work_run_ref").cloned().unwrap_or(Value::Null),
        "admitted_at": super::iso_now(),
    });
    let commitment = match scm_publication_proposal_commitment(&record) {
        Ok(commitment) => commitment,
        Err(error) => return fail(verr("scm_publication_artifact_invalid", error)),
    };
    record["proposal_hash"] = json!(commitment);
    match persist_publication_record(&state.data_dir, SCM_PUBLICATION_PROPOSAL_FAMILY, &record) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "proposal": record })),
        ),
        Err(error) => fail(error),
    }
}

/// GET /v1/hypervisor/scm-publication-effects — every committed effect,
/// rebuilt from the durable plane.
pub(crate) async fn handle_publication_effect_list(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    match read_publication_family(&state.data_dir, SCM_PUBLICATION_EFFECT_FAMILY) {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "publication_effects": rows })),
        ),
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
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
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
        request_facets: json!({
            "environment_id": environment_id,
            "destination_binding_ref": submission.destination_binding_ref,
            "proposal_ref": submission.proposal_ref,
            "target_ref_name": submission.target_ref_name,
        }),
        credential_connector_id: Some(connector_id.clone()),
        credential_store: "scm-credentials".to_owned(),
        credential_required: requires_credential,
        github_host_fallback: remote_url.contains("github.com"),
        receipt_required: true,
        revocation_ref: format!("scm-connectors/{connector_id}/credential"),
        authority_reason: "scm_publish_authority_required".to_owned(),
        grant_value: body
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
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
    let authority = PublicationAuthority {
        grant_refs: vec![format!("grant://{}", lease.grant_ref)],
        scope_refs: scopes,
        capability_lease_ref: format!("lease://{lease_id}"),
        admission_receipt_ref: format!("receipt://scm-publication/admission/{lease_id}"),
    };
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Hypervisor publication")
        .to_owned();

    match execute_scm_publication(
        &state.data_dir,
        &GitProcessScmPort,
        &workspace_root,
        &submission,
        &authority,
        &title,
        &super::iso_now(),
    ) {
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
            admission_receipt_ref: "receipt://acme/scm-publication/admission/0001".to_owned(),
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
