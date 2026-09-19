//! The delegation EDGE: the parent-to-child work-owning relation and its bounds.
//!
//! ADR 0034 splits a delegation in two and gives the halves to different layers. The CHILD OBJECT
//! — prompt, status, role, run ref — is the subagent surface's and persists there. The EDGE is the
//! kernel's, admitted as a `child_reference` on the work-lifecycle record chain, and it is what
//! carries depth, fanout and attribution. Sub-ruling 1 is the reason this module exists at all:
//! delegation bounds live in the kernel admission path and NOWHERE else, "a bound added at a call
//! site is a defect, not a stopgap, including a temporary one".
//!
//! WHAT THE PLATFORM READS, AND WHAT IT REFUSES TO UNDERSTAND. It reads the ancestor chain (whose
//! LENGTH is the depth), the fanout claim, the accountable actor, and the resolver the child will
//! run on. It carries `role_kind` and `topology_kind` and branches on NEITHER — no match arm, no
//! default, no behaviour keyed on either value anywhere in this file or downstream of it. Those
//! vocabularies are closed by the registered contract, not by the runtime, which is how the
//! primitive stays topology-agnostic in the only sense that means anything: it privileges no
//! topology because it understands none. The kernel this replaced emitted ONE hardcoded
//! `topology_kind` and branched on it; a daemon that enumerated ten would be that defect larger.
//!
//! WHERE A BOUND COMES FROM (R-194). The reservation seam derives nothing — ceilings are the
//! ancestor owners' truth and are supplied to it. So a delegation's ceiling comes from the PARENT's
//! admitted edge first and the request second, and a child narrows from its parent and can never
//! widen (ADR 0034 sub-ruling 3). When neither yields a ceiling the absence is RECORDED on the edge
//! as a typed absence rather than defaulted: a fabricated bound is worse than a recorded one,
//! because only one of the two can be measured. Turning that absence into a refusal is S5-2b, once
//! every caller supplies a bound.

use serde_json::{json, Value};

use super::work_lifecycle_routes::{WorkLifecycleStore, WorkLifecycleStoreError};

/// The contract this module admits against.
pub(crate) const DELEGATION_EDGE_SCHEMA_VERSION: &str = "ioi.foundations.delegation-edge.v1";

/// An admitted delegation, or the typed reason it was refused.
#[derive(Debug)]
pub(crate) struct AdmittedDelegation {
    /// The edge as admitted, exactly as it was written.
    pub(crate) edge: Value,
    /// True when no ceiling was derivable from the parent or supplied by the caller, so the depth
    /// bound was RECORDED as absent rather than enforced. Never silently true: the caller surfaces
    /// it and the gate asserts it by name.
    pub(crate) depth_bound_absent: bool,
}

/// Why a delegation was refused. Each variant is a wire code, never a message a caller parses.
#[derive(Debug)]
pub(crate) enum DelegationRefusal {
    /// The delegation would sit deeper than the ceiling it narrowed from.
    DepthCeilingExceeded { depth: u64, ceiling: u64 },
    /// The request tried to widen a ceiling its parent admitted under.
    CeilingWidened { requested: u64, parent: u64 },
    /// The parent's recorded depth disagrees with the chain it recorded beside it.
    ParentPositionInconsistent { recorded: u64, chain_length: u64 },
    /// The chain or the edge could not be admitted durably.
    Store(WorkLifecycleStoreError),
}

impl DelegationRefusal {
    pub(crate) fn code(&self) -> String {
        match self {
            Self::DepthCeilingExceeded { .. } => "delegation_depth_ceiling_exceeded".to_string(),
            Self::CeilingWidened { .. } => "delegation_ceiling_widened".to_string(),
            Self::ParentPositionInconsistent { .. } => {
                "delegation_parent_position_inconsistent".to_string()
            }
            Self::Store(error) => error.code(),
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::DepthCeilingExceeded { depth, ceiling } => format!(
                "a delegation at depth {depth} exceeds the ceiling {ceiling} it narrows from"
            ),
            Self::CeilingWidened { requested, parent } => format!(
                "a delegation may not widen its parent's ceiling: requested {requested}, parent {parent}"
            ),
            Self::ParentPositionInconsistent {
                recorded,
                chain_length,
            } => format!(
                "the parent records depth {recorded} beside a chain of {chain_length} ancestors;                  depth is the chain's length and a stored copy that disagrees with it is drift,                  not a second opinion"
            ),
            Self::Store(error) => error.message(),
        }
    }
}

/// The work-lifecycle object a thread's own delegation state lives under.
fn thread_object_ref(thread_id: &str) -> String {
    format!("thread://{thread_id}")
}

/// What the parent thread's own chain says about its position, if it has one.
///
/// A ROOT thread has no chain and answers `None` — that is the honest shape, not a zero. A thread
/// that was itself delegated carries a genesis on its own chain recording the depth it admitted at
/// and the ceiling it admitted under, which is how a grandchild narrows without searching the
/// graph for its grandparent's record.
struct ParentPosition {
    depth: u64,
    ceiling: Option<u64>,
    chain: Vec<String>,
}

/// Read the position from the CHAIN, not the projection.
///
/// The kernel's projection has a fixed shape — phase, head, counts, active children — and it does
/// not surface arbitrary fields out of a `phase_transition`. A first draft of this function read
/// `projection.delegation_position` and would have answered `None` for every thread forever, which
/// is the quietest possible bug: every delegation would have looked like a root, every depth would
/// have been 1, and no ceiling would ever have been inherited. The position is a RECORD, so it is
/// read from the record.
fn read_parent_position(
    store: &WorkLifecycleStore,
    parent_thread_id: &str,
) -> Option<ParentPosition> {
    let chain = store
        .load_chain(&thread_object_ref(parent_thread_id))
        .ok()?;
    let position = chain
        .iter()
        .find_map(|record| record.pointer("/phase_transition/delegation_position"))?;
    Some(ParentPosition {
        depth: position.get("depth").and_then(Value::as_u64).unwrap_or(0),
        ceiling: position.get("depth_ceiling").and_then(Value::as_u64),
        chain: position
            .get("ancestor_chain")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// The bounds this delegation admits under: the parent's first, the request's second, and neither
/// widening the other.
fn resolve_ceiling(
    parent: Option<&ParentPosition>,
    requested: Option<u64>,
) -> Result<Option<u64>, DelegationRefusal> {
    match (parent.and_then(|p| p.ceiling), requested) {
        (Some(parent_ceiling), Some(requested)) if requested > parent_ceiling => {
            Err(DelegationRefusal::CeilingWidened {
                requested,
                parent: parent_ceiling,
            })
        }
        (Some(parent_ceiling), Some(requested)) => Ok(Some(requested.min(parent_ceiling))),
        (Some(parent_ceiling), None) => Ok(Some(parent_ceiling)),
        (None, requested) => Ok(requested),
    }
}

/// The caller's request for one delegation. Every field the platform reads to bound or attribute
/// the work is here; nothing here is interpreted for behaviour.
pub(crate) struct DelegationRequest<'a> {
    pub(crate) parent_thread_id: &'a str,
    pub(crate) child_subagent_id: &'a str,
    pub(crate) child_thread_id: &'a str,
    pub(crate) accountable_actor_ref: String,
    pub(crate) role_kind: String,
    pub(crate) topology_kind: String,
    pub(crate) requested_depth_ceiling: Option<u64>,
    pub(crate) fanout_reservation_ref: Option<String>,
    pub(crate) selected_resolver_kind: String,
    pub(crate) selected_resolver_revision_ref: Option<String>,
    pub(crate) selected_resolver_content_hash: Option<String>,
    pub(crate) selected_model_route_ref: Option<String>,
    pub(crate) orchestration_ref: Option<String>,
    pub(crate) owner_ref: String,
    pub(crate) now_ms: u64,
}

/// Admit one delegation edge, and record the child's own position so its children can narrow from
/// it without walking the graph.
///
/// TWO APPENDS, BOTH THROUGH THE SAME KERNEL. The edge is a `child_reference` on the PARENT's
/// chain — that is the work-owning relation ADR 0034 sub-ruling 5 names. The child's position is a
/// genesis `phase_transition` on the CHILD's own chain, carrying the depth it admitted at and the
/// ceiling it admitted under. Neither is a projection this module maintains by hand: both are
/// records the kernel admits and rebuilds.
///
/// Refusal happens BEFORE either append, so a refused delegation leaves no record of any kind —
/// which is what lets the caller obey ADR 0034's "the child object is written only after admission
/// succeeds".
pub(crate) fn admit_delegation(
    data_dir: &str,
    request: &DelegationRequest<'_>,
) -> Result<AdmittedDelegation, DelegationRefusal> {
    let store = WorkLifecycleStore::new(data_dir);
    let parent = read_parent_position(&store, request.parent_thread_id);

    let mut ancestor_chain: Vec<String> = parent
        .as_ref()
        .map(|position| position.chain.clone())
        .unwrap_or_default();
    ancestor_chain.push(thread_object_ref(request.parent_thread_id));
    ancestor_chain.dedup();
    let depth = ancestor_chain.len() as u64;

    // The parent stores its depth beside its chain, and the two must agree. Depth IS the chain's
    // length, so a stored copy is only useful as a cross-check — and a cross-check that is never
    // read is just drift waiting to be trusted.
    if let Some(position) = parent.as_ref() {
        let chain_length = position.chain.len() as u64;
        if position.depth != chain_length {
            return Err(DelegationRefusal::ParentPositionInconsistent {
                recorded: position.depth,
                chain_length,
            });
        }
    }

    let ceiling = resolve_ceiling(parent.as_ref(), request.requested_depth_ceiling)?;
    if let Some(ceiling) = ceiling {
        if depth > ceiling {
            return Err(DelegationRefusal::DepthCeilingExceeded { depth, ceiling });
        }
    }
    // The contract requires a ceiling, so an UNDECIDABLE bound is recorded at the depth itself and
    // flagged — the edge then says "bounded at exactly where it sits", which is true and is the
    // weakest honest claim, rather than a large number nobody chose.
    let depth_bound_absent = ceiling.is_none();
    let recorded_ceiling = ceiling.unwrap_or(depth);

    let delegation_ref = format!(
        "delegation://{}/{}",
        request.parent_thread_id, request.child_subagent_id
    );
    let edge = json!({
        "schema_version": DELEGATION_EDGE_SCHEMA_VERSION,
        "delegation_ref": delegation_ref,
        "parent_thread_id": request.parent_thread_id,
        "child_subagent_id": request.child_subagent_id,
        "accountable_actor_ref": request.accountable_actor_ref,
        "role_kind": request.role_kind,
        "topology_kind": request.topology_kind,
        "ancestor_chain": ancestor_chain,
        "delegation_depth": depth,
        "depth_ceiling": recorded_ceiling,
        "depth_bound_absent": depth_bound_absent,
        "fanout_reservation_ref": request.fanout_reservation_ref,
        "selected_resolver_kind": request.selected_resolver_kind,
        "selected_resolver_revision_ref": request.selected_resolver_revision_ref,
        "selected_resolver_content_hash": request.selected_resolver_content_hash,
        "selected_model_route_ref": request.selected_model_route_ref,
        "forked_thread_ref": thread_object_ref(request.child_thread_id),
        "managed_session_ref": Value::Null,
        "launch_recipe_ref": Value::Null,
        "harness_binding_ref": Value::Null,
        "orchestration_ref": request.orchestration_ref,
        "admitted_at_ms": request.now_ms,
    });

    // APPEND 1 — the edge, as a child_reference on the PARENT's chain. This is the work-owning
    // relation; the parent's projection answers "what are this parent's children?" from here
    // rather than from a `parent_thread_id` scan (ADR 0034 sub-ruling 5).
    let parent_object = thread_object_ref(request.parent_thread_id);
    let parent_chain = store.load_chain(&parent_object).unwrap_or_default();
    let parent_head = parent_chain
        .last()
        .and_then(|record| record.get("resulting_head"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if parent_head.is_none() {
        // The parent has no chain yet. Its genesis records the parent's OWN position, which for a
        // root thread is depth 0 under no ceiling — stated rather than assumed, so a later
        // delegation from this thread narrows from a record instead of from a default.
        let genesis = position_record(
            &parent_object,
            request,
            0,
            &[],
            None,
            "root",
            &format!("{}/position/0", request.parent_thread_id),
        );
        store
            .append_gated(&genesis, &DelegationContinuityGate)
            .map_err(DelegationRefusal::Store)?;
    }
    let attach = json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!("work-lifecycle://{delegation_ref}"),
        "record_hash": "",
        "record_type": "child_reference",
        "object_kind": "work_run",
        "object_ref": parent_object,
        "owner_ref": request.owner_ref,
        "expected_head": store
            .load_chain(&parent_object)
            .ok()
            .and_then(|chain| {
                chain
                    .last()
                    .and_then(|record| record.get("resulting_head"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .map(Value::String)
            .unwrap_or(Value::Null),
        "resulting_head": "",
        "idempotency_key": format!("delegation-attach/{delegation_ref}"),
        "authority_class": "daemon",
        "authority_ref": "actor://daemon",
        "authority_grant_refs": [],
        "decision_receipt_ref": Value::Null,
        "evidence_refs": [],
        "receipt_refs": [],
        "phase_transition": Value::Null,
        "child_reference": {
            "operation": "attach",
            "relation_kind": "harness_invocation",
            "child_ref": delegation_ref,
            "effect_recovery_class": "compensatable",
            "delegation_edge": edge.clone(),
        },
        "occurred_at_ms": request.now_ms,
    });
    store
        .append_gated(&attach, &DelegationContinuityGate)
        .map_err(DelegationRefusal::Store)?;

    // APPEND 2 — the CHILD's own position, so its children narrow from a record rather than from
    // a walk of the graph. Genesis on the child thread's own chain.
    let child_object = thread_object_ref(request.child_thread_id);
    // THE CEILING PROPAGATES AS IT WAS DERIVED, NOT AS IT WAS RECORDED. The edge must carry an
    // integer because the contract requires one, so an absent bound is written there as the depth
    // itself. Writing that same number into the child's POSITION would invent a real ceiling out
    // of an absence: the child would inherit "ceiling 1", and its own children would be refused
    // for exceeding a bound nobody ever set. A unit test caught exactly that. The position carries
    // `ceiling`, which is None when the bound was underivable, so absence propagates as absence.
    let position = position_record(
        &child_object,
        request,
        depth,
        &ancestor_chain,
        ceiling,
        "delegated",
        &format!("{}/position/{depth}", request.child_thread_id),
    );
    store
        .append_gated(&position, &DelegationContinuityGate)
        .map_err(DelegationRefusal::Store)?;

    Ok(AdmittedDelegation {
        edge,
        depth_bound_absent,
    })
}

/// A thread's own position on its own chain: the depth it admitted at and the ceiling it admitted
/// under. Genesis, so it is written once and read by every delegation that narrows from it.
fn position_record(
    object_ref: &str,
    request: &DelegationRequest<'_>,
    depth: u64,
    ancestor_chain: &[String],
    ceiling: Option<u64>,
    phase: &str,
    key: &str,
) -> Value {
    json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!("work-lifecycle://{key}"),
        "record_hash": "",
        "record_type": "phase_transition",
        "object_kind": "work_run",
        "object_ref": object_ref,
        "owner_ref": request.owner_ref,
        "expected_head": Value::Null,
        "resulting_head": "",
        "idempotency_key": format!("delegation-position/{key}"),
        "authority_class": "daemon",
        "authority_ref": "actor://daemon",
        "authority_grant_refs": [],
        "decision_receipt_ref": Value::Null,
        "evidence_refs": [],
        "receipt_refs": [],
        "phase_transition": {
            "from_phase": Value::Null,
            "to_phase": phase,
            "delegation_position": {
                "depth": depth,
                "depth_ceiling": ceiling,
                "ancestor_chain": ancestor_chain,
            },
        },
        "child_reference": Value::Null,
        "occurred_at_ms": request.now_ms,
    })
}

/// The same continuity rule the generic writer enforces (R-192): a successor may not re-declare
/// the object kind its genesis fixed. Stated here rather than imported so this module's admission
/// carries a gate of its own, as `append_gated` requires of every caller.
struct DelegationContinuityGate;

impl ioi_services::agentic::runtime::kernel::runtime_work_lifecycle_log::LegalEdgeGate
    for DelegationContinuityGate
{
    fn authorize(&self, prior: Option<&Value>, candidate: &Value) -> Result<(), String> {
        let Some(prior) = prior else {
            return Ok(());
        };
        let before = prior
            .get("object_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let after = candidate
            .get("object_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if before != after {
            return Err(format!(
                "a delegation record may not change `object_kind` under its object: '{before}' -> '{after}'"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::substrate_store;
    use super::*;

    fn fresh() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        substrate_store::reset_handle_for_test();
        let data_dir = dir.path().to_str().unwrap().to_string();
        (dir, data_dir)
    }

    fn request<'a>(
        parent: &'a str,
        child: &'a str,
        child_thread: &'a str,
    ) -> DelegationRequest<'a> {
        DelegationRequest {
            parent_thread_id: parent,
            child_subagent_id: child,
            child_thread_id: child_thread,
            accountable_actor_ref: "user://operator-7".into(),
            role_kind: "implementer".into(),
            topology_kind: "direct".into(),
            requested_depth_ceiling: None,
            fanout_reservation_ref: None,
            selected_resolver_kind: "none".into(),
            selected_resolver_revision_ref: None,
            selected_resolver_content_hash: None,
            selected_model_route_ref: None,
            orchestration_ref: None,
            owner_ref: "user://operator-7".into(),
            now_ms: 1_789_000_000_000,
        }
    }

    /// The whole point of the edge: depth is the chain's length, and a grandchild narrows from a
    /// RECORD its parent left rather than from a walk of the graph.
    #[test]
    fn depth_is_the_chain_length_and_a_grandchild_narrows_from_its_parents_record() {
        let (_dir, data_dir) = fresh();
        let first = admit_delegation(&data_dir, &request("thread_root", "sub_a", "thread_a"))
            .expect("first delegation");
        assert_eq!(first.edge["delegation_depth"], json!(1));
        assert_eq!(
            first.edge["ancestor_chain"],
            json!(["thread://thread_root"])
        );
        assert_eq!(
            first.edge["delegation_ref"],
            json!("delegation://thread_root/sub_a")
        );

        // The child's own position was recorded, so a delegation FROM it reads depth 2 without
        // this function knowing anything about the first call.
        let second = admit_delegation(&data_dir, &request("thread_a", "sub_b", "thread_b"))
            .expect("second delegation");
        assert_eq!(second.edge["delegation_depth"], json!(2));
        assert_eq!(
            second.edge["ancestor_chain"],
            json!(["thread://thread_root", "thread://thread_a"])
        );
    }

    /// A ceiling is inherited, and a request may narrow it but never widen it.
    #[test]
    fn a_child_narrows_its_parents_ceiling_and_cannot_widen_it() {
        let (_dir, data_dir) = fresh();
        let mut bounded = request("thread_root", "sub_a", "thread_a");
        bounded.requested_depth_ceiling = Some(2);
        let first = admit_delegation(&data_dir, &bounded).expect("bounded delegation");
        assert_eq!(first.edge["depth_ceiling"], json!(2));
        assert!(!first.depth_bound_absent);

        let mut widening = request("thread_a", "sub_b", "thread_b");
        widening.requested_depth_ceiling = Some(9);
        let refused = admit_delegation(&data_dir, &widening).expect_err("widening is refused");
        assert_eq!(refused.code(), "delegation_ceiling_widened");

        let inherited = admit_delegation(&data_dir, &request("thread_a", "sub_c", "thread_c"))
            .expect("inherits the parent's ceiling");
        assert_eq!(inherited.edge["depth_ceiling"], json!(2));
        assert!(!inherited.depth_bound_absent);
    }

    /// And the ceiling is ENFORCED, not merely recorded: the delegation that would sit past it is
    /// refused before anything durable is written for it.
    #[test]
    fn a_delegation_past_its_inherited_ceiling_is_refused() {
        let (_dir, data_dir) = fresh();
        let mut bounded = request("thread_root", "sub_a", "thread_a");
        bounded.requested_depth_ceiling = Some(1);
        admit_delegation(&data_dir, &bounded).expect("at the ceiling");

        let refused = admit_delegation(&data_dir, &request("thread_a", "sub_b", "thread_b"))
            .expect_err("past the ceiling");
        assert_eq!(refused.code(), "delegation_depth_ceiling_exceeded");

        // Nothing was written for the refused delegation: the child thread has no position, so a
        // later delegation from it still reads as a root rather than inheriting a phantom.
        let store = WorkLifecycleStore::new(&data_dir);
        assert!(store
            .load_chain("thread://thread_b")
            .unwrap_or_default()
            .is_empty());
    }

    /// An undecidable bound is RECORDED as absent, never defaulted to a number nobody chose — and
    /// the absence PROPAGATES as an absence.
    ///
    /// The second half is the half a unit test had to find. The edge must carry an integer ceiling
    /// because its contract requires one, so an absent bound is written there as the depth itself.
    /// Writing that same number into the child's position invented a real ceiling out of an
    /// absence: the child inherited "ceiling 1" and its own children were refused for exceeding a
    /// bound nobody ever set. The edge says the number AND says it is not a bound.
    #[test]
    fn an_underivable_bound_is_recorded_absent_and_propagates_as_absent() {
        let (_dir, data_dir) = fresh();
        let admitted = admit_delegation(&data_dir, &request("thread_root", "sub_a", "thread_a"))
            .expect("unbounded delegation");
        assert!(admitted.depth_bound_absent);
        assert_eq!(admitted.edge["depth_bound_absent"], json!(true));
        // The recorded ceiling is the depth itself — the weakest honest claim, "bounded at exactly
        // where it sits" — rather than a large number that would read as headroom.
        assert_eq!(
            admitted.edge["depth_ceiling"],
            admitted.edge["delegation_depth"]
        );

        // And the grandchild is NOT refused against that number.
        let grandchild = admit_delegation(&data_dir, &request("thread_a", "sub_b", "thread_b"))
            .expect("an absent bound does not become an inherited ceiling");
        assert_eq!(grandchild.edge["delegation_depth"], json!(2));
        assert!(grandchild.depth_bound_absent);
    }

    /// A bounded parent still bounds: the absence rule must not weaken a real ceiling.
    #[test]
    fn a_real_ceiling_still_refuses_after_the_absence_fix() {
        let (_dir, data_dir) = fresh();
        let mut bounded = request("thread_root", "sub_a", "thread_a");
        bounded.requested_depth_ceiling = Some(1);
        let first = admit_delegation(&data_dir, &bounded).expect("at the ceiling");
        assert_eq!(first.edge["depth_bound_absent"], json!(false));
        let refused = admit_delegation(&data_dir, &request("thread_a", "sub_b", "thread_b"))
            .expect_err("a real ceiling still refuses");
        assert_eq!(refused.code(), "delegation_depth_ceiling_exceeded");
    }
}
