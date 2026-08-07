//! Shared WorkLifecycle admission kernel.
//!
//! This is the single bounding site for work-owning admission edges (INV-35).
//! Every path that delegates execution, authority, or consumable capacity
//! admits its child here. No caller implements its own depth, fanout, budget,
//! narrowing, or cancellation logic (ADR 0034 sub-ruling 1).
//!
//! The discipline is ported from the wallet/authority delegation plane
//! (`crates/services/src/wallet_network/`), which already implements it
//! correctly for that plane, rather than designed fresh.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

pub const RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.work-lifecycle-admission-request.v1";
pub const RUNTIME_WORK_LIFECYCLE_ADMISSION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.work_lifecycle_admission.v1";

/// Admitted state of one node in the work-owning graph.
///
/// `state_head` is the exact head this record was admitted at. Every mutation
/// validates it, so a stale ancestor cannot authorize a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOwningNodeState {
    pub node_id: String,
    pub root_id: String,
    pub parent_id: Option<String>,
    pub state_head: String,
    pub depth: u8,
    pub max_depth: u8,
    pub can_delegate: bool,
    /// Remaining descendant admissions. `None` = unbounded.
    pub remaining_descendant_budget: Option<u32>,
    pub children_admitted: u32,
    pub active_children: u32,
    /// Concurrent active children ceiling. `None` = unbounded.
    pub max_concurrent_children: Option<u32>,
    pub deadline_unix_s: Option<u64>,
    pub authority_scope_refs: BTreeSet<String>,
    pub context_visibility_refs: BTreeSet<String>,
    /// Per-dimension conserved capacity owned by this node.
    pub capacity: BTreeMap<String, u64>,
    /// Per-dimension capacity already reserved to children. Disjoint by
    /// construction: a reservation is subtracted here, never copied.
    pub reserved: BTreeMap<String, u64>,
    /// Per-dimension capacity protected for policy-required verification,
    /// integration, cancellation, reconciliation, and receipts. Reserved
    /// first; children can never consume it.
    pub protected: BTreeMap<String, u64>,
    pub terminal: bool,
    pub fenced: bool,
}

impl WorkOwningNodeState {
    /// Capacity actually available to a new child in one dimension.
    pub fn available(&self, dimension: &str) -> u64 {
        let total = self.capacity.get(dimension).copied().unwrap_or(0);
        let reserved = self.reserved.get(dimension).copied().unwrap_or(0);
        let protected = self.protected.get(dimension).copied().unwrap_or(0);
        total.saturating_sub(reserved).saturating_sub(protected)
    }

    pub fn is_settled(&self) -> bool {
        self.terminal || self.fenced
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WorkLifecycleAdmissionRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub parent_node_id: Option<String>,
    /// Exact head the caller believes the parent is at.
    #[serde(default)]
    pub expected_parent_head: Option<String>,
    #[serde(default)]
    pub child_node_id: Option<String>,
    #[serde(default)]
    pub requested_max_depth: Option<u8>,
    #[serde(default)]
    pub requested_descendant_budget: Option<u32>,
    #[serde(default)]
    pub requested_max_concurrent_children: Option<u32>,
    #[serde(default)]
    pub requested_deadline_unix_s: Option<u64>,
    #[serde(default)]
    pub requested_authority_scope_refs: Vec<String>,
    #[serde(default)]
    pub requested_context_visibility_refs: Vec<String>,
    #[serde(default)]
    pub requested_reservations: BTreeMap<String, u64>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLifecycleAdmissionError {
    code: &'static str,
    message: String,
}

impl WorkLifecycleAdmissionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

type AdmitResult<T> = Result<T, WorkLifecycleAdmissionError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLifecycleAdmissionRecord {
    pub child: WorkOwningNodeState,
    pub parent_after: WorkOwningNodeState,
    pub admitted_reservations: BTreeMap<String, u64>,
}

/// Result of asking whether a node may release its conserved capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityReleasePlan {
    pub node_id: String,
    pub may_release: bool,
    pub blocking_children: Vec<String>,
    pub released: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkLifecycleAdmissionCore;

impl WorkLifecycleAdmissionCore {
    /// Admit one work-owning child edge under `parent`.
    ///
    /// `ancestors` is the parent's ancestor chain, root-first, excluding the
    /// parent itself. It is used for cycle detection.
    pub fn admit_child(
        &self,
        parent: &WorkOwningNodeState,
        ancestors: &[WorkOwningNodeState],
        request: &WorkLifecycleAdmissionRequest,
    ) -> AdmitResult<WorkLifecycleAdmissionRecord> {
        if let Some(version) = optional_trimmed(request.schema_version.as_deref()) {
            if version != RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION}, got {version}"
                    ),
                ));
            }
        }

        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "work.admit_child".to_string());
        if operation_kind != "work.admit_child" {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_operation_kind_unsupported",
                format!("{operation_kind} is not a work-owning admission"),
            ));
        }

        let parent_node_id =
            optional_trimmed(request.parent_node_id.as_deref()).ok_or_else(|| {
                WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_parent_node_id_required",
                    "admission requires parent_node_id",
                )
            })?;
        if parent_node_id != parent.node_id {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_parent_mismatch",
                "parent_node_id does not match the supplied parent state",
            ));
        }

        let child_node_id =
            optional_trimmed(request.child_node_id.as_deref()).ok_or_else(|| {
                WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_child_node_id_required",
                    "admission requires child_node_id",
                )
            })?;

        // Exact-head ancestor admission. A stale parent cannot authorize.
        let expected_head =
            optional_trimmed(request.expected_parent_head.as_deref()).ok_or_else(|| {
                WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_expected_parent_head_required",
                    "admission requires expected_parent_head",
                )
            })?;
        if expected_head != parent.state_head {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_stale_ancestor_head",
                "expected_parent_head does not match the current parent head",
            ));
        }

        if parent.is_settled() {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_parent_settled",
                "a terminal or fenced parent cannot admit new work-owning children",
            ));
        }

        // Every applicable ancestor limit, not just the parent's.
        for ancestor in ancestors {
            if ancestor.is_settled() {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_ancestor_settled",
                    format!("ancestor {} is terminal or fenced", ancestor.node_id),
                ));
            }
            if !ancestor.can_delegate {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_ancestor_delegation_revoked",
                    format!("ancestor {} does not allow delegation", ancestor.node_id),
                ));
            }
        }

        // Finite and acyclic.
        if child_node_id == parent.node_id {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_cycle_detected",
                "a node cannot be its own child",
            ));
        }
        if ancestors
            .iter()
            .any(|ancestor| ancestor.node_id == child_node_id)
        {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_cycle_detected",
                "child_node_id already appears in the ancestor chain",
            ));
        }

        if !parent.can_delegate {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_delegation_not_permitted",
                "parent does not allow further delegation",
            ));
        }

        if parent.depth > parent.max_depth {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_parent_depth_invalid",
                "parent depth already exceeds its max_depth",
            ));
        }

        let child_depth_u16 = u16::from(parent.depth) + 1;
        if child_depth_u16 > u16::from(u8::MAX) {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_depth_overflow",
                "work-owning delegation depth overflow",
            ));
        }
        let depth = child_depth_u16 as u8;
        if depth > parent.max_depth {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_depth_exceeded",
                "work-owning delegation depth exceeds max_depth",
            ));
        }

        // Concurrency ceiling.
        if let Some(max_concurrent) = parent.max_concurrent_children {
            if parent.active_children >= max_concurrent {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_concurrency_exceeded",
                    "parent already has its maximum concurrent active children",
                ));
            }
        }

        // Descendant budget: decrement the parent, never copy it.
        if let Some(remaining) = parent.remaining_descendant_budget {
            if remaining == 0 {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_descendant_budget_exhausted",
                    "parent descendant budget exhausted",
                ));
            }
        }
        let parent_remaining_after = parent
            .remaining_descendant_budget
            .map(|remaining| remaining.saturating_sub(1));

        // Ceilings only narrow.
        let child_max_depth = request.requested_max_depth.unwrap_or(parent.max_depth);
        if child_max_depth > parent.max_depth {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_max_depth_widened",
                "child max_depth must be <= parent max_depth",
            ));
        }
        if child_max_depth < depth {
            return Err(WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_max_depth_below_current",
                "child max_depth must be >= current depth",
            ));
        }

        let child_budget = match (parent_remaining_after, request.requested_descendant_budget) {
            (Some(parent_remaining), Some(requested)) => {
                if requested > parent_remaining {
                    return Err(WorkLifecycleAdmissionError::new(
                        "work_lifecycle_admission_descendant_budget_widened",
                        "child descendant budget must be <= parent remaining budget",
                    ));
                }
                Some(requested)
            }
            (Some(parent_remaining), None) => Some(parent_remaining),
            (None, Some(requested)) => Some(requested),
            (None, None) => None,
        };

        let child_max_concurrent = match (
            parent.max_concurrent_children,
            request.requested_max_concurrent_children,
        ) {
            (Some(parent_max), Some(requested)) => {
                if requested > parent_max {
                    return Err(WorkLifecycleAdmissionError::new(
                        "work_lifecycle_admission_concurrency_widened",
                        "child max_concurrent_children must be <= parent",
                    ));
                }
                Some(requested)
            }
            (Some(parent_max), None) => Some(parent_max),
            (None, Some(requested)) => Some(requested),
            (None, None) => None,
        };

        let child_deadline = match (parent.deadline_unix_s, request.requested_deadline_unix_s) {
            (Some(parent_deadline), Some(requested)) => {
                if requested > parent_deadline {
                    return Err(WorkLifecycleAdmissionError::new(
                        "work_lifecycle_admission_deadline_widened",
                        "child deadline must be <= parent deadline",
                    ));
                }
                Some(requested)
            }
            (Some(parent_deadline), None) => Some(parent_deadline),
            (None, Some(requested)) => Some(requested),
            (None, None) => None,
        };

        let child_authority = narrow_ref_set(
            &parent.authority_scope_refs,
            &request.requested_authority_scope_refs,
        )
        .map_err(|extra| {
            WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_authority_widened",
                format!("child authority scope not held by parent: {extra}"),
            )
        })?;

        let child_context = narrow_ref_set(
            &parent.context_visibility_refs,
            &request.requested_context_visibility_refs,
        )
        .map_err(|extra| {
            WorkLifecycleAdmissionError::new(
                "work_lifecycle_admission_context_visibility_widened",
                format!("child context visibility not held by parent: {extra}"),
            )
        })?;

        // Per-dimension atomic disjoint reservations. Protected capacity is
        // subtracted first and is never reachable by a child.
        let mut parent_reserved_after = parent.reserved.clone();
        let mut admitted_reservations = BTreeMap::new();
        for (dimension, requested) in &request.requested_reservations {
            if *requested == 0 {
                continue;
            }
            let available = parent.available(dimension);
            if *requested > available {
                return Err(WorkLifecycleAdmissionError::new(
                    "work_lifecycle_admission_reservation_unavailable",
                    format!(
                        "requested {requested} of dimension {dimension} exceeds available {available}"
                    ),
                ));
            }
            let entry = parent_reserved_after.entry(dimension.clone()).or_insert(0);
            *entry = entry.saturating_add(*requested);
            admitted_reservations.insert(dimension.clone(), *requested);
        }

        let child_capacity = admitted_reservations.clone();

        let child = WorkOwningNodeState {
            node_id: child_node_id,
            root_id: parent.root_id.clone(),
            parent_id: Some(parent.node_id.clone()),
            state_head: String::new(),
            depth,
            max_depth: child_max_depth,
            can_delegate: can_delegate_further(depth, child_max_depth, child_budget),
            remaining_descendant_budget: child_budget,
            children_admitted: 0,
            active_children: 0,
            max_concurrent_children: child_max_concurrent,
            deadline_unix_s: child_deadline,
            authority_scope_refs: child_authority,
            context_visibility_refs: child_context,
            capacity: child_capacity,
            reserved: BTreeMap::new(),
            protected: BTreeMap::new(),
            terminal: false,
            fenced: false,
        };

        let mut parent_after = parent.clone();
        parent_after.remaining_descendant_budget = parent_remaining_after;
        parent_after.children_admitted = parent_after.children_admitted.saturating_add(1);
        parent_after.active_children = parent_after.active_children.saturating_add(1);
        parent_after.reserved = parent_reserved_after;
        parent_after.can_delegate = parent_after.can_delegate
            && can_delegate_further(
                parent_after.depth,
                parent_after.max_depth,
                parent_after.remaining_descendant_budget,
            );

        Ok(WorkLifecycleAdmissionRecord {
            child,
            parent_after,
            admitted_reservations,
        })
    }

    /// Decide whether a node may release its conserved capacity.
    ///
    /// INV-35: process exit, a cancellation request, or bare local detach
    /// neither releases capacity nor permits parent success until relevant
    /// child effects are terminal or fenced.
    pub fn plan_capacity_release(
        &self,
        node: &WorkOwningNodeState,
        children: &[WorkOwningNodeState],
    ) -> CapacityReleasePlan {
        let blocking: Vec<String> = children
            .iter()
            .filter(|child| child.parent_id.as_deref() == Some(node.node_id.as_str()))
            .filter(|child| !child.is_settled())
            .map(|child| child.node_id.clone())
            .collect();

        let may_release = blocking.is_empty();
        let released = if may_release {
            node.reserved.clone()
        } else {
            BTreeMap::new()
        };

        CapacityReleasePlan {
            node_id: node.node_id.clone(),
            may_release,
            blocking_children: blocking,
            released,
        }
    }
}

fn can_delegate_further(depth: u8, max_depth: u8, remaining_budget: Option<u32>) -> bool {
    if depth >= max_depth {
        return false;
    }
    !matches!(remaining_budget, Some(0))
}

/// Returns the requested set if it is a subset of `parent`, else the first
/// offending ref. An empty request inherits the parent's set unchanged.
fn narrow_ref_set(
    parent: &BTreeSet<String>,
    requested: &[String],
) -> Result<BTreeSet<String>, String> {
    if requested.is_empty() {
        return Ok(parent.clone());
    }
    let mut out = BTreeSet::new();
    for candidate in requested {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !parent.contains(trimmed) {
            return Err(trimmed.to_string());
        }
        out.insert(trimmed.to_string());
    }
    Ok(out)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn parent() -> WorkOwningNodeState {
        WorkOwningNodeState {
            node_id: "parent".into(),
            root_id: "root".into(),
            parent_id: None,
            state_head: "head-1".into(),
            depth: 0,
            max_depth: 3,
            can_delegate: true,
            remaining_descendant_budget: Some(4),
            children_admitted: 0,
            active_children: 0,
            max_concurrent_children: Some(2),
            deadline_unix_s: Some(1_000),
            authority_scope_refs: refs(&["scope:a", "scope:b"]),
            context_visibility_refs: refs(&["ctx:a"]),
            capacity: BTreeMap::from([("tokens".to_string(), 100)]),
            reserved: BTreeMap::new(),
            protected: BTreeMap::from([("tokens".to_string(), 20)]),
            terminal: false,
            fenced: false,
        }
    }

    fn request() -> WorkLifecycleAdmissionRequest {
        WorkLifecycleAdmissionRequest {
            schema_version: Some(
                RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation_kind: Some("work.admit_child".into()),
            parent_node_id: Some("parent".into()),
            expected_parent_head: Some("head-1".into()),
            child_node_id: Some("child".into()),
            ..Default::default()
        }
    }

    #[test]
    fn admits_a_child_and_narrows_by_default() {
        let core = WorkLifecycleAdmissionCore;
        let record = core.admit_child(&parent(), &[], &request()).unwrap();
        assert_eq!(record.child.depth, 1);
        assert_eq!(record.child.max_depth, 3);
        assert_eq!(record.child.remaining_descendant_budget, Some(3));
        assert_eq!(record.parent_after.remaining_descendant_budget, Some(3));
        assert_eq!(record.parent_after.active_children, 1);
        assert_eq!(
            record.child.authority_scope_refs,
            refs(&["scope:a", "scope:b"])
        );
    }

    #[test]
    fn stale_ancestor_head_is_refused() {
        let core = WorkLifecycleAdmissionCore;
        let mut req = request();
        req.expected_parent_head = Some("head-0".into());
        let err = core.admit_child(&parent(), &[], &req).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_admission_stale_ancestor_head");
    }

    #[test]
    fn depth_ceiling_is_enforced() {
        let core = WorkLifecycleAdmissionCore;
        let mut p = parent();
        p.depth = 3;
        p.max_depth = 3;
        let err = core.admit_child(&p, &[], &request()).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_admission_depth_exceeded");
    }

    #[test]
    fn ceilings_only_narrow() {
        let core = WorkLifecycleAdmissionCore;
        let mut req = request();
        req.requested_max_depth = Some(9);
        assert_eq!(
            core.admit_child(&parent(), &[], &req).unwrap_err().code(),
            "work_lifecycle_admission_max_depth_widened"
        );

        let mut req = request();
        req.requested_deadline_unix_s = Some(9_999);
        assert_eq!(
            core.admit_child(&parent(), &[], &req).unwrap_err().code(),
            "work_lifecycle_admission_deadline_widened"
        );

        let mut req = request();
        req.requested_authority_scope_refs = vec!["scope:z".into()];
        assert_eq!(
            core.admit_child(&parent(), &[], &req).unwrap_err().code(),
            "work_lifecycle_admission_authority_widened"
        );

        let mut req = request();
        req.requested_context_visibility_refs = vec!["ctx:z".into()];
        assert_eq!(
            core.admit_child(&parent(), &[], &req).unwrap_err().code(),
            "work_lifecycle_admission_context_visibility_widened"
        );
    }

    #[test]
    fn descendant_budget_exhaustion_refuses() {
        let core = WorkLifecycleAdmissionCore;
        let mut p = parent();
        p.remaining_descendant_budget = Some(0);
        let err = core.admit_child(&p, &[], &request()).unwrap_err();
        assert_eq!(
            err.code(),
            "work_lifecycle_admission_descendant_budget_exhausted"
        );
    }

    #[test]
    fn concurrency_ceiling_refuses() {
        let core = WorkLifecycleAdmissionCore;
        let mut p = parent();
        p.active_children = 2;
        let err = core.admit_child(&p, &[], &request()).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_admission_concurrency_exceeded");
    }

    #[test]
    fn simultaneous_siblings_get_disjoint_reservations_not_copies() {
        let core = WorkLifecycleAdmissionCore;
        let mut req_a = request();
        req_a.child_node_id = Some("child-a".into());
        req_a.requested_reservations = BTreeMap::from([("tokens".to_string(), 50)]);

        // 100 capacity - 20 protected = 80 available.
        let first = core.admit_child(&parent(), &[], &req_a).unwrap();
        assert_eq!(first.admitted_reservations.get("tokens"), Some(&50));

        // The sibling admits against the PARENT AFTER, not a copy of the
        // original allowance. Only 30 remains.
        let mut req_b = request();
        req_b.child_node_id = Some("child-b".into());
        req_b.requested_reservations = BTreeMap::from([("tokens".to_string(), 50)]);
        let err = core
            .admit_child(&first.parent_after, &[], &req_b)
            .unwrap_err();
        assert_eq!(
            err.code(),
            "work_lifecycle_admission_reservation_unavailable"
        );

        let mut req_c = request();
        req_c.child_node_id = Some("child-c".into());
        req_c.requested_reservations = BTreeMap::from([("tokens".to_string(), 30)]);
        let second = core.admit_child(&first.parent_after, &[], &req_c).unwrap();
        assert_eq!(second.admitted_reservations.get("tokens"), Some(&30));
    }

    #[test]
    fn protected_capacity_is_never_reachable_by_a_child() {
        let core = WorkLifecycleAdmissionCore;
        let mut req = request();
        // 100 total, 20 protected -> 80 available. 81 must fail.
        req.requested_reservations = BTreeMap::from([("tokens".to_string(), 81)]);
        let err = core.admit_child(&parent(), &[], &req).unwrap_err();
        assert_eq!(
            err.code(),
            "work_lifecycle_admission_reservation_unavailable"
        );
    }

    #[test]
    fn cycles_are_refused() {
        let core = WorkLifecycleAdmissionCore;
        let mut req = request();
        req.child_node_id = Some("parent".into());
        assert_eq!(
            core.admit_child(&parent(), &[], &req).unwrap_err().code(),
            "work_lifecycle_admission_cycle_detected"
        );

        let ancestor = WorkOwningNodeState {
            node_id: "grandparent".into(),
            ..parent()
        };
        let mut req = request();
        req.child_node_id = Some("grandparent".into());
        assert_eq!(
            core.admit_child(&parent(), &[ancestor], &req)
                .unwrap_err()
                .code(),
            "work_lifecycle_admission_cycle_detected"
        );
    }

    #[test]
    fn settled_parent_or_ancestor_refuses() {
        let core = WorkLifecycleAdmissionCore;
        let mut p = parent();
        p.terminal = true;
        assert_eq!(
            core.admit_child(&p, &[], &request()).unwrap_err().code(),
            "work_lifecycle_admission_parent_settled"
        );

        let mut ancestor = parent();
        ancestor.node_id = "grandparent".into();
        ancestor.fenced = true;
        assert_eq!(
            core.admit_child(&parent(), &[ancestor], &request())
                .unwrap_err()
                .code(),
            "work_lifecycle_admission_ancestor_settled"
        );
    }

    #[test]
    fn capacity_is_not_released_while_children_are_unsettled() {
        let core = WorkLifecycleAdmissionCore;
        let mut node = parent();
        node.reserved = BTreeMap::from([("tokens".to_string(), 50)]);

        let mut live_child = parent();
        live_child.node_id = "child".into();
        live_child.parent_id = Some("parent".into());

        let plan = core.plan_capacity_release(&node, std::slice::from_ref(&live_child));
        assert!(!plan.may_release);
        assert_eq!(plan.blocking_children, vec!["child".to_string()]);
        assert!(plan.released.is_empty());

        let mut settled_child = live_child.clone();
        settled_child.fenced = true;
        let plan = core.plan_capacity_release(&node, &[settled_child]);
        assert!(plan.may_release);
        assert_eq!(plan.released.get("tokens"), Some(&50));
    }
}
