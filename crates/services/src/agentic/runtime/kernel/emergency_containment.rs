//! Emergency containment and claim-truth core.
//!
//! This module is a CLAIM-REDUCING containment layer. It adds no capability and grants no
//! authority. It exists because several runtime surfaces asserted stronger isolation, cleaner
//! evidence, and safer restore behaviour than the code actually measured. Every decision here
//! fails CLOSED and names its reason.
//!
//! Five containments live here, each with one entry point:
//!
//! 1. [`admit_isolated_execution`] — an execution whose environment DECLARED an isolated
//!    substrate must never silently run on the host. If the isolated substrate is not live, the
//!    operation refuses by name instead of falling back.
//! 2. [`unsafe_path_gate`] — cache/export/restore paths whose safety is not established are
//!    gated behind an explicit opt-in that defaults OFF.
//! 3. [`admit_resource_creation`] — nothing NEW may be admitted when its safe cleanup cannot be
//!    guaranteed.
//! 4. [`close_deletion`] — the owner-specified CARVE-OUT. Deletion of an EXISTING resource stays
//!    callable at all times, returns an exact `succeeded | failed | unknown` outcome, and opens a
//!    durable cleanup obligation whenever the outcome is not `succeeded`. `unknown` is a
//!    first-class outcome and is NEVER coerced into either of the other two.
//! 5. [`evidence_citation`] — quarantined evidence is retained but cannot be cited as proof.
//!
//! Design rule: these are pure functions over plain values. They hold no I/O, so the route layer
//! cannot satisfy their preconditions by writing constants into a request (INV-37) — the caller
//! must pass an OBSERVATION, and the observation type names what was actually measured.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const EMERGENCY_CONTAINMENT_SCHEMA_VERSION: &str = "ioi.runtime.emergency_containment.v1";

/// A fail-closed containment refusal. `reason` is a stable snake_case code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentRefusal {
    pub reason: String,
    pub detail: String,
}

impl ContainmentRefusal {
    fn new(reason: &str, detail: impl Into<String>) -> Self {
        Self {
            reason: reason.to_string(),
            detail: detail.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": EMERGENCY_CONTAINMENT_SCHEMA_VERSION,
            "refused": true,
            "reason": self.reason,
            "detail": self.detail,
        })
    }
}

// ---------------------------------------------------------------------------
// 1. Isolation: refuse, never fall back.
// ---------------------------------------------------------------------------

/// What the environment record DECLARES about its isolation floor.
///
/// This is the declaration, not a measurement. It is deliberately separate from
/// [`IsolatedSubstrate`] so a caller cannot conflate "we asked for a VM" with "a VM is running".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredIsolation {
    /// The environment declared a kernel/VM isolation floor (`minimum_isolation: vm_kernel`,
    /// `substrate: microvm`, or a microVM environment class).
    VmKernel,
    /// The environment declared only process/workspace scoping. Host execution is truthful here.
    ProcessScoped,
}

impl DeclaredIsolation {
    /// Read the declaration off an environment status record.
    ///
    /// Any of the three microVM signals is sufficient — a record that lost one field must not
    /// thereby lose its isolation floor.
    pub fn from_env_status(status: &Value) -> Self {
        let minimum = status.get("minimum_isolation").and_then(|v| v.as_str());
        let substrate = status.get("substrate").and_then(|v| v.as_str());
        let claim = status.get("isolation_claim").and_then(|v| v.as_str());
        if minimum == Some("vm_kernel")
            || substrate == Some("microvm")
            || claim == Some("cross_tenant_capable")
        {
            Self::VmKernel
        } else {
            Self::ProcessScoped
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::VmKernel => "vm_kernel",
            Self::ProcessScoped => "process_scoped",
        }
    }
}

/// A MEASURED observation of whether the isolated substrate is actually live.
///
/// Constructed only from a real probe of the live-VM registry. There is deliberately no
/// `From<bool>` and no `Deserialize`: a request body cannot become an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolatedSubstrate {
    Live,
    Unavailable,
}

impl IsolatedSubstrate {
    /// Build the observation from a live-handle probe performed by the runtime.
    pub fn observed(live_handle_present: bool) -> Self {
        if live_handle_present {
            Self::Live
        } else {
            Self::Unavailable
        }
    }
}

/// Where the operation would actually run if it were allowed to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionLocus {
    /// Inside the isolated guest.
    Guest,
    /// On the host — a host process, a host filesystem write, or a host PTY.
    Host,
}

/// Refuse host execution whenever an isolated substrate was declared.
///
/// Returns `Ok(())` only when the execution is truthful: either it runs in the guest with a live
/// guest, or the environment never claimed isolation in the first place.
///
/// The two refusal reasons are distinct on purpose:
/// - `isolation_required_substrate_unavailable` — isolation was declared and the substrate is
///   gone. This is the "do not silently fall back to the host" case.
/// - `isolation_required_host_execution_refused` — isolation was declared, the substrate may even
///   be live, but this code path executes host-side regardless. This is the "host-executed
///   WorkRun" case.
pub fn admit_isolated_execution(
    declared: DeclaredIsolation,
    substrate: IsolatedSubstrate,
    locus: ExecutionLocus,
) -> Result<(), ContainmentRefusal> {
    if declared == DeclaredIsolation::ProcessScoped {
        return Ok(());
    }
    match (locus, substrate) {
        (ExecutionLocus::Guest, IsolatedSubstrate::Live) => Ok(()),
        (ExecutionLocus::Guest, IsolatedSubstrate::Unavailable) => Err(ContainmentRefusal::new(
            "isolation_required_substrate_unavailable",
            "environment declared minimum_isolation=vm_kernel but no live isolated substrate \
             backs it; refusing rather than falling back to the host",
        )),
        (ExecutionLocus::Host, _) => Err(ContainmentRefusal::new(
            "isolation_required_host_execution_refused",
            "environment declared minimum_isolation=vm_kernel; this operation executes host-side \
             and cannot honour that declaration, so it is refused",
        )),
    }
}

/// Withdraw an isolation label that measurement does not support.
///
/// Given the declared floor and what was actually observed, return the label that is TRUE. This
/// is how the runtime stops publishing `vm_kernel` enforcement for an environment whose microVM
/// failed to boot.
pub fn truthful_isolation_label(
    declared: DeclaredIsolation,
    substrate: IsolatedSubstrate,
) -> &'static str {
    match (declared, substrate) {
        (DeclaredIsolation::VmKernel, IsolatedSubstrate::Live) => "vm_kernel",
        // Declared a VM, did not get one: say so, do not inherit the stronger label.
        (DeclaredIsolation::VmKernel, IsolatedSubstrate::Unavailable) => {
            "unverified_isolation_declared_vm_kernel_substrate_unavailable"
        }
        (DeclaredIsolation::ProcessScoped, _) => "process_scoped",
    }
}

// ---------------------------------------------------------------------------
// 2. Unsafe cache / export / restore paths: explicit opt-in, default OFF.
// ---------------------------------------------------------------------------

/// The explicit opt-in for restoring workspace material whose provenance is not established.
///
/// Default: OFF. Recorded in `docs/architecture/_meta/current-canon-defaults.md`.
pub const UNVERIFIED_WORKSPACE_RESTORE_GATE: &str = "IOI_ALLOW_UNVERIFIED_WORKSPACE_RESTORE";

/// The explicit opt-in for accepting a guest-declared transfer length.
///
/// Default: OFF. Recorded in `docs/architecture/_meta/current-canon-defaults.md`.
pub const UNBOUNDED_GUEST_TRANSFER_GATE: &str = "IOI_ALLOW_UNBOUNDED_GUEST_TRANSFER";

/// Hard ceiling on a guest-declared transfer, applied when the gate is OFF.
pub const GUEST_TRANSFER_MAX_BYTES: u64 = 1 << 30; // 1 GiB

/// Every containment gate, for canon/documentation cross-checks. Each entry is
/// `(gate name, default enabled)`. Every default MUST be `false`.
pub const CONTAINMENT_GATES: &[(&str, bool)] = &[
    (UNVERIFIED_WORKSPACE_RESTORE_GATE, false),
    (UNBOUNDED_GUEST_TRANSFER_GATE, false),
];

/// Whether an opt-in gate is enabled. Absent, empty, `0`, and `false` all mean OFF.
///
/// The `enabled` argument is the raw environment value, read by the caller.
pub fn gate_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim)
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Refuse an unsafe path unless its gate is explicitly enabled.
pub fn unsafe_path_gate(gate: &str, raw: Option<&str>) -> Result<(), ContainmentRefusal> {
    if gate_enabled(raw) {
        return Ok(());
    }
    Err(ContainmentRefusal::new(
        "unsafe_path_gate_disabled",
        format!(
            "this path is quarantined pending a provenance/integrity bar; set {gate}=1 to opt in \
             (default OFF)"
        ),
    ))
}

/// Bound a guest-declared transfer length.
///
/// A guest inside the isolation boundary declares how many bytes the host should allocate. With
/// the gate OFF, an over-large declaration is refused instead of being allocated.
pub fn admit_guest_transfer_len(
    declared_len: u64,
    raw_gate: Option<&str>,
) -> Result<u64, ContainmentRefusal> {
    if declared_len <= GUEST_TRANSFER_MAX_BYTES || gate_enabled(raw_gate) {
        return Ok(declared_len);
    }
    Err(ContainmentRefusal::new(
        "guest_declared_transfer_too_large",
        format!(
            "guest declared {declared_len} bytes, ceiling is {GUEST_TRANSFER_MAX_BYTES}; set \
             {UNBOUNDED_GUEST_TRANSFER_GATE}=1 to opt in (default OFF)"
        ),
    ))
}

/// Admit one relative cache path declared by a recipe.
///
/// A cache path is copied both INTO and OUT OF a workspace. `Path::join` does not normalize, so
/// an absolute segment silently replaces the base and `..` walks out of it. Both are refused.
pub fn admit_cache_path(rel: &str) -> Result<(), ContainmentRefusal> {
    let trimmed = rel.trim();
    if trimmed.is_empty() {
        return Err(ContainmentRefusal::new(
            "cache_path_not_relative",
            "empty cache path",
        ));
    }
    let path = std::path::Path::new(trimmed);
    if path.is_absolute() || trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(ContainmentRefusal::new(
            "cache_path_not_relative",
            format!("cache path {rel:?} is absolute; Path::join would discard the cache root"),
        ));
    }
    if trimmed.contains('\0') {
        return Err(ContainmentRefusal::new(
            "cache_path_not_relative",
            format!("cache path {rel:?} contains NUL"),
        ));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(ContainmentRefusal::new(
                    "cache_path_escapes_root",
                    format!("cache path {rel:?} contains '..' and escapes the cache root"),
                ))
            }
            _ => {
                return Err(ContainmentRefusal::new(
                    "cache_path_not_relative",
                    format!("cache path {rel:?} has a root or prefix component"),
                ))
            }
        }
    }
    Ok(())
}

/// Build the tenant-scoped cache key segment.
///
/// A cache keyed only by recipe is SHARED across every System on the node: one tenant's build
/// output is restored into another tenant's workspace and then executed. The owning scope is part
/// of the key, and an unattributed cache is refused rather than silently shared.
pub fn admit_cache_scope(owner_scope_ref: Option<&str>) -> Result<String, ContainmentRefusal> {
    match owner_scope_ref.map(str::trim).filter(|s| !s.is_empty()) {
        Some(scope) => Ok(scope.to_string()),
        None => Err(ContainmentRefusal::new(
            "cache_scope_unattributed",
            "refusing to use a cache that is not scoped to an owning System/tenant; an \
             unattributed cache is shared across tenants",
        )),
    }
}

// ---------------------------------------------------------------------------
// 3. Admission: block NEW resources when safe cleanup is unavailable.
// ---------------------------------------------------------------------------

/// A MEASURED observation of whether this resource kind can be cleanly destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupCapability {
    /// A teardown path exists AND its outcome is observed.
    Available,
    /// No teardown path, or teardown outcome is discarded.
    Unavailable,
}

impl CleanupCapability {
    pub fn observed(teardown_path_exists: bool, teardown_outcome_observed: bool) -> Self {
        if teardown_path_exists && teardown_outcome_observed {
            Self::Available
        } else {
            Self::Unavailable
        }
    }
}

/// Refuse to admit a NEW resource whose safe cleanup cannot be guaranteed.
///
/// This deliberately governs CREATION ONLY. Deletion of already-existing resources is never
/// routed through here — see [`close_deletion`].
pub fn admit_resource_creation(
    resource_kind: &str,
    cleanup: CleanupCapability,
) -> Result<(), ContainmentRefusal> {
    match cleanup {
        CleanupCapability::Available => Ok(()),
        CleanupCapability::Unavailable => Err(ContainmentRefusal::new(
            "safe_cleanup_unavailable",
            format!(
                "refusing to admit a new {resource_kind}: its teardown outcome is not observable, \
                 so admitting it would create a resource that cannot be provably destroyed"
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// 4. CARVE-OUT: deletion of existing resources always remains callable.
// ---------------------------------------------------------------------------

/// The exact outcome of deleting an EXISTING resource.
///
/// `Unknown` is first-class. It means the delete was attempted and the runtime cannot prove
/// whether the underlying resource is gone. It is never coerced to `Succeeded` (which would
/// strand a live resource silently) nor to `Failed` (which would falsely imply the resource is
/// definitely still there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionOutcome {
    Succeeded,
    Failed,
    Unknown,
}

impl DeletionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    /// Classify a teardown attempt WITHOUT collapsing ambiguity.
    ///
    /// `proven_absent` must come from a post-delete observation, not from the fact that the
    /// delete call returned. A delete call that returned `Ok` but was never re-observed is
    /// `Unknown`, not `Succeeded`.
    pub fn classify(call_succeeded: bool, proven_absent: bool) -> Self {
        match (call_succeeded, proven_absent) {
            (_, true) => Self::Succeeded,
            (false, false) => Self::Failed,
            // The call returned but absence was never confirmed: honestly unknown.
            (true, false) => Self::Unknown,
        }
    }

    /// Whether this outcome leaves a durable obligation open.
    pub fn opens_obligation(self) -> bool {
        !matches!(self, Self::Succeeded)
    }
}

/// The disposition of one deletion: the exact outcome plus any obligation it opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionDisposition {
    pub schema_version: String,
    pub resource_ref: String,
    pub outcome: DeletionOutcome,
    /// Present exactly when `outcome != succeeded`.
    pub cleanup_obligation_ref: Option<String>,
    pub detail: String,
}

impl DeletionDisposition {
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "resource_ref": self.resource_ref,
            "outcome": self.outcome.as_str(),
            "cleanup_obligation_ref": self.cleanup_obligation_ref,
            "detail": self.detail,
        })
    }
}

/// Close out a deletion of an EXISTING resource.
///
/// This function NEVER refuses. Containment must not strand an operator with resources they
/// cannot delete, so deletion stays callable under every containment above. What containment
/// changes is honesty: a non-`succeeded` outcome opens a durable cleanup obligation rather than
/// being reported as done.
pub fn close_deletion(resource_ref: &str, outcome: DeletionOutcome) -> DeletionDisposition {
    let cleanup_obligation_ref = if outcome.opens_obligation() {
        Some(format!(
            "cleanup-obligation://containment/{}/{}",
            outcome.as_str(),
            resource_ref.replace([':', '/'], "_")
        ))
    } else {
        None
    };
    let detail = match outcome {
        DeletionOutcome::Succeeded => {
            "resource observed absent after delete; nothing further is owed".to_string()
        }
        DeletionOutcome::Failed => {
            "delete attempt failed; the resource is presumed live and an obligation is open"
                .to_string()
        }
        DeletionOutcome::Unknown => {
            "delete attempted but absence could not be confirmed; the obligation stays open until \
             the resource is reconciled"
                .to_string()
        }
    };
    DeletionDisposition {
        schema_version: EMERGENCY_CONTAINMENT_SCHEMA_VERSION.to_string(),
        resource_ref: resource_ref.to_string(),
        outcome,
        cleanup_obligation_ref,
        detail,
    }
}

// ---------------------------------------------------------------------------
// 5. Evidence quarantine: retained, but not citable as proof.
// ---------------------------------------------------------------------------

/// Whether a retained evidence artifact may be cited as proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStanding {
    /// Citable as proof of what it measured.
    Authoritative,
    /// Retained for the record, NEVER citable. Quarantine never deletes evidence.
    Quarantined,
}

impl EvidenceStanding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Quarantined => "quarantined_non_authoritative",
        }
    }
}

/// Decide whether an evidence artifact can back a claim.
pub fn evidence_citation(
    evidence_ref: &str,
    standing: EvidenceStanding,
) -> Result<(), ContainmentRefusal> {
    match standing {
        EvidenceStanding::Authoritative => Ok(()),
        EvidenceStanding::Quarantined => Err(ContainmentRefusal::new(
            "evidence_quarantined_non_authoritative",
            format!(
                "{evidence_ref} is retained but quarantined: it asserted more than it measured, \
                 so it cannot be cited as proof"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 1. isolation ---

    #[test]
    fn isolation_required_with_unavailable_substrate_refuses_by_name() {
        let refusal = admit_isolated_execution(
            DeclaredIsolation::VmKernel,
            IsolatedSubstrate::Unavailable,
            ExecutionLocus::Guest,
        )
        .expect_err("must refuse");
        assert_eq!(refusal.reason, "isolation_required_substrate_unavailable");
    }

    #[test]
    fn host_execution_under_declared_isolation_refuses_even_when_substrate_is_live() {
        // A host-executed WorkRun cannot honour a vm_kernel declaration even if a VM happens to
        // be running beside it — the work is still on the host.
        let refusal = admit_isolated_execution(
            DeclaredIsolation::VmKernel,
            IsolatedSubstrate::Live,
            ExecutionLocus::Host,
        )
        .expect_err("must refuse");
        assert_eq!(refusal.reason, "isolation_required_host_execution_refused");
    }

    #[test]
    fn guest_execution_with_live_substrate_is_admitted() {
        assert!(admit_isolated_execution(
            DeclaredIsolation::VmKernel,
            IsolatedSubstrate::Live,
            ExecutionLocus::Guest,
        )
        .is_ok());
    }

    #[test]
    fn process_scoped_environments_may_still_execute_on_the_host() {
        // Containment reduces claims; it does not break honest process-scoped environments.
        assert!(admit_isolated_execution(
            DeclaredIsolation::ProcessScoped,
            IsolatedSubstrate::Unavailable,
            ExecutionLocus::Host,
        )
        .is_ok());
    }

    #[test]
    fn declared_isolation_reads_every_microvm_signal() {
        assert_eq!(
            DeclaredIsolation::from_env_status(&json!({"minimum_isolation": "vm_kernel"})),
            DeclaredIsolation::VmKernel
        );
        assert_eq!(
            DeclaredIsolation::from_env_status(&json!({"substrate": "microvm"})),
            DeclaredIsolation::VmKernel
        );
        assert_eq!(
            DeclaredIsolation::from_env_status(&json!({"isolation_claim": "cross_tenant_capable"})),
            DeclaredIsolation::VmKernel
        );
        assert_eq!(
            DeclaredIsolation::from_env_status(&json!({"substrate": "local"})),
            DeclaredIsolation::ProcessScoped
        );
    }

    #[test]
    fn a_failed_microvm_boot_withdraws_the_vm_kernel_label() {
        assert_eq!(
            truthful_isolation_label(DeclaredIsolation::VmKernel, IsolatedSubstrate::Unavailable),
            "unverified_isolation_declared_vm_kernel_substrate_unavailable"
        );
        assert_eq!(
            truthful_isolation_label(DeclaredIsolation::VmKernel, IsolatedSubstrate::Live),
            "vm_kernel"
        );
    }

    // --- 2. gates ---

    #[test]
    fn every_containment_gate_defaults_off() {
        for (name, default_enabled) in CONTAINMENT_GATES {
            assert!(!default_enabled, "{name} must default OFF");
            assert!(
                unsafe_path_gate(name, None).is_err(),
                "{name} must refuse when unset"
            );
        }
    }

    #[test]
    fn unsafe_path_refuses_when_gate_is_off_and_admits_when_opted_in() {
        let refusal = unsafe_path_gate(UNVERIFIED_WORKSPACE_RESTORE_GATE, None)
            .expect_err("must refuse by default");
        assert_eq!(refusal.reason, "unsafe_path_gate_disabled");
        assert!(refusal.detail.contains(UNVERIFIED_WORKSPACE_RESTORE_GATE));
        assert!(unsafe_path_gate(UNVERIFIED_WORKSPACE_RESTORE_GATE, Some("1")).is_ok());
    }

    #[test]
    fn gate_parsing_treats_falsey_values_as_off() {
        for off in ["", " ", "0", "false", "no", "off", "maybe"] {
            assert!(!gate_enabled(Some(off)), "{off:?} must be OFF");
        }
        for on in ["1", "true", "TRUE", "yes", "on"] {
            assert!(gate_enabled(Some(on)), "{on:?} must be ON");
        }
    }

    #[test]
    fn oversized_guest_declared_transfer_is_refused_by_default() {
        let refusal = admit_guest_transfer_len(u64::MAX, None).expect_err("must refuse");
        assert_eq!(refusal.reason, "guest_declared_transfer_too_large");
        // A sane length still passes with the gate off.
        assert_eq!(admit_guest_transfer_len(4096, None).unwrap(), 4096);
        // The opt-in restores the old behaviour explicitly.
        assert_eq!(
            admit_guest_transfer_len(u64::MAX, Some("1")).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn traversing_and_absolute_cache_paths_are_refused() {
        for escape in ["../../etc", "a/../../b", ".."] {
            let refusal = admit_cache_path(escape).expect_err("must refuse");
            assert_eq!(refusal.reason, "cache_path_escapes_root", "{escape:?}");
        }
        for absolute in ["/root/.ssh", "/etc/passwd"] {
            let refusal = admit_cache_path(absolute).expect_err("must refuse");
            assert_eq!(refusal.reason, "cache_path_not_relative", "{absolute:?}");
        }
        assert!(admit_cache_path("").is_err());
    }

    #[test]
    fn ordinary_relative_cache_paths_still_work() {
        // Containment must not break the legitimate build-cache use case.
        for ok in ["node_modules", "target", ".venv", "a/b/c", "./target"] {
            assert!(admit_cache_path(ok).is_ok(), "{ok:?} must be admitted");
        }
    }

    #[test]
    fn an_unattributed_cache_scope_is_refused() {
        let refusal = admit_cache_scope(None).expect_err("must refuse");
        assert_eq!(refusal.reason, "cache_scope_unattributed");
        assert!(admit_cache_scope(Some("   ")).is_err());
        assert_eq!(admit_cache_scope(Some("system://a")).unwrap(), "system://a");
    }

    // --- 3. admission ---

    #[test]
    fn admission_refuses_when_safe_cleanup_is_unavailable() {
        let refusal = admit_resource_creation("microvm", CleanupCapability::Unavailable)
            .expect_err("must refuse");
        assert_eq!(refusal.reason, "safe_cleanup_unavailable");
        assert!(refusal.detail.contains("microvm"));
    }

    #[test]
    fn admission_proceeds_when_teardown_outcome_is_observed() {
        assert!(
            admit_resource_creation("microvm", CleanupCapability::observed(true, true)).is_ok()
        );
        // A teardown path that exists but discards its outcome is NOT cleanup capability.
        assert_eq!(
            CleanupCapability::observed(true, false),
            CleanupCapability::Unavailable
        );
    }

    // --- 4. CARVE-OUT: deletion ---

    #[test]
    fn deletion_remains_callable_and_returns_each_of_the_three_outcomes() {
        let succeeded = close_deletion("env://a", DeletionOutcome::Succeeded);
        let failed = close_deletion("env://b", DeletionOutcome::Failed);
        let unknown = close_deletion("env://c", DeletionOutcome::Unknown);

        assert_eq!(succeeded.outcome.as_str(), "succeeded");
        assert_eq!(failed.outcome.as_str(), "failed");
        assert_eq!(unknown.outcome.as_str(), "unknown");
    }

    #[test]
    fn non_succeeded_deletions_open_a_durable_obligation() {
        assert!(close_deletion("env://a", DeletionOutcome::Succeeded)
            .cleanup_obligation_ref
            .is_none());
        for outcome in [DeletionOutcome::Failed, DeletionOutcome::Unknown] {
            let disposition = close_deletion("env://b", outcome);
            assert!(
                disposition.cleanup_obligation_ref.is_some(),
                "{outcome:?} must open an obligation"
            );
        }
    }

    #[test]
    fn unknown_is_never_coerced_to_success_or_failure() {
        // A delete call that returned Ok but was never re-observed is UNKNOWN.
        assert_eq!(
            DeletionOutcome::classify(true, false),
            DeletionOutcome::Unknown
        );
        // Only a post-delete absence observation yields success.
        assert_eq!(
            DeletionOutcome::classify(true, true),
            DeletionOutcome::Succeeded
        );
        assert_eq!(
            DeletionOutcome::classify(false, false),
            DeletionOutcome::Failed
        );
        // And even a failed call with proven absence is honestly succeeded.
        assert_eq!(
            DeletionOutcome::classify(false, true),
            DeletionOutcome::Succeeded
        );
    }

    #[test]
    fn deletion_is_not_gated_by_any_containment() {
        // The carve-out in one assertion: nothing in this module can make deletion refuse.
        // close_deletion is total over its input domain and returns a disposition every time.
        for outcome in [
            DeletionOutcome::Succeeded,
            DeletionOutcome::Failed,
            DeletionOutcome::Unknown,
        ] {
            let disposition = close_deletion("provider://vast/instance/1", outcome);
            assert_eq!(disposition.outcome, outcome);
            assert_eq!(
                disposition.schema_version,
                EMERGENCY_CONTAINMENT_SCHEMA_VERSION
            );
            assert_eq!(
                disposition.cleanup_obligation_ref.is_some(),
                outcome != DeletionOutcome::Succeeded
            );
        }
    }

    // --- 5. evidence quarantine ---

    #[test]
    fn quarantined_evidence_cannot_be_cited_as_proof() {
        let refusal = evidence_citation("evidence://vm-boot/phase1", EvidenceStanding::Quarantined)
            .expect_err("must refuse");
        assert_eq!(refusal.reason, "evidence_quarantined_non_authoritative");
        assert!(evidence_citation("evidence://ok", EvidenceStanding::Authoritative).is_ok());
    }

    #[test]
    fn quarantine_is_a_standing_change_not_a_deletion() {
        // Quarantine must be expressible as a status; nothing here removes an artifact.
        assert_eq!(
            EvidenceStanding::Quarantined.as_str(),
            "quarantined_non_authoritative"
        );
    }
}
