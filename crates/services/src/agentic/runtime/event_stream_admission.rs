//! The injection boundary for event-stream admission.
//!
//! The runtime side of the estate cannot open the substrate writer: the
//! handle steward lives in the daemon, and `agentgres::event_stream` exposes
//! no way to acquire a handle. So the daemon INJECTS an admission capability
//! here at boot, and runtime writers admit through it.
//!
//! This boundary FAILS CLOSED. When no capability has been installed, every
//! accessor refuses with `AdmissionRefusal::CapabilityAbsent`, and there is
//! no path from that refusal to the legacy append-only event log. That is the
//! whole point: a wiring gap must be loud. If an un-injected build quietly
//! reverted to JSONL, the substrate would decay back to the spine this cut
//! replaced — not by anyone's decision, but through a boot path nobody
//! noticed, with every bar still green.
//!
//! `agentgres` is a TYPES-ONLY dependency of this crate. Nothing here
//! redefines the capability, the request shape, or the refusal vocabulary;
//! a local redefinition would be the shared-definition drift class
//! reappearing one layer down.

use agentgres::event_stream::{AdmissionRefusal, EventAdmission, EventStreamAdmission};
use agentgres::mux::ExactProjection;
use std::sync::{Arc, OnceLock};

static CAPABILITY: OnceLock<Arc<dyn EventStreamAdmission>> = OnceLock::new();

/// Install the process's admission capability. Called once by the daemon at
/// boot. A second install is refused rather than silently ignored: two
/// capabilities in one process would mean two stewards, which is the exact
/// condition the library's signature-only core exists to prevent.
pub fn install(capability: Arc<dyn EventStreamAdmission>) -> Result<(), &'static str> {
    CAPABILITY
        .set(capability)
        .map_err(|_| "an event-stream admission capability is already installed in this process")
}

/// True when a capability has been injected. Read by diagnostics only —
/// callers must not branch to a different store on `false`.
pub fn is_installed() -> bool {
    CAPABILITY.get().is_some()
}

/// The installed capability, or the fail-closed refusal.
pub fn capability() -> Result<&'static Arc<dyn EventStreamAdmission>, AdmissionRefusal> {
    CAPABILITY.get().ok_or(AdmissionRefusal::CapabilityAbsent)
}

/// Admit one event through the injected capability.
///
/// This is the production entry point for runtime-side event admission. The
/// un-injected proof drives a real write through THIS function rather than
/// calling `capability()` directly, because a test that reconstructs the call
/// path re-supplies the wiring the same way a fixture re-supplies the input
/// set — and would keep passing while production routed around the boundary
/// entirely.
pub fn admit_event(request: EventAdmission<'_>) -> Result<ExactProjection, AdmissionRefusal> {
    capability()?.admit_event(request)
}

/// Read one stream's exact admitted head through the injected capability.
pub fn read_head(
    owner_namespace: &str,
    stream_tail: &str,
) -> Result<Option<ExactProjection>, AdmissionRefusal> {
    capability()?.read_head(owner_namespace, stream_tail)
}

/// The owner namespace thread orchestration admits under.
///
/// It is a VALUE, not a branch. Nothing in the substrate reads it and behaves
/// differently; a second owner (`automation-scheduler`) traverses identical
/// code, which is what the two-namespace proof asserts.
pub const THREAD_ORCHESTRATION_NAMESPACE: &str = "thread-orchestration";

/// The successor record that owns migrating pre-existing legacy streams.
/// Named in the refusal so the refusal points at its own remedy.
pub const LEGACY_STREAM_MIGRATION_SUCCESSOR: &str =
    "m5-thread-event-legacy-stream-migration-successor";

/// Derive the canonical Agentgres stream tail for one event stream id.
///
/// Event stream ids carry a colon (`thr_abc:events`), which is not a
/// canonical coordinate component. The digest is the mapping the estate
/// ALREADY uses for this identifier — the legacy log names its file
/// `sha256(event_stream_id).jsonl` — so re-homing introduces no second naming
/// scheme, and the original id travels in the admitted payload.
pub fn stream_tail(event_stream_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(event_stream_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Where one stream's truth lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHoming {
    /// The stream has pre-existing append-only history. Writes are REFUSED
    /// and pointed at the migration successor; the history is never
    /// recomputed and never silently continued on a new spine.
    Legacy,
    /// The stream has no legacy history and admits through Agentgres.
    Admitted,
}

/// Classify one stream before dispatching a write.
///
/// Classification is dispatch on a DETERMINED FACT — does legacy history
/// exist for these coordinates — and never on a failure. That distinction is
/// the whole difference between this and a fallback: no error on either path
/// can change which path was taken, so a broken substrate surfaces as a
/// refusal rather than as a quiet write to the old log.
pub fn classify_stream(state_dir: &str, event_stream_id: &str) -> StreamHoming {
    let path = std::path::Path::new(state_dir)
        .join("events")
        .join(format!("{}.jsonl", stream_tail(event_stream_id)));
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => StreamHoming::Legacy,
        _ => StreamHoming::Admitted,
    }
}

/// The refusal a legacy stream's write receives.
pub fn unmigrated_refusal(event_stream_id: &str) -> String {
    format!(
        "event stream {event_stream_id} still has pre-Agentgres history; \
         migrating it is owned by {LEGACY_STREAM_MIGRATION_SUCCESSOR} and this \
         write is refused rather than continued on the legacy spine"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fail-closed boundary, exercised through the production entry point.
    //
    // This test is only meaningful in a process where no capability has been
    // installed, which is exactly the state of a unit-test binary — and
    // exactly the state of a daemon whose boot wiring was dropped. It asserts
    // the refusal SURFACES from a real admission attempt, not that a refusal
    // function returns a refusal when called.
    #[test]
    fn an_uninjected_process_refuses_and_never_falls_back() {
        assert!(!is_installed(), "unit-test process must start un-injected");
        let payload = serde_json::Value::Null;
        let refusal = admit_event(EventAdmission {
            owner_namespace: "thread-orchestration",
            stream_tail: "t1",
            op_kind: "event_stream.append",
            expected_head: None,
            payload: &payload,
            recorded_at_ms: 0,
            idem_key: "k1",
        })
        .expect_err("an un-injected boundary must refuse, never fall back");
        assert_eq!(refusal, AdmissionRefusal::CapabilityAbsent);
        assert_eq!(refusal.code(), "event_stream_admission_capability_absent");

        let read = read_head("thread-orchestration", "t1")
            .expect_err("reads must refuse too; a read fallback is a fallback");
        assert_eq!(read, AdmissionRefusal::CapabilityAbsent);
    }
}
