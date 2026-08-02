//! Canonical ref branding for admitted Agentgres facts.
//!
//! A scheme is not provenance: an `agentgres://` (or Agentgres-derived
//! `receipt://` / `commitment://`) string proves nothing by itself, and until
//! 2026-08-01 the schemes were minted by `format!` at dozens of consumer
//! sites. The enforced boundary (owner ruling, same date) is that ONLY this
//! crate constructs them: consumers call these constructors, and the
//! `check-agentgres-ref-minting` ratchet fails any new construction site
//! outside `crates/agentgres`.
//!
//! Coordinate provenance is the caller's obligation and is documented per
//! constructor: coordinates must come from admitted engine facts — an
//! `AdmitAck`, an `ExactProjection`, a replay walk over admitted records, or
//! a validated expected head — never from caller-supplied candidates. The
//! interim self-minted runtime planes (`agentgres://runtime-events/...`,
//! `agentgres://runtime-state/...`) are NOT constructed here; they are
//! ratchet-pinned debt owned by m5-agentgres-durable-event-subscription-
//! successor and shrink toward this module as each family is re-homed.

fn strip_sha(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

/// Receipt ref for one admitted outcome-room-system batch. `batch_seq` and
/// `root` come from the admitting `AdmitAck` / `ExactProjection`
/// (`admission_batch_seq`, `admission_root`) or a replay walk over admitted
/// batch-root records.
pub fn outcome_room_system_receipt_ref(room_tail: &str, batch_seq: u64, root: &str) -> String {
    format!(
        "receipt://agentgres/outcome-room-system/{room_tail}/batch/{batch_seq}/{}",
        strip_sha(root)
    )
}

/// Operation ref for one admitted outcome-room-system operation. `sequence`
/// and `head` come from the admitted fact (`ExactProjection::seq` / `head`).
pub fn outcome_room_system_operation_ref(room_tail: &str, sequence: u64, head: &str) -> String {
    format!("agentgres://operation/outcome-room-system/{room_tail}/sequence/{sequence}/head/{head}")
}

/// Transition-commitment ref for one admitted outcome-room-system head.
/// `head` comes from the admitted fact or a validated expected head.
pub fn outcome_room_system_transition_ref(room_tail: &str, head: &str) -> String {
    format!(
        "commitment://agentgres/outcome-room-system/{room_tail}/head/{}",
        strip_sha(head)
    )
}

/// Storage object ref for one room's outcome-room-system operations domain —
/// the object identity operations are admitted under and replayed from.
pub fn outcome_room_system_object_ref(room_tail: &str) -> String {
    format!("agentgres://outcome-room-system-operations/{room_tail}")
}

// --- generic owner-namespaced event streams ---------------------------------
//
// These constructors are deliberately namespace-GENERIC: they take the owner's
// namespace as data and brand identically for every owner. Nothing here
// branches on a namespace value, and no consumer vocabulary appears — that
// genericity is what the >= 2-owner-namespace proof asserts.

/// Agentgres domain for one owner-namespaced event stream.
pub fn event_stream_domain(owner_namespace: &str, stream_tail: &str) -> String {
    format!("event-stream-operations.{owner_namespace}.{stream_tail}")
}

/// Storage object ref for one owner-namespaced event stream's operations.
pub fn event_stream_object_ref(owner_namespace: &str, stream_tail: &str) -> String {
    format!("agentgres://event-stream-operations/{owner_namespace}/{stream_tail}")
}

/// Operation ref for one admitted event append. `sequence` and `head` come
/// from the admitted fact (`ExactProjection::seq` / `head`).
pub fn event_stream_operation_ref(
    owner_namespace: &str,
    stream_tail: &str,
    sequence: u64,
    head: &str,
) -> String {
    format!(
        "agentgres://operation/event-stream/{owner_namespace}/{stream_tail}/sequence/{sequence}/head/{head}"
    )
}

/// Receipt ref for one admitted event-stream batch. `batch_seq` and `root`
/// come from the admitting ack / `ExactProjection`.
pub fn event_stream_receipt_ref(
    owner_namespace: &str,
    stream_tail: &str,
    batch_seq: u64,
    root: &str,
) -> String {
    format!(
        "receipt://agentgres/event-stream/{owner_namespace}/{stream_tail}/batch/{batch_seq}/{}",
        strip_sha(root)
    )
}

/// Subscription-lease operation ref for one admitted lease transition or
/// checkpoint advance.
pub fn subscription_lease_operation_ref(lease_tail: &str, sequence: u64, head: &str) -> String {
    format!("agentgres://operation/subscription-lease/{lease_tail}/sequence/{sequence}/head/{head}")
}

/// Receipt ref for one admitted subscription-lease batch.
pub fn subscription_lease_receipt_ref(lease_tail: &str, batch_seq: u64, root: &str) -> String {
    format!(
        "receipt://agentgres/subscription-lease/{lease_tail}/batch/{batch_seq}/{}",
        strip_sha(root)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-format compatibility is load-bearing: these strings appear in
    // admitted room records, retained evidence, and the certified M4 proof
    // logs. The golden values below are copied verbatim from the route-local
    // formatters this module replaced; a change here is a migration, not a
    // refactor.
    #[test]
    fn ref_formats_are_byte_identical_to_the_retired_route_formatters() {
        assert_eq!(
            outcome_room_system_receipt_ref("or_abc", 4, "sha256:deadbeef"),
            "receipt://agentgres/outcome-room-system/or_abc/batch/4/deadbeef"
        );
        assert_eq!(
            outcome_room_system_receipt_ref("or_abc", 4, "deadbeef"),
            "receipt://agentgres/outcome-room-system/or_abc/batch/4/deadbeef"
        );
        assert_eq!(
            outcome_room_system_operation_ref("or_abc", 7, "sha256:beef"),
            "agentgres://operation/outcome-room-system/or_abc/sequence/7/head/sha256:beef"
        );
        assert_eq!(
            outcome_room_system_transition_ref("or_abc", "sha256:beef"),
            "commitment://agentgres/outcome-room-system/or_abc/head/beef"
        );
        assert_eq!(
            outcome_room_system_object_ref("or_abc"),
            "agentgres://outcome-room-system-operations/or_abc"
        );
    }

    // Genericity is a property of the CONSTRUCTORS, not only of the runtime:
    // two unrelated owner namespaces must brand through identical structure
    // with the namespace carried as data. A constructor that special-cased a
    // namespace would show up here as an asymmetry.
    #[test]
    fn event_stream_refs_are_namespace_generic() {
        for ns in ["thread-orchestration", "automation-scheduler"] {
            assert_eq!(
                event_stream_domain(ns, "s1"),
                format!("event-stream-operations.{ns}.s1")
            );
            assert_eq!(
                event_stream_object_ref(ns, "s1"),
                format!("agentgres://event-stream-operations/{ns}/s1")
            );
            assert_eq!(
                event_stream_operation_ref(ns, "s1", 4, "sha256:beef"),
                format!("agentgres://operation/event-stream/{ns}/s1/sequence/4/head/sha256:beef")
            );
            assert_eq!(
                event_stream_receipt_ref(ns, "s1", 2, "sha256:feed"),
                format!("receipt://agentgres/event-stream/{ns}/s1/batch/2/feed")
            );
        }
        assert_eq!(
            subscription_lease_operation_ref("sub_1", 3, "sha256:cafe"),
            "agentgres://operation/subscription-lease/sub_1/sequence/3/head/sha256:cafe"
        );
        assert_eq!(
            subscription_lease_receipt_ref("sub_1", 1, "sha256:dead"),
            "receipt://agentgres/subscription-lease/sub_1/batch/1/dead"
        );
    }
}
