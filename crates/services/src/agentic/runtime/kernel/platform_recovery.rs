//! Reference mechanisms for platform restore, mixed-version admission, key
//! rotation, and privacy-safe operability projections.
//!
//! These functions are pure validators/replayers. Plane owners still produce
//! the checkpoint, suffix, key, label, and deployment evidence supplied here.

use std::collections::{BTreeMap, BTreeSet};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::information_flow::INFORMATION_FLOW_LABEL_CONTRACT_ID;
use super::platform_operability::{PlatformOperationClass, PlatformPlane};

pub const PLATFORM_STATE_ROOT_DOMAIN: &str = "ioi.platform-state-root-jcs-sha256.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformRecoveryDenial {
    pub code: &'static str,
    pub message: String,
}

impl PlatformRecoveryDenial {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCheckpoint {
    pub plane: PlatformPlane,
    pub contract_version: u32,
    pub sequence: u64,
    pub entries: BTreeMap<String, String>,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PlatformStateMutation {
    Upsert { key: String, value_hash: String },
    Delete { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSuffixRecord {
    pub sequence: u64,
    pub previous_root: String,
    pub resulting_root: String,
    pub mutation: PlatformStateMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformRecoveryInput {
    pub checkpoint: PlatformCheckpoint,
    pub suffix_records: Vec<PlatformSuffixRecord>,
    pub expected_final_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformRecoveryResult {
    pub plane: PlatformPlane,
    pub contract_version: u32,
    pub restored_through_sequence: u64,
    pub final_state_root: String,
    pub object_count: usize,
}

#[derive(Serialize)]
struct StateRootMaterial<'a> {
    domain: &'static str,
    plane: PlatformPlane,
    contract_version: u32,
    sequence: u64,
    entries: &'a BTreeMap<String, String>,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

pub fn compute_platform_state_root(
    plane: PlatformPlane,
    contract_version: u32,
    sequence: u64,
    entries: &BTreeMap<String, String>,
) -> Result<String, PlatformRecoveryDenial> {
    if contract_version == 0 {
        return Err(PlatformRecoveryDenial::new(
            "platform_checkpoint_contract_version_invalid",
            "checkpoint contract version must be positive",
        ));
    }
    if entries
        .iter()
        .any(|(key, value_hash)| key.trim().is_empty() || !is_sha256(value_hash))
    {
        return Err(PlatformRecoveryDenial::new(
            "platform_checkpoint_entry_invalid",
            "checkpoint entries require non-empty keys and sha256 value hashes",
        ));
    }
    let bytes = serde_jcs::to_vec(&StateRootMaterial {
        domain: PLATFORM_STATE_ROOT_DOMAIN,
        plane,
        contract_version,
        sequence,
        entries,
    })
    .map_err(|error| {
        PlatformRecoveryDenial::new(
            "platform_checkpoint_canonicalization_failed",
            error.to_string(),
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn apply_mutation(
    entries: &mut BTreeMap<String, String>,
    mutation: &PlatformStateMutation,
) -> Result<(), PlatformRecoveryDenial> {
    match mutation {
        PlatformStateMutation::Upsert { key, value_hash } => {
            if key.trim().is_empty() || !is_sha256(value_hash) {
                return Err(PlatformRecoveryDenial::new(
                    "platform_suffix_mutation_invalid",
                    "upsert requires a non-empty key and sha256 value hash",
                ));
            }
            entries.insert(key.clone(), value_hash.clone());
        }
        PlatformStateMutation::Delete { key } => {
            if key.trim().is_empty() {
                return Err(PlatformRecoveryDenial::new(
                    "platform_suffix_mutation_invalid",
                    "delete requires a non-empty key",
                ));
            }
            entries.remove(key);
        }
    }
    Ok(())
}

pub fn replay_platform_checkpoint(
    input: &PlatformRecoveryInput,
) -> Result<PlatformRecoveryResult, PlatformRecoveryDenial> {
    let mut entries = input.checkpoint.entries.clone();
    let mut sequence = input.checkpoint.sequence;
    let mut root = compute_platform_state_root(
        input.checkpoint.plane,
        input.checkpoint.contract_version,
        sequence,
        &entries,
    )?;
    if root != input.checkpoint.state_root {
        return Err(PlatformRecoveryDenial::new(
            "platform_checkpoint_root_mismatch",
            "checkpoint material does not reproduce its declared state root",
        ));
    }

    for record in &input.suffix_records {
        let expected_sequence = sequence.checked_add(1).ok_or_else(|| {
            PlatformRecoveryDenial::new(
                "platform_suffix_sequence_overflow",
                "suffix sequence overflowed",
            )
        })?;
        if record.sequence != expected_sequence {
            return Err(PlatformRecoveryDenial::new(
                "platform_suffix_gap_or_reorder",
                format!(
                    "expected suffix sequence {expected_sequence}, received {}",
                    record.sequence
                ),
            ));
        }
        if record.previous_root != root {
            return Err(PlatformRecoveryDenial::new(
                "platform_suffix_previous_root_mismatch",
                "suffix record does not extend the reconstructed root",
            ));
        }
        apply_mutation(&mut entries, &record.mutation)?;
        sequence = record.sequence;
        root = compute_platform_state_root(
            input.checkpoint.plane,
            input.checkpoint.contract_version,
            sequence,
            &entries,
        )?;
        if record.resulting_root != root {
            return Err(PlatformRecoveryDenial::new(
                "platform_suffix_resulting_root_mismatch",
                "suffix mutation does not reproduce its declared resulting root",
            ));
        }
    }

    if root != input.expected_final_root {
        return Err(PlatformRecoveryDenial::new(
            "platform_recovery_final_root_mismatch",
            "checkpoint plus supplied suffix does not reproduce the expected final root",
        ));
    }

    Ok(PlatformRecoveryResult {
        plane: input.checkpoint.plane,
        contract_version: input.checkpoint.contract_version,
        restored_through_sequence: sequence,
        final_state_root: root,
        object_count: entries.len(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersionRange {
    pub minimum: u32,
    pub maximum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCompatibilityInput {
    pub operation: PlatformOperationClass,
    pub local: SchemaVersionRange,
    pub peer: SchemaVersionRange,
    #[serde(default)]
    pub unknown_consequential_fields_present: bool,
    #[serde(default)]
    pub both_sides_preserve_unknown_fields: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCompatibilityDecision {
    pub selected_version: u32,
    pub mixed_version: bool,
}

fn is_consequential(operation: PlatformOperationClass) -> bool {
    !matches!(
        operation,
        PlatformOperationClass::ProposalOnly
            | PlatformOperationClass::CachedRead
            | PlatformOperationClass::ConsistentRead
    )
}

pub fn negotiate_schema_version(
    input: &SchemaCompatibilityInput,
) -> Result<SchemaCompatibilityDecision, PlatformRecoveryDenial> {
    if input.local.minimum == 0
        || input.peer.minimum == 0
        || input.local.minimum > input.local.maximum
        || input.peer.minimum > input.peer.maximum
    {
        return Err(PlatformRecoveryDenial::new(
            "platform_schema_range_invalid",
            "schema ranges must be positive and ordered",
        ));
    }
    let minimum = input.local.minimum.max(input.peer.minimum);
    let maximum = input.local.maximum.min(input.peer.maximum);
    if minimum > maximum {
        return Err(PlatformRecoveryDenial::new(
            "platform_schema_upgrade_required",
            "no compatible schema version exists",
        ));
    }
    if is_consequential(input.operation)
        && input.unknown_consequential_fields_present
        && !input.both_sides_preserve_unknown_fields
    {
        return Err(PlatformRecoveryDenial::new(
            "platform_schema_lossy_downgrade_forbidden",
            "consequential unknown fields cannot be dropped or guessed",
        ));
    }
    Ok(SchemaCompatibilityDecision {
        selected_version: maximum,
        mixed_version: input.local != input.peer,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformKeyEpochTransition {
    pub current_signing_epoch: u64,
    pub successor_epoch: u64,
    pub successor_published: bool,
    pub distribution_receipt_refs: Vec<String>,
    pub active_signing_epochs: Vec<u64>,
    pub retained_verification_epochs: Vec<u64>,
    pub revocation_snapshot_current: bool,
    #[serde(default)]
    pub revoked_epochs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformKeyEpochDecision {
    pub active_signing_epoch: u64,
    pub retained_verification_epochs: Vec<u64>,
}

pub fn validate_platform_key_epoch_transition(
    transition: &PlatformKeyEpochTransition,
) -> Result<PlatformKeyEpochDecision, PlatformRecoveryDenial> {
    let expected_successor = transition
        .current_signing_epoch
        .checked_add(1)
        .ok_or_else(|| {
            PlatformRecoveryDenial::new("platform_key_epoch_overflow", "key epoch overflowed")
        })?;
    if transition.successor_epoch != expected_successor {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_epoch_not_monotonic",
            "successor key epoch must be exactly current epoch plus one",
        ));
    }
    if !transition.successor_published || transition.distribution_receipt_refs.is_empty() {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_successor_not_distributed",
            "successor key material must be published and distribution receipted",
        ));
    }
    let active = transition
        .active_signing_epochs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if active.len() != 1 || !active.contains(&transition.successor_epoch) {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_signing_epoch_ambiguous",
            "exactly the successor epoch may retain signing authority",
        ));
    }
    if !transition.revocation_snapshot_current {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_revocation_state_stale",
            "current revocation state is required before key activation",
        ));
    }
    if transition
        .revoked_epochs
        .iter()
        .any(|epoch| active.contains(epoch))
    {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_revoked_epoch_active",
            "a revoked epoch cannot sign",
        ));
    }
    let retained = transition
        .retained_verification_epochs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if !retained.contains(&transition.current_signing_epoch)
        || !retained.contains(&transition.successor_epoch)
    {
        return Err(PlatformRecoveryDenial::new(
            "platform_key_verification_window_incomplete",
            "current and successor verification material must be retained",
        ));
    }
    Ok(PlatformKeyEpochDecision {
        active_signing_epoch: transition.successor_epoch,
        retained_verification_epochs: retained.into_iter().collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityFieldCandidate {
    pub field_name: String,
    pub allowlisted: bool,
    #[serde(default)]
    pub raw_value: Option<Value>,
    #[serde(default)]
    pub value_hash: Option<String>,
    #[serde(default)]
    pub value_ref: Option<String>,
    pub information_flow_label: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityFieldProjection {
    pub field_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_ref: Option<String>,
    pub label_ref: String,
    pub label_content_hash: String,
}

fn label_str<'a>(label: &'a Value, pointer: &str) -> Option<&'a str> {
    label.pointer(pointer).and_then(Value::as_str)
}

pub fn admit_privacy_safe_observability(
    candidates: &[ObservabilityFieldCandidate],
) -> Result<Vec<ObservabilityFieldProjection>, PlatformRecoveryDenial> {
    let mut names = BTreeSet::new();
    let mut projections = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.field_name.trim().is_empty() || !names.insert(candidate.field_name.clone()) {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_field_invalid",
                "observability field names must be non-empty and unique",
            ));
        }
        if !candidate.allowlisted {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_field_not_allowlisted",
                format!("field {} is not allowlisted", candidate.field_name),
            ));
        }
        validate_architecture_contract(
            INFORMATION_FLOW_LABEL_CONTRACT_ID,
            &candidate.information_flow_label,
        )
        .map_err(|error| {
            PlatformRecoveryDenial::new("platform_observability_label_invalid", error.to_string())
        })?;
        let confidentiality = label_str(&candidate.information_flow_label, "/confidentiality")
            .ok_or_else(|| {
                PlatformRecoveryDenial::new(
                    "platform_observability_label_invalid",
                    "information-flow confidentiality is missing",
                )
            })?;
        let protected = matches!(confidentiality, "confidential" | "private" | "restricted");
        if confidentiality == "unknown" {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_unknown_label",
                "unknown confidentiality cannot enter observability",
            ));
        }
        if protected && candidate.raw_value.is_some() {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_protected_raw_value_forbidden",
                "protected observability fields may carry only governed refs or hashes",
            ));
        }
        if protected
            && candidate
                .value_hash
                .as_deref()
                .is_none_or(|value| !is_sha256(value))
            && candidate
                .value_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_protected_evidence_missing",
                "protected observability fields require a governed ref or sha256 hash",
            ));
        }
        if candidate
            .value_hash
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
        {
            return Err(PlatformRecoveryDenial::new(
                "platform_observability_hash_invalid",
                "observability value hash must use sha256",
            ));
        }
        projections.push(ObservabilityFieldProjection {
            field_name: candidate.field_name.clone(),
            raw_value: candidate.raw_value.clone(),
            value_hash: candidate.value_hash.clone(),
            value_ref: candidate.value_ref.clone(),
            label_ref: label_str(&candidate.information_flow_label, "/label_ref")
                .unwrap_or_default()
                .to_string(),
            label_content_hash: label_str(&candidate.information_flow_label, "/content_hash")
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(projections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hash(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn suffix_record(
        checkpoint: &PlatformCheckpoint,
        current_entries: &mut BTreeMap<String, String>,
        current_sequence: u64,
        previous_root: String,
        mutation: PlatformStateMutation,
    ) -> PlatformSuffixRecord {
        apply_mutation(current_entries, &mutation).expect("valid mutation");
        let sequence = current_sequence + 1;
        let resulting_root = compute_platform_state_root(
            checkpoint.plane,
            checkpoint.contract_version,
            sequence,
            current_entries,
        )
        .expect("root");
        PlatformSuffixRecord {
            sequence,
            previous_root,
            resulting_root,
            mutation,
        }
    }

    #[test]
    fn checkpoint_plus_suffix_reproduces_exact_final_root() {
        let mut entries = BTreeMap::from([("goal/a".to_string(), hash('a'))]);
        let checkpoint_root =
            compute_platform_state_root(PlatformPlane::Agentgres, 2, 4, &entries).unwrap();
        let checkpoint = PlatformCheckpoint {
            plane: PlatformPlane::Agentgres,
            contract_version: 2,
            sequence: 4,
            entries: entries.clone(),
            state_root: checkpoint_root.clone(),
        };
        let first = suffix_record(
            &checkpoint,
            &mut entries,
            4,
            checkpoint_root,
            PlatformStateMutation::Upsert {
                key: "goal/b".to_string(),
                value_hash: hash('b'),
            },
        );
        let second = suffix_record(
            &checkpoint,
            &mut entries,
            5,
            first.resulting_root.clone(),
            PlatformStateMutation::Delete {
                key: "goal/a".to_string(),
            },
        );
        let result = replay_platform_checkpoint(&PlatformRecoveryInput {
            checkpoint,
            suffix_records: vec![first, second.clone()],
            expected_final_root: second.resulting_root,
        })
        .expect("exact recovery");
        assert_eq!(result.restored_through_sequence, 6);
        assert_eq!(result.object_count, 1);
    }

    #[test]
    fn missing_or_tampered_suffix_fails_closed() {
        let entries = BTreeMap::from([("goal/a".to_string(), hash('a'))]);
        let checkpoint_root =
            compute_platform_state_root(PlatformPlane::Agentgres, 2, 4, &entries).unwrap();
        let checkpoint = PlatformCheckpoint {
            plane: PlatformPlane::Agentgres,
            contract_version: 2,
            sequence: 4,
            entries,
            state_root: checkpoint_root,
        };
        let error = replay_platform_checkpoint(&PlatformRecoveryInput {
            checkpoint,
            suffix_records: vec![PlatformSuffixRecord {
                sequence: 6,
                previous_root: hash('c'),
                resulting_root: hash('d'),
                mutation: PlatformStateMutation::Delete {
                    key: "goal/a".to_string(),
                },
            }],
            expected_final_root: hash('e'),
        })
        .unwrap_err();
        assert_eq!(error.code, "platform_suffix_gap_or_reorder");
    }

    #[test]
    fn mixed_versions_select_highest_overlap_or_require_upgrade() {
        let decision = negotiate_schema_version(&SchemaCompatibilityInput {
            operation: PlatformOperationClass::ConsistentRead,
            local: SchemaVersionRange {
                minimum: 1,
                maximum: 3,
            },
            peer: SchemaVersionRange {
                minimum: 2,
                maximum: 4,
            },
            unknown_consequential_fields_present: false,
            both_sides_preserve_unknown_fields: false,
        })
        .unwrap();
        assert_eq!(decision.selected_version, 3);
        assert!(decision.mixed_version);

        let error = negotiate_schema_version(&SchemaCompatibilityInput {
            operation: PlatformOperationClass::TruthMutation,
            local: SchemaVersionRange {
                minimum: 1,
                maximum: 1,
            },
            peer: SchemaVersionRange {
                minimum: 2,
                maximum: 3,
            },
            unknown_consequential_fields_present: false,
            both_sides_preserve_unknown_fields: false,
        })
        .unwrap_err();
        assert_eq!(error.code, "platform_schema_upgrade_required");
    }

    #[test]
    fn consequential_lossy_downgrade_is_forbidden() {
        let error = negotiate_schema_version(&SchemaCompatibilityInput {
            operation: PlatformOperationClass::ExternalEffect,
            local: SchemaVersionRange {
                minimum: 1,
                maximum: 2,
            },
            peer: SchemaVersionRange {
                minimum: 1,
                maximum: 1,
            },
            unknown_consequential_fields_present: true,
            both_sides_preserve_unknown_fields: false,
        })
        .unwrap_err();
        assert_eq!(error.code, "platform_schema_lossy_downgrade_forbidden");
    }

    #[test]
    fn key_rotation_has_one_signer_and_retains_verification() {
        let decision = validate_platform_key_epoch_transition(&PlatformKeyEpochTransition {
            current_signing_epoch: 7,
            successor_epoch: 8,
            successor_published: true,
            distribution_receipt_refs: vec!["receipt://key-distribution/8".to_string()],
            active_signing_epochs: vec![8],
            retained_verification_epochs: vec![7, 8],
            revocation_snapshot_current: true,
            revoked_epochs: vec![],
        })
        .unwrap();
        assert_eq!(decision.active_signing_epoch, 8);

        let error = validate_platform_key_epoch_transition(&PlatformKeyEpochTransition {
            current_signing_epoch: 7,
            successor_epoch: 8,
            successor_published: true,
            distribution_receipt_refs: vec!["receipt://key-distribution/8".to_string()],
            active_signing_epochs: vec![7, 8],
            retained_verification_epochs: vec![7, 8],
            revocation_snapshot_current: true,
            revoked_epochs: vec![],
        })
        .unwrap_err();
        assert_eq!(error.code, "platform_key_signing_epoch_ambiguous");
    }

    #[test]
    fn protected_observability_is_ref_or_hash_only() {
        let private_label: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/information-flow-label-v1/positive-private-untrusted.json"
        )))
        .unwrap();
        let error = admit_privacy_safe_observability(&[ObservabilityFieldCandidate {
            field_name: "prompt".to_string(),
            allowlisted: true,
            raw_value: Some(json!("secret customer prompt")),
            value_hash: None,
            value_ref: None,
            information_flow_label: private_label.clone(),
        }])
        .unwrap_err();
        assert_eq!(
            error.code,
            "platform_observability_protected_raw_value_forbidden"
        );

        let projection = admit_privacy_safe_observability(&[ObservabilityFieldCandidate {
            field_name: "prompt_hash".to_string(),
            allowlisted: true,
            raw_value: None,
            value_hash: Some(hash('f')),
            value_ref: Some("artifact://protected-observation/1".to_string()),
            information_flow_label: private_label,
        }])
        .unwrap();
        assert_eq!(projection.len(), 1);
        assert!(projection[0].raw_value.is_none());
    }
}
