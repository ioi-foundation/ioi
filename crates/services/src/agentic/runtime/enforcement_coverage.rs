//! Admission and operability lifecycle for immutable enforcement-coverage snapshots.
//!
//! The registered `EnforcementCoverageDeclaration` contract describes evidence; it does not
//! become runtime truth merely because it deserializes. This owner keeps exact JCS bytes bound to
//! an artifact ref and SHA-256 digest, tracks an explicit logical head, records revocation without
//! rewriting an admitted snapshot, and resolves coverage only against exact subject/scope and
//! evidence requirements. The store is deliberately in-memory. Its deterministic export/restore
//! seam supports callers that own durable storage without this module claiming daemon durability.

use std::collections::BTreeMap;

use ioi_types::app::generated::architecture_contracts::EnforcementCoverageDeclarationV1;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const ARTIFACT_PREFIX: &str = "artifact://";
const HASH_PREFIX: &str = "sha256:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementCoverageError {
    pub code: &'static str,
    pub message: String,
}

impl EnforcementCoverageError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EnforcementCoverageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for EnforcementCoverageError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementCoverageAdmissionRequest {
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    pub declaration: Value,
    pub expected_previous_hash: Option<String>,
    pub evidence_receipt_ref: String,
    pub admitted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementCoverageSnapshot {
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    /// Exact RFC 8785/JCS bytes whose digest is `declaration_content_hash`.
    pub canonical_jcs: Vec<u8>,
    pub declaration: Value,
    pub evidence_receipt_ref: String,
    pub admitted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementCoverageRevocation {
    pub declaration_id: String,
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    pub revocation_receipt_ref: String,
    pub reason: String,
    pub revoked_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementCoverageRevocationRequest {
    pub declaration_id: String,
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    pub revocation_receipt_ref: String,
    pub reason: String,
    pub revoked_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementCoverageEvidenceRequirement {
    Verification,
    VerificationAndReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementCoverageClaim {
    Discovered,
    Observable,
    Attributable,
    Mediated,
    Preventable,
    Receipted,
}

impl EnforcementCoverageClaim {
    fn field(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Observable => "observable",
            Self::Attributable => "attributable",
            Self::Mediated => "mediated",
            Self::Preventable => "preventable",
            Self::Receipted => "receipted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementCoverageRequirement {
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    pub subject_kind: String,
    pub profile_or_adapter_ref: String,
    pub subject_version: String,
    pub subject_content_hash: String,
    pub surface: String,
    pub action_class: String,
    pub boundary: String,
    pub scope_ref: String,
    pub required_operating_mode: Option<String>,
    pub required_claims: Vec<EnforcementCoverageClaim>,
    pub evidence_requirement: EnforcementCoverageEvidenceRequirement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementCoverageCurrentness {
    Current,
    Superseded,
    Revoked,
    Expired,
    Stale,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementCoverageOperabilityEntry {
    pub declaration_id: String,
    pub declaration_artifact_ref: String,
    pub declaration_content_hash: String,
    pub is_logical_head: bool,
    pub currentness: EnforcementCoverageCurrentness,
    pub operable: bool,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEnforcementCoverage {
    pub operability: EnforcementCoverageOperabilityEntry,
    pub declaration: Value,
    pub evidence_receipt_ref: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementCoverageRegistry {
    snapshots_by_hash: BTreeMap<String, EnforcementCoverageSnapshot>,
    hash_by_artifact_ref: BTreeMap<String, String>,
    head_by_declaration_id: BTreeMap<String, String>,
    revocations_by_hash: BTreeMap<String, EnforcementCoverageRevocation>,
}

fn canonical_hash(value: &Value) -> Result<(Vec<u8>, String), EnforcementCoverageError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        EnforcementCoverageError::new(
            "enforcement_coverage_canonicalization_failed",
            error.to_string(),
        )
    })?;
    let digest = format!("{HASH_PREFIX}{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn validate_artifact_ref(reference: &str) -> Result<(), EnforcementCoverageError> {
    if !reference.starts_with(ARTIFACT_PREFIX)
        || reference.len() <= ARTIFACT_PREFIX.len()
        || reference.chars().any(char::is_whitespace)
    {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_artifact_ref_invalid",
            "declaration_artifact_ref must be an exact artifact:// reference",
        ));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), EnforcementCoverageError> {
    let Some(tail) = hash.strip_prefix(HASH_PREFIX) else {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_hash_invalid",
            "declaration_content_hash must be sha256:<64 lowercase hex>",
        ));
    };
    if tail.len() != 64
        || !tail
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_hash_invalid",
            "declaration_content_hash must be sha256:<64 lowercase hex>",
        ));
    }
    Ok(())
}

fn validate_receipt_ref(reference: &str) -> Result<(), EnforcementCoverageError> {
    if !reference.starts_with("receipt://")
        || reference.len() <= "receipt://".len()
        || reference.chars().any(char::is_whitespace)
    {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_receipt_ref_invalid",
            "lifecycle receipts must be exact receipt:// references",
        ));
    }
    Ok(())
}

fn validate_time(
    value: &str,
    code: &'static str,
) -> Result<OffsetDateTime, EnforcementCoverageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| EnforcementCoverageError::new(code, error.to_string()))
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn validate_portable_invariants(value: &Value) -> Result<(), EnforcementCoverageError> {
    if value.pointer("/claims/receipted") == Some(&Value::Bool(true))
        && !value
            .pointer("/receipt/evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| !refs.is_empty())
    {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_invariant_failed",
            "enforcement_coverage.receipt.evidence.required_when_receipted",
        ));
    }
    if value.pointer("/claims/uncovered") == Some(&Value::Bool(true))
        && !value
            .pointer("/known_gaps")
            .and_then(Value::as_array)
            .is_some_and(|gaps| !gaps.is_empty())
    {
        return Err(EnforcementCoverageError::new(
            "enforcement_coverage_invariant_failed",
            "enforcement_coverage.gap.required_when_uncovered",
        ));
    }
    Ok(())
}

impl EnforcementCoverageRegistry {
    pub fn admit(
        &mut self,
        request: EnforcementCoverageAdmissionRequest,
        now_ms: i64,
    ) -> Result<EnforcementCoverageOperabilityEntry, EnforcementCoverageError> {
        validate_artifact_ref(&request.declaration_artifact_ref)?;
        validate_hash(&request.declaration_content_hash)?;
        validate_receipt_ref(&request.evidence_receipt_ref)?;
        let admitted_at = validate_time(
            &request.admitted_at,
            "enforcement_coverage_admitted_at_invalid",
        )?;
        let now_nanos = i128::from(now_ms).saturating_mul(1_000_000);
        if admitted_at.unix_timestamp_nanos() > now_nanos {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_admitted_at_future",
                "admitted_at cannot be later than the owner-supplied current time",
            ));
        }

        let typed: EnforcementCoverageDeclarationV1 =
            serde_json::from_value(request.declaration.clone()).map_err(|error| {
                EnforcementCoverageError::new(
                    "enforcement_coverage_contract_invalid",
                    error.to_string(),
                )
            })?;
        let declaration = serde_json::to_value(typed).map_err(|error| {
            EnforcementCoverageError::new(
                "enforcement_coverage_projection_failed",
                error.to_string(),
            )
        })?;
        if declaration != request.declaration {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_projection_mismatch",
                "generated contract projection changed the supplied declaration",
            ));
        }
        validate_portable_invariants(&declaration)?;
        let (canonical_jcs, computed_hash) = canonical_hash(&declaration)?;
        if computed_hash != request.declaration_content_hash {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_hash_mismatch",
                format!(
                    "supplied hash {} does not bind the exact JCS bytes ({computed_hash})",
                    request.declaration_content_hash
                ),
            ));
        }
        let declaration_id = string_at(&declaration, "/declaration_id")
            .expect("generated contract requires declaration_id")
            .to_string();

        if let Some(existing_hash) = self
            .hash_by_artifact_ref
            .get(&request.declaration_artifact_ref)
        {
            if existing_hash != &computed_hash {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_artifact_collision",
                    "artifact ref is already bound to different declaration bytes",
                ));
            }
        }
        if let Some(existing) = self.snapshots_by_hash.get(&computed_hash) {
            if existing.declaration_artifact_ref != request.declaration_artifact_ref
                || existing.declaration != declaration
                || existing.canonical_jcs != canonical_jcs
                || existing.evidence_receipt_ref != request.evidence_receipt_ref
                || existing.admitted_at != request.admitted_at
            {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_snapshot_collision",
                    "content hash is already retained with different declaration or admission coordinates",
                ));
            }
            return Ok(self.operability_for_hash(&computed_hash, now_ms));
        }

        let current_head = self.head_by_declaration_id.get(&declaration_id).cloned();
        if current_head != request.expected_previous_hash {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_stale_head",
                format!(
                    "expected previous hash {:?} does not match current logical head {:?}",
                    request.expected_previous_hash, current_head
                ),
            ));
        }
        if let Some(current_head_hash) = &current_head {
            let previous = self
                .snapshots_by_hash
                .get(current_head_hash)
                .expect("logical heads always reference retained snapshots");
            let previous_admitted_at = validate_time(
                &previous.admitted_at,
                "enforcement_coverage_admitted_at_invalid",
            )?;
            if admitted_at < previous_admitted_at {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_admission_time_regressed",
                    "a successor snapshot cannot predate its exact logical predecessor",
                ));
            }
        }

        let snapshot = EnforcementCoverageSnapshot {
            declaration_artifact_ref: request.declaration_artifact_ref.clone(),
            declaration_content_hash: computed_hash.clone(),
            canonical_jcs,
            declaration,
            evidence_receipt_ref: request.evidence_receipt_ref,
            admitted_at: request.admitted_at,
        };
        self.hash_by_artifact_ref
            .insert(request.declaration_artifact_ref, computed_hash.clone());
        self.snapshots_by_hash
            .insert(computed_hash.clone(), snapshot);
        self.head_by_declaration_id
            .insert(declaration_id, computed_hash.clone());
        Ok(self.operability_for_hash(&computed_hash, now_ms))
    }

    pub fn revoke(
        &mut self,
        request: EnforcementCoverageRevocationRequest,
        now_ms: i64,
    ) -> Result<EnforcementCoverageOperabilityEntry, EnforcementCoverageError> {
        validate_artifact_ref(&request.declaration_artifact_ref)?;
        validate_hash(&request.declaration_content_hash)?;
        validate_receipt_ref(&request.revocation_receipt_ref)?;
        let revoked_at = validate_time(
            &request.revoked_at,
            "enforcement_coverage_revoked_at_invalid",
        )?;
        let now_nanos = i128::from(now_ms).saturating_mul(1_000_000);
        if revoked_at.unix_timestamp_nanos() > now_nanos {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_revoked_at_future",
                "revoked_at cannot be later than the owner-supplied current time",
            ));
        }
        if request.reason.trim().is_empty() {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_revocation_reason_required",
                "revocation requires a nonblank reason",
            ));
        }
        let snapshot = self
            .snapshots_by_hash
            .get(&request.declaration_content_hash)
            .ok_or_else(|| {
                EnforcementCoverageError::new(
                    "enforcement_coverage_snapshot_missing",
                    "the exact declaration hash is not admitted",
                )
            })?;
        if snapshot.declaration_artifact_ref != request.declaration_artifact_ref
            || string_at(&snapshot.declaration, "/declaration_id")
                != Some(request.declaration_id.as_str())
        {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_revocation_binding_mismatch",
                "revocation coordinates do not bind the admitted snapshot",
            ));
        }
        let admitted_at = validate_time(
            &snapshot.admitted_at,
            "enforcement_coverage_admitted_at_invalid",
        )?;
        if revoked_at < admitted_at {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_revoked_before_admission",
                "a revocation cannot predate the exact snapshot it revokes",
            ));
        }
        let revocation = EnforcementCoverageRevocation {
            declaration_id: request.declaration_id,
            declaration_artifact_ref: request.declaration_artifact_ref,
            declaration_content_hash: request.declaration_content_hash.clone(),
            revocation_receipt_ref: request.revocation_receipt_ref,
            reason: request.reason,
            revoked_at: request.revoked_at,
        };
        if let Some(existing) = self
            .revocations_by_hash
            .get(&request.declaration_content_hash)
        {
            if existing != &revocation {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_revocation_conflict",
                    "the snapshot already has a different immutable revocation record",
                ));
            }
        } else {
            self.revocations_by_hash
                .insert(request.declaration_content_hash.clone(), revocation);
        }
        Ok(self.operability_for_hash(&request.declaration_content_hash, i64::MIN))
    }

    pub fn resolve(
        &self,
        requirement: &EnforcementCoverageRequirement,
        now_ms: i64,
    ) -> Result<ResolvedEnforcementCoverage, EnforcementCoverageError> {
        let snapshot = self
            .snapshots_by_hash
            .get(&requirement.declaration_content_hash)
            .ok_or_else(|| {
                EnforcementCoverageError::new(
                    "enforcement_coverage_snapshot_missing",
                    "the exact declaration hash is not admitted",
                )
            })?;
        if snapshot.declaration_artifact_ref != requirement.declaration_artifact_ref {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_artifact_mismatch",
                "the requested artifact ref is not bound to the requested hash",
            ));
        }
        let declaration = &snapshot.declaration;
        let exact = [
            ("/subject/kind", requirement.subject_kind.as_str()),
            (
                "/subject/profile_or_adapter_ref",
                requirement.profile_or_adapter_ref.as_str(),
            ),
            ("/subject/version", requirement.subject_version.as_str()),
            (
                "/subject/content_hash",
                requirement.subject_content_hash.as_str(),
            ),
            ("/scope/surface", requirement.surface.as_str()),
            ("/scope/action_class", requirement.action_class.as_str()),
            ("/scope/boundary", requirement.boundary.as_str()),
            ("/scope/scope_ref", requirement.scope_ref.as_str()),
        ];
        for (pointer, expected) in exact {
            if string_at(declaration, pointer) != Some(expected) {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_scope_mismatch",
                    format!("{pointer} does not match the required exact coverage coordinates"),
                ));
            }
        }
        if let Some(mode) = &requirement.required_operating_mode {
            if string_at(declaration, "/operating_mode") != Some(mode.as_str()) {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_mode_mismatch",
                    "the declaration operating mode does not match the required mode",
                ));
            }
        }
        for claim in &requirement.required_claims {
            let pointer = format!("/claims/{}", claim.field());
            if declaration.pointer(&pointer) != Some(&Value::Bool(true)) {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_claim_missing",
                    format!("required claim '{}' is not proven true", claim.field()),
                ));
            }
        }
        let verification_evidence = declaration
            .pointer("/verification/evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty());
        if !verification_evidence {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_verification_evidence_missing",
                "operability requires retained verification evidence",
            ));
        }
        if requirement.evidence_requirement
            == EnforcementCoverageEvidenceRequirement::VerificationAndReceipt
        {
            let receipt_evidence = declaration
                .pointer("/receipt/evidence_refs")
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty());
            if declaration.pointer("/claims/receipted") != Some(&Value::Bool(true))
                || string_at(declaration, "/receipt/scope") == Some("none")
                || !receipt_evidence
            {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_receipt_evidence_missing",
                    "operability requires a true receipted claim, non-none scope, and receipt evidence",
                ));
            }
        }

        let operability = self.operability_for_hash(&requirement.declaration_content_hash, now_ms);
        if !operability.operable {
            return Err(EnforcementCoverageError::new(
                "enforcement_coverage_not_operable",
                format!(
                    "exact coverage snapshot is not operable ({})",
                    operability.reason_code
                ),
            ));
        }
        Ok(ResolvedEnforcementCoverage {
            operability,
            declaration: declaration.clone(),
            evidence_receipt_ref: snapshot.evidence_receipt_ref.clone(),
        })
    }

    pub fn operability_index(&self, now_ms: i64) -> Vec<EnforcementCoverageOperabilityEntry> {
        self.snapshots_by_hash
            .keys()
            .map(|hash| self.operability_for_hash(hash, now_ms))
            .collect()
    }

    pub fn export_snapshot(&self) -> Result<Value, EnforcementCoverageError> {
        serde_json::to_value(self).map_err(|error| {
            EnforcementCoverageError::new("enforcement_coverage_export_failed", error.to_string())
        })
    }

    pub fn restore_snapshot(value: Value) -> Result<Self, EnforcementCoverageError> {
        let restored: Self = serde_json::from_value(value).map_err(|error| {
            EnforcementCoverageError::new("enforcement_coverage_restore_invalid", error.to_string())
        })?;
        restored.validate_internal_bindings()?;
        Ok(restored)
    }

    fn operability_for_hash(&self, hash: &str, now_ms: i64) -> EnforcementCoverageOperabilityEntry {
        let snapshot = self
            .snapshots_by_hash
            .get(hash)
            .expect("operability is derived only for retained snapshots");
        let declaration_id = string_at(&snapshot.declaration, "/declaration_id")
            .unwrap_or_default()
            .to_string();
        let is_logical_head = self.head_by_declaration_id.get(&declaration_id)
            == Some(&snapshot.declaration_content_hash);
        let (currentness, reason_code) = if !is_logical_head {
            (EnforcementCoverageCurrentness::Superseded, "superseded")
        } else if self.revocations_by_hash.contains_key(hash)
            || string_at(&snapshot.declaration, "/status") == Some("revoked")
        {
            (EnforcementCoverageCurrentness::Revoked, "revoked")
        } else if string_at(&snapshot.declaration, "/status") == Some("stale")
            || string_at(&snapshot.declaration, "/verification/freshness_status") == Some("stale")
        {
            (EnforcementCoverageCurrentness::Stale, "stale")
        } else if string_at(&snapshot.declaration, "/status") != Some("verified")
            || string_at(&snapshot.declaration, "/verification/freshness_status")
                == Some("unverified")
            || self.snapshot_not_yet_valid(snapshot, now_ms)
        {
            (EnforcementCoverageCurrentness::Unverified, "unverified")
        } else if self.snapshot_expired(snapshot, now_ms) {
            (EnforcementCoverageCurrentness::Expired, "expired")
        } else {
            (EnforcementCoverageCurrentness::Current, "current")
        };
        EnforcementCoverageOperabilityEntry {
            declaration_id,
            declaration_artifact_ref: snapshot.declaration_artifact_ref.clone(),
            declaration_content_hash: snapshot.declaration_content_hash.clone(),
            is_logical_head,
            currentness,
            operable: currentness == EnforcementCoverageCurrentness::Current,
            reason_code: reason_code.to_string(),
        }
    }

    fn snapshot_expired(&self, snapshot: &EnforcementCoverageSnapshot, now_ms: i64) -> bool {
        if string_at(&snapshot.declaration, "/verification/freshness_status") == Some("expired") {
            return true;
        }
        let Some(valid_until) = string_at(&snapshot.declaration, "/verification/valid_until")
        else {
            return true;
        };
        let Ok(valid_until) = OffsetDateTime::parse(valid_until, &Rfc3339) else {
            return true;
        };
        let now_nanos = i128::from(now_ms).saturating_mul(1_000_000);
        valid_until.unix_timestamp_nanos() <= now_nanos
    }

    fn snapshot_not_yet_valid(&self, snapshot: &EnforcementCoverageSnapshot, now_ms: i64) -> bool {
        let now_nanos = i128::from(now_ms).saturating_mul(1_000_000);
        [
            snapshot.admitted_at.as_str(),
            string_at(&snapshot.declaration, "/verification/evaluated_at").unwrap_or_default(),
        ]
        .into_iter()
        .any(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .map(|time| time.unix_timestamp_nanos() > now_nanos)
                .unwrap_or(true)
        })
    }

    fn validate_internal_bindings(&self) -> Result<(), EnforcementCoverageError> {
        for (hash, snapshot) in &self.snapshots_by_hash {
            validate_hash(hash)?;
            validate_artifact_ref(&snapshot.declaration_artifact_ref)?;
            validate_receipt_ref(&snapshot.evidence_receipt_ref)?;
            validate_time(
                &snapshot.admitted_at,
                "enforcement_coverage_admitted_at_invalid",
            )?;
            let typed: EnforcementCoverageDeclarationV1 =
                serde_json::from_value(snapshot.declaration.clone()).map_err(|error| {
                    EnforcementCoverageError::new(
                        "enforcement_coverage_restore_contract_invalid",
                        error.to_string(),
                    )
                })?;
            let canonical_value = serde_json::to_value(typed).map_err(|error| {
                EnforcementCoverageError::new(
                    "enforcement_coverage_projection_failed",
                    error.to_string(),
                )
            })?;
            validate_portable_invariants(&canonical_value)?;
            let (canonical_jcs, computed_hash) = canonical_hash(&canonical_value)?;
            if hash != &computed_hash
                || hash != &snapshot.declaration_content_hash
                || canonical_value != snapshot.declaration
                || canonical_jcs != snapshot.canonical_jcs
                || self
                    .hash_by_artifact_ref
                    .get(&snapshot.declaration_artifact_ref)
                    != Some(hash)
            {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_binding_mismatch",
                    "restored declaration bytes, hash, artifact index, or projection do not bind",
                ));
            }
        }
        for (artifact_ref, hash) in &self.hash_by_artifact_ref {
            if self
                .snapshots_by_hash
                .get(hash)
                .map(|snapshot| snapshot.declaration_artifact_ref.as_str())
                != Some(artifact_ref.as_str())
            {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_artifact_index_invalid",
                    "artifact index points to no exactly bound snapshot",
                ));
            }
        }
        for (declaration_id, hash) in &self.head_by_declaration_id {
            let Some(head) = self.snapshots_by_hash.get(hash) else {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_head_invalid",
                    "logical head does not bind a retained declaration with the same identity",
                ));
            };
            if string_at(&head.declaration, "/declaration_id") != Some(declaration_id.as_str()) {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_head_invalid",
                    "logical head does not bind a retained declaration with the same identity",
                ));
            }
            let head_admitted_at = validate_time(
                &head.admitted_at,
                "enforcement_coverage_admitted_at_invalid",
            )?;
            for retained in self.snapshots_by_hash.values().filter(|snapshot| {
                string_at(&snapshot.declaration, "/declaration_id") == Some(declaration_id.as_str())
            }) {
                let retained_admitted_at = validate_time(
                    &retained.admitted_at,
                    "enforcement_coverage_admitted_at_invalid",
                )?;
                if retained_admitted_at > head_admitted_at {
                    return Err(EnforcementCoverageError::new(
                        "enforcement_coverage_admission_time_regressed",
                        "restored logical head predates a retained snapshot of the same declaration",
                    ));
                }
            }
        }
        for (hash, revocation) in &self.revocations_by_hash {
            validate_receipt_ref(&revocation.revocation_receipt_ref)?;
            validate_time(
                &revocation.revoked_at,
                "enforcement_coverage_revoked_at_invalid",
            )?;
            let Some(snapshot) = self.snapshots_by_hash.get(hash) else {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_revocation_invalid",
                    "revocation points to no retained snapshot",
                ));
            };
            if revocation.declaration_content_hash != *hash
                || revocation.declaration_artifact_ref != snapshot.declaration_artifact_ref
                || string_at(&snapshot.declaration, "/declaration_id")
                    != Some(revocation.declaration_id.as_str())
            {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_restore_revocation_invalid",
                    "revocation does not bind its exact retained snapshot",
                ));
            }
            let admitted_at = validate_time(
                &snapshot.admitted_at,
                "enforcement_coverage_admitted_at_invalid",
            )?;
            let revoked_at = validate_time(
                &revocation.revoked_at,
                "enforcement_coverage_revoked_at_invalid",
            )?;
            if revoked_at < admitted_at {
                return Err(EnforcementCoverageError::new(
                    "enforcement_coverage_revoked_before_admission",
                    "restored revocation predates the exact snapshot it revokes",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/positive-active-enforcement.json"
        )))
        .expect("fixture JSON")
    }

    fn admitted() -> (EnforcementCoverageRegistry, Value, String, String) {
        let declaration = declaration();
        let (_, hash) = canonical_hash(&declaration).expect("hash");
        let artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        let mut registry = EnforcementCoverageRegistry::default();
        registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: artifact_ref.clone(),
                    declaration_content_hash: hash.clone(),
                    declaration: declaration.clone(),
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-1".into(),
                    admitted_at: "2026-07-21T16:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .expect("admitted");
        (registry, declaration, artifact_ref, hash)
    }

    fn requirement(artifact_ref: String, hash: String) -> EnforcementCoverageRequirement {
        EnforcementCoverageRequirement {
            declaration_artifact_ref: artifact_ref,
            declaration_content_hash: hash,
            subject_kind: "node_enforcement_profile".into(),
            profile_or_adapter_ref: "node-enforcement://acme/node-alpha/revision/v1.2.0".into(),
            subject_version: "1.2.0".into(),
            subject_content_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            surface: "shell".into(),
            action_class: "process_spawn".into(),
            boundary: "managed_workload".into(),
            scope_ref: "enforcement-scope://acme/node-alpha/managed-shell".into(),
            required_operating_mode: Some("active_enforcement".into()),
            required_claims: vec![
                EnforcementCoverageClaim::Mediated,
                EnforcementCoverageClaim::Preventable,
                EnforcementCoverageClaim::Receipted,
            ],
            evidence_requirement: EnforcementCoverageEvidenceRequirement::VerificationAndReceipt,
        }
    }

    #[test]
    fn admits_and_resolves_only_the_exact_current_snapshot() {
        let (registry, _, artifact_ref, hash) = admitted();
        let resolved = registry
            .resolve(
                &requirement(artifact_ref, hash),
                1_784_678_400_000, // 2026-07-22; after evaluation and before valid_until.
            )
            .expect("operable");
        assert_eq!(
            resolved.operability.currentness,
            EnforcementCoverageCurrentness::Current
        );
        assert!(resolved.operability.operable);
    }

    #[test]
    fn refuses_hash_scope_claim_and_expiry_mismatches() {
        let (registry, _, artifact_ref, hash) = admitted();
        let mut mismatched = requirement(artifact_ref.clone(), hash.clone());
        mismatched.surface = "browser".into();
        assert_eq!(
            registry
                .resolve(&mismatched, 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_scope_mismatch"
        );
        let mut mode_mismatch = requirement(artifact_ref.clone(), hash.clone());
        mode_mismatch.required_operating_mode = Some("audit_only".into());
        assert_eq!(
            registry
                .resolve(&mode_mismatch, 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_mode_mismatch"
        );
        assert_eq!(
            registry
                .resolve(
                    &requirement(artifact_ref, hash),
                    1_800_000_000_000, // after 2026-08-21
                )
                .unwrap_err()
                .code,
            "enforcement_coverage_not_operable"
        );
    }

    #[test]
    fn refuses_a_required_claim_that_is_not_proven_true() {
        let mut declaration = declaration();
        declaration["claims"]["discovered"] = Value::Bool(false);
        let (_, hash) = canonical_hash(&declaration).expect("hash");
        let artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        let mut registry = EnforcementCoverageRegistry::default();
        registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: artifact_ref.clone(),
                    declaration_content_hash: hash.clone(),
                    declaration,
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-claim"
                        .into(),
                    admitted_at: "2026-07-21T16:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .expect("valid declaration with an explicit false discovery claim");
        let mut required = requirement(artifact_ref, hash);
        required.required_claims = vec![EnforcementCoverageClaim::Discovered];
        assert_eq!(
            registry
                .resolve(&required, 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_claim_missing"
        );
    }

    #[test]
    fn refuses_receipt_reliance_without_receipt_evidence() {
        let mut declaration = declaration();
        declaration["claims"]["receipted"] = Value::Bool(false);
        declaration["receipt"]["scope"] = Value::String("none".into());
        declaration["receipt"]["contract_refs"] = Value::Array(vec![]);
        declaration["receipt"]["evidence_refs"] = Value::Array(vec![]);
        let (_, hash) = canonical_hash(&declaration).expect("hash");
        let artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        let mut registry = EnforcementCoverageRegistry::default();
        registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: artifact_ref.clone(),
                    declaration_content_hash: hash.clone(),
                    declaration,
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-no-receipt"
                        .into(),
                    admitted_at: "2026-07-21T16:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .expect("valid non-receipted coverage snapshot");
        let mut required = requirement(artifact_ref, hash);
        required.required_claims = vec![];
        assert_eq!(
            registry
                .resolve(&required, 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_receipt_evidence_missing"
        );
    }

    #[test]
    fn successor_requires_exact_head_and_supersedes_without_mutating_prior() {
        let (mut registry, mut successor, _, prior_hash) = admitted();
        successor["limitations"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("successor verification run".into()));
        let (_, successor_hash) = canonical_hash(&successor).expect("successor hash");
        let successor_artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            successor_hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        let request = EnforcementCoverageAdmissionRequest {
            declaration_artifact_ref: successor_artifact_ref,
            declaration_content_hash: successor_hash.clone(),
            declaration: successor,
            expected_previous_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-2".into(),
            admitted_at: "2026-07-21T17:00:00Z".into(),
        };
        assert_eq!(
            registry
                .admit(request.clone(), 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_stale_head"
        );
        let mut regressed = request.clone();
        regressed.expected_previous_hash = Some(prior_hash.clone());
        regressed.admitted_at = "2026-07-21T15:59:59Z".into();
        assert_eq!(
            registry
                .admit(regressed, 1_784_678_400_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_admission_time_regressed"
        );
        let mut corrected = request;
        corrected.expected_previous_hash = Some(prior_hash.clone());
        registry
            .admit(corrected, 1_784_678_400_000)
            .expect("exact-head successor admitted");
        let prior = registry.operability_for_hash(&prior_hash, 1_784_678_400_000);
        assert_eq!(
            prior.currentness,
            EnforcementCoverageCurrentness::Superseded
        );
        assert!(!prior.operable);
        assert_eq!(
            registry.snapshots_by_hash[&prior_hash].declaration_content_hash,
            prior_hash
        );
        assert_eq!(
            registry.head_by_declaration_id.values().next(),
            Some(&successor_hash)
        );
    }

    #[test]
    fn rejects_unbound_hash_before_state_mutation() {
        let declaration = declaration();
        let mut registry = EnforcementCoverageRegistry::default();
        let error = registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: "artifact://ioi/enforcement-coverage/wrong".into(),
                    declaration_content_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into(),
                    declaration,
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-bad".into(),
                    admitted_at: "2026-07-21T16:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .unwrap_err();
        assert_eq!(error.code, "enforcement_coverage_hash_mismatch");
        assert!(registry.operability_index(0).is_empty());
    }

    #[test]
    fn refuses_registered_portable_invariant_failures_at_admission() {
        for (fixture, expected_rule) in [
            (
                "negative-receipted-missing-evidence.json",
                "enforcement_coverage.receipt.evidence.required_when_receipted",
            ),
            (
                "negative-uncovered-missing-gap.json",
                "enforcement_coverage.gap.required_when_uncovered",
            ),
        ] {
            let path = format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1/{fixture}",
                env!("CARGO_MANIFEST_DIR")
            );
            let declaration: Value =
                serde_json::from_slice(&std::fs::read(path).expect("registered invariant fixture"))
                    .expect("fixture JSON");
            let (_, hash) = canonical_hash(&declaration).expect("hash");
            let artifact_ref = format!(
                "artifact://ioi/enforcement-coverage/{}",
                hash.strip_prefix(HASH_PREFIX).unwrap()
            );
            let mut registry = EnforcementCoverageRegistry::default();
            let error = registry
                .admit(
                    EnforcementCoverageAdmissionRequest {
                        declaration_artifact_ref: artifact_ref,
                        declaration_content_hash: hash,
                        declaration,
                        expected_previous_hash: None,
                        evidence_receipt_ref:
                            "receipt://ioi/enforcement-coverage/admission-invariant".into(),
                        admitted_at: "2026-07-21T16:00:00Z".into(),
                    },
                    1_784_678_400_000,
                )
                .unwrap_err();
            assert_eq!(error.code, "enforcement_coverage_invariant_failed");
            assert_eq!(error.message, expected_rule);
            assert!(registry.operability_index(0).is_empty());
        }
    }

    #[test]
    fn refuses_every_registered_negative_fixture_at_admission() {
        let fixture_dir = format!(
            "{}/../../docs/architecture/_meta/schemas/fixtures/enforcement-coverage-declaration-v1",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut fixture_paths = std::fs::read_dir(fixture_dir)
            .expect("registered fixture directory")
            .map(|entry| entry.expect("fixture entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("negative-") && name.ends_with(".json"))
            })
            .collect::<Vec<_>>();
        fixture_paths.sort();
        assert_eq!(fixture_paths.len(), 17, "negative fixture census drifted");

        for path in fixture_paths {
            let declaration: Value =
                serde_json::from_slice(&std::fs::read(&path).expect("registered negative fixture"))
                    .expect("fixture JSON");
            let (_, hash) = canonical_hash(&declaration).expect("hash");
            let artifact_ref = format!(
                "artifact://ioi/enforcement-coverage/{}",
                hash.strip_prefix(HASH_PREFIX).unwrap()
            );
            let mut registry = EnforcementCoverageRegistry::default();
            let error = registry
                .admit(
                    EnforcementCoverageAdmissionRequest {
                        declaration_artifact_ref: artifact_ref,
                        declaration_content_hash: hash,
                        declaration,
                        expected_previous_hash: None,
                        evidence_receipt_ref: "receipt://ioi/enforcement-coverage/negative-fixture"
                            .into(),
                        admitted_at: "2026-07-21T16:00:00Z".into(),
                    },
                    1_784_678_400_000,
                )
                .expect_err("every registered negative fixture must fail closed");
            assert!(
                matches!(
                    error.code,
                    "enforcement_coverage_contract_invalid"
                        | "enforcement_coverage_invariant_failed"
                ),
                "{} failed through an unexpected boundary: {error}",
                path.display()
            );
            assert!(registry.operability_index(0).is_empty());
        }
    }

    #[test]
    fn idempotent_admission_requires_exact_lifecycle_coordinates() {
        let (mut registry, declaration, artifact_ref, hash) = admitted();
        let error = registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: artifact_ref,
                    declaration_content_hash: hash,
                    declaration,
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/different-admission"
                        .into(),
                    admitted_at: "2026-07-21T16:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .unwrap_err();
        assert_eq!(error.code, "enforcement_coverage_snapshot_collision");
    }

    #[test]
    fn revocation_is_exact_immutable_and_fail_closed() {
        let (mut registry, declaration, artifact_ref, hash) = admitted();
        let declaration_id = string_at(&declaration, "/declaration_id")
            .unwrap()
            .to_string();
        let revocation = EnforcementCoverageRevocationRequest {
            declaration_id,
            declaration_artifact_ref: artifact_ref.clone(),
            declaration_content_hash: hash.clone(),
            revocation_receipt_ref: "receipt://ioi/enforcement-coverage/revocation-1".into(),
            reason: "mechanism version withdrawn".into(),
            revoked_at: "2026-07-22T16:00:00Z".into(),
        };
        let mut predating = revocation.clone();
        predating.revoked_at = "2026-07-21T15:59:59Z".into();
        assert_eq!(
            registry
                .revoke(predating, 1_784_739_600_000)
                .unwrap_err()
                .code,
            "enforcement_coverage_revoked_before_admission"
        );
        registry
            .revoke(revocation, 1_784_739_600_000)
            .expect("revoked");
        let error = registry
            .resolve(&requirement(artifact_ref, hash), 1_784_678_400_000)
            .unwrap_err();
        assert_eq!(error.code, "enforcement_coverage_not_operable");
        assert!(error.message.contains("revoked"));
    }

    #[test]
    fn deterministic_export_restore_revalidates_every_binding() {
        let (registry, _, artifact_ref, hash) = admitted();
        let exported = registry.export_snapshot().expect("export");
        let restored = EnforcementCoverageRegistry::restore_snapshot(exported.clone())
            .expect("restore exact snapshot");
        assert_eq!(restored.export_snapshot().unwrap(), exported);
        restored
            .resolve(&requirement(artifact_ref, hash), 1_784_678_400_000)
            .expect("restored snapshot remains operable");
    }

    #[test]
    fn restore_rejects_tampered_snapshot_bytes() {
        let (registry, _, _, hash) = admitted();
        let mut exported = registry.export_snapshot().expect("export");
        exported["snapshots_by_hash"][hash.as_str()]["declaration"]["scope"]["surface"] =
            Value::String("browser".into());
        let error = EnforcementCoverageRegistry::restore_snapshot(exported).unwrap_err();
        assert_eq!(error.code, "enforcement_coverage_restore_binding_mismatch");
    }

    #[test]
    fn restore_rejects_internally_rebound_portable_invariant_failure() {
        let (mut registry, _, _, prior_hash) = admitted();
        let mut snapshot = registry
            .snapshots_by_hash
            .remove(&prior_hash)
            .expect("admitted snapshot");
        snapshot.declaration["receipt"]["evidence_refs"] = Value::Array(vec![]);
        let (canonical_jcs, rebound_hash) =
            canonical_hash(&snapshot.declaration).expect("rebound hash");
        let rebound_artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            rebound_hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        snapshot.canonical_jcs = canonical_jcs;
        snapshot.declaration_content_hash = rebound_hash.clone();
        snapshot.declaration_artifact_ref = rebound_artifact_ref.clone();
        registry.snapshots_by_hash.clear();
        registry
            .snapshots_by_hash
            .insert(rebound_hash.clone(), snapshot);
        registry.hash_by_artifact_ref.clear();
        registry
            .hash_by_artifact_ref
            .insert(rebound_artifact_ref, rebound_hash.clone());
        registry.head_by_declaration_id.clear();
        registry.head_by_declaration_id.insert(
            "enforcement-coverage://acme/node-alpha/shell/process-spawn/v1".into(),
            rebound_hash,
        );

        let error = EnforcementCoverageRegistry::restore_snapshot(
            registry
                .export_snapshot()
                .expect("internally rebound export"),
        )
        .expect_err("restore must re-run portable invariants");
        assert_eq!(error.code, "enforcement_coverage_invariant_failed");
        assert_eq!(
            error.message,
            "enforcement_coverage.receipt.evidence.required_when_receipted"
        );
    }

    #[test]
    fn restore_rejects_regressed_head_and_revocation_times() {
        let (mut registry, mut successor, artifact_ref, prior_hash) = admitted();
        successor["limitations"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("later retained snapshot".into()));
        let (_, successor_hash) = canonical_hash(&successor).expect("successor hash");
        let successor_artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            successor_hash.strip_prefix(HASH_PREFIX).unwrap()
        );
        registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: successor_artifact_ref,
                    declaration_content_hash: successor_hash.clone(),
                    declaration: successor.clone(),
                    expected_previous_hash: Some(prior_hash.clone()),
                    evidence_receipt_ref: "receipt://ioi/enforcement-coverage/admission-later"
                        .into(),
                    admitted_at: "2026-07-21T17:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .expect("successor admitted");

        let mut regressed_head = registry.export_snapshot().expect("export");
        regressed_head["snapshots_by_hash"][successor_hash.as_str()]["admitted_at"] =
            Value::String("2026-07-21T15:59:59Z".into());
        assert_eq!(
            EnforcementCoverageRegistry::restore_snapshot(regressed_head)
                .unwrap_err()
                .code,
            "enforcement_coverage_admission_time_regressed"
        );

        let declaration_id = string_at(&successor, "/declaration_id")
            .expect("declaration identity")
            .to_string();
        registry
            .revoke(
                EnforcementCoverageRevocationRequest {
                    declaration_id,
                    declaration_artifact_ref: registry.snapshots_by_hash[&successor_hash]
                        .declaration_artifact_ref
                        .clone(),
                    declaration_content_hash: successor_hash.clone(),
                    revocation_receipt_ref: "receipt://ioi/enforcement-coverage/revocation-later"
                        .into(),
                    reason: "later mechanism withdrawal".into(),
                    revoked_at: "2026-07-21T18:00:00Z".into(),
                },
                1_784_678_400_000,
            )
            .expect("revoked successor");
        let mut predating_revocation = registry.export_snapshot().expect("export revoked");
        predating_revocation["revocations_by_hash"][successor_hash.as_str()]["revoked_at"] =
            Value::String("2026-07-21T15:59:59Z".into());
        assert_eq!(
            EnforcementCoverageRegistry::restore_snapshot(predating_revocation)
                .unwrap_err()
                .code,
            "enforcement_coverage_revoked_before_admission"
        );

        assert!(registry.snapshots_by_hash.contains_key(&prior_hash));
        assert_eq!(registry.hash_by_artifact_ref[&artifact_ref], prior_hash);
    }
}
