//! Immutable admission and operability owner for runtime tool-contract revisions.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ioi_types::app::agentic::AgentTool;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tools::contracts::{
    admitted_runtime_tool_contract_for_definition, admitted_runtime_tool_contract_for_native_name,
    runtime_tool_contract_canonical_hash_material, runtime_tool_id_for_name,
    validate_admitted_runtime_tool_contract, AdmittedRuntimeToolContract,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeToolContractRegistryError {
    pub code: &'static str,
    pub message: String,
}

impl RuntimeToolContractRegistryError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RuntimeToolContractRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RuntimeToolContractRegistryError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeToolContractSnapshot {
    /// Exact JCS bytes whose SHA-256 digest is `contract.content_hash`.
    pub canonical_jcs: Vec<u8>,
    pub canonical_contract: Value,
    pub contract: AdmittedRuntimeToolContract,
    pub admission_receipt_ref: String,
    pub predecessor_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeToolContractRevocation {
    pub revision_ref: String,
    pub content_hash: String,
    pub revocation_receipt_ref: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedRegisteredRuntimeToolContract {
    pub contract: AdmittedRuntimeToolContract,
    pub admission_receipt_ref: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeToolContractRegistry {
    snapshots_by_hash: BTreeMap<String, RuntimeToolContractSnapshot>,
    hash_by_revision_ref: BTreeMap<String, String>,
    head_by_tool_id: BTreeMap<String, String>,
    revocations_by_hash: BTreeMap<String, RuntimeToolContractRevocation>,
}

pub fn default_seeded_registry(
) -> Result<&'static RuntimeToolContractRegistry, RuntimeToolContractRegistryError> {
    static DEFAULT: OnceLock<
        Result<RuntimeToolContractRegistry, RuntimeToolContractRegistryError>,
    > = OnceLock::new();
    match DEFAULT.get_or_init(RuntimeToolContractRegistry::seeded_native) {
        Ok(registry) => Ok(registry),
        Err(error) => Err(error.clone()),
    }
}

impl RuntimeToolContractRegistry {
    pub fn seeded_native() -> Result<Self, RuntimeToolContractRegistryError> {
        let mut registry = Self::default();
        for name in AgentTool::RESERVED_TOOL_NAMES {
            let contract =
                admitted_runtime_tool_contract_for_native_name(name).map_err(|error| {
                    RuntimeToolContractRegistryError::new(
                        "runtime_tool_contract_seed_invalid",
                        error,
                    )
                })?;
            registry.admit(
                contract,
                format!("receipt://runtime-tool-contract/native/{name}"),
                None,
            )?;
        }
        for definition in super::connectors::google_workspace::google_connector_tool_definitions() {
            let contract = admitted_runtime_tool_contract_for_definition(
                &definition,
                "connector://google-workspace",
                "Custom(google_workspace_connector)",
            )
            .map_err(|error| {
                RuntimeToolContractRegistryError::new("runtime_tool_contract_seed_invalid", error)
            })?
            .contract;
            let name = definition.name.clone();
            registry.admit(
                contract,
                format!("receipt://runtime-tool-contract/connector/google/{name}"),
                None,
            )?;
        }
        for binding in super::connectors::mail_connector::mail_connector_tool_route_bindings() {
            let definition = ioi_types::app::agentic::LlmToolDefinition {
                name: binding.tool_name.to_string(),
                description: "Wallet-network mail connector capability".to_string(),
                parameters: r#"{"type":"object"}"#.to_string(),
            };
            let contract = admitted_runtime_tool_contract_for_definition(
                &definition,
                "connector://wallet-network-mail",
                "Custom(wallet_network_mail_connector)",
            )
            .map_err(|error| {
                RuntimeToolContractRegistryError::new("runtime_tool_contract_seed_invalid", error)
            })?
            .contract;
            registry.admit(
                contract,
                format!(
                    "receipt://runtime-tool-contract/connector/mail/{}",
                    binding.tool_name
                ),
                None,
            )?;
        }
        Ok(registry)
    }

    pub fn admit(
        &mut self,
        contract: AdmittedRuntimeToolContract,
        admission_receipt_ref: String,
        expected_previous_hash: Option<String>,
    ) -> Result<ResolvedRegisteredRuntimeToolContract, RuntimeToolContractRegistryError> {
        validate_admitted_runtime_tool_contract(&contract).map_err(|error| {
            RuntimeToolContractRegistryError::new("runtime_tool_contract_invalid", error)
        })?;
        if !admission_receipt_ref.starts_with("receipt://") {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_receipt_ref_invalid",
                "admission receipt must be an exact receipt:// reference",
            ));
        }
        let canonical_contract = serde_json::to_value(&contract).map_err(|error| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_projection_failed",
                error.to_string(),
            )
        })?;
        let canonical_jcs =
            runtime_tool_contract_canonical_hash_material(&contract).map_err(|error| {
                RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_canonicalization_failed",
                    error,
                )
            })?;
        if let Some(existing) = self.snapshots_by_hash.get(&contract.content_hash) {
            if existing.contract != contract
                || existing.canonical_jcs != canonical_jcs
                || existing.canonical_contract != canonical_contract
                || existing.admission_receipt_ref != admission_receipt_ref
                || existing.predecessor_content_hash != expected_previous_hash
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_snapshot_collision",
                    "content hash is retained with different admission coordinates",
                ));
            }
            if self.head_by_tool_id.get(&contract.tool_id) != Some(&contract.content_hash) {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_stale_head",
                    "idempotent retry no longer names the current tool head",
                ));
            }
            return Ok(ResolvedRegisteredRuntimeToolContract {
                contract,
                admission_receipt_ref,
            });
        }
        let current_head = self.head_by_tool_id.get(&contract.tool_id).cloned();
        if current_head != expected_previous_hash {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_stale_head",
                format!(
                    "expected previous hash {:?} does not match current head {:?}",
                    expected_previous_hash, current_head
                ),
            ));
        }
        if current_head.is_some()
            && contract.predecessor_revision_ref.as_deref()
                != current_head.as_ref().and_then(|hash| {
                    self.snapshots_by_hash
                        .get(hash)
                        .map(|snapshot| snapshot.contract.revision_ref.as_str())
                })
        {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_predecessor_mismatch",
                "successor does not name the exact current revision",
            ));
        }
        if let Some(bound_hash) = self.hash_by_revision_ref.get(&contract.revision_ref) {
            if bound_hash != &contract.content_hash {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_revision_collision",
                    "revision_ref is already bound to different immutable bytes",
                ));
            }
        }
        let content_hash = contract.content_hash.clone();
        let revision_ref = contract.revision_ref.clone();
        let tool_id = contract.tool_id.clone();
        self.snapshots_by_hash.insert(
            content_hash.clone(),
            RuntimeToolContractSnapshot {
                canonical_jcs,
                canonical_contract,
                contract: contract.clone(),
                admission_receipt_ref: admission_receipt_ref.clone(),
                predecessor_content_hash: expected_previous_hash,
            },
        );
        self.hash_by_revision_ref
            .insert(revision_ref, content_hash.clone());
        self.head_by_tool_id.insert(tool_id, content_hash);
        Ok(ResolvedRegisteredRuntimeToolContract {
            contract,
            admission_receipt_ref,
        })
    }

    pub fn revoke(
        &mut self,
        revision_ref: &str,
        content_hash: &str,
        revocation_receipt_ref: String,
        reason: String,
    ) -> Result<(), RuntimeToolContractRegistryError> {
        let snapshot = self.snapshots_by_hash.get(content_hash).ok_or_else(|| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_snapshot_missing",
                "exact contract hash is not admitted",
            )
        })?;
        if snapshot.contract.revision_ref != revision_ref
            || self
                .hash_by_revision_ref
                .get(revision_ref)
                .map(String::as_str)
                != Some(content_hash)
        {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_revocation_binding_mismatch",
                "revocation does not bind one exact admitted revision and hash",
            ));
        }
        if !revocation_receipt_ref.starts_with("receipt://") || reason.trim().is_empty() {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_revocation_invalid",
                "revocation requires a receipt and nonblank reason",
            ));
        }
        let revocation = RuntimeToolContractRevocation {
            revision_ref: revision_ref.to_string(),
            content_hash: content_hash.to_string(),
            revocation_receipt_ref,
            reason,
        };
        if let Some(existing) = self.revocations_by_hash.get(content_hash) {
            if existing != &revocation {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_revocation_conflict",
                    "revision already has a different immutable revocation",
                ));
            }
        } else {
            self.revocations_by_hash
                .insert(content_hash.to_string(), revocation);
        }
        Ok(())
    }

    pub fn resolve_current_for_name(
        &self,
        tool_name: &str,
    ) -> Result<ResolvedRegisteredRuntimeToolContract, RuntimeToolContractRegistryError> {
        let tool_id = runtime_tool_id_for_name(tool_name);
        let hash = self.head_by_tool_id.get(&tool_id).ok_or_else(|| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_unresolved",
                format!("no admitted head exists for '{tool_name}'"),
            )
        })?;
        self.resolve_hash(hash)
    }

    pub fn current_released(
        &self,
    ) -> Result<Vec<ResolvedRegisteredRuntimeToolContract>, RuntimeToolContractRegistryError> {
        let mut contracts = self
            .head_by_tool_id
            .values()
            .map(|hash| self.resolve_hash(hash))
            .collect::<Result<Vec<_>, _>>()?;
        contracts.sort_by(|left, right| left.contract.tool_id.cmp(&right.contract.tool_id));
        Ok(contracts)
    }

    pub fn resolve_exact(
        &self,
        revision_ref: &str,
        content_hash: &str,
    ) -> Result<ResolvedRegisteredRuntimeToolContract, RuntimeToolContractRegistryError> {
        if self
            .hash_by_revision_ref
            .get(revision_ref)
            .map(String::as_str)
            != Some(content_hash)
        {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_exact_binding_mismatch",
                "revision_ref and content_hash do not identify one admitted snapshot",
            ));
        }
        self.resolve_hash(content_hash)
    }

    fn resolve_hash(
        &self,
        content_hash: &str,
    ) -> Result<ResolvedRegisteredRuntimeToolContract, RuntimeToolContractRegistryError> {
        let snapshot = self.snapshots_by_hash.get(content_hash).ok_or_else(|| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_snapshot_missing",
                "exact contract hash is not admitted",
            )
        })?;
        validate_admitted_runtime_tool_contract(&snapshot.contract).map_err(|error| {
            RuntimeToolContractRegistryError::new("runtime_tool_contract_snapshot_invalid", error)
        })?;
        if snapshot.contract.registry_status != "released"
            || self.revocations_by_hash.contains_key(content_hash)
        {
            return Err(RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_not_operable",
                "contract head is not released and unrevoked",
            ));
        }
        Ok(ResolvedRegisteredRuntimeToolContract {
            contract: snapshot.contract.clone(),
            admission_receipt_ref: snapshot.admission_receipt_ref.clone(),
        })
    }

    pub fn export_snapshot(&self) -> Result<Value, RuntimeToolContractRegistryError> {
        serde_json::to_value(self).map_err(|error| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_export_failed",
                error.to_string(),
            )
        })
    }

    pub fn restore_snapshot(value: Value) -> Result<Self, RuntimeToolContractRegistryError> {
        let registry: Self = serde_json::from_value(value).map_err(|error| {
            RuntimeToolContractRegistryError::new(
                "runtime_tool_contract_restore_invalid",
                error.to_string(),
            )
        })?;
        for (hash, snapshot) in &registry.snapshots_by_hash {
            let canonical_jcs = runtime_tool_contract_canonical_hash_material(&snapshot.contract)
                .map_err(|error| {
                RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_canonicalization_failed",
                    error,
                )
            })?;
            if hash != &snapshot.contract.content_hash
                || snapshot.canonical_jcs != canonical_jcs
                || snapshot.canonical_contract != serde_json::to_value(&snapshot.contract).unwrap()
                || !snapshot.admission_receipt_ref.starts_with("receipt://")
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_binding_mismatch",
                    "snapshot key or canonical bytes do not bind its contract",
                ));
            }
            validate_admitted_runtime_tool_contract(&snapshot.contract).map_err(|error| {
                RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_contract_invalid",
                    error,
                )
            })?;
            if registry
                .hash_by_revision_ref
                .get(&snapshot.contract.revision_ref)
                != Some(hash)
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_revision_mismatch",
                    "revision index does not bind snapshot hash",
                ));
            }
            let predecessor_hash = snapshot
                .contract
                .predecessor_revision_ref
                .as_ref()
                .map(|revision_ref| {
                    registry
                        .hash_by_revision_ref
                        .get(revision_ref)
                        .cloned()
                        .ok_or_else(|| {
                            RuntimeToolContractRegistryError::new(
                                "runtime_tool_contract_restore_predecessor_missing",
                                "predecessor revision is not retained",
                            )
                        })
                })
                .transpose()?;
            if snapshot.predecessor_content_hash != predecessor_hash {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_predecessor_mismatch",
                    "snapshot CAS predecessor does not bind its predecessor revision",
                ));
            }
        }
        for (revision_ref, hash) in &registry.hash_by_revision_ref {
            if registry
                .snapshots_by_hash
                .get(hash)
                .map(|snapshot| snapshot.contract.revision_ref.as_str())
                != Some(revision_ref.as_str())
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_revision_mismatch",
                    "revision index contains an orphaned or mismatched binding",
                ));
            }
        }
        for (tool_id, hash) in &registry.head_by_tool_id {
            if registry
                .snapshots_by_hash
                .get(hash)
                .map(|snapshot| snapshot.contract.tool_id.as_str())
                != Some(tool_id.as_str())
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_head_mismatch",
                    "tool head does not bind a retained snapshot",
                ));
            }
        }
        for (hash, revocation) in &registry.revocations_by_hash {
            if hash != &revocation.content_hash
                || !revocation.revocation_receipt_ref.starts_with("receipt://")
                || revocation.reason.trim().is_empty()
                || registry
                    .snapshots_by_hash
                    .get(hash)
                    .map(|snapshot| snapshot.contract.revision_ref.as_str())
                    != Some(revocation.revision_ref.as_str())
            {
                return Err(RuntimeToolContractRegistryError::new(
                    "runtime_tool_contract_restore_revocation_mismatch",
                    "revocation does not bind one retained immutable snapshot",
                ));
            }
        }
        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_seed_covers_closed_tool_census() {
        let registry = RuntimeToolContractRegistry::seeded_native().unwrap();
        for name in AgentTool::RESERVED_TOOL_NAMES {
            let resolved = registry.resolve_current_for_name(name).unwrap();
            assert!(!resolved.contract.primitive_capabilities_required.is_empty());
            if resolved.contract.effect_class != "read" {
                assert!(!resolved.contract.authority_scopes_required.is_empty());
            }
        }
        registry
            .resolve_current_for_name("connector__google__gmail_read_emails")
            .unwrap();
        registry
            .resolve_current_for_name("mail__read_latest")
            .unwrap();
    }

    #[test]
    fn unregistered_and_revoked_contracts_fail_closed() {
        let mut registry = RuntimeToolContractRegistry::seeded_native().unwrap();
        assert_eq!(
            registry
                .resolve_current_for_name("unowned__effect")
                .unwrap_err()
                .code,
            "runtime_tool_contract_unresolved"
        );
        let resolved = registry.resolve_current_for_name("file__write").unwrap();
        registry
            .revoke(
                &resolved.contract.revision_ref,
                &resolved.contract.content_hash,
                "receipt://test/revoke".to_string(),
                "test".to_string(),
            )
            .unwrap();
        assert_eq!(
            registry
                .resolve_current_for_name("file__write")
                .unwrap_err()
                .code,
            "runtime_tool_contract_not_operable"
        );
    }

    #[test]
    fn restore_rejects_tampered_snapshot() {
        let registry = RuntimeToolContractRegistry::seeded_native().unwrap();
        let mut exported = registry.export_snapshot().unwrap();
        let hash = exported["head_by_tool_id"][runtime_tool_id_for_name("file__read")]
            .as_str()
            .unwrap()
            .to_string();
        exported["snapshots_by_hash"][&hash]["contract"]["effect_class"] =
            Value::String("destructive".to_string());
        assert!(RuntimeToolContractRegistry::restore_snapshot(exported).is_err());
    }

    #[test]
    fn exact_admission_retry_is_idempotent_under_original_precondition() {
        let mut registry = RuntimeToolContractRegistry::default();
        let contract = admitted_runtime_tool_contract_for_native_name("file__read").unwrap();
        let receipt = "receipt://test/admit-file-read".to_string();
        let first = registry
            .admit(contract.clone(), receipt.clone(), None)
            .unwrap();
        let retry = registry.admit(contract, receipt, None).unwrap();
        assert_eq!(first, retry);
    }
}
