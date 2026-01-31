// Path: crates/execution/src/upgrade_manager/mod.rs

use crate::runtime_service::RuntimeService;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::{StateAccess, VmStateAccessor};
use ioi_api::vm::VirtualMachine;
use ioi_types::codec;
use ioi_types::error::{CoreError, UpgradeError};
// [FIX] Removed StateError from here if we use qualified path, or keep it.
// Let's keep it and see.
use ioi_types::error::StateError; 

use ioi_types::keys::{
    active_service_key, UPGRADE_ARTIFACT_PREFIX, UPGRADE_MANIFEST_PREFIX, UPGRADE_PENDING_PREFIX,
};
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use toml;
// [FIX] Import AccountId
use ioi_types::app::AccountId;

/// An intermediate struct that matches the schema of a service's on-chain TOML manifest.
#[derive(serde::Deserialize, Debug, Clone)]
struct OnChainManifest {
    id: String,
    abi_version: u32,
    state_schema: String,
    runtime: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    methods: BTreeMap<String, String>, // e.g., "ante_handle@v1" = "Internal"
    #[serde(default)]
    allowed_system_prefixes: Vec<String>,
    
    // [NEW] Allow author field in TOML
    #[serde(default)]
    author: Option<String>, // Hex encoded account ID
}

impl OnChainManifest {
    /// Converts the manifest into the canonical `ActiveServiceMeta` struct for state storage.
    fn to_active_meta(
        self,
        artifact_hash: [u8; 32],
        activated_at: u64,
    ) -> Result<ActiveServiceMeta, CoreError> {
        // Map capability strings from TOML to the Capabilities bitflags.
        let caps = Capabilities::from_strings(&self.capabilities)?;

        // Map method permission strings from TOML to the MethodPermission enum.
        let mut perms = BTreeMap::new();
        for (name, p) in self.methods {
            let mp = match p.as_str() {
                "User" => MethodPermission::User,
                "Governance" => MethodPermission::Governance,
                "Internal" => MethodPermission::Internal,
                other => {
                    return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                        "Unknown method permission '{}' in manifest",
                        other
                    ))))
                }
            };
            perms.insert(name, mp);
        }
        
        // [FIX] Parse author from hex string if present
        let author_id = if let Some(hex_str) = self.author {
             let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                .map_err(|e| CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!("Invalid author hex: {}", e))))?;
             if bytes.len() != 32 {
                 return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade("Author ID must be 32 bytes".into())));
             }
             let mut arr = [0u8; 32];
             arr.copy_from_slice(&bytes);
             Some(AccountId(arr))
        } else {
             None
        };

        Ok(ActiveServiceMeta {
            id: self.id,
            abi_version: self.abi_version,
            state_schema: self.state_schema,
            caps,
            artifact_hash,
            activated_at,
            methods: perms,
            allowed_system_prefixes: self.allowed_system_prefixes,
            generation_id: 0,
            parent_hash: None,
            author: author_id, // [FIX] Initialized
        })
    }
}

// ... [validate_service_id function] ...
fn validate_service_id(id: &str) -> Result<(), CoreError> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
            "Invalid service_id: '{}'. Must be lowercase alphanumeric with underscores.",
            id
        ))));
    }
    Ok(())
}

pub struct ServiceUpgradeManager {
    active_services: HashMap<String, Arc<dyn UpgradableService>>,
    upgrade_history: HashMap<String, Vec<u64>>,
    runtimes: HashMap<String, Arc<dyn VirtualMachine>>,
    refreshed_this_block: bool,
}

impl fmt::Debug for ServiceUpgradeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceUpgradeManager")
            .field("active_services", &self.active_services.keys())
            .field("upgrade_history", &self.upgrade_history)
            .field("runtimes", &self.runtimes.keys())
            .finish()
    }
}

impl ServiceUpgradeManager {
    pub fn new() -> Self {
        Self {
            active_services: HashMap::new(),
            upgrade_history: HashMap::new(),
            runtimes: HashMap::new(),
            refreshed_this_block: false,
        }
    }

    /// Checks if the service directory was modified in the current block.
    pub fn refreshed_this_block(&self) -> bool {
        self.refreshed_this_block
    }

    /// Resets the `refreshed_this_block` flag at the end of a block.
    pub fn clear_refreshed_flag(&mut self) {
        self.refreshed_this_block = false;
    }

    pub fn register_service(
        &mut self,
        service: Arc<dyn UpgradableService>,
    ) -> Result<(), CoreError> {
        let service_id = service.id().to_string(); // Create owned String immediately.
        if let Err(e) = validate_service_id(&service_id) {
            return Err(e);
        }
        log::info!("Registering service: {}", service_id);
        self.active_services.insert(service_id.clone(), service);
        self.upgrade_history.entry(service_id).or_default();
        Ok(())
    }

    pub fn register_runtime(&mut self, id: &str, runtime: Arc<dyn VirtualMachine>) {
        self.runtimes.insert(id.to_string(), runtime);
    }

    pub fn get_service(&self, service_id: &str) -> Option<Arc<dyn UpgradableService>> {
        self.active_services.get(service_id).cloned()
    }

    pub fn all_services(&self) -> Vec<Arc<dyn UpgradableService>> {
        let mut keys: Vec<_> = self.active_services.keys().cloned().collect();
        keys.sort();
        keys.into_iter()
            .filter_map(|k| self.active_services.get(&k).cloned())
            .collect()
    }

    /// Helper for the `Chain` struct to rebuild its `ServiceDirectory`.
    pub fn all_services_as_trait_objects(&self) -> Vec<Arc<dyn BlockchainService>> {
        self.all_services()
            .into_iter()
            .map(|s| s as Arc<dyn BlockchainService>)
            .collect()
    }

    pub fn get_service_as<T: Any>(&self) -> Option<&T> {
        for service in self.active_services.values() {
            if let Some(downcasted) = service.as_any().downcast_ref::<T>() {
                return Some(downcasted);
            }
        }
        None
    }

    pub async fn apply_upgrades_at_height(
        &mut self,
        height: u64,
        state: &mut dyn StateAccess,
    ) -> Result<usize, CoreError> {
        let index_key = [UPGRADE_PENDING_PREFIX, &height.to_le_bytes()].concat();
        let Some(index_bytes) = state.get(&index_key).map_err(CoreError::from)? else {
            // This is normal; most blocks have no upgrades. Use trace level.
            tracing::trace!(target: "upgrade_manager", height=height, "No pending upgrades found for this height.");
            return Ok(0); // No upgrades scheduled for this height.
        };

        tracing::info!(target: "upgrade_manager", height=height, "Found pending upgrades for this height. Applying...");

        let upgrades_to_apply: Vec<(String, [u8; 32], [u8; 32])> =
            codec::from_bytes_canonical(&index_bytes).map_err(CoreError::Custom)?;

        let mut applied_count = 0;

        for (service_id, manifest_hash, artifact_hash) in upgrades_to_apply {
            tracing::info!(target: "upgrade_manager", service_id=%service_id, manifest_hash=%hex::encode(manifest_hash), artifact_hash=%hex::encode(artifact_hash), "Attempting to apply upgrade.");

            let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
            let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();

            let Some(manifest_bytes) = state.get(&manifest_key).map_err(CoreError::from)? else {
                log::error!(
                    "Upgrade for service '{}' failed: manifest not found for hash {}",
                    service_id,
                    hex::encode(manifest_hash)
                );
                continue;
            };

            let Some(artifact) = state.get(&artifact_key).map_err(CoreError::from)? else {
                log::error!(
                    "Upgrade for service '{}' failed: artifact not found for hash {}",
                    service_id,
                    hex::encode(artifact_hash)
                );
                continue;
            };

            let manifest = String::from_utf8(manifest_bytes).map_err(|e| {
                CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "Manifest is not valid UTF-8: {}",
                    e
                )))
            })?;

            match self
                .execute_upgrade(&service_id, &manifest, &artifact, state, height)
                .await
            {
                Ok(()) => {
                    applied_count += 1;
                    self.refreshed_this_block = true;
                    if let Some(history) = self.upgrade_history.get_mut(&service_id) {
                        history.push(height);
                    }
                }
                Err(e) => {
                    log::error!("Failed to upgrade service {}: {}", service_id, e);
                }
            }
        }

        // If any upgrades were processed, remove the index entry to prevent re-execution.
        if applied_count > 0 {
            state.delete(&index_key).map_err(CoreError::from)?;
        }

        Ok(applied_count)
    }

    pub async fn execute_upgrade(
        &mut self,
        service_id: &str,
        manifest_str: &str,
        artifact: &[u8],
        state: &mut dyn StateAccess,
        activation_height: u64,
    ) -> Result<(), CoreError> {
        tracing::info!(target: "upgrade_manager", service_id=%service_id, "Executing upgrade.");
        // First, parse the manifest to determine which runtime to use.
        let parsed: OnChainManifest = toml::from_str(manifest_str).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "Failed to parse manifest: {}",
                e
            )))
        })?;
        tracing::debug!(target: "upgrade_manager", service_id=%service_id, "Parsed manifest successfully.");

        // Select the runtime based on the manifest.
        let runtime_id = parsed.runtime.to_ascii_lowercase();
        let runtime = self.runtimes.get(&runtime_id).ok_or_else(|| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "Execution runtime '{}' not found",
                runtime_id
            )))
        })?;
        tracing::debug!(target: "upgrade_manager", service_id=%service_id, "Selected runtime '{}'.", runtime_id);

        // --- Security Constraint: `manifest()` must be pure ---
        // The `manifest()` function is called here to verify the artifact's integrity
        // before it is trusted with state access. It is executed in a null state context.
        let manifest_exec_context = ioi_api::vm::ExecutionContext {
            gas_limit: 1_000_000_000, // Generous gas limit for pure manifest retrieval.
            ..Default::default()
        };
        let temp_instance_output = runtime
            .execute(
                artifact,
                "manifest",
                &[],
                &NullStateAccessor,
                manifest_exec_context,
            )
            .await
            .map_err(|e| CoreError::Upgrade(UpgradeError::InvalidUpgrade(e.to_string())))?;
        let embedded_manifest_bytes = temp_instance_output.return_data;
        let embedded_manifest_str = String::from_utf8(embedded_manifest_bytes).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "Embedded manifest is not valid UTF-8: {}",
                e
            )))
        })?;

        // Compare manifests semantically to avoid false mismatches due to whitespace or ordering.
        let stored_val: toml::Value = toml::from_str(manifest_str).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "Stored manifest TOML parse error: {}",
                e
            )))
        })?;
        let embedded_val: toml::Value = toml::from_str(&embedded_manifest_str).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "Embedded manifest TOML parse error: {}",
                e
            )))
        })?;
        if stored_val != embedded_val {
            // This is a hard failure: the code claims to be a different service than what was scheduled.
            let s_hash = ioi_crypto::algorithms::hash::sha256(manifest_str.as_bytes())
                .map(|h| hex::encode(h))
                .unwrap_or_else(|_| "<hash-error>".into());
            let e_hash = ioi_crypto::algorithms::hash::sha256(embedded_manifest_str.as_bytes())
                .map(|h| hex::encode(h))
                .unwrap_or_else(|_| "<hash-error>".into());
            log::error!(
                "Manifest mismatch for service '{}': stored_hash={}, embedded_hash={}",
                service_id,
                s_hash,
                e_hash
            );
            return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(
                "Mismatch between stored and embedded manifest".to_string(),
            )));
        }
        tracing::debug!(target: "upgrade_manager", service_id=%service_id, "Manifests match.");

        if parsed.id != service_id {
            return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(
                "Embedded manifest ID does not match service ID".to_string(),
            )));
        }

        for method_name in parsed.methods.keys() {
            if !method_name.contains('@')
                || !method_name
                    .chars()
                    .last()
                    .map_or(false, |c| c.is_ascii_digit())
            {
                return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "Invalid method name format in manifest: '{}'. Must be 'name@vN'",
                    method_name
                ))));
            }
        }

        let artifact_hash = ioi_crypto::algorithms::hash::sha256(artifact)?;
        let full_meta = parsed
            .clone()
            .to_active_meta(artifact_hash, activation_height)?;

        if !self.active_services.contains_key(service_id) {
            let new_service_arc = Arc::new(RuntimeService::new(
                parsed.id,
                parsed.abi_version,
                parsed.state_schema,
                runtime.clone(),
                artifact.to_vec(),
                full_meta.caps,
            ));
            self.register_service(new_service_arc as Arc<dyn UpgradableService>)?;
            let meta_bytes = ioi_types::codec::to_bytes_canonical(&full_meta)?;
            state
                .insert(&active_service_key(service_id), &meta_bytes)
                .map_err(|e| CoreError::Custom(e.to_string()))?;
            tracing::info!(
                target = "upgrade_manager",
                service_id=%service_id,
                height = activation_height,
                artifact_hash = %hex::encode(artifact_hash),
                "Successfully INSTALLED and ACTIVATED new service.",
            );
            return Ok(());
        }

        let active_service = self
            .active_services
            .get(service_id)
            .ok_or_else(|| CoreError::ServiceNotFound(service_id.to_string()))?;

        let snapshot = active_service.prepare_upgrade(artifact).await?;

        let new_service_arc = Arc::new(RuntimeService::new(
            parsed.id,
            parsed.abi_version,
            parsed.state_schema,
            runtime.clone(),
            artifact.to_vec(),
            full_meta.caps,
        ));

        if new_service_arc.abi_version() != active_service.abi_version() {
            return Err(CoreError::Upgrade(UpgradeError::InvalidUpgrade(
                "Incompatible ABI version".to_string(),
            )));
        }

        new_service_arc.complete_upgrade(&snapshot).await?;

        // Atomically replace the old service with the new one.
        self.active_services
            .insert(service_id.to_string(), new_service_arc);
        let meta_bytes = ioi_types::codec::to_bytes_canonical(&full_meta)?;
        state
            .insert(&active_service_key(service_id), &meta_bytes)
            .map_err(|e| CoreError::Custom(e.to_string()))?;
        tracing::info!(
            target = "upgrade_manager",
            service_id=%service_id,
            height = activation_height,
            artifact_hash = %hex::encode(artifact_hash),
            "Successfully SWAPPED and ACTIVATED service.",
        );
        Ok(())
    }

    pub fn disable_service(
        &mut self,
        service_id: &str,
        state: &mut dyn StateAccess,
    ) -> Result<(), CoreError> {
        validate_service_id(service_id)?;
        if !self.active_services.contains_key(service_id) {
            return Err(CoreError::ServiceNotFound(service_id.to_string()));
        }
        let meta_key = active_service_key(service_id);
        let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
        state
            .insert(&disabled_key, &[1])
            .map_err(|e| CoreError::Custom(e.to_string()))?;
        log::info!(
            "Service '{}' has been disabled via on-chain state.",
            service_id
        );
        Ok(())
    }

    pub fn get_upgrade_history(&self, service_id: &str) -> Vec<u64> {
        self.upgrade_history
            .get(service_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn check_all_health(&self) -> Vec<(String, bool)> {
        self.active_services
            .iter()
            .map(|(service_id, service)| {
                let is_healthy = service.health_check().is_ok();
                (service_id.clone(), is_healthy)
            })
            .collect()
    }
}

struct NullStateAccessor;

#[async_trait::async_trait]
impl VmStateAccessor for NullStateAccessor {
    async fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(None)
    }
    async fn insert(&self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Ok(())
    }
    async fn delete(&self, _key: &[u8]) -> Result<(), StateError> {
        Ok(())
    }
    async fn prefix_scan(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        Ok(Vec::new())
    }
}