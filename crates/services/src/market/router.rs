// Path: crates/services/src/market/router.rs

use anyhow::Result;
use ioi_drivers::provisioning::{CloudProvider, InstanceHandle, InstanceSpec};
use ioi_types::app::agentic::{AgentManifest, RuntimeEnvironment};
use ioi_types::config::WorkloadConfig; // Removed ConnectorConfig unused import
use std::collections::HashMap;
use std::sync::Arc;

/// Orchestrates the provisioning of infrastructure based on Agent Manifests.
pub struct ProvisioningRouter {
    providers: HashMap<String, Arc<dyn CloudProvider>>,
}

impl ProvisioningRouter {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Initializes providers based on the node configuration.
    /// This allows dynamic loading of AWS/Akash based on user keys.
    pub fn load_from_config(&mut self, config: &WorkloadConfig) {
        // AWS
        if let Some(aws_cfg) = config.connectors.get("aws_primary") {
            if aws_cfg.enabled {
                // [FIX] Convert string literals to String
                let p = ioi_drivers::provisioning::aws::AwsProvider::new(
                    "mock_key".to_string(),
                    "mock_secret".to_string(),
                    "us-east-1".to_string(),
                );
                self.providers.insert("aws".to_string(), Arc::new(p));
            }
        }

        // Akash
        if let Some(akash_cfg) = config.connectors.get("akash_wallet") {
            if akash_cfg.enabled {
                let p =
                    ioi_drivers::provisioning::akash::AkashProvider::new(akash_cfg.key_ref.clone());
                self.providers.insert("akash".to_string(), Arc::new(p));
            }
        }
    }

    /// Converts an AgentManifest into a concrete InstanceSpec.
    fn map_manifest_to_spec(&self, manifest: &AgentManifest) -> InstanceSpec {
        let image = match &manifest.runtime {
            RuntimeEnvironment::Docker { image_cid, .. } => image_cid.clone(),
            _ => "ioi-standard-runtime:latest".to_string(),
        };

        InstanceSpec {
            image,
            cpu: manifest.resources.min_cpus,
            memory_mb: (manifest.resources.min_ram_gb as u64) * 1024,
            gpu_type: None, // Logic to map manifest tags to GPU types would go here
            region: None,
        }
    }

    /// Dispatches a provisioning request.
    pub async fn launch_agent(&self, manifest: &AgentManifest) -> Result<InstanceHandle> {
        let spec = self.map_manifest_to_spec(manifest);

        // 1. Determine Preferred Provider
        let pref = &manifest.resources.provider_preference;

        let provider = if let Some(p) = self.providers.get(pref) {
            p
        } else {
            // Fallback strategy: Try decentralized first, then centralized
            if let Some(p) = self.providers.get("akash") {
                p
            } else if let Some(p) = self.providers.get("aws") {
                p
            } else {
                return Err(anyhow::anyhow!("No suitable cloud provider configured"));
            }
        };

        // 2. Estimate Cost & Check Policy (omitted for brevity, assume checked by MarketService)

        // 3. Provision
        provider.provision(&spec).await
    }
}
