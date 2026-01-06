// Path: crates/validator/src/standard/workload/hydration.rs

use anyhow::{anyhow, Result};
use ioi_api::vm::inference::HardwareDriver;
use ioi_crypto::algorithms::hash::sha256;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Manages the lifecycle of model artifacts (fetching, verifying, loading).
pub struct ModelHydrator {
    storage_dir: PathBuf,
    driver: Arc<dyn HardwareDriver>,
    // Track loaded models to prevent redundant IO/hashing
    loaded_models: Mutex<std::collections::HashSet<[u8; 32]>>,
}

impl ModelHydrator {
    /// Creates a new `ModelHydrator`.
    ///
    /// # Arguments
    /// * `storage_dir` - The local directory where model artifacts are cached.
    /// * `driver` - The hardware driver used to load models into accelerator memory.
    pub fn new(storage_dir: PathBuf, driver: Arc<dyn HardwareDriver>) -> Self {
        Self {
            storage_dir,
            driver,
            loaded_models: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// The "JIT Hydration" flow.
    /// 1. Check if model is already on device (Warm Start).
    /// 2. If not, check if file exists locally.
    /// 3. Verify file hash (Integrity Check).
    /// 4. Load into driver (VRAM).
    pub async fn hydrate(&self, model_hash: [u8; 32], _cid: &str) -> Result<()> {
        let hex_hash = hex::encode(model_hash);

        // 1. Warm Start Check
        if self.driver.is_model_loaded(&model_hash).await {
            tracing::debug!(target: "workload", "Model {} is already loaded (Warm).", hex_hash);
            return Ok(());
        }

        // 2. Resolve Path (Simulate IPFS/CAS resolution)
        // In a real impl, `cid` would resolve to a path in `storage_dir`.
        // For now, we assume the file is named `{hash}.bin` in storage_dir.
        let model_path = self.storage_dir.join(format!("{}.bin", hex_hash));

        if !model_path.exists() {
            // In Phase 3, this triggers a p2p fetch.
            return Err(anyhow!(
                "Model artifact not found locally: {:?}",
                model_path
            ));
        }

        // 3. Integrity Check (The "Safety Sandwich" bottom bread)
        // We MUST verify the hash matches the request before loading into VRAM.
        tracing::info!(target: "workload", "Verifying integrity of {}", hex_hash);
        let bytes = tokio::fs::read(&model_path).await?;
        let computed_hash = sha256(&bytes)?;

        if computed_hash != model_hash {
            return Err(anyhow!(
                "Model integrity failure! Expected {}, got {}",
                hex_hash,
                hex::encode(computed_hash)
            ));
        }

        // 4. Load to Hardware
        tracing::info!(target: "workload", "Loading model {} into accelerator...", hex_hash);
        self.driver
            .load_model(model_hash, &model_path, &[])
            .await
            .map_err(|e| anyhow!("Driver load failed: {:?}", e))?;

        let mut cache = self.loaded_models.lock().await;
        cache.insert(model_hash);

        Ok(())
    }
}
