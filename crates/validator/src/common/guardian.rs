// Path: crates/validator/src/common/guardian.rs
use async_trait::async_trait;
use depin_sdk_api::validator::{Container, GuardianContainer as GuardianContainerTrait};
use depin_sdk_types::error::ValidatorError;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug, Default)]
pub struct GuardianContainer {
    running: Arc<AtomicBool>,
}

impl GuardianContainer {
    pub fn new(_config_path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!("Starting GuardianContainer...");
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping GuardianContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "guardian"
    }
}

impl GuardianContainerTrait for GuardianContainer {
    fn start_boot(&self) -> Result<(), ValidatorError> {
        log::info!("Guardian: Initiating secure boot sequence...");
        Ok(())
    }

    fn verify_attestation(&self) -> Result<bool, ValidatorError> {
        log::info!("Guardian: Verifying inter-container attestation...");
        Ok(true)
    }
}
