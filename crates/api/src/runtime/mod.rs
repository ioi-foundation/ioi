// Path: crates/api/src/runtime/mod.rs
use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Failed to load artifact: {0}")]
    LoadFailed(String),
    #[error("Entrypoint '{0}' not found")]
    EntrypointNotFound(String),
    #[error("Execution call failed: {0}")]
    CallFailed(String),
}

/// A trait for a runtime that can load code artifacts.
#[async_trait]
pub trait Runtime: Send + Sync {
    /// Loads a binary artifact and returns a callable instance.
    async fn load(&self, artifact: &[u8]) -> Result<Box<dyn Runnable>, RuntimeError>;
}

/// A trait for a loaded, runnable artifact.
#[async_trait]
pub trait Runnable: Send + Sync {
    /// Calls an entrypoint with SCALE-encoded request bytes.
    async fn call(
        &mut self,
        entrypoint: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, RuntimeError>;
}