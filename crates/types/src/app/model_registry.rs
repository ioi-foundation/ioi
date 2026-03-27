//! Typed first-party model and backend lifecycle contracts.
//!
//! These types define the absorbed control-plane receipt surface for model,
//! backend, gallery, and installation lifecycle operations.

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The kind of registry subject manipulated by a lifecycle workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum RegistrySubjectKind {
    /// A model artifact or installed model entry.
    Model,
    /// A backend runtime or backend package.
    Backend,
    /// A gallery or catalog synchronization target.
    Gallery,
    /// A long-running install or apply job.
    InstallJob,
}

impl RegistrySubjectKind {
    /// Returns a stable deterministic label for receipts and projections.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Backend => "backend",
            Self::Gallery => "gallery",
            Self::InstallJob => "install_job",
        }
    }
}

/// The specific lifecycle operation executed against a registry subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum ModelLifecycleOperationKind {
    /// Register a model, backend, or gallery entry.
    Register,
    /// Install or import an artifact.
    Install,
    /// Apply configuration or activate an installed artifact.
    Apply,
    /// Delete an existing artifact or entry.
    Delete,
    /// Load a model or backend into an active runtime slot.
    Load,
    /// Unload a model or backend from an active runtime slot.
    Unload,
    /// Start a managed backend process or service.
    Start,
    /// Stop a managed backend process or service.
    Stop,
    /// Perform an explicit health or readiness check.
    HealthCheck,
    /// Synchronize or refresh gallery metadata.
    SyncGallery,
}

impl ModelLifecycleOperationKind {
    /// Returns a stable deterministic label for receipts and projections.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Install => "install",
            Self::Apply => "apply",
            Self::Delete => "delete",
            Self::Load => "load",
            Self::Unload => "unload",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::HealthCheck => "health_check",
            Self::SyncGallery => "sync_gallery",
        }
    }
}

/// Typed receipt for an absorbed model or backend lifecycle workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WorkloadModelLifecycleReceipt {
    /// Tool that initiated the lifecycle workload.
    pub tool_name: String,
    /// Specific lifecycle operation executed.
    pub operation: ModelLifecycleOperationKind,
    /// Kind of subject targeted by the operation.
    pub subject_kind: RegistrySubjectKind,
    /// Stable subject identifier.
    pub subject_id: String,
    /// Optional backend identifier associated with the subject.
    #[serde(default)]
    pub backend_id: Option<String>,
    /// Optional source URI used for install or registration.
    #[serde(default)]
    pub source_uri: Option<String>,
    /// Optional job identifier associated with this operation.
    #[serde(default)]
    pub job_id: Option<String>,
    /// Bytes downloaded, unpacked, or otherwise transferred when known.
    #[serde(default)]
    pub bytes_transferred: Option<u64>,
    /// Optional hardware or runtime profile used to evaluate fit.
    #[serde(default)]
    pub hardware_profile: Option<String>,
    /// Success flag as surfaced by the runtime.
    pub success: bool,
    /// Optional machine-readable failure class.
    #[serde(default)]
    pub error_class: Option<String>,
}
