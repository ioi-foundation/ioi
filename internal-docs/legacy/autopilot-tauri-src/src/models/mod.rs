// apps/autopilot/src-tauri/src/models.rs
mod app_state;
mod atlas;
mod capabilities;
mod chat;
mod events;
mod knowledge;
mod local_engine;
mod notifications;
mod plugins;
mod session;
mod session_compaction;
mod session_continuity;
mod voice;

pub use app_state::*;
pub use atlas::*;
pub use capabilities::*;
pub use chat::*;
pub use events::*;
pub use knowledge::*;
pub use local_engine::*;
pub use notifications::*;
pub use plugins::*;
pub use session::*;
pub use session_compaction::*;
pub use session_continuity::*;
pub use voice::*;

pub use ioi_api::chat::{ChatArtifactValidationResult, ChatArtifactValidationStatus};
pub use ioi_types::app::{
    ChatArtifactClass, ChatArtifactDeliverableShape, ChatArtifactFailure, ChatArtifactFailureKind,
    ChatArtifactFileRole, ChatArtifactLifecycleState, ChatArtifactManifest,
    ChatArtifactManifestFile, ChatArtifactManifestStorage, ChatArtifactManifestTab,
    ChatArtifactManifestVerification, ChatArtifactPersistenceMode, ChatArtifactTabKind,
    ChatArtifactVerificationStatus, ChatExecutionSubstrate, ChatOutcomeArtifactRequest,
    ChatOutcomeArtifactScope, ChatOutcomeArtifactVerificationRequest, ChatOutcomeKind,
    ChatOutcomeRequest, ChatPresentationSurface, ChatRendererKind, ChatRetainedWidgetState,
    ChatRuntimeProvenance, ChatRuntimeProvenanceKind, ChatVerifiedReply,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
