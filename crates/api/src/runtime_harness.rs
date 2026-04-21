//! Product-agnostic runtime-harness facade.
//!
//! This module exposes reusable routing, retrieval, operator, verification, and
//! artifact-planning semantics without making the Chat product shell the
//! conceptual center. During migration, it re-exports the existing shared
//! `chat` module so product shells can move to a neutral namespace first,
//! while the deeper implementation continues to be extracted underneath.

pub use crate::chat::*;

pub type ArtifactOperatorRun = crate::chat::ArtifactOperatorRun;
pub type ArtifactOperatorStep = crate::chat::ArtifactOperatorStep;
pub type ArtifactOperatorRunMode = crate::chat::ArtifactOperatorRunMode;
pub type ArtifactOperatorRunStatus = crate::chat::ArtifactOperatorRunStatus;
pub type ArtifactOperatorPhase = crate::chat::ArtifactOperatorPhase;
pub type ArtifactPlanningContext = crate::chat::ChatArtifactPlanningContext;
pub type ArtifactSourcePack = crate::chat::ArtifactSourcePack;
pub type ArtifactSourceReference = crate::chat::ArtifactSourceReference;
pub type ArtifactVerificationOutcome = crate::chat::ArtifactVerificationOutcome;
pub type ArtifactVerificationRef = crate::chat::ArtifactVerificationRef;
pub type ArtifactFileRef = crate::chat::ArtifactFileRef;
pub type ArtifactRenderEvaluation = crate::chat::ChatArtifactRenderEvaluation;
pub type ArtifactResolvedRuntimePlan = crate::chat::ChatArtifactResolvedRuntimePlan;
pub type ConnectorGrounding = crate::chat::ArtifactConnectorGrounding;
pub type TopologyProjection = crate::chat::TopologyProjection;
