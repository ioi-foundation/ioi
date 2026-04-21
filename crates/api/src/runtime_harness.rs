//! Product-agnostic runtime-harness facade.
//!
//! This module exposes reusable routing, retrieval, operator, verification, and
//! artifact-planning semantics without making the Studio product shell the
//! conceptual center. During migration, it re-exports the existing shared
//! `studio` module so product shells can move to a neutral namespace first,
//! while the deeper implementation continues to be extracted underneath.

pub use crate::studio::*;

pub type ArtifactOperatorRun = crate::studio::ArtifactOperatorRun;
pub type ArtifactOperatorStep = crate::studio::ArtifactOperatorStep;
pub type ArtifactOperatorRunMode = crate::studio::ArtifactOperatorRunMode;
pub type ArtifactOperatorRunStatus = crate::studio::ArtifactOperatorRunStatus;
pub type ArtifactOperatorPhase = crate::studio::ArtifactOperatorPhase;
pub type ArtifactPlanningContext = crate::studio::StudioArtifactPlanningContext;
pub type ArtifactSourcePack = crate::studio::ArtifactSourcePack;
pub type ArtifactSourceReference = crate::studio::ArtifactSourceReference;
pub type ArtifactVerificationOutcome = crate::studio::ArtifactVerificationOutcome;
pub type ArtifactVerificationRef = crate::studio::ArtifactVerificationRef;
pub type ArtifactFileRef = crate::studio::ArtifactFileRef;
pub type ArtifactRenderEvaluation = crate::studio::StudioArtifactRenderEvaluation;
pub type ArtifactResolvedRuntimePlan = crate::studio::StudioArtifactResolvedRuntimePlan;
pub type ConnectorGrounding = crate::studio::ArtifactConnectorGrounding;
pub type TopologyProjection = crate::studio::TopologyProjection;
