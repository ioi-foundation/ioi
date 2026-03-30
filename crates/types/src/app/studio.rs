#![allow(missing_docs)]
//! Shared Studio outcome and artifact contracts.
//!
//! These types define the schema for outcome routing, artifact manifests, and
//! verification-backed replies so that Studio surfaces and CLI tooling can
//! operate on the same typed work product language.

use serde::{Deserialize, Serialize};

/// The top-level outcome class selected by Studio's router.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioOutcomeKind {
    Conversation,
    ToolWidget,
    Visualizer,
    Artifact,
}

/// The broad class of artifact being produced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactClass {
    Document,
    Visual,
    InteractiveSingleFile,
    DownloadableFile,
    WorkspaceProject,
    CompoundBundle,
    CodePatch,
    ReportBundle,
}

/// The deliverable shape for a Studio artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactDeliverableShape {
    SingleFile,
    FileSet,
    WorkspaceProject,
}

/// The renderer backend used to present the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioRendererKind {
    Markdown,
    HtmlIframe,
    JsxSandbox,
    Svg,
    Mermaid,
    PdfEmbed,
    DownloadCard,
    WorkspaceSurface,
    BundleManifest,
}

/// The presentation surface used in the product shell.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioPresentationSurface {
    Inline,
    SidePanel,
    Overlay,
    TabbedPanel,
}

/// The persistence mode available to the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactPersistenceMode {
    Ephemeral,
    ArtifactScoped,
    SharedArtifactScoped,
    WorkspaceFilesystem,
}

/// The execution substrate required to materialize the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioExecutionSubstrate {
    None,
    ClientSandbox,
    BinaryGenerator,
    WorkspaceRuntime,
}

/// The tab kinds supported by the artifact host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactTabKind {
    Render,
    Source,
    Download,
    Evidence,
    Workspace,
}

/// The role a file plays inside an artifact package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactFileRole {
    Primary,
    Source,
    Export,
    Supporting,
}

/// Verification state for the manifest as currently known by Studio.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactVerificationStatus {
    Ready,
    Blocked,
    Failed,
    Partial,
}

/// Truthful runtime provenance for Studio generation and judging.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioRuntimeProvenanceKind {
    RealRemoteModelRuntime,
    RealLocalRuntime,
    FixtureRuntime,
    MockRuntime,
    DeterministicContinuityFallback,
    InferenceUnavailable,
    OpaqueRuntime,
}

/// Shared Studio runtime provenance surfaced in manifests, evidence, and UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRuntimeProvenance {
    pub kind: StudioRuntimeProvenanceKind,
    pub label: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Explicit typed artifact failure surfaced when Studio cannot truthfully
/// produce or judge an artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactFailureKind {
    InferenceUnavailable,
    RoutingFailure,
    GenerationFailure,
    VerificationFailure,
}

/// Failure payload persisted across Studio surfaces instead of being hidden
/// behind substitute artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactFailure {
    pub kind: StudioArtifactFailureKind,
    pub code: String,
    pub message: String,
}

/// Explicit lifecycle state for a Studio artifact session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactLifecycleState {
    Draft,
    Planned,
    Materializing,
    Rendering,
    Implementing,
    Verifying,
    Ready,
    Partial,
    Blocked,
    Failed,
}

/// Scope and mutation boundaries for artifact work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactScope {
    pub target_project: Option<String>,
    pub create_new_workspace: bool,
    pub mutation_boundary: Vec<String>,
}

/// Verification requests attached to an artifact plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactVerificationRequest {
    pub require_render: bool,
    pub require_build: bool,
    pub require_preview: bool,
    pub require_export: bool,
    pub require_diff_review: bool,
}

/// Typed artifact request emitted by the router.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactRequest {
    pub artifact_class: StudioArtifactClass,
    pub deliverable_shape: StudioArtifactDeliverableShape,
    pub renderer: StudioRendererKind,
    pub presentation_surface: StudioPresentationSurface,
    pub persistence: StudioArtifactPersistenceMode,
    pub execution_substrate: StudioExecutionSubstrate,
    pub workspace_recipe_id: Option<String>,
    pub presentation_variant_id: Option<String>,
    pub scope: StudioOutcomeArtifactScope,
    pub verification: StudioOutcomeArtifactVerificationRequest,
}

/// The top-level typed outcome router result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeRequest {
    pub request_id: String,
    pub raw_prompt: String,
    pub active_artifact_id: Option<String>,
    pub outcome_kind: StudioOutcomeKind,
    pub confidence: f32,
    pub needs_clarification: bool,
    pub clarification_questions: Vec<String>,
    pub artifact: Option<StudioOutcomeArtifactRequest>,
}

/// Raw planner payload emitted by inference before request IDs are assigned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomePlanningPayload {
    pub outcome_kind: StudioOutcomeKind,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub needs_clarification: bool,
    #[serde(default)]
    pub clarification_questions: Vec<String>,
    #[serde(default)]
    pub artifact: Option<StudioOutcomeArtifactRequest>,
}

/// A tab entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestTab {
    pub id: String,
    pub label: String,
    pub kind: StudioArtifactTabKind,
    pub renderer: Option<StudioRendererKind>,
    pub file_path: Option<String>,
    pub lens: Option<String>,
}

/// A file entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestFile {
    pub path: String,
    pub mime: String,
    pub role: StudioArtifactFileRole,
    pub renderable: bool,
    pub downloadable: bool,
    pub artifact_id: Option<String>,
    pub external_url: Option<String>,
}

/// Verification summary embedded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestVerification {
    pub status: StudioArtifactVerificationStatus,
    pub lifecycle_state: StudioArtifactLifecycleState,
    pub summary: String,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
}

/// Storage capabilities exposed by the artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestStorage {
    pub mode: StudioArtifactPersistenceMode,
    pub api_label: Option<String>,
}

/// Canonical manifest for a Studio artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifest {
    pub artifact_id: String,
    pub title: String,
    pub artifact_class: StudioArtifactClass,
    pub renderer: StudioRendererKind,
    pub primary_tab: String,
    pub tabs: Vec<StudioArtifactManifestTab>,
    pub files: Vec<StudioArtifactManifestFile>,
    pub verification: StudioArtifactManifestVerification,
    pub storage: Option<StudioArtifactManifestStorage>,
}

/// Verification-backed reply composed from the artifact state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioVerifiedReply {
    pub status: StudioArtifactVerificationStatus,
    pub lifecycle_state: StudioArtifactLifecycleState,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
    pub updated_at: String,
}
