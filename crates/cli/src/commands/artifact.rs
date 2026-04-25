use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ioi_api::chat::{plan_chat_outcome_with_runtime, ChatArtifactRefinementContext};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::{
    ChatArtifactFailure, ChatArtifactFailureKind, ChatOutcomePlanningPayload, ChatRendererKind,
    ChatRuntimeProvenance, ChatRuntimeProvenanceKind,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod evidence;
mod generation;
mod manifest;
mod runtime;
mod types;
mod workspace;

use evidence::{
    build_generated_manifest, derive_generated_artifact_title, format_validation_label,
    load_refinement_evidence, run_validation_result, write_generated_payload,
};
#[cfg(test)]
use generation::{route_with_runtime, select_generate_route_runtime};
use generation::{run_generate, run_route};
use manifest::{
    artifact_class_label, compose_verified_reply, outcome_kind_label, prepare_output_directory,
    renderer_label, run_compose_reply, run_inspect, run_materialize, run_validate,
};
use runtime::{
    build_acceptance_inference_runtime, build_inference_runtime, runtime_provenance_matches,
};
use types::{ArtifactCommandErrorEnvelope, GeneratedArtifactEvidence};
use workspace::generate_workspace_artifact_bundle_with_runtimes;

#[derive(Parser, Debug)]
pub struct ArtifactArgs {
    #[clap(subcommand)]
    pub command: ArtifactCommands,
}

#[derive(Subcommand, Debug)]
pub enum ArtifactCommands {
    /// Inspect a Chat artifact manifest.
    Inspect {
        /// Path to a Chat artifact manifest JSON file.
        manifest: PathBuf,
        /// Emit machine-readable JSON instead of human text.
        #[clap(long)]
        json: bool,
    },
    /// Validate a Chat artifact manifest contract.
    Validate {
        /// Path to a Chat artifact manifest JSON file.
        manifest: PathBuf,
        /// Optional source root for renderer-aware validation against real files.
        #[clap(long)]
        source_root: Option<PathBuf>,
    },
    /// Materialize an artifact package/repo from a manifest and source root.
    Materialize {
        /// Path to a Chat artifact manifest JSON file.
        manifest: PathBuf,
        /// Root directory that contains the manifest's referenced files.
        #[clap(long)]
        source_root: PathBuf,
        /// Output directory for the packaged artifact.
        #[clap(long)]
        output: PathBuf,
        /// Replace the output directory if it already exists.
        #[clap(long)]
        force: bool,
    },
    /// Route or query a Chat prompt through the shared local inference contract.
    #[clap(alias = "query")]
    Route {
        /// Prompt to route.
        prompt: String,
        /// Optional active artifact id.
        #[clap(long)]
        active_artifact_id: Option<String>,
        /// Optional prior generation evidence JSON or directory containing generation.json for continuity-aware routing.
        #[clap(long)]
        refinement: Option<PathBuf>,
        /// Selected artifact target as JSON. Repeat for each target.
        #[clap(long = "selected-target-json")]
        selected_target_json: Vec<String>,
        /// Local fixture JSON returned by the inference runtime.
        #[clap(long)]
        fixture: Option<PathBuf>,
        /// Route through the local inference runtime instead of a fixture payload.
        #[clap(long, conflicts_with = "fixture")]
        local: bool,
        /// Route through Chat's mock inference runtime.
        #[clap(long, conflicts_with_all = ["fixture", "local"])]
        mock: bool,
        /// Local inference API URL (defaults to LOCAL_LLM_URL or Ollama OpenAI shim).
        #[clap(long, requires = "local")]
        api_url: Option<String>,
        /// Local inference API key when the local endpoint requires authentication.
        #[clap(long, requires = "local")]
        api_key: Option<String>,
        /// Local inference model name (defaults to LOCAL_LLM_MODEL or AUTOPILOT_LOCAL_RUNTIME_MODEL).
        #[clap(long, requires = "local")]
        model_name: Option<String>,
        /// Emit machine-readable JSON instead of human text.
        #[clap(long)]
        json: bool,
    },
    /// Generate a Chat artifact package and evidence bundle through the shared generation path.
    Generate {
        /// Prompt to generate.
        prompt: String,
        /// Output directory for the generated artifact bundle.
        #[clap(long)]
        output: PathBuf,
        /// Replace the output directory if it already exists.
        #[clap(long)]
        force: bool,
        /// Optional active artifact id for routing continuity.
        #[clap(long)]
        active_artifact_id: Option<String>,
        /// Optional prior generation evidence JSON or directory containing generation.json for patch-first refinement.
        #[clap(long)]
        refinement: Option<PathBuf>,
        /// Selected artifact target as JSON. Repeat for each target.
        #[clap(long = "selected-target-json")]
        selected_target_json: Vec<String>,
        /// Local fixture JSON returned by the inference runtime.
        #[clap(long)]
        fixture: Option<PathBuf>,
        /// Route through the local inference runtime instead of a fixture payload.
        #[clap(long, conflicts_with_all = ["fixture", "mock"])]
        local: bool,
        /// Route through Chat's mock inference runtime.
        #[clap(long, conflicts_with_all = ["fixture", "local"])]
        mock: bool,
        /// Local inference API URL (defaults to LOCAL_LLM_URL or Ollama OpenAI shim).
        #[clap(long, requires = "local")]
        api_url: Option<String>,
        /// Local inference API key when the local endpoint requires authentication.
        #[clap(long, requires = "local")]
        api_key: Option<String>,
        /// Local inference model name (defaults to LOCAL_LLM_MODEL or AUTOPILOT_LOCAL_RUNTIME_MODEL).
        #[clap(long, requires = "local")]
        model_name: Option<String>,
        /// Acceptance validation API URL for local generation proof.
        #[clap(long, requires = "local")]
        acceptance_api_url: Option<String>,
        /// Acceptance validation API key when the acceptance endpoint requires authentication.
        #[clap(long, requires = "local")]
        acceptance_api_key: Option<String>,
        /// Acceptance validation model name (defaults to AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL or OPENAI_MODEL).
        #[clap(long, requires = "local")]
        acceptance_model_name: Option<String>,
        /// Emit machine-readable JSON instead of human text.
        #[clap(long)]
        json: bool,
    },
    /// Inspect the typed validation result from a generated artifact evidence bundle.
    Validation {
        /// Path to generation.json, or a directory containing generation.json.
        evidence: PathBuf,
        /// Emit machine-readable JSON instead of human text.
        #[clap(long)]
        json: bool,
    },
    /// Compose the verification-backed reply that Chat would show for a manifest.
    ComposeReply {
        /// Path to a Chat artifact manifest JSON file.
        manifest: PathBuf,
        /// Emit machine-readable JSON instead of human text.
        #[clap(long)]
        json: bool,
    },
}

pub async fn run(args: ArtifactArgs) -> Result<()> {
    match args.command {
        ArtifactCommands::Inspect { manifest, json } => run_inspect(&manifest, json),
        ArtifactCommands::Validate {
            manifest,
            source_root,
        } => run_validate(&manifest, source_root.as_deref()),
        ArtifactCommands::Materialize {
            manifest,
            source_root,
            output,
            force,
        } => run_materialize(&manifest, &source_root, &output, force),
        ArtifactCommands::Route {
            prompt,
            active_artifact_id,
            refinement,
            selected_target_json,
            fixture,
            local,
            mock,
            api_url,
            api_key,
            model_name,
            json,
        } => {
            run_route(
                &prompt,
                active_artifact_id.as_deref(),
                refinement.as_deref(),
                &selected_target_json,
                fixture.as_deref(),
                local,
                mock,
                api_url.as_deref(),
                api_key.as_deref(),
                model_name.as_deref(),
                json,
            )
            .await
        }
        ArtifactCommands::Generate {
            prompt,
            output,
            force,
            active_artifact_id,
            refinement,
            selected_target_json,
            fixture,
            local,
            mock,
            api_url,
            api_key,
            model_name,
            acceptance_api_url,
            acceptance_api_key,
            acceptance_model_name,
            json,
        } => {
            run_generate(
                &prompt,
                &output,
                force,
                active_artifact_id.as_deref(),
                refinement.as_deref(),
                &selected_target_json,
                fixture.as_deref(),
                local,
                mock,
                api_url.as_deref(),
                api_key.as_deref(),
                model_name.as_deref(),
                acceptance_api_url.as_deref(),
                acceptance_api_key.as_deref(),
                acceptance_model_name.as_deref(),
                json,
            )
            .await
        }
        ArtifactCommands::Validation { evidence, json } => run_validation_result(&evidence, json),
        ArtifactCommands::ComposeReply { manifest, json } => run_compose_reply(&manifest, json),
    }
}

#[cfg(test)]
mod tests;
