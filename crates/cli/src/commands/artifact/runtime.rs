use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ioi_api::studio::StudioArtifactOutputOrigin;
use ioi_api::vm::inference::{
    mock::MockInferenceRuntime, HttpInferenceRuntime, InferenceRuntime, UnavailableInferenceRuntime,
};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{StudioRuntimeProvenance, StudioRuntimeProvenanceKind};
use ioi_types::error::VmError;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(super) struct FixtureInferenceRuntime {
    pub(super) payload: String,
    pub(super) source_label: String,
}

#[async_trait]
impl InferenceRuntime for FixtureInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(self.payload.clone().into_bytes())
    }

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        Ok(Vec::new())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture runtime".to_string(),
            model: None,
            endpoint: Some(self.source_label.clone()),
        }
    }
}

pub(super) fn build_inference_runtime(
    fixture_path: Option<&Path>,
    use_local_runtime: bool,
    use_mock_runtime: bool,
    api_url: Option<&str>,
    api_key: Option<&str>,
    model_name: Option<&str>,
) -> Result<Arc<dyn InferenceRuntime>> {
    match (fixture_path, use_local_runtime, use_mock_runtime) {
        (Some(_), true, _) | (Some(_), _, true) | (None, true, true) => {
            bail!("Choose exactly one runtime source: --fixture, --local, or --mock.")
        }
        (Some(fixture_path), false, false) => {
            let payload = fs::read_to_string(fixture_path).with_context(|| {
                format!(
                    "Failed to read local inference fixture '{}'.",
                    fixture_path.display()
                )
            })?;
            Ok(Arc::new(FixtureInferenceRuntime {
                payload,
                source_label: fixture_path.display().to_string(),
            }))
        }
        (None, true, false) => {
            let runtime = resolve_local_runtime_config(api_url, api_key, model_name);
            Ok(Arc::new(HttpInferenceRuntime::new(
                runtime.api_url,
                runtime.api_key,
                runtime.model_name,
            )))
        }
        (None, false, true) => Ok(Arc::new(MockInferenceRuntime)),
        (None, false, false) => {
            bail!(
                "artifact commands require one runtime source: --fixture <path>, --local, or --mock."
            )
        }
    }
}

pub(super) fn runtime_provenance_matches(
    left: &StudioRuntimeProvenance,
    right: &StudioRuntimeProvenance,
) -> bool {
    fn normalized_runtime_endpoint(endpoint: Option<&str>) -> Option<String> {
        let endpoint = endpoint?.trim();
        if endpoint.is_empty() {
            return None;
        }

        let (without_fragment, fragment) = endpoint.split_once('#').unwrap_or((endpoint, ""));
        let Some((base, query)) = without_fragment.split_once('?') else {
            return Some(endpoint.to_string());
        };

        let filtered_pairs = query
            .split('&')
            .filter(|pair| {
                let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(*pair).trim();
                !key.is_empty() && !key.eq_ignore_ascii_case("lane")
            })
            .collect::<Vec<_>>();

        let mut normalized = base.to_string();
        if !filtered_pairs.is_empty() {
            normalized.push('?');
            normalized.push_str(&filtered_pairs.join("&"));
        }
        if !fragment.is_empty() {
            normalized.push('#');
            normalized.push_str(fragment);
        }

        Some(normalized)
    }

    left.kind == right.kind
        && left.label == right.label
        && left.model == right.model
        && normalized_runtime_endpoint(left.endpoint.as_deref())
            == normalized_runtime_endpoint(right.endpoint.as_deref())
}

pub(super) fn build_acceptance_inference_runtime(
    production_runtime: Arc<dyn InferenceRuntime>,
    fixture_path: Option<&Path>,
    use_mock_runtime: bool,
    acceptance_api_url: Option<&str>,
    acceptance_api_key: Option<&str>,
    acceptance_model_name: Option<&str>,
) -> Result<Arc<dyn InferenceRuntime>> {
    if fixture_path.is_some() || use_mock_runtime {
        return Ok(production_runtime);
    }

    let production_provenance = production_runtime.studio_runtime_provenance();
    let explicit_url = acceptance_api_url
        .map(str::to_string)
        .or_else(|| env::var("AUTOPILOT_ACCEPTANCE_RUNTIME_URL").ok());
    let explicit_api_key = acceptance_api_key
        .map(str::to_string)
        .or_else(|| env::var("AUTOPILOT_ACCEPTANCE_RUNTIME_API_KEY").ok());
    let explicit_model = acceptance_model_name
        .map(str::to_string)
        .or_else(|| env::var("AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL").ok())
        .or_else(|| env::var("AUTOPILOT_ACCEPTANCE_OPENAI_MODEL").ok());
    let openai_key = env::var("AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY")
        .ok()
        .or_else(|| env::var("OPENAI_API_KEY").ok());

    let runtime: Arc<dyn InferenceRuntime> = if let Some(url) = explicit_url {
        Arc::new(HttpInferenceRuntime::new(
            url,
            explicit_api_key.unwrap_or_default(),
            explicit_model
                .clone()
                .or_else(|| production_provenance.model.clone())
                .unwrap_or_else(|| "acceptance-judge".to_string()),
        ))
    } else if production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        || explicit_model.is_some()
    {
        if let Some(key) = openai_key {
            Arc::new(HttpInferenceRuntime::new(
                "https://api.openai.com/v1/chat/completions".to_string(),
                key,
                explicit_model
                    .or_else(|| env::var("OPENAI_MODEL").ok())
                    .unwrap_or_else(|| "gpt-4o".to_string()),
            ))
        } else {
            Arc::new(UnavailableInferenceRuntime::new(
                "Acceptance judging requires a distinct configured runtime. Set AUTOPILOT_ACCEPTANCE_RUNTIME_URL or AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY/AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL.",
            ))
        }
    } else {
        Arc::new(UnavailableInferenceRuntime::new(
            "Acceptance judging requires a distinct configured runtime. Set AUTOPILOT_ACCEPTANCE_RUNTIME_URL or AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY/AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL.",
        ))
    };

    let acceptance_provenance = runtime.studio_runtime_provenance();
    if acceptance_provenance.kind != StudioRuntimeProvenanceKind::InferenceUnavailable
        && runtime_provenance_matches(&acceptance_provenance, &production_provenance)
    {
        return Ok(Arc::new(UnavailableInferenceRuntime::new(
            "Acceptance judging requires runtime provenance distinct from the production artifact runtime.",
        )));
    }

    Ok(runtime)
}

pub(super) fn runtime_origin_label(
    provenance: &StudioRuntimeProvenance,
) -> StudioArtifactOutputOrigin {
    match provenance.kind {
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | StudioRuntimeProvenanceKind::RealLocalRuntime => {
            StudioArtifactOutputOrigin::LiveInference
        }
        StudioRuntimeProvenanceKind::FixtureRuntime => StudioArtifactOutputOrigin::FixtureRuntime,
        StudioRuntimeProvenanceKind::MockRuntime => StudioArtifactOutputOrigin::MockInference,
        StudioRuntimeProvenanceKind::DeterministicContinuityFallback => {
            StudioArtifactOutputOrigin::DeterministicFallback
        }
        StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactOutputOrigin::InferenceUnavailable
        }
        StudioRuntimeProvenanceKind::OpaqueRuntime => StudioArtifactOutputOrigin::OpaqueRuntime,
    }
}

pub(super) fn runtime_model_label(runtime: &Arc<dyn InferenceRuntime>) -> String {
    let provenance = runtime.studio_runtime_provenance();
    provenance.model.unwrap_or(provenance.label)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalRouteRuntimeConfig {
    pub(super) api_url: String,
    pub(super) api_key: String,
    pub(super) model_name: String,
}

pub(super) fn resolve_local_runtime_config(
    api_url: Option<&str>,
    api_key: Option<&str>,
    model_name: Option<&str>,
) -> LocalRouteRuntimeConfig {
    LocalRouteRuntimeConfig {
        api_url: api_url
            .map(str::to_string)
            .or_else(|| env::var("LOCAL_LLM_URL").ok())
            .or_else(|| env::var("AUTOPILOT_LOCAL_RUNTIME_URL").ok())
            .unwrap_or_else(|| "http://localhost:11434/v1/chat/completions".to_string()),
        api_key: api_key
            .map(str::to_string)
            .or_else(|| env::var("LOCAL_LLM_API_KEY").ok())
            .or_else(|| env::var("AUTOPILOT_LOCAL_RUNTIME_API_KEY").ok())
            .unwrap_or_default(),
        model_name: model_name
            .map(str::to_string)
            .or_else(|| env::var("LOCAL_LLM_MODEL").ok())
            .or_else(|| env::var("AUTOPILOT_LOCAL_RUNTIME_MODEL").ok())
            .unwrap_or_else(|| "llama3".to_string()),
    }
}
