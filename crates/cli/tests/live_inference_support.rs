use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc::Sender;

pub const OPENAI_CHAT_COMPLETIONS_URL: &str = "https://api.openai.com/v1/chat/completions";

fn load_env_file_if_present(path: &str) {
    let Some(resolved_path) = find_env_file(path) else {
        return;
    };

    let Ok(contents) = std::fs::read_to_string(resolved_path) else {
        return;
    };

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if !value.is_empty() {
            std::env::set_var(key, value);
        }
    }
}

fn candidate_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if !roots.iter().any(|existing| existing == &manifest_dir) {
        roots.push(manifest_dir);
    }

    roots
}

fn find_env_file(file_name: &str) -> Option<PathBuf> {
    for root in candidate_search_roots() {
        let mut cursor = Some(root);
        while let Some(path) = cursor {
            let candidate = path.join(file_name);
            if candidate.is_file() {
                return Some(candidate);
            }
            cursor = path.parent().map(|parent| parent.to_path_buf());
        }
    }

    None
}

pub fn load_env_from_workspace_dotenv_if_present() {
    load_env_file_if_present(".env");
}

pub fn configured_model_candidates(explicit_env: &str, default_env: &str) -> Vec<String> {
    let explicit = std::env::var(explicit_env)
        .ok()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if !explicit.is_empty() {
        return explicit;
    }

    let mut candidates = Vec::new();
    if let Ok(model) = std::env::var(default_env) {
        let trimmed = model.trim();
        if !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
    }

    for candidate in ["gpt-4o-mini", "gpt-3.5-turbo"] {
        if !candidates
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(candidate))
        {
            candidates.push(candidate.to_string());
        }
    }

    candidates
}

pub async fn probe_http_inference_model(api_url: &str, api_key: &str, model: &str) -> Result<()> {
    let runtime =
        HttpInferenceRuntime::new(api_url.to_string(), api_key.to_string(), model.to_string());
    let response = runtime
        .execute_inference([0u8; 32], b"Reply with ok.", InferenceOptions::default())
        .await
        .map_err(|err| anyhow!("model probe failed for '{}': {}", model, err))?;
    if response.is_empty() {
        return Err(anyhow!(
            "model probe returned empty response for '{}'",
            model
        ));
    }
    Ok(())
}

pub async fn select_http_inference_model(
    api_url: &str,
    api_key: &str,
    candidates: &[String],
    selection_label: &str,
) -> Result<String> {
    let mut failures = Vec::new();
    for model in candidates {
        match probe_http_inference_model(api_url, api_key, model).await {
            Ok(()) => {
                println!("{}={}", selection_label, model);
                return Ok(model.clone());
            }
            Err(err) => failures.push(err.to_string()),
        }
    }

    Err(anyhow!(
        "no runnable inference model found for {}. attempted_models={:?} failures={:?}",
        selection_label,
        candidates,
        failures
    ))
}

pub struct CountingInferenceRuntime {
    inner: Arc<dyn InferenceRuntime>,
    call_count: AtomicUsize,
    call_records: Mutex<Vec<InferenceCallRecord>>,
}

impl CountingInferenceRuntime {
    pub fn new(inner: Arc<dyn InferenceRuntime>) -> Self {
        Self {
            inner,
            call_count: AtomicUsize::new(0),
            call_records: Mutex::new(Vec::new()),
        }
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn call_records(&self) -> Vec<InferenceCallRecord> {
        self.call_records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InferenceCallRecord {
    pub ordinal: usize,
    pub method: &'static str,
    pub model_hash_hex: String,
    pub input_utf8: Option<String>,
    pub output_utf8: Option<String>,
    pub error: Option<String>,
}

impl CountingInferenceRuntime {
    fn record_call(
        &self,
        ordinal: usize,
        method: &'static str,
        model_hash: [u8; 32],
        input_context: &[u8],
        outcome: &Result<Vec<u8>, VmError>,
    ) {
        let record = InferenceCallRecord {
            ordinal,
            method,
            model_hash_hex: hex::encode(model_hash),
            input_utf8: String::from_utf8(input_context.to_vec()).ok(),
            output_utf8: outcome
                .as_ref()
                .ok()
                .and_then(|bytes| String::from_utf8(bytes.clone()).ok()),
            error: outcome.as_ref().err().map(ToString::to_string),
        };
        if let Ok(mut records) = self.call_records.lock() {
            records.push(record);
        }
    }
}

#[async_trait]
impl InferenceRuntime for CountingInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let ordinal = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let outcome = self
            .inner
            .execute_inference(model_hash, input_context, options)
            .await;
        self.record_call(ordinal, "execute_inference", model_hash, input_context, &outcome);
        outcome
    }

    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let ordinal = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let outcome = self
            .inner
            .execute_inference_streaming(model_hash, input_context, options, token_stream)
            .await;
        self.record_call(
            ordinal,
            "execute_inference_streaming",
            model_hash,
            input_context,
            &outcome,
        );
        outcome
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        self.inner.embed_text(text).await
    }

    async fn embed_image(&self, image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
        self.inner.embed_image(image_bytes).await
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        self.inner.load_model(model_hash, path).await
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        self.inner.unload_model(model_hash).await
    }
}
