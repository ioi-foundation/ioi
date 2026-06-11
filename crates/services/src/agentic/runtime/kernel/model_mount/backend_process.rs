use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    option_trimmed, require_non_empty, sha256_hex, ModelMountError,
    MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModelMountBackendProcessLoadOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_model_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tensor_parallel_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_memory_utilization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default)]
    pub embeddings: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessPlanRequest {
    pub schema_version: String,
    pub backend_ref: String,
    pub backend_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default)]
    pub binary_configured: bool,
    #[serde(default)]
    pub load_options: ModelMountBackendProcessLoadOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessPlan {
    pub schema_version: String,
    pub backend_ref: String,
    pub backend_kind: String,
    pub supports_supervision: bool,
    pub supervisor_kind: String,
    pub public_args: Vec<String>,
    pub spawn_args: Vec<String>,
    pub spawn_required: bool,
    pub spawn_status: String,
    pub evidence_refs: Vec<String>,
    pub plan_hash: String,
}

impl ModelMountBackendProcessPlanRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("backend_ref", &self.backend_ref)?;
        require_non_empty("backend_kind", &self.backend_kind)?;
        Ok(())
    }
}

pub(super) fn plan_backend_process(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<ModelMountBackendProcessPlan, ModelMountError> {
    request.validate()?;
    let supports_supervision = backend_supports_supervision(&request.backend_kind);
    let mut plan = ModelMountBackendProcessPlan {
        schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
        backend_ref: request.backend_ref.clone(),
        backend_kind: request.backend_kind.clone(),
        supports_supervision,
        supervisor_kind: backend_supervisor_kind(request),
        public_args: backend_process_public_args(request)?,
        spawn_args: backend_process_spawn_args(request)?,
        spawn_required: backend_spawn_required(request, supports_supervision),
        spawn_status: backend_spawn_status(request, supports_supervision),
        evidence_refs: backend_process_evidence_refs(request, supports_supervision),
        plan_hash: String::new(),
    };
    plan.plan_hash = backend_process_plan_hash(&plan)?;
    Ok(plan)
}

fn backend_supports_supervision(backend_kind: &str) -> bool {
    matches!(
        backend_kind.trim(),
        "native_local" | "llama_cpp" | "ollama" | "vllm"
    )
}

fn backend_supervisor_kind(request: &ModelMountBackendProcessPlanRequest) -> String {
    if request.backend_kind.trim() == "native_local" {
        "deterministic_fixture_process".to_string()
    } else if backend_supports_supervision(&request.backend_kind) {
        "external_process".to_string()
    } else {
        "unsupported".to_string()
    }
}

fn backend_process_public_args(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<Vec<String>, ModelMountError> {
    let model_arg = request
        .model_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("runtime-engine-profile");
    let context_length = request
        .load_options
        .context_length
        .or(request.load_options.max_model_len);
    let parallel = request
        .load_options
        .parallel
        .or(request.load_options.tensor_parallel_size);
    let artifact_path_hash = request
        .artifact_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            sha256_hex(value.as_bytes()).map(|hash| hash.chars().take(16).collect::<String>())
        })
        .transpose()?;
    let mut args = Vec::new();
    match request.backend_kind.trim() {
        "llama_cpp" => {
            args.extend(["llama-server".to_string(), "--model".to_string()]);
            args.push(
                artifact_path_hash
                    .map(|hash| format!("artifact:{hash}"))
                    .unwrap_or_else(|| model_arg.to_string()),
            );
            if let Some(value) = context_length {
                args.extend(["--ctx-size".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend(["--gpu-layers".to_string(), llama_cpp_gpu_layers_arg(value)]);
            }
        }
        "vllm" => {
            args.extend(["vllm".to_string(), "serve".to_string()]);
            args.push(
                artifact_path_hash
                    .map(|hash| format!("artifact:{hash}"))
                    .unwrap_or_else(|| model_arg.to_string()),
            );
            if let Some(value) = context_length {
                args.extend(["--max-model-len".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--tensor-parallel-size".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.dtype) {
                args.extend(["--dtype".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu_memory_utilization) {
                args.extend(["--gpu-memory-utilization".to_string(), value.to_string()]);
            }
        }
        "ollama" => {
            args.extend(["ollama".to_string(), "serve".to_string()]);
        }
        "native_local" => {
            args.extend([
                "ioi-native-local-fixture".to_string(),
                "--model".to_string(),
                model_arg.to_string(),
            ]);
            if let Some(value) = context_length {
                args.extend(["--context".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend(["--gpu".to_string(), value.to_string()]);
            }
        }
        other => {
            args.extend([
                other.to_string(),
                "--model".to_string(),
                model_arg.to_string(),
            ]);
        }
    }
    if let Some(value) = option_trimmed(&request.load_options.identifier) {
        let hash = sha256_hex(value.as_bytes())?;
        args.extend(["--identifier".to_string(), hash.chars().take(12).collect()]);
    }
    Ok(args)
}

fn backend_process_spawn_args(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<Vec<String>, ModelMountError> {
    match request.backend_kind.trim() {
        "ollama" => Ok(vec!["serve".to_string()]),
        "vllm" => {
            let mut args = vec!["serve".to_string(), backend_spawn_model_arg(request)];
            let bind = backend_bind_address(request.base_url.as_deref());
            if let Some(host) = bind.0 {
                args.extend(["--host".to_string(), host]);
            }
            if let Some(port) = bind.1 {
                args.extend(["--port".to_string(), port]);
            }
            let context_length = request
                .load_options
                .max_model_len
                .or(request.load_options.context_length);
            let parallel = request
                .load_options
                .tensor_parallel_size
                .or(request.load_options.parallel);
            if let Some(value) = context_length {
                args.extend(["--max-model-len".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--tensor-parallel-size".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.dtype) {
                args.extend(["--dtype".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu_memory_utilization) {
                args.extend(["--gpu-memory-utilization".to_string(), value.to_string()]);
            }
            Ok(args)
        }
        "llama_cpp" => {
            let mut args = Vec::new();
            if let Some(model_path) = backend_model_path(request) {
                args.extend(["--model".to_string(), model_path]);
            }
            if let Some(value) = request.load_options.context_length {
                args.extend(["--ctx-size".to_string(), value.to_string()]);
            }
            if let Some(value) = request.load_options.parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend([
                    "--n-gpu-layers".to_string(),
                    llama_cpp_gpu_layers_arg(value),
                ]);
            }
            if request.load_options.embeddings {
                args.push("--embedding".to_string());
            }
            let bind = backend_bind_address(request.base_url.as_deref());
            if let Some(host) = bind.0 {
                args.extend(["--host".to_string(), host]);
            }
            if let Some(port) = bind.1 {
                args.extend(["--port".to_string(), port]);
            }
            Ok(args)
        }
        _ => Ok(backend_process_public_args(request)?
            .into_iter()
            .skip(1)
            .collect()),
    }
}

fn backend_spawn_required(request: &ModelMountBackendProcessPlanRequest, supports: bool) -> bool {
    if !supports || request.backend_kind.trim() == "native_local" || !request.binary_configured {
        return false;
    }
    request.backend_kind.trim() != "llama_cpp" || backend_model_path(request).is_some()
}

fn backend_spawn_status(request: &ModelMountBackendProcessPlanRequest, supports: bool) -> String {
    if !supports || request.backend_kind.trim() == "native_local" {
        return "not_required".to_string();
    }
    if !request.binary_configured {
        return "binary_absent".to_string();
    }
    if request.backend_kind.trim() == "llama_cpp" && backend_model_path(request).is_none() {
        return "waiting_for_model".to_string();
    }
    "spawn_ready".to_string()
}

fn backend_process_evidence_refs(
    request: &ModelMountBackendProcessPlanRequest,
    supports: bool,
) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_backend_process_plan".to_string()];
    if supports {
        refs.push(format!(
            "rust_model_mount_{}_backend_process",
            request.backend_kind.trim()
        ));
    } else {
        refs.push("rust_model_mount_backend_process_not_supervised".to_string());
    }
    refs.push(backend_spawn_status(request, supports));
    refs
}

fn backend_spawn_model_arg(request: &ModelMountBackendProcessPlanRequest) -> String {
    backend_model_path(request)
        .or_else(|| option_trimmed(&request.load_options.model).map(str::to_string))
        .or_else(|| {
            request
                .model_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "runtime-engine-profile".to_string())
}

fn backend_model_path(request: &ModelMountBackendProcessPlanRequest) -> Option<String> {
    request
        .artifact_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| option_trimmed(&request.load_options.model_path).map(str::to_string))
}

fn backend_bind_address(base_url: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(base_url) = base_url.map(str::trim).filter(|value| !value.is_empty()) else {
        return (None, None);
    };
    let Some(authority) = base_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
    else {
        return (None, None);
    };
    let mut parts = authority.rsplitn(2, ':');
    let port = parts
        .next()
        .filter(|value| value.chars().all(|c| c.is_ascii_digit()));
    let host = if port.is_some() {
        parts.next().unwrap_or(authority)
    } else {
        authority
    };
    (
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        },
        port.map(str::to_string),
    )
}

fn llama_cpp_gpu_layers_arg(value: &str) -> String {
    if value == "auto" {
        "-1".to_string()
    } else {
        value.to_string()
    }
}

fn backend_process_plan_hash(
    plan: &ModelMountBackendProcessPlan,
) -> Result<String, ModelMountError> {
    let mut canonical = plan.clone();
    canonical.plan_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
