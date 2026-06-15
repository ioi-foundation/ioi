use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

pub fn plan_model_mount_backend_process(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_backend_process(request)?;
    Ok(json!({
        "source": "rust_daemon_core.model_mount.backend_process",
        "result": plan.clone(),
        "supports_supervision": plan.supports_supervision,
        "supervisor_kind": plan.supervisor_kind,
        "public_args": plan.public_args,
        "spawn_args": plan.spawn_args,
        "spawn_required": plan.spawn_required,
        "spawn_status": plan.spawn_status,
        "plan_hash": plan.plan_hash,
        "evidence_refs": plan.evidence_refs,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;
    fn backend_process_plan_request() -> ModelMountBackendProcessPlanRequest {
        ModelMountBackendProcessPlanRequest {
            schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
            backend_ref: "backend.llama".to_string(),
            backend_kind: "llama_cpp".to_string(),
            base_url: Some("http://127.0.0.1:8091/v1".to_string()),
            model_ref: Some("model://qwen/qwen3.5-9b".to_string()),
            artifact_path: Some("/models/private/model.gguf".to_string()),
            binary_configured: true,
            load_options: ModelMountBackendProcessLoadOptions {
                context_length: Some(4096),
                parallel: Some(2),
                gpu: Some("auto".to_string()),
                identifier: Some("llama profile".to_string()),
                embeddings: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn backend_process_plan_owns_supervision_args_and_readiness() {
        let plan =
            plan_backend_process(&backend_process_plan_request()).expect("backend process planned");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION
        );
        assert!(plan.supports_supervision);
        assert_eq!(plan.supervisor_kind, "external_process");
        assert_eq!(plan.spawn_status, "spawn_ready");
        assert!(plan.spawn_required);
        assert_eq!(plan.public_args[0], "llama-server");
        assert_eq!(plan.public_args[1], "--model");
        assert!(plan.public_args[2].starts_with("artifact:"));
        assert!(plan.public_args.contains(&"--gpu-layers".to_string()));
        assert!(plan.public_args.contains(&"-1".to_string()));
        assert_eq!(plan.spawn_args[0], "--model");
        assert_eq!(plan.spawn_args[1], "/models/private/model.gguf");
        assert!(plan.spawn_args.contains(&"--embedding".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_plan".to_string()));
        assert!(plan.plan_hash.starts_with("sha256:"));
    }

    #[test]
    fn backend_process_plan_blocks_llama_spawn_without_model_artifact() {
        let mut request = backend_process_plan_request();
        request.artifact_path = None;
        request.load_options.model_path = None;

        let plan = plan_backend_process(&request).expect("backend process planned");

        assert!(plan.supports_supervision);
        assert!(!plan.spawn_required);
        assert_eq!(plan.spawn_status, "waiting_for_model");
        assert!(!plan.spawn_args.contains(&"--model".to_string()));
    }

    #[test]
    fn backend_process_plan_supports_vllm_bind_spawn_args() {
        let mut request = backend_process_plan_request();
        request.backend_ref = "backend.vllm".to_string();
        request.backend_kind = "vllm".to_string();
        request.base_url = Some("http://0.0.0.0:8092/v1".to_string());
        request.artifact_path = None;
        request.load_options = ModelMountBackendProcessLoadOptions {
            model_path: Some("/models/raw/vllm".to_string()),
            max_model_len: Some(16384),
            tensor_parallel_size: Some(2),
            dtype: Some("bfloat16".to_string()),
            ..Default::default()
        };

        let plan = plan_backend_process(&request).expect("vllm backend process planned");

        assert_eq!(
            plan.spawn_args,
            vec![
                "serve",
                "/models/raw/vllm",
                "--host",
                "0.0.0.0",
                "--port",
                "8092",
                "--max-model-len",
                "16384",
                "--tensor-parallel-size",
                "2",
                "--dtype",
                "bfloat16"
            ]
        );
        assert_eq!(plan.spawn_status, "spawn_ready");
    }

    #[test]
    fn rust_core_shapes_model_mount_backend_process_direct_api() {
        let response = plan_model_mount_backend_process(&backend_process_plan_request())
            .expect("backend process planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.backend_process"
        );
        assert!(response.get("backend").is_none());
        assert_eq!(response["supports_supervision"], true);
        assert_eq!(response["spawn_status"], "spawn_ready");
        assert_eq!(response["spawn_required"], true);
        assert!(response.get("spawnStatus").is_none());
        assert!(response.get("publicArgs").is_none());
        assert!(response.get("spawnArgs").is_none());
        assert!(response["public_args"]
            .as_array()
            .expect("public args")
            .iter()
            .any(|value| value.as_str().unwrap_or("").starts_with("artifact:")));
        assert_eq!(response["spawn_args"][0], "--model");
        assert_eq!(response["spawn_args"][1], "/models/private/model.gguf");
        assert!(response["plan_hash"]
            .as_str()
            .expect("plan hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_backend_process_plan"));
    }
}
