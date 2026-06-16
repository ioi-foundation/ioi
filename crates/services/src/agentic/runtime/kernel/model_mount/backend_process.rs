use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    non_empty_string, option_trimmed, push_unique_ref, require_non_empty, sha256_hex,
    trimmed_string, ModelMountError,
    MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessMaterializationRequest {
    pub schema_version: String,
    pub operation_kind: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_lifecycle_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_lifecycle_hash: Option<String>,
    #[serde(default)]
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessMaterializationPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    pub process_plan: ModelMountBackendProcessPlan,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub materialization_hash: String,
    pub authority_hash: String,
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

impl ModelMountBackendProcessMaterializationRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.operation_kind != "model_mount.backend_process.materialize" {
            return Err(ModelMountError::UnsupportedBackendProcessMaterializationOperation);
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

pub(super) fn plan_backend_process_materialization(
    request: &ModelMountBackendProcessMaterializationRequest,
) -> Result<ModelMountBackendProcessMaterializationPlan, ModelMountError> {
    request.validate()?;
    let process_plan = plan_backend_process(&ModelMountBackendProcessPlanRequest {
        schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
        backend_ref: request.backend_ref.clone(),
        backend_kind: request.backend_kind.clone(),
        base_url: request.base_url.clone(),
        model_ref: request.model_ref.clone(),
        artifact_path: request.artifact_path.clone(),
        binary_configured: request.binary_configured,
        load_options: request.load_options.clone(),
    })?;
    if process_plan.supports_supervision
        && process_plan.backend_kind.trim() != "native_local"
        && process_plan.spawn_status != "spawn_ready"
    {
        return Err(ModelMountError::BackendProcessMaterializationNotReady);
    }

    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let backend_ref = trimmed_string(&request.backend_ref, "backend_ref")?;
    let backend_kind = trimmed_string(&request.backend_kind, "backend_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| {
            "runtime-daemon.model_mounting.backend_process_materialization".to_string()
        });
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let receipt_refs = receipt_refs_for_materialization(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let spawn_args_hash = format!("sha256:{}", hash_json(&json!(process_plan.spawn_args))?);
    let public_args_hash = format!("sha256:{}", hash_json(&json!(process_plan.public_args))?);
    let materialization_status = backend_process_materialization_status(&process_plan);
    let record_id = format!("{}_process", safe_segment(&backend_ref));
    let backend_process_ref = format!(
        "backend_process://{record_id}#{}",
        process_plan.plan_hash.trim()
    );
    let authority_seed = json!({
        "operation_kind": operation_kind,
        "backend_ref": backend_ref,
        "backend_kind": backend_kind,
        "plan_hash": process_plan.plan_hash,
        "spawn_args_hash": spawn_args_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": request.custody_ref,
        "containment_ref": request.containment_ref,
    });
    let authority_hash = format!("sha256:{}", hash_json(&authority_seed)?);
    let materialization_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": operation_kind,
        "backend_ref": backend_ref,
        "backend_kind": backend_kind,
        "plan_hash": process_plan.plan_hash,
        "spawn_args_hash": spawn_args_hash,
        "public_args_hash": public_args_hash,
        "materialization_status": materialization_status,
        "authority_hash": authority_hash,
        "receipt_refs": receipt_refs,
    });
    let materialization_hash = format!("sha256:{}", hash_json(&materialization_seed)?);
    let evidence_refs = backend_process_materialization_evidence_refs(&process_plan);
    let public_response = json!({
        "object": "ioi.model_mount_backend_process_materialization",
        "id": record_id,
        "backend_ref": backend_ref,
        "backend_kind": backend_kind,
        "backend_process_ref": backend_process_ref,
        "process_materialization_status": materialization_status,
        "rust_core_boundary": "model_mount.backend_process_materialization",
        "process_execution_owner": "rust_daemon_core.model_mount.backend_process_materialization",
        "supervisor_kind": process_plan.supervisor_kind,
        "supports_supervision": process_plan.supports_supervision,
        "spawn_required": process_plan.spawn_required,
        "spawn_status": process_plan.spawn_status,
        "plan_hash": process_plan.plan_hash,
        "public_args": process_plan.public_args,
        "public_args_hash": public_args_hash,
        "spawn_args_hash": spawn_args_hash,
        "spawn_args_returned": false,
        "pid_returned": false,
        "plaintext_process_material_returned": false,
        "js_process_supervisor": false,
        "command_transport_spawn": false,
        "binary_bridge_spawn": false,
        "compatibility_spawn_fallback": false,
        "materialization_hash": materialization_hash,
        "authority_hash": authority_hash,
    });
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION,
        "object": "ioi.model_mount_backend_process_materialization",
        "status": "materialized",
        "operation_kind": operation_kind,
        "source": source,
        "backend_ref": backend_ref,
        "backend_kind": backend_kind,
        "backend_process_ref": backend_process_ref,
        "rust_core_boundary": "model_mount.backend_process_materialization",
        "wallet_authority_boundary": "wallet.network.backend_process",
        "ctee_custody_boundary": "ctee.backend_process",
        "process_execution_owner": "rust_daemon_core.model_mount.backend_process_materialization",
        "process_materialization_status": materialization_status,
        "backend_lifecycle_ref": request.backend_lifecycle_ref,
        "backend_lifecycle_hash": request.backend_lifecycle_hash,
        "process_plan": {
            "schema_version": process_plan.schema_version,
            "backend_ref": process_plan.backend_ref,
            "backend_kind": process_plan.backend_kind,
            "supports_supervision": process_plan.supports_supervision,
            "supervisor_kind": process_plan.supervisor_kind,
            "public_args": process_plan.public_args,
            "spawn_required": process_plan.spawn_required,
            "spawn_status": process_plan.spawn_status,
            "plan_hash": process_plan.plan_hash,
            "evidence_refs": process_plan.evidence_refs,
        },
        "spawn_contract": {
            "spawn_args_hash": spawn_args_hash,
            "spawn_args_redacted": true,
            "spawn_args_returned": false,
            "pid_returned": false,
            "plaintext_process_material_returned": false,
            "ctee_custody_required": true,
            "custody_ref": request.custody_ref,
            "containment_ref": request.containment_ref,
        },
        "retired_paths": {
            "js_process_supervisor": false,
            "command_transport_spawn": false,
            "binary_bridge_spawn": false,
            "compatibility_spawn_fallback": false,
        },
        "authority": {
            "authority_hash": authority_hash,
            "required_scope": request.required_scope,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
        },
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "materialization_hash": materialization_hash,
        "authority_hash": authority_hash,
        "planned_at": generated_at,
    });

    Ok(ModelMountBackendProcessMaterializationPlan {
        schema_version: MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_backend_process_materialization_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.backend_process_materialization".to_string(),
        operation_kind,
        source,
        record_dir: "model-backend-process-materializations".to_string(),
        record_id,
        record,
        public_response,
        process_plan,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        materialization_hash,
        authority_hash,
    })
}

pub fn plan_model_mount_backend_process_materialization(
    request: &ModelMountBackendProcessMaterializationRequest,
) -> Result<ModelMountBackendProcessMaterializationPlan, ModelMountError> {
    plan_backend_process_materialization(request)
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

fn backend_process_materialization_status(plan: &ModelMountBackendProcessPlan) -> String {
    if plan.backend_kind.trim() == "native_local" {
        "rust_fixture_process_materialized".to_string()
    } else if plan.spawn_required && plan.spawn_status == "spawn_ready" {
        "rust_spawn_contract_bound".to_string()
    } else if plan.supports_supervision {
        format!("rust_process_materialization_{}", plan.spawn_status)
    } else {
        "rust_process_materialization_not_supervised".to_string()
    }
}

fn backend_process_materialization_evidence_refs(
    plan: &ModelMountBackendProcessPlan,
) -> Vec<String> {
    let mut refs = vec![
        "rust_daemon_core_backend_process_materialization".to_string(),
        "rust_backend_process_materialization_bound".to_string(),
        "wallet_network_backend_process_authority_bound".to_string(),
        "ctee_backend_process_custody_enforced".to_string(),
        "agentgres_backend_process_materialization_truth_required".to_string(),
        "js_backend_process_supervisor_retired".to_string(),
        "command_transport_backend_process_spawn_retired".to_string(),
        "binary_bridge_backend_process_spawn_retired".to_string(),
    ];
    for evidence_ref in &plan.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn receipt_refs_for_materialization(
    request: &ModelMountBackendProcessMaterializationRequest,
) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    for value in &request.authority_receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn safe_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    sha256_hex(
        &serde_json::to_vec(value)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?,
    )
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

    fn backend_process_materialization_request() -> ModelMountBackendProcessMaterializationRequest {
        ModelMountBackendProcessMaterializationRequest {
            schema_version: MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.backend_process.materialize".to_string(),
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
            source: Some("test.backend_process_materialization".to_string()),
            generated_at: Some("2026-06-16T12:00:00.000Z".to_string()),
            receipt_refs: vec!["receipt://backend-lifecycle/start".to_string()],
            authority_grant_refs: vec!["grant://wallet/backend-process".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/backend-process".to_string()],
            custody_ref: Some("ctee://backend/backend.llama".to_string()),
            containment_ref: Some("ctee://workspace/private".to_string()),
            required_scope: Some("backend.process:backend.llama".to_string()),
            backend_lifecycle_ref: Some(
                "agentgres://model-mounting/model-backend-lifecycle-controls/start".to_string(),
            ),
            backend_lifecycle_hash: Some("sha256:backend-lifecycle".to_string()),
            body: Value::Null,
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

    #[test]
    fn rust_core_plans_backend_process_materialization_direct_api() {
        let plan = plan_backend_process_materialization(&backend_process_materialization_request())
            .expect("backend process materialization planned");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_BACKEND_PROCESS_MATERIALIZATION_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "model-backend-process-materializations");
        assert_eq!(
            plan.rust_core_boundary,
            "model_mount.backend_process_materialization"
        );
        assert_eq!(
            plan.record["object"],
            "ioi.model_mount_backend_process_materialization"
        );
        assert_eq!(
            plan.record["process_materialization_status"],
            "rust_spawn_contract_bound"
        );
        assert_eq!(plan.record["retired_paths"]["js_process_supervisor"], false);
        assert_eq!(
            plan.record["retired_paths"]["command_transport_spawn"],
            false
        );
        assert_eq!(plan.record["retired_paths"]["binary_bridge_spawn"], false);
        assert_eq!(plan.record["spawn_contract"]["spawn_args_returned"], false);
        assert_eq!(plan.public_response["spawn_args_returned"], false);
        assert_eq!(
            plan.public_response["process_execution_owner"],
            "rust_daemon_core.model_mount.backend_process_materialization"
        );
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_backend_process_materialization".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_backend_process_materialization_truth_required".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"command_transport_backend_process_spawn_retired".to_string()));
        assert!(plan.materialization_hash.starts_with("sha256:"));
        assert!(plan.authority_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_core_rejects_backend_process_materialization_when_not_ready() {
        let mut request = backend_process_materialization_request();
        request.binary_configured = false;

        assert_eq!(
            plan_backend_process_materialization(&request).unwrap_err(),
            ModelMountError::BackendProcessMaterializationNotReady
        );
    }

    #[test]
    fn rust_core_materializes_native_local_fixture_process_without_js_supervisor() {
        let mut request = backend_process_materialization_request();
        request.backend_ref = "backend.native".to_string();
        request.backend_kind = "native_local".to_string();
        request.binary_configured = false;

        let plan = plan_backend_process_materialization(&request)
            .expect("native-local fixture process materialized");

        assert_eq!(
            plan.record["process_materialization_status"],
            "rust_fixture_process_materialized"
        );
        assert_eq!(plan.record["retired_paths"]["js_process_supervisor"], false);
        assert_eq!(plan.public_response["command_transport_spawn"], false);
        assert!(plan
            .evidence_refs
            .contains(&"js_backend_process_supervisor_retired".to_string()));
    }
}
