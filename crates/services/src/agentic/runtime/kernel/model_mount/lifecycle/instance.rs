use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::{
    non_empty_string, option_trimmed, push_unique_ref,
    read_projection::{plan_read_projection, ModelMountReadProjectionRequest},
    require_non_empty, sha256_hex, ModelMountError, MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleRequest {
    pub schema_version: String,
    #[serde(default)]
    pub instance_ref: String,
    #[serde(default)]
    pub endpoint_ref: String,
    #[serde(default)]
    pub model_ref: String,
    #[serde(default)]
    pub provider_ref: String,
    pub action: String,
    pub target_status: String,
    pub execution_backend: String,
    #[serde(default)]
    pub backend_ref: String,
    #[serde(default)]
    pub driver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_lifecycle_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_materialization_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_engine_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_options: Option<Value>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub endpoint: Value,
    #[serde(default)]
    pub provider: Value,
    #[serde(default)]
    pub instance: Value,
    #[serde(default)]
    pub endpoints: Vec<Value>,
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default)]
    pub instances: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleResult {
    pub schema_version: String,
    pub id: String,
    pub endpoint_id: String,
    pub model_id: String,
    pub provider_id: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub status: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub provider_lifecycle_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_materialization_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_supervision_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_engine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_options: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_estimate: Option<Value>,
    pub evidence_refs: Vec<String>,
    pub instance_lifecycle_hash: String,
}

impl ModelMountInstanceLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("action", &self.action)?;
        require_non_empty("target_status", &self.target_status)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        option_trimmed(&self.state_dir).ok_or(ModelMountError::MissingField("state_dir"))?;
        if !self.endpoint.is_null() {
            return Err(ModelMountError::MissingField("retired_endpoint"));
        }
        if !self.provider.is_null() {
            return Err(ModelMountError::MissingField("retired_provider"));
        }
        if !self.instance.is_null() {
            return Err(ModelMountError::MissingField("retired_instance"));
        }
        if !self.endpoints.is_empty() {
            return Err(ModelMountError::MissingField("retired_endpoints"));
        }
        if !self.providers.is_empty() {
            return Err(ModelMountError::MissingField("retired_providers"));
        }
        if !self.instances.is_empty() {
            return Err(ModelMountError::MissingField("retired_instances"));
        }
        if self.action.trim() == "load" {
            require_non_empty("backend_process_ref", &self.backend_process_ref)?;
            require_non_empty(
                "backend_process_materialization_hash",
                &self.backend_process_materialization_hash,
            )?;
            require_non_empty("backend_supervision_ref", &self.backend_supervision_ref)?;
            require_non_empty("backend_supervision_hash", &self.backend_supervision_hash)?;
            require_non_empty(
                "backend_supervision_status",
                &self.backend_supervision_status,
            )?;
        }
        if self.execution_backend.trim() != "rust_model_mount_instance_lifecycle" {
            return Err(ModelMountError::UnsupportedInstanceLifecycleBackend);
        }
        if self.action.trim() == "supersede" {
            require_non_empty(
                "superseded_by",
                self.superseded_by.as_deref().unwrap_or_default(),
            )?;
        }
        match self.action.trim() {
            "load" if self.target_status.trim() == "loaded" => Ok(()),
            "unload" if self.target_status.trim() == "unloaded" => Ok(()),
            "evict" if self.target_status.trim() == "evicted" => Ok(()),
            "supersede" if self.target_status.trim() == "superseded" => Ok(()),
            "estimate" if self.target_status.trim() == "estimated" => Ok(()),
            "load" | "unload" | "evict" | "supersede" | "estimate" => {
                Err(ModelMountError::InstanceLifecycleStatusMismatch)
            }
            _ => Err(ModelMountError::UnsupportedInstanceLifecycleAction),
        }
    }
}

pub(super) fn plan_instance_lifecycle(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
    request.validate()?;
    let subject = resolve_instance_lifecycle_subject(request)?;
    let mut result = ModelMountInstanceLifecycleResult {
        schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
        id: subject.instance_ref.clone(),
        endpoint_id: subject.endpoint_ref.clone(),
        model_id: subject.model_ref.clone(),
        provider_id: subject.provider_ref.clone(),
        instance_ref: subject.instance_ref.clone(),
        endpoint_ref: subject.endpoint_ref.clone(),
        model_ref: subject.model_ref.clone(),
        provider_ref: subject.provider_ref.clone(),
        action: request.action.clone(),
        status: request.target_status.clone(),
        backend_id: subject.backend_ref.clone(),
        driver: subject.driver.clone(),
        execution_backend: request.execution_backend.clone(),
        provider_lifecycle_hash: provider_lifecycle_hash(request, &subject)?,
        backend_process_ref: request.backend_process_ref.clone(),
        backend_process_materialization_hash: request.backend_process_materialization_hash.clone(),
        backend_supervision_ref: request.backend_supervision_ref.clone(),
        backend_supervision_hash: request.backend_supervision_hash.clone(),
        backend_supervision_status: request.backend_supervision_status.clone(),
        reason: request.reason.clone(),
        superseded_by: request.superseded_by.clone(),
        runtime_engine_id: request.runtime_engine_ref.clone(),
        load_options: request.load_options.clone(),
        load_estimate: load_estimate(request)?,
        evidence_refs: instance_lifecycle_evidence_refs(request),
        instance_lifecycle_hash: String::new(),
    };
    result.instance_lifecycle_hash = instance_lifecycle_hash(&result)?;
    Ok(result)
}

#[derive(Debug, Clone)]
struct InstanceLifecycleSubject {
    instance_ref: String,
    endpoint_ref: String,
    model_ref: String,
    provider_ref: String,
    backend_ref: String,
    driver: String,
    provider_lifecycle_hash: String,
}

struct InstanceLifecycleReplay {
    endpoints: Vec<Value>,
    providers: Vec<Value>,
    instances: Vec<Value>,
}

fn resolve_instance_lifecycle_subject(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<InstanceLifecycleSubject, ModelMountError> {
    let replay = instance_lifecycle_replay(request)?;
    match request.action.trim() {
        "load" | "estimate" => resolve_load_subject(request, &replay),
        "unload" | "evict" | "supersede" => resolve_existing_instance_subject(request, &replay),
        _ => Err(ModelMountError::UnsupportedInstanceLifecycleAction),
    }
}

fn resolve_load_subject(
    request: &ModelMountInstanceLifecycleRequest,
    replay: &InstanceLifecycleReplay,
) -> Result<InstanceLifecycleSubject, ModelMountError> {
    let endpoint = endpoint_for_request(request, &replay.endpoints)?;
    let endpoint_id = value_string_any(&endpoint, &["id", "endpoint_id", "endpointId"])
        .ok_or(ModelMountError::MissingField("state_dir.model_endpoints"))?;
    let model_ref = non_empty_string(&request.model_ref)
        .or_else(|| value_string_any(&endpoint, &["model_id", "modelId", "model_ref"]))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_endpoints.model_id",
        ))?;
    if model_ref.eq_ignore_ascii_case("auto") {
        return Err(ModelMountError::UnresolvedAutoModel);
    }
    let provider = provider_for_endpoint(&endpoint, &replay.providers)?;
    let provider_ref = provider_identity(&provider).ok_or(ModelMountError::MissingField(
        "state_dir.model_providers.provider_ref",
    ))?;
    let backend_ref = non_empty_string(&request.backend_ref)
        .or_else(|| value_string_any(&endpoint, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| value_string_any(&provider, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| default_backend_for_provider(&provider))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_endpoints.backend_ref",
        ))?;
    let driver = non_empty_string(&request.driver)
        .or_else(|| value_string_any(&provider, &["driver", "driver_ref"]))
        .or_else(|| value_string_any(&endpoint, &["driver"]))
        .or_else(|| default_driver_for_provider(&provider))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_providers.driver",
        ))?;
    let instance_ref = non_empty_string(&request.instance_ref).unwrap_or_else(|| {
        if request.action.trim() == "estimate" {
            default_model_load_estimate_id(&endpoint, &model_ref, request)
        } else {
            default_model_instance_id(&endpoint, &model_ref, request)
        }
    });
    Ok(InstanceLifecycleSubject {
        instance_ref,
        endpoint_ref: endpoint_id,
        model_ref,
        provider_ref,
        backend_ref,
        driver,
        provider_lifecycle_hash: request.provider_lifecycle_hash.clone(),
    })
}

fn resolve_existing_instance_subject(
    request: &ModelMountInstanceLifecycleRequest,
    replay: &InstanceLifecycleReplay,
) -> Result<InstanceLifecycleSubject, ModelMountError> {
    let instance = if let Some(instance_ref) = non_empty_string(&request.instance_ref) {
        instance_by_ref(&replay.instances, &instance_ref)
    } else {
        let endpoint = endpoint_for_request(request, &replay.endpoints)?;
        let endpoint_id = value_string_any(&endpoint, &["id", "endpoint_id", "endpointId"])
            .ok_or(ModelMountError::MissingField("state_dir.model_endpoints"))?;
        loaded_instance_for_endpoint(&replay.instances, &endpoint_id)
    }
    .ok_or(ModelMountError::MissingField("state_dir.model_instances"))?;
    let instance_ref = value_string_any(&instance, &["id", "instance_ref", "instance_id"]).ok_or(
        ModelMountError::MissingField("state_dir.model_instances.id"),
    )?;
    let endpoint_ref = value_string_any(&instance, &["endpoint_id", "endpointId", "endpoint_ref"])
        .or_else(|| non_empty_string(&request.endpoint_ref))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_instances.endpoint_id",
        ))?;
    let endpoint = endpoint_by_ref(&replay.endpoints, &endpoint_ref).unwrap_or_default();
    let model_ref = value_string_any(&instance, &["model_id", "modelId", "model_ref"])
        .or_else(|| value_string_any(&endpoint, &["model_id", "modelId", "model_ref"]))
        .or_else(|| non_empty_string(&request.model_ref))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_instances.model_id",
        ))?;
    let provider_ref = value_string_any(&instance, &["provider_id", "providerId", "provider_ref"])
        .or_else(|| value_string_any(&endpoint, &["provider_id", "providerId", "provider_ref"]))
        .or_else(|| non_empty_string(&request.provider_ref))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_instances.provider_id",
        ))?;
    let provider = provider_by_ref(&replay.providers, &provider_ref).unwrap_or_default();
    let backend_ref = non_empty_string(&request.backend_ref)
        .or_else(|| value_string_any(&instance, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| value_string_any(&endpoint, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| value_string_any(&provider, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| default_backend_for_provider(&provider))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_instances.backend_ref",
        ))?;
    let driver = non_empty_string(&request.driver)
        .or_else(|| value_string_any(&instance, &["driver", "driver_ref"]))
        .or_else(|| value_string_any(&provider, &["driver", "driver_ref"]))
        .or_else(|| value_string_any(&endpoint, &["driver"]))
        .or_else(|| default_driver_for_provider(&provider))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_instances.driver",
        ))?;
    let provider_lifecycle_hash = non_empty_string(&request.provider_lifecycle_hash)
        .or_else(|| {
            value_string_any(
                &instance,
                &[
                    "provider_lifecycle_hash",
                    "model_mount_provider_lifecycle_hash",
                ],
            )
        })
        .ok_or(ModelMountError::MissingField("provider_lifecycle_hash"))?;
    Ok(InstanceLifecycleSubject {
        instance_ref,
        endpoint_ref,
        model_ref,
        provider_ref,
        backend_ref,
        driver,
        provider_lifecycle_hash,
    })
}

fn instance_lifecycle_replay(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<InstanceLifecycleReplay, ModelMountError> {
    Ok(InstanceLifecycleReplay {
        endpoints: instance_lifecycle_replay_records(request, "endpoints")?,
        providers: instance_lifecycle_replay_records(request, "providers")?,
        instances: instance_lifecycle_replay_records(request, "instances")?,
    })
}

fn instance_lifecycle_replay_records(
    request: &ModelMountInstanceLifecycleRequest,
    projection_kind: &str,
) -> Result<Vec<Value>, ModelMountError> {
    let plan = plan_read_projection(&ModelMountReadProjectionRequest {
        projection_kind: projection_kind.to_string(),
        schema_version: None,
        generated_at: None,
        receipt_id: None,
        engine_id: None,
        provider_id: None,
        download_id: None,
        base_url: None,
        state_dir: request.state_dir.clone(),
        state: Value::Null,
    })
    .map_err(|error| {
        ModelMountError::HashFailed(format!(
            "model_mount_instance_lifecycle_replay_{projection_kind}: {}",
            error.message
        ))
    })?;
    match plan.projection {
        Value::Array(records) => Ok(records),
        _ => Err(ModelMountError::MissingField("state_dir_projection")),
    }
}

fn endpoint_for_request(
    request: &ModelMountInstanceLifecycleRequest,
    endpoints: &[Value],
) -> Result<Value, ModelMountError> {
    if let Some(endpoint_ref) = non_empty_string(&request.endpoint_ref) {
        return endpoint_by_ref(endpoints, &endpoint_ref)
            .ok_or(ModelMountError::MissingField("state_dir.model_endpoints"));
    }
    if let Some(model_ref) = non_empty_string(&request.model_ref) {
        return endpoints
            .iter()
            .filter(|record| endpoint_is_mounted(record))
            .find(|record| model_matches(record, &model_ref))
            .cloned()
            .ok_or(ModelMountError::MissingField("state_dir.model_endpoints"));
    }
    Err(ModelMountError::MissingField("endpoint_ref"))
}

fn endpoint_by_ref(endpoints: &[Value], endpoint_ref: &str) -> Option<Value> {
    endpoints
        .iter()
        .filter(|record| endpoint_is_mounted(record))
        .find(|record| {
            identity_matches(record, &["id", "endpoint_id", "endpoint_ref"], endpoint_ref)
        })
        .cloned()
}

fn endpoint_is_mounted(record: &Value) -> bool {
    !matches!(
        value_string(record, "status").as_deref(),
        Some("unmounted") | Some("blocked")
    )
}

fn instance_by_ref(instances: &[Value], instance_ref: &str) -> Option<Value> {
    instances
        .iter()
        .find(|record| {
            identity_matches(record, &["id", "instance_ref", "instance_id"], instance_ref)
        })
        .cloned()
}

fn loaded_instance_for_endpoint(instances: &[Value], endpoint_ref: &str) -> Option<Value> {
    instances
        .iter()
        .find(|record| {
            value_string(record, "status").as_deref() == Some("loaded")
                && identity_matches(
                    record,
                    &["endpoint_id", "endpointId", "endpoint_ref"],
                    endpoint_ref,
                )
        })
        .cloned()
}

fn provider_for_endpoint(endpoint: &Value, providers: &[Value]) -> Result<Value, ModelMountError> {
    let provider_ref = value_string_any(endpoint, &["provider_id", "providerId", "provider_ref"])
        .ok_or(ModelMountError::MissingField(
        "state_dir.model_endpoints.provider_id",
    ))?;
    provider_by_ref(providers, &provider_ref)
        .ok_or(ModelMountError::MissingField("state_dir.model_providers"))
}

fn provider_by_ref(providers: &[Value], provider_ref: &str) -> Option<Value> {
    providers
        .iter()
        .find(|record| {
            identity_matches(record, &["id", "provider_id", "provider_ref"], provider_ref)
        })
        .cloned()
}

fn provider_identity(provider: &Value) -> Option<String> {
    value_string_any(provider, &["id", "provider_id", "provider_ref"])
}

fn identity_matches(record: &Value, fields: &[&str], requested: &str) -> bool {
    let requested = requested.trim();
    fields.iter().any(|field| {
        value_string(record, field)
            .as_deref()
            .is_some_and(|value| value == requested || ref_alias_matches(value, requested))
    })
}

fn ref_alias_matches(left: &str, right: &str) -> bool {
    left.rsplit_once("://")
        .map(|(_, suffix)| suffix == right)
        .unwrap_or(false)
        || right
            .rsplit_once("://")
            .map(|(_, suffix)| suffix == left)
            .unwrap_or(false)
}

fn model_matches(endpoint: &Value, requested_model: &str) -> bool {
    identity_matches(
        endpoint,
        &["model_id", "modelId", "model_ref"],
        requested_model,
    )
}

fn value_string_any(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| value_string(value, field))
}

fn value_string(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn default_backend_for_provider(provider: &Value) -> Option<String> {
    let kind = value_string(provider, "kind").unwrap_or_default();
    match kind.as_str() {
        "ioi_native_local" => Some("backend.hypervisor.native-local.fixture".to_string()),
        "lm_studio" => Some("backend.lmstudio".to_string()),
        "ollama" => Some("backend.ollama".to_string()),
        "vllm" => Some("backend.vllm".to_string()),
        "llama_cpp" => Some("backend.llama-cpp".to_string()),
        "openai_compatible" | "custom_http" | "openai" | "anthropic" | "gemini" => {
            Some("backend.openai-compatible".to_string())
        }
        _ => None,
    }
}

fn default_driver_for_provider(provider: &Value) -> Option<String> {
    let kind = value_string(provider, "kind").unwrap_or_default();
    match kind.as_str() {
        "ioi_native_local" => Some("native_local".to_string()),
        "local_folder" => Some("fixture".to_string()),
        "openai" | "anthropic" | "gemini" | "custom_http" | "openai_compatible" => {
            Some("openai_compatible".to_string())
        }
        "lm_studio" | "ollama" | "vllm" | "llama_cpp" => Some(kind),
        _ => None,
    }
}

fn default_model_instance_id(
    endpoint: &Value,
    model_ref: &str,
    request: &ModelMountInstanceLifecycleRequest,
) -> String {
    let endpoint_id = value_string_any(endpoint, &["id", "endpoint_id", "endpointId"])
        .unwrap_or_else(|| "endpoint".to_string());
    let identifier = request
        .load_options
        .as_ref()
        .and_then(|options| value_string(options, "identifier"))
        .unwrap_or_else(|| model_ref.to_string());
    format!(
        "model_instance.{}.{}",
        record_id_segment(&endpoint_id, "endpoint"),
        record_id_segment(&identifier, "model")
    )
}

fn default_model_load_estimate_id(
    endpoint: &Value,
    model_ref: &str,
    request: &ModelMountInstanceLifecycleRequest,
) -> String {
    let endpoint_id = value_string_any(endpoint, &["id", "endpoint_id", "endpointId"])
        .unwrap_or_else(|| "endpoint".to_string());
    let seed = json!({
        "endpoint_id": endpoint_id,
        "model_ref": model_ref,
        "load_options": request.load_options,
        "state_dir_replay_required": true,
    });
    let digest = serde_json::to_vec(&seed)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
        .unwrap_or_else(|_| "estimate".repeat(8));
    format!(
        "model_instance_estimate.{}.{}",
        record_id_segment(&endpoint_id, "endpoint"),
        digest.chars().take(16).collect::<String>()
    )
}

fn record_id_segment(value: &str, fallback: &str) -> String {
    let segment = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if segment.is_empty() {
        fallback.to_string()
    } else {
        segment
    }
}

fn instance_lifecycle_evidence_refs(request: &ModelMountInstanceLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_instance_lifecycle".to_string(),
        "agentgres_model_instance_registry_planned".to_string(),
        "agentgres_instance_lifecycle_topology_replay_required".to_string(),
        "model_mount_instance_lifecycle_candidate_transport_retired".to_string(),
    ];
    if request.action.trim() == "estimate" {
        refs.push("rust_model_mount_load_estimate".to_string());
        refs.push("agentgres_model_instance_estimate_truth_required".to_string());
        refs.push("model_mount_model_loading_js_estimate_facade_retired".to_string());
    } else {
        refs.push("rust_model_mount_provider_lifecycle_bound".to_string());
        refs.push("rust_model_mount_backend_process_materialization_bound".to_string());
        refs.push("rust_model_mount_backend_process_supervision_bound".to_string());
    }
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_lifecycle_hash(
    request: &ModelMountInstanceLifecycleRequest,
    subject: &InstanceLifecycleSubject,
) -> Result<String, ModelMountError> {
    if !request.provider_lifecycle_hash.trim().is_empty() {
        return Ok(request.provider_lifecycle_hash.clone());
    }
    if !subject.provider_lifecycle_hash.trim().is_empty() {
        return Ok(subject.provider_lifecycle_hash.clone());
    }
    if request.action.trim() != "estimate" {
        return Err(ModelMountError::MissingField("provider_lifecycle_hash"));
    }
    let bytes = serde_json::to_vec(&json!({
        "instance_ref": subject.instance_ref,
        "endpoint_ref": subject.endpoint_ref,
        "model_ref": subject.model_ref,
        "provider_ref": subject.provider_ref,
        "action": request.action,
        "runtime_engine_ref": request.runtime_engine_ref,
        "load_options": request.load_options,
        "provider_lifecycle_execution": false,
    }))
    .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!(
        "sha256:estimate-provider-lifecycle-not-executed:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn load_estimate(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<Option<Value>, ModelMountError> {
    if request.action.trim() != "estimate" {
        return Ok(None);
    }
    let options = request.load_options.clone().unwrap_or_else(|| json!({}));
    let requested_context_tokens = number_field(&options, "context_length").unwrap_or(0);
    let parallel = number_field(&options, "parallel").unwrap_or(1).max(1);
    let ttl_seconds = number_field(&options, "ttl_seconds");
    let estimated_memory_bytes = requested_context_tokens
        .saturating_mul(parallel)
        .saturating_mul(64);
    Ok(Some(json!({
        "object": "ioi.model_mount_load_estimate",
        "status": "estimated",
        "provider_lifecycle_execution": false,
        "js_sizing_execution": false,
        "js_driver_execution": false,
        "runtime_engine_id": request.runtime_engine_ref,
        "backend_id": request.backend_ref,
        "requested_context_tokens": requested_context_tokens,
        "parallel": parallel,
        "ttl_seconds": ttl_seconds,
        "estimated_memory_bytes": estimated_memory_bytes,
        "estimate_source": "rust_daemon_core.model_mount.instance_lifecycle",
    })))
}

fn number_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn instance_lifecycle_hash(
    result: &ModelMountInstanceLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.instance_lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    fn write_json_record(state_dir: &Path, record_dir: &str, file_name: &str, record: Value) {
        let dir = state_dir.join(record_dir);
        fs::create_dir_all(&dir).expect("record dir");
        fs::write(
            dir.join(file_name),
            serde_json::to_string_pretty(&record).expect("record json"),
        )
        .expect("write record");
    }

    fn seeded_instance_lifecycle_state_dir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("instance lifecycle state dir");
        write_json_record(
            temp.path(),
            "model-endpoints",
            "endpoint.native-qwen3.json",
            json!({
                "id": "endpoint://ioi-native-local/qwen3",
                "record_id": "endpoint://ioi-native-local/qwen3",
                "schema_version": "ioi.model_mount.artifact_endpoint.v1",
                "object": "ioi.model_mount_endpoint",
                "status": "mounted",
                "operation_kind": "model_mount.endpoint.mount",
                "source": "runtime-daemon.model_mounting.artifact_endpoint",
                "rust_core_boundary": "model_mount.artifact_endpoint",
                "endpoint_id": "endpoint://ioi-native-local/qwen3",
                "model_id": "model://qwen/qwen3.5-9b",
                "provider_id": "provider://ioi-native-local",
                "provider_kind": "ioi_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_id": "backend.hypervisor.native-local.fixture",
                "privacy_class": "local_private",
                "plaintext_transport_material_returned": false,
                "authority": {"authority_hash": "sha256:authority:endpoint.native-qwen3"},
                "receipt_refs": ["receipt://endpoint/native-qwen3"],
                "evidence_refs": [
                    "public_artifact_endpoint_js_facade_retired",
                    "rust_daemon_core_artifact_endpoint",
                    "agentgres_artifact_endpoint_truth_required",
                    "rust_daemon_core_model_endpoint_mount"
                ],
                "control_hash": "sha256:control:endpoint.native-qwen3",
                "authority_hash": "sha256:authority:endpoint.native-qwen3",
                "mounted_at": "2026-06-13T00:03:00.000Z"
            }),
        );
        write_json_record(
            temp.path(),
            "model-providers",
            "provider.native-local.json",
            json!({
                "id": "provider://ioi-native-local",
                "record_id": "provider://ioi-native-local",
                "schema_version": "ioi.model_mount.provider_control.v1",
                "object": "ioi.model_mount_provider",
                "status": "configured",
                "operation_kind": "model_mount.provider.write",
                "source": "rust_daemon_core.model_mount.provider_control",
                "provider_id": "provider://ioi-native-local",
                "provider_ref": "provider://ioi-native-local",
                "kind": "ioi_native_local",
                "label": "IOI native local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "privacy_class": "local_private",
                "capabilities": ["chat", "responses"],
                "rust_core_boundary": "model_mount.provider_control",
                "wallet_authority_boundary": "wallet.network.provider_control",
                "ctee_custody_boundary": "ctee.provider_material",
                "plaintext_material_returned": false,
                "authority": {
                    "authority_hash": "sha256:authority:provider.native-local",
                    "required_scope": "provider.write:provider.native-local",
                    "authority_grant_refs": ["wallet://grant/provider-control"],
                    "authority_receipt_refs": ["receipt://wallet/provider-control"]
                },
                "control_hash": "sha256:control:provider.native-local",
                "evidence_refs": [
                    "rust_daemon_core_provider_control",
                    "wallet_network_provider_control_authority_required",
                    "wallet_network_vault_authority_required",
                    "ctee_provider_custody_enforced",
                    "agentgres_provider_control_truth_required",
                    "public_provider_control_js_facade_retired"
                ]
            }),
        );
        write_json_record(
            temp.path(),
            "model-instances",
            "model_instance.native-qwen3.json",
            json!({
                "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                "id": "model_instance://native/qwen3",
                "endpoint_id": "endpoint://ioi-native-local/qwen3",
                "model_id": "model://qwen/qwen3.5-9b",
                "provider_id": "provider://ioi-native-local",
                "instance_ref": "model_instance://native/qwen3",
                "endpoint_ref": "endpoint://ioi-native-local/qwen3",
                "model_ref": "model://qwen/qwen3.5-9b",
                "provider_ref": "provider://ioi-native-local",
                "action": "load",
                "status": "loaded",
                "backend_id": "backend.hypervisor.native-local.fixture",
                "driver": "native_local",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "provider_lifecycle_hash": "sha256:provider-lifecycle",
                "instance_lifecycle_hash": "sha256:instance-lifecycle",
                "evidence_refs": [
                    "rust_model_mount_instance_lifecycle",
                    "agentgres_model_instance_registry_planned"
                ]
            }),
        );
        temp
    }

    fn instance_lifecycle_request() -> (tempfile::TempDir, ModelMountInstanceLifecycleRequest) {
        let temp = seeded_instance_lifecycle_state_dir();
        let request = ModelMountInstanceLifecycleRequest {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: "model_instance://native/qwen3".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            action: "load".to_string(),
            target_status: "loaded".to_string(),
            execution_backend: "rust_model_mount_instance_lifecycle".to_string(),
            backend_ref: "backend.hypervisor.native-local.fixture".to_string(),
            driver: "native_local".to_string(),
            provider_lifecycle_hash: "sha256:provider-lifecycle".to_string(),
            backend_process_ref: "backend_process://backend.native_process#sha256:plan".to_string(),
            backend_process_materialization_hash: "sha256:backend-process-materialization"
                .to_string(),
            backend_supervision_ref: "backend_supervision://backend.native_process#sha256:plan"
                .to_string(),
            backend_supervision_hash: "sha256:backend-supervision".to_string(),
            backend_supervision_status: "rust_fixture_supervision_bound".to_string(),
            reason: None,
            superseded_by: None,
            runtime_engine_ref: None,
            load_options: None,
            evidence_refs: vec!["rust_model_mount_provider_lifecycle".to_string()],
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            endpoint: Value::Null,
            provider: Value::Null,
            instance: Value::Null,
            endpoints: vec![],
            providers: vec![],
            instances: vec![],
        };
        (temp, request)
    }

    #[test]
    fn instance_lifecycle_child_module_owns_planner_surface() {
        let (_temp, request) = instance_lifecycle_request();
        let result =
            plan_instance_lifecycle(&request).expect("model instance lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.id, "model_instance://native/qwen3");
        assert_eq!(result.endpoint_id, "endpoint://ioi-native-local/qwen3");
        assert_eq!(result.model_id, "model://qwen/qwen3.5-9b");
        assert_eq!(result.provider_id, "provider://ioi-native-local");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend_id, "backend.hypervisor.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_instance_lifecycle"
        );
        assert_eq!(result.provider_lifecycle_hash, "sha256:provider-lifecycle");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle_bound".to_string()));
        assert_eq!(
            result.backend_supervision_ref,
            "backend_supervision://backend.native_process#sha256:plan"
        );
        assert_eq!(
            result.backend_supervision_hash,
            "sha256:backend-supervision"
        );
        assert_eq!(
            result.backend_supervision_status,
            "rust_fixture_supervision_bound"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_supervision_bound".to_string()));
        assert!(result.instance_lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn model_instance_lifecycle_is_planned_in_rust_model_mount() {
        let (_temp, request) = instance_lifecycle_request();
        let result =
            plan_instance_lifecycle(&request).expect("model instance lifecycle planned in Rust");

        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
    }

    #[test]
    fn model_instance_unload_lifecycle_is_planned_in_rust_model_mount() {
        let (_temp, mut request) = instance_lifecycle_request();
        request.action = "unload".to_string();
        request.target_status = "unloaded".to_string();
        request.evidence_refs = vec!["rust_model_mount_fixture_lifecycle_backend".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model instance unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
    }

    #[test]
    fn model_instance_eviction_and_supersede_lifecycle_are_planned_in_rust_model_mount() {
        let (temp, mut request) = instance_lifecycle_request();
        request.action = "evict".to_string();
        request.target_status = "evicted".to_string();
        request.reason = Some("idle_ttl".to_string());
        request.evidence_refs = vec!["model_idle_evict".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model instance eviction lifecycle planned in Rust");

        assert_eq!(result.action, "evict");
        assert_eq!(result.status, "evicted");
        assert_eq!(result.reason.as_deref(), Some("idle_ttl"));
        assert!(result
            .evidence_refs
            .contains(&"model_idle_evict".to_string()));

        drop(request);
        let mut request = ModelMountInstanceLifecycleRequest {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: "model_instance://native/qwen3".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            action: "supersede".to_string(),
            target_status: "superseded".to_string(),
            execution_backend: "rust_model_mount_instance_lifecycle".to_string(),
            backend_ref: "backend.hypervisor.native-local.fixture".to_string(),
            driver: "native_local".to_string(),
            provider_lifecycle_hash: "sha256:provider-lifecycle".to_string(),
            backend_process_ref: "backend_process://backend.native_process#sha256:plan".to_string(),
            backend_process_materialization_hash: "sha256:backend-process-materialization"
                .to_string(),
            backend_supervision_ref: "backend_supervision://backend.native_process#sha256:plan"
                .to_string(),
            backend_supervision_hash: "sha256:backend-supervision".to_string(),
            backend_supervision_status: "rust_fixture_supervision_bound".to_string(),
            reason: None,
            superseded_by: None,
            runtime_engine_ref: None,
            load_options: None,
            evidence_refs: vec!["rust_model_mount_provider_lifecycle".to_string()],
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            endpoint: Value::Null,
            provider: Value::Null,
            instance: Value::Null,
            endpoints: vec![],
            providers: vec![],
            instances: vec![],
        };
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        request.reason = Some("endpoint_reload".to_string());
        request.superseded_by = Some("model_instance://native/qwen3-reload".to_string());
        request.evidence_refs = vec!["model_supersede".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model instance supersede lifecycle planned in Rust");

        assert_eq!(result.action, "supersede");
        assert_eq!(result.status, "superseded");
        assert_eq!(result.reason.as_deref(), Some("endpoint_reload"));
        assert_eq!(
            result.superseded_by.as_deref(),
            Some("model_instance://native/qwen3-reload")
        );
        assert!(result
            .evidence_refs
            .contains(&"model_supersede".to_string()));
    }

    #[test]
    fn model_instance_lifecycle_rejects_js_backend_and_status_drift() {
        let (_temp, mut request) = instance_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleBackend);

        let (_temp, mut request) = instance_lifecycle_request();
        request.target_status = "unloaded".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("load action must bind the loaded target status");

        assert_eq!(error, ModelMountError::InstanceLifecycleStatusMismatch);

        let (_temp, mut request) = instance_lifecycle_request();
        request.action = "restart".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner only supports canonical instance transitions");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleAction);

        let (_temp, mut request) = instance_lifecycle_request();
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("supersede action must bind its replacement instance");

        assert_eq!(error, ModelMountError::MissingField("superseded_by"));
    }

    #[test]
    fn rust_core_rejects_instance_lifecycle_candidate_transport() {
        let (_temp, mut request) = instance_lifecycle_request();
        request.endpoint = json!({"id": "endpoint.candidate"});
        let error =
            plan_instance_lifecycle(&request).expect_err("endpoint candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_endpoint"));

        let (_temp, mut request) = instance_lifecycle_request();
        request.provider = json!({"id": "provider.candidate"});
        let error =
            plan_instance_lifecycle(&request).expect_err("provider candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_provider"));

        let (_temp, mut request) = instance_lifecycle_request();
        request.instance = json!({"id": "instance.candidate"});
        let error =
            plan_instance_lifecycle(&request).expect_err("instance candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_instance"));

        let (_temp, mut request) = instance_lifecycle_request();
        request.endpoints = vec![json!({"id": "endpoint.candidate"})];
        let error = plan_instance_lifecycle(&request)
            .expect_err("endpoint list candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_endpoints"));

        let (_temp, mut request) = instance_lifecycle_request();
        request.providers = vec![json!({"id": "provider.candidate"})];
        let error = plan_instance_lifecycle(&request)
            .expect_err("provider list candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_providers"));

        let (_temp, mut request) = instance_lifecycle_request();
        request.instances = vec![json!({"id": "instance.candidate"})];
        let error = plan_instance_lifecycle(&request)
            .expect_err("instance list candidate transport retired");
        assert_eq!(error, ModelMountError::MissingField("retired_instances"));
    }

    #[test]
    fn model_instance_load_estimate_is_planned_in_rust_without_provider_lifecycle() {
        let (_temp, mut request) = instance_lifecycle_request();
        request.action = "estimate".to_string();
        request.target_status = "estimated".to_string();
        request.provider_lifecycle_hash.clear();
        request.runtime_engine_ref = Some("engine.native".to_string());
        request.load_options = Some(json!({
            "estimate_only": true,
            "context_length": 2048,
            "parallel": 2,
            "ttl_seconds": 120,
        }));
        request.evidence_refs =
            vec!["model_mount_model_load_estimate_rust_positive_api".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model load estimate lifecycle planned in Rust");

        assert_eq!(result.action, "estimate");
        assert_eq!(result.status, "estimated");
        assert_eq!(result.runtime_engine_id.as_deref(), Some("engine.native"));
        assert!(result
            .provider_lifecycle_hash
            .starts_with("sha256:estimate-provider-lifecycle-not-executed:"));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_load_estimate".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_instance_estimate_truth_required".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle_bound".to_string()));
        let estimate = result.load_estimate.expect("load estimate");
        assert_eq!(estimate["js_sizing_execution"], false);
        assert_eq!(estimate["js_driver_execution"], false);
        assert_eq!(estimate["provider_lifecycle_execution"], false);
        assert_eq!(estimate["requested_context_tokens"], 2048);
        assert_eq!(estimate["parallel"], 2);
        assert!(result.instance_lifecycle_hash.starts_with("sha256:"));
    }
}
