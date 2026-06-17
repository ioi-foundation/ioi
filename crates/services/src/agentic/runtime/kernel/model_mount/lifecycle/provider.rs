use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::{
    non_empty_string, option_trimmed, push_unique_ref,
    read_projection::{plan_read_projection, ModelMountReadProjectionRequest},
    require_non_empty, ModelMountError, MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleRequest {
    pub schema_version: String,
    #[serde(default)]
    pub provider_ref: String,
    #[serde(default)]
    pub provider_kind: String,
    #[serde(default)]
    pub endpoint_ref: String,
    #[serde(default)]
    pub model_ref: String,
    pub action: String,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub process_evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub provider: Value,
    #[serde(default)]
    pub endpoint: Value,
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default)]
    pub endpoints: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub action: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub evidence_refs: Vec<String>,
    pub transport_contract: Value,
    pub lifecycle_hash: String,
    pub operation_kind: String,
    pub rust_core_boundary: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
}

impl ModelMountProviderLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        option_trimmed(&self.state_dir).ok_or(ModelMountError::MissingField("state_dir"))?;
        if !self.provider.is_null() {
            return Err(ModelMountError::MissingField("retired_provider"));
        }
        if !self.endpoint.is_null() {
            return Err(ModelMountError::MissingField("retired_endpoint"));
        }
        if !self.providers.is_empty() {
            return Err(ModelMountError::MissingField("retired_providers"));
        }
        if !self.endpoints.is_empty() {
            return Err(ModelMountError::MissingField("retired_endpoints"));
        }
        if !matches!(self.action.trim(), "health" | "load" | "unload") {
            return Err(ModelMountError::UnsupportedProviderLifecycleAction);
        }
        Ok(())
    }
}

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    request.validate()?;
    let subject = resolve_provider_lifecycle_subject(request)?;
    if subject.model_ref.trim().eq_ignore_ascii_case("auto") {
        return Err(ModelMountError::UnresolvedAutoModel);
    }
    if !is_native_local_provider_lifecycle_backend(request, &subject)
        && !is_fixture_provider_lifecycle_backend(request, &subject)
        && !is_hosted_provider_lifecycle_backend(request, &subject)
    {
        return Err(ModelMountError::UnsupportedProviderLifecycleBackend);
    }
    let operation_kind = provider_lifecycle_operation_kind(request);
    let receipt_refs = non_empty_vec(&request.receipt_refs);
    let mut result = ModelMountProviderLifecycleResult {
        schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
        provider_ref: subject.provider_ref.clone(),
        provider_kind: subject.provider_kind.clone(),
        endpoint_ref: subject.endpoint_ref.clone(),
        model_ref: subject.model_ref.clone(),
        action: request.action.clone(),
        status: provider_lifecycle_status(request, &subject)?,
        backend: provider_lifecycle_backend(request, &subject),
        backend_id: provider_lifecycle_backend_id(request, &subject),
        driver: provider_lifecycle_driver(request, &subject),
        execution_backend: request.execution_backend.clone(),
        evidence_refs: provider_lifecycle_evidence_refs(request, &subject),
        transport_contract: provider_lifecycle_transport_contract(request, &subject),
        lifecycle_hash: String::new(),
        operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle".to_string(),
        record_dir: "model-provider-lifecycle-controls".to_string(),
        record_id: String::new(),
        record: Value::Null,
        public_response: Value::Null,
        receipt_refs,
    };
    result.lifecycle_hash = provider_lifecycle_hash(&result)?;
    result.record_id = provider_lifecycle_record_id(&result);
    result.public_response = provider_lifecycle_public_response(&result);
    result.record = provider_lifecycle_record(&result);
    Ok(result)
}

#[derive(Debug, Clone)]
struct ProviderLifecycleSubject {
    provider_ref: String,
    provider_kind: String,
    endpoint_ref: String,
    model_ref: String,
    api_format: Option<String>,
    driver: Option<String>,
    backend_ref: Option<String>,
    provider_status: Option<String>,
}

struct ProviderLifecycleReplay {
    providers: Vec<Value>,
    endpoints: Vec<Value>,
}

fn resolve_provider_lifecycle_subject(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ProviderLifecycleSubject, ModelMountError> {
    let replay = provider_lifecycle_replay(request)?;
    let provider = provider_by_ref(&replay.providers, &request.provider_ref)
        .ok_or(ModelMountError::MissingField("state_dir.model_providers"))?;
    let provider_ref = value_string_any(&provider, &["provider_ref", "id", "provider_id"])
        .or_else(|| non_empty_string(&request.provider_ref))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_providers.provider_ref",
        ))?;
    let provider_kind = value_string_any(&provider, &["kind", "provider_kind", "api_format"])
        .or_else(|| non_empty_string(&request.provider_kind))
        .ok_or(ModelMountError::MissingField(
            "state_dir.model_providers.kind",
        ))?;
    let api_format = value_string_any(&provider, &["api_format", "apiFormat"])
        .or_else(|| request.api_format.as_deref().and_then(non_empty_string));
    let driver = value_string_any(&provider, &["driver", "driver_ref"])
        .or_else(|| request.driver.as_deref().and_then(non_empty_string));
    let provider_status =
        value_string_any(&provider, &["status", "provider_status"]).or_else(|| {
            request
                .provider_status
                .as_deref()
                .and_then(non_empty_string)
        });
    let endpoint = endpoint_for_provider(request, &provider_ref, &replay.endpoints);
    let hosted_subject = is_hosted_provider_metadata_subject(
        &provider_kind,
        api_format.as_deref(),
        driver.as_deref(),
    );
    let (endpoint_ref, model_ref, endpoint_backend_ref) = if let Some(endpoint) = endpoint {
        let endpoint_ref = value_string_any(&endpoint, &["endpoint_ref", "id", "endpoint_id"])
            .ok_or(ModelMountError::MissingField(
                "state_dir.model_endpoints.endpoint_ref",
            ))?;
        let model_ref = value_string_any(&endpoint, &["model_ref", "model_id", "modelId"])
            .or_else(|| non_empty_string(&request.model_ref))
            .ok_or(ModelMountError::MissingField(
                "state_dir.model_endpoints.model_id",
            ))?;
        let endpoint_backend_ref =
            value_string_any(&endpoint, &["backend_ref", "backend_id", "backendId"]);
        (endpoint_ref, model_ref, endpoint_backend_ref)
    } else if hosted_subject {
        let provider_id = record_id_segment(&provider_ref, "hosted");
        let provider_segment = record_id_segment(&provider_kind, "hosted");
        (
            non_empty_string(&request.endpoint_ref)
                .unwrap_or_else(|| format!("endpoint://{provider_id}/hosted-metadata")),
            non_empty_string(&request.model_ref)
                .unwrap_or_else(|| format!("model://{provider_segment}/hosted-metadata")),
            None,
        )
    } else {
        return Err(ModelMountError::MissingField("state_dir.model_endpoints"));
    };
    let backend_ref = endpoint_backend_ref
        .or_else(|| value_string_any(&provider, &["backend_ref", "backend_id", "backendId"]))
        .or_else(|| request.backend_ref.as_deref().and_then(non_empty_string))
        .or_else(|| {
            default_backend_for_provider(&provider_kind, api_format.as_deref(), driver.as_deref())
        });
    Ok(ProviderLifecycleSubject {
        provider_ref,
        provider_kind,
        endpoint_ref,
        model_ref,
        api_format,
        driver,
        backend_ref,
        provider_status,
    })
}

fn provider_lifecycle_replay(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ProviderLifecycleReplay, ModelMountError> {
    Ok(ProviderLifecycleReplay {
        providers: provider_lifecycle_replay_records(request, "providers")?,
        endpoints: provider_lifecycle_replay_records(request, "endpoints")?,
    })
}

fn provider_lifecycle_replay_records(
    request: &ModelMountProviderLifecycleRequest,
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
            "model_mount_provider_lifecycle_replay_{projection_kind}: {}",
            error.message
        ))
    })?;
    match plan.projection {
        Value::Array(records) => Ok(records),
        _ => Err(ModelMountError::MissingField("state_dir_projection")),
    }
}

fn endpoint_for_provider(
    request: &ModelMountProviderLifecycleRequest,
    provider_ref: &str,
    endpoints: &[Value],
) -> Option<Value> {
    if let Some(endpoint_ref) = non_empty_string(&request.endpoint_ref) {
        return endpoints
            .iter()
            .filter(|record| endpoint_is_mounted(record))
            .find(|record| {
                identity_matches(
                    record,
                    &["endpoint_ref", "id", "endpoint_id"],
                    &endpoint_ref,
                )
            })
            .cloned();
    }
    endpoints
        .iter()
        .filter(|record| endpoint_is_mounted(record))
        .find(|record| {
            identity_matches(
                record,
                &["provider_ref", "provider_id", "providerId"],
                provider_ref,
            )
        })
        .cloned()
}

fn endpoint_is_mounted(record: &Value) -> bool {
    !matches!(
        value_string(record, "status").as_deref(),
        Some("unmounted") | Some("blocked")
    )
}

fn provider_by_ref(providers: &[Value], provider_ref: &str) -> Option<Value> {
    providers
        .iter()
        .find(|record| {
            identity_matches(record, &["provider_ref", "id", "provider_id"], provider_ref)
        })
        .cloned()
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

fn is_hosted_provider_metadata_subject(
    provider_kind: &str,
    api_format: Option<&str>,
    driver: Option<&str>,
) -> bool {
    matches!(
        provider_kind.trim(),
        "openai"
            | "anthropic"
            | "gemini"
            | "custom_http"
            | "openai_compatible"
            | "ollama"
            | "vllm"
            | "llama_cpp"
            | "lm_studio"
            | "depin_tee"
    ) || matches!(
        api_format.unwrap_or("").trim(),
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(
        driver.unwrap_or("").trim(),
        "openai_compatible" | "hosted_provider" | "hosted_provider_metadata"
    )
}

fn default_backend_for_provider(
    provider_kind: &str,
    api_format: Option<&str>,
    driver: Option<&str>,
) -> Option<String> {
    if provider_kind == "ioi_native_local"
        || driver == Some("native_local")
        || api_format == Some("ioi_native")
    {
        return Some("backend.hypervisor.native-local.fixture".to_string());
    }
    if is_hosted_provider_metadata_subject(provider_kind, api_format, driver) {
        return Some(format!(
            "backend.hosted.{}",
            record_id_segment(provider_kind, "hosted")
        ));
    }
    Some("backend.fixture".to_string())
}

fn is_native_local_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_lifecycle" {
        return false;
    }
    let provider_kind = subject.provider_kind.trim();
    let api_format = subject.api_format.as_deref().unwrap_or("").trim();
    let driver = subject.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_lifecycle" {
        return false;
    }
    let provider_kind = subject.provider_kind.trim();
    let api_format = subject.api_format.as_deref().unwrap_or("").trim();
    let driver = subject.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_hosted_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider_lifecycle" {
        return false;
    }
    is_hosted_provider_metadata_subject(
        &subject.provider_kind,
        subject.api_format.as_deref(),
        subject.driver.as_deref(),
    )
}

fn provider_lifecycle_status(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> Result<String, ModelMountError> {
    match request.action.trim() {
        "health" => {
            if matches!(
                subject.provider_status.as_deref().map(str::trim),
                Some("blocked")
            ) {
                Ok("blocked".to_string())
            } else {
                Ok("available".to_string())
            }
        }
        "load" => Ok("loaded".to_string()),
        "unload" => Ok("unloaded".to_string()),
        _ => Err(ModelMountError::UnsupportedProviderLifecycleAction),
    }
}

fn provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> String {
    if is_native_local_provider_lifecycle_backend(request, subject) {
        "hypervisor.native_local.fixture".to_string()
    } else if is_hosted_provider_lifecycle_backend(request, subject) {
        subject
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                subject
                    .driver
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or("hosted_provider_metadata")
            .to_string()
    } else {
        subject
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string()
    }
}

fn provider_lifecycle_backend_id(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> String {
    if is_native_local_provider_lifecycle_backend(request, subject) {
        return subject
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.hypervisor.native-local.fixture")
            .to_string();
    }
    if is_hosted_provider_lifecycle_backend(request, subject) {
        return subject
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.{}",
                    record_id_segment(&subject.provider_kind, "hosted")
                )
            });
    }
    subject
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_lifecycle_driver(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> String {
    if is_native_local_provider_lifecycle_backend(request, subject) {
        "native_local".to_string()
    } else if is_hosted_provider_lifecycle_backend(request, subject) {
        "hosted_provider_metadata".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_lifecycle_evidence_refs(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> Vec<String> {
    let mut refs = vec![
        "public_provider_lifecycle_js_facade_retired".to_string(),
        "rust_model_mount_provider_lifecycle".to_string(),
        "agentgres_provider_lifecycle_truth_required".to_string(),
        "agentgres_provider_lifecycle_topology_replay_required".to_string(),
        "model_mount_provider_lifecycle_candidate_transport_retired".to_string(),
    ];
    if is_native_local_provider_lifecycle_backend(request, subject) {
        refs.push("rust_model_mount_native_local_lifecycle_backend".to_string());
        if matches!(request.action.trim(), "health" | "load") {
            refs.push("hypervisor_native_local_backend_registry".to_string());
        }
        if matches!(request.action.trim(), "load" | "unload") {
            refs.push("hypervisor_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_lifecycle_backend(request, subject) {
        refs.push("rust_model_mount_hosted_provider_lifecycle_backend".to_string());
        refs.push("rust_hosted_provider_metadata_transport_materialized".to_string());
        refs.push("ctee_hosted_provider_secret_not_exposed".to_string());
        refs.push("wallet_network_provider_transport_authority_bound".to_string());
        refs.push("wallet_network_provider_lifecycle_authority_required".to_string());
    } else {
        refs.push("rust_model_mount_fixture_lifecycle_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in request
        .process_evidence_refs
        .iter()
        .chain(request.evidence_refs.iter())
    {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_lifecycle_transport_contract(
    request: &ModelMountProviderLifecycleRequest,
    subject: &ProviderLifecycleSubject,
) -> Value {
    let (materialization_kind, containment_ref) =
        if is_hosted_provider_lifecycle_backend(request, subject) {
            (
                "hosted_provider_metadata_lifecycle",
                "ctee://model_mount/hosted_provider_lifecycle",
            )
        } else if is_native_local_provider_lifecycle_backend(request, subject) {
            (
                "native_local_lifecycle",
                "ctee://model_mount/native_local_lifecycle",
            )
        } else {
            ("fixture_lifecycle", "ctee://model_mount/fixture_lifecycle")
        };
    json!({
        "transport_execution_status": "rust_materialized",
        "transport_execution_owner": "rust_daemon_core.model_mount.provider_lifecycle",
        "transport_materialization_kind": materialization_kind,
        "containment_ref": containment_ref,
        "provider_ref": &subject.provider_ref,
        "endpoint_ref": &subject.endpoint_ref,
        "model_ref": &subject.model_ref,
        "action": &request.action,
        "plaintext_secret_material_returned": false,
    })
}

fn provider_lifecycle_hash(
    result: &ModelMountProviderLifecycleResult,
) -> Result<String, ModelMountError> {
    let canonical = json!({
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "operation_kind": &result.operation_kind,
        "rust_core_boundary": &result.rust_core_boundary,
        "evidence_refs": &result.evidence_refs,
        "transport_contract": &result.transport_contract,
        "receipt_refs": &result.receipt_refs,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_lifecycle_operation_kind(request: &ModelMountProviderLifecycleRequest) -> String {
    request
        .operation_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| match request.action.trim() {
            "load" => "model_mount.provider.start".to_string(),
            "unload" => "model_mount.provider.stop".to_string(),
            _ => "model_mount.provider.health".to_string(),
        })
}

fn provider_lifecycle_record_id(result: &ModelMountProviderLifecycleResult) -> String {
    let provider = record_id_segment(&result.provider_ref, "provider");
    let action = record_id_segment(&result.action, "lifecycle");
    let hash = result
        .lifecycle_hash
        .strip_prefix("sha256:")
        .unwrap_or(&result.lifecycle_hash)
        .chars()
        .take(16)
        .collect::<String>();
    format!("provider_lifecycle_{provider}_{action}_{hash}")
}

fn provider_lifecycle_public_response(result: &ModelMountProviderLifecycleResult) -> Value {
    json!({
        "object": "ioi.model_mount_provider_lifecycle",
        "status": &result.status,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "backend_id": &result.backend_id,
        "provider_backend": &result.backend,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "operation_kind": &result.operation_kind,
        "rust_core_boundary": &result.rust_core_boundary,
        "lifecycle_hash": &result.lifecycle_hash,
        "transport_contract": &result.transport_contract,
        "transport_execution_status": result
            .transport_contract
            .get("transport_execution_status")
            .cloned()
            .unwrap_or(Value::Null),
        "transport_execution_owner": result
            .transport_contract
            .get("transport_execution_owner")
            .cloned()
            .unwrap_or(Value::Null),
        "transport_materialization_kind": result
            .transport_contract
            .get("transport_materialization_kind")
            .cloned()
            .unwrap_or(Value::Null),
        "plaintext_secret_material_returned": false,
        "js_provider_driver_call": false,
        "js_provider_map_write": false,
        "js_lifecycle_receipt": false,
        "js_projection_write": false,
    })
}

fn provider_lifecycle_record(result: &ModelMountProviderLifecycleResult) -> Value {
    let mut record_receipt_refs = result.receipt_refs.clone();
    push_unique_ref(&mut record_receipt_refs, &result.lifecycle_hash);
    json!({
        "id": &result.record_id,
        "record_id": &result.record_id,
        "object": "ioi.model_mount_provider_lifecycle",
        "schema_version": MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "endpoint_ref": &result.endpoint_ref,
        "model_ref": &result.model_ref,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "transport_contract": &result.transport_contract,
        "transport_execution_status": result
            .transport_contract
            .get("transport_execution_status")
            .cloned()
            .unwrap_or(Value::Null),
        "transport_execution_owner": result
            .transport_contract
            .get("transport_execution_owner")
            .cloned()
            .unwrap_or(Value::Null),
        "transport_materialization_kind": result
            .transport_contract
            .get("transport_materialization_kind")
            .cloned()
            .unwrap_or(Value::Null),
        "plaintext_secret_material_returned": false,
        "lifecycle_hash": &result.lifecycle_hash,
        "record_dir": &result.record_dir,
        "receipt_refs": record_receipt_refs,
        "rust_core_boundary": &result.rust_core_boundary,
        "source": "rust_model_mount_provider_lifecycle_api",
        "public_response": &result.public_response,
        "evidence_refs": &result.evidence_refs,
    })
}

fn record_id_segment(value: &str, fallback: &str) -> String {
    let mut segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while segment.contains("__") {
        segment = segment.replace("__", "_");
    }
    let segment = segment.trim_matches('_');
    if segment.is_empty() {
        fallback.to_string()
    } else {
        segment.to_string()
    }
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, path::Path};

    fn write_json_record(
        state_dir: &Path,
        record_dir: &str,
        file_name: &str,
        record: serde_json::Value,
    ) {
        let dir = state_dir.join(record_dir);
        fs::create_dir_all(&dir).expect("record dir");
        fs::write(
            dir.join(file_name),
            serde_json::to_string_pretty(&record).expect("record json"),
        )
        .expect("write record");
    }

    fn seeded_provider_lifecycle_state_dir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("provider lifecycle state dir");
        write_json_record(
            temp.path(),
            "model-providers",
            "ioi-native-local.json",
            json!({
                "id": "ioi-native-local",
                "record_id": "ioi-native-local",
                "provider_id": "ioi-native-local",
                "provider_ref": "provider://ioi-native-local",
                "schema_version": "ioi.model_mount.provider_control.v1",
                "object": "ioi.model_mount_provider",
                "status": "configured",
                "operation_kind": "model_mount.provider.write",
                "source": "rust_daemon_core.model_mount.provider_control",
                "kind": "ioi_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_id": "backend.hypervisor.native-local.fixture",
                "rust_core_boundary": "model_mount.provider_control",
                "plaintext_material_returned": false,
                "control_hash": "sha256:control:ioi-native-local",
                "evidence_refs": [
                    "rust_daemon_core_provider_control",
                    "agentgres_provider_control_truth_required",
                    "public_provider_control_js_facade_retired"
                ]
            }),
        );
        write_json_record(
            temp.path(),
            "model-providers",
            "fixture.json",
            json!({
                "id": "fixture",
                "record_id": "fixture",
                "provider_id": "fixture",
                "provider_ref": "provider://fixture",
                "schema_version": "ioi.model_mount.provider_control.v1",
                "object": "ioi.model_mount_provider",
                "status": "configured",
                "operation_kind": "model_mount.provider.write",
                "source": "rust_daemon_core.model_mount.provider_control",
                "kind": "local_folder",
                "api_format": "ioi_fixture",
                "driver": "fixture",
                "backend_id": "backend.fixture",
                "rust_core_boundary": "model_mount.provider_control",
                "plaintext_material_returned": false,
                "control_hash": "sha256:control:fixture",
                "evidence_refs": [
                    "rust_daemon_core_provider_control",
                    "agentgres_provider_control_truth_required",
                    "public_provider_control_js_facade_retired"
                ]
            }),
        );
        write_json_record(
            temp.path(),
            "model-providers",
            "openai.json",
            json!({
                "id": "openai",
                "record_id": "openai",
                "provider_id": "openai",
                "provider_ref": "provider://openai",
                "schema_version": "ioi.model_mount.provider_control.v1",
                "object": "ioi.model_mount_provider",
                "status": "configured",
                "operation_kind": "model_mount.provider.write",
                "source": "rust_daemon_core.model_mount.provider_control",
                "kind": "custom_http",
                "api_format": "openai_compatible",
                "driver": "hosted_provider_metadata",
                "backend_id": "backend.hosted.custom_http",
                "rust_core_boundary": "model_mount.provider_control",
                "plaintext_material_returned": false,
                "control_hash": "sha256:control:openai",
                "evidence_refs": [
                    "rust_daemon_core_provider_control",
                    "agentgres_provider_control_truth_required",
                    "public_provider_control_js_facade_retired"
                ]
            }),
        );
        write_json_record(
            temp.path(),
            "model-endpoints",
            "ioi-native-local-qwen3.json",
            json!({
                "id": "endpoint://ioi-native-local/qwen3",
                "record_id": "endpoint://ioi-native-local/qwen3",
                "endpoint_id": "endpoint://ioi-native-local/qwen3",
                "schema_version": "ioi.model_mount.artifact_endpoint.v1",
                "object": "ioi.model_mount_endpoint",
                "status": "mounted",
                "operation_kind": "model_mount.endpoint.mount",
                "source": "runtime-daemon.model_mounting.artifact_endpoint",
                "provider_id": "ioi-native-local",
                "provider_ref": "provider://ioi-native-local",
                "provider_kind": "ioi_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "model_id": "model://qwen/qwen3.5-9b",
                "backend_id": "backend.hypervisor.native-local.fixture",
                "privacy_class": "local_private",
                "plaintext_transport_material_returned": false,
                "mounted_at": "2026-06-13T00:00:00.000Z",
                "rust_core_boundary": "model_mount.artifact_endpoint",
                "control_hash": "sha256:control:ioi-native-local-qwen3",
                "authority_hash": "sha256:authority:ioi-native-local-qwen3",
                "evidence_refs": [
                    "public_artifact_endpoint_js_facade_retired",
                    "rust_daemon_core_artifact_endpoint",
                    "agentgres_artifact_endpoint_truth_required",
                    "rust_daemon_core_model_endpoint_mount"
                ]
            }),
        );
        write_json_record(
            temp.path(),
            "model-endpoints",
            "fixture-qwen3.json",
            json!({
                "id": "endpoint://fixture/qwen3",
                "record_id": "endpoint://fixture/qwen3",
                "endpoint_id": "endpoint://fixture/qwen3",
                "schema_version": "ioi.model_mount.artifact_endpoint.v1",
                "object": "ioi.model_mount_endpoint",
                "status": "mounted",
                "operation_kind": "model_mount.endpoint.mount",
                "source": "runtime-daemon.model_mounting.artifact_endpoint",
                "provider_id": "fixture",
                "provider_ref": "provider://fixture",
                "provider_kind": "local_folder",
                "api_format": "ioi_fixture",
                "driver": "fixture",
                "model_id": "model://fixture/qwen3",
                "backend_id": "backend.fixture",
                "privacy_class": "local_private",
                "plaintext_transport_material_returned": false,
                "mounted_at": "2026-06-13T00:00:00.000Z",
                "rust_core_boundary": "model_mount.artifact_endpoint",
                "control_hash": "sha256:control:fixture-qwen3",
                "authority_hash": "sha256:authority:fixture-qwen3",
                "evidence_refs": [
                    "public_artifact_endpoint_js_facade_retired",
                    "rust_daemon_core_artifact_endpoint",
                    "agentgres_artifact_endpoint_truth_required",
                    "rust_daemon_core_model_endpoint_mount"
                ]
            }),
        );
        temp
    }

    fn provider_lifecycle_request(state_dir: &Path) -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            action: "load".to_string(),
            execution_backend: "rust_model_mount_native_local_lifecycle".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.hypervisor.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_model_load_request".to_string()],
            process_evidence_refs: vec!["hypervisor_native_local_process_started".to_string()],
            operation_kind: Some("model_mount.provider.start".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_refs: vec!["receipt://provider-lifecycle".to_string()],
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            provider: Value::Null,
            endpoint: Value::Null,
            providers: Vec::new(),
            endpoints: Vec::new(),
        }
    }

    fn fixture_provider_lifecycle_request(state_dir: &Path) -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: "endpoint://fixture/qwen3".to_string(),
            model_ref: "model://fixture/qwen3".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_fixture_lifecycle".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_fixture_health_request".to_string()],
            process_evidence_refs: vec![],
            operation_kind: Some("model_mount.provider.health".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_refs: vec![],
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            provider: Value::Null,
            endpoint: Value::Null,
            providers: Vec::new(),
            endpoints: Vec::new(),
        }
    }

    #[test]
    fn provider_lifecycle_child_module_owns_planner_surface() {
        let temp = seeded_provider_lifecycle_state_dir();
        let result = plan_provider_lifecycle(&provider_lifecycle_request(temp.path()))
            .expect("native-local provider lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend, "hypervisor.native_local.fixture");
        assert_eq!(result.backend_id, "backend.hypervisor.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"hypervisor_native_local_process_started".to_string()));
        assert!(result.lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_lifecycle_is_planned_in_rust_model_mount() {
        let temp = seeded_provider_lifecycle_state_dir();
        let mut request = provider_lifecycle_request(temp.path());
        request.action = "unload".to_string();
        request.evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(!result
            .evidence_refs
            .contains(&"hypervisor_native_local_backend_registry".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_health_lifecycle_is_planned_in_rust_model_mount() {
        let temp = seeded_provider_lifecycle_state_dir();
        let mut request = provider_lifecycle_request(temp.path());
        request.action = "health".to_string();
        request.evidence_refs = vec!["daemon_native_local_health_request".to_string()];
        request.process_evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(
            result.status, "available",
            "caller-authored status must not override Rust-owned health replay"
        );
        assert!(result
            .evidence_refs
            .contains(&"hypervisor_native_local_backend_registry".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"hypervisor_native_local_process_supervisor".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));

        request.provider_status = Some("blocked".to_string());
        let result = plan_provider_lifecycle(&request)
            .expect("blocked native-local provider health planned in Rust");

        assert_eq!(result.status, "available");
    }

    #[test]
    fn fixture_provider_lifecycle_is_planned_in_rust_model_mount() {
        let temp = seeded_provider_lifecycle_state_dir();
        let mut request = fixture_provider_lifecycle_request(temp.path());

        let result =
            plan_provider_lifecycle(&request).expect("fixture provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "load".to_string();
        let result =
            plan_provider_lifecycle(&request).expect("fixture provider load planned in Rust");
        assert_eq!(result.status, "loaded");

        request.action = "unload".to_string();
        let result =
            plan_provider_lifecycle(&request).expect("fixture provider unload planned in Rust");
        assert_eq!(result.status, "unloaded");
    }

    #[test]
    fn hosted_provider_lifecycle_materializes_contained_metadata_transport_in_rust() {
        let temp = seeded_provider_lifecycle_state_dir();
        let request = ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://openai".to_string(),
            provider_kind: "custom_http".to_string(),
            endpoint_ref: "endpoint://openai/hosted-metadata".to_string(),
            model_ref: "model://custom_http/hosted-metadata".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_hosted_provider_lifecycle".to_string(),
            api_format: Some("openai_compatible".to_string()),
            driver: Some("hosted_provider_metadata".to_string()),
            backend_ref: Some("backend.hosted.custom_http".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_hosted_health_request".to_string()],
            process_evidence_refs: vec![],
            operation_kind: Some("model_mount.provider.health".to_string()),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-14T00:00:00.000Z".to_string()),
            receipt_refs: vec![],
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            provider: Value::Null,
            endpoint: Value::Null,
            providers: Vec::new(),
            endpoints: Vec::new(),
        };

        let result = plan_provider_lifecycle(&request)
            .expect("hosted provider metadata lifecycle planned in Rust");

        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "openai_compatible");
        assert_eq!(result.driver, "hosted_provider_metadata");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_hosted_provider_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_metadata_transport_materialized".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"hosted_provider_transport_not_executed".to_string()));
        assert_eq!(
            result.transport_contract["transport_execution_status"],
            "rust_materialized"
        );
        assert_eq!(
            result.transport_contract["transport_execution_owner"],
            "rust_daemon_core.model_mount.provider_lifecycle"
        );
        assert_eq!(
            result.transport_contract["transport_materialization_kind"],
            "hosted_provider_metadata_lifecycle"
        );
        for retired_field in [
            "js_transport_invocation",
            "command_transport_fallback",
            "binary_bridge_fallback",
            "compatibility_fallback",
        ] {
            assert!(
                result.transport_contract.get(retired_field).is_none(),
                "{retired_field} must stay out of provider lifecycle transport contracts"
            );
            assert!(
                result.public_response.get(retired_field).is_none(),
                "{retired_field} must stay out of provider lifecycle public responses"
            );
            assert!(
                result.record.get(retired_field).is_none(),
                "{retired_field} must stay out of provider lifecycle records"
            );
        }
        assert_eq!(
            result.public_response["transport_execution_status"],
            "rust_materialized"
        );
        assert!(result.public_response["js_provider_driver_call"] == false);
    }

    #[test]
    fn native_local_provider_lifecycle_rejects_unsupported_backend_and_action() {
        let temp = seeded_provider_lifecycle_state_dir();
        let mut request = provider_lifecycle_request(temp.path());
        request.execution_backend = "daemon_js".to_string();

        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleBackend);

        request = provider_lifecycle_request(temp.path());
        request.action = "restart".to_string();
        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner only supports explicit health/load/unload actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleAction);
    }

    #[test]
    fn rust_core_rejects_provider_lifecycle_candidate_transport() {
        let temp = seeded_provider_lifecycle_state_dir();

        let mut request = provider_lifecycle_request(temp.path());
        request.provider = json!({"id": "provider.candidate"});
        assert_eq!(
            plan_provider_lifecycle(&request)
                .expect_err("provider candidate transport must stay retired"),
            ModelMountError::MissingField("retired_provider")
        );

        let mut request = provider_lifecycle_request(temp.path());
        request.endpoint = json!({"id": "endpoint.candidate"});
        assert_eq!(
            plan_provider_lifecycle(&request)
                .expect_err("endpoint candidate transport must stay retired"),
            ModelMountError::MissingField("retired_endpoint")
        );

        let mut request = provider_lifecycle_request(temp.path());
        request.providers = vec![json!({"id": "provider.candidate"})];
        assert_eq!(
            plan_provider_lifecycle(&request)
                .expect_err("provider list candidate transport must stay retired"),
            ModelMountError::MissingField("retired_providers")
        );

        let mut request = provider_lifecycle_request(temp.path());
        request.endpoints = vec![json!({"id": "endpoint.candidate"})];
        assert_eq!(
            plan_provider_lifecycle(&request)
                .expect_err("endpoint list candidate transport must stay retired"),
            ModelMountError::MissingField("retired_endpoints")
        );
    }
}
