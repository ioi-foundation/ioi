use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::super::{
    require_non_empty, sha256_hex, ModelMountError, MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_auth_materialization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_header_binding_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_materialization_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctee_egress_resolver_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctee_egress_resolver_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctee_egress_resolution_status: Option<String>,
    #[serde(default)]
    pub item_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub action: String,
    pub operation_kind: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub item_refs: Vec<String>,
    pub item_count: usize,
    pub evidence_refs: Vec<String>,
    pub transport_contract: Value,
    pub inventory_hash: String,
    pub rust_core_boundary: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
}

impl ModelMountProviderInventoryRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if !matches!(self.action.trim(), "list_models" | "list_loaded") {
            return Err(ModelMountError::UnsupportedProviderInventoryAction);
        }
        if !is_native_local_provider_inventory_backend(self)
            && !is_fixture_provider_inventory_backend(self)
            && !is_hosted_provider_inventory_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderInventoryBackend);
        }
        if !self.item_refs.is_empty() || !self.evidence_refs.is_empty() {
            return Err(ModelMountError::ProviderInventoryCallerAuthoredTruthRetired);
        }
        Ok(())
    }
}

pub(super) fn plan_provider_inventory(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
    request.validate()?;
    let ProviderInventoryMaterialization {
        item_refs,
        transport,
    } = provider_inventory_materialization(request)?;
    let mut result = ModelMountProviderInventoryResult {
        schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
        provider_ref: request.provider_ref.clone(),
        provider_kind: request.provider_kind.clone(),
        action: request.action.clone(),
        operation_kind: provider_inventory_operation_kind(request),
        status: "listed".to_string(),
        backend: provider_inventory_backend(request),
        backend_id: provider_inventory_backend_id(request),
        driver: provider_inventory_driver(request),
        execution_backend: request.execution_backend.clone(),
        item_refs: item_refs.clone(),
        item_count: item_refs.len(),
        evidence_refs: provider_inventory_evidence_refs(request, transport.as_ref()),
        transport_contract: provider_inventory_transport_contract(
            request,
            &item_refs,
            transport.as_ref(),
        ),
        inventory_hash: String::new(),
        rust_core_boundary: "model_mount.provider_inventory".to_string(),
        record_dir: "model-provider-inventory".to_string(),
        record_id: String::new(),
        record: Value::Null,
        receipt_refs: vec![],
    };
    result.inventory_hash = provider_inventory_hash(&result)?;
    result.record_id = provider_inventory_record_id(&result);
    result.record = provider_inventory_record(&result);
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderInventoryMaterialization {
    item_refs: Vec<String>,
    transport: Option<HostedProviderCatalogTransportBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedProviderCatalogTransportBinding {
    request_ref: String,
    method: String,
    path: String,
    base_url_hash: String,
    request_hash: String,
    response_hash: String,
    status: String,
    provider_auth_materialization_ref: String,
    outbound_header_binding_ref: String,
    auth_header_materialization_status: String,
    ctee_egress_resolver_ref: String,
    ctee_egress_resolver_hash: String,
    ctee_egress_resolution_status: String,
    ctee_outbound_secret_injection_ref: String,
    ctee_outbound_secret_injection_hash: String,
    ctee_outbound_secret_injection_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedProviderCatalogSecretInjectionBinding {
    provider_auth_materialization_ref: String,
    outbound_header_binding_ref: String,
    auth_header_materialization_status: String,
    ctee_egress_resolver_ref: String,
    ctee_egress_resolver_hash: String,
    ctee_egress_resolution_status: String,
}

fn provider_inventory_operation_kind(request: &ModelMountProviderInventoryRequest) -> String {
    match request.action.trim() {
        "list_loaded" => "model_mount.provider.inventory.list_loaded".to_string(),
        _ => "model_mount.provider.inventory.list_models".to_string(),
    }
}

fn is_native_local_provider_inventory_backend(
    request: &ModelMountProviderInventoryRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_hosted_provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    matches!(
        provider_kind,
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
        api_format,
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(
        driver,
        "openai_compatible" | "hosted_provider" | "hosted_provider_metadata"
    )
}

fn provider_inventory_materialization(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ProviderInventoryMaterialization, ModelMountError> {
    if is_native_local_provider_inventory_backend(request) {
        let item_refs = if request.action.trim() == "list_loaded" {
            vec!["model_instance://native/qwen3".to_string()]
        } else {
            vec!["model://native/qwen3".to_string()]
        };
        Ok(ProviderInventoryMaterialization {
            item_refs,
            transport: None,
        })
    } else if is_hosted_provider_inventory_backend(request) {
        hosted_provider_inventory_item_refs(request)
    } else if request.action.trim() == "list_loaded" {
        Ok(ProviderInventoryMaterialization {
            item_refs: vec!["model_instance://fixture/qwen3".to_string()],
            transport: None,
        })
    } else {
        Ok(ProviderInventoryMaterialization {
            item_refs: vec!["model://fixture/qwen3".to_string()],
            transport: None,
        })
    }
}

fn hosted_provider_inventory_item_refs(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ProviderInventoryMaterialization, ModelMountError> {
    let provider = hosted_provider_catalog_segment(request);
    if request.action.trim() == "list_loaded" {
        return Ok(ProviderInventoryMaterialization {
            item_refs: vec![format!("model_instance://{provider}/hosted-active")],
            transport: None,
        });
    }
    hosted_provider_catalog_transport(request, &provider)
}

fn hosted_provider_catalog_segment(request: &ModelMountProviderInventoryRequest) -> String {
    let provider_kind = request.provider_kind.trim();
    if !provider_kind.is_empty() {
        return record_id_segment(provider_kind, "hosted_provider");
    }
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    if !api_format.is_empty() {
        return record_id_segment(api_format, "hosted_provider");
    }
    let driver = request.driver.as_deref().unwrap_or("").trim();
    if !driver.is_empty() {
        return record_id_segment(driver, "hosted_provider");
    }
    "hosted_provider".to_string()
}

fn hosted_provider_catalog_transport(
    request: &ModelMountProviderInventoryRequest,
    provider: &str,
) -> Result<ProviderInventoryMaterialization, ModelMountError> {
    let base_url = request
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ModelMountError::HostedProviderInvocationMissingEndpointUrl)?;
    let path = hosted_provider_catalog_path(request);
    let url = hosted_provider_catalog_url(base_url, path);
    let secret_injection = hosted_provider_catalog_secret_injection_binding(request)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| {
            ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
        })?;
    let builder = client
        .get(url)
        .header("accept", "application/json")
        .header("x-ioi-ctee-secret-custody", "no-plaintext")
        .header(
            "x-ioi-provider-auth-materialization-ref",
            &secret_injection.provider_auth_materialization_ref,
        )
        .header(
            "x-ioi-outbound-header-binding-ref",
            &secret_injection.outbound_header_binding_ref,
        )
        .header(
            "x-ioi-auth-header-materialization-status",
            &secret_injection.auth_header_materialization_status,
        )
        .header(
            "x-ioi-ctee-egress-resolver-ref",
            &secret_injection.ctee_egress_resolver_ref,
        )
        .header(
            "x-ioi-ctee-egress-resolver-hash",
            &secret_injection.ctee_egress_resolver_hash,
        )
        .header(
            "x-ioi-ctee-egress-resolution-status",
            &secret_injection.ctee_egress_resolution_status,
        )
        .header(
            "x-ioi-ctee-outbound-secret-injection-status",
            "rust_ctee_outbound_secret_injection_bound",
        );
    let response = builder.send().map_err(|error| {
        ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
    })?;
    let status = response.status();
    let response_text = response.text().map_err(|error| {
        ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
    })?;
    if !status.is_success() {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            format!("hosted provider catalog transport returned HTTP {status}"),
        ));
    }
    let item_refs = hosted_provider_catalog_item_refs(request, provider, &response_text)?;
    let transport = hosted_provider_catalog_transport_binding(
        request,
        base_url,
        path,
        &response_text,
        &secret_injection,
    )?;
    Ok(ProviderInventoryMaterialization {
        item_refs,
        transport: Some(transport),
    })
}

fn hosted_provider_catalog_path(request: &ModelMountProviderInventoryRequest) -> &'static str {
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    if provider_kind == "ollama" || api_format == "ollama" || driver == "ollama" {
        "/api/tags"
    } else {
        "/models"
    }
}

fn hosted_provider_catalog_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn hosted_provider_catalog_item_refs(
    request: &ModelMountProviderInventoryRequest,
    provider: &str,
    response_text: &str,
) -> Result<Vec<String>, ModelMountError> {
    let value = serde_json::from_str::<Value>(response_text).map_err(|error| {
        ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
    })?;
    let ids = if hosted_provider_catalog_path(request) == "/api/tags" {
        value
            .get("models")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|model| {
                string_value_any(model, &["name", "model", "id"]).map(str::to_string)
            })
            .collect::<Vec<_>>()
    } else {
        value
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|model| {
                string_value_any(model, &["id", "model", "name"]).map(str::to_string)
            })
            .collect::<Vec<_>>()
    };
    if ids.is_empty() {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            "hosted provider catalog transport returned no model ids".to_string(),
        ));
    }
    Ok(ids
        .into_iter()
        .map(|id| format!("model://{provider}/{id}"))
        .collect())
}

fn hosted_provider_catalog_transport_binding(
    request: &ModelMountProviderInventoryRequest,
    base_url: &str,
    path: &str,
    response_text: &str,
    secret_injection: &HostedProviderCatalogSecretInjectionBinding,
) -> Result<HostedProviderCatalogTransportBinding, ModelMountError> {
    let base_url_hash = format!("sha256:{}", sha256_hex(base_url.as_bytes())?);
    let method = "GET".to_string();
    let request_seed = json!({
        "schema": "ioi.model_mount.hosted_catalog_transport_request.v1",
        "provider_ref": request.provider_ref,
        "provider_kind": request.provider_kind,
        "action": request.action,
        "method": method,
        "path": path,
        "base_url_hash": base_url_hash,
        "provider_auth_materialization_ref": &secret_injection.provider_auth_materialization_ref,
        "outbound_header_binding_ref": &secret_injection.outbound_header_binding_ref,
        "auth_header_materialization_status": &secret_injection.auth_header_materialization_status,
        "ctee_egress_resolver_ref": &secret_injection.ctee_egress_resolver_ref,
        "ctee_egress_resolver_hash": &secret_injection.ctee_egress_resolver_hash,
        "ctee_egress_resolution_status": &secret_injection.ctee_egress_resolution_status,
        "transport_execution_owner": "rust_daemon_core.model_mount.provider_inventory",
        "ctee_secret_injection": "ctee_egress_resolver_ref",
        "ctee_outbound_secret_injection_ref": &secret_injection.ctee_egress_resolver_ref,
        "ctee_outbound_secret_injection_hash": &secret_injection.ctee_egress_resolver_hash,
        "ctee_outbound_secret_injection_status": "rust_ctee_outbound_secret_injection_bound",
        "secret_injection_owner": "rust_daemon_core.ctee.egress_resolver",
        "plaintext_secret_material_returned": false,
    });
    let request_hash = hash_json_ref(&request_seed)?;
    let response_hash = hash_json_ref(&json!({
        "schema": "ioi.model_mount.hosted_catalog_transport_response.v1",
        "transport_request_hash": request_hash,
        "provider_ref": request.provider_ref,
        "action": request.action,
        "response_body_hash": format!("sha256:{}", sha256_hex(response_text.as_bytes())?),
        "status": "rust_hosted_provider_catalog_transport_response_bound",
        "transport_execution_owner": "rust_daemon_core.model_mount.provider_inventory",
        "live_network_io": true,
        "plaintext_secret_material_returned": false,
    }))?;
    let suffix = request_hash
        .trim_start_matches("sha256:")
        .chars()
        .take(24)
        .collect::<String>();
    Ok(HostedProviderCatalogTransportBinding {
        request_ref: format!("model_mount://hosted_catalog_transport_request/{suffix}"),
        method,
        path: path.to_string(),
        base_url_hash,
        request_hash,
        response_hash,
        status: "rust_hosted_provider_catalog_transport_response_bound".to_string(),
        provider_auth_materialization_ref: secret_injection
            .provider_auth_materialization_ref
            .clone(),
        outbound_header_binding_ref: secret_injection.outbound_header_binding_ref.clone(),
        auth_header_materialization_status: secret_injection
            .auth_header_materialization_status
            .clone(),
        ctee_egress_resolver_ref: secret_injection.ctee_egress_resolver_ref.clone(),
        ctee_egress_resolver_hash: secret_injection.ctee_egress_resolver_hash.clone(),
        ctee_egress_resolution_status: secret_injection.ctee_egress_resolution_status.clone(),
        ctee_outbound_secret_injection_ref: secret_injection.ctee_egress_resolver_ref.clone(),
        ctee_outbound_secret_injection_hash: secret_injection.ctee_egress_resolver_hash.clone(),
        ctee_outbound_secret_injection_status: "rust_ctee_outbound_secret_injection_bound"
            .to_string(),
    })
}

fn hosted_provider_catalog_secret_injection_binding(
    request: &ModelMountProviderInventoryRequest,
) -> Result<HostedProviderCatalogSecretInjectionBinding, ModelMountError> {
    let provider_auth_materialization_ref =
        trimmed_option(&request.provider_auth_materialization_ref)
            .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    let outbound_header_binding_ref = trimmed_option(&request.outbound_header_binding_ref)
        .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    let auth_header_materialization_status =
        trimmed_option(&request.auth_header_materialization_status)
            .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    if auth_header_materialization_status != "rust_ctee_outbound_header_bound" {
        return Err(ModelMountError::HostedProviderInvocationMissingAuthMaterialization);
    }
    let ctee_egress_resolver_ref = trimmed_option(&request.ctee_egress_resolver_ref)
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    let ctee_egress_resolver_hash = trimmed_option(&request.ctee_egress_resolver_hash)
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    let ctee_egress_resolution_status = trimmed_option(&request.ctee_egress_resolution_status)
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    if ctee_egress_resolution_status != "rust_ctee_outbound_egress_resolved" {
        return Err(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver);
    }
    Ok(HostedProviderCatalogSecretInjectionBinding {
        provider_auth_materialization_ref: provider_auth_materialization_ref.to_string(),
        outbound_header_binding_ref: outbound_header_binding_ref.to_string(),
        auth_header_materialization_status: auth_header_materialization_status.to_string(),
        ctee_egress_resolver_ref: ctee_egress_resolver_ref.to_string(),
        ctee_egress_resolver_hash: ctee_egress_resolver_hash.to_string(),
        ctee_egress_resolution_status: ctee_egress_resolution_status.to_string(),
    })
}

fn string_value_any<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_str).map(str::trim))
        .filter(|value| !value.is_empty())
}

fn trimmed_option(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn hash_json_ref(value: &Value) -> Result<String, ModelMountError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "autopilot.native_local.fixture".to_string()
    } else if is_hosted_provider_inventory_backend(request) {
        "hosted_provider_metadata".to_string()
    } else {
        request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string()
    }
}

fn provider_inventory_backend_id(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    if is_hosted_provider_inventory_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.{}",
                    record_id_segment(&request.provider_kind, "provider")
                )
            });
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_inventory_driver(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "native_local".to_string()
    } else if is_hosted_provider_inventory_backend(request) {
        "hosted_provider_metadata".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_inventory_evidence_refs(
    request: &ModelMountProviderInventoryRequest,
    _transport: Option<&HostedProviderCatalogTransportBinding>,
) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_inventory".to_string(),
        "agentgres_provider_inventory_truth_required".to_string(),
        "rust_provider_inventory_item_refs_materialized".to_string(),
    ];
    if is_native_local_provider_inventory_backend(request) {
        refs.push("rust_model_mount_native_local_inventory_backend".to_string());
        refs.push("autopilot_native_local_backend_registry".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_inventory_backend(request) {
        refs.push("rust_model_mount_hosted_provider_inventory_backend".to_string());
        refs.push("rust_hosted_provider_metadata_transport_materialized".to_string());
        refs.push("ctee_hosted_provider_secret_not_exposed".to_string());
        refs.push("wallet_network_provider_transport_authority_bound".to_string());
        refs.push("wallet_network_provider_secret_boundary".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("hosted_provider_loaded_instance_replay_required".to_string());
        } else {
            refs.push("hosted_provider_catalog_metadata_recorded".to_string());
            refs.push("rust_hosted_provider_catalog_live_network_io_executed".to_string());
            refs.push("rust_hosted_provider_catalog_transport_executor_owned".to_string());
            refs.push("rust_hosted_provider_catalog_transport_request_bound".to_string());
            refs.push("rust_hosted_provider_catalog_transport_response_bound".to_string());
            refs.push("rust_hosted_provider_endpoint_url_bound".to_string());
            refs.push("rust_provider_auth_materialization_bound".to_string());
            refs.push("hosted_provider_auth_header_materialized_by_rust".to_string());
            refs.push("hosted_provider_auth_header_materialization_contract_bound".to_string());
            refs.push("rust_ctee_egress_resolver_bound".to_string());
            refs.push("ctee_outbound_secret_injection_ref_bound".to_string());
            refs.push("ctee_outbound_egress_resolver_depth_bound".to_string());
            refs.push("ctee_hosted_catalog_secret_injection_bound".to_string());
        }
    } else {
        refs.push("rust_model_mount_fixture_inventory_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("agentgres_model_instance_registry_fixture".to_string());
        }
        refs.push("deterministic_fixture".to_string());
    }
    refs
}

fn provider_inventory_transport_contract(
    request: &ModelMountProviderInventoryRequest,
    item_refs: &[String],
    transport: Option<&HostedProviderCatalogTransportBinding>,
) -> Value {
    let (status, materialization_kind, containment_ref) =
        if is_hosted_provider_inventory_backend(request) {
            (
                "rust_materialized",
                "hosted_provider_metadata",
                "ctee://model_mount/hosted_provider_metadata",
            )
        } else if is_native_local_provider_inventory_backend(request) {
            (
                "rust_materialized",
                "native_local_inventory",
                "ctee://model_mount/native_local_inventory",
            )
        } else {
            (
                "rust_materialized",
                "fixture_inventory",
                "ctee://model_mount/fixture_inventory",
            )
        };
    let mut contract = json!({
        "transport_execution_status": status,
        "transport_execution_owner": "rust_daemon_core.model_mount.provider_inventory",
        "transport_materialization_kind": materialization_kind,
        "containment_ref": containment_ref,
        "provider_ref": &request.provider_ref,
        "action": &request.action,
        "metadata_item_refs": item_refs,
        "live_network_io": transport.is_some(),
        "plaintext_secret_material_returned": false,
    });
    if let Some(transport) = transport {
        if let Some(object) = contract.as_object_mut() {
            object.insert("method".to_string(), json!(&transport.method));
            object.insert("path".to_string(), json!(&transport.path));
            object.insert("base_url_hash".to_string(), json!(&transport.base_url_hash));
            object.insert(
                "hosted_catalog_transport_request_ref".to_string(),
                json!(&transport.request_ref),
            );
            object.insert(
                "hosted_catalog_transport_request_hash".to_string(),
                json!(&transport.request_hash),
            );
            object.insert(
                "hosted_catalog_transport_response_hash".to_string(),
                json!(&transport.response_hash),
            );
            object.insert(
                "hosted_catalog_transport_status".to_string(),
                json!(&transport.status),
            );
            object.insert(
                "ctee_secret_injection".to_string(),
                json!("ctee_egress_resolver_ref"),
            );
            object.insert(
                "provider_auth_materialization_ref".to_string(),
                json!(&transport.provider_auth_materialization_ref),
            );
            object.insert(
                "outbound_header_binding_ref".to_string(),
                json!(&transport.outbound_header_binding_ref),
            );
            object.insert(
                "auth_header_materialization_status".to_string(),
                json!(&transport.auth_header_materialization_status),
            );
            object.insert(
                "ctee_egress_resolver_ref".to_string(),
                json!(&transport.ctee_egress_resolver_ref),
            );
            object.insert(
                "ctee_egress_resolver_hash".to_string(),
                json!(&transport.ctee_egress_resolver_hash),
            );
            object.insert(
                "ctee_egress_resolution_status".to_string(),
                json!(&transport.ctee_egress_resolution_status),
            );
            object.insert(
                "ctee_outbound_secret_injection_ref".to_string(),
                json!(&transport.ctee_outbound_secret_injection_ref),
            );
            object.insert(
                "ctee_outbound_secret_injection_hash".to_string(),
                json!(&transport.ctee_outbound_secret_injection_hash),
            );
            object.insert(
                "ctee_outbound_secret_injection_status".to_string(),
                json!(&transport.ctee_outbound_secret_injection_status),
            );
        }
    }
    contract
}

fn provider_inventory_hash(
    result: &ModelMountProviderInventoryResult,
) -> Result<String, ModelMountError> {
    let canonical = json!({
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "item_refs": &result.item_refs,
        "item_count": result.item_count,
        "evidence_refs": &result.evidence_refs,
        "transport_contract": &result.transport_contract,
        "rust_core_boundary": &result.rust_core_boundary,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_inventory_record_id(result: &ModelMountProviderInventoryResult) -> String {
    let provider = record_id_segment(&result.provider_ref, "provider");
    let action = record_id_segment(&result.action, "inventory");
    let hash = result
        .inventory_hash
        .strip_prefix("sha256:")
        .unwrap_or(&result.inventory_hash)
        .chars()
        .take(16)
        .collect::<String>();
    format!("provider_inventory_{provider}_{action}_{hash}")
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

fn provider_inventory_record(result: &ModelMountProviderInventoryResult) -> Value {
    let mut record = json!({
        "id": &result.record_id,
        "object": "ioi.model_mount_provider_inventory",
        "schema_version": &result.schema_version,
        "provider_ref": &result.provider_ref,
        "provider_kind": &result.provider_kind,
        "action": &result.action,
        "operation_kind": &result.operation_kind,
        "status": &result.status,
        "backend": &result.backend,
        "backend_id": &result.backend_id,
        "driver": &result.driver,
        "execution_backend": &result.execution_backend,
        "item_refs": &result.item_refs,
        "item_count": result.item_count,
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
        "live_network_io": result
            .transport_contract
            .get("live_network_io")
            .cloned()
            .unwrap_or(Value::Bool(false)),
        "method": result
            .transport_contract
            .get("method")
            .cloned()
            .unwrap_or(Value::Null),
        "path": result
            .transport_contract
            .get("path")
            .cloned()
            .unwrap_or(Value::Null),
        "base_url_hash": result
            .transport_contract
            .get("base_url_hash")
            .cloned()
            .unwrap_or(Value::Null),
        "hosted_catalog_transport_request_ref": result
            .transport_contract
            .get("hosted_catalog_transport_request_ref")
            .cloned()
            .unwrap_or(Value::Null),
        "hosted_catalog_transport_request_hash": result
            .transport_contract
            .get("hosted_catalog_transport_request_hash")
            .cloned()
            .unwrap_or(Value::Null),
        "hosted_catalog_transport_response_hash": result
            .transport_contract
            .get("hosted_catalog_transport_response_hash")
            .cloned()
            .unwrap_or(Value::Null),
        "hosted_catalog_transport_status": result
            .transport_contract
            .get("hosted_catalog_transport_status")
            .cloned()
            .unwrap_or(Value::Null),
        "plaintext_secret_material_returned": false,
        "inventory_hash": &result.inventory_hash,
        "record_dir": &result.record_dir,
        "record_id": &result.record_id,
        "receipt_refs": &result.receipt_refs,
        "rust_core_boundary": &result.rust_core_boundary,
        "source": "rust_model_mount_provider_inventory_api",
        "evidence_refs": &result.evidence_refs,
    });
    if let Some(object) = record.as_object_mut() {
        for field in [
            "provider_auth_materialization_ref",
            "outbound_header_binding_ref",
            "auth_header_materialization_status",
            "ctee_egress_resolver_ref",
            "ctee_egress_resolver_hash",
            "ctee_egress_resolution_status",
            "ctee_outbound_secret_injection_ref",
            "ctee_outbound_secret_injection_hash",
            "ctee_outbound_secret_injection_status",
        ] {
            object.insert(
                field.to_string(),
                result
                    .transport_contract
                    .get(field)
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};

    fn start_catalog_server(path: &'static str, body: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("catalog fixture listener");
        let address = listener.local_addr().expect("catalog fixture address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("catalog fixture request");
            let mut buffer = [0_u8; 2048];
            let bytes = stream.read(&mut buffer).expect("read catalog request");
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            assert!(
                request.starts_with(&format!("GET {path} HTTP/1.1")),
                "catalog fixture expected GET {path}, got {request}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write catalog response");
        });
        (format!("http://{address}"), handle)
    }

    fn provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            action: "list_loaded".to_string(),
            execution_backend: "rust_model_mount_native_local_inventory".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            ctee_egress_resolver_ref: None,
            ctee_egress_resolver_hash: None,
            ctee_egress_resolution_status: None,
            item_refs: vec![],
            evidence_refs: vec![],
        }
    }

    fn fixture_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_fixture_inventory".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            ctee_egress_resolver_ref: None,
            ctee_egress_resolver_hash: None,
            ctee_egress_resolution_status: None,
            item_refs: vec![],
            evidence_refs: vec![],
        }
    }

    fn hosted_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://openai".to_string(),
            provider_kind: "openai".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_hosted_provider_inventory".to_string(),
            api_format: Some("openai".to_string()),
            driver: Some("openai_compatible".to_string()),
            backend_ref: None,
            provider_status: Some("configured".to_string()),
            base_url: None,
            provider_auth_materialization_ref: Some(
                "agentgres://model-mounting/model-provider-auth-materializations/provider.openai"
                    .to_string(),
            ),
            outbound_header_binding_ref: Some(
                "provider_auth_header://provider.openai#sha256:provider-auth".to_string(),
            ),
            auth_header_materialization_status: Some("rust_ctee_outbound_header_bound".to_string()),
            ctee_egress_resolver_ref: Some(
                "ctee://model-mount/egress-resolver/provider.openai#sha256:egress".to_string(),
            ),
            ctee_egress_resolver_hash: Some("sha256:ctee-egress".to_string()),
            ctee_egress_resolution_status: Some("rust_ctee_outbound_egress_resolved".to_string()),
            item_refs: vec![],
            evidence_refs: vec![],
        }
    }

    #[test]
    fn provider_inventory_child_module_owns_planner_surface() {
        let result = plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(result.action, "list_loaded");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_loaded"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(result.item_count, 1);
        assert_eq!(
            result.item_refs,
            vec!["model_instance://native/qwen3".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_inventory".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_provider_inventory_truth_required".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_provider_inventory_item_refs_materialized".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result.inventory_hash.starts_with("sha256:"));
        assert_eq!(result.rust_core_boundary, "model_mount.provider_inventory");
        assert_eq!(result.record_dir, "model-provider-inventory");
        assert!(result.record_id.starts_with("provider_inventory_provider_"));
        assert_eq!(result.record["id"], result.record_id);
        assert_eq!(
            result.record["object"],
            "ioi.model_mount_provider_inventory"
        );
        assert_eq!(
            result.record["rust_core_boundary"],
            "model_mount.provider_inventory"
        );
        assert_eq!(result.record["inventory_hash"], result.inventory_hash);
    }

    #[test]
    fn native_local_provider_inventory_is_planned_in_rust_model_mount() {
        let result = plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(result.action, "list_loaded");
        assert_eq!(result.status, "listed");
        assert_eq!(result.item_count, 1);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
    }

    #[test]
    fn fixture_provider_inventory_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_inventory_request();

        let result = plan_provider_inventory(&request)
            .expect("fixture provider model inventory planned in Rust");

        assert_eq!(result.action, "list_models");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_models"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert_eq!(result.item_count, 1);
        assert_eq!(result.item_refs, vec!["model://fixture/qwen3".to_string()]);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "list_loaded".to_string();
        let result = plan_provider_inventory(&request)
            .expect("fixture provider loaded inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert_eq!(
            result.item_refs,
            vec!["model_instance://fixture/qwen3".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_instance_registry_fixture".to_string()));
    }

    #[test]
    fn hosted_provider_inventory_materializes_contained_metadata_transport_in_rust() {
        let mut request = hosted_provider_inventory_request();
        let (base_url, handle) = start_catalog_server(
            "/v1/models",
            r#"{"object":"list","data":[{"id":"hosted-chat"},{"id":"hosted-embeddings"}]}"#,
        );
        request.base_url = Some(format!("{base_url}/v1"));

        let result = plan_provider_inventory(&request)
            .expect("hosted provider metadata inventory planned in Rust");
        handle.join().expect("catalog fixture joined");

        assert_eq!(result.action, "list_models");
        assert_eq!(
            result.operation_kind,
            "model_mount.provider.inventory.list_models"
        );
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "hosted_provider_metadata");
        assert_eq!(result.backend_id, "backend.hosted.openai");
        assert_eq!(result.driver, "hosted_provider_metadata");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_hosted_provider_inventory"
        );
        assert_eq!(
            result.item_refs,
            vec![
                "model://openai/hosted-chat".to_string(),
                "model://openai/hosted-embeddings".to_string()
            ]
        );
        assert_eq!(result.item_count, 2);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_metadata_transport_materialized".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"hosted_provider_transport_not_executed".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"wallet_network_provider_secret_boundary".to_string()));
        assert_eq!(
            result.transport_contract["transport_execution_status"],
            "rust_materialized"
        );
        assert_eq!(
            result.transport_contract["transport_execution_owner"],
            "rust_daemon_core.model_mount.provider_inventory"
        );
        assert_eq!(
            result.transport_contract["transport_materialization_kind"],
            "hosted_provider_metadata"
        );
        assert_eq!(result.transport_contract["live_network_io"], true);
        assert_eq!(result.transport_contract["method"], "GET");
        assert_eq!(result.transport_contract["path"], "/models");
        assert_eq!(
            result.transport_contract["hosted_catalog_transport_status"],
            "rust_hosted_provider_catalog_transport_response_bound"
        );
        assert_eq!(
            result.transport_contract["provider_auth_materialization_ref"],
            "agentgres://model-mounting/model-provider-auth-materializations/provider.openai"
        );
        assert_eq!(
            result.transport_contract["outbound_header_binding_ref"],
            "provider_auth_header://provider.openai#sha256:provider-auth"
        );
        assert_eq!(
            result.transport_contract["auth_header_materialization_status"],
            "rust_ctee_outbound_header_bound"
        );
        assert_eq!(
            result.transport_contract["ctee_egress_resolver_ref"],
            "ctee://model-mount/egress-resolver/provider.openai#sha256:egress"
        );
        assert_eq!(
            result.transport_contract["ctee_egress_resolver_hash"],
            "sha256:ctee-egress"
        );
        assert_eq!(
            result.transport_contract["ctee_egress_resolution_status"],
            "rust_ctee_outbound_egress_resolved"
        );
        assert_eq!(
            result.transport_contract["ctee_outbound_secret_injection_ref"],
            "ctee://model-mount/egress-resolver/provider.openai#sha256:egress"
        );
        assert_eq!(
            result.transport_contract["ctee_outbound_secret_injection_hash"],
            "sha256:ctee-egress"
        );
        assert_eq!(
            result.transport_contract["ctee_outbound_secret_injection_status"],
            "rust_ctee_outbound_secret_injection_bound"
        );
        assert!(result
            .transport_contract
            .get("hosted_catalog_transport_request_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .starts_with("sha256:"));
        assert!(result
            .transport_contract
            .get("hosted_catalog_transport_response_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .starts_with("sha256:"));
        for retired_field in [
            "js_transport_invocation",
            "command_transport_fallback",
            "binary_bridge_fallback",
            "compatibility_fallback",
        ] {
            assert!(
                result.transport_contract.get(retired_field).is_none(),
                "{retired_field} must stay out of provider inventory transport contracts"
            );
            assert!(
                result.record.get(retired_field).is_none(),
                "{retired_field} must stay out of provider inventory records"
            );
        }
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_catalog_metadata_recorded".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_catalog_live_network_io_executed".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_catalog_transport_executor_owned".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_catalog_transport_request_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_hosted_provider_catalog_transport_response_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_ctee_egress_resolver_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_provider_auth_materialization_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"ctee_outbound_secret_injection_ref_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"ctee_hosted_catalog_secret_injection_bound".to_string()));
        assert_eq!(
            result.transport_contract["metadata_item_refs"],
            json!(result.item_refs)
        );
        assert!(result.record_id.starts_with("provider_inventory_provider_"));
        assert_eq!(result.record["id"], result.record_id);
        assert_eq!(
            result.record["rust_core_boundary"],
            "model_mount.provider_inventory"
        );
        assert_eq!(
            result.record["transport_execution_status"],
            "rust_materialized"
        );
        assert_eq!(
            result.record["transport_execution_owner"],
            "rust_daemon_core.model_mount.provider_inventory"
        );
        assert_eq!(result.record["live_network_io"], true);
        assert_eq!(
            result.record["hosted_catalog_transport_status"],
            "rust_hosted_provider_catalog_transport_response_bound"
        );
        assert_eq!(
            result.record["provider_auth_materialization_ref"],
            "agentgres://model-mounting/model-provider-auth-materializations/provider.openai"
        );
        assert_eq!(
            result.record["ctee_outbound_secret_injection_ref"],
            "ctee://model-mount/egress-resolver/provider.openai#sha256:egress"
        );
        assert_eq!(
            result.record["ctee_outbound_secret_injection_status"],
            "rust_ctee_outbound_secret_injection_bound"
        );

        request.action = "list_loaded".to_string();
        let result = plan_provider_inventory(&request)
            .expect("hosted provider loaded metadata inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert_eq!(
            result.item_refs,
            vec!["model_instance://openai/hosted-active".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"hosted_provider_loaded_instance_replay_required".to_string()));
    }

    #[test]
    fn hosted_provider_inventory_requires_live_catalog_endpoint_for_model_list() {
        let request = hosted_provider_inventory_request();

        let error = plan_provider_inventory(&request)
            .expect_err("hosted provider catalog listing requires a Rust-bound endpoint URL");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingEndpointUrl
        );
    }

    #[test]
    fn hosted_provider_inventory_requires_rust_auth_and_ctee_secret_injection_before_transport() {
        let mut missing_auth = hosted_provider_inventory_request();
        missing_auth.base_url = Some("http://127.0.0.1:9/v1".to_string());
        missing_auth.provider_auth_materialization_ref = None;

        let error = plan_provider_inventory(&missing_auth)
            .expect_err("hosted catalog inventory must reject missing Rust auth before network");
        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthMaterialization
        );

        let mut missing_ctee = hosted_provider_inventory_request();
        missing_ctee.base_url = Some("http://127.0.0.1:9/v1".to_string());
        missing_ctee.ctee_egress_resolver_ref = None;

        let error = plan_provider_inventory(&missing_ctee).expect_err(
            "hosted catalog inventory must reject missing cTEE resolver before network",
        );
        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingCteeEgressResolver
        );
    }

    #[test]
    fn provider_inventory_rejects_caller_authored_item_refs_and_evidence_refs() {
        let mut request = provider_inventory_request();
        request.item_refs = vec!["model_instance://js/retired".to_string()];

        let error = plan_provider_inventory(&request)
            .expect_err("caller-supplied inventory item refs must stay retired");

        assert_eq!(
            error,
            ModelMountError::ProviderInventoryCallerAuthoredTruthRetired
        );

        request = provider_inventory_request();
        request.evidence_refs = vec!["js_inventory_evidence".to_string()];
        let error = plan_provider_inventory(&request)
            .expect_err("caller-supplied inventory evidence refs must stay retired");

        assert_eq!(
            error,
            ModelMountError::ProviderInventoryCallerAuthoredTruthRetired
        );
    }

    #[test]
    fn native_local_provider_inventory_rejects_unsupported_backend_and_action() {
        let mut request = provider_inventory_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_provider_inventory(&request)
            .expect_err("inventory planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryBackend);

        request = provider_inventory_request();
        request.action = "scan".to_string();
        let error = plan_provider_inventory(&request)
            .expect_err("inventory planner only supports explicit listing actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryAction);
    }
}
