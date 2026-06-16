use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::{
    push_unique_ref, require_non_empty, ModelMountError,
    MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleRequest {
    pub schema_version: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub target_status: String,
    pub execution_backend: String,
    pub backend_ref: String,
    pub driver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_lifecycle_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend_process_materialization_hash: String,
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
        require_non_empty("instance_ref", &self.instance_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("target_status", &self.target_status)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        require_non_empty("backend_ref", &self.backend_ref)?;
        require_non_empty("driver", &self.driver)?;
        if self.action.trim() != "estimate" {
            require_non_empty("provider_lifecycle_hash", &self.provider_lifecycle_hash)?;
        }
        if self.action.trim() == "load" {
            require_non_empty("backend_process_ref", &self.backend_process_ref)?;
            require_non_empty(
                "backend_process_materialization_hash",
                &self.backend_process_materialization_hash,
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
    let mut result = ModelMountInstanceLifecycleResult {
        schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
        id: request.instance_ref.clone(),
        endpoint_id: request.endpoint_ref.clone(),
        model_id: request.model_ref.clone(),
        provider_id: request.provider_ref.clone(),
        instance_ref: request.instance_ref.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        provider_ref: request.provider_ref.clone(),
        action: request.action.clone(),
        status: request.target_status.clone(),
        backend_id: request.backend_ref.clone(),
        driver: request.driver.clone(),
        execution_backend: request.execution_backend.clone(),
        provider_lifecycle_hash: provider_lifecycle_hash(request)?,
        backend_process_ref: request.backend_process_ref.clone(),
        backend_process_materialization_hash: request.backend_process_materialization_hash.clone(),
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

fn instance_lifecycle_evidence_refs(request: &ModelMountInstanceLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_instance_lifecycle".to_string(),
        "agentgres_model_instance_registry_planned".to_string(),
    ];
    if request.action.trim() == "estimate" {
        refs.push("rust_model_mount_load_estimate".to_string());
        refs.push("agentgres_model_instance_estimate_truth_required".to_string());
        refs.push("model_mount_model_loading_js_estimate_facade_retired".to_string());
    } else {
        refs.push("rust_model_mount_provider_lifecycle_bound".to_string());
        refs.push("rust_model_mount_backend_process_materialization_bound".to_string());
    }
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_lifecycle_hash(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<String, ModelMountError> {
    if !request.provider_lifecycle_hash.trim().is_empty() {
        return Ok(request.provider_lifecycle_hash.clone());
    }
    let bytes = serde_json::to_vec(&json!({
        "instance_ref": request.instance_ref,
        "endpoint_ref": request.endpoint_ref,
        "model_ref": request.model_ref,
        "provider_ref": request.provider_ref,
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

    fn instance_lifecycle_request() -> ModelMountInstanceLifecycleRequest {
        ModelMountInstanceLifecycleRequest {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: "model_instance://native/qwen3".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            action: "load".to_string(),
            target_status: "loaded".to_string(),
            execution_backend: "rust_model_mount_instance_lifecycle".to_string(),
            backend_ref: "backend.autopilot.native-local.fixture".to_string(),
            driver: "native_local".to_string(),
            provider_lifecycle_hash: "sha256:provider-lifecycle".to_string(),
            backend_process_ref: "backend_process://backend.native_process#sha256:plan".to_string(),
            backend_process_materialization_hash: "sha256:backend-process-materialization"
                .to_string(),
            reason: None,
            superseded_by: None,
            runtime_engine_ref: None,
            load_options: None,
            evidence_refs: vec!["rust_model_mount_provider_lifecycle".to_string()],
        }
    }

    #[test]
    fn instance_lifecycle_child_module_owns_planner_surface() {
        let result = plan_instance_lifecycle(&instance_lifecycle_request())
            .expect("model instance lifecycle planned in Rust");

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
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
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
        assert!(result.instance_lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn model_instance_lifecycle_is_planned_in_rust_model_mount() {
        let result = plan_instance_lifecycle(&instance_lifecycle_request())
            .expect("model instance lifecycle planned in Rust");

        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
    }

    #[test]
    fn model_instance_unload_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = instance_lifecycle_request();
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
        let mut request = instance_lifecycle_request();
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

        request = instance_lifecycle_request();
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
        let mut request = instance_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleBackend);

        request = instance_lifecycle_request();
        request.target_status = "unloaded".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("load action must bind the loaded target status");

        assert_eq!(error, ModelMountError::InstanceLifecycleStatusMismatch);

        request = instance_lifecycle_request();
        request.action = "restart".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner only supports canonical instance transitions");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleAction);

        request = instance_lifecycle_request();
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        let error = plan_instance_lifecycle(&request)
            .expect_err("supersede action must bind its replacement instance");

        assert_eq!(error, ModelMountError::MissingField("superseded_by"));
    }

    #[test]
    fn model_instance_load_estimate_is_planned_in_rust_without_provider_lifecycle() {
        let mut request = instance_lifecycle_request();
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
