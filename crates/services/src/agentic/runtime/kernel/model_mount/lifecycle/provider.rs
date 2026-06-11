use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::{
    push_unique_ref, require_non_empty, ModelMountError,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
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
    pub lifecycle_hash: String,
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
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if !matches!(self.action.trim(), "health" | "load" | "unload") {
            return Err(ModelMountError::UnsupportedProviderLifecycleAction);
        }
        if !is_native_local_provider_lifecycle_backend(self)
            && !is_fixture_provider_lifecycle_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderLifecycleBackend);
        }
        Ok(())
    }
}

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    request.validate()?;
    let mut result = ModelMountProviderLifecycleResult {
        schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
        provider_ref: request.provider_ref.clone(),
        provider_kind: request.provider_kind.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        action: request.action.clone(),
        status: provider_lifecycle_status(request)?,
        backend: provider_lifecycle_backend(request),
        backend_id: provider_lifecycle_backend_id(request),
        driver: provider_lifecycle_driver(request),
        execution_backend: request.execution_backend.clone(),
        evidence_refs: provider_lifecycle_evidence_refs(request),
        lifecycle_hash: String::new(),
    };
    result.lifecycle_hash = provider_lifecycle_hash(&result)?;
    Ok(result)
}

fn is_native_local_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn provider_lifecycle_status(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<String, ModelMountError> {
    match request.action.trim() {
        "health" => {
            if matches!(
                request.provider_status.as_deref().map(str::trim),
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

fn provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "autopilot.native_local.fixture".to_string()
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

fn provider_lifecycle_backend_id(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_lifecycle_driver(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "native_local".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_lifecycle_evidence_refs(request: &ModelMountProviderLifecycleRequest) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_provider_lifecycle".to_string()];
    if is_native_local_provider_lifecycle_backend(request) {
        refs.push("rust_model_mount_native_local_lifecycle_backend".to_string());
        if matches!(request.action.trim(), "health" | "load") {
            refs.push("autopilot_native_local_backend_registry".to_string());
        }
        if matches!(request.action.trim(), "load" | "unload") {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
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

fn provider_lifecycle_hash(
    result: &ModelMountProviderLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
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
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_model_load_request".to_string()],
            process_evidence_refs: vec!["autopilot_native_local_process_started".to_string()],
        }
    }

    fn fixture_provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
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
        }
    }

    #[test]
    fn provider_lifecycle_child_module_owns_planner_surface() {
        let result = plan_provider_lifecycle(&provider_lifecycle_request())
            .expect("native-local provider lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
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
            .contains(&"autopilot_native_local_process_started".to_string()));
        assert!(result.lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "unload".to_string();
        request.evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_health_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "health".to_string();
        request.evidence_refs = vec!["daemon_native_local_health_request".to_string()];
        request.process_evidence_refs.clear();

        let result = plan_provider_lifecycle(&request)
            .expect("native-local provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));

        request.provider_status = Some("blocked".to_string());
        let result = plan_provider_lifecycle(&request)
            .expect("blocked native-local provider health planned in Rust");

        assert_eq!(result.status, "blocked");
    }

    #[test]
    fn fixture_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_lifecycle_request();

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
    fn native_local_provider_lifecycle_rejects_unsupported_backend_and_action() {
        let mut request = provider_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleBackend);

        request = provider_lifecycle_request();
        request.action = "restart".to_string();
        let error = plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner only supports explicit health/load/unload actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleAction);
    }
}
