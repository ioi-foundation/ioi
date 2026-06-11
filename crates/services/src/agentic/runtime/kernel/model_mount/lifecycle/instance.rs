use serde::{Deserialize, Serialize};
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
    pub provider_lifecycle_hash: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleResult {
    pub schema_version: String,
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
        require_non_empty("provider_lifecycle_hash", &self.provider_lifecycle_hash)?;
        if self.execution_backend.trim() != "rust_model_mount_instance_lifecycle" {
            return Err(ModelMountError::UnsupportedInstanceLifecycleBackend);
        }
        match self.action.trim() {
            "load" if self.target_status.trim() == "loaded" => Ok(()),
            "unload" if self.target_status.trim() == "unloaded" => Ok(()),
            "evict" if self.target_status.trim() == "evicted" => Ok(()),
            "supersede" if self.target_status.trim() == "superseded" => Ok(()),
            "load" | "unload" | "evict" | "supersede" => {
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
        instance_ref: request.instance_ref.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        provider_ref: request.provider_ref.clone(),
        action: request.action.clone(),
        status: request.target_status.clone(),
        backend_id: request.backend_ref.clone(),
        driver: request.driver.clone(),
        execution_backend: request.execution_backend.clone(),
        provider_lifecycle_hash: request.provider_lifecycle_hash.clone(),
        evidence_refs: instance_lifecycle_evidence_refs(request),
        instance_lifecycle_hash: String::new(),
    };
    result.instance_lifecycle_hash = instance_lifecycle_hash(&result)?;
    Ok(result)
}

fn instance_lifecycle_evidence_refs(request: &ModelMountInstanceLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_instance_lifecycle".to_string(),
        "rust_model_mount_provider_lifecycle_bound".to_string(),
        "agentgres_model_instance_registry_planned".to_string(),
    ];
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
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
        request.evidence_refs = vec!["model_idle_evict".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model instance eviction lifecycle planned in Rust");

        assert_eq!(result.action, "evict");
        assert_eq!(result.status, "evicted");
        assert!(result
            .evidence_refs
            .contains(&"model_idle_evict".to_string()));

        request = instance_lifecycle_request();
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        request.evidence_refs = vec!["model_supersede".to_string()];

        let result = plan_instance_lifecycle(&request)
            .expect("model instance supersede lifecycle planned in Rust");

        assert_eq!(result.action, "supersede");
        assert_eq!(result.status, "superseded");
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
    }
}
