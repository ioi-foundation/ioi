mod instance;
mod inventory;
mod provider;

pub use instance::{ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult};
pub use inventory::{ModelMountProviderInventoryRequest, ModelMountProviderInventoryResult};
pub use provider::{ModelMountProviderLifecycleRequest, ModelMountProviderLifecycleResult};

use super::ModelMountError;

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    provider::plan_provider_lifecycle(request)
}

pub(super) fn plan_provider_inventory(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
    inventory::plan_provider_inventory(request)
}

pub(super) fn plan_instance_lifecycle(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
    instance::plan_instance_lifecycle(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
    };
    use serde_json::json;

    #[test]
    fn rust_core_plans_model_mount_provider_lifecycle_direct_api() {
        let request: ModelMountProviderLifecycleRequest = serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
            "provider_ref": "provider.autopilot.local",
            "provider_kind": "ioi_native_local",
            "endpoint_ref": "endpoint.native-local",
            "model_ref": "model://qwen/qwen3.5-9b",
            "action": "load",
            "execution_backend": "rust_model_mount_native_local_lifecycle",
            "api_format": "ioi_native",
            "driver": "native_local",
            "backend_ref": "backend.autopilot.native-local.fixture",
            "evidence_refs": ["daemon_model_load_request"],
            "process_evidence_refs": ["autopilot_native_local_process_started"]
        }))
        .expect("native-local lifecycle request");

        let response = plan_provider_lifecycle(&request).expect("lifecycle planned");

        assert_eq!(response.status, "loaded");
        assert_eq!(
            response.backend_id,
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response.backend, "autopilot.native_local.fixture");
        assert_eq!(response.driver, "native_local");
        assert!(response.lifecycle_hash.starts_with("sha256:"));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_native_local_lifecycle_backend".to_string()));
        assert_eq!(response.operation_kind, "model_mount.provider.start");
        assert_eq!(
            response.rust_core_boundary,
            "model_mount.provider_lifecycle"
        );
        assert_eq!(response.record_dir, "model-provider-lifecycle-controls");
        assert_eq!(
            response.record["schema_version"],
            MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION
        );
        assert_eq!(
            response.record["object"],
            "ioi.model_mount_provider_lifecycle"
        );
        assert_eq!(
            response.record["rust_core_boundary"],
            "model_mount.provider_lifecycle"
        );
        assert!(response.record["receipt_refs"]
            .as_array()
            .expect("record receipt refs")
            .iter()
            .any(|value| value.as_str() == Some(response.lifecycle_hash.as_str())));
        assert_eq!(response.public_response["js_provider_driver_call"], false);
    }

    #[test]
    fn rust_core_plans_model_mount_provider_inventory_direct_api() {
        let request: ModelMountProviderInventoryRequest = serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
            "provider_ref": "provider.autopilot.local",
            "provider_kind": "ioi_native_local",
            "action": "list_loaded",
            "execution_backend": "rust_model_mount_native_local_inventory",
            "api_format": "ioi_native",
            "driver": "native_local",
            "backend_ref": "backend.autopilot.native-local.fixture",
            "item_refs": ["model_instance://native/qwen3"],
            "evidence_refs": ["daemon_native_local_list_loaded_request"]
        }))
        .expect("native-local inventory request");

        let response = plan_provider_inventory(&request).expect("inventory planned");

        assert_eq!(response.status, "listed");
        assert_eq!(
            response.backend_id,
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response.backend, "autopilot.native_local.fixture");
        assert_eq!(response.driver, "native_local");
        assert_eq!(response.item_count, 1);
        assert_eq!(
            response.operation_kind,
            "model_mount.provider.inventory.list_loaded"
        );
        assert_eq!(
            response.rust_core_boundary,
            "model_mount.provider_inventory"
        );
        assert_eq!(response.record_dir, "model-provider-inventory");
        assert!(response
            .record_id
            .starts_with("provider_inventory_provider.autopilot.local_list_loaded_"));
        assert_eq!(
            response.record["id"].as_str(),
            Some(response.record_id.as_str())
        );
        assert_eq!(
            response.record["object"],
            "ioi.model_mount_provider_inventory"
        );
        assert!(response.inventory_hash.starts_with("sha256:"));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
    }

    #[test]
    fn rust_core_plans_model_mount_instance_lifecycle_direct_api() {
        let request: ModelMountInstanceLifecycleRequest = serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
            "instance_ref": "model_instance://native/qwen3",
            "endpoint_ref": "endpoint.native-local",
            "model_ref": "model://qwen/qwen3.5-9b",
            "provider_ref": "provider.autopilot.local",
            "action": "load",
            "target_status": "loaded",
            "execution_backend": "rust_model_mount_instance_lifecycle",
            "backend_ref": "backend.autopilot.native-local.fixture",
            "driver": "native_local",
            "provider_lifecycle_hash": "sha256:provider-lifecycle",
            "backend_process_ref": "backend_process://backend.autopilot.native-local.fixture_process#sha256:plan",
            "backend_process_materialization_hash": "sha256:backend-process-materialization",
            "evidence_refs": ["rust_model_mount_provider_lifecycle"]
        }))
        .expect("instance lifecycle request");

        let response = plan_instance_lifecycle(&request).expect("instance planned");

        assert_eq!(response.status, "loaded");
        assert_eq!(
            response.backend_id,
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response.driver, "native_local");
        assert_eq!(
            response.provider_lifecycle_hash,
            "sha256:provider-lifecycle"
        );
        assert_eq!(
            response.backend_process_materialization_hash,
            "sha256:backend-process-materialization"
        );
        assert!(response.instance_lifecycle_hash.starts_with("sha256:"));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_materialization_bound".to_string()));
    }
}
