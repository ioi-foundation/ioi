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

    fn seeded_instance_lifecycle_state_dir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("instance lifecycle state dir");
        write_json_record(
            temp.path(),
            "model-endpoints",
            "endpoint.native-local.json",
            json!({
                "id": "endpoint.native-local",
                "record_id": "endpoint.native-local",
                "schema_version": "ioi.model_mount.artifact_endpoint.v1",
                "object": "ioi.model_mount_endpoint",
                "status": "mounted",
                "operation_kind": "model_mount.endpoint.mount",
                "source": "runtime-daemon.model_mounting.artifact_endpoint",
                "rust_core_boundary": "model_mount.artifact_endpoint",
                "endpoint_id": "endpoint.native-local",
                "model_id": "model://qwen/qwen3.5-9b",
                "provider_id": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_id": "backend.autopilot.native-local.fixture",
                "privacy_class": "local_private",
                "plaintext_transport_material_returned": false,
                "receipt_refs": ["receipt://endpoint/native-local"],
                "evidence_refs": [
                    "public_artifact_endpoint_js_facade_retired",
                    "rust_daemon_core_artifact_endpoint",
                    "agentgres_artifact_endpoint_truth_required",
                    "rust_daemon_core_model_endpoint_mount"
                ],
                "control_hash": "sha256:control:endpoint.native-local",
                "authority_hash": "sha256:authority:endpoint.native-local",
                "mounted_at": "2026-06-13T00:03:00.000Z"
            }),
        );
        write_json_record(
            temp.path(),
            "model-providers",
            "provider.autopilot.local.json",
            json!({
                "id": "provider.autopilot.local",
                "record_id": "provider.autopilot.local",
                "schema_version": "ioi.model_mount.provider_control.v1",
                "object": "ioi.model_mount_provider",
                "status": "configured",
                "operation_kind": "model_mount.provider.write",
                "source": "rust_daemon_core.model_mount.provider_control",
                "provider_id": "provider.autopilot.local",
                "provider_ref": "provider://provider.autopilot.local",
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
                    "authority_hash": "sha256:authority:provider.autopilot.local",
                    "required_scope": "provider.write:provider.autopilot.local",
                    "authority_grant_refs": ["wallet://grant/provider-control"],
                    "authority_receipt_refs": ["receipt://wallet/provider-control"]
                },
                "control_hash": "sha256:control:provider.autopilot.local",
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
        temp
    }

    #[test]
    fn rust_core_plans_model_mount_provider_lifecycle_direct_api() {
        let temp = seeded_instance_lifecycle_state_dir();
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
            "process_evidence_refs": ["autopilot_native_local_process_started"],
            "state_dir": temp.path().to_string_lossy().to_string()
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
            "backend_ref": "backend.autopilot.native-local.fixture"
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
            response.item_refs,
            vec!["model_instance://native/qwen3".to_string()]
        );
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
        let temp = seeded_instance_lifecycle_state_dir();
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
            "backend_supervision_ref": "backend_supervision://backend.autopilot.native-local.fixture_process#sha256:plan",
            "backend_supervision_hash": "sha256:backend-supervision",
            "backend_supervision_status": "rust_fixture_supervision_bound",
            "state_dir": temp.path().to_string_lossy().to_string(),
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
        assert_eq!(
            response.backend_supervision_hash,
            "sha256:backend-supervision"
        );
        assert!(response.instance_lifecycle_hash.starts_with("sha256:"));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_materialization_bound".to_string()));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_supervision_bound".to_string()));
    }
}
