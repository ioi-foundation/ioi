use serde_json::{json, Value};

use super::common::model_mount_projection_schema_version;
use super::ModelMountReadProjectionRequest;

pub(super) fn server_status(request: &ModelMountReadProjectionRequest) -> Value {
    let base_url = request.base_url.clone();
    let native_base_url = base_url
        .as_ref()
        .map(|url| format!("{url}/api/v1"))
        .unwrap_or_else(|| "/api/v1".to_string());
    let open_ai_compatible_base_url = base_url
        .as_ref()
        .map(|url| format!("{url}/v1"))
        .unwrap_or_else(|| "/v1".to_string());
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "status": "stopped",
        "gatewayStatus": "running",
        "controlStatus": "running",
        "lastServerOperation": "server_status",
        "lastServerOperationAt": Value::Null,
        "lastServerReceiptId": Value::Null,
        "nativeBaseUrl": native_base_url,
        "openAiCompatibleBaseUrl": open_ai_compatible_base_url,
        "loadedInstances": 0,
        "mountedEndpoints": 0,
        "providerStates": {
            "available": 0,
            "degraded": 0,
        },
        "backendStates": {
            "available": 0,
            "degraded": 0,
        },
        "idleTtlSeconds": 900,
        "autoEvict": true,
        "checkedAt": Value::Null,
    })
}

pub(super) fn catalog_status(request: &ModelMountReadProjectionRequest) -> Value {
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "checkedAt": Value::Null,
        "providers": [],
        "adapterBoundary": catalog_adapter_boundary(),
        "filters": {
            "formats": ["gguf", "mlx", "safetensors"],
            "quantization": ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
            "compatibility": ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
        },
        "storage": Value::Null,
        "lastSearch": Value::Null,
        "results": [],
    })
}

fn catalog_adapter_boundary() -> Value {
    json!({
        "port": "ModelCatalogProviderPort",
        "operations": ["search", "resolveVariant", "importUrl", "download", "health"],
        "evidenceRefs": ["provider_neutral_model_catalog_adapter_boundary"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

    #[test]
    fn server_status_is_planned_in_rust_model_mount_projection() {
        let status = server_status(&ModelMountReadProjectionRequest {
            projection_kind: "server_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: None,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: Some("http://127.0.0.1:3200".to_string()),
            state: json!({
                "provider_statuses": [{"status": "available"}],
            }),
        });

        assert_eq!(status["schemaVersion"], MODEL_MOUNT_RUNTIME_SCHEMA_VERSION);
        assert_eq!(status["status"], "stopped");
        assert_eq!(status["nativeBaseUrl"], "http://127.0.0.1:3200/api/v1");
        assert_eq!(
            status["openAiCompatibleBaseUrl"],
            "http://127.0.0.1:3200/v1"
        );
        assert_eq!(status["loadedInstances"], 0);
        assert_eq!(status["mountedEndpoints"], 0);
    }

    #[test]
    fn catalog_status_is_planned_in_rust_model_mount_projection() {
        let status = catalog_status(&ModelMountReadProjectionRequest {
            projection_kind: "catalog_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: None,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state: json!({
                "catalog_status_input": {"checkedAt": "retired-js-input"},
            }),
        });

        assert_eq!(status["schemaVersion"], MODEL_MOUNT_RUNTIME_SCHEMA_VERSION);
        assert_eq!(
            status["adapterBoundary"]["port"],
            "ModelCatalogProviderPort"
        );
        assert_eq!(status["providers"].as_array().expect("providers").len(), 0);
        assert_eq!(status["storage"], Value::Null);
        assert_eq!(status["lastSearch"], Value::Null);
        assert_eq!(status["results"].as_array().expect("results").len(), 0);
    }
}
