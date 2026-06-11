use serde_json::Value;

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn engines() -> Value {
    Value::Array(Vec::new())
}

pub(super) fn engine_profiles() -> Value {
    Value::Array(Vec::new())
}

pub(super) fn preference() -> Value {
    Value::Null
}

pub(super) fn preference_for_endpoint() -> Value {
    Value::Null
}

pub(super) fn default_load_options() -> Value {
    Value::Null
}

pub(super) fn engine_detail(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("unknown_runtime_engine");
    Err(ModelMountReadProjectionError::new(
        "model_mount_runtime_engine_not_found",
        format!("runtime engine not found: {engine_id}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use serde_json::json;

    fn request(projection_kind: &str) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: projection_kind.to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: Some("backend.llama-cpp".to_string()),
            provider_id: None,
            base_url: None,
            state: json!({
                "runtime_engines": [
                    {"id": "backend.llama-cpp", "status": "caller_supplied"}
                ],
                "runtime_engine_profiles": [
                    {"engine_id": "backend.llama-cpp", "gpu_layers": 42}
                ],
                "runtime_preference": {"routeId": "route.local-first"},
                "default_load_options": {"gpuLayers": 42},
                "runtime_engine": {"id": "backend.llama-cpp"}
            }),
        }
    }

    #[test]
    fn runtime_projection_defaults_ignore_caller_supplied_js_state() {
        assert_eq!(engines(), json!([]));
        assert_eq!(engine_profiles(), json!([]));
        assert_eq!(preference(), Value::Null);
        assert_eq!(preference_for_endpoint(), Value::Null);
        assert_eq!(default_load_options(), Value::Null);
        let _proof = "runtime engine projection defaults are authored by Rust";
    }

    #[test]
    fn runtime_engine_detail_fails_closed_until_rust_projection_owns_state() {
        let error = engine_detail(&request("runtime_engine_detail"))
            .expect_err("runtime engine detail requires Rust-owned engine state");

        assert_eq!(error.code, "model_mount_runtime_engine_not_found");
        assert_eq!(error.message, "runtime engine not found: backend.llama-cpp");
    }
}
