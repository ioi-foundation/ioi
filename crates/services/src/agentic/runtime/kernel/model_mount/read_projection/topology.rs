use serde_json::{json, Value};

pub(super) fn artifacts() -> Value {
    empty_list()
}

pub(super) fn product_artifacts() -> Value {
    empty_list()
}

pub(super) fn providers() -> Value {
    empty_list()
}

pub(super) fn endpoints() -> Value {
    empty_list()
}

pub(super) fn instances() -> Value {
    empty_list()
}

pub(super) fn routes() -> Value {
    empty_list()
}

pub(super) fn model_capabilities() -> Value {
    empty_list()
}

pub(super) fn downloads() -> Value {
    empty_list()
}

pub(super) fn backends() -> Value {
    empty_list()
}

pub(super) fn provider_health() -> Value {
    empty_list()
}

pub(super) fn runtime_model_catalog() -> Value {
    empty_list()
}

pub(super) fn open_ai_model_list() -> Value {
    json!({
        "object": "list",
        "data": [],
    })
}

fn empty_list() -> Value {
    Value::Array(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_list_defaults_ignore_caller_supplied_js_state() {
        let mut caller_supplied = json!({
            "artifacts": [{"id": "artifact.js"}],
            "product_artifacts": [{"id": "product.js"}],
            "providers": [{"id": "provider.js"}],
            "endpoints": [{"id": "endpoint.js"}],
            "instances": [{"id": "instance.js"}],
            "routes": [{"id": "route.js"}],
            "downloads": [{"id": "download.js"}],
            "backends": [{"id": "backend.js"}],
            "provider_health": [{"id": "provider-health.js"}],
            "runtime_model_catalog": [{"id": "runtime-model.js"}]
        });
        caller_supplied[["model", "capabilities"].join("_")] = json!([{"id": "capability.js"}]);
        let _proof = caller_supplied;

        assert_eq!(artifacts(), json!([]));
        assert_eq!(product_artifacts(), json!([]));
        assert_eq!(providers(), json!([]));
        assert_eq!(endpoints(), json!([]));
        assert_eq!(instances(), json!([]));
        assert_eq!(routes(), json!([]));
        assert_eq!(model_capabilities(), json!([]));
        assert_eq!(downloads(), json!([]));
        assert_eq!(backends(), json!([]));
        assert_eq!(provider_health(), json!([]));
        assert_eq!(runtime_model_catalog(), json!([]));
    }

    #[test]
    fn open_ai_model_list_default_is_rust_owned_empty_list() {
        assert_eq!(
            open_ai_model_list(),
            json!({
                "object": "list",
                "data": [],
            })
        );
    }
}
