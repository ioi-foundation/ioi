use serde_json::Value;

use super::ModelMountReadProjectionError;

pub(super) fn status() -> Result<Value, ModelMountReadProjectionError> {
    Err(ModelMountReadProjectionError::new(
        "model_catalog_status_js_readback_retired",
        "Model catalog status readback requires Rust daemon-core catalog projection",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_catalog_status_readback_fails_closed_in_rust_boundary() {
        let error = status().expect_err("direct catalog status readback is retired");

        assert_eq!(error.code, "model_catalog_status_js_readback_retired");
        assert!(error
            .message
            .contains("Rust daemon-core catalog projection"));
    }
}
