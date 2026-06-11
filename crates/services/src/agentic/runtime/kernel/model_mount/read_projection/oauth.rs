use serde_json::Value;

use super::ModelMountReadProjectionError;

pub(super) fn sessions() -> Result<Value, ModelMountReadProjectionError> {
    Err(ModelMountReadProjectionError::new(
        "model_mount_oauth_read_projection_js_retired",
        "OAuth session read projection requires Rust daemon-core wallet/cTEE projection",
    ))
}

pub(super) fn states() -> Result<Value, ModelMountReadProjectionError> {
    Err(ModelMountReadProjectionError::new(
        "model_mount_oauth_read_projection_js_retired",
        "OAuth state read projection requires Rust daemon-core wallet/cTEE projection",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_session_read_projection_fails_closed_in_rust_boundary() {
        let error = sessions().expect_err("OAuth session readback is retired");

        assert_eq!(error.code, "model_mount_oauth_read_projection_js_retired");
        assert!(error.message.contains("wallet/cTEE projection"));
    }

    #[test]
    fn oauth_state_read_projection_fails_closed_in_rust_boundary() {
        let error = states().expect_err("OAuth state readback is retired");

        assert_eq!(error.code, "model_mount_oauth_read_projection_js_retired");
        assert!(error.message.contains("wallet/cTEE projection"));
    }
}
