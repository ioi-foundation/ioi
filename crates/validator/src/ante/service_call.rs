// Path: crates/validator/src/ante/service_call.rs
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::{
    codec,
    error::TransactionError,
    keys::active_service_key,
};
use depin_sdk_types::service_configs::{ActiveServiceMeta, MethodPermission};
use tracing::{debug, warn};

/// Ante precheck for CallService.
/// Ensures ABI presence or applies the narrow svc-ibc fallback for ibc::msg_dispatch@v1.
/// Also enforces that Internal methods are not callable by user txs.
pub fn precheck_call_service(
    state: &dyn StateAccessor,
    service_id: &str,
    method: &str,
    is_internal: bool,
) -> Result<MethodPermission, TransactionError> {
    debug!(target = "ante", "precheck CallService {}::{}", service_id, method);

    let meta_key = active_service_key(service_id);
    let maybe_meta_bytes = state.get(&meta_key)?;

    let meta: Option<ActiveServiceMeta> = if let Some(bytes) = maybe_meta_bytes {
        Some(codec::from_bytes_canonical::<ActiveServiceMeta>(&bytes)?)
    } else {
        #[cfg(feature = "svc-ibc")]
        {
            if service_id == "ibc" && method == "msg_dispatch@v1" {
                warn!(target = "ante",
                    "ActiveServiceMeta missing for {}::{}; allowing as User (svc-ibc)",
                    service_id, method);
                return Ok(MethodPermission::User);
            }
        }
        return Err(TransactionError::Unsupported(format!(
            "Service '{}' is not active", service_id
        )));
    };

    let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
    if state.get(&disabled_key)?.is_some() {
        return Err(TransactionError::Unsupported(format!(
            "Service '{}' is administratively disabled", service_id
        )));
    }

    let perm = if let Some(p) = meta.as_ref().and_then(|m| m.methods.get(method)).cloned() {
        p
    } else {
        #[cfg(feature = "svc-ibc")]
        {
            if service_id == "ibc" && method == "msg_dispatch@v1" {
                warn!(target = "ante",
                    "Method missing for {}::{}; allowing as User (svc-ibc)",
                    service_id, method);
                MethodPermission::User
            } else {
                return Err(TransactionError::Unsupported(format!(
                    "Method '{}' not found in service '{}' ABI", method, service_id
                )));
            }
        }
        #[cfg(not(feature = "svc-ibc"))]
        {
            return Err(TransactionError::Unsupported(format!(
                "Method '{}' not found in service '{}' ABI", method, service_id
            )));
        }
    };

    if let MethodPermission::Internal = perm {
        if !is_internal {
            return Err(TransactionError::Invalid(
                "Internal method cannot be called via transaction".into(),
            ));
        }
    }

    Ok(perm)
}