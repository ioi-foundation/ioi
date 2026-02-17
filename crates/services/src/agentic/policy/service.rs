use ioi_api::state::StateAccess;
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ioi_types::{codec, error::TransactionError, keys::active_service_key};

use super::PolicyEngine;

impl PolicyEngine {
    /// Checks permission for a `CallService` transaction based on the service's ABI metadata.
    pub fn check_service_call(
        state: &dyn StateAccess,
        service_id: &str,
        method: &str,
        is_internal: bool,
    ) -> Result<(), TransactionError> {
        let meta_key = active_service_key(service_id);
        let maybe_meta_bytes = state.get(&meta_key)?;

        let meta: ActiveServiceMeta = if let Some(bytes) = maybe_meta_bytes {
            codec::from_bytes_canonical(&bytes)?
        } else {
            return Err(TransactionError::Unsupported(format!(
                "Service '{}' is not active",
                service_id
            )));
        };

        let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
        if state.get(&disabled_key)?.is_some() {
            return Err(TransactionError::Unsupported(format!(
                "Service '{}' is administratively disabled",
                service_id
            )));
        }

        let perm = meta.methods.get(method).ok_or_else(|| {
            TransactionError::Unsupported(format!(
                "Method '{}' not found in service '{}' ABI",
                method, service_id
            ))
        })?;

        if let MethodPermission::Internal = perm {
            if !is_internal {
                return Err(TransactionError::Invalid(
                    "Internal method cannot be called via transaction".into(),
                ));
            }
        }

        Ok(())
    }
}
