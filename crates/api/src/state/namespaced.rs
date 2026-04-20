// Path: crates/api/src/state/namespaced.rs

//! A state access wrapper that enforces namespacing and permissions for services.

use crate::state::{StateAccess, StateError, StateScanIter};
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;

/// A wrapper that provides namespaced, isolated access to a StateAccess object.
///
/// It enforces two critical security policies:
/// 1.  **Namespacing:** All keys that do not start with `system::` are automatically
///     prefixed with `_service_data::{service_id}::`, creating a private keyspace for each service.
/// 2.  **Allowlist:** Access to `system::` keys is denied unless the service's manifest
///     explicitly lists the requested key prefix in its `allowed_system_prefixes`.
pub struct NamespacedStateAccess<'a> {
    inner: &'a mut dyn StateAccess,
    prefix: Vec<u8>,
    meta: &'a ActiveServiceMeta,
}

impl<'a> NamespacedStateAccess<'a> {
    /// Creates a new namespaced state accessor for a service.
    pub fn new(
        inner: &'a mut dyn StateAccess,
        prefix: Vec<u8>,
        meta: &'a ActiveServiceMeta,
    ) -> Self {
        Self {
            inner,
            prefix,
            meta,
        }
    }

    fn is_allowlisted_system_prefix(&self, key: &[u8]) -> bool {
        self.meta
            .allowed_system_prefixes
            .iter()
            .any(|p| key.starts_with(p.as_bytes()))
    }

    // Active service metadata is global chain configuration and must be visible
    // to all services for deterministic capability/tool discovery.
    fn is_globally_readable_prefix(key: &[u8]) -> bool {
        key.starts_with(UPGRADE_ACTIVE_SERVICE_PREFIX)
    }

    /// Qualifies a key for read access by either passing through known global keys,
    /// honoring the configured allowlist, or prefixing with the service namespace.
    #[inline]
    fn qualify_read(&self, key: &[u8]) -> Result<Vec<u8>, StateError> {
        if self.is_allowlisted_system_prefix(key) || Self::is_globally_readable_prefix(key) {
            Ok(key.to_vec())
        } else {
            if key.starts_with(b"_service_data::") {
                return Err(StateError::PermissionDenied(format!(
                    "Service '{}' attempted to access raw service data key '{}'",
                    self.meta.id,
                    String::from_utf8_lossy(key)
                )));
            }
            Ok([self.prefix.as_slice(), key].concat())
        }
    }

    /// Qualifies a key for write access by either honoring the configured allowlist
    /// or prefixing with the service namespace.
    #[inline]
    fn qualify_write(&self, key: &[u8]) -> Result<Vec<u8>, StateError> {
        if self.is_allowlisted_system_prefix(key) {
            Ok(key.to_vec())
        } else {
            if key.starts_with(b"_service_data::") {
                return Err(StateError::PermissionDenied(format!(
                    "Service '{}' attempted to access raw service data key '{}'",
                    self.meta.id,
                    String::from_utf8_lossy(key)
                )));
            }
            Ok([self.prefix.as_slice(), key].concat())
        }
    }
}

impl<'a> StateAccess for NamespacedStateAccess<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        self.inner.get(&self.qualify_read(key)?)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.inner.insert(&self.qualify_write(key)?, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.inner.delete(&self.qualify_write(key)?)
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        let mapped: Vec<(Vec<u8>, Vec<u8>)> = updates
            .iter()
            .map(|(k, v)| self.qualify_write(k).map(|qk| (qk, v.clone())))
            .collect::<Result<_, _>>()?;
        self.inner.batch_set(&mapped)
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mapped: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| self.qualify_read(k))
            .collect::<Result<_, _>>()?;
        self.inner.batch_get(&mapped)
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        let mapped_inserts: Vec<(Vec<u8>, Vec<u8>)> = inserts
            .iter()
            .map(|(k, v)| self.qualify_write(k).map(|qk| (qk, v.clone())))
            .collect::<Result<_, _>>()?;
        let mapped_deletes: Vec<Vec<u8>> = deletes
            .iter()
            .map(|k| self.qualify_write(k))
            .collect::<Result<_, _>>()?;
        self.inner.batch_apply(&mapped_inserts, &mapped_deletes)
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let effective_prefix = self.qualify_read(prefix)?;
        self.inner.prefix_scan(&effective_prefix)
    }
}

/// A read-only version of `NamespacedStateAccess` that wraps an immutable reference
/// to `StateAccess`.
///
/// This is used during the `validate_ante` phase of transaction processing to enforce
/// that no state mutations occur during validation checks, while still applying
/// correct namespace isolation rules.
pub struct ReadOnlyNamespacedStateAccess<'a> {
    inner: &'a dyn StateAccess,
    prefix: Vec<u8>,
    meta: &'a ActiveServiceMeta,
}

impl<'a> ReadOnlyNamespacedStateAccess<'a> {
    /// Creates a new read-only namespaced state accessor.
    pub fn new(inner: &'a dyn StateAccess, prefix: Vec<u8>, meta: &'a ActiveServiceMeta) -> Self {
        Self {
            inner,
            prefix,
            meta,
        }
    }

    fn is_allowlisted_system_prefix(&self, key: &[u8]) -> bool {
        self.meta
            .allowed_system_prefixes
            .iter()
            .any(|p| key.starts_with(p.as_bytes()))
    }

    fn is_globally_readable_prefix(key: &[u8]) -> bool {
        key.starts_with(UPGRADE_ACTIVE_SERVICE_PREFIX)
    }

    /// Qualifies a key for read-only access.
    #[inline]
    fn qualify(&self, key: &[u8]) -> Result<Vec<u8>, StateError> {
        if self.is_allowlisted_system_prefix(key) || Self::is_globally_readable_prefix(key) {
            Ok(key.to_vec())
        } else {
            if key.starts_with(b"_service_data::") {
                return Err(StateError::PermissionDenied(format!(
                    "Service '{}' attempted to access raw service data key '{}'",
                    self.meta.id,
                    String::from_utf8_lossy(key)
                )));
            }
            Ok([self.prefix.as_slice(), key].concat())
        }
    }
}

impl<'a> StateAccess for ReadOnlyNamespacedStateAccess<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        self.inner.get(&self.qualify(key)?)
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Write attempted in read-only validation context".into(),
        ))
    }

    fn delete(&mut self, _key: &[u8]) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Delete attempted in read-only validation context".into(),
        ))
    }

    fn batch_set(&mut self, _updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Batch set attempted in read-only validation context".into(),
        ))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mapped: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| self.qualify(k))
            .collect::<Result<_, _>>()?;
        self.inner.batch_get(&mapped)
    }

    fn batch_apply(
        &mut self,
        _inserts: &[(Vec<u8>, Vec<u8>)],
        _deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        Err(StateError::PermissionDenied(
            "Batch apply attempted in read-only validation context".into(),
        ))
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let effective_prefix = self.qualify(prefix)?;
        self.inner.prefix_scan(&effective_prefix)
    }
}

/// Helper to generate a canonical namespace prefix for a service.
pub fn service_namespace_prefix(service_id: &str) -> Vec<u8> {
    format!("_service_data::{}::", service_id).into_bytes()
}

#[cfg(test)]
#[path = "namespaced/tests.rs"]
mod tests;
