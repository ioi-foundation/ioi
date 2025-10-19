// Path: crates/api/src/services/access.rs

//! Read-only access to shared blockchain services.

use crate::services::BlockchainService;
use std::any::TypeId;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// A helper macro to reduce boilerplate for simple services that don't
/// need to override any special downcasting methods.
#[macro_export]
macro_rules! impl_service_base {
    ($type:ty, $id:expr) => {
        impl $crate::services::BlockchainService for $type {
            fn id(&self) -> &'static str {
                $id
            }
            fn abi_version(&self) -> u32 {
                1
            }
            fn state_schema(&self) -> &'static str {
                "v1"
            }
            fn capabilities(&self) -> depin_sdk_types::service_configs::Capabilities {
                depin_sdk_types::service_configs::Capabilities::empty()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
    };
}

/// A read-only, type-safe service locator.
#[derive(Clone, Default)]
pub struct ServiceDirectory {
    /// A deterministically ordered list of services, crucial for ante handlers.
    ordered: Arc<Vec<Arc<dyn BlockchainService>>>,
    /// A map for fast, type-based lookups.
    by_type: Arc<HashMap<TypeId, Arc<dyn BlockchainService>>>,
}

impl fmt::Debug for ServiceDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceDirectory")
            .field("service_count", &self.ordered.len())
            .finish()
    }
}

impl ServiceDirectory {
    /// Creates a new directory from a list of services.
    /// Services are sorted lexicographically by their `id()` to ensure deterministic iteration order.
    pub fn new(mut services: Vec<Arc<dyn BlockchainService>>) -> Self {
        let mut by_type = HashMap::new();
        // Sort by unique service ID for deterministic ordering.
        services.sort_by_key(|s| s.id());
        for s in &services {
            by_type.insert(s.as_any().type_id(), s.clone());
        }
        Self {
            ordered: Arc::new(services),
            by_type: Arc::new(by_type),
        }
    }

    /// Gets a service by its concrete type.
    pub fn get<T: BlockchainService + 'static>(&self) -> Option<Arc<T>> {
        self.by_type
            .get(&TypeId::of::<T>())
            .and_then(|svc| Arc::downcast(svc.clone()).ok())
    }

    /// Returns a deterministically ordered iterator over all stored services.
    /// This is critical for ante handlers to run in the same order on all nodes.
    pub fn services_in_deterministic_order(
        &self,
    ) -> impl Iterator<Item = &Arc<dyn BlockchainService>> {
        self.ordered.iter()
    }

    /// Returns an iterator over all stored service trait objects in a deterministic order.
    pub fn services(&self) -> impl Iterator<Item = &Arc<dyn BlockchainService>> {
        self.ordered.iter()
    }

    /// An efficient, deterministic iterator for the dispatcher.
    pub fn iter_deterministic(&self) -> std::slice::Iter<'_, Arc<dyn BlockchainService>> {
        self.ordered.iter()
    }
}