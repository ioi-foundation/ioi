// Path: crates/api/src/services/access.rs

//! Read-only access to shared blockchain services.

use crate::identity::CredentialsView;
use crate::lifecycle::OnEndBlock;
use crate::transaction::decorator::TxDecorator;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// A marker trait for any struct that can be stored in the ServiceDirectory.
pub trait Service: Any + Send + Sync {
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Attempts to downcast this service to a `TxDecorator` trait object.
    fn as_tx_decorator(&self) -> Option<&dyn TxDecorator> {
        None
    }

    /// Attempts to downcast this service to an `OnEndBlock` trait object.
    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        None
    }

    /// Attempts to downcast this service to a `CredentialsView` trait object.
    fn as_credentials_view(&self) -> Option<&dyn CredentialsView> {
        None
    }
}

/// A helper macro to reduce boilerplate for simple services that don't
/// need to override any special downcasting methods.
#[macro_export]
macro_rules! impl_service_base {
    ($type:ty) => {
        impl $crate::services::access::Service for $type {
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
    ordered: Arc<Vec<Arc<dyn Service>>>,
    /// A map for fast, type-based lookups.
    by_type: Arc<HashMap<TypeId, Arc<dyn Service>>>,
}

impl fmt::Debug for ServiceDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceDirectory")
            .field("service_count", &self.ordered.len())
            .finish()
    }
}

impl ServiceDirectory {
    /// Creates a new directory from a list of services. The provided order is preserved for deterministic iteration.
    pub fn new(services: Vec<Arc<dyn Service>>) -> Self {
        let mut by_type = HashMap::new();
        for s in &services {
            by_type.insert(s.as_any().type_id(), s.clone());
        }
        Self {
            ordered: Arc::new(services),
            by_type: Arc::new(by_type),
        }
    }

    /// Gets a service by its concrete type.
    pub fn get<T: Service + 'static>(&self) -> Option<Arc<T>> {
        self.by_type
            .get(&TypeId::of::<T>())
            .and_then(|svc| (svc.clone() as Arc<dyn Any + Send + Sync>).downcast::<T>().ok())
    }

    /// Returns a deterministically ordered iterator over all stored services.
    /// This is critical for ante handlers to run in the same order on all nodes.
    pub fn services_in_deterministic_order(&self) -> impl Iterator<Item = &Arc<dyn Service>> {
        self.ordered.iter()
    }

    /// Returns an iterator over all stored service trait objects in a deterministic order.
    pub fn services(&self) -> impl Iterator<Item = &Arc<dyn Service>> {
        self.ordered.iter()
    }
}