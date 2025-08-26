// Path: crates/api/src/services/access.rs
//! Read-only access to shared blockchain services.

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
    services: Arc<HashMap<TypeId, Arc<dyn Service>>>,
}

impl fmt::Debug for ServiceDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceDirectory")
            .field("service_count", &self.services.len())
            .finish()
    }
}

impl ServiceDirectory {
    /// Creates a new directory from a list of services.
    pub fn new(services: Vec<Arc<dyn Service>>) -> Self {
        let mut map = HashMap::new();
        for service in services {
            map.insert(service.as_any().type_id(), service);
        }
        Self {
            services: Arc::new(map),
        }
    }

    /// Gets a service by its concrete type.
    pub fn get<T: Service + 'static>(&self) -> Option<Arc<T>> {
        self.services
            .get(&TypeId::of::<T>())
            .and_then(|service_arc| {
                let any_arc = service_arc.clone() as Arc<dyn Any + Send + Sync>;
                any_arc.downcast::<T>().ok()
            })
    }

    /// Returns an iterator over all stored service trait objects.
    pub fn services(&self) -> impl Iterator<Item = &Arc<dyn Service>> {
        self.services.values()
    }
}