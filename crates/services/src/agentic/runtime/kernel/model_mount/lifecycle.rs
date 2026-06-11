mod instance;
mod inventory;
mod provider;

pub use instance::{ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult};
pub use inventory::{ModelMountProviderInventoryRequest, ModelMountProviderInventoryResult};
pub use provider::{ModelMountProviderLifecycleRequest, ModelMountProviderLifecycleResult};

use super::ModelMountError;

pub(super) fn plan_provider_lifecycle(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
    provider::plan_provider_lifecycle(request)
}

pub(super) fn plan_provider_inventory(
    request: &ModelMountProviderInventoryRequest,
) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
    inventory::plan_provider_inventory(request)
}

pub(super) fn plan_instance_lifecycle(
    request: &ModelMountInstanceLifecycleRequest,
) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
    instance::plan_instance_lifecycle(request)
}
