mod backend_lifecycle;
mod route_control;
mod runtime_engine;
mod server_control;
mod tokenizer;

pub use backend_lifecycle::{
    ModelMountBackendLifecycleRequiredRecord, ModelMountBackendLifecycleRequiredRequest,
};
pub use route_control::{
    ModelMountRouteControlRequiredRecord, ModelMountRouteControlRequiredRequest,
};
pub use runtime_engine::{
    ModelMountRuntimeEngineRequiredRecord, ModelMountRuntimeEngineRequiredRequest,
};
pub use server_control::{
    ModelMountServerControlRequiredRecord, ModelMountServerControlRequiredRequest,
};
pub use tokenizer::{ModelMountTokenizerRequiredRecord, ModelMountTokenizerRequiredRequest};

use super::ModelMountError;

pub fn plan_backend_lifecycle_required(
    request: &ModelMountBackendLifecycleRequiredRequest,
) -> Result<ModelMountBackendLifecycleRequiredRecord, ModelMountError> {
    backend_lifecycle::plan_backend_lifecycle_required(request)
}

pub fn plan_server_control_required(
    request: &ModelMountServerControlRequiredRequest,
) -> Result<ModelMountServerControlRequiredRecord, ModelMountError> {
    server_control::plan_server_control_required(request)
}

pub fn plan_runtime_engine_required(
    request: &ModelMountRuntimeEngineRequiredRequest,
) -> Result<ModelMountRuntimeEngineRequiredRecord, ModelMountError> {
    runtime_engine::plan_runtime_engine_required(request)
}

pub fn plan_tokenizer_required(
    request: &ModelMountTokenizerRequiredRequest,
) -> Result<ModelMountTokenizerRequiredRecord, ModelMountError> {
    tokenizer::plan_tokenizer_required(request)
}

pub fn plan_route_control_required(
    request: &ModelMountRouteControlRequiredRequest,
) -> Result<ModelMountRouteControlRequiredRecord, ModelMountError> {
    route_control::plan_route_control_required(request)
}
