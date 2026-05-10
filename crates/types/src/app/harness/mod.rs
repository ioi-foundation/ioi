#![allow(missing_docs)]

use crate::app::action::ActionTarget;
use crate::app::adapter::AdapterKind;
use crate::app::events::{
    ExecutionContractReceiptEvent, PlanReceiptEvent, RoutingReceiptEvent, WorkloadReceipt,
    WorkloadReceiptEvent,
};
use parity_scale_codec::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

mod activation;
mod components;
mod core;
mod promotion;
mod receipts;
mod replay;
mod serde_bridge;
mod slots;
mod worker_binding;

pub use activation::*;
pub use components::*;
pub use core::*;
pub use promotion::*;
pub use receipts::*;
pub use serde_bridge::*;
pub use worker_binding::*;

#[cfg(test)]
mod tests;
