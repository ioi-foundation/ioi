use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An item in a commerce transaction.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct CommerceItem {
    /// Item ID.
    pub id: String,
    /// Quantity.
    pub quantity: u32,
}
