use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionEventRef {
    pub event_id: String,
    pub authority_tier: String,
}
