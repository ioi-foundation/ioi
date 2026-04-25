use ioi_types::app::ActionRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIntent {
    pub intent_id: String,
    pub source: String,
    pub request: ActionRequest,
    pub intent_hash: [u8; 32],
}
