// Path: crates/types/src/app/events.rs

use crate::app::agentic::StepTrace;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// A unified event type representing observable state changes within the Kernel.
/// These events are streamed to the UI (Autopilot) to provide visual feedback
/// and "Visual Sovereignty".
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub enum KernelEvent {
    /// The agent "thought" or took a step (Thought -> Action -> Output).
    AgentStep(StepTrace),

    /// The Agency Firewall intercepted an action.
    FirewallInterception {
        /// The decision made ("BLOCK", "REQUIRE_APPROVAL", "ALLOW").
        verdict: String,
        /// The target capability (e.g., "net::fetch").
        target: String,
        /// The hash of the ActionRequest, used for signing ApprovalTokens.
        request_hash: [u8; 32],
    },

    /// The user performed a physical input while in Ghost Mode (Recording).
    GhostInput {
        /// The input device ("mouse", "keyboard").
        device: String,
        /// Human-readable description of the input (e.g., "Click(100, 200)").
        description: String,
    },

    /// A new block was committed to the local chain state.
    BlockCommitted {
        /// The height of the committed block.
        height: u64,
        /// The number of transactions included in the block.
        tx_count: u64,
    },
}
