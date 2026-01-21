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
        /// The session ID associated with this interception (if available).
        session_id: Option<[u8; 32]>, // [NEW] Added session_id
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

    /// [NEW] The result of an agent action execution.
    AgentActionResult {
        /// The session ID the action belongs to.
        session_id: [u8; 32],
        /// The sequence number of the step.
        step_index: u32,
        /// The name of the tool executed (e.g. "sys__exec").
        tool_name: String,
        /// The output/result of the execution (e.g. stdout).
        output: String,
    },
}