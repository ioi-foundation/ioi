// Path: crates/types/src/app/timing.rs
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// On-chain, governance-controlled parameters for block timing.
#[derive(Serialize, Deserialize, Encode, Decode, Clone, Debug, Default)]
pub struct BlockTimingParams {
    /// The neutral block interval when network load matches the target.
    pub base_interval_secs: u64,
    /// The shortest possible block interval, acting as a floor.
    pub min_interval_secs: u64,
    /// The longest possible block interval, acting as a ceiling.
    pub max_interval_secs: u64,
    /// The target amount of gas to be consumed per block, used for calculating network load.
    pub target_gas_per_block: u64,
    /// The smoothing factor (alpha) for the Exponential Moving Average of gas usage, in thousandths.
    pub ema_alpha_milli: u32,
    /// The maximum change (step) in the block interval per retarget, in basis points.
    pub interval_step_bps: u32, // bps = basis points (1/100th of a percent)
    /// The number of blocks between block interval adjustments. If 0, adaptive timing is disabled.
    pub retarget_every_blocks: u32,
}

/// On-chain runtime state for the adaptive block timing mechanism.
#[derive(Serialize, Deserialize, Encode, Decode, Clone, Debug, Default)]
pub struct BlockTimingRuntime {
    /// The Exponential Moving Average of gas used per block.
    pub ema_gas_used: u128,
    /// The current block interval that is in effect.
    pub effective_interval_secs: u64,
}

/// Computes the deterministic block interval for the *next* block based on the *parent* state.
/// This is a pure function and is the single source of truth for both proposers and verifiers.
pub fn compute_interval_from_parent_state(
    params: &BlockTimingParams,
    runtime_state: &BlockTimingRuntime,
    parent_height: u64,
    parent_gas_used: u64,
) -> u64 {
    // If adaptive timing is disabled or it's not a retargeting block, use the last effective interval.
    if params.retarget_every_blocks == 0
        || (parent_height + 1) % params.retarget_every_blocks as u64 != 0
    {
        return runtime_state
            .effective_interval_secs
            .clamp(params.min_interval_secs, params.max_interval_secs);
    }

    let alpha = params.ema_alpha_milli as u128; // 0..1000
    let ema =
        (alpha * parent_gas_used as u128 + (1000 - alpha) * runtime_state.ema_gas_used) / 1000;
    let target = params.target_gas_per_block.max(1) as u128;

    let u_fp = (ema * 10_000) / target; // Utilization ratio in basis points (bps)
    let u_clamped = u_fp.clamp(5_000, 20_000); // Clamp utilization to [0.5x, 2.0x]

    let desired = (params.base_interval_secs as u128 * 10_000) / u_clamped;
    let last = runtime_state.effective_interval_secs as u128;
    let step = (last * params.interval_step_bps as u128) / 10_000;

    let proposed = desired.clamp(last.saturating_sub(step), last + step);
    (proposed as u64).clamp(params.min_interval_secs, params.max_interval_secs)
}

/// A centralized helper to compute the timestamp for the next block.
///
/// This is the canonical implementation that MUST be used by both `decide` and
/// `handle_block_proposal` to ensure consensus.
///
/// # Arguments
/// * `params` - The on-chain `BlockTimingParams` from the parent state.
/// * `runtime_state` - The on-chain `BlockTimingRuntime` from the parent state.
/// * `parent_height` - The height of the parent block (H-1).
/// * `parent_timestamp` - The timestamp (UNIX seconds) of the parent block.
/// * `parent_gas_used` - The total gas used in the parent block.
///
/// # Returns
/// The authoritative UNIX timestamp (in seconds) for the next block (height H).
pub fn compute_next_timestamp(
    params: &BlockTimingParams,
    runtime_state: &BlockTimingRuntime,
    parent_height: u64,
    parent_timestamp: u64,
    parent_gas_used: u64,
) -> Option<u64> {
    // If genesis block (height 0), its timestamp is determined by the application,
    // so we can't compute a "next" timestamp from it in this context.
    // The first block to be produced is block 1.
    if parent_height == 0 {
        // A fixed interval for the very first block can be used.
        return parent_timestamp.checked_add(params.base_interval_secs);
    }

    let interval = compute_interval_from_parent_state(
        params,
        runtime_state,
        parent_height,
        parent_gas_used,
    );

    // The next block's timestamp is the parent's timestamp plus the computed interval.
    parent_timestamp.checked_add(interval)
}