// Path: crates/types/src/app/timing.rs
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

/// On-chain, governance-controlled parameters for block timing.
#[derive(Serialize, Deserialize, Encode, Clone, Debug, Default)]
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

impl Decode for BlockTimingParams {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        // Always present in all versions (legacy and current).
        let base_interval_secs = u64::decode(input)?;
        let min_interval_secs = u64::decode(input)?;
        let max_interval_secs = u64::decode(input)?;
        let target_gas_per_block = u64::decode(input)?;

        // Helper: try to read a u32 if there are at least 4 bytes remaining.
        fn maybe_u32<I: Input>(input: &mut I) -> Result<Option<u32>, parity_scale_codec::Error> {
            match input.remaining_len()? {
                // Known remaining length:
                Some(rem) if rem >= 4 => Ok(Some(u32::decode(input)?)),
                // No remaining bytes or unknown length: treat as "field missing".
                _ => Ok(None),
            }
        }

        // New fields were appended at the end. If the value was encoded with the
        // legacy 4-field layout, there will be exactly 0 bytes left at this point,
        // and all of these will default to 0.
        let ema_alpha_milli = maybe_u32(input)?.unwrap_or(0);
        let interval_step_bps = maybe_u32(input)?.unwrap_or(0);
        let retarget_every_blocks = maybe_u32(input)?.unwrap_or(0);

        Ok(BlockTimingParams {
            base_interval_secs,
            min_interval_secs,
            max_interval_secs,
            target_gas_per_block,
            ema_alpha_milli,
            interval_step_bps,
            retarget_every_blocks,
        })
    }
}

/// On-chain runtime state for the adaptive block timing mechanism.
#[derive(Serialize, Deserialize, Encode, Clone, Debug, Default)]
pub struct BlockTimingRuntime {
    /// The Exponential Moving Average of gas used per block.
    pub ema_gas_used: u128,
    /// The current block interval that is in effect.
    pub effective_interval_secs: u64,
}

// NOTE: BlockTimingRuntime used to have a larger layout (extra fields appended).
// Old genesis/state values are therefore *longer* than the new 2-field struct.
// We implement a custom Decode that:
//   - Reads the two current fields.
//   - Consumes (and discards) any remaining bytes so canonical decoding succeeds.
impl Decode for BlockTimingRuntime {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let ema_gas_used = u128::decode(input)?;
        let effective_interval_secs = u64::decode(input)?;

        // Drain any trailing bytes for forward compatibility with legacy encodings.
        match input.remaining_len()? {
            Some(0) | None => {
                // Nothing left or unknown length but assume "just enough".
            }
            Some(rem) => {
                for _ in 0..rem {
                    // Decode and discard individual bytes.
                    // This is layout-agnostic: we don't care how old versions grouped fields.
                    let _ = u8::decode(input)?;
                }
            }
        }

        Ok(BlockTimingRuntime {
            ema_gas_used,
            effective_interval_secs,
        })
    }
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

    let interval =
        compute_interval_from_parent_state(params, runtime_state, parent_height, parent_gas_used);

    // The next block's timestamp is the parent's timestamp plus the computed interval.
    parent_timestamp.checked_add(interval)
}
