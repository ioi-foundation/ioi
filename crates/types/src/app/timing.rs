// Path: crates/types/src/app/timing.rs
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

const MILLIS_PER_SECOND: u64 = 1_000;

/// Converts a legacy second-based timestamp or interval into milliseconds.
#[inline]
pub fn seconds_to_millis(seconds: u64) -> u64 {
    seconds.saturating_mul(MILLIS_PER_SECOND)
}

/// Mirrors a millisecond timestamp into the legacy whole-second block header field.
#[inline]
pub fn timestamp_millis_to_legacy_seconds(ms: u64) -> u64 {
    ms / MILLIS_PER_SECOND
}

/// Mirrors a millisecond interval into the legacy second interval field using ceiling rounding.
#[inline]
pub fn interval_millis_to_legacy_seconds(ms: u64) -> u64 {
    if ms == 0 {
        0
    } else {
        ms.saturating_add(MILLIS_PER_SECOND - 1) / MILLIS_PER_SECOND
    }
}

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
    /// The neutral block interval when network load matches the target, in milliseconds.
    #[serde(default)]
    pub base_interval_ms: u64,
    /// The shortest possible block interval, in milliseconds.
    #[serde(default)]
    pub min_interval_ms: u64,
    /// The longest possible block interval, in milliseconds.
    #[serde(default)]
    pub max_interval_ms: u64,
}

impl BlockTimingParams {
    /// Returns the authoritative base interval in milliseconds, falling back to legacy seconds.
    pub fn base_interval_ms_or_legacy(&self) -> u64 {
        if self.base_interval_ms > 0 {
            self.base_interval_ms
        } else {
            seconds_to_millis(self.base_interval_secs)
        }
    }

    /// Returns the authoritative minimum interval in milliseconds, falling back to legacy seconds.
    pub fn min_interval_ms_or_legacy(&self) -> u64 {
        if self.min_interval_ms > 0 {
            self.min_interval_ms
        } else {
            seconds_to_millis(self.min_interval_secs)
        }
    }

    /// Returns the authoritative maximum interval in milliseconds, falling back to legacy seconds.
    pub fn max_interval_ms_or_legacy(&self) -> u64 {
        if self.max_interval_ms > 0 {
            self.max_interval_ms
        } else {
            seconds_to_millis(self.max_interval_secs)
        }
    }
}

impl Decode for BlockTimingParams {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let base_interval_secs = u64::decode(input)?;
        let min_interval_secs = u64::decode(input)?;
        let max_interval_secs = u64::decode(input)?;
        let target_gas_per_block = u64::decode(input)?;
        let ema_alpha_milli = u32::decode(input)?;
        let interval_step_bps = u32::decode(input)?;
        let retarget_every_blocks = u32::decode(input)?;
        let base_interval_ms = u64::decode(input)
            .ok()
            .unwrap_or_else(|| seconds_to_millis(base_interval_secs));
        let min_interval_ms = u64::decode(input)
            .ok()
            .unwrap_or_else(|| seconds_to_millis(min_interval_secs));
        let max_interval_ms = u64::decode(input)
            .ok()
            .unwrap_or_else(|| seconds_to_millis(max_interval_secs));

        while input.read_byte().is_ok() {}

        Ok(Self {
            base_interval_secs,
            min_interval_secs,
            max_interval_secs,
            target_gas_per_block,
            ema_alpha_milli,
            interval_step_bps,
            retarget_every_blocks,
            base_interval_ms,
            min_interval_ms,
            max_interval_ms,
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
    /// The current block interval that is in effect, in milliseconds.
    #[serde(default)]
    pub effective_interval_ms: u64,
}

impl BlockTimingRuntime {
    /// Returns the authoritative effective interval in milliseconds, falling back to legacy seconds.
    pub fn effective_interval_ms_or_legacy(&self) -> u64 {
        if self.effective_interval_ms > 0 {
            self.effective_interval_ms
        } else {
            seconds_to_millis(self.effective_interval_secs)
        }
    }
}

// Custom Decode for BlockTimingRuntime to consume trailing bytes for forward compatibility.
impl Decode for BlockTimingRuntime {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let ema_gas_used = u128::decode(input)?;
        let effective_interval_secs = u64::decode(input)?;
        let effective_interval_ms = u64::decode(input)
            .ok()
            .unwrap_or_else(|| seconds_to_millis(effective_interval_secs));

        // Drain any trailing bytes.
        while input.read_byte().is_ok() {}

        Ok(BlockTimingRuntime {
            ema_gas_used,
            effective_interval_secs,
            effective_interval_ms,
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
    interval_millis_to_legacy_seconds(compute_interval_from_parent_state_ms(
        params,
        runtime_state,
        parent_height,
        parent_gas_used,
    ))
}

/// Millisecond-precision version of `compute_interval_from_parent_state`.
pub fn compute_interval_from_parent_state_ms(
    params: &BlockTimingParams,
    runtime_state: &BlockTimingRuntime,
    parent_height: u64,
    parent_gas_used: u64,
) -> u64 {
    if params.retarget_every_blocks == 0
        || !(parent_height + 1).is_multiple_of(params.retarget_every_blocks as u64)
    {
        return runtime_state.effective_interval_ms_or_legacy().clamp(
            params.min_interval_ms_or_legacy(),
            params.max_interval_ms_or_legacy(),
        );
    }

    let alpha = params.ema_alpha_milli as u128;
    let ema =
        (alpha * parent_gas_used as u128 + (1000 - alpha) * runtime_state.ema_gas_used) / 1000;
    let target = params.target_gas_per_block.max(1) as u128;

    let u_fp = (ema * 10_000) / target;
    let u_clamped = u_fp.clamp(5_000, 20_000);

    let desired = (params.base_interval_ms_or_legacy() as u128 * 10_000) / u_clamped;
    let last = runtime_state.effective_interval_ms_or_legacy() as u128;
    let step = (last * params.interval_step_bps as u128) / 10_000;

    let proposed = desired.clamp(last.saturating_sub(step), last + step);
    (proposed as u64).clamp(
        params.min_interval_ms_or_legacy(),
        params.max_interval_ms_or_legacy(),
    )
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
    compute_next_timestamp_ms(
        params,
        runtime_state,
        parent_height,
        seconds_to_millis(parent_timestamp),
        parent_gas_used,
    )
    .map(timestamp_millis_to_legacy_seconds)
}

/// Millisecond-precision version of `compute_next_timestamp`.
pub fn compute_next_timestamp_ms(
    params: &BlockTimingParams,
    runtime_state: &BlockTimingRuntime,
    parent_height: u64,
    parent_timestamp_ms: u64,
    parent_gas_used: u64,
) -> Option<u64> {
    if parent_height == 0 {
        return parent_timestamp_ms.checked_add(params.base_interval_ms_or_legacy());
    }

    let interval = compute_interval_from_parent_state_ms(
        params,
        runtime_state,
        parent_height,
        parent_gas_used,
    );

    parent_timestamp_ms.checked_add(interval)
}
