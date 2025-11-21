// Path: crates/execution/src/app/end_block.rs

//! Contains handler functions for logic that runs at the end of a block commit.
//! This includes service upgrades, lifecycle hooks, validator set promotion, and timing updates.

use crate::upgrade_manager::ServiceUpgradeManager;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::{service_namespace_prefix, NamespacedStateAccess, StateAccess};
use ioi_api::transaction::context::TxContext;
use ioi_types::app::{
    read_validator_sets, write_validator_sets, BlockTimingParams, BlockTimingRuntime,
};
use ioi_types::codec;
use ioi_types::error::{ChainError, StateError};
use ioi_types::keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, VALIDATOR_SET_KEY};
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};
use std::collections::HashMap; // Import HashMap for the cache type
use std::sync::Arc; // Import Arc for the cache type

/// Applies any pending service upgrades scheduled for the given block height.
/// Returns the number of upgrades applied.
pub(super) async fn handle_service_upgrades<S: StateAccess>(
    service_manager: &mut ServiceUpgradeManager,
    height: u64,
    state: &mut S,
) -> Result<usize, ChainError> {
    tracing::debug!(target: "end_block", height=height, "Checking for service upgrades.");
    let result = service_manager
        .apply_upgrades_at_height(height, state)
        .await
        .map_err(|e| ChainError::State(StateError::Apply(e.to_string())));

    if let Ok(count) = result {
        if count > 0 {
            tracing::info!(target: "end_block", height=height, upgrades_applied=count, "Service upgrades applied successfully.");
        }
    } else if let Err(ref e) = result {
        tracing::error!(target: "end_block", height=height, error=%e, "Service upgrade application failed.");
    }

    result
}

/// Runs the `on_end_block` hook for all services that implement the capability.
pub(super) async fn run_on_end_block_hooks(
    services: &ServiceDirectory,
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    // Pass the cache from the execution machine
    service_meta_cache: &HashMap<String, Arc<ActiveServiceMeta>>,
) -> Result<(), ChainError> {
    for service in services.services_in_deterministic_order() {
        if service.capabilities().contains(Capabilities::ON_END_BLOCK) {
            if let Some(hook) = service.as_on_end_block() {
                // MODIFIED: Use the in-memory cache instead of hitting the state.
                let meta = service_meta_cache.get(service.id()).ok_or_else(|| {
                    StateError::Apply(format!(
                        "Metadata not found in cache for active service hook '{}'",
                        service.id()
                    ))
                })?;
                let prefix = service_namespace_prefix(service.id());
                let mut namespaced_state = NamespacedStateAccess::new(state, prefix, meta);
                hook.on_end_block(&mut namespaced_state, ctx).await?;
            }
        }
    }
    Ok(())
}

/// Checks for and applies the promotion of a 'next' validator set to 'current'.
/// Returns `true` if a promotion occurred.
pub(super) fn handle_validator_set_promotion(
    state: &mut dyn StateAccess,
    current_height: u64,
) -> Result<bool, ChainError> {
    let Some(bytes) = state.get(VALIDATOR_SET_KEY)? else {
        tracing::error!(
            target: "chain",
            event = "end_block",
            height = current_height,
            "MISSING VALIDATOR_SET_KEY before promotion check."
        );
        return Ok(false);
    };

    let mut sets = read_validator_sets(&bytes)?;
    let mut modified = false;

    if let Some(next_vs) = &sets.next {
        if current_height >= next_vs.effective_from_height
            && !next_vs.validators.is_empty()
            && next_vs.total_weight > 0
        {
            tracing::info!(
                target: "chain",
                event = "validator_set_promotion",
                height = current_height,
                "Promoting validator set effective from height {}",
                next_vs.effective_from_height
            );
            sets.current = next_vs.clone();
            // Clear the 'next' set now that it has been promoted.
            sets.next = None;
            modified = true;
        }
    }

    if modified {
        let out = write_validator_sets(&sets)?;
        state.insert(VALIDATOR_SET_KEY, &out)?;
    }
    Ok(modified)
}

/// Updates the block timing parameters based on the last block's gas usage.
pub(super) fn handle_timing_update(
    state: &mut dyn StateAccess,
    current_height: u64,
    gas_used_this_block: u64,
) -> Result<(), ChainError> {
    let (Some(params_bytes), Some(runtime_bytes)) = (
        state.get(BLOCK_TIMING_PARAMS_KEY)?,
        state.get(BLOCK_TIMING_RUNTIME_KEY)?,
    ) else {
        // If timing keys aren't set, do nothing.
        return Ok(());
    };

    let params: BlockTimingParams =
        codec::from_bytes_canonical(&params_bytes).map_err(ChainError::Transaction)?;
    let old_runtime: BlockTimingRuntime =
        codec::from_bytes_canonical(&runtime_bytes).map_err(ChainError::Transaction)?;

    // Always update EMA gas used, regardless of whether we retarget the interval.
    let mut new_runtime = old_runtime.clone();
    let alpha = params.ema_alpha_milli as u128;
    new_runtime.ema_gas_used = (alpha * gas_used_this_block as u128
        + (1000 - alpha) * old_runtime.ema_gas_used)
        / 1000;

    // Only recalculate the effective interval if we are on a retargeting block.
    if params.retarget_every_blocks > 0 && current_height % params.retarget_every_blocks as u64 == 0
    {
        let parent_height = current_height.saturating_sub(1);
        let next_interval = ioi_types::app::compute_interval_from_parent_state(
            &params,
            &old_runtime,
            parent_height,
            gas_used_this_block,
        );
        new_runtime.effective_interval_secs = next_interval;
        tracing::info!(
            target: "chain",
            event = "timing_retarget",
            height = current_height,
            old_interval = old_runtime.effective_interval_secs,
            new_interval = next_interval,
            ema_gas = new_runtime.ema_gas_used
        );
    }

    if new_runtime.ema_gas_used != old_runtime.ema_gas_used
        || new_runtime.effective_interval_secs != old_runtime.effective_interval_secs
    {
        state.insert(
            BLOCK_TIMING_RUNTIME_KEY,
            &codec::to_bytes_canonical(&new_runtime).map_err(ChainError::Transaction)?,
        )?;
    }

    Ok(())
}