// Path: crates/consensus/src/common/penalty.rs
//! Shared penalty logic for consensus engines.

use ioi_api::state::StateAccess;
use ioi_types::{
    app::{read_validator_sets, AccountId, FailureReport},
    error::{StateError, TransactionError},
    keys::{QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY},
};
use std::collections::BTreeSet;

/// Placeholder function to read the liveness guard from on-chain parameters.
fn read_min_live_authorities(_state: &dyn StateAccess) -> Result<Option<usize>, StateError> {
    // TODO: Read this value from a governance-controlled parameter in the state.
    // For now, it returns None, and the caller uses a hardcoded default.
    Ok(None)
}

/// A pure function that computes the result of a quarantine action without I/O.
/// This makes the core logic easily unit-testable.
///
/// Returns:
/// - `Ok(Some(new_set))` if the offender should be quarantined and the set is updated.
/// - `Ok(None)` if the offender is already quarantined (no-op).
/// - `Err(TransactionError)` if the action is invalid (e.g., liveness violation).
pub(crate) fn compute_quarantine_update(
    authorities: &Vec<AccountId>,
    quarantined: &BTreeSet<AccountId>,
    offender: &AccountId,
    min_live: usize,
) -> Result<Option<BTreeSet<AccountId>>, TransactionError> {
    if !authorities.contains(offender) {
        return Err(TransactionError::Invalid(
            "Reported offender is not a current authority.".into(),
        ));
    }

    if quarantined.contains(offender) {
        return Ok(None); // Already quarantined, no state change needed.
    }

    let live_after = authorities
        .len()
        .saturating_sub(quarantined.len())
        .saturating_sub(1);
    if live_after < min_live {
        return Err(TransactionError::Invalid(
            "Quarantine would jeopardize network liveness".into(),
        ));
    }

    let mut new_quarantined = quarantined.clone();
    new_quarantined.insert(*offender);
    Ok(Some(new_quarantined))
}

/// Applies a quarantine penalty to an authority-based validator by updating the state.
/// This is a thin, stateful wrapper around the pure `compute_quarantine_update` function.
pub(crate) async fn apply_quarantine_penalty(
    state: &mut dyn StateAccess,
    report: &FailureReport,
) -> Result<(), TransactionError> {
    let min_live = read_min_live_authorities(state)?.unwrap_or(2); // Default to 2

    let authorities_bytes = state
        .get(VALIDATOR_SET_KEY)?
        .ok_or(TransactionError::State(StateError::KeyNotFound))?;
    let sets = read_validator_sets(&authorities_bytes)?;
    let authorities: Vec<AccountId> = sets
        .current
        .validators
        .into_iter()
        .map(|v| v.account_id)
        .collect();

    let quarantined: BTreeSet<AccountId> = state
        .get(QUARANTINED_VALIDATORS_KEY)?
        .map(|b| ioi_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue))
        .transpose()?
        .unwrap_or_default();

    if let Some(new_quarantined) =
        compute_quarantine_update(&authorities, &quarantined, &report.offender, min_live)?
    {
        state.insert(
            QUARANTINED_VALIDATORS_KEY,
            &ioi_types::codec::to_bytes_canonical(&new_quarantined)?,
        )?;
        log::info!(
            "[Penalty] Quarantined authority: 0x{} (set size = {})",
            hex::encode(report.offender.as_ref()),
            new_quarantined.len()
        );
    }
    Ok(())
}
