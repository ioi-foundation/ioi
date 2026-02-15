use super::core::{IncidentState, LegacyIncidentState};
use crate::agentic::desktop::keys::get_incident_key;
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub fn load_incident_state(
    state: &dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<Option<IncidentState>, TransactionError> {
    let key = get_incident_key(session_id);
    let Some(bytes) = state.get(&key)? else {
        return Ok(None);
    };
    match codec::from_bytes_canonical::<IncidentState>(&bytes) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(_) => {
            let legacy = codec::from_bytes_canonical::<LegacyIncidentState>(&bytes)
                .map_err(TransactionError::Serialization)?;
            Ok(Some(legacy.into()))
        }
    }
}

pub fn clear_incident_state(
    state: &mut dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<(), TransactionError> {
    let key = get_incident_key(session_id);
    state.delete(&key)?;
    Ok(())
}

pub(super) fn persist_incident_state(
    state: &mut dyn StateAccess,
    session_id: &[u8; 32],
    incident_state: &IncidentState,
) -> Result<(), TransactionError> {
    let key = get_incident_key(session_id);
    let bytes =
        codec::to_bytes_canonical(incident_state).map_err(TransactionError::Serialization)?;
    state.insert(&key, &bytes)?;
    Ok(())
}
