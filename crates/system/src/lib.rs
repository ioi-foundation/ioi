// Path: crates/system/src/lib.rs

use ioi_api::state::StateAccess;
use ioi_types::{
    app::{AccountId, ChainStatus, ValidatorSetsV1},
    codec,
    error::StateError,
};
use std::collections::BTreeSet;

// --- PRIVATE KERNEL KEYS ---
const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";
const EVIDENCE_REGISTRY_KEY: &[u8] = b"system::penalties::evidence";
const STATUS_KEY: &[u8] = b"chain::status";
const QUARANTINED_VALIDATORS_KEY: &[u8] = b"system::penalties::quarantined_poa";

// --- PUBLIC STRING CONSTANTS (For Genesis/Testing Only) ---
pub mod keys {
    pub const VALIDATOR_SET_KEY_STR: &str = "system::validators::current";
    pub const STATUS_KEY_STR: &str = "chain::status";
}

// --- TRAITS ---

pub trait SystemState {
    fn validators(&self) -> &dyn ValidatorRegistry;
    fn validators_mut(&mut self) -> &mut dyn ValidatorRegistryMut;
    fn evidence(&self) -> &dyn EvidenceRegistry;
    fn evidence_mut(&mut self) -> &mut dyn EvidenceRegistryMut;
    fn quarantine(&self) -> &dyn QuarantineRegistry;
    fn quarantine_mut(&mut self) -> &mut dyn QuarantineRegistryMut;
    fn status(&self) -> Result<ChainStatus, StateError>;
    fn set_status(&mut self, status: &ChainStatus) -> Result<(), StateError>;
}

pub trait ValidatorRegistry {
    fn current_sets(&self) -> Result<ValidatorSetsV1, StateError>;
}

pub trait ValidatorRegistryMut: ValidatorRegistry {
    fn set_sets(&mut self, sets: &ValidatorSetsV1) -> Result<(), StateError>;
}

pub trait EvidenceRegistry {
    fn contains(&self, id: &[u8; 32]) -> Result<bool, StateError>;
}

pub trait EvidenceRegistryMut: EvidenceRegistry {
    fn insert(&mut self, id: [u8; 32]) -> Result<(), StateError>;
}

pub trait QuarantineRegistry {
    fn contains(&self, account: &AccountId) -> Result<bool, StateError>;
    /// Returns the full set of quarantined accounts.
    fn get_all(&self) -> Result<BTreeSet<AccountId>, StateError>;
}

pub trait QuarantineRegistryMut: QuarantineRegistry {
    fn insert(&mut self, account: AccountId) -> Result<(), StateError>;
}

// --- IMPLEMENTATION ---

pub struct KvSystemState<'a> {
    state: &'a mut dyn StateAccess,
}

impl<'a> KvSystemState<'a> {
    pub fn new(state: &'a mut dyn StateAccess) -> Self {
        Self { state }
    }
}

impl<'a> SystemState for KvSystemState<'a> {
    fn validators(&self) -> &dyn ValidatorRegistry {
        self
    }
    fn validators_mut(&mut self) -> &mut dyn ValidatorRegistryMut {
        self
    }
    fn evidence(&self) -> &dyn EvidenceRegistry {
        self
    }
    fn evidence_mut(&mut self) -> &mut dyn EvidenceRegistryMut {
        self
    }
    fn quarantine(&self) -> &dyn QuarantineRegistry {
        self
    }
    fn quarantine_mut(&mut self) -> &mut dyn QuarantineRegistryMut {
        self
    }

    fn status(&self) -> Result<ChainStatus, StateError> {
        match self.state.get(STATUS_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode),
            None => Err(StateError::KeyNotFound),
        }
    }

    fn set_status(&mut self, status: &ChainStatus) -> Result<(), StateError> {
        let bytes = codec::to_bytes_canonical(status).map_err(|e| StateError::InvalidValue(e))?;
        self.state.insert(STATUS_KEY, &bytes)
    }
}

impl<'a> ValidatorRegistry for KvSystemState<'a> {
    fn current_sets(&self) -> Result<ValidatorSetsV1, StateError> {
        match self.state.get(VALIDATOR_SET_KEY)? {
            Some(b) => ioi_types::app::read_validator_sets(&b),
            None => Err(StateError::KeyNotFound),
        }
    }
}

impl<'a> ValidatorRegistryMut for KvSystemState<'a> {
    fn set_sets(&mut self, sets: &ValidatorSetsV1) -> Result<(), StateError> {
        let bytes = ioi_types::app::write_validator_sets(sets)?;
        self.state.insert(VALIDATOR_SET_KEY, &bytes)
    }
}

impl<'a> EvidenceRegistry for KvSystemState<'a> {
    fn contains(&self, id: &[u8; 32]) -> Result<bool, StateError> {
        let set: BTreeSet<[u8; 32]> = match self.state.get(EVIDENCE_REGISTRY_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode)?,
            None => BTreeSet::new(),
        };
        Ok(set.contains(id))
    }
}

impl<'a> EvidenceRegistryMut for KvSystemState<'a> {
    fn insert(&mut self, id: [u8; 32]) -> Result<(), StateError> {
        let mut set: BTreeSet<[u8; 32]> = match self.state.get(EVIDENCE_REGISTRY_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode)?,
            None => BTreeSet::new(),
        };
        set.insert(id);
        let bytes = codec::to_bytes_canonical(&set).map_err(|e| StateError::InvalidValue(e))?;
        self.state.insert(EVIDENCE_REGISTRY_KEY, &bytes)
    }
}

impl<'a> QuarantineRegistry for KvSystemState<'a> {
    fn contains(&self, account: &AccountId) -> Result<bool, StateError> {
        let set: BTreeSet<AccountId> = match self.state.get(QUARANTINED_VALIDATORS_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode)?,
            None => BTreeSet::new(),
        };
        Ok(set.contains(account))
    }

    fn get_all(&self) -> Result<BTreeSet<AccountId>, StateError> {
        match self.state.get(QUARANTINED_VALIDATORS_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode),
            None => Ok(BTreeSet::new()),
        }
    }
}

impl<'a> QuarantineRegistryMut for KvSystemState<'a> {
    fn insert(&mut self, account: AccountId) -> Result<(), StateError> {
        let mut set: BTreeSet<AccountId> = match self.state.get(QUARANTINED_VALIDATORS_KEY)? {
            Some(b) => codec::from_bytes_canonical(&b).map_err(StateError::Decode)?,
            None => BTreeSet::new(),
        };
        set.insert(account);
        let bytes = codec::to_bytes_canonical(&set).map_err(|e| StateError::InvalidValue(e))?;
        self.state.insert(QUARANTINED_VALIDATORS_KEY, &bytes)
    }
}
