// Path: crates/services/src/gas_escrow/mod.rs
use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateManager;
use depin_sdk_types::error::UpgradeError;
use depin_sdk_types::keys::{ACCOUNT_KEY_PREFIX, GAS_ESCROW_KEY_PREFIX};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Account {
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EscrowEntry {
    pub account: Vec<u8>,
    pub amount: u64,
}

pub trait GasEscrowHandler: BlockchainService {
    fn bond<S: StateManager + ?Sized>(&self, state: &mut S, user_account: &[u8], max_gas: u64) -> Result<(), String>;
    fn settle<S: StateManager + ?Sized>(&self, state: &mut S, user_account: &[u8], gas_used: u64, quality_score: f32) -> Result<(), String>;
}

pub struct GasEscrowService;

impl GasEscrowService {
    fn account_key(user_account: &[u8]) -> Vec<u8> { [ACCOUNT_KEY_PREFIX, user_account].concat() }
    fn escrow_key(user_account: &[u8]) -> Vec<u8> { [GAS_ESCROW_KEY_PREFIX, user_account].concat() }
    fn get_account<S: StateManager + ?Sized>(&self, state: &S, user_account: &[u8]) -> Result<Account, String> {
        let key = Self::account_key(user_account);
        let bytes = state.get(&key).map_err(|e| e.to_string())?.unwrap_or_default();
        serde_json::from_slice(&bytes).or(Ok(Account::default()))
    }
}

impl BlockchainService for GasEscrowService {
    fn service_type(&self) -> ServiceType { ServiceType::Custom("GasEscrow".to_string()) }
}

impl_service_base!(GasEscrowService);

impl UpgradableService for GasEscrowService {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> { Ok(vec![]) }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> { Ok(()) }
}

impl GasEscrowHandler for GasEscrowService {
    fn bond<S: StateManager + ?Sized>(&self, state: &mut S, user_account: &[u8], max_gas: u64) -> Result<(), String> {
        let mut account = self.get_account(state, user_account)?;
        if account.balance < max_gas { return Err(format!("Insufficient funds: required {}, available {}", max_gas, account.balance)); }
        let escrow_entry = EscrowEntry { account: user_account.to_vec(), amount: max_gas };
        account.balance -= max_gas;
        let updates = &[(Self::account_key(user_account), serde_json::to_vec(&account).unwrap()), (Self::escrow_key(user_account), serde_json::to_vec(&escrow_entry).unwrap())];
        state.batch_set(updates).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn settle<S: StateManager + ?Sized>(&self, state: &mut S, user_account: &[u8], gas_used: u64, _quality_score: f32) -> Result<(), String> {
        let escrow_key = Self::escrow_key(user_account);
        let escrow_bytes = state.get(&escrow_key).map_err(|e| e.to_string())?.ok_or("No escrow found for user")?;
        state.delete(&escrow_key).map_err(|e| e.to_string())?;
        let escrow: EscrowEntry = serde_json::from_slice(&escrow_bytes).map_err(|e| e.to_string())?;
        if gas_used > escrow.amount { return Err("gas_used exceeds bonded amount".to_string()); }
        let refund = escrow.amount - gas_used;
        let mut account = self.get_account(state, user_account)?;
        account.balance += refund;
        let account_bytes = serde_json::to_vec(&account).unwrap();
        state.insert(&Self::account_key(user_account), &account_bytes).map_err(|e| e.to_string())?;
        Ok(())
    }
}