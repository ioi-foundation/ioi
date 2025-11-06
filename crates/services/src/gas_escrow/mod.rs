// Path: crates/services/src/gas_escrow/mod.rs
use async_trait::async_trait;
use ioi_types::codec;
use ioi_types::error::UpgradeError;
use ioi_types::keys::{ACCOUNT_KEY_PREFIX, GAS_ESCROW_KEY_PREFIX};
use ioi_api::impl_service_base;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccessor;
use parity_scale_codec::{Decode, Encode};

#[derive(Encode, Decode, Debug, Default, Clone)]
pub struct Account {
    pub balance: u64,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct EscrowEntry {
    pub account: Vec<u8>,
    pub amount: u64,
}

pub trait GasEscrowHandler: BlockchainService {
    fn bond<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), String>;
    fn settle<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        quality_score: f32,
    ) -> Result<(), String>;
}

pub struct GasEscrowService;

impl GasEscrowService {
    fn account_key(user_account: &[u8]) -> Vec<u8> {
        [ACCOUNT_KEY_PREFIX, user_account].concat()
    }
    fn escrow_key(user_account: &[u8]) -> Vec<u8> {
        [GAS_ESCROW_KEY_PREFIX, user_account].concat()
    }
    fn get_account<S: StateAccessor + ?Sized>(
        &self,
        state: &S,
        user_account: &[u8],
    ) -> Result<Account, String> {
        let key = Self::account_key(user_account);
        let bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        codec::from_bytes_canonical(&bytes).or(Ok(Account::default()))
    }
}

impl_service_base!(GasEscrowService, "gas_escrow");

#[async_trait]
impl UpgradableService for GasEscrowService {
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(vec![])
    }
    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl GasEscrowHandler for GasEscrowService {
    fn bond<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), String> {
        let mut account = self.get_account(state, user_account)?;
        if account.balance < max_gas {
            return Err(format!(
                "Insufficient funds: required {}, available {}",
                max_gas, account.balance
            ));
        }
        let escrow_entry = EscrowEntry {
            account: user_account.to_vec(),
            amount: max_gas,
        };
        account.balance -= max_gas;
        let updates = &[
            (
                Self::account_key(user_account),
                codec::to_bytes_canonical(&account)?,
            ),
            (
                Self::escrow_key(user_account),
                codec::to_bytes_canonical(&escrow_entry)?,
            ),
        ];
        state.batch_set(updates).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn settle<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        _quality_score: f32,
    ) -> Result<(), String> {
        let escrow_key = Self::escrow_key(user_account);
        let escrow_bytes = state
            .get(&escrow_key)
            .map_err(|e| e.to_string())?
            .ok_or("No escrow found for user")?;
        state.delete(&escrow_key).map_err(|e| e.to_string())?;
        let escrow: EscrowEntry = codec::from_bytes_canonical(&escrow_bytes)?;
        if gas_used > escrow.amount {
            return Err("gas_used exceeds bonded amount".to_string());
        }
        let refund = escrow.amount - gas_used;
        let mut account = self.get_account(state, user_account)?;
        account.balance += refund;
        let account_bytes = codec::to_bytes_canonical(&account)?;
        state
            .insert(&Self::account_key(user_account), &account_bytes)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
