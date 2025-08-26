// Path: crates/services/src/gas_escrow/mod.rs
use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType};
use depin_sdk_api::state::StateManager;
use depin_sdk_types::keys::{ACCOUNT_KEY_PREFIX, GAS_ESCROW_KEY_PREFIX};
use serde::{Deserialize, Serialize};

// --- State Structs ---

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Account {
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EscrowEntry {
    pub account: Vec<u8>,
    pub amount: u64,
}

// --- Trait Definition ---

pub trait GasEscrowHandler: BlockchainService {
    /// Locks a user's funds before a computationally expensive operation.
    fn bond<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), String>;

    /// Settles the escrow after execution, refunding unused gas and applying bonuses/penalties.
    fn settle<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        quality_score: f32,
    ) -> Result<(), String>;
}

// --- Service Implementation ---

pub struct GasEscrowService;

impl GasEscrowService {
    /// Helper to construct a state key for a user's account.
    fn account_key(user_account: &[u8]) -> Vec<u8> {
        [ACCOUNT_KEY_PREFIX, user_account].concat()
    }

    /// Helper to construct a state key for a user's escrow entry.
    fn escrow_key(user_account: &[u8]) -> Vec<u8> {
        [GAS_ESCROW_KEY_PREFIX, user_account].concat()
    }

    /// Helper to read and deserialize an account from state.
    fn get_account<S: StateManager + ?Sized>(
        &self,
        state: &S,
        user_account: &[u8],
    ) -> Result<Account, String> {
        let key = Self::account_key(user_account);
        let bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        serde_json::from_slice(&bytes).or(Ok(Account::default()))
    }
}

impl BlockchainService for GasEscrowService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("GasEscrow".to_string())
    }
}

impl_service_base!(GasEscrowService);

impl GasEscrowHandler for GasEscrowService {
    fn bond<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        max_gas: u64,
    ) -> Result<(), String> {
        log::info!(
            "GasEscrowHandler::bond() called for user {:?} with max_gas {}",
            hex::encode(user_account),
            max_gas
        );

        // 1. Get user's current account balance.
        let mut account = self.get_account(state, user_account)?;

        // 2. Verify the user has sufficient funds.
        if account.balance < max_gas {
            return Err(format!(
                "Insufficient funds: required {}, available {}",
                max_gas, account.balance
            ));
        }

        // 3. Create the escrow entry.
        let escrow_entry = EscrowEntry {
            account: user_account.to_vec(),
            amount: max_gas,
        };

        // 4. Atomically update state: decrease balance, create escrow.
        account.balance -= max_gas;

        let account_bytes = serde_json::to_vec(&account).unwrap();
        let escrow_bytes = serde_json::to_vec(&escrow_entry).unwrap();

        let updates = &[
            (Self::account_key(user_account), account_bytes),
            (Self::escrow_key(user_account), escrow_bytes),
        ];

        state.batch_set(updates).map_err(|e| e.to_string())?;

        Ok(())
    }

    fn settle<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        user_account: &[u8],
        gas_used: u64,
        quality_score: f32,
    ) -> Result<(), String> {
        log::info!(
            "GasEscrowHandler::settle() called for user {:?} with gas_used {} and quality {}",
            hex::encode(user_account),
            gas_used,
            quality_score
        );

        // 1. Retrieve and delete the escrow entry.
        let escrow_key = Self::escrow_key(user_account);
        let escrow_bytes = state
            .get(&escrow_key)
            .map_err(|e| e.to_string())?
            .ok_or("No escrow found for user")?;
        state.delete(&escrow_key).map_err(|e| e.to_string())?;

        let escrow: EscrowEntry =
            serde_json::from_slice(&escrow_bytes).map_err(|e| e.to_string())?;

        // 2. Calculate refund and fees.
        if gas_used > escrow.amount {
            return Err("gas_used exceeds bonded amount".to_string());
        }
        let refund = escrow.amount - gas_used;
        // NOTE: In a real implementation, `gas_used` would be distributed to validators.
        // For P1, we simply burn it. A bonus/penalty from `quality_score` could also be applied here.

        // 3. Update user's balance with the refund.
        let mut account = self.get_account(state, user_account)?;
        account.balance += refund;
        let account_bytes = serde_json::to_vec(&account).unwrap();
        state
            .insert(&Self::account_key(user_account), &account_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}