//! Account-based transaction model implementation.


use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::TransactionError;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use std::any::Any;
use std::collections::HashMap;

/// Account transaction
#[derive(Debug, Clone)]
pub struct AccountTransaction {
    /// Transaction ID
    pub txid: Vec<u8>,
    /// Sender account
    pub from: Vec<u8>,
    /// Receiver account
    pub to: Vec<u8>,
    /// Value to transfer
    pub value: u64,
    /// Nonce to prevent replay
    pub nonce: u64,
    /// Signature from sender
    pub signature: Vec<u8>,
}

/// Account proof for transaction verification
#[derive(Debug, Clone)]
pub struct AccountProof {
    /// Proof for sender's account
    pub sender_proof: Vec<u8>,
    /// Proof for sender's nonce
    pub nonce_proof: Vec<u8>,
    /// Additional data for verification
    pub metadata: HashMap<String, Vec<u8>>,
}

/// Account state stored in the state manager
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Account balance
    pub balance: u64,
    /// Account nonce (for replay protection)
    pub nonce: u64,
}

/// Account-specific operations
pub trait AccountOperations {
    /// Create a key for an account in the state store.
    ///
    /// # Arguments
    /// * `account` - Account identifier.
    ///
    /// # Returns
    /// * `Ok(key)` - The generated key.
    /// * `Err(TransactionError)` - If key creation failed.
    fn create_account_key(&self, account: &[u8]) -> Result<Vec<u8>, TransactionError>;

    /// Create a key for an account nonce in the state store.
    ///
    /// # Arguments
    /// * `account` - Account identifier.
    ///
    /// # Returns
    /// * `Ok(key)` - The generated key.
    /// * `Err(TransactionError)` - If key creation failed.
    fn create_nonce_key(&self, account: &[u8]) -> Result<Vec<u8>, TransactionError>;
}

/// Account model configuration
#[derive(Clone)]
pub struct AccountConfig {
    /// Maximum transaction value
    pub max_value: u64,
    /// Initial balance for new accounts (if auto-create is enabled)
    pub initial_balance: u64,
    /// Whether to automatically create accounts on first receive
    pub auto_create_accounts: bool,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            max_value: u64::MAX,
            initial_balance: 0,
            auto_create_accounts: true,
        }
    }
}

/// Account transaction model implementation
pub struct AccountModel<CS: CommitmentScheme> {
    /// Model configuration
    config: AccountConfig,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> AccountModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new account model with default configuration.
    pub fn new(scheme: CS) -> Self {
        Self {
            config: AccountConfig::default(),
            scheme,
        }
    }

    /// Create a new account model with custom configuration.
    pub fn with_config(scheme: CS, config: AccountConfig) -> Self {
        Self {
            config,
            scheme,
        }
    }

    /// Get model configuration.
    pub fn config(&self) -> &AccountConfig {
        &self.config
    }

    /// Get the commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Convert a value to the commitment scheme's value type
    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }

    /// Helper method to get an account from the state.
    fn get_account<S>(
        &self,
        state: &S,
        account: &[u8],
    ) -> Result<Option<AccountState>, TransactionError>
    where
        S: StateManager<
            Commitment = CS::Commitment,
            Proof = CS::Proof,
        > + ?Sized,
    {
        let key = self.create_account_key(account)?;
        let value = state
            .get(&key)
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;

        match value {
            Some(data) => self.decode_account(&data),
            None => Ok(None),
        }
    }

    /// Helper method to decode an account from bytes.
    fn decode_account(&self, data: &[u8]) -> Result<Option<AccountState>, TransactionError> {
        if data.len() < 16 {
            return Err(TransactionError::SerializationError(
                "Account data too short".to_string(),
            ));
        }

        let mut balance_bytes = [0u8; 8];
        balance_bytes.copy_from_slice(&data[0..8]);
        let balance = u64::from_le_bytes(balance_bytes);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&data[8..16]);
        let nonce = u64::from_le_bytes(nonce_bytes);

        Ok(Some(AccountState { balance, nonce }))
    }

    /// Helper method to encode an account to bytes.
    fn encode_account(&self, account: &AccountState) -> Vec<u8> {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&account.balance.to_le_bytes());
        data.extend_from_slice(&account.nonce.to_le_bytes());
        data
    }
}

impl<CS: CommitmentScheme> TransactionModel for AccountModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Transaction = AccountTransaction;
    type Proof = AccountProof;
    type CommitmentScheme = CS;

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // Check transaction structure
        if tx.value == 0 {
            return Ok(false);
        }

        if tx.value > self.config.max_value {
            return Ok(false);
        }

        // Get sender account
        let sender = self.get_account(state, &tx.from)?;

        match sender {
            Some(account) => {
                // Check balance
                if account.balance < tx.value {
                    return Ok(false);
                }

                // Check nonce
                if account.nonce != tx.nonce {
                    return Ok(false);
                }

                // TODO: Validate signature

                Ok(true)
            }
            None => Ok(false), // Sender doesn't exist
        }
    }

    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // Validate transaction first
        if !self.validate(tx, state)? {
            return Err(TransactionError::InvalidTransaction(
                "Transaction validation failed".to_string(),
            ));
        }

        // Get sender account
        let sender_key = self.create_account_key(&tx.from)?;
        let sender = self.get_account(state, &tx.from)?.ok_or_else(|| {
            TransactionError::InvalidTransaction("Sender account not found".to_string())
        })?;

        // Update sender account
        let new_sender = AccountState {
            balance: sender.balance - tx.value,
            nonce: sender.nonce + 1,
        };

        state
            .set(&sender_key, &self.encode_account(&new_sender))
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;

        // Get or create receiver account
        let receiver_key = self.create_account_key(&tx.to)?;
        let receiver = match self.get_account(state, &tx.to)? {
            Some(account) => account,
            None => {
                if !self.config.auto_create_accounts {
                    return Err(TransactionError::InvalidTransaction(
                        "Receiver account not found".to_string(),
                    ));
                }

                AccountState {
                    balance: self.config.initial_balance,
                    nonce: 0,
                }
            }
        };

        // Update receiver account
        let new_receiver = AccountState {
            balance: receiver.balance.checked_add(tx.value).ok_or_else(|| {
                TransactionError::InvalidTransaction("Balance overflow".to_string())
            })?,
            nonce: receiver.nonce,
        };

        state
            .set(&receiver_key, &self.encode_account(&new_receiver))
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;

        Ok(())
    }

    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        let sender_key = self.create_account_key(&tx.from)?;
        let nonce_key = self.create_nonce_key(&tx.from)?;

        // In a real implementation, we would create cryptographic proofs
        // For this example, we'll just get the raw account data
        let sender_data = state
            .get(&sender_key)
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?
            .ok_or_else(|| {
                TransactionError::InvalidInput("Sender account not found".to_string())
            })?;

        let nonce_data = state
            .get(&nonce_key)
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?
            .unwrap_or_else(|| vec![0; 8]); // Default nonce is 0

        Ok(AccountProof {
            sender_proof: sender_data,
            nonce_proof: nonce_data,
            metadata: HashMap::new(),
        })
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // In a real implementation, this would verify cryptographic proofs
        // For this example, we'll just return true
        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        // Simple manual serialization for demonstration
        let mut data = Vec::new();

        // Serialize txid
        data.extend_from_slice(&(tx.txid.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.txid);

        // Serialize from
        data.extend_from_slice(&(tx.from.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.from);

        // Serialize to
        data.extend_from_slice(&(tx.to.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.to);

        // Serialize value and nonce
        data.extend_from_slice(&tx.value.to_le_bytes());
        data.extend_from_slice(&tx.nonce.to_le_bytes());

        // Serialize signature
        data.extend_from_slice(&(tx.signature.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.signature);

        Ok(data)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        if data.len() < 4 {
            return Err(TransactionError::SerializationError(
                "Data too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Deserialize txid
        let txid_len = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + txid_len > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid txid length".to_string(),
            ));
        }

        let txid = data[pos..pos + txid_len].to_vec();
        pos += txid_len;

        // Deserialize from
        if pos + 4 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let from_len = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + from_len > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid from length".to_string(),
            ));
        }

        let from = data[pos..pos + from_len].to_vec();
        pos += from_len;

        // Deserialize to
        if pos + 4 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let to_len = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + to_len > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid to length".to_string(),
            ));
        }

        let to = data[pos..pos + to_len].to_vec();
        pos += to_len;

        // Deserialize value and nonce
        if pos + 16 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&data[pos..pos + 8]);
        let value = u64::from_le_bytes(value_bytes);
        pos += 8;

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&data[pos..pos + 8]);
        let nonce = u64::from_le_bytes(nonce_bytes);
        pos += 8;

        // Deserialize signature
        if pos + 4 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let signature_len = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + signature_len > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid signature length".to_string(),
            ));
        }

        let signature = data[pos..pos + signature_len].to_vec();

        Ok(AccountTransaction {
            txid,
            from,
            to,
            value,
            nonce,
            signature,
        })
    }

    fn get_model_extensions(&self) -> Option<&dyn Any> {
        Some(self as &dyn Any)
    }
}

impl<CS: CommitmentScheme> AccountOperations for AccountModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn create_account_key(&self, account: &[u8]) -> Result<Vec<u8>, TransactionError> {
        let mut key = Vec::with_capacity(account.len() + 1);
        key.push(b'a'); // Prefix 'a' for account
        key.extend_from_slice(account);
        Ok(key)
    }

    fn create_nonce_key(&self, account: &[u8]) -> Result<Vec<u8>, TransactionError> {
        let mut key = Vec::with_capacity(account.len() + 1);
        key.push(b'n'); // Prefix 'n' for nonce
        key.extend_from_slice(account);
        Ok(key)
    }
}

/// Helper function to read a u32 from a byte slice
fn read_u32(data: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(data);
    u32::from_le_bytes(bytes)
}