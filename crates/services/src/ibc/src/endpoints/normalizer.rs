// Path: crates/services/src/ibc/src/endpoints/normalizer.rs

use depin_sdk_api::ibc::DigestAlgo;
use serde::Serialize;
use serde_jcs::to_vec;
use std::collections::HashMap;

// --- Stubs to make the code compile in this context ---
#[derive(Debug)]
pub struct CanonicalEndpointMapping {
    data: HashMap<(String, String), String>,
}
impl CanonicalEndpointMapping {
    fn get_canonical_id(&self, chain_id: &str, source_id: &str) -> Option<&String> {
        self.data
            .get(&(chain_id.to_string(), source_id.to_string()))
    }
}

#[derive(Debug)]
struct Log {
    topics: Vec<[u8; 32]>,
    data: Vec<u8>,
}
#[derive(Debug)]
struct TypedReceipt {
    logs: Vec<Log>,
}
mod u256 {
    pub fn from_big_endian(_bs: &[u8]) -> U256 {
        U256("0".to_string())
    }
    pub struct U256(String);
    impl U256 {
        pub fn to_string(&self) -> String {
            self.0.clone()
        }
    }
}
// --- End Stubs ---

#[derive(Debug)]
pub struct NormalizedData {
    pub endpoint_id: String,
    pub params_jcs: Vec<u8>,
    pub result_digest: [u8; 32],
    pub result_digest_algo: DigestAlgo,
}

pub trait EndpointNormalizer {
    fn chain_id(&self) -> &'static str;
    fn normalize(
        &self,
        cem: &CanonicalEndpointMapping,
        receipt_rlp: &[u8],
        tx_index: u32,
        log_index: u32,
    ) -> Result<NormalizedData, String>;
}

// --- EVM Normalizer for ERC-20 Transfer Event ---
pub struct EvmNormalizer;

#[derive(Serialize)]
struct Erc20TransferParams {
    from: String,
    to: String,
    amount: String,
}

impl EndpointNormalizer for EvmNormalizer {
    fn chain_id(&self) -> &'static str {
        "eth-mainnet"
    }

    fn normalize(
        &self,
        cem: &CanonicalEndpointMapping,
        _receipt_rlp: &[u8],
        _tx_index: u32,
        log_index: u32,
    ) -> Result<NormalizedData, String> {
        // A real implementation would use a robust RLP and EIP-2718 typed receipt decoder.
        // For example: `let receipt = TypedReceipt::decode(receipt_rlp)?;`
        let receipt = TypedReceipt {
            logs: vec![Log {
                topics: vec![[0; 32]; 3],
                data: vec![],
            }],
        };
        let log = receipt
            .logs
            .get(log_index as usize)
            .ok_or("log_index out of bounds")?;

        const TRANSFER_TOPIC0: &str =
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        let topic0 = hex::encode(log.topics[0]);
        if topic0 != TRANSFER_TOPIC0 {
            return Err("Log is not an ERC-20 Transfer event".into());
        }

        let endpoint_id = cem
            .get_canonical_id(self.chain_id(), &format!("0x{}", topic0))
            .ok_or("Unknown event topic")?
            .clone();

        let from = format!("0x{}", hex::encode(&log.topics[1][12..]));
        let to = format!("0x{}", hex::encode(&log.topics[2][12..]));
        let amount = u256::from_big_endian(&log.data).to_string();

        let params = Erc20TransferParams { from, to, amount };
        let params_jcs = to_vec(&params).map_err(|e| e.to_string())?;

        let result_digest = *depin_sdk_crypto::algorithms::hash::sha256(&[])
            .as_slice()
            .try_into()
            .unwrap();

        Ok(NormalizedData {
            endpoint_id,
            params_jcs,
            result_digest,
            result_digest_algo: DigestAlgo::Sha256,
        })
    }
}
