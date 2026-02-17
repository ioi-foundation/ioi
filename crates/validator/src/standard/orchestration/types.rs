use ioi_api::vm::inference::PiiRiskSurface;
use ioi_pii::RiskSurface;
use ioi_types::app::agentic::PiiEgressRiskSurface;
use ioi_types::app::{AccountId, BlockTimingParams, BlockTimingRuntime, ChainTransaction, TxHash};

/// Configuration for the ingestion worker.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Maximum number of transactions to process in one batch.
    pub batch_size: usize,
    /// Maximum time to wait for a batch to fill before processing.
    pub batch_timeout_ms: u64,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            batch_timeout_ms: 10,
        }
    }
}

pub(crate) fn to_shared_risk_surface(risk_surface: PiiRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiRiskSurface::LocalProcessing => RiskSurface::LocalProcessing,
        PiiRiskSurface::Egress => RiskSurface::Egress,
    }
}

pub(crate) fn to_shared_risk_surface_from_egress(
    risk_surface: PiiEgressRiskSurface,
) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

pub(crate) fn parse_hash_hex(input: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// A simplified view of the chain tip needed for ante checks.
#[derive(Clone, Debug)]
pub struct ChainTipInfo {
    pub height: u64,
    pub timestamp: u64,
    pub gas_used: u64,
    pub state_root: Vec<u8>,
    pub genesis_root: Vec<u8>,
}

/// Helper struct to keep related transaction data aligned during batch processing.
pub(crate) struct ProcessedTx {
    pub tx: ChainTransaction,
    pub canonical_hash: TxHash,
    pub raw_bytes: Vec<u8>,
    pub receipt_hash_hex: String,
    pub account_id: Option<AccountId>,
    pub nonce: Option<u64>,
}

/// Cache for block timing parameters to avoid constant fetching from state.
pub(crate) struct TimingCache {
    pub params: BlockTimingParams,
    pub runtime: BlockTimingRuntime,
    pub last_fetched: std::time::Instant,
}
