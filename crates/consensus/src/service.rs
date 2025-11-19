// Path: crates/consensus/src/service.rs

use crate::PenaltyEngine;
use async_trait::async_trait;
// REMOVED: use ioi_api::impl_service_base;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_system::{KvSystemState, SystemState}; // Added SystemState import
use ioi_types::{
    app::evidence_id,
    app::penalties::ReportMisbehaviorParams,
    codec,
    error::{TransactionError, UpgradeError}, // Added UpgradeError
    service_configs::Capabilities,
};
use std::sync::Arc;

/// A specialized system service that exposes the Consensus Engine's
/// penalty logic to the transaction layer.
pub struct PenaltiesService {
    engine: Arc<dyn PenaltyEngine>,
}

impl PenaltiesService {
    pub fn new(engine: Arc<dyn PenaltyEngine>) -> Self {
        Self { engine }
    }
}

// REMOVED: impl_service_base!(PenaltiesService, "penalties");

#[async_trait]
impl UpgradableService for PenaltiesService {
    async fn prepare_upgrade(&self, _: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(vec![])
    }
    async fn complete_upgrade(&self, _: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for PenaltiesService {
    fn id(&self) -> &str {
        "penalties"
    }
    fn abi_version(&self) -> u32 {
        1
    }
    fn state_schema(&self) -> &str {
        "v1"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        _ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "report_misbehavior@v1" => {
                let p: ReportMisbehaviorParams = codec::from_bytes_canonical(params)?;

                // 1. Wrap the raw state in the semantic SystemState wrapper
                let mut sys = KvSystemState::new(state);

                // 2. Check for duplicate evidence
                // Map CoreError from evidence_id -> TransactionError::Invalid
                let id =
                    evidence_id(&p.report).map_err(|e| TransactionError::Invalid(e.to_string()))?;

                if sys
                    .evidence()
                    .contains(&id)
                    .map_err(TransactionError::State)?
                {
                    return Err(TransactionError::Invalid("Duplicate evidence".into()));
                }

                // 3. Delegate to the Consensus Engine to apply the penalty
                self.engine.apply(&mut sys, &p.report)?;

                // 4. Record evidence to prevent replay
                sys.evidence_mut()
                    .insert(id)
                    .map_err(TransactionError::State)?;

                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.to_string())),
        }
    }
}
