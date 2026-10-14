// Path: crates/services/src/market/licensing.rs

use anyhow::{anyhow, Result};
use ioi_api::chain::WorkloadClientApi; // [FIX] Import trait for query_state_at
use ioi_api::state::Verifier;
use ioi_client::WorkloadClient;
use ioi_state::tree::iavl::verifier::IAVLHashVerifier;
use ioi_types::app::agentic::AssetLicense;
use ioi_types::app::{AccountId, Membership};
use ioi_types::codec;

pub struct LicenseVerifier {
    rpc_url: String,
    trusted_root: [u8; 32],
}

impl LicenseVerifier {
    pub fn new(rpc_url: String, trusted_root: [u8; 32]) -> Self {
        Self {
            rpc_url,
            trusted_root,
        }
    }

    /// Verifies license ownership using a Merkle Proof.
    pub async fn verify_license(&self, user: AccountId, asset_hash: [u8; 32]) -> Result<bool> {
        let client = WorkloadClient::new(&self.rpc_url, "", "", "").await?;

        let license_key = [b"market::license::", user.as_ref(), b"::", &asset_hash].concat();

        // 1. Request Proof for the License Key
        let root = ioi_types::app::StateRoot(self.trusted_root.to_vec());
        let response = client.query_state_at(root, &license_key).await?;

        // 2. Local Verification
        let verifier = IAVLHashVerifier::default();
        let commitment = verifier.commitment_from_bytes(&self.trusted_root)?;

        // [FIX] Explicitly map codec string error to anyhow::Error
        let proof = codec::from_bytes_canonical(&response.proof_bytes)
            .map_err(|e| anyhow!("Codec error: {}", e))?;

        verifier
            .verify(&commitment, &proof, &license_key, &response.membership)
            .map_err(|e| anyhow!("License proof verification failed: {}", e))?;

        // 3. Check Content
        if let Membership::Present(bytes) = response.membership {
            if let Ok(license) = codec::from_bytes_canonical::<AssetLicense>(&bytes) {
                return license_currently_valid(&client, &license).await;
            }
        }

        Ok(false)
    }
}

/// Whether a proven licence is in force: perpetual (expiry 0), or the latest COMMITTED
/// (Agentgres-admitted) height has not reached its expiry. The durable status is never used: it
/// counts signed but uncommitted blocks, and on an AFT chain it was pinned at height 1, so expiring
/// licences never expired (FU-N11-DURABLE-STATUS-1 D2a, C6; BUILD-DELTA #71).
pub(crate) async fn license_currently_valid(
    client: &(dyn WorkloadClientApi + '_),
    license: &AssetLicense,
) -> Result<bool> {
    if license.expiry == 0 {
        return Ok(true);
    }
    let status = client.get_committed_status().await?;
    Ok(status.height < license.expiry)
}

#[cfg(test)]
mod committed_expiry_tests {
    //! FU-N11-DURABLE-STATUS-1 D2a RED-C6 (BUILD-DELTA #71): licence expiry keys on the COMMITTED
    //! height, not on the durable status.
    use super::license_currently_valid;
    use ioi_api::chain::{BlockExecutionReceipt, QueryStateResponse, WorkloadClientApi};
    use ioi_types::app::agentic::{AssetLicense, AssetType};
    use ioi_types::app::{AccountId, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot};
    use ioi_types::error::ChainError;

    /// Polls a future that completes without waking (the client below never awaits I/O).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("the status-only client never pends"),
        }
    }

    fn unused<T>() -> Result<T, ChainError> {
        Err(ChainError::Transaction("unused by the status-only client".into()))
    }

    /// A workload client whose durable status (`get_status`) runs ahead of its committed status.
    #[derive(Debug)]
    struct StatusOnlyClient {
        durable: u64,
        committed: u64,
    }

    #[async_trait::async_trait]
    impl WorkloadClientApi for StatusOnlyClient {
        async fn process_block(
            &self,
            _block: Block<ChainTransaction>,
        ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>, Vec<BlockExecutionReceipt>), ChainError>
        {
            unused()
        }
        async fn get_blocks_range(
            &self,
            _since: u64,
            _max_blocks: u32,
            _max_bytes: u32,
        ) -> Result<Vec<Block<ChainTransaction>>, ChainError> {
            unused()
        }
        async fn get_block_by_height(
            &self,
            _height: u64,
        ) -> Result<Option<Block<ChainTransaction>>, ChainError> {
            unused()
        }
        async fn check_transactions_at(
            &self,
            _anchor: StateAnchor,
            _expected_timestamp_secs: u64,
            _txs: Vec<ChainTransaction>,
        ) -> Result<Vec<Result<(), String>>, ChainError> {
            unused()
        }
        async fn query_state_at(
            &self,
            _root: StateRoot,
            _key: &[u8],
        ) -> Result<QueryStateResponse, ChainError> {
            unused()
        }
        async fn query_raw_state(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            unused()
        }
        async fn prefix_scan(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
            unused()
        }
        async fn get_staked_validators(
            &self,
        ) -> Result<std::collections::BTreeMap<AccountId, u64>, ChainError> {
            unused()
        }
        async fn get_genesis_status(&self) -> Result<bool, ChainError> {
            unused()
        }
        async fn update_block_header(&self, _block: Block<ChainTransaction>) -> Result<(), ChainError> {
            unused()
        }
        async fn get_state_root(&self) -> Result<StateRoot, ChainError> {
            unused()
        }
        async fn get_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: self.durable,
                ..Default::default()
            })
        }
        async fn get_committed_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: self.committed,
                ..Default::default()
            })
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn licence(expiry: u64) -> AssetLicense {
        AssetLicense {
            asset_hash: [7; 32],
            asset_type: AssetType::Agent,
            licensee: AccountId([8; 32]),
            purchase_height: 1,
            expiry,
        }
    }

    #[test]
    fn a_licence_expires_by_the_committed_height_not_the_durable_height() {
        let ahead = StatusOnlyClient {
            durable: 60,
            committed: 4,
        };
        assert!(
            block_on(license_currently_valid(&ahead, &licence(50))).expect("check"),
            "committed height 4 < expiry 50: in force, although the durable height is past it"
        );
        let reached = StatusOnlyClient {
            durable: 60,
            committed: 50,
        };
        assert!(
            !block_on(license_currently_valid(&reached, &licence(50))).expect("check"),
            "the committed height reached the expiry: expired"
        );
        assert!(
            block_on(license_currently_valid(&reached, &licence(0))).expect("check"),
            "expiry 0 is perpetual"
        );
    }
}
