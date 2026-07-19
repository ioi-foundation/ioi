use super::apply_system_transaction;
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_api::transaction::context::TxContext;
use ioi_types::app::{
    AccountId, ChainId, SignHeader, SignatureProof, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::config::default_service_policies;
use ioi_types::error::{StateError, TransactionError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};
use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.data.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.data.remove(key);
        }
        self.batch_set(inserts)
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| {
                Ok((
                    Arc::<[u8]>::from(key.as_slice()),
                    Arc::<[u8]>::from(value.as_slice()),
                ))
            })
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DispatchCall {
    method: String,
    params: Vec<u8>,
    signer: AccountId,
}

#[derive(Default)]
struct DispatchProbe {
    calls: Mutex<Vec<DispatchCall>>,
}

#[async_trait]
impl BlockchainService for DispatchProbe {
    fn id(&self) -> &str {
        "wallet_network"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "wallet_network.v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        _state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        self.calls
            .lock()
            .expect("dispatch probe lock")
            .push(DispatchCall {
                method: method.to_string(),
                params: params.to_vec(),
                signer: ctx.signer_account_id,
            });
        Ok(())
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn default_wallet_policy_effect_consumption_transaction_reaches_dispatch() {
    let wallet_policy = default_service_policies()
        .remove("wallet_network")
        .expect("default wallet_network policy");
    let meta = ActiveServiceMeta {
        id: "wallet_network".to_string(),
        abi_version: 1,
        state_schema: "wallet_network.v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods: wallet_policy.methods,
        allowed_system_prefixes: wallet_policy.allowed_system_prefixes,
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    };
    let mut state = MockState::default();
    state
        .insert(
            &active_service_key("wallet_network"),
            &codec::to_bytes_canonical(&meta).expect("encode active service metadata"),
        )
        .expect("store active service metadata");

    let probe = Arc::new(DispatchProbe::default());
    let services = ServiceDirectory::new(vec![probe.clone() as Arc<dyn BlockchainService>]);
    let signer = AccountId([0x42u8; 32]);
    let params = vec![0x10, 0x20, 0x30];
    let transaction = SystemTransaction {
        header: SignHeader {
            account_id: signer,
            nonce: 7,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: "consume_approval_grant_for_effect@v1".to_string(),
            params: params.clone(),
        },
        signature_proof: SignatureProof::default(),
    };
    let mut ctx = TxContext {
        block_height: 9,
        block_timestamp: 1_750_000_000_000_000_000,
        chain_id: ChainId(1),
        signer_account_id: AccountId([0u8; 32]),
        services: &services,
        simulation: false,
        is_internal: false,
    };

    block_on(apply_system_transaction(&mut state, &transaction, &mut ctx))
        .expect("default-policy transaction should reach service dispatch");

    assert_eq!(
        *probe.calls.lock().expect("dispatch probe lock"),
        vec![DispatchCall {
            method: "consume_approval_grant_for_effect@v1".to_string(),
            params,
            signer,
        }]
    );
}
