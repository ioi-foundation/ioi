// Path: crates/tx/src/settlement/tests.rs
//! BD-57 RED tests for the settlement model (FIX-PLAN §3, R1-R11), BD-57 review 1's
//! tests (R6b and R9 strengthened; R12-R24), and, in their own sections, the tests
//! of BD-61, BD-62 and BD-63.
//!
//! Every test drives the model through its real entry point,
//! `TransactionModel::apply_payload`, with a `TxContext` and an in-memory
//! `StateAccess`. Only the genesis-like starting state (balances, the identity
//! hub's activation record and each account's credential) is written directly;
//! every bond, settlement, escalation and transfer goes through `apply_payload`.
//! Two exceptions, each stated at its test: a credential TRANSITION (an alias
//! account in R13/R14, the rotation in R23, the missing credential in R24) writes
//! the identity hub's credentials key in the layout the hub itself writes, and R22
//! re-writes an open bond beside a dispute (a state no handler produces), so that
//! only the dispute guard can refuse.
//!
//! Each test asserts the FIXED behaviour. A comment above each test states its
//! predicted outcome at the RED commit that added (or last changed) it, and the
//! reason. For R1-R11 that is a76dcb018 (handlers unchanged except for the
//! compile-only `_` patterns); for the later tests it is their own RED commit,
//! whose handlers are those of the BD-57 GREEN commit 03c7ef148.
//!
//! Signatures are real Ed25519 signatures. Accounts are registered exactly as
//! `GenesisBuilder::add_identity` registers them (crates/cli/src/testing/genesis.rs):
//! the account id is `account_id_from_key_material(ED25519, protobuf public key)`,
//! the identity hub holds `[Some(active credential), None]` under its namespace, and
//! the global `ACCOUNT_ID_TO_PUBKEY_PREFIX` map holds the full public key. That is
//! the state `verify_stateful_authorization` (crates/tx/src/system/validation.rs)
//! reads for the credential path, so a fix that resolves each party's ACTIVE
//! credential through the identity hub, or through the pubkey map, or through the
//! bootstrap derivation, finds the same key.

use super::{BondRecordV1, DisputeRecordV1, SettlementModel};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::{
    CommitmentScheme, CommitmentStructure, ProofContext, SchemeIdentifier, Selector,
};
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::error::CryptoError;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::{
    service_namespace_prefix, ProofProvider, PrunePlan, StateAccess, StateManager,
    StateScanIter, VerifiableState,
};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_api::validator::WorkloadContainer;
use ioi_services::identity::IdentityHub;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChallengePackage,
    Credential, Membership, Receipt, RootHash, SettlementPayload, SettlementSummary,
    SettlementTransaction, SignHeader, SignatureProof, SignatureSuite,
};
use ioi_types::codec;
use ioi_types::config::ConsensusType;
use ioi_types::error::{ChainError, StateError, TransactionError};
use ioi_types::keys::{
    active_service_key, ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX,
};
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MigrationConfig};
use libp2p::identity::Keypair;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

// ---------------------------------------------------------------------------
// State-layout constants. They are written out here, independently of the
// handler module, because they are the state ABI the tests observe.
// ---------------------------------------------------------------------------

/// Balance key prefix (`balance::` ‖ account id), as the handlers use it.
const BALANCE_PREFIX: &[u8] = b"balance::";
/// Open bond key prefix (`settle::bond::` ‖ session id); equals the handler's `BOND_PREFIX`.
const BOND_PREFIX: &[u8] = b"settle::bond::";
/// Dispute key prefix (`dispute::` ‖ session id), as the Escalate handler uses it.
const DISPUTE_PREFIX: &[u8] = b"dispute::";
/// Settled-session TOMBSTONE key prefix (`settled::` ‖ session id), FIX-PLAN §2.2:
/// a successful cooperative close writes it, and Commit refuses a session id that
/// has one. The fix must define the same literal.
const SETTLED_TOMBSTONE_PREFIX: &[u8] = b"settled::";

/// Domain separator of the settlement summary signature (FIX-PLAN §2.2).
///
/// The exact signed byte layout is:
///
/// ```text
/// b"ioi::settlement::summary::v1\0"   29 bytes, the trailing NUL included
/// ‖ SCALE(chain_id: ChainId)          4 bytes, u32 little-endian
/// ‖ SCALE(summary: SettlementSummary) the summary's canonical SCALE encoding
/// ‖ SCALE(expires_at_height: u64)     8 bytes, u64 little-endian
/// ```
///
/// `chain_id` is the executing chain's id (`TxContext::chain_id`).
const SUMMARY_SIGNING_DOMAIN: &[u8] = b"ioi::settlement::summary::v1\0";

// ---------------------------------------------------------------------------
// Scenario constants.
// ---------------------------------------------------------------------------

const CHAIN: ChainId = ChainId(7);
const OTHER_CHAIN: ChainId = ChainId(8);
const HEIGHT: u64 = 100;
const EXPIRES: u64 = 200;
const SESSION: [u8; 32] = [0x5E; 32];
const BOND: u128 = 100;
const FINAL: u128 = 60;
const APPEAL: u128 = 5;
const PAYER_START: u128 = 1_000;
const PROVIDER_START: u128 = 50;
const MALLORY_START: u128 = 1_000;

// ---------------------------------------------------------------------------
// Type-level stand-ins. `apply_payload` is generic over a commitment scheme, a
// state manager and a chain view. The settlement model never calls the chain
// view (its parameter is `_chain`), so these types exist only to satisfy the
// bounds; every method that could be reached is `unreachable!`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TestScheme;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestCommitment(Vec<u8>);

impl AsRef<[u8]> for TestCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
struct TestProof(Vec<u8>);

impl CommitmentStructure for TestScheme {
    fn commit_leaf(_key: &[u8], _value: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unreachable!("the settlement model does not commit")
    }

    fn commit_branch(_left: &[u8], _right: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unreachable!("the settlement model does not commit")
    }
}

impl CommitmentScheme for TestScheme {
    type Commitment = TestCommitment;
    type Proof = TestProof;
    type Value = Vec<u8>;
    type Witness = ();

    fn commit_with_witness(
        &self,
        _values: &[Option<Self::Value>],
    ) -> Result<(Self::Commitment, Self::Witness), CryptoError> {
        unreachable!("the settlement model does not commit")
    }

    fn create_proof(
        &self,
        _witness: &Self::Witness,
        _selector: &Selector,
        _value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        unreachable!("the settlement model does not prove")
    }

    fn verify(
        &self,
        _commitment: &Self::Commitment,
        _proof: &Self::Proof,
        _selector: &Selector,
        _value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        unreachable!("the settlement model does not verify commitments")
    }

    fn scheme_id() -> SchemeIdentifier {
        unreachable!("the settlement model does not name its scheme")
    }
}

/// The state-manager type parameter. It is never constructed.
#[derive(Debug)]
struct UnusedBackend;

impl StateAccess for UnusedBackend {
    fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        unreachable!("type-level stand-in")
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn delete(&mut self, _key: &[u8]) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn batch_set(&mut self, _updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn batch_get(&self, _keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        unreachable!("type-level stand-in")
    }

    fn batch_apply(
        &mut self,
        _inserts: &[(Vec<u8>, Vec<u8>)],
        _deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn prefix_scan(&self, _prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        unreachable!("type-level stand-in")
    }
}

impl VerifiableState for UnusedBackend {
    type Commitment = TestCommitment;
    type Proof = TestProof;

    fn root_commitment(&self) -> TestCommitment {
        unreachable!("type-level stand-in")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl ProofProvider for UnusedBackend {
    fn create_proof(&self, _key: &[u8]) -> Option<TestProof> {
        unreachable!("type-level stand-in")
    }

    fn verify_proof(
        &self,
        _commitment: &TestCommitment,
        _proof: &TestProof,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn get_with_proof_at(
        &self,
        _root: &TestCommitment,
        _key: &[u8],
    ) -> Result<(Membership, TestProof), StateError> {
        unreachable!("type-level stand-in")
    }

    fn commitment_from_anchor(&self, _anchor: &[u8; 32]) -> Option<TestCommitment> {
        unreachable!("type-level stand-in")
    }

    fn commitment_from_bytes(&self, _bytes: &[u8]) -> Result<TestCommitment, StateError> {
        unreachable!("type-level stand-in")
    }

    fn commitment_to_bytes(&self, _c: &TestCommitment) -> Vec<u8> {
        unreachable!("type-level stand-in")
    }
}

#[async_trait]
impl StateManager for UnusedBackend {
    fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }

    fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
        unreachable!("type-level stand-in")
    }

    fn commit_version(&mut self, _height: u64) -> Result<RootHash, StateError> {
        unreachable!("type-level stand-in")
    }

    fn adopt_known_root(&mut self, _root_bytes: &[u8], _version: u64) -> Result<(), StateError> {
        unreachable!("type-level stand-in")
    }
}

/// The chain-view argument. The settlement model binds it to `_chain` and never calls it.
#[derive(Debug)]
struct UnusedChain;

#[async_trait]
impl ChainView<TestScheme, UnusedBackend> for UnusedChain {
    async fn view_at(
        &self,
        _state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the settlement model".into(),
        ))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        unreachable!("unused by the settlement model")
    }

    fn consensus_type(&self) -> ConsensusType {
        ConsensusType::Aft
    }

    fn workload_container(&self) -> &WorkloadContainer<UnusedBackend> {
        unreachable!("unused by the settlement model")
    }
}

// ---------------------------------------------------------------------------
// In-memory state (the same shape as crates/tx/src/unified/tests.rs `MockState`)
// and a dependency-free executor for the async entry point.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Parties, signing and the scenario world.
// ---------------------------------------------------------------------------

/// The exact message both summary signatures cover (see `SUMMARY_SIGNING_DOMAIN`).
fn summary_sign_bytes(
    chain_id: ChainId,
    summary: &SettlementSummary,
    expires_at_height: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(SUMMARY_SIGNING_DOMAIN);
    message.extend_from_slice(&chain_id.encode());
    message.extend_from_slice(&summary.encode());
    message.extend_from_slice(&expires_at_height.encode());
    message
}

/// An account with a deterministic Ed25519 key, registered like a genesis identity.
struct Party {
    keypair: Keypair,
    /// The libp2p protobuf encoding, as `GenesisBuilder::add_identity` stores it.
    public_key: Vec<u8>,
    id: AccountId,
}

impl Party {
    fn from_seed(seed: u8) -> Self {
        let keypair =
            Keypair::ed25519_from_bytes([seed; 32]).expect("setup: ed25519 key from seed");
        let public_key = keypair.public().encode_protobuf();
        let id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .expect("setup: account id from key material"),
        );
        Self {
            keypair,
            public_key,
            id,
        }
    }

    /// A real signature by this party's active credential over `message`.
    fn sign_raw(&self, message: &[u8]) -> SignatureProof {
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: self.public_key.clone(),
            signature: self.keypair.sign(message).expect("setup: ed25519 sign"),
        }
    }

    /// A real signature over the domain-separated summary message.
    fn sign_summary(
        &self,
        chain_id: ChainId,
        summary: &SettlementSummary,
        expires_at_height: u64,
    ) -> SignatureProof {
        self.sign_raw(&summary_sign_bytes(chain_id, summary, expires_at_height))
    }
}

fn put(state: &mut MockState, key: Vec<u8>, value: Vec<u8>) {
    state.insert(&key, &value).expect("setup: state insert");
}

/// The identity hub's activation record, so its credentials view is readable
/// (the same `ActiveServiceMeta` shape as crates/tx/src/unified/tests.rs).
fn activate_identity_hub(state: &mut MockState) {
    let meta = ActiveServiceMeta {
        id: "identity_hub".to_string(),
        abi_version: 1,
        state_schema: "v1".to_string(),
        caps: Capabilities::ON_END_BLOCK,
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods: BTreeMap::new(),
        allowed_system_prefixes: Vec::new(),
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    };
    put(
        state,
        active_service_key("identity_hub"),
        codec::to_bytes_canonical(&meta).expect("setup: encode identity hub meta"),
    );
}

/// Registers `party` exactly as `GenesisBuilder::add_identity_custom` does.
fn register_identity(state: &mut MockState, party: &Party) {
    let ns = service_namespace_prefix("identity_hub");
    let creds: [Option<Credential>; 2] = [
        Some(Credential {
            suite: SignatureSuite::ED25519,
            public_key_hash: party.id.0,
            activation_height: 0,
            l2_location: None,
            weight: 1,
        }),
        None,
    ];
    put(
        state,
        [ns.as_slice(), IDENTITY_CREDENTIALS_PREFIX, party.id.as_ref()].concat(),
        codec::to_bytes_canonical(&creds).expect("setup: encode credentials"),
    );
    let record = ActiveKeyRecord {
        suite: SignatureSuite::ED25519,
        public_key_hash: party.id.0,
        since_height: 0,
    };
    put(
        state,
        [ns.as_slice(), b"identity::key_record::", party.id.as_ref()].concat(),
        codec::to_bytes_canonical(&record).expect("setup: encode key record"),
    );
    put(
        state,
        [ACCOUNT_ID_TO_PUBKEY_PREFIX, party.id.as_ref()].concat(),
        party.public_key.clone(),
    );
}

fn balance_key(id: &AccountId) -> Vec<u8> {
    [BALANCE_PREFIX, id.as_ref()].concat()
}

fn bond_key() -> Vec<u8> {
    [BOND_PREFIX, SESSION.as_slice()].concat()
}

fn dispute_key() -> Vec<u8> {
    [DISPUTE_PREFIX, SESSION.as_slice()].concat()
}

fn tombstone_key() -> Vec<u8> {
    [SETTLED_TOMBSTONE_PREFIX, SESSION.as_slice()].concat()
}

fn summary(
    payer_id: AccountId,
    provider_id: AccountId,
    final_amount: u128,
    mode: u8,
) -> SettlementSummary {
    SettlementSummary {
        session_id: SESSION,
        provider_id,
        payer_id,
        terms_hash: [0x7E; 32],
        final_seq: 9,
        final_amount,
        final_receipt_root: [0x3C; 32],
        mode,
    }
}

fn commit_payload(provider_id: AccountId) -> SettlementPayload {
    SettlementPayload::Commit {
        session_id: SESSION,
        provider_id,
        bond_amount: BOND,
        policy_hash: [0x9A; 32],
        receipt_root: [0u8; 32],
    }
}

fn settle_payload(
    summary: SettlementSummary,
    expires_at_height: u64,
    payer_sig: SignatureProof,
    provider_sig: SignatureProof,
) -> SettlementPayload {
    SettlementPayload::Settle {
        summary,
        expires_at_height,
        payer_sig,
        provider_sig,
    }
}

fn escalate_payload(signer_id: AccountId, appeal_bond: u128) -> SettlementPayload {
    SettlementPayload::Escalate {
        session_id: SESSION,
        evidence: ChallengePackage {
            contested_receipt: Receipt {
                canonical_payload_hash: [0x01; 32],
                inputs_commitment: [0x02; 32],
                outputs_commitment: [0x03; 32],
                model_snapshot_id: [0x04; 32],
                policy_hash: [0x9A; 32],
                session_id: Some(SESSION),
                prev_receipt_hash: [0u8; 32],
                signer_id,
                signature: Vec::new(),
                external_proof: None,
            },
            inclusion_proof: Vec::new(),
        },
        bond: appeal_bond,
    }
}

fn printable(key: &[u8]) -> String {
    key.iter()
        .map(|b| {
            if b.is_ascii_graphic() {
                (*b as char).to_string()
            } else {
                format!("\\x{:02x}", b)
            }
        })
        .collect()
}

/// Lists the keys added (+), changed (~) and removed (-) between two snapshots.
fn describe_diff(before: &BTreeMap<Vec<u8>, Vec<u8>>, after: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut lines = Vec::new();
    for (key, value) in after {
        match before.get(key) {
            None => lines.push(format!("+ {}", printable(key))),
            Some(old) if old != value => lines.push(format!("~ {}", printable(key))),
            Some(_) => {}
        }
    }
    for key in before.keys() {
        if !after.contains_key(key) {
            lines.push(format!("- {}", printable(key)));
        }
    }
    lines.join("; ")
}

/// The payer (seed 0x11), the provider (0x22) and a funded third party, Mallory
/// (0x33), with their identities registered and balances seeded at genesis.
struct World {
    model: SettlementModel<TestScheme>,
    services: ServiceDirectory,
    state: MockState,
    payer: Party,
    provider: Party,
    mallory: Party,
    nonce: u64,
}

impl World {
    fn new() -> Self {
        let hub = IdentityHub::new(MigrationConfig {
            grace_period_blocks: 10,
            accept_staged_during_grace: false,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
            chain_id: CHAIN.0,
        });
        let services = ServiceDirectory::new(vec![Arc::new(hub) as Arc<dyn BlockchainService>]);
        let payer = Party::from_seed(0x11);
        let provider = Party::from_seed(0x22);
        let mallory = Party::from_seed(0x33);

        let mut state = MockState::default();
        activate_identity_hub(&mut state);
        for (party, start) in [
            (&payer, PAYER_START),
            (&provider, PROVIDER_START),
            (&mallory, MALLORY_START),
        ] {
            register_identity(&mut state, party);
            put(
                &mut state,
                balance_key(&party.id),
                codec::to_bytes_canonical(&start).expect("setup: encode balance"),
            );
        }

        Self {
            model: SettlementModel::new(TestScheme),
            services,
            state,
            payer,
            provider,
            mallory,
            nonce: 0,
        }
    }

    /// Builds a settlement transaction from `signer`. The outer signature is not
    /// part of the model's input: it is verified upstream (validation.rs), and the
    /// model sees only `ctx.signer_account_id`.
    fn tx(&mut self, signer: AccountId, payload: SettlementPayload) -> SettlementTransaction {
        self.nonce += 1;
        SettlementTransaction {
            header: SignHeader {
                account_id: signer,
                nonce: self.nonce,
                chain_id: CHAIN,
                tx_version: 1,
                session_auth: None,
            },
            payload,
            signature_proof: SignatureProof::default(),
        }
    }

    /// Runs one transaction through `SettlementModel::apply_payload` at `block_height`.
    fn apply(
        &mut self,
        signer: AccountId,
        block_height: u64,
        tx: &SettlementTransaction,
    ) -> Result<(), TransactionError> {
        let mut ctx = TxContext {
            block_height,
            block_timestamp: 1_750_000_000_000_000_000 + block_height,
            chain_id: CHAIN,
            signer_account_id: signer,
            services: &self.services,
            simulation: false,
            is_internal: false,
        };
        block_on(self.model.apply_payload::<UnusedBackend, UnusedChain>(
            &UnusedChain,
            &mut self.state,
            tx,
            &mut ctx,
        ))
        .map(|_| ())
    }

    fn submit(
        &mut self,
        signer: AccountId,
        block_height: u64,
        payload: SettlementPayload,
    ) -> Result<(), TransactionError> {
        let tx = self.tx(signer, payload);
        self.apply(signer, block_height, &tx)
    }

    /// The payer opens the bond for `SESSION`, backing the provider.
    fn commit_bond(&mut self) {
        let payer = self.payer.id;
        let provider = self.provider.id;
        self.submit(payer, HEIGHT, commit_payload(provider))
            .expect("setup: the payer's Commit must be accepted");
        assert_eq!(
            self.balance(&payer),
            PAYER_START - BOND,
            "setup: Commit debits the bond from the payer"
        );
        assert!(self.bond().is_some(), "setup: Commit writes the bond key");
    }

    /// A summary signed by both parties' active credentials over `chain_id`.
    fn doubly_signed_close(
        &self,
        summary: SettlementSummary,
        chain_id: ChainId,
        expires_at_height: u64,
    ) -> SettlementPayload {
        let payer_sig = self.payer.sign_summary(chain_id, &summary, expires_at_height);
        let provider_sig = self
            .provider
            .sign_summary(chain_id, &summary, expires_at_height);
        settle_payload(summary, expires_at_height, payer_sig, provider_sig)
    }

    fn balance(&self, id: &AccountId) -> u128 {
        self.state
            .data
            .get(&balance_key(id))
            .map(|bytes| codec::from_bytes_canonical(bytes).expect("balance decodes"))
            .unwrap_or(0)
    }

    fn bond(&self) -> Option<Vec<u8>> {
        self.state.data.get(&bond_key()).cloned()
    }

    fn dispute(&self) -> Option<Vec<u8>> {
        self.state.data.get(&dispute_key()).cloned()
    }

    fn tombstone(&self) -> Option<Vec<u8>> {
        self.state.data.get(&tombstone_key()).cloned()
    }

    fn snapshot(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.state.data.clone()
    }

    /// A refused transaction returns `Err` and leaves EVERY key unchanged
    /// (balances, the bond key, the dispute key and the tombstone key included).
    fn assert_refused_without_writes(
        &self,
        case: &str,
        result: Result<(), TransactionError>,
        before: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) {
        assert!(
            result.is_err(),
            "{case}: expected REFUSED, got ACCEPTED; state diff: [{}]; payer {}, provider {}, mallory {}",
            describe_diff(before, &self.state.data),
            self.balance(&self.payer.id),
            self.balance(&self.provider.id),
            self.balance(&self.mallory.id),
        );
        assert!(
            self.state.data == *before,
            "{case}: refused ({:?}) but state changed: [{}]",
            result,
            describe_diff(before, &self.state.data),
        );
    }
}

// ---------------------------------------------------------------------------
// R1-R10 (FIX-PLAN §3). Setup steps panic with "setup:" or "R<n> setup:";
// a RED failure for the defect's own reason panics with "R<n>: ...".
// ---------------------------------------------------------------------------

// R1: a third party (Mallory) submits Settle naming itself as provider, with
// garbage signatures (the payer's real public key with an all-zero signature,
// and Mallory's key with filler bytes).
// After the fix: REFUSED; no state written; the victim's bond intact.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. The Settle
// arm binds payer_sig and provider_sig to `_`, never reads ctx.signer_account_id,
// and pays summary.final_amount (the whole bond) to summary.provider_id (Mallory),
// then deletes the bond.
#[test]
fn r1_third_party_settle_naming_itself_provider_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let victim_bond = world.bond();
    let before = world.snapshot();

    let mallory = world.mallory.id;
    let theft = summary(world.payer.id, mallory, BOND, 0);
    let payload = settle_payload(
        theft,
        EXPIRES,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: world.payer.public_key.clone(),
            signature: vec![0u8; 64],
        },
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: world.mallory.public_key.clone(),
            signature: vec![0xA5; 64],
        },
    );
    let result = world.submit(mallory, HEIGHT, payload);

    world.assert_refused_without_writes("R1", result, &before);
    assert_eq!(world.bond(), victim_bond, "R1: the victim's bond is intact");
    assert_eq!(
        world.balance(&mallory),
        MALLORY_START,
        "R1: Mallory is not paid"
    );
    assert!(world.dispute().is_none(), "R1: no dispute is opened");
    assert!(world.tombstone().is_none(), "R1: no tombstone is written");
}

// R2 (first arm): a valid provider signature, and an invalid payer signature made
// with the payer's own active credential but over a DIFFERENT summary (the payer
// authorized 30; the provider claims 60). Only cryptographic verification of
// payer_sig over the submitted summary can refuse it.
// After the fix: REFUSED; no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. payer_sig is
// bound to `_` and never verified, so the provider is paid 60 out of the bond.
#[test]
fn r2a_payer_signature_over_a_different_summary_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let claimed = summary(payer, provider, FINAL, 0);
    let authorized = summary(payer, provider, 30, 0);
    let payer_sig = world.payer.sign_summary(CHAIN, &authorized, EXPIRES);
    let provider_sig = world.provider.sign_summary(CHAIN, &claimed, EXPIRES);
    let result = world.submit(
        provider,
        HEIGHT,
        settle_payload(claimed, EXPIRES, payer_sig, provider_sig),
    );

    world.assert_refused_without_writes("R2a", result, &before);
}

// R2 (second arm): a valid provider signature, and an invalid payer signature that
// is a cryptographically valid signature over the CORRECT message, made by a key
// that is not the payer's active credential (Mallory's key, presented in payer_sig).
// It is refused only if payer_sig is bound to the payer account's ACTIVE credential,
// not merely checked against the public key it carries.
// After the fix: REFUSED; no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. payer_sig is
// bound to `_` and never read.
#[test]
fn r2b_payer_signature_by_a_key_that_is_not_the_payers_credential_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let claimed = summary(payer, provider, FINAL, 0);
    let payer_sig = world.mallory.sign_summary(CHAIN, &claimed, EXPIRES);
    let provider_sig = world.provider.sign_summary(CHAIN, &claimed, EXPIRES);
    let result = world.submit(
        provider,
        HEIGHT,
        settle_payload(claimed, EXPIRES, payer_sig, provider_sig),
    );

    world.assert_refused_without_writes("R2b", result, &before);
}

// R3: summary.payer_id is Mallory, not the bond's payer, and both signatures are
// valid: Mallory signs as the stated payer, and the bond's provider signs.
// After the fix: REFUSED (summary.payer_id != bond.payer); no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. The bond
// record holds only the amount, the payer is never recorded or compared, and the
// refund (bond - final_amount = 90) is paid to summary.payer_id (Mallory).
#[test]
fn r3_summary_payer_other_than_the_bond_payer_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let mallory = world.mallory.id;
    let forged = summary(mallory, world.provider.id, 10, 0);
    let payer_sig = world.mallory.sign_summary(CHAIN, &forged, EXPIRES);
    let provider_sig = world.provider.sign_summary(CHAIN, &forged, EXPIRES);
    let result = world.submit(
        mallory,
        HEIGHT,
        settle_payload(forged, EXPIRES, payer_sig, provider_sig),
    );

    world.assert_refused_without_writes("R3", result, &before);
}

// R4: a correctly signed cooperative close (mode 0, both active credentials,
// this chain, not expired), submitted by the provider.
// After the fix: ACCEPTED; provider +final_amount, payer +refund, bond key gone,
// no dispute, and the settled tombstone written.
// PREDICTED AT THE RED COMMIT: FAILS on the LAST assertion only. The Settle is
// ACCEPTED and pays and refunds correctly, but no tombstone is written (the
// handler deletes the bond and writes nothing else).
#[test]
fn r4_correctly_signed_cooperative_close_is_accepted_and_tombstoned() {
    let mut world = World::new();
    world.commit_bond();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    let result = world.submit(provider, HEIGHT, close);

    assert!(
        result.is_ok(),
        "R4: a correctly signed cooperative close must be ACCEPTED, got {:?}",
        result
    );
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START + FINAL,
        "R4: the provider is paid final_amount"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - BOND + (BOND - FINAL),
        "R4: the payer is refunded bond - final_amount"
    );
    assert_eq!(
        world.balance(&world.mallory.id),
        MALLORY_START,
        "R4: no third party is touched"
    );
    assert!(world.bond().is_none(), "R4: the bond key is deleted");
    assert!(world.dispute().is_none(), "R4: no dispute is opened");
    assert!(
        world.tombstone().is_some(),
        "R4: the settled tombstone ({}) must be written",
        printable(&tombstone_key())
    );
}

// R5: REPLAY. After an accepted cooperative close, the same payer re-Commits the
// same session_id, and the old doubly-signed summary is submitted again (in a new
// outer transaction).
// After the fix: the re-Commit is REFUSED (the tombstone), the replayed Settle is
// REFUSED (no bond), and no state changes after the first close.
// PREDICTED AT THE RED COMMIT: FAILS, because both are ACCEPTED. Commit checks only
// the bond key, which the first Settle deleted, so the freed id is re-bonded; the
// replayed Settle then pays the provider final_amount a second time. The failure
// message prints both results and the balances.
#[test]
fn r5_recommit_of_a_settled_session_is_refused_so_the_old_summary_cannot_pay_again() {
    let mut world = World::new();
    world.commit_bond();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    world
        .submit(provider, HEIGHT, close.clone())
        .expect("R5 setup: the first cooperative close is accepted");
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START + FINAL,
        "R5 setup: the provider is paid once"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - FINAL,
        "R5 setup: the payer is refunded"
    );
    let before = world.snapshot();

    let recommit = world.submit(payer, HEIGHT + 1, commit_payload(provider));
    let replay = world.submit(provider, HEIGHT + 1, close);

    assert!(
        recommit.is_err() && replay.is_err() && world.state.data == before,
        "R5: a re-Commit of a settled session_id must be REFUSED and the old summary must not \
         pay again; re-Commit {:?}, replayed Settle {:?}, provider {} (was {}), payer {} (was {}); \
         state diff: [{}]",
        recommit,
        replay,
        world.balance(&provider),
        PROVIDER_START + FINAL,
        world.balance(&payer),
        PAYER_START - FINAL,
        describe_diff(&before, &world.state.data),
    );
}

// R6 (non-party arm): Mallory, neither payer nor provider, escalates the session.
// After the fix: REFUSED; no state written (the bond stays open, no dispute, and
// Mallory is not debited).
// PREDICTED AT THE RED COMMIT: FAILS, because the Escalate is ACCEPTED. The
// Escalate arm (`Escalate { session_id, .. }`) has no signer or role check, so any
// funded account moves the bond to dispute::, from which nothing releases it.
#[test]
fn r6a_escalate_by_a_non_party_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let mallory = world.mallory.id;
    let result = world.submit(mallory, HEIGHT, escalate_payload(mallory, APPEAL));

    world.assert_refused_without_writes("R6a", result, &before);
}

// R6 (payer arm): the payer escalates with an appeal bond.
// After the fix: ACCEPTED; the appeal bond is debited from the signer, the bond key
// is gone, no tombstone, the provider is untouched, and (BD-57 review 1, finding 1)
// the appeal bond is HELD, not burned: dispute:: holds DisputeRecordV1 { bond: the
// record Commit wrote, appeal_amount: APPEAL, appeal_depositor: the payer }, and the
// total value held (World::total_value: balances + open bonds + dispute custody) is
// the genesis total after Commit and after Escalate.
// PREDICTED AT THE BD-57 RED COMMIT (a76dcb018, before review 1, when this test
// expected the bond bytes to move unchanged): FAILED on the debit assertion only
// (measured; RESULT-red.md).
// PREDICTED AT THE BD-57b RED COMMIT (Escalate arm as at 03c7ef148): FAILS at the
// custody decode (the second-last assertion), after the debit assertion passes. The
// arm debits the appeal bond but writes only the bare BondRecordV1 (112 bytes) under
// dispute::, which does not decode as DisputeRecordV1 (160 bytes).
#[test]
fn r6b_escalate_by_the_payer_is_accepted_and_debits_the_appeal_bond() {
    let mut world = World::new();
    let genesis_total = world.total_value();
    world.commit_bond();
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R6b: Commit conserves the total value held"
    );
    let bond_record = world.bond_record("R6b setup");

    let (payer, provider) = (world.payer.id, world.provider.id);
    let result = world.submit(payer, HEIGHT, escalate_payload(payer, APPEAL));

    assert!(
        result.is_ok(),
        "R6b: an Escalate by the payer must be ACCEPTED, got {:?}",
        result
    );
    assert!(world.bond().is_none(), "R6b: the bond leaves the open-bond key");
    assert!(
        world.tombstone().is_none(),
        "R6b: an escalated session is not settled"
    );
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START,
        "R6b: the provider is untouched"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - BOND - APPEAL,
        "R6b: the appeal bond must be debited from the signer"
    );
    assert_eq!(
        world.dispute_record("R6b"),
        DisputeRecordV1 {
            bond: bond_record,
            appeal_amount: APPEAL,
            appeal_depositor: payer,
        },
        "R6b: dispute:: holds the bond record and the appeal bond, deposited by the payer"
    );
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R6b: Escalate conserves the total value held (the appeal bond is not burned)"
    );
}

// R7: Settle with mode = 1 (unilateral close), with both signatures valid.
// After the fix: REFUSED (no challenge window exists; FU-N5-2); no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. The arm never
// reads summary.mode.
#[test]
fn r7_unilateral_close_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 1), CHAIN, EXPIRES);
    let result = world.submit(provider, HEIGHT, close);

    world.assert_refused_without_writes("R7", result, &before);
}

// R8: both signatures are valid, but over another chain's id (OTHER_CHAIN), and the
// summary is submitted on CHAIN: a cross-chain replay of a doubly-signed summary.
// After the fix: REFUSED; no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. No signature
// is verified, so the chain id bound into the message is never checked.
#[test]
fn r8_signature_over_another_chain_id_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let close = world.doubly_signed_close(
        summary(payer, provider, FINAL, 0),
        OTHER_CHAIN,
        EXPIRES,
    );
    let result = world.submit(provider, HEIGHT, close);

    world.assert_refused_without_writes("R8", result, &before);
}

// R9: FAIL-CLOSED DISPUTE (the Director's condition (1); FU-N5-1). After the payer's
// Escalate, each of these is tried in order against the disputed session:
//   arm 1, a validly signed cooperative Settle;
//   arm 2, a re-Commit of the session id by the payer;
//   arm 3, a second Escalate, by the provider (who can pay the appeal bond);
//   arm 4, Transfers by the payer and by the provider that draw on the bonded amount.
// After the fix: each REFUSED with no state written, and the dispute:: record stays
// byte-for-byte what the Escalate wrote. That record (BD-57 review 1, finding 1) is
// DisputeRecordV1 { the bond record, appeal_amount: APPEAL, appeal_depositor: the
// payer }, and the total value held (World::total_value) is the genesis total at
// the end. (Arm 3 is refused before the dispute guard by the missing open bond; R22
// isolates the dispute guard itself.)
// PREDICTED AT THE BD-57 RED COMMIT (a76dcb018): FAILED on ARM 2 (measured;
// RESULT-red.md). Arm 2 was ACCEPTED: Commit checked only the bond key, not
// dispute::, so a disputed session id was re-bonded.
// PREDICTED AT THE BD-57b RED COMMIT (handlers as at 03c7ef148): arms 1-4 are each
// refused with no write, and the test FAILS at the custody decode after them: the
// Escalate wrote only the bare BondRecordV1 (112 bytes) under dispute::, which does
// not decode as DisputeRecordV1 (160 bytes).
#[test]
fn r9_disputed_bond_is_frozen_fail_closed() {
    let mut world = World::new();
    let genesis_total = world.total_value();
    world.commit_bond();
    let bond_record = world.bond_record("R9 setup");

    let (payer, provider, mallory) = (world.payer.id, world.provider.id, world.mallory.id);
    world
        .submit(payer, HEIGHT, escalate_payload(payer, APPEAL))
        .expect("R9 setup: the payer's Escalate is accepted");
    let disputed = world
        .dispute()
        .expect("R9 setup: the bond is under dispute::");
    assert!(
        world.bond().is_none(),
        "R9 setup: the bond left the open-bond key"
    );
    let before = world.snapshot();

    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    let result = world.submit(provider, HEIGHT + 1, close);
    world.assert_refused_without_writes("R9 arm 1 (validly signed Settle)", result, &before);

    let result = world.submit(payer, HEIGHT + 2, commit_payload(provider));
    world.assert_refused_without_writes(
        "R9 arm 2 (re-Commit of the disputed session)",
        result,
        &before,
    );

    let result = world.submit(provider, HEIGHT + 3, escalate_payload(provider, APPEAL));
    world.assert_refused_without_writes("R9 arm 3 (second Escalate)", result, &before);

    let payer_draw = world.balance(&payer) + BOND;
    let result = world.submit(
        payer,
        HEIGHT + 4,
        SettlementPayload::Transfer {
            to: mallory,
            amount: payer_draw,
        },
    );
    world.assert_refused_without_writes(
        "R9 arm 4a (payer Transfer drawing on the bond)",
        result,
        &before,
    );

    let provider_draw = world.balance(&provider) + BOND;
    let result = world.submit(
        provider,
        HEIGHT + 4,
        SettlementPayload::Transfer {
            to: mallory,
            amount: provider_draw,
        },
    );
    world.assert_refused_without_writes(
        "R9 arm 4b (provider Transfer drawing on the bond)",
        result,
        &before,
    );

    assert_eq!(
        world.dispute(),
        Some(disputed),
        "R9: the disputed amount stays exactly under dispute::"
    );
    assert!(world.bond().is_none(), "R9: no bond is reopened");
    assert!(world.tombstone().is_none(), "R9: the disputed session is not settled");
    assert_eq!(
        world.dispute_record("R9"),
        DisputeRecordV1 {
            bond: bond_record,
            appeal_amount: APPEAL,
            appeal_depositor: payer,
        },
        "R9: dispute:: holds the bond record and the appeal bond, deposited by the payer"
    );
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R9: the total value held is conserved (the appeal bond is held, not burned)"
    );
}

// R10: an EXPIRED authorization. Both signatures are valid over
// expires_at_height = HEIGHT + 50, and the Settle executes at HEIGHT + 51.
// After the fix: REFUSED (the block height exceeds expires_at_height); no state written.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. The Settle arm
// binds expires_at_height to `_` (a compile-only edit), so expiry is not checked.
#[test]
fn r10_expired_authorization_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let expires_at_height = HEIGHT + 50;
    let close = world.doubly_signed_close(
        summary(payer, provider, FINAL, 0),
        CHAIN,
        expires_at_height,
    );
    let result = world.submit(provider, expires_at_height + 1, close);

    world.assert_refused_without_writes("R10", result, &before);
}

// R11 (the provider-side mirror of R2b): a Settle whose payer_sig is fully valid
// (the payer's active credential, correct message), but whose provider_sig is a
// cryptographically valid signature over the CORRECT message made by a key that is
// not the provider's active credential (Mallory's key, presented in provider_sig).
// The summary has final_amount = 0: the payer-only close, in which the payer would
// take back the whole bond without the provider's consent. It is refused only if
// provider_sig is bound to the provider account's ACTIVE credential.
// After the fix: REFUSED; state byte-for-byte unchanged.
// PREDICTED AT THE RED COMMIT: FAILS, because the Settle is ACCEPTED. provider_sig
// is bound to `_` and never verified, so the payer is refunded the whole bond, the
// provider is paid nothing, and the bond is deleted.
#[test]
fn r11_provider_signature_by_a_key_that_is_not_the_providers_credential_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let before = world.snapshot();

    let (payer, provider) = (world.payer.id, world.provider.id);
    let payer_only_close = summary(payer, provider, 0, 0);
    let payer_sig = world.payer.sign_summary(CHAIN, &payer_only_close, EXPIRES);
    let provider_sig = world.mallory.sign_summary(CHAIN, &payer_only_close, EXPIRES);
    let result = world.submit(
        payer,
        HEIGHT,
        settle_payload(payer_only_close, EXPIRES, payer_sig, provider_sig),
    );

    world.assert_refused_without_writes("R11", result, &before);
}

// ---------------------------------------------------------------------------
// BD-61 (BD-57 review 1, finding 2): a Transfer to oneself MINTED `amount`. Both
// balance reads return the same value, and the receiver write (balance + amount)
// lands after the sender write (balance - amount), so the account gains `amount`.
// After the fix: a self-transfer is a no-op once the funds check passes.
// ---------------------------------------------------------------------------

// BD-61 (no-op arm): the payer transfers 10 to itself, with PAYER_START funds.
// After the fix: ACCEPTED as a no-op: the state is byte-for-byte unchanged (the payer
// keeps PAYER_START, so the total held is unchanged).
// PREDICTED AT THE BD-61 RED COMMIT (Transfer arm as at 03c7ef148): FAILS on the
// SECOND assertion. The Transfer is ACCEPTED and writes the sender key with
// PAYER_START - 10, then the same key as the receiver with PAYER_START + 10, so the
// payer holds 1010 (minted 10).
#[test]
fn bd61_self_transfer_is_a_no_op_after_the_funds_check() {
    let mut world = World::new();
    let before = world.snapshot();

    let payer = world.payer.id;
    let result = world.submit(
        payer,
        HEIGHT,
        SettlementPayload::Transfer {
            to: payer,
            amount: 10,
        },
    );

    assert!(
        result.is_ok(),
        "BD-61: a funded self-transfer is ACCEPTED as a no-op, got {:?}",
        result
    );
    assert!(
        world.state.data == before,
        "BD-61: a self-transfer must change nothing; payer {} (was {}); state diff: [{}]",
        world.balance(&payer),
        PAYER_START,
        describe_diff(&before, &world.state.data),
    );
}

// BD-61 (funds arm): the payer transfers PAYER_START + 1 to itself.
// After the fix: REFUSED by the funds check (the no-op comes only after it); no state
// written.
// PREDICTED AT THE BD-61 RED COMMIT: PASSES (a PIN). The funds check
// (`sender_bal < amount`) already refuses before any write. It pins that the fix
// keeps the funds check ahead of the self-transfer no-op.
#[test]
fn bd61_insufficient_self_transfer_is_refused() {
    let mut world = World::new();
    let before = world.snapshot();

    let payer = world.payer.id;
    let result = world.submit(
        payer,
        HEIGHT,
        SettlementPayload::Transfer {
            to: payer,
            amount: PAYER_START + 1,
        },
    );

    world.assert_refused_without_writes("BD-61 (insufficient self-transfer)", result, &before);
}

// ---------------------------------------------------------------------------
// BD-62 (BD-57 review 1, finding 3): the Transfer receiver credit was unchecked
// (`receiver_bal + amount`). Without overflow checks it wraps (the sender is
// debited and the receiver drops to a small value: a burn); with them it panics
// instead of refusing. After the fix: an overflowing credit is REFUSED, and every
// new value is computed before the first write, so the refusal writes nothing.
// ---------------------------------------------------------------------------

impl World {
    /// Writes `id`'s balance directly, as genesis writes balances (`World::new`).
    fn put_balance(&mut self, id: &AccountId, amount: u128) {
        put(
            &mut self.state,
            balance_key(id),
            codec::to_bytes_canonical(&amount).expect("setup: encode balance"),
        );
    }
}

// BD-62: the receiver (Mallory) holds u128::MAX, and the payer (PAYER_START funds)
// transfers 1 to Mallory.
// After the fix: REFUSED (the credit would overflow u128); the state is byte-for-byte
// unchanged, so the payer is not debited.
// PREDICTED AT THE BD-62 RED COMMIT (Transfer arm as at 03c7ef148): FAILS by a PANIC,
// "attempt to add with overflow", at the receiver credit `receiver_bal + amount` in
// crates/tx/src/settlement/mod.rs. The test build keeps overflow checks (the
// workspace [profile.dev] sets only opt-level and debug). Without overflow checks the
// credit would wrap to 0 and the Transfer would be ACCEPTED with the payer debited.
#[test]
fn bd62_transfer_credit_overflow_is_refused_without_writes() {
    let mut world = World::new();
    let (payer, mallory) = (world.payer.id, world.mallory.id);
    world.put_balance(&mallory, u128::MAX);
    let before = world.snapshot();

    let result = world.submit(
        payer,
        HEIGHT,
        SettlementPayload::Transfer {
            to: mallory,
            amount: 1,
        },
    );

    world.assert_refused_without_writes("BD-62", result, &before);
}

// ---------------------------------------------------------------------------
// BD-63 (BD-57 review 1, finding 4): UpgradeLiability keyed its bond custody by the
// receipt's payload hash alone (`liability::upgrade::` ‖ canonical_payload_hash) and
// overwrote it: a second upgrade debited again but kept one amount, and any signer
// could overwrite another's record (with Some(0) included). After the fix: an
// occupied upgrade key is REFUSED before any debit.
// ---------------------------------------------------------------------------

/// Liability-upgrade bond key prefix (`liability::upgrade::` ‖ receipt payload hash),
/// as the UpgradeLiability arm writes it.
const UPGRADE_BOND_PREFIX: &[u8] = b"liability::upgrade::";
/// The upgraded receipt's canonical payload hash.
const UPGRADE_RECEIPT_HASH: [u8; 32] = [0xC4; 32];
/// The upgrade bond the payer posts first.
const UPGRADE: u128 = 10;

fn upgrade_key() -> Vec<u8> {
    [UPGRADE_BOND_PREFIX, UPGRADE_RECEIPT_HASH.as_slice()].concat()
}

fn upgrade_payload(signer_id: AccountId, bond_amount: Option<u128>) -> SettlementPayload {
    SettlementPayload::UpgradeLiability {
        receipt: Receipt {
            canonical_payload_hash: UPGRADE_RECEIPT_HASH,
            inputs_commitment: [0x02; 32],
            outputs_commitment: [0x03; 32],
            model_snapshot_id: [0x04; 32],
            policy_hash: [0x9A; 32],
            session_id: None,
            prev_receipt_hash: [0u8; 32],
            signer_id,
            signature: Vec::new(),
            external_proof: None,
        },
        target_level: 3,
        bond_amount,
        zk_proof: None,
    }
}

impl World {
    fn upgrade_bond(&self) -> Option<u128> {
        self.state
            .data
            .get(&upgrade_key())
            .map(|bytes| codec::from_bytes_canonical(bytes).expect("upgrade bond decodes"))
    }

    /// BD-63 setup: the payer posts an UPGRADE bond against the receipt (accepted). The
    /// payer's debit and the custody under the upgrade key sum to PAYER_START.
    fn upgrade_once(&mut self) {
        let payer = self.payer.id;
        self.submit(payer, HEIGHT, upgrade_payload(payer, Some(UPGRADE)))
            .expect("BD-63 setup: the first upgrade bond is accepted");
        assert_eq!(
            self.balance(&payer),
            PAYER_START - UPGRADE,
            "BD-63 setup: the upgrade bond is debited from the payer"
        );
        assert_eq!(
            self.upgrade_bond(),
            Some(UPGRADE),
            "BD-63 setup: the upgrade bond is held under the upgrade key"
        );
    }
}

// BD-63 (same-signer arm): after the payer's first upgrade bond, the payer posts a
// second UPGRADE bond against the same receipt.
// After the fix: REFUSED before any debit; no state written (one debit, one custody).
// PREDICTED AT THE BD-63 RED COMMIT (UpgradeLiability arm as at 03c7ef148): FAILS,
// because the second upgrade is ACCEPTED: the payer is debited again (980) and the
// upgrade key is rewritten with the same 10, so 20 is debited and 10 is held.
#[test]
fn bd63_second_upgrade_bond_by_the_same_signer_is_refused_before_any_debit() {
    let mut world = World::new();
    world.upgrade_once();
    let before = world.snapshot();

    let payer = world.payer.id;
    let result = world.submit(payer, HEIGHT + 1, upgrade_payload(payer, Some(UPGRADE)));

    world.assert_refused_without_writes("BD-63 (same signer)", result, &before);
}

// BD-63 (other-signer arm): after the payer's upgrade bond, Mallory (funded) posts an
// UPGRADE bond against the same receipt.
// After the fix: REFUSED before any debit; no state written.
// PREDICTED AT THE BD-63 RED COMMIT: FAILS, because Mallory's upgrade is ACCEPTED:
// Mallory is debited and the payer's custody record is overwritten.
#[test]
fn bd63_upgrade_bond_by_another_signer_is_refused_before_any_debit() {
    let mut world = World::new();
    world.upgrade_once();
    let before = world.snapshot();

    let mallory = world.mallory.id;
    let result = world.submit(mallory, HEIGHT + 1, upgrade_payload(mallory, Some(UPGRADE)));

    world.assert_refused_without_writes("BD-63 (another signer)", result, &before);
}

// BD-63 (Some(0) arm): after the payer's upgrade bond, Mallory posts Some(0) against
// the same receipt, which would overwrite the payer's 10 with 0 at no cost.
// After the fix: REFUSED; no state written (the payer's custody stays 10).
// PREDICTED AT THE BD-63 RED COMMIT: FAILS, because the Some(0) upgrade is ACCEPTED:
// the upgrade key is rewritten with 0 (Mallory's balance key is rewritten with the
// same bytes), so the payer's 10 is no longer held anywhere.
#[test]
fn bd63_zero_upgrade_bond_by_another_signer_cannot_overwrite_the_custody() {
    let mut world = World::new();
    world.upgrade_once();
    let before = world.snapshot();

    let mallory = world.mallory.id;
    let result = world.submit(mallory, HEIGHT + 1, upgrade_payload(mallory, Some(0)));

    world.assert_refused_without_writes("BD-63 (Some(0) by another signer)", result, &before);
    assert_eq!(
        world.upgrade_bond(),
        Some(UPGRADE),
        "BD-63: the payer's upgrade custody is intact"
    );
}

// BD-63 (funds arm): on an unoccupied upgrade key, the payer posts PAYER_START + 1.
// After the fix: REFUSED by the funds check (checked arithmetic); no state written.
// PREDICTED AT THE BD-63 RED COMMIT: PASSES (a PIN). The funds check
// (`sender_bal < amount`) already refuses before any write. It pins the funds refusal
// across the fix's rewrite of the debit to checked arithmetic.
#[test]
fn bd63_upgrade_bond_without_funds_is_refused() {
    let mut world = World::new();
    let before = world.snapshot();

    let payer = world.payer.id;
    let result = world.submit(payer, HEIGHT, upgrade_payload(payer, Some(PAYER_START + 1)));

    world.assert_refused_without_writes("BD-63 (insufficient funds)", result, &before);
    assert_eq!(world.upgrade_bond(), None, "BD-63: no upgrade custody is written");
}

// ---------------------------------------------------------------------------
// BD-57 review 1 (BD-57b): finding 1, the appeal bond's custody (R6b and R9 above,
// R12), and finding 5, one isolated, state-preserving refusal test per guard
// (R13-R22) and the credential transitions (R23, R24). Each refusal test uses
// otherwise-VALID inputs, so that only the guard it names can refuse.
// ---------------------------------------------------------------------------

/// An account (not key-derived) whose active credential is the PROVIDER's key: an
/// account the provider also controls. An account id stays fixed while its key
/// changes (crates/types/src/app/identity.rs:47), so it need not derive from the key.
const PROVIDER_ALIAS: AccountId = AccountId([0xA1; 32]);
/// The payer-side counterpart of PROVIDER_ALIAS: its active credential is the PAYER's key.
const PAYER_ALIAS: AccountId = AccountId([0xA2; 32]);

/// The identity hub's credentials key of `account`, as `register_identity` writes it:
/// the hub's namespace ‖ `IDENTITY_CREDENTIALS_PREFIX` ‖ account id. The hub reads and
/// writes this key as `[Option<Credential>; 2]` (active, staged) in
/// `IdentityHub::load_credentials` / `save_credentials`
/// (crates/services/src/identity/mod.rs:60-82); an absent key reads as `[None, None]`
/// (:67).
fn credentials_key(account: &AccountId) -> Vec<u8> {
    let ns = service_namespace_prefix("identity_hub");
    [ns.as_slice(), IDENTITY_CREDENTIALS_PREFIX, account.as_ref()].concat()
}

/// An Ed25519 credential for the key whose hash is `public_key_hash`.
fn ed25519_credential(public_key_hash: [u8; 32], activation_height: u64) -> Credential {
    Credential {
        suite: SignatureSuite::ED25519,
        public_key_hash,
        activation_height,
        l2_location: None,
        weight: 1,
    }
}

impl World {
    /// Writes `account`'s credentials `[active, staged]` directly (see `credentials_key`).
    fn set_credentials(&mut self, account: &AccountId, creds: [Option<Credential>; 2]) {
        put(
            &mut self.state,
            credentials_key(account),
            codec::to_bytes_canonical(&creds).expect("setup: encode credentials"),
        );
    }

    /// Deletes `account`'s credentials key (the hub then reads `[None, None]`).
    fn remove_credentials(&mut self, account: &AccountId) {
        self.state.data.remove(&credentials_key(account));
    }

    /// The open bond under `SESSION`, decoded as the handler's `BondRecordV1`.
    fn bond_record(&self, case: &str) -> BondRecordV1 {
        let bytes = self
            .bond()
            .unwrap_or_else(|| panic!("{case}: no open bond under the session id"));
        codec::from_bytes_canonical(&bytes)
            .unwrap_or_else(|e| panic!("{case}: the open bond must decode as BondRecordV1 ({e})"))
    }

    /// The dispute record under `SESSION`, decoded as the handler's `DisputeRecordV1`.
    fn dispute_record(&self, case: &str) -> DisputeRecordV1 {
        let bytes = self
            .dispute()
            .unwrap_or_else(|| panic!("{case}: no dispute:: record is written"));
        codec::from_bytes_canonical(&bytes).unwrap_or_else(|e| {
            panic!(
                "{case}: the dispute:: record must decode as DisputeRecordV1 {{ bond, \
                 appeal_amount, appeal_depositor }}, holding the appeal bond in custody; it \
                 holds {} bytes ({e})",
                bytes.len()
            )
        })
    }

    /// BD-57 review 1, finding 1 (CONSERVATION): the total value the settlement state
    /// holds: every balance (`balance::`), every open bond's amount (`settle::bond::`),
    /// every dispute custody (`dispute::`: the bond's amount plus the appeal amount) and
    /// every liability-upgrade bond (`liability::upgrade::`). Every accepted operation
    /// only moves value among these keys, so it must leave the total unchanged. Panics
    /// if a value does not decode, or if the total overflows u128 (so it is not called
    /// in the tests that hold balances near u128::MAX).
    fn total_value(&self) -> u128 {
        let mut total: u128 = 0;
        for (key, value) in &self.state.data {
            let held: u128 = if key.starts_with(BALANCE_PREFIX) {
                codec::from_bytes_canonical(value).unwrap_or_else(|e| {
                    panic!("conservation: balance {} does not decode ({e})", printable(key))
                })
            } else if key.starts_with(BOND_PREFIX) {
                let bond: BondRecordV1 = codec::from_bytes_canonical(value).unwrap_or_else(|e| {
                    panic!(
                        "conservation: bond {} does not decode as BondRecordV1 ({e})",
                        printable(key)
                    )
                });
                bond.amount
            } else if key.starts_with(DISPUTE_PREFIX) {
                let custody: DisputeRecordV1 =
                    codec::from_bytes_canonical(value).unwrap_or_else(|e| {
                        panic!(
                            "conservation: dispute {} does not decode as DisputeRecordV1 ({e})",
                            printable(key)
                        )
                    });
                custody
                    .bond
                    .amount
                    .checked_add(custody.appeal_amount)
                    .expect("conservation: a dispute custody overflows u128")
            } else if key.starts_with(UPGRADE_BOND_PREFIX) {
                codec::from_bytes_canonical(value).unwrap_or_else(|e| {
                    panic!(
                        "conservation: upgrade bond {} does not decode ({e})",
                        printable(key)
                    )
                })
            } else {
                0
            };
            total = total
                .checked_add(held)
                .expect("conservation: the total overflows u128");
        }
        total
    }
}

// R12 (finding 1; the provider arm of R6): the PROVIDER escalates with an appeal bond.
// After the fix: ACCEPTED; the provider is debited APPEAL; dispute:: holds
// DisputeRecordV1 { the bond record, APPEAL, appeal_depositor: the PROVIDER } (the
// custody records who paid the appeal bond, not merely the bond's payer); the payer
// is untouched beyond its bond; the total value held is unchanged.
// PREDICTED AT THE BD-57b RED COMMIT (Escalate arm as at 03c7ef148): FAILS at the
// custody decode, as R6b (dispute:: holds the bare 112-byte BondRecordV1).
#[test]
fn r12_escalate_by_the_provider_holds_its_appeal_bond_in_custody() {
    let mut world = World::new();
    let genesis_total = world.total_value();
    world.commit_bond();
    let bond_record = world.bond_record("R12 setup");

    let (payer, provider) = (world.payer.id, world.provider.id);
    let result = world.submit(provider, HEIGHT, escalate_payload(provider, APPEAL));

    assert!(
        result.is_ok(),
        "R12: an Escalate by the provider must be ACCEPTED, got {:?}",
        result
    );
    assert!(world.bond().is_none(), "R12: the bond leaves the open-bond key");
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START - APPEAL,
        "R12: the appeal bond is debited from the provider"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - BOND,
        "R12: the payer is untouched beyond its bond"
    );
    assert_eq!(
        world.dispute_record("R12"),
        DisputeRecordV1 {
            bond: bond_record,
            appeal_amount: APPEAL,
            appeal_depositor: provider,
        },
        "R12: dispute:: holds the bond record and the appeal bond, deposited by the provider"
    );
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R12: Escalate conserves the total value held"
    );
}

// R13 (finding 5; isolates the provider-id guard, which R1 cannot, since R1's
// signatures are also invalid): summary.provider_id is NOT the bond's provider, and
// BOTH signatures are VALID: the payer's and the RECORDED provider's active
// credentials, over that summary. Arm 1 names Mallory as provider. Arm 2 names
// PROVIDER_ALIAS, whose active credential is the provider's key, so the provider
// signature is valid as the STATED provider's as well.
// After the fix: each REFUSED by `summary.provider_id != bond.provider_id`; no state
// written. (The handler verifies provider_sig against bond.provider_id, so without
// the id guard both arms would be ACCEPTED, paying the recorded provider.)
// PREDICTED AT THE BD-57b RED COMMIT (Settle arm as at 03c7ef148): PASSES (a PIN).
#[test]
fn r13_settle_naming_another_provider_with_valid_party_signatures_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider, mallory) = (world.payer.id, world.provider.id, world.mallory.id);

    let close = world.doubly_signed_close(summary(payer, mallory, FINAL, 0), CHAIN, EXPIRES);
    let before = world.snapshot();
    let result = world.submit(mallory, HEIGHT, close);
    world.assert_refused_without_writes(
        "R13 arm 1 (the summary names Mallory as provider)",
        result,
        &before,
    );

    let provider_key_hash = provider.0;
    world.set_credentials(
        &PROVIDER_ALIAS,
        [Some(ed25519_credential(provider_key_hash, 0)), None],
    );
    let close = world.doubly_signed_close(
        summary(payer, PROVIDER_ALIAS, FINAL, 0),
        CHAIN,
        EXPIRES,
    );
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);
    world.assert_refused_without_writes(
        "R13 arm 2 (the summary names an alias holding the provider's key)",
        result,
        &before,
    );
}

// R14 (finding 5; isolates the payer-id guard, which R3 cannot, since R3's payer
// signature is by the substituted payer's key and the recorded payer's credential
// check also refuses it): summary.payer_id is NOT the bond's payer, and BOTH
// signatures are VALID: payer_sig by the RECORDED payer's active credential and
// provider_sig by the provider's, over that summary. Arm 1 names Mallory as payer.
// Arm 2 names PAYER_ALIAS, whose active credential is the payer's key.
// After the fix: each REFUSED by `summary.payer_id != bond.payer`; no state written.
// (payer_sig is verified against bond.payer, so without the id guard both arms would
// be ACCEPTED.)
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN).
#[test]
fn r14_settle_naming_another_payer_with_valid_party_signatures_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider, mallory) = (world.payer.id, world.provider.id, world.mallory.id);

    let close = world.doubly_signed_close(summary(mallory, provider, FINAL, 0), CHAIN, EXPIRES);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);
    world.assert_refused_without_writes(
        "R14 arm 1 (the summary names Mallory as payer)",
        result,
        &before,
    );

    let payer_key_hash = payer.0;
    world.set_credentials(&PAYER_ALIAS, [Some(ed25519_credential(payer_key_hash, 0)), None]);
    let close = world.doubly_signed_close(
        summary(PAYER_ALIAS, provider, FINAL, 0),
        CHAIN,
        EXPIRES,
    );
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);
    world.assert_refused_without_writes(
        "R14 arm 2 (the summary names an alias holding the payer's key)",
        result,
        &before,
    );
}

// R15 (finding 5; the open-bond collision): after the payer's Commit, arm 1: Mallory
// (funded) Commits the same session id, backing herself; arm 2: the payer Commits it
// again. No dispute and no tombstone exist, and both signers can pay the bond, so only
// the open-bond guard can refuse.
// After the fix: each REFUSED; no state written (the payer's bond record is intact).
// PREDICTED AT THE BD-57b RED COMMIT (Commit arm as at 03c7ef148): PASSES (a PIN).
#[test]
fn r15_commit_onto_an_open_bond_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider, mallory) = (world.payer.id, world.provider.id, world.mallory.id);
    let before = world.snapshot();

    let result = world.submit(mallory, HEIGHT, commit_payload(mallory));
    world.assert_refused_without_writes("R15 arm 1 (Mallory re-bonds the session)", result, &before);

    let result = world.submit(payer, HEIGHT, commit_payload(provider));
    world.assert_refused_without_writes("R15 arm 2 (the payer re-bonds the session)", result, &before);
}

// R16 (finding 5; Commit funds): the payer Commits PAYER_START + 1 on an unused
// session id (no bond, no dispute, no tombstone), so only the funds check can refuse.
// After the fix: REFUSED; no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN).
#[test]
fn r16_commit_without_funds_is_refused() {
    let mut world = World::new();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let before = world.snapshot();

    let result = world.submit(
        payer,
        HEIGHT,
        SettlementPayload::Commit {
            session_id: SESSION,
            provider_id: provider,
            bond_amount: PAYER_START + 1,
            policy_hash: [0x9A; 32],
            receipt_root: [0u8; 32],
        },
    );

    world.assert_refused_without_writes("R16", result, &before);
}

// R17 (finding 5; payment above the bond): a cooperative close for BOND + 1, signed by
// both parties' active credentials, on this chain, unexpired.
// After the fix: REFUSED (`final_amount > bond.amount`); no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN).
#[test]
fn r17_settle_above_the_bond_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);

    let close = world.doubly_signed_close(summary(payer, provider, BOND + 1, 0), CHAIN, EXPIRES);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);

    world.assert_refused_without_writes("R17", result, &before);
}

// R18 (finding 5; provider credit overflow): the provider holds
// u128::MAX - (FINAL - 1) (written directly), and a valid cooperative close pays it
// FINAL.
// After the fix: REFUSED (the provider credit would overflow); no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN: the checked provider credit).
#[test]
fn r18_settle_whose_provider_credit_overflows_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    world.put_balance(&provider, u128::MAX - (FINAL - 1));

    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);

    world.assert_refused_without_writes("R18", result, &before);
}

// R19 (finding 5; payer refund overflow): after the Commit the payer holds
// u128::MAX - (BOND - FINAL - 1) (written directly), and a valid cooperative close
// refunds it BOND - FINAL.
// After the fix: REFUSED (the payer credit would overflow); no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN: the checked payer credit).
#[test]
fn r19_settle_whose_payer_refund_overflows_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    world.put_balance(&payer, u128::MAX - (BOND - FINAL - 1));

    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close);

    world.assert_refused_without_writes("R19", result, &before);
}

// R20 (finding 5; Escalate with no open bond and no dispute): arm 1: the payer
// escalates a session id that was never bonded; arm 2: after an accepted cooperative
// close (the bond deleted, the tombstone written), the payer escalates it.
// After the fix: each REFUSED; no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN).
#[test]
fn r20_escalate_without_an_open_bond_is_refused() {
    let mut world = World::new();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let before = world.snapshot();
    let result = world.submit(payer, HEIGHT, escalate_payload(payer, APPEAL));
    world.assert_refused_without_writes("R20 arm 1 (never bonded)", result, &before);

    world.commit_bond();
    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);
    world
        .submit(provider, HEIGHT, close)
        .expect("R20 setup: the cooperative close is accepted");
    let before = world.snapshot();
    let result = world.submit(payer, HEIGHT + 1, escalate_payload(payer, APPEAL));
    world.assert_refused_without_writes("R20 arm 2 (already settled)", result, &before);
}

// R21 (finding 5; appeal funds): with the bond open, arm 1: the provider (holding
// PROVIDER_START) escalates with an appeal bond of PROVIDER_START + 1; arm 2: the payer
// (holding PAYER_START - BOND) escalates with PAYER_START - BOND + 1. Each signer is a
// party, the bond is open and no dispute exists, so only the funds check can refuse.
// After the fix: each REFUSED; no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN).
#[test]
fn r21_escalate_without_appeal_funds_is_refused() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let before = world.snapshot();

    let result = world.submit(
        provider,
        HEIGHT,
        escalate_payload(provider, PROVIDER_START + 1),
    );
    world.assert_refused_without_writes("R21 arm 1 (the provider)", result, &before);

    let result = world.submit(
        payer,
        HEIGHT,
        escalate_payload(payer, PAYER_START - BOND + 1),
    );
    world.assert_refused_without_writes("R21 arm 2 (the payer)", result, &before);
}

// R22 (finding 5; the dispute guard ITSELF, which R9 arm 3 cannot isolate because the
// open bond is already gone there): after the payer's Escalate, the open bond record
// is written back under the bond key (directly: no handler produces an open bond beside
// a dispute), so the open-bond check passes. The provider, a party with funds, then
// escalates again.
// After the fix: REFUSED by the dispute guard; no state written.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN). This test never decodes dispute::.
#[test]
fn r22_second_escalate_is_refused_by_the_dispute_guard() {
    let mut world = World::new();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let open_bond = world.bond().expect("R22 setup: the bond is open");
    world
        .submit(payer, HEIGHT, escalate_payload(payer, APPEAL))
        .expect("R22 setup: the payer's Escalate is accepted");
    assert!(
        world.dispute().is_some() && world.bond().is_none(),
        "R22 setup: the session is under dispute and its bond key is empty"
    );
    put(&mut world.state, bond_key(), open_bond);
    let before = world.snapshot();

    let result = world.submit(provider, HEIGHT + 1, escalate_payload(provider, APPEAL));

    world.assert_refused_without_writes("R22", result, &before);
}

// R23 (finding 5; rotation cutover): the payer's key is rotated to NEXT (seed 0x44),
// and a summary is signed by the payer's OLD key (the provider's signature is valid).
//   Arm 1: the staged credential is in force but not yet promoted: credentials
//     [Some(old, 0), Some(NEXT, activation HEIGHT)], as IdentityHub::rotate writes them
//     (crates/services/src/identity/mod.rs:289-302) at HEIGHT - grace, read at HEIGHT.
//   Arm 2: the staged credential is promoted: [Some(NEXT, HEIGHT), None], as
//     IdentityHub::on_end_block writes it (:493-494).
//   Control: in arm 2's state, the same summary with payer_sig by NEXT is ACCEPTED, so
//     only the credential state refuses the old key.
// After the fix: arms 1 and 2 REFUSED with no state written; the control pays as R4
// and conserves the total value held.
// PREDICTED AT THE BD-57b RED COMMIT (the credential path as at 03c7ef148): PASSES
// (a PIN). Arm 1: enforce_credential_policy returns ExpiredKey; arm 2:
// UnauthorizedByCredentials.
#[test]
fn r23_after_rotation_a_summary_signed_by_the_old_payer_key_is_refused() {
    let mut world = World::new();
    let genesis_total = world.total_value();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let next = Party::from_seed(0x44);

    let terms = summary(payer, provider, FINAL, 0);
    let old_key_close = world.doubly_signed_close(terms.clone(), CHAIN, EXPIRES);
    let next_key_close = settle_payload(
        terms.clone(),
        EXPIRES,
        next.sign_summary(CHAIN, &terms, EXPIRES),
        world.provider.sign_summary(CHAIN, &terms, EXPIRES),
    );

    world.set_credentials(
        &payer,
        [
            Some(ed25519_credential(payer.0, 0)),
            Some(ed25519_credential(next.id.0, HEIGHT)),
        ],
    );
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, old_key_close.clone());
    world.assert_refused_without_writes(
        "R23 arm 1 (old key; the staged key is in force)",
        result,
        &before,
    );

    world.set_credentials(&payer, [Some(ed25519_credential(next.id.0, HEIGHT)), None]);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, old_key_close);
    world.assert_refused_without_writes(
        "R23 arm 2 (old key; the new key is promoted)",
        result,
        &before,
    );

    let result = world.submit(provider, HEIGHT, next_key_close);
    assert!(
        result.is_ok(),
        "R23 control: the same summary signed by the payer's NEW key must be ACCEPTED, got {:?}",
        result
    );
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START + FINAL,
        "R23 control: the provider is paid final_amount"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - FINAL,
        "R23 control: the payer is refunded bond - final_amount"
    );
    assert!(world.bond().is_none(), "R23 control: the bond key is deleted");
    assert!(
        world.tombstone().is_some(),
        "R23 control: the settled tombstone is written"
    );
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R23 control: Commit and Settle conserve the total value held"
    );
}

// R24 (finding 5; no active credential): a summary validly signed by the payer's key
// and the provider's, while the payer has NO active credential.
//   Arm 1: the payer's credentials key is absent (the hub reads [None, None]).
//   Arm 2: the payer's credentials are an explicit [None, None].
//   Control: the payer's genesis credential restored, the same payload is ACCEPTED.
// After the fix: arms 1 and 2 REFUSED with no state written (no bootstrap fallback:
// fail-closed); the control pays as R4 and conserves the total value held.
// PREDICTED AT THE BD-57b RED COMMIT: PASSES (a PIN): enforce_credential_policy
// returns UnauthorizedByCredentials when there is no active credential.
#[test]
fn r24_a_payer_without_an_active_credential_cannot_authorize_a_settlement() {
    let mut world = World::new();
    let genesis_total = world.total_value();
    world.commit_bond();
    let (payer, provider) = (world.payer.id, world.provider.id);
    let close = world.doubly_signed_close(summary(payer, provider, FINAL, 0), CHAIN, EXPIRES);

    world.remove_credentials(&payer);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close.clone());
    world.assert_refused_without_writes("R24 arm 1 (no credentials key)", result, &before);

    world.set_credentials(&payer, [None, None]);
    let before = world.snapshot();
    let result = world.submit(provider, HEIGHT, close.clone());
    world.assert_refused_without_writes("R24 arm 2 ([None, None])", result, &before);

    world.set_credentials(&payer, [Some(ed25519_credential(payer.0, 0)), None]);
    let result = world.submit(provider, HEIGHT, close);
    assert!(
        result.is_ok(),
        "R24 control: with the payer's credential restored the close must be ACCEPTED, got {:?}",
        result
    );
    assert_eq!(
        world.balance(&provider),
        PROVIDER_START + FINAL,
        "R24 control: the provider is paid final_amount"
    );
    assert_eq!(
        world.balance(&payer),
        PAYER_START - FINAL,
        "R24 control: the payer is refunded bond - final_amount"
    );
    assert_eq!(
        world.total_value(),
        genesis_total,
        "R24 control: Commit and Settle conserve the total value held"
    );
}
