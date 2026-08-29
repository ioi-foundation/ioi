use super::*;
use crate::primitives::hash::HashCommitmentScheme;
use ioi_api::app::{Block, ChainTransaction};
use ioi_api::storage::{
    CommitInput, Epoch, Height, NodeHash as StoreNodeHash, PruneStats, RootHash as StoreRootHash,
    StorageError,
};
use std::future::Future;
use std::sync::Mutex;
use std::task::{Context, Poll, Wake, Waker};

#[test]
fn test_iavl_commit_with_witness_and_create_proof() {
    // 1. SETUP
    // The IAVLTree uses a HashCommitmentScheme, which has a stateless witness `()`.
    let scheme = HashCommitmentScheme::new();
    let mut tree = IAVLTree::new(scheme);

    // 2. ACT: Insert data and commit a version to finalize the state.
    tree.insert(b"key1", b"value1").unwrap();
    tree.insert(b"key3", b"value3").unwrap();
    tree.commit_version(1).unwrap();

    let root_commitment = tree.root_commitment();
    let anchor = ioi_types::app::StateRoot(root_commitment.as_ref().to_vec())
        .to_anchor()
        .unwrap();
    assert_eq!(
        tree.commitment_from_anchor(&anchor.0)
            .expect("retained IAVL anchor must resolve")
            .as_ref(),
        root_commitment.as_ref(),
        "StateRoot::to_anchor is a hash identity, not the raw 32-byte IAVL root"
    );

    // 3. ASSERT EXISTENCE PROOF
    // The `create_proof` method should now correctly use the new trait signature.
    // For HashCommitmentScheme, the witness is just `()`.
    let proof_for_key1 = tree
        .create_proof(b"key1")
        .expect("Proof should be generated");

    // Verify the proof against the root commitment.
    let verification_result =
        tree.verify_proof(&root_commitment, &proof_for_key1, b"key1", b"value1");
    assert!(
        verification_result.is_ok(),
        "Existence proof for key1 should be valid"
    );

    // 4. ASSERT NON-EXISTENCE PROOF
    // Create a proof for a key that does not exist but is between two existing keys.
    let proof_for_key2 = tree
        .create_proof(b"key2")
        .expect("Non-existence proof should be generated");

    // Verify that the proof correctly proves the absence of "key2".
    // The `verify_iavl_proof` helper takes an `Option<&[u8]>` for the value.
    // `None` signifies a non-existence check.
    let proof_bytes = proof_for_key2.as_ref();
    let iavl_proof = IavlProof::decode(&mut &*proof_bytes).unwrap();
    let root_hash: [u8; 32] = root_commitment.as_ref().try_into().unwrap();
    let non_existence_result =
        proof::verify_iavl_proof(&root_hash, b"key2", None, &iavl_proof).unwrap();
    assert!(
        non_existence_result,
        "Non-existence proof for key2 should be valid"
    );
}

/// Epoch width for the test store. Every height used here lands in epoch 0.
const TEST_EPOCH_SIZE: u64 = 1000;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

/// Drives a future to completion without pulling in an async runtime.
///
/// Every future polled here is backed by `CombinedOnlyStore`, which never yields,
/// so a `Pending` poll means the commit path started awaiting something this test
/// cannot observe and the test must fail rather than hang.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("commit path awaited a source the test store does not drive"),
    }
}

#[derive(Default)]
struct Recorded {
    combined_calls: usize,
    commit_block_calls: usize,
    put_block_calls: usize,
    nodes: HashMap<[u8; 32], Vec<u8>>,
    roots_by_height: HashMap<u64, RootHash>,
    blocks_by_height: HashMap<u64, Vec<u8>>,
    head: Option<Height>,
}

/// A `NodeStore` that only honours the combined state+block commit.
///
/// `commit_block` and `put_block` are exactly the two-operation fallback that the
/// default `commit_version_persist_with_block` performs. Both count their calls and
/// then refuse, so a regression to the fallback fails the commit outright instead of
/// quietly producing the same end state.
struct CombinedOnlyStore {
    inner: Mutex<Recorded>,
    /// When set, the combined operation is counted and then fails, standing in for a
    /// backend that never reached durability.
    fail_combined: bool,
}

impl CombinedOnlyStore {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Recorded::default()),
            fail_combined: false,
        }
    }

    fn failing() -> Self {
        Self {
            inner: Mutex::new(Recorded::default()),
            fail_combined: true,
        }
    }

    fn combined_calls(&self) -> usize {
        self.inner.lock().unwrap().combined_calls
    }

    fn commit_block_calls(&self) -> usize {
        self.inner.lock().unwrap().commit_block_calls
    }

    fn put_block_calls(&self) -> usize {
        self.inner.lock().unwrap().put_block_calls
    }

    /// The exact payload bytes durably recorded for `height`, as `get_block_by_height`
    /// would read them.
    fn recorded_block_payload(&self, height: u64) -> Option<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        inner.blocks_by_height.get(&height).cloned()
    }
}

/// Commits `tree` through the trait method under repair.
fn commit_with_block(
    tree: &mut IAVLTree<HashCommitmentScheme>,
    store: &CombinedOnlyStore,
    height: u64,
    block_bytes: &[u8],
) -> Result<RootHash, StateError> {
    block_on(tree.commit_version_persist_with_block(height, store, block_bytes))
}

#[async_trait]
impl NodeStore for CombinedOnlyStore {
    fn epoch_size(&self) -> u64 {
        TEST_EPOCH_SIZE
    }

    fn epoch_of(&self, height: u64) -> u64 {
        height / TEST_EPOCH_SIZE
    }

    fn get_node(&self, _epoch: u64, node: StoreNodeHash) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.inner.lock().unwrap().nodes.get(&node.0).cloned())
    }

    fn head(&self) -> Result<(Height, Epoch), StorageError> {
        match self.inner.lock().unwrap().head {
            Some(height) => Ok((height, height / TEST_EPOCH_SIZE)),
            None => Err(StorageError::NotFound),
        }
    }

    fn height_for_root(&self, root: StoreRootHash) -> Result<Option<Height>, StorageError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .roots_by_height
            .iter()
            .find(|(_, recorded)| **recorded == root.0)
            .map(|(height, _)| *height))
    }

    fn root_for_height(&self, height: Height) -> Result<Option<StoreRootHash>, StorageError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .roots_by_height
            .get(&height)
            .map(|root| StoreRootHash(*root)))
    }

    fn seal_epoch(&self, _epoch: Epoch) -> Result<(), StorageError> {
        Ok(())
    }

    fn is_sealed(&self, _epoch: Epoch) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn commit_block(&self, _input: CommitInput) -> Result<(), StorageError> {
        self.inner.lock().unwrap().commit_block_calls += 1;
        Err(StorageError::Backend(
            "state-only commit_block is not part of the combined commit path".into(),
        ))
    }

    async fn commit_block_with_payload(
        &self,
        input: CommitInput,
        block_bytes: &[u8],
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().unwrap();
        inner.combined_calls += 1;
        if self.fail_combined {
            return Err(StorageError::Backend(
                "combined commit never reached durability".into(),
            ));
        }
        for (hash, bytes) in &input.new_nodes {
            inner.nodes.insert(hash.0, bytes.clone());
        }
        inner.roots_by_height.insert(input.height, input.root.0);
        inner
            .blocks_by_height
            .insert(input.height, block_bytes.to_vec());
        inner.head = Some(input.height);
        Ok(())
    }

    fn prune_batch(
        &self,
        _cutoff_height: Height,
        _excluded_heights: &[Height],
        _limit: usize,
    ) -> Result<PruneStats, StorageError> {
        Ok(PruneStats::default())
    }

    fn drop_sealed_epoch(&self, _epoch: Epoch) -> Result<(), StorageError> {
        Ok(())
    }

    async fn put_block(&self, _height: u64, _block_bytes: &[u8]) -> Result<(), StorageError> {
        self.inner.lock().unwrap().put_block_calls += 1;
        Err(StorageError::Backend(
            "standalone put_block is not part of the combined commit path".into(),
        ))
    }

    fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>, StorageError> {
        match self.recorded_block_payload(height) {
            Some(bytes) => ioi_types::codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(StorageError::Decode),
            None => Ok(None),
        }
    }

    fn get_blocks_range(
        &self,
        start: u64,
        limit: u32,
        _max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>, StorageError> {
        let mut blocks = Vec::new();
        for height in start..start.saturating_add(u64::from(limit)) {
            match self.get_block_by_height(height)? {
                Some(block) => blocks.push(block),
                None => break,
            }
        }
        Ok(blocks)
    }
}

#[test]
fn iavl_commit_with_block_uses_one_combined_store_operation() {
    let store = Arc::new(CombinedOnlyStore::new());
    let mut tree = IAVLTree::new(HashCommitmentScheme::new());
    tree.attach_store(store.clone());

    tree.insert(b"key1", b"value1").unwrap();
    tree.insert(b"key3", b"value3").unwrap();

    let block_bytes = b"m048-block-payload-at-height-7".to_vec();
    let root = commit_with_block(&mut tree, &store, 7, &block_bytes)
        .expect("combined commit should succeed");

    // The combined operation is the only durable write the commit path performs.
    assert_eq!(
        store.combined_calls(),
        1,
        "commit_block_with_payload must be invoked exactly once"
    );
    assert_eq!(
        store.commit_block_calls(),
        0,
        "the state-only commit_block leg of the fallback must not be used"
    );
    assert_eq!(
        store.put_block_calls(),
        0,
        "the standalone put_block leg of the fallback must not be used"
    );

    // The block payload is durably recorded against its height, byte for byte.
    assert_eq!(
        store.recorded_block_payload(7).as_deref(),
        Some(block_bytes.as_slice()),
        "the combined operation must carry the exact block payload"
    );

    // The state version and root are recorded by that same operation.
    assert_eq!(
        store.root_for_height(7).unwrap(),
        Some(StoreRootHash(root)),
        "the combined operation must record the state root for the height"
    );
    assert_eq!(store.height_for_root(StoreRootHash(root)).unwrap(), Some(7));

    let commitment = tree.root_commitment();
    assert_eq!(commitment.as_ref(), root.as_slice());
    assert!(
        tree.version_exists_for_root(&commitment),
        "the committed root must map to a queryable version"
    );

    // Caches are dropped only after durable success, so these reads can only be
    // served by nodes the combined operation carried into the store.
    assert!(tree.node_cache.is_empty() && tree.kv_cache.is_empty());
    assert_eq!(tree.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(tree.get(b"key3").unwrap(), Some(b"value3".to_vec()));
}

#[test]
fn iavl_commit_with_block_does_not_advance_commit_state_before_durability() {
    let store = Arc::new(CombinedOnlyStore::failing());
    let mut tree = IAVLTree::new(HashCommitmentScheme::new());
    tree.attach_store(store.clone());

    tree.insert(b"key1", b"value1").unwrap();
    let pending_root = tree.root_hash.expect("insert must produce a root");

    let error = commit_with_block(&mut tree, &store, 7, b"payload")
        .expect_err("a store that never reached durability must fail the commit");
    assert!(matches!(error, StateError::Backend(_)), "{error:?}");

    assert_eq!(store.combined_calls(), 1);
    assert_eq!(
        store.commit_block_calls() + store.put_block_calls(),
        0,
        "a failed combined operation must not fall back to the two-operation sequence"
    );

    // Commit indices never advanced past the failed durable write.
    assert!(tree.indices.versions_by_height.is_empty());
    assert!(tree.indices.roots.is_empty());
    assert!(!tree.version_exists_for_root(&tree.root_commitment()));

    // The pending version is still fully in memory, so a retry has everything it needs.
    assert!(tree.node_cache.contains_key(&pending_root));
    assert_eq!(tree.get(b"key1").unwrap(), Some(b"value1".to_vec()));
}

#[test]
fn iavl_bench_sample_renders_the_exact_field_contract() {
    let sample = CombinedCommitSample {
        height: 7,
        block_bytes: 512,
        commitment: Duration::from_micros(1_250),
        durable_store: Duration::from_micros(43_500),
        tree_depth: Some(3),
        unique_nodes: 9,
        new_nodes: 4,
        new_node_bytes: 640,
    };

    assert_eq!(
        sample.render(2),
        "[BENCH-IAVL] height=7 version_count=2 tree_depth=3 unique_nodes=9 new_nodes=4 \
         new_node_bytes=640 block_bytes=512 commitment_ms=1.250 durable_store_ms=43.500 \
         atomic_state_block=true"
    );
}

#[test]
fn iavl_bench_sample_reports_unavailable_depth_rather_than_guessing() {
    let sample = CombinedCommitSample::new(1, 0);

    assert_eq!(sample.tree_depth, None);
    assert!(sample.render(0).contains(" tree_depth=unavailable "));
}

#[test]
fn iavl_bench_sample_captures_the_staged_delta_and_depth() {
    let mut tree = IAVLTree::new(HashCommitmentScheme::new());
    tree.insert(b"key1", b"value1").unwrap();
    tree.insert(b"key3", b"value3").unwrap();

    let (root, stats) = tree.stage_height_delta(9).unwrap();
    let mut sample = CombinedCommitSample::new(9, 128);
    tree.record_commitment_sample(&mut sample, root, stats);

    // Two leaves plus the inner node that joins them.
    assert_eq!(sample.new_nodes, 3);
    assert_eq!(sample.unique_nodes, 3);
    assert_eq!(sample.tree_depth, Some(1));
    assert_eq!(sample.block_bytes, 128);

    let mut expected_bytes = 0usize;
    for node in tree.node_cache.values() {
        let bytes = super::super::encode::encode_node_canonical(node).unwrap();
        expected_bytes += bytes.len();
    }
    assert_eq!(sample.new_node_bytes, expected_bytes);
    assert!(
        sample.new_node_bytes > 3 * 32,
        "new_node_bytes must be canonical node bytes, not node hashes"
    );
}

#[test]
fn iavl_bench_tree_depth_uses_the_avl_height_convention() {
    let mut tree = IAVLTree::new(HashCommitmentScheme::new());
    assert_eq!(tree.traced_tree_depth(EMPTY_HASH), Some(-1));

    tree.insert(b"key1", b"value1").unwrap();
    let leaf_root = tree.root_hash.expect("insert must produce a root");
    assert_eq!(tree.traced_tree_depth(leaf_root), Some(0));

    tree.insert(b"key3", b"value3").unwrap();
    let inner_root = tree.root_hash.expect("insert must produce a root");
    assert_eq!(tree.traced_tree_depth(inner_root), Some(1));

    // A root no cache and no store can serve is unavailable, never a substituted value.
    assert_eq!(tree.traced_tree_depth([9u8; 32]), None);
}

#[test]
fn iavl_bench_version_count_tracks_the_retained_version_index() {
    let store = Arc::new(CombinedOnlyStore::new());
    let mut tree = IAVLTree::new(HashCommitmentScheme::new());
    tree.attach_store(store.clone());

    tree.insert(b"key1", b"value1").unwrap();
    commit_with_block(&mut tree, &store, 7, b"block-7").unwrap();
    assert_eq!(tree.indices.versions_by_height.len(), 1);

    tree.insert(b"key3", b"value3").unwrap();
    commit_with_block(&mut tree, &store, 8, b"block-8").unwrap();
    assert_eq!(tree.indices.versions_by_height.len(), 2);

    // The count is the retained height->root index, so pruning moves it back down.
    let plan = PrunePlan {
        cutoff_height: 8,
        ..PrunePlan::default()
    };
    tree.prune(&plan).unwrap();
    assert_eq!(tree.indices.versions_by_height.len(), 1);
}
