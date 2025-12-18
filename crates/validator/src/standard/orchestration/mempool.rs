// Path: crates/validator/src/standard/orchestration/mempool.rs

use ahash::RandomState;
use ioi_types::app::{AccountId, ChainTransaction, TxHash};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

const SHARD_COUNT: usize = 64;

/// Represents the status of a transaction after attempting to add it to the pool.
#[derive(Debug, PartialEq, Eq)]
pub enum AddResult {
    /// Added to the Ready queue (executable immediately).
    Ready,
    /// Added to the Future queue (waiting for a nonce gap to be filled).
    Future,
    /// Rejected (nonce too low, duplicate, or other error).
    Rejected(String),
}

/// A structure to manage transactions for a single account, enforcing strict nonce ordering.
#[derive(Debug, Default)]
struct AccountQueue {
    pending_nonce: u64,
    ready: BTreeMap<u64, (ChainTransaction, TxHash)>,
    future: BTreeMap<u64, (ChainTransaction, TxHash)>,
}

impl AccountQueue {
    fn new(committed_nonce: u64) -> Self {
        Self {
            pending_nonce: committed_nonce,
            ready: BTreeMap::new(),
            future: BTreeMap::new(),
        }
    }

    fn update_base_nonce(&mut self, committed_nonce: u64) -> usize {
        if committed_nonce > self.pending_nonce {
            self.prune_committed(committed_nonce)
        } else {
            0
        }
    }

    fn prune_committed(&mut self, new_committed_nonce: u64) -> usize {
        let mut removed = 0;
        self.pending_nonce = std::cmp::max(self.pending_nonce, new_committed_nonce);

        let stale_ready: Vec<u64> = self
            .ready
            .range(..self.pending_nonce)
            .map(|(&n, _)| n)
            .collect();
        for n in stale_ready {
            self.ready.remove(&n);
            removed += 1;
        }

        let stale_future: Vec<u64> = self
            .future
            .range(..self.pending_nonce)
            .map(|(&n, _)| n)
            .collect();
        for n in stale_future {
            self.future.remove(&n);
            removed += 1;
        }

        self.try_promote();
        removed
    }

    fn try_promote(&mut self) {
        loop {
            let next_needed = self.pending_nonce + self.ready.len() as u64;
            if let Some(entry) = self.future.remove(&next_needed) {
                self.ready.insert(next_needed, entry);
            } else {
                break;
            }
        }
    }

    fn repair_hole(&mut self, hole_nonce: u64) {
        let to_demote: Vec<u64> = self
            .ready
            .range((hole_nonce + 1)..)
            .map(|(&n, _)| n)
            .collect();
        for nonce in to_demote {
            if let Some(entry) = self.ready.remove(&nonce) {
                self.future.insert(nonce, entry);
            }
        }
    }

    fn add(&mut self, tx: ChainTransaction, hash: TxHash, nonce: u64) -> AddResult {
        if nonce < self.pending_nonce {
            return AddResult::Rejected(format!(
                "Nonce {} too low (expected >= {})",
                nonce, self.pending_nonce
            ));
        }

        if self.ready.contains_key(&nonce) {
            return AddResult::Ready;
        }
        if self.future.contains_key(&nonce) {
            return AddResult::Future;
        }

        let next_needed = self.pending_nonce + self.ready.len() as u64;
        if nonce == next_needed {
            self.ready.insert(nonce, (tx, hash));
            self.try_promote();
            AddResult::Ready
        } else {
            self.future.insert(nonce, (tx, hash));
            AddResult::Future
        }
    }
}

/// A high-performance, sharded mempool.
///
/// This mempool is designed for high-concurrency environments by sharding account queues
/// across multiple locks, minimizing contention between the RPC ingestion worker and the
/// consensus block production task.
#[derive(Debug)]
pub struct Mempool {
    shards: Vec<Mutex<HashMap<AccountId, AccountQueue>>>,
    hasher: RandomState,
    others: Mutex<VecDeque<(ChainTransaction, TxHash)>>,
    total_count: AtomicUsize,
}

impl Mempool {
    /// Creates a new, empty mempool with a fixed number of internal shards.
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards,
            hasher: RandomState::new(),
            others: Mutex::new(VecDeque::new()),
            total_count: AtomicUsize::new(0),
        }
    }

    fn get_shard_index(&self, account: &AccountId) -> usize {
        let mut h = self.hasher.build_hasher();
        account.hash(&mut h);
        (h.finish() as usize) % SHARD_COUNT
    }

    /// Returns the total number of transactions in the pool (ready, future, and other).
    pub fn len(&self) -> usize {
        self.total_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the mempool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checks if the mempool is already tracking any transactions for a specific account.
    pub fn contains_account(&self, account_id: &AccountId) -> bool {
        let idx = self.get_shard_index(account_id);
        self.shards[idx].lock().contains_key(account_id)
    }

    /// Adds a transaction to the pool, routing it to the appropriate queue based on its type and nonce.
    ///
    /// # Arguments
    /// * `tx` - The transaction object.
    /// * `hash` - The pre-computed canonical hash of the transaction.
    /// * `account_info` - An `Option` containing the signer's `AccountId` and `nonce` if applicable.
    /// * `committed_nonce_state` - The last known committed nonce for the account from the blockchain state.
    pub fn add(
        &self,
        tx: ChainTransaction,
        hash: TxHash,
        account_info: Option<(AccountId, u64)>,
        committed_nonce_state: u64,
    ) -> AddResult {
        if let Some((account_id, tx_nonce)) = account_info {
            let idx = self.get_shard_index(&account_id);
            let mut guard = self.shards[idx].lock();

            let queue = guard
                .entry(account_id)
                .or_insert_with(|| AccountQueue::new(committed_nonce_state));

            let removed = queue.update_base_nonce(committed_nonce_state);
            self.total_count.fetch_sub(removed, Ordering::Relaxed);

            let res = queue.add(tx, hash, tx_nonce);
            if matches!(res, AddResult::Ready | AddResult::Future) {
                self.total_count.fetch_add(1, Ordering::Relaxed);
            }
            res
        } else {
            self.others.lock().push_back((tx, hash));
            self.total_count.fetch_add(1, Ordering::Relaxed);
            AddResult::Ready
        }
    }

    /// Updates an account's base nonce after a block commit, pruning processed transactions.
    pub fn update_account_nonce(&self, account_id: &AccountId, new_committed_nonce: u64) {
        let idx = self.get_shard_index(account_id);
        let mut guard = self.shards[idx].lock();
        if let Some(queue) = guard.get_mut(account_id) {
            let removed = queue.prune_committed(new_committed_nonce);
            self.total_count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    /// Removes a specific transaction from any queue by its hash. Used for cleanup.
    pub fn remove_by_hash(&self, hash: &TxHash) {
        if let Some(pos) = self.others.lock().iter().position(|(_, h)| h == hash) {
            self.others.lock().remove(pos);
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        for shard in &self.shards {
            let mut guard = shard.lock();
            for queue in guard.values_mut() {
                if let Some(n) = queue
                    .ready
                    .iter()
                    .find(|(_, (_, h))| h == hash)
                    .map(|(&n, _)| n)
                {
                    queue.ready.remove(&n);
                    self.total_count.fetch_sub(1, Ordering::Relaxed);
                    queue.repair_hole(n);
                    return;
                }
                if let Some(n) = queue
                    .future
                    .iter()
                    .find(|(_, (_, h))| h == hash)
                    .map(|(&n, _)| n)
                {
                    queue.future.remove(&n);
                    self.total_count.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    /// Selects a batch of valid transactions for inclusion in a new block.
    pub fn select_transactions(&self, total_limit: usize) -> Vec<ChainTransaction> {
        let mut selected = Vec::with_capacity(total_limit);

        {
            let guard = self.others.lock();
            for (tx, _) in guard.iter().take(total_limit) {
                selected.push(tx.clone());
            }
        }

        if selected.len() >= total_limit {
            return selected;
        }

        'outer: for shard in &self.shards {
            let guard = shard.lock();
            for queue in guard.values() {
                for (tx, _) in queue.ready.values() {
                    if selected.len() >= total_limit {
                        break 'outer;
                    }
                    selected.push(tx.clone());
                }
            }
        }
        selected
    }
}
