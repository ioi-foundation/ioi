// Path: crates/validator/src/standard/orchestration/mempool.rs
use ahash::RandomState;
use ioi_types::app::{AccountId, ChainTransaction, TxHash};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

const SHARD_COUNT: usize = 64;

/// Represents the status of a transaction after attempting to add it to the pool.
#[derive(Debug)]
pub enum AddResult {
    /// Added to the Ready queue (executable immediately).
    Ready,
    /// Added to the Future queue (waiting for nonce gap).
    Future,
    /// Rejected (nonce too low, duplicate, or other error).
    Rejected(String),
}

/// A structure to manage transactions for a single account, enforcing nonce ordering.
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

    fn prune_committed(&mut self, new_committed_nonce: u64) -> usize {
        let mut removed = 0;
        self.pending_nonce = std::cmp::max(self.pending_nonce, new_committed_nonce);

        let stale_ready: Vec<u64> = self
            .ready
            .range(..new_committed_nonce)
            .map(|(n, _)| *n)
            .collect();
        for nonce in stale_ready {
            self.ready.remove(&nonce);
            removed += 1;
        }

        let stale_future: Vec<u64> = self
            .future
            .range(..new_committed_nonce)
            .map(|(n, _)| *n)
            .collect();
        for nonce in stale_future {
            self.future.remove(&nonce);
            removed += 1;
        }
        self.try_promote();
        removed
    }

    fn try_promote(&mut self) {
        while let Some(&next_future_nonce) = self.future.keys().next() {
            let tail_nonce = self
                .ready
                .keys()
                .last()
                .copied()
                .unwrap_or(self.pending_nonce.saturating_sub(1));
            let expected = if self.ready.is_empty() {
                self.pending_nonce
            } else {
                tail_nonce + 1
            };

            if next_future_nonce == expected {
                let entry = self.future.remove(&next_future_nonce).unwrap();
                self.ready.insert(next_future_nonce, entry);
            } else {
                break;
            }
        }
    }

    fn add(&mut self, tx: ChainTransaction, hash: TxHash, nonce: u64) -> AddResult {
        if nonce < self.pending_nonce {
            return AddResult::Rejected(format!("Nonce {} too low", nonce));
        }
        if self.ready.contains_key(&nonce) {
            return AddResult::Rejected(format!("Nonce {} already in ready queue", nonce));
        }

        let tail_nonce = self
            .ready
            .keys()
            .last()
            .copied()
            .unwrap_or(self.pending_nonce.saturating_sub(1));
        let expected_next = if self.ready.is_empty() {
            self.pending_nonce
        } else {
            tail_nonce + 1
        };

        if nonce == expected_next {
            self.ready.insert(nonce, (tx, hash));
            self.try_promote();
            AddResult::Ready
        } else {
            if self.future.insert(nonce, (tx, hash)).is_some() {
                return AddResult::Rejected(format!("Nonce {} already in future queue", nonce));
            }
            AddResult::Future
        }
    }
}

/// A sharded, nonce-aware mempool that prioritizes sequential execution per account.
#[derive(Debug)]
pub struct Mempool {
    // Shards protected by parking_lot for non-awaitable critical sections
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
        let guard = self.shards[idx].lock();
        guard.contains_key(account_id)
    }

    /// Adds a transaction to the pool, routing it to the appropriate queue.
    /// `committed_nonce_state` is the last known nonce for the account from the blockchain state.
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

            if committed_nonce_state > queue.pending_nonce {
                let removed = queue.prune_committed(committed_nonce_state);
                self.total_count.fetch_sub(removed, Ordering::Relaxed);
            }

            let res = queue.add(tx, hash, tx_nonce);
            if !matches!(res, AddResult::Rejected(_)) {
                self.total_count.fetch_add(1, Ordering::Relaxed);
            }
            res
        } else {
            let mut guard = self.others.lock();
            guard.push_back((tx, hash));
            self.total_count.fetch_add(1, Ordering::Relaxed);
            AddResult::Ready
        }
    }

    /// Updates an account's state after a block commit, pruning processed transactions.
    pub fn update_account_nonce(&self, account_id: &AccountId, new_committed_nonce: u64) {
        let idx = self.get_shard_index(account_id);
        let mut guard = self.shards[idx].lock();
        if let Some(queue) = guard.get_mut(account_id) {
            let removed = queue.prune_committed(new_committed_nonce);
            self.total_count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    /// Removes a specific transaction from any queue by its hash.
    pub fn remove_by_hash(&self, hash: &TxHash) {
        {
            let mut guard = self.others.lock();
            if let Some(pos) = guard.iter().position(|(_, h)| h == hash) {
                guard.remove(pos);
                self.total_count.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }

        for shard in &self.shards {
            let mut guard = shard.lock();
            for queue in guard.values_mut() {
                let mut ready_remove = None;
                for (n, (_, h)) in &queue.ready {
                    if h == hash {
                        ready_remove = Some(*n);
                        break;
                    }
                }
                if let Some(n) = ready_remove {
                    queue.ready.remove(&n);
                    self.total_count.fetch_sub(1, Ordering::Relaxed);
                    return;
                }

                let mut future_remove = None;
                for (n, (_, h)) in &queue.future {
                    if h == hash {
                        future_remove = Some(*n);
                        break;
                    }
                }
                if let Some(n) = future_remove {
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

        for shard in &self.shards {
            let mut guard = shard.lock();
            for queue in guard.values_mut() {
                for (tx, _) in queue.ready.values() {
                    selected.push(tx.clone());
                    if selected.len() >= total_limit {
                        return selected;
                    }
                }
            }
        }
        selected
    }
}
