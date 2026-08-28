// Path: crates/validator/src/standard/orchestration/mempool.rs

use ahash::RandomState;
use ioi_types::app::{AccountId, ChainTransaction, TxHash};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SHARD_COUNT: usize = 64;

/// Ceiling on the observation-only first-seen table.
///
/// The table exists solely to bracket the mempool-to-proposal wait. It is
/// drained on selection and on every hash-keyed removal, so it tracks the
/// live pool; the ceiling is the backstop for a pathological arrival burst.
/// Refusing to record past the ceiling loses OBSERVATIONS (which then read as
/// absent and fail closed downstream) rather than growing without bound, which
/// would be the instrumentation degrading the path it measures.
const FIRST_SEEN_OBSERVATION_CAPACITY: usize = 65_536;

/// Whether the observation-only first-seen table is armed.
///
/// The estate's existing, explicit, test-only benchmark-trace gate. Unarmed,
/// no timestamp is ever taken and the table stays empty.
fn first_seen_observation_armed() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

/// Wall-clock milliseconds since the UNIX epoch.
fn observation_wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Represents the status of a transaction after attempting to add it to the pool.
#[derive(Debug, PartialEq, Eq)]
pub enum AddResult {
    /// Added to the Ready queue (executable immediately).
    Ready,
    /// Added to the Future queue (waiting for a nonce gap to be filled).
    Future,
    /// Transaction was already present in the pool and was not reinserted.
    Known,
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

    /// Returns the hashes pruned, so the caller can drop their observation
    /// entries. The count is `len()`; nothing else changed about this path.
    fn update_base_nonce(&mut self, committed_nonce: u64) -> Vec<TxHash> {
        if committed_nonce > self.pending_nonce {
            self.prune_committed(committed_nonce)
        } else {
            Vec::new()
        }
    }

    /// Prunes every queued transaction below the newly committed nonce and
    /// returns their hashes.
    ///
    /// This used to return only a count. It returns the hashes so the
    /// observation-only first-seen table can be drained on the SAME path that
    /// drops the transactions -- a table that only shrank on explicit
    /// hash-keyed removal would retain entries for everything a nonce advance
    /// swept away.
    fn prune_committed(&mut self, new_committed_nonce: u64) -> Vec<TxHash> {
        let mut removed = Vec::new();
        self.pending_nonce = std::cmp::max(self.pending_nonce, new_committed_nonce);

        let stale_ready: Vec<u64> = self
            .ready
            .range(..self.pending_nonce)
            .map(|(&n, _)| n)
            .collect();
        for n in stale_ready {
            if let Some((_, hash)) = self.ready.remove(&n) {
                removed.push(hash);
            }
        }

        let stale_future: Vec<u64> = self
            .future
            .range(..self.pending_nonce)
            .map(|(&n, _)| n)
            .collect();
        for n in stale_future {
            if let Some((_, hash)) = self.future.remove(&n) {
                removed.push(hash);
            }
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
            return AddResult::Known;
        }
        if self.future.contains_key(&nonce) {
            return AddResult::Known;
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

    fn is_empty(&self) -> bool {
        self.ready.is_empty() && self.future.is_empty()
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
    /// OBSERVATION ONLY: when a transaction hash was first admitted here.
    ///
    /// M04.9 reported the mempool-to-proposal wait as unmeasured because no
    /// seam bracketed it. This table is that bracket's opening edge. It is
    /// deliberately a SEPARATE structure from the account queues: nothing in
    /// `add`, `select_transactions`, or any pruning decision reads it, so no
    /// timestamp can reach admission ordering, nonce arithmetic, block
    /// contents, or any canonical state. Removing this field would change no
    /// consensus behaviour at all.
    first_seen_ms: Mutex<HashMap<TxHash, u64>>,
    /// Whether `first_seen_ms` is maintained. Resolved once at construction so
    /// the arming cannot change under a running pool and leave half a table.
    first_seen_armed: bool,
}

impl Mempool {
    /// Creates a new, empty mempool with a fixed number of internal shards.
    pub fn new() -> Self {
        Self::with_first_seen_observation(first_seen_observation_armed())
    }

    /// Creates a mempool with the first-seen observation table explicitly
    /// armed or disarmed.
    ///
    /// Exists so the observation behaviour can be tested for BOTH arming
    /// states without a test mutating process environment, which would make
    /// the tests order-dependent against each other.
    pub fn with_first_seen_observation(first_seen_armed: bool) -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards,
            hasher: RandomState::new(),
            others: Mutex::new(VecDeque::new()),
            total_count: AtomicUsize::new(0),
            first_seen_ms: Mutex::new(HashMap::new()),
            first_seen_armed,
        }
    }

    /// Records when a hash was FIRST admitted, and never overwrites it.
    ///
    /// First-seen means first: a re-broadcast or a `Known` re-add must not
    /// reset the clock, or a transaction that sat in the pool across several
    /// proposals would report the wait of its most recent duplicate.
    fn note_first_seen(&self, hash: TxHash) {
        if !self.first_seen_armed {
            return;
        }
        let mut guard = self.first_seen_ms.lock();
        if guard.contains_key(&hash) {
            return;
        }
        if guard.len() >= FIRST_SEEN_OBSERVATION_CAPACITY {
            return;
        }
        guard.insert(hash, observation_wall_clock_ms());
    }

    /// Drops observation entries for hashes that have left the pool.
    fn forget_first_seen<'a>(&self, hashes: impl IntoIterator<Item = &'a TxHash>) {
        if !self.first_seen_armed {
            return;
        }
        let mut guard = self.first_seen_ms.lock();
        for hash in hashes {
            guard.remove(hash);
        }
    }

    /// Takes the first-seen observations for the hashes a proposal selected,
    /// REMOVING them.
    ///
    /// Removal on selection is what bounds the table: an entry lives from
    /// admission until the proposal that picked the transaction up, which is
    /// exactly the interval it measures. A transaction re-proposed after its
    /// entry was taken therefore reports NO wait rather than a second, wrong
    /// one -- an absent observation fails closed downstream, a fabricated one
    /// would not.
    ///
    /// Returns nothing when unarmed.
    pub fn take_first_seen(&self, hashes: &[TxHash]) -> Vec<(TxHash, u64)> {
        if !self.first_seen_armed {
            return Vec::new();
        }
        let mut guard = self.first_seen_ms.lock();
        hashes
            .iter()
            .filter_map(|hash| guard.remove(hash).map(|at_ms| (*hash, at_ms)))
            .collect()
    }

    /// How many first-seen observations are currently held. Test/diagnostic
    /// only; nothing in the commit path branches on it.
    pub fn first_seen_observation_len(&self) -> usize {
        self.first_seen_ms.lock().len()
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
        guard
            .get(account_id)
            .map(|queue| !queue.is_empty())
            .unwrap_or(false)
    }

    /// Adds a transaction to the pool, routing it to the appropriate queue based on its type and nonce.
    pub fn add(
        &self,
        tx: ChainTransaction,
        hash: TxHash,
        account_info: Option<(AccountId, u64)>,
        committed_nonce_state: u64,
    ) -> AddResult {
        if let Some((account_id, tx_nonce)) = account_info {
            let idx = self.get_shard_index(&account_id);
            let (res, pruned) = {
                let mut guard = self.shards[idx].lock();

                let queue = guard
                    .entry(account_id)
                    .or_insert_with(|| AccountQueue::new(committed_nonce_state));

                let pruned = queue.update_base_nonce(committed_nonce_state);
                self.total_count.fetch_sub(pruned.len(), Ordering::Relaxed);

                let before_len = queue.ready.len() + queue.future.len();
                let res = queue.add(tx, hash, tx_nonce);
                let after_len = queue.ready.len() + queue.future.len();
                if after_len > before_len {
                    self.total_count
                        .fetch_add(after_len - before_len, Ordering::Relaxed);
                }
                // Publish the observation before releasing the queue lock that
                // makes this transaction selectable. Otherwise selection can
                // win the gap, observe no timestamp, and leave a stale entry
                // when this thread records it afterwards.
                if matches!(res, AddResult::Ready | AddResult::Future) {
                    self.note_first_seen(hash);
                }
                (res, pruned)
            };
            self.forget_first_seen(pruned.iter());
            res
        } else {
            let mut others = self.others.lock();
            others.push_back((tx, hash));
            // Same lock-ordering rule as the account queue: the timestamp is
            // present before `others` becomes selectable by another thread.
            self.note_first_seen(hash);
            drop(others);
            self.total_count.fetch_add(1, Ordering::Relaxed);
            AddResult::Ready
        }
    }

    /// Updates an account's base nonce after a block commit, pruning processed transactions.
    pub fn update_account_nonce(&self, account_id: &AccountId, new_committed_nonce: u64) {
        let idx = self.get_shard_index(account_id);
        let pruned = {
            let mut guard = self.shards[idx].lock();
            match guard.get_mut(account_id) {
                Some(queue) => {
                    let pruned = queue.prune_committed(new_committed_nonce);
                    self.total_count.fetch_sub(pruned.len(), Ordering::Relaxed);
                    pruned
                }
                None => Vec::new(),
            }
        };
        self.forget_first_seen(pruned.iter());
    }

    /// Efficiently updates multiple accounts in a batch, acquiring each shard lock only once.
    pub fn update_account_nonces_batch(&self, updates: &HashMap<AccountId, u64>) {
        // Group updates by shard index to minimize locking
        let mut updates_by_shard: HashMap<usize, Vec<(&AccountId, u64)>> = HashMap::new();

        for (acct, &nonce) in updates {
            let idx = self.get_shard_index(acct);
            updates_by_shard.entry(idx).or_default().push((acct, nonce));
        }

        for (idx, account_updates) in updates_by_shard {
            let removed_hashes = {
                let mut guard = self.shards[idx].lock();
                let mut removed_hashes: Vec<TxHash> = Vec::new();

                for (acct, new_committed_nonce) in account_updates {
                    if let Some(queue) = guard.get_mut(acct) {
                        removed_hashes.extend(queue.prune_committed(new_committed_nonce));
                    }
                }

                if !removed_hashes.is_empty() {
                    self.total_count
                        .fetch_sub(removed_hashes.len(), Ordering::Relaxed);
                }
                removed_hashes
            };
            self.forget_first_seen(removed_hashes.iter());
        }
    }

    /// Removes a specific transaction from any queue by its hash. Used for cleanup.
    pub fn remove_by_hash(&self, hash: &TxHash) {
        // Dropped FIRST, and unconditionally: this hash is leaving the pool on
        // every branch below, including the not-found one where it already
        // left. Doing it here keeps the observation table off every shard-lock
        // path rather than nesting two locks in four places.
        self.forget_first_seen([hash]);

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

    /// Read-only occupant lookup for one (account, nonce) slot.
    ///
    /// A submitter that collides with an occupied slot needs the occupant's
    /// hash to decide whether the occupant can still commit: an occupant
    /// whose transaction was already execution-rejected holds a nonce that
    /// will never advance, so it can never leave the queue on its own and
    /// the slot must be healed explicitly.
    pub fn peek_account_nonce(&self, account_id: &AccountId, nonce: u64) -> Option<TxHash> {
        let idx = self.get_shard_index(account_id);
        let guard = self.shards[idx].lock();
        let queue = guard.get(account_id)?;
        queue
            .ready
            .get(&nonce)
            .or_else(|| queue.future.get(&nonce))
            .map(|(_, hash)| *hash)
    }

    /// Removes the transaction occupying a specific account nonce, if present.
    ///
    /// Lifecycle service calls can be semantically rejected after they have already
    /// advanced runtime state to an operator pause. A later approval can legitimately
    /// re-admit the same account nonce against the new state, so admission needs a
    /// nonce-scoped eviction primitive rather than hash-only cleanup.
    pub fn remove_by_account_nonce(&self, account_id: &AccountId, nonce: u64) -> Option<TxHash> {
        let idx = self.get_shard_index(account_id);
        let removed = {
            let mut guard = self.shards[idx].lock();
            let queue = guard.get_mut(account_id)?;
            if let Some((_, hash)) = queue.ready.remove(&nonce) {
                self.total_count.fetch_sub(1, Ordering::Relaxed);
                queue.repair_hole(nonce);
                Some(hash)
            } else if let Some((_, hash)) = queue.future.remove(&nonce) {
                self.total_count.fetch_sub(1, Ordering::Relaxed);
                Some(hash)
            } else {
                None
            }
        };
        self.forget_first_seen(removed.iter());
        removed
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

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        ChainId, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    };

    fn system_tx(account_id: AccountId, nonce: u64) -> ChainTransaction {
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id,
                nonce,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "step@v1".to_string(),
                params: Vec::new(),
            },
            signature_proof: SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
        }))
    }

    #[test]
    fn removes_account_nonce_slot_for_lifecycle_readmission() {
        let pool = Mempool::new();
        let account = AccountId([7u8; 32]);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");

        assert_eq!(pool.add(tx, hash, Some((account, 1)), 1), AddResult::Ready);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.remove_by_account_nonce(&account, 1), Some(hash));
        assert_eq!(pool.len(), 0);
        assert!(pool.select_transactions(8).is_empty());
    }

    // -----------------------------------------------------------------------
    // Observation-only first-seen table
    // -----------------------------------------------------------------------

    #[test]
    fn unarmed_pool_records_no_first_seen_observation() {
        // The default path for every non-benchmark run. Nothing is timed, so
        // nothing can leak into admission or grow without bound.
        let pool = Mempool::with_first_seen_observation(false);
        let account = AccountId([1u8; 32]);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");

        assert_eq!(pool.add(tx, hash, Some((account, 1)), 1), AddResult::Ready);
        assert_eq!(pool.first_seen_observation_len(), 0);
        assert!(pool.take_first_seen(&[hash]).is_empty());
        // And the pool itself behaves identically.
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.select_transactions(8).len(), 1);
    }

    #[test]
    fn armed_pool_records_first_seen_and_selection_takes_it_exactly_once() {
        let pool = Mempool::with_first_seen_observation(true);
        let account = AccountId([2u8; 32]);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");

        assert_eq!(pool.add(tx, hash, Some((account, 1)), 1), AddResult::Ready);
        assert_eq!(pool.first_seen_observation_len(), 1);

        let taken = pool.take_first_seen(&[hash]);
        assert_eq!(taken.len(), 1, "the selecting proposal takes the entry");
        assert_eq!(taken[0].0, hash, "keyed by the exact transaction hash");
        assert!(taken[0].1 > 0, "a real wall-clock observation was recorded");
        assert_eq!(
            pool.first_seen_observation_len(),
            0,
            "selection removes the entry, which is what bounds the table"
        );
        // A second take reports ABSENCE rather than inventing a second wait.
        assert!(pool.take_first_seen(&[hash]).is_empty());
        // The transaction itself is untouched by the observation being taken.
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.select_transactions(8).len(), 1);
    }

    #[test]
    fn a_readd_does_not_reset_the_first_seen_clock() {
        // First-seen means FIRST. A re-broadcast that reset the clock would
        // report the wait of the duplicate, not of the transaction.
        let pool = Mempool::with_first_seen_observation(true);
        let account = AccountId([3u8; 32]);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");

        assert_eq!(
            pool.add(tx.clone(), hash, Some((account, 1)), 1),
            AddResult::Ready
        );
        let first = pool.take_first_seen(&[hash]);
        // Put it back so the observation exists again, then re-add.
        pool.note_first_seen(hash);
        let restored = pool.first_seen_ms.lock().get(&hash).copied();
        assert_eq!(pool.add(tx, hash, Some((account, 1)), 1), AddResult::Known);
        assert_eq!(
            pool.first_seen_ms.lock().get(&hash).copied(),
            restored,
            "a Known re-add must not overwrite the recorded first-seen time"
        );
        assert_eq!(first.len(), 1);
    }

    #[test]
    fn every_removal_path_drops_the_observation() {
        let account = AccountId([4u8; 32]);

        // Hash-keyed removal.
        let pool = Mempool::with_first_seen_observation(true);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");
        pool.add(tx, hash, Some((account, 1)), 1);
        pool.remove_by_hash(&hash);
        assert_eq!(pool.first_seen_observation_len(), 0, "remove_by_hash");

        // Nonce-slot removal.
        let pool = Mempool::with_first_seen_observation(true);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");
        pool.add(tx, hash, Some((account, 1)), 1);
        assert_eq!(pool.remove_by_account_nonce(&account, 1), Some(hash));
        assert_eq!(
            pool.first_seen_observation_len(),
            0,
            "remove_by_account_nonce"
        );

        // Nonce-advance pruning, single account.
        let pool = Mempool::with_first_seen_observation(true);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");
        pool.add(tx, hash, Some((account, 1)), 1);
        pool.update_account_nonce(&account, 2);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.first_seen_observation_len(), 0, "update_account_nonce");

        // Nonce-advance pruning, batch.
        let pool = Mempool::with_first_seen_observation(true);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");
        pool.add(tx, hash, Some((account, 1)), 1);
        let mut updates = HashMap::new();
        updates.insert(account, 2u64);
        pool.update_account_nonces_batch(&updates);
        assert_eq!(pool.len(), 0);
        assert_eq!(
            pool.first_seen_observation_len(),
            0,
            "update_account_nonces_batch"
        );
    }

    #[test]
    fn multiple_transactions_are_observed_independently_by_hash() {
        // Two transactions that will land in the SAME proposal must still
        // carry two distinct waits. Correlating by height would collapse them.
        let pool = Mempool::with_first_seen_observation(true);
        let first_account = AccountId([5u8; 32]);
        let second_account = AccountId([6u8; 32]);
        let first = system_tx(first_account, 1);
        let second = system_tx(second_account, 1);
        let first_hash = first.hash().expect("hash");
        let second_hash = second.hash().expect("hash");
        assert_ne!(first_hash, second_hash);

        pool.add(first, first_hash, Some((first_account, 1)), 1);
        pool.add(second, second_hash, Some((second_account, 1)), 1);
        assert_eq!(pool.first_seen_observation_len(), 2);

        let taken = pool.take_first_seen(&[first_hash, second_hash]);
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].0, first_hash);
        assert_eq!(taken[1].0, second_hash);
        assert_eq!(pool.first_seen_observation_len(), 0);
    }

    #[test]
    fn taking_an_unknown_hash_yields_nothing_rather_than_a_default() {
        let pool = Mempool::with_first_seen_observation(true);
        let account = AccountId([9u8; 32]);
        let tx = system_tx(account, 1);
        let hash = tx.hash().expect("hash");
        pool.add(tx, hash, Some((account, 1)), 1);

        let unknown = system_tx(AccountId([10u8; 32]), 1).hash().expect("hash");
        let taken = pool.take_first_seen(&[unknown]);
        assert!(
            taken.is_empty(),
            "an unobserved hash must produce no observation, not a zero"
        );
        assert_eq!(
            pool.first_seen_observation_len(),
            1,
            "and must not disturb the observation that does exist"
        );
    }
}
