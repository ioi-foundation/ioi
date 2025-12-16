// Path: crates/validator/src/standard/orchestration/mempool.rs
use ioi_types::app::{AccountId, ChainTransaction, TxHash};
use std::collections::{BTreeMap, HashMap, VecDeque};

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
    /// The next expected nonce for this account based on the mempool state.
    /// This starts at the committed state nonce and advances as txs become Ready.
    pending_nonce: u64,
    /// Transactions that are ready to execute (contiguous nonces starting at pending_nonce).
    ready: BTreeMap<u64, (ChainTransaction, TxHash)>,
    /// Transactions received out-of-order (waiting for gaps).
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

    /// Prunes transactions <= committed_nonce.
    /// Returns the number of transactions removed.
    fn prune_committed(&mut self, new_committed_nonce: u64) -> usize {
        let mut removed = 0;

        // Update our baseline
        self.pending_nonce = std::cmp::max(self.pending_nonce, new_committed_nonce);

        // Remove stale ready txs
        let stale_ready: Vec<u64> = self
            .ready
            .range(..new_committed_nonce)
            .map(|(n, _)| *n)
            .collect();
        for nonce in stale_ready {
            self.ready.remove(&nonce);
            removed += 1;
        }

        // Remove stale future txs (shouldn't happen if logic is correct, but safe guard)
        let stale_future: Vec<u64> = self
            .future
            .range(..new_committed_nonce)
            .map(|(n, _)| *n)
            .collect();
        for nonce in stale_future {
            self.future.remove(&nonce);
            removed += 1;
        }

        // Try to promote futures to ready
        self.try_promote();
        removed
    }

    /// Moves transactions from Future to Ready if they fill the sequence.
    fn try_promote(&mut self) {
        while let Some(&next_future_nonce) = self.future.keys().next() {
            // We expect pending_nonce + len(ready).
            // Example: pending=5, ready has [5, 6]. Next expected is 7.
            // If future has 7, move it.

            // Calculate the tail of the ready chain
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
                break; // Gap remains
            }
        }
    }

    fn add(&mut self, tx: ChainTransaction, hash: TxHash, nonce: u64) -> AddResult {
        // 1. Check if Stale
        if nonce < self.pending_nonce {
            return AddResult::Rejected(format!(
                "Nonce {} too low (expected >= {})",
                nonce, self.pending_nonce
            ));
        }

        // 2. Check if Duplicate in Ready
        if self.ready.contains_key(&nonce) {
            // TODO: Implement Replace-By-Fee here. For now, reject duplicate nonces.
            return AddResult::Rejected(format!("Nonce {} already in ready queue", nonce));
        }

        // 3. Determine Queue
        // It fits in ready if it is exactly the next needed nonce OR extends the ready chain.
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
            // Adding this might bridge a gap to existing futures
            self.try_promote();
            AddResult::Ready
        } else {
            // It's a future transaction
            if self.future.insert(nonce, (tx, hash)).is_some() {
                return AddResult::Rejected(format!("Nonce {} already in future queue", nonce));
            }
            AddResult::Future
        }
    }
}

/// A nonce-aware mempool that prioritizes sequential execution per account.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Nonce-ordered queues for standard accounts.
    accounts: HashMap<AccountId, AccountQueue>,
    /// FIFO queue for transactions that do not utilize account nonces (e.g. UTXO, Semantic).
    others: VecDeque<(ChainTransaction, TxHash)>,
    /// Total count of transactions (Ready + Future + Other).
    total_count: usize,
}

impl Mempool {
    /// Creates a new, empty mempool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.total_count
    }

    /// Returns true if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Checks if the mempool is already tracking this account.
    pub fn contains_account(&self, account_id: &AccountId) -> bool {
        self.accounts.contains_key(account_id)
    }

    /// Adds a transaction to the pool.
    ///
    /// `committed_nonce` is the nonce currently stored in the blockchain state for this account.
    /// This is used to initialize the queue if the account is new to the mempool.
    pub fn add(
        &mut self,
        tx: ChainTransaction,
        hash: TxHash,
        account_info: Option<(AccountId, u64)>, // (ID, Nonce) extracted from tx headers
        committed_nonce_state: u64,             // The nonce currently on-chain
    ) -> AddResult {
        if let Some((account_id, tx_nonce)) = account_info {
            // Account-based Transaction
            let queue = self
                .accounts
                .entry(account_id)
                .or_insert_with(|| AccountQueue::new(committed_nonce_state));

            // If the state advanced since we last touched this queue, fast-forward.
            // This handles cases where we didn't see the block (e.g. restart) but are getting new txs.
            if committed_nonce_state > queue.pending_nonce {
                queue.prune_committed(committed_nonce_state);
            }

            let res = queue.add(tx, hash, tx_nonce);
            if !matches!(res, AddResult::Rejected(_)) {
                self.total_count += 1;
            }
            res
        } else {
            // Non-Account Transaction (Semantic, UTXO, etc.)
            // Treat as FIFO / Always Ready
            self.others.push_back((tx, hash));
            self.total_count += 1;
            AddResult::Ready
        }
    }

    /// Updates the mempool based on a newly committed block.
    /// Removes included transactions and promotes future transactions to ready.
    ///
    /// Note: A full implementation would inspect the block contents.
    /// For O(1) simplicity in this iteration, we rely on the `committed_nonce_state` lookup
    /// provided by the caller for every account involved in the block.
    ///
    /// Instead of scanning the block here, the caller (Orchestrator) simply calls `update_account`
    /// for relevant accounts after block commit.
    pub fn update_account_nonce(&mut self, account_id: &AccountId, new_committed_nonce: u64) {
        if let Some(queue) = self.accounts.get_mut(account_id) {
            let removed = queue.prune_committed(new_committed_nonce);
            self.total_count = self.total_count.saturating_sub(removed);

            // [FIXED] Removed aggressive cleanup of empty queues to prevent thrashing
            // the state query cache in grpc_public. If we remove the account, the next
            // transaction will trigger a fresh gRPC call to Workload to fetch the nonce,
            // destroying throughput during high-load bursts.
            //
            // if queue.ready.is_empty() && queue.future.is_empty() {
            //    self.accounts.remove(account_id);
            // }
        }
    }

    /// Removes a specific transaction (e.g. invalidated).
    pub fn remove_by_hash(&mut self, hash: &TxHash) {
        // Expensive scan, but necessary for generic removal.
        // In production, maintain a Hash -> (AccountId, Nonce) index.

        // Basic handling for `others`
        if let Some(pos) = self.others.iter().position(|(_, h)| h == hash) {
            self.others.remove(pos);
            self.total_count = self.total_count.saturating_sub(1);
        }

        // Scan accounts (inefficient, but correct for Phase 1)
        for queue in self.accounts.values_mut() {
            // Check ready
            let mut ready_remove = None;
            for (nonce, (_, h)) in &queue.ready {
                if h == hash {
                    ready_remove = Some(*nonce);
                    break;
                }
            }
            if let Some(n) = ready_remove {
                queue.ready.remove(&n);
                self.total_count = self.total_count.saturating_sub(1);
            }

            // Check future
            let mut future_remove = None;
            for (nonce, (_, h)) in &queue.future {
                if h == hash {
                    future_remove = Some(*nonce);
                    break;
                }
            }
            if let Some(n) = future_remove {
                queue.future.remove(&n);
                self.total_count = self.total_count.saturating_sub(1);
            }
        }
    }

    /// Selects the best transactions for a block proposal.
    /// Uses Round-Robin scheduling between accounts to ensure fairness and prevent starvation.
    pub fn select_transactions(&self, limit: usize) -> Vec<ChainTransaction> {
        let mut selected = Vec::with_capacity(limit);

        // 1. Prioritize System/Other transactions (FIFO)
        // (Cloning for selection; real impl would use iterators)
        let mut others_iter = self.others.iter();
        while selected.len() < limit {
            if let Some((tx, _)) = others_iter.next() {
                selected.push(tx.clone());
            } else {
                break;
            }
        }

        if selected.len() >= limit {
            return selected;
        }

        // 2. Round-Robin select from Account Ready Queues
        // We construct VecDeques of references for all ready queues to round-robin efficiently.
        let mut deques: Vec<VecDeque<&ChainTransaction>> = self
            .accounts
            .values()
            .map(|q| q.ready.values().map(|(tx, _)| tx).collect::<VecDeque<_>>())
            .filter(|d: &VecDeque<&ChainTransaction>| !d.is_empty())
            .collect();

        while selected.len() < limit && !deques.is_empty() {
            // Iterate over all active accounts
            let mut finished_indices = Vec::new();
            for (idx, queue) in deques.iter_mut().enumerate() {
                if let Some(tx) = queue.pop_front() {
                    selected.push(tx.clone());
                }

                if queue.is_empty() {
                    finished_indices.push(idx);
                }
                if selected.len() >= limit {
                    break;
                }
            }

            // Remove empty queues (reverse order to keep indices valid)
            for &idx in finished_indices.iter().rev() {
                deques.swap_remove(idx);
            }
        }

        selected
    }
}
