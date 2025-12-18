// Path: crates/execution/src/scheduler.rs
use crate::mv_memory::TxIndex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Task {
    Execute(TxIndex),
    Validate(TxIndex),
    Done,
    RetryLater, // If dependency handling is added later
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TxStatus {
    Ready,
    Executed,
    Validated,
}

pub struct Scheduler {
    num_txs: usize,
    execution_idx: AtomicUsize,
    validation_idx: AtomicUsize,
    /// Tracks total completed validations to ensure safe termination.
    completed_validations: AtomicUsize,
    // Simple status tracking. In production, this would be more complex to handle dependency graphs.
    // Using Mutex for status vector for simplicity in this implementation phase.
    status: Mutex<Vec<TxStatus>>,
    // Track how many times a tx has been aborted (incarnation)
    incarnations: Mutex<Vec<usize>>,
}

impl Scheduler {
    pub fn new(num_txs: usize) -> Self {
        Self {
            num_txs,
            execution_idx: AtomicUsize::new(0),
            validation_idx: AtomicUsize::new(0),
            completed_validations: AtomicUsize::new(0),
            status: Mutex::new(vec![TxStatus::Ready; num_txs]),
            incarnations: Mutex::new(vec![0; num_txs]),
        }
    }

    pub fn next_task(&self) -> Task {
        loop {
            let val_idx = self.validation_idx.load(Ordering::Acquire);
            let exec_idx = self.execution_idx.load(Ordering::Acquire);

            // 1. Check for termination: only exit when all transactions are Validated.
            if self.completed_validations.load(Ordering::Acquire) >= self.num_txs {
                return Task::Done;
            }

            // 2. Prioritize Validation
            if val_idx < exec_idx {
                if self
                    .validation_idx
                    .compare_exchange(val_idx, val_idx + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return Task::Validate(val_idx);
                }
                continue; // CAS failed, retry loop
            }

            // 3. Pick Execution
            if exec_idx < self.num_txs {
                if self
                    .execution_idx
                    .compare_exchange(exec_idx, exec_idx + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return Task::Execute(exec_idx);
                }
                continue; // CAS failed, retry loop
            }

            // 4. No tasks currently available, spin/yield.
            return Task::RetryLater;
        }
    }

    /// Mark a transaction as executed.
    pub fn finish_execution(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().expect("Scheduler status lock poisoned");
        status[tx_idx] = TxStatus::Executed;
    }

    /// Mark a transaction as validated. This is the condition for block completion.
    pub fn finish_validation(&self, tx_idx: TxIndex) {
        {
            let mut status = self.status.lock().expect("Scheduler status lock poisoned");
            status[tx_idx] = TxStatus::Validated;
        }
        self.completed_validations.fetch_add(1, Ordering::SeqCst);
    }

    /// Mark a transaction as aborted (failed validation).
    /// This resets the execution index to ensure it gets picked up again.
    pub fn abort_tx(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().expect("Scheduler status lock poisoned");
        status[tx_idx] = TxStatus::Ready;

        let mut incarnations = self
            .incarnations
            .lock()
            .expect("Scheduler incarnations lock poisoned");
        incarnations[tx_idx] += 1;

        // CRITICAL: Reset indices to force re-execution of this and potentially subsequent txs.
        // This effectively "rewinds" the scheduler.
        self.execution_idx.fetch_min(tx_idx, Ordering::SeqCst);
        self.validation_idx.fetch_min(tx_idx, Ordering::SeqCst);
    }
}