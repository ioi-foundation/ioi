// Path: crates/execution/src/scheduler.rs
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use crate::mv_memory::TxIndex;

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
    Executing,
    Executed,
    Aborted,
}

pub struct Scheduler {
    num_txs: usize,
    execution_idx: AtomicUsize,
    validation_idx: AtomicUsize,
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
            status: Mutex::new(vec![TxStatus::Ready; num_txs]),
            incarnations: Mutex::new(vec![0; num_txs]),
        }
    }

    pub fn next_task(&self) -> Task {
        // 1. Prioritize Validation
        // In a real STM, we'd have a more granular wave-front. 
        // Here we validate optimistically.
        let val_idx = self.validation_idx.load(Ordering::Acquire);
        let exec_idx = self.execution_idx.load(Ordering::Acquire);

        if val_idx < exec_idx {
            // Try to pick up a validation task
            // Simple atomic increment is naive but works for phase 2.1
            // A better approach checks if val_idx is actually ready to be validated.
             let idx = self.validation_idx.fetch_add(1, Ordering::SeqCst);
             if idx < exec_idx {
                 return Task::Validate(idx);
             }
        }

        // 2. Pick Execution
        if exec_idx < self.num_txs {
             let idx = self.execution_idx.fetch_add(1, Ordering::SeqCst);
             if idx < self.num_txs {
                 return Task::Execute(idx);
             }
        }

        // 3. Check termination
        if val_idx >= self.num_txs {
            return Task::Done;
        }

        // 4. Spin/Backoff if waiting for others
        Task::RetryLater
    }

    /// Mark a transaction as executed.
    pub fn finish_execution(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().unwrap();
        status[tx_idx] = TxStatus::Executed;
    }

    /// Mark a transaction as aborted (failed validation).
    /// This resets the execution index to ensure it gets picked up again.
    pub fn abort_tx(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().unwrap();
        status[tx_idx] = TxStatus::Aborted;
        
        let mut incarnations = self.incarnations.lock().unwrap();
        incarnations[tx_idx] += 1;

        // CRITICAL: Reset indices to force re-execution of this and potentially subsequent txs.
        // In simplified Block-STM, we might just decrease execution_idx min(current, tx_idx).
        // This effectively "rewinds" the scheduler.
        self.execution_idx.fetch_min(tx_idx, Ordering::SeqCst);
        self.validation_idx.fetch_min(tx_idx, Ordering::SeqCst);
    }
}