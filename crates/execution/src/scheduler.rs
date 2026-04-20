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
    Executing,
    Executed,
    Validating,
    Validated,
    PendingReexecute,
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
}

impl Scheduler {
    pub fn new(num_txs: usize) -> Self {
        Self {
            num_txs,
            execution_idx: AtomicUsize::new(0),
            validation_idx: AtomicUsize::new(0),
            completed_validations: AtomicUsize::new(0),
            status: Mutex::new(vec![TxStatus::Ready; num_txs]),
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

            // 2. Prioritize validation only after execution has actually finished.
            if val_idx < self.num_txs {
                let validation_ready = {
                    let status = self.status.lock().expect("Scheduler status lock poisoned");
                    status.get(val_idx).copied()
                };

                match validation_ready {
                    Some(TxStatus::Executed) => {
                        let mut status =
                            self.status.lock().expect("Scheduler status lock poisoned");
                        if status.get(val_idx) == Some(&TxStatus::Executed)
                            && self
                                .validation_idx
                                .compare_exchange(
                                    val_idx,
                                    val_idx + 1,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                )
                                .is_ok()
                        {
                            status[val_idx] = TxStatus::Validating;
                            return Task::Validate(val_idx);
                        }
                        continue;
                    }
                    Some(TxStatus::Validated) => {
                        let _ = self.validation_idx.compare_exchange(
                            val_idx,
                            val_idx + 1,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        );
                        continue;
                    }
                    _ => {}
                }
            }

            // 3. Pick execution for the next transaction that is still Ready.
            if exec_idx < self.num_txs {
                let exec_status = {
                    let status = self.status.lock().expect("Scheduler status lock poisoned");
                    status.get(exec_idx).copied()
                };

                match exec_status {
                    Some(TxStatus::Ready) => {
                        let mut status =
                            self.status.lock().expect("Scheduler status lock poisoned");
                        if status.get(exec_idx) == Some(&TxStatus::Ready)
                            && self
                                .execution_idx
                                .compare_exchange(
                                    exec_idx,
                                    exec_idx + 1,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                )
                                .is_ok()
                        {
                            status[exec_idx] = TxStatus::Executing;
                            return Task::Execute(exec_idx);
                        }
                        continue;
                    }
                    Some(TxStatus::Executed | TxStatus::Validated) => {
                        let _ = self.execution_idx.compare_exchange(
                            exec_idx,
                            exec_idx + 1,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        );
                        continue;
                    }
                    Some(
                        TxStatus::Executing | TxStatus::Validating | TxStatus::PendingReexecute,
                    ) => {}
                    None => {}
                }
            }

            // 4. No tasks currently available, spin/yield.
            return Task::RetryLater;
        }
    }

    /// Mark a transaction as executed.
    pub fn finish_execution(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().expect("Scheduler status lock poisoned");
        status[tx_idx] = match status[tx_idx] {
            TxStatus::Executing => TxStatus::Executed,
            TxStatus::PendingReexecute => TxStatus::Ready,
            current => current,
        };
    }

    /// Mark a transaction as validated. This is the condition for block completion.
    pub fn finish_validation(&self, tx_idx: TxIndex) {
        let mut newly_validated = false;
        {
            let mut status = self.status.lock().expect("Scheduler status lock poisoned");
            match status[tx_idx] {
                TxStatus::Validating => {
                    status[tx_idx] = TxStatus::Validated;
                    newly_validated = true;
                }
                TxStatus::PendingReexecute => {
                    status[tx_idx] = TxStatus::Ready;
                }
                _ => {}
            }
        }
        if newly_validated {
            self.completed_validations.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Mark a transaction as aborted (failed validation).
    /// This resets the execution index to ensure it gets picked up again.
    pub fn abort_tx(&self, tx_idx: TxIndex) {
        let mut status = self.status.lock().expect("Scheduler status lock poisoned");
        let mut revoked_validations = 0usize;
        for (idx, entry) in status.iter_mut().enumerate().skip(tx_idx) {
            let next_status = match *entry {
                TxStatus::Validated => {
                    revoked_validations += 1;
                    TxStatus::Ready
                }
                TxStatus::Executing | TxStatus::Validating if idx > tx_idx => {
                    TxStatus::PendingReexecute
                }
                TxStatus::PendingReexecute => TxStatus::PendingReexecute,
                _ => TxStatus::Ready,
            };
            *entry = next_status;
        }

        if revoked_validations > 0 {
            self.completed_validations
                .fetch_sub(revoked_validations, Ordering::SeqCst);
        }

        // CRITICAL: Reset indices to force re-execution and re-validation from the aborted point.
        self.execution_idx.fetch_min(tx_idx, Ordering::SeqCst);
        self.validation_idx.fetch_min(tx_idx, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[path = "scheduler/tests.rs"]
mod tests;
