// Path: crates/api/src/state/retention.rs

//! A centralized retention manager for handling state pruning, version pinning,
//! and long-running historical access requirements.

use crate::state::pins::StateVersionPins;
use crate::state::PrunePlan;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A unique identifier for a retention client.
pub type RetentionClientId = u64;

/// A central manager for determining which state versions must be retained.
///
/// It combines three sources of truth:
/// 1. Configuration (horizon/finality depth).
/// 2. Sparse Pins (`StateVersionPins`) for specific, temporary height access.
/// 3. Retention Clients (via `RetentionHandle`) for long-running tasks requiring a history floor.
#[derive(Debug)]
pub struct RetentionManager {
    /// Sparse pins for specific heights (e.g., during block verification).
    pins: Arc<StateVersionPins>,
    /// Active clients declaring a minimum required height (floor).
    clients: DashMap<RetentionClientId, AtomicU64>,
    /// Counter for generating client IDs.
    next_client_id: AtomicU64,
}

impl Default for RetentionManager {
    fn default() -> Self {
        Self {
            pins: Arc::new(StateVersionPins::default()),
            clients: DashMap::new(),
            next_client_id: AtomicU64::new(1),
        }
    }
}

impl RetentionManager {
    /// Creates a new `RetentionManager`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Access the underlying sparse pins system (e.g., for creating PinGuards).
    pub fn pins(&self) -> &Arc<StateVersionPins> {
        &self.pins
    }

    /// Registers a new client that needs to prevent pruning below a certain height.
    /// Returns a handle that automatically deregisters the client when dropped.
    ///
    /// This method takes `&Arc<Self>` to ensure the returned handle can hold a
    /// clone of the Arc, keeping the manager alive as long as the handle exists.
    pub fn register_client(self: &Arc<Self>, name: &'static str) -> RetentionHandle {
        let id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        // Initialize with MAX so a new client doesn't accidentally block all pruning
        // until it explicitly sets a floor.
        self.clients.insert(id, AtomicU64::new(u64::MAX));
        
        log::debug!(target: "retention", "Registered retention client '{}' (ID: {})", name, id);
        
        RetentionHandle {
            manager: Arc::clone(self),
            client_id: id,
            name,
        }
    }

    /// Calculates the global pruning plan based on current height, config, and all active guards.
    pub fn calculate_prune_plan(
        &self,
        current_height: u64,
        keep_recent: u64,
        min_finality: u64,
    ) -> PrunePlan {
        // 1. Config-based cutoff (The Goal)
        let horizon_cutoff = current_height.saturating_sub(keep_recent);
        let finality_cutoff = current_height.saturating_sub(min_finality);
        let config_cutoff = horizon_cutoff.min(finality_cutoff);

        // 2. Retention Clients (The Safety Brakes)
        // Find the minimum floor among all active clients.
        let mut client_floor = u64::MAX;
        for entry in self.clients.iter() {
            let floor = entry.value().load(Ordering::Acquire);
            if floor < client_floor {
                client_floor = floor;
            }
        }

        // 3. Sparse Pins
        // We must also respect the lowest individual pin.
        let pin_floor = self.pins.min_pinned_height();

        // The final cutoff is the minimum of all constraints.
        // We cannot prune anything >= global_floor.
        let global_floor = client_floor.min(pin_floor);
        
        // We want to prune everything strictly less than `cutoff`.
        // So if global_floor is 100, we can at most prune up to 100 (deleting 0..99).
        // Therefore, effective_cutoff = min(config_cutoff, global_floor).
        let effective_cutoff = config_cutoff.min(global_floor);

        // Snapshot pins for the exclusion list to handle sparse gaps.
        let excluded_heights = self.pins.snapshot();

        if effective_cutoff < config_cutoff {
            log::debug!(
                target: "retention",
                "Pruning restricted: Config wants {}, but Active Clients/Pins require >= {}",
                config_cutoff, effective_cutoff
            );
        }

        PrunePlan {
            cutoff_height: effective_cutoff,
            excluded_heights,
        }
    }
}

/// A handle required to maintain a retention floor.
/// When this struct is dropped, the constraint is removed.
pub struct RetentionHandle {
    manager: Arc<RetentionManager>, 
    client_id: RetentionClientId,
    name: &'static str,
}

impl RetentionHandle {
    /// Updates the retention floor. The GC guarantees that state at `height` 
    /// (and above) will NOT be pruned.
    pub fn set_floor(&self, height: u64) {
        if let Some(entry) = self.manager.clients.get(&self.client_id) {
            entry.store(height, Ordering::Release);
        }
    }

    /// Clears the floor constraint (effectively setting it to u64::MAX).
    pub fn clear(&self) {
        if let Some(entry) = self.manager.clients.get(&self.client_id) {
            entry.store(u64::MAX, Ordering::Release);
        }
    }
}

impl Drop for RetentionHandle {
    fn drop(&mut self) {
        self.manager.clients.remove(&self.client_id);
        log::debug!(target: "retention", "Deregistered retention client '{}' (ID: {})", self.name, self.client_id);
    }
}