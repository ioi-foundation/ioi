// Path: crates/services/src/agentic/desktop/service/visual.rs

use super::DesktopAgentService;
use ioi_types::error::TransactionError;
use std::collections::{HashMap, BTreeMap, VecDeque};
use hex;

/// An in-memory Least Recently Used (LRU) cache for storing visual contexts.
pub struct VisualContextCache {
    /// Maps visual pHash -> SoM Bounding Boxes.
    map: HashMap<[u8; 32], BTreeMap<u32, (i32, i32, i32, i32)>>,
    /// Queue to track usage order for eviction (front = oldest/least used).
    queue: VecDeque<[u8; 32]>,
    /// Maximum number of contexts to retain.
    capacity: usize,
}

impl VisualContextCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            queue: VecDeque::new(),
            capacity,
        }
    }

    pub fn insert(&mut self, hash: [u8; 32], data: BTreeMap<u32, (i32, i32, i32, i32)>) {
        if self.map.contains_key(&hash) {
            self.queue.retain(|x| *x != hash);
            self.queue.push_back(hash);
            self.map.insert(hash, data);
        } else {
            if self.queue.len() >= self.capacity {
                if let Some(oldest) = self.queue.pop_front() {
                    self.map.remove(&oldest);
                }
            }
            self.queue.push_back(hash);
            self.map.insert(hash, data);
        }
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<&BTreeMap<u32, (i32, i32, i32, i32)>> {
        self.map.get(hash)
    }
}

/// Restores the visual grounding context (Set-of-Marks) for a specific historical screenshot.
/// This is critical for resuming execution after a human approval gate.
pub async fn restore_visual_context(
    service: &DesktopAgentService,
    visual_hash: [u8; 32]
) -> Result<(), TransactionError> {
    let history = service.som_history.read().await;
    
    if let Some(map) = history.get(&visual_hash) {
        // Convert BTreeMap to HashMap for the driver interface
        let mut driver_map = HashMap::new();
        for (k, v) in map {
            driver_map.insert(*k, *v);
        }
        
        // Re-inject the Set-of-Marks overlay into the GUI driver
        service.gui.register_som_overlay(driver_map).await
            .map_err(|e| TransactionError::Invalid(format!("Failed to restore SoM overlay: {}", e)))?;
        Ok(())
    } else {
        // If cache evicted the map, we log a warning but proceed. 
        // The agent might click blindly or rely on coordinate persistence.
        log::warn!("Visual context cache miss for hash 0x{}", hex::encode(&visual_hash[0..4]));
        Ok(())
    }
}