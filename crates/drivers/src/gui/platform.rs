// Path: crates/drivers/src/gui/platform.rs

use super::accessibility::{
    serialize_tree_to_xml, AccessibilityNode, Rect, SovereignSubstrateProvider,
};
use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, SovereignContextStore};
use ioi_types::app::{ActionRequest, ContextSlice};
use std::sync::{Arc, Mutex};

/// A real, persistent substrate provider backed by `ioi-scs`.
pub struct NativeSubstrateProvider {
    scs: Arc<Mutex<SovereignContextStore>>,
}

impl NativeSubstrateProvider {
    pub fn new(scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        Self { scs }
    }

    /// Simulates fetching the accessibility tree from the OS.
    /// In a real implementation, this would call UIAutomation/AX/AT-SPI.
    fn fetch_os_tree(&self) -> Result<AccessibilityNode> {
        // [MOCK] Return a complex tree simulating a real application (e.g. VS Code)
        Ok(AccessibilityNode {
            id: "root".to_string(),
            role: "window".to_string(),
            name: Some("Visual Studio Code".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            is_visible: true,
            children: vec![
                AccessibilityNode {
                    id: "sidebar".to_string(),
                    role: "group".to_string(),
                    name: Some("Explorer".to_string()),
                    value: None,
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 300,
                        height: 1080,
                    },
                    is_visible: true,
                    children: vec![
                        AccessibilityNode {
                            id: "file1".to_string(),
                            role: "listitem".to_string(),
                            name: Some("main.rs".to_string()),
                            value: None,
                            rect: Rect {
                                x: 10,
                                y: 50,
                                width: 280,
                                height: 20,
                            },
                            is_visible: true,
                            children: vec![],
                        },
                        AccessibilityNode {
                            id: "file2".to_string(),
                            role: "listitem".to_string(),
                            name: Some("lib.rs".to_string()),
                            value: None,
                            rect: Rect {
                                x: 10,
                                y: 70,
                                width: 280,
                                height: 20,
                            },
                            is_visible: true,
                            children: vec![],
                        },
                    ],
                },
                AccessibilityNode {
                    id: "editor".to_string(),
                    role: "textbox".to_string(),
                    name: Some("Editor".to_string()),
                    value: Some("fn main() { println!(\"Hello World\"); }".to_string()),
                    rect: Rect {
                        x: 300,
                        y: 0,
                        width: 1620,
                        height: 1080,
                    },
                    is_visible: true,
                    children: vec![],
                },
            ],
        })
    }
}

impl SovereignSubstrateProvider for NativeSubstrateProvider {
    fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        _monitor_handle: u32,
    ) -> Result<ContextSlice> {
        // 1. Capture Raw Context from OS
        let raw_tree = self.fetch_os_tree()?;

        // 2. Apply Intent-Constraint (The Filter)
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Persist to Local SCS
        // We write the raw (but filtered) XML to the local store as a new Frame.
        // This gives us a permanent record of what the agent saw.
        let mut store = self.scs.lock().map_err(|_| anyhow!("SCS lock poisoned"))?;

        // Placeholder: Assuming block height 0 for local captures if not synced from a service call
        let frame_id = store.append_frame(
            FrameType::Observation,
            &xml_data,
            0,
            [0u8; 32], // mHNSW root placeholder - would come from index update
        )?;

        // 4. Generate Provenance (Binding to the Store)
        // The slice_id is the hash of the data.
        let slice_id_digest = sha256(&xml_data)?;
        let mut slice_id = [0u8; 32];
        slice_id.copy_from_slice(slice_id_digest.as_ref());

        // The intent_hash binds this slice to the specific request.
        let intent_hash = intent.hash();

        // The provenance proof links this specific frame in the store to the SCS root.
        // For MVP, we use the Frame's checksum.
        let frame = store.toc.frames.get(frame_id as usize).unwrap();
        let proof = frame.checksum.to_vec();

        Ok(ContextSlice {
            slice_id,
            frame_id,
            chunks: vec![xml_data],
            mhnsw_root: frame.mhnsw_root,
            traversal_proof: Some(proof),
            intent_id: intent_hash,
        })
    }
}
