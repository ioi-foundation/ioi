// Path: crates/drivers/src/gui/platform.rs

use super::accessibility::{
    serialize_tree_to_xml, AccessibilityNode, Rect, SovereignSubstrateProvider,
};
use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{ActionRequest, ContextSlice};

// [NOTE] This is a placeholder for the platform-specific implementation.
// AccessKit requires a window loop/context which is complex to setup in a headless library.
// For Phase 1, we simulate the "Real" provider structure but mock the OS call.
// In Phase 2, this will be replaced with `racc` (Windows) or `ax` (macOS) calls.

pub struct NativeSubstrateProvider;

impl NativeSubstrateProvider {
    pub fn new() -> Self {
        Self
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

        // 2. Apply Intent-Constraint (The Filter) using the shared logic
        // This exercises the `serialize_tree_to_xml` filtering we added in the previous step.
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Generate Provenance Proof (Standard Logic)
        let intent_hash = intent.hash();
        let mut proof_input = xml_data.clone();
        proof_input.extend_from_slice(&intent_hash);

        let proof =
            sha256(&proof_input).map_err(|e| anyhow!("Provenance generation failed: {}", e))?;
        let mut proof_arr = [0u8; 32];
        proof_arr.copy_from_slice(proof.as_ref());

        let slice_id = sha256(&xml_data).map_err(|e| anyhow!("Slice ID gen failed: {}", e))?;
        let mut slice_id_arr = [0u8; 32];
        slice_id_arr.copy_from_slice(slice_id.as_ref());

        Ok(ContextSlice {
            slice_id: slice_id_arr,
            data: xml_data,
            provenance_proof: proof.to_vec(),
            intent_id: intent_hash,
        })
    }
}
