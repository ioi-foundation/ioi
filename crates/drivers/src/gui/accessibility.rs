// Path: crates/drivers/src/gui/accessibility.rs

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use ioi_types::app::{ActionRequest, ContextSlice}; 
use ioi_crypto::algorithms::hash::sha256;
use dcrypt::algorithms::ByteSerializable; // [FIX] Required for copy_from_slice

/// A simplified, VLM-friendly representation of a UI element.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessibilityNode {
    pub id: String,
    pub role: String, // button, link, window, etc.
    pub name: Option<String>,
    pub value: Option<String>,
    pub rect: Rect,
    pub children: Vec<AccessibilityNode>,
    pub is_visible: bool,
}

impl AccessibilityNode {
    /// Heuristic to determine if a node is relevant for interaction.
    /// Used for semantic filtering (Phase 1.1).
    pub fn is_interactive(&self) -> bool {
        // Common interactive roles
        matches!(
            self.role.as_str(),
            "button" | "link" | "checkbox" | "radio" | "slider" | "textbox" | "combobox" | "menuitem" | "listitem"
        )
    }

    /// Checks if the node carries meaningful text content.
    pub fn has_content(&self) -> bool {
        self.name.as_ref().map_or(false, |s| !s.trim().is_empty()) ||
        self.value.as_ref().map_or(false, |s| !s.trim().is_empty())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Serializes the accessibility tree into a simplified XML-like format optimized for LLM token usage.
/// Applies semantic filtering to reduce noise.
pub fn serialize_tree_to_xml(node: &AccessibilityNode, depth: usize) -> String {
    // 1. Prune invisible nodes immediately
    if !node.is_visible {
        return String::new();
    }

    // 2. Recursively serialize children first.
    // This allows us to detect if a container has interesting content.
    let mut children_xml = String::new();
    for child in &node.children {
        children_xml.push_str(&serialize_tree_to_xml(child, depth + 1));
    }

    // 3. Semantic Filter Logic
    // Keep node IF:
    // - It is interactive (button, input)
    // - OR it has text content
    // - OR it is a structural root (window)
    // - OR it has interesting children (non-empty children_xml)
    let is_interesting = node.is_interactive() 
        || node.has_content() 
        || !children_xml.is_empty() 
        || node.role == "window" 
        || node.role == "root";

    if !is_interesting {
        // If it's a boring leaf (empty div), prune it.
        return String::new();
    }

    // 4. Construct XML
    let indent = "  ".repeat(depth);
    
    // Only include name/value attributes if they exist
    let name_attr = node.name.as_ref()
        .map(|n| format!(" name=\"{}\"", escape_xml(n)))
        .unwrap_or_default();
    
    let value_attr = node.value.as_ref()
        .map(|v| format!(" value=\"{}\"", escape_xml(v)))
        .unwrap_or_default();
        
    // Compact coordinate string to save tokens
    let coords_attr = format!(" rect=\"{},{},{},{}\"", node.rect.x, node.rect.y, node.rect.width, node.rect.height);
    
    let mut output = format!("{}<{} id=\"{}\"{}{}{}", indent, node.role, node.id, name_attr, value_attr, coords_attr);

    if children_xml.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        output.push_str(&children_xml);
        output.push_str(&format!("{}</{}>\n", indent, node.role));
    }

    output
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

/// The interface for the Sovereign Context Substrate (SCS).
/// Unlike a passive file system, the SCS actively filters data based on agentic intent.
pub trait SovereignSubstrateProvider: Send + Sync {
    /// Retrieves a context slice authorized and filtered by the provided intent.
    fn get_intent_constrained_slice(
        &self, 
        intent: &ActionRequest, 
        monitor_handle: u32
    ) -> Result<ContextSlice>;
}

// --- Mock Implementation for Development/Testing ---
pub struct MockSubstrateProvider;

impl SovereignSubstrateProvider for MockSubstrateProvider {
    fn get_intent_constrained_slice(
        &self, 
        intent: &ActionRequest, 
        _monitor_handle: u32
    ) -> Result<ContextSlice> {
        // 1. Capture Raw Context (Simulated)
        let raw_tree = AccessibilityNode {
            id: "win-1".to_string(),
            role: "window".to_string(),
            name: Some("IOI Autopilot".to_string()),
            value: None,
            rect: Rect { x: 0, y: 0, width: 1920, height: 1080 },
            is_visible: true,
            children: vec![
                AccessibilityNode {
                    id: "btn-1".to_string(),
                    role: "button".to_string(),
                    name: Some("Connect Wallet".to_string()),
                    value: None,
                    rect: Rect { x: 100, y: 100, width: 200, height: 50 },
                    is_visible: true,
                    children: vec![],
                },
                // This node should be filtered out by logic if it has no content and isn't interactive
                AccessibilityNode {
                    id: "div-empty".to_string(),
                    role: "group".to_string(),
                    name: None,
                    value: None,
                    rect: Rect { x: 0, y: 0, width: 10, height: 10 },
                    is_visible: true,
                    children: vec![],
                },
                AccessibilityNode {
                    id: "ad-1".to_string(),
                    role: "frame".to_string(),
                    name: Some("Irrelevant Ads".to_string()),
                    value: None,
                    rect: Rect { x: 1500, y: 0, width: 300, height: 600 },
                    is_visible: true,
                    children: vec![],
                }
            ],
        };

        // 2. Apply Intent-Constraint (The Filter)
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();
        
        // 3. Generate Provenance Proof
        let intent_hash = intent.hash();
        let mut proof_input = xml_data.clone();
        proof_input.extend_from_slice(&intent_hash);
        
        let proof = sha256(&proof_input).map_err(|e| anyhow!("Provenance generation failed: {}", e))?;
        let mut proof_arr = [0u8; 32];
        proof_arr.copy_from_slice(proof.as_ref());
        
        let slice_id = sha256(&xml_data).map_err(|e| anyhow!("Slice ID gen failed: {}", e))?;
        let mut slice_id_arr = [0u8; 32];
        slice_id_arr.copy_from_slice(slice_id.as_ref());

        Ok(ContextSlice {
            slice_id: slice_id_arr,
            frame_id: 0, // [FIX] Added frame_id
            chunks: vec![xml_data], // [FIX] Wrapped in chunks vector
            mhnsw_root: [0u8; 32], // [FIX] Added mhnsw_root
            traversal_proof: Some(proof.to_vec()), // [FIX] Renamed to traversal_proof
            intent_id: intent_hash,
        })
    }
}