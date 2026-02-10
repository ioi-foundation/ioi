// Path: crates/drivers/src/gui/accessibility.rs

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{ActionRequest, ContextSlice};
use serde::{Deserialize, Serialize};
use std::collections::HashMap; // [NEW] Added for attributes map

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

    // [NEW] Store raw platform attributes for Application Lens processing.
    // This holds raw data like "data-testid", "aria-label", "class", etc.
    // that Lenses use to semanticize the tree.
    #[serde(default)]
    pub attributes: HashMap<String, String>,

    // [NEW] Transient Visual Grounding ID (Set-of-Marks).
    // This connects the Visual Overlay (screenshot) to the Semantic Tree (XML).
    // It is populated during the Perception phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub som_id: Option<u32>,
}

impl AccessibilityNode {
    /// Heuristic to determine if a node is relevant for interaction.
    /// Used for semantic filtering (Phase 1.1).
    pub fn is_interactive(&self) -> bool {
        // Common interactive roles
        matches!(
            self.role.as_str(),
            "button"
                | "link"
                | "checkbox"
                | "radio"
                | "slider"
                | "textbox"
                | "combobox"
                | "menuitem"
                | "listitem"
        )
    }

    /// Checks if the node carries meaningful text content.
    pub fn has_content(&self) -> bool {
        self.name.as_ref().map_or(false, |s| !s.trim().is_empty())
            || self.value.as_ref().map_or(false, |s| !s.trim().is_empty())
    }

    /// [NEW] Recursively shifts the coordinates of this node and all children.
    /// Used to align browser DOM trees with OS window coordinates.
    pub fn offset(&mut self, dx: i32, dy: i32) {
        self.rect.x += dx;
        self.rect.y += dy;
        for child in &mut self.children {
            child.offset(dx, dy);
        }
    }

    /// Recursively searches the tree for nodes matching the text query.
    /// Returns a list of (ID, Role, Name, Rect).
    pub fn find_matches(&self, query: &str) -> Vec<(String, String, String, Rect)> {
        let mut results = Vec::new();
        let q = query.to_lowercase();
        let normalized_q: String = q.chars().filter(|c| c.is_ascii_alphanumeric()).collect();

        // Check self
        let id_lc = self.id.to_lowercase();
        let id_match = !q.is_empty() && id_lc.contains(&q);
        let name_match = self
            .name
            .as_ref()
            .map_or(false, |n| n.to_lowercase().contains(&q));
        let value_match = self
            .value
            .as_ref()
            .map_or(false, |v| v.to_lowercase().contains(&q));
        let role_match = self.role.to_lowercase().contains(&q);
        let normalized_id_match = if normalized_q.is_empty() {
            false
        } else {
            let normalized_id: String = id_lc
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            normalized_id.contains(&normalized_q)
        };

        // Also check attributes (e.g. data-testid)
        let attr_match = self
            .attributes
            .values()
            .any(|v| v.to_lowercase().contains(&q));

        if (id_match
            || normalized_id_match
            || name_match
            || value_match
            || role_match
            || attr_match)
            && self.is_visible
        {
            let label = self
                .name
                .clone()
                .or(self.value.clone())
                .unwrap_or(self.role.clone());
            results.push((self.id.clone(), self.role.clone(), label, self.rect));
        }

        // Recurse children
        for child in &self.children {
            results.extend(child.find_matches(query));
        }

        results
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Merges a child accessibility tree (e.g. Browser DOM) into a parent tree (e.g. OS Window)
/// at the node matching the `target_app_name`.
///
/// If `target_app_name` is found, its children are replaced/augmented with the `graft_tree`.
pub fn merge_trees(
    mut root: AccessibilityNode,
    graft_tree: AccessibilityNode,
    target_app_name: &str,
    offset: (i32, i32),
) -> AccessibilityNode {
    // 1. Find target node in OS tree
    // We look for a window or application node that matches the target name.

    // Helper recursive finder/replacer
    fn recurse_graft(
        node: &mut AccessibilityNode,
        graft: &AccessibilityNode,
        target: &str,
        offset: (i32, i32),
    ) -> bool {
        // Simple case-insensitive contains match for robustness
        let name_match = node
            .name
            .as_ref()
            .map_or(false, |n| n.to_lowercase().contains(&target.to_lowercase()));

        if name_match && (node.role == "window" || node.role == "application") {
            // Found it!
            // The graft tree (DOM) is usually screen-relative or window-relative.
            // If it's window-relative, we add the window offset.
            // If it's screen-relative (which CDP usually gives if configured right), we might not need offset.
            // Assuming here the graft needs the offset applied.

            let mut shifted_graft = graft.clone();
            shifted_graft.offset(offset.0, offset.1);

            // We append the DOM as a child of the Window.
            // We don't replace children because the window might have other UI (title bar, menus) we want to keep.
            node.children.push(shifted_graft);
            return true;
        }

        for child in &mut node.children {
            if recurse_graft(child, graft, target, offset) {
                return true;
            }
        }
        false
    }

    recurse_graft(&mut root, &graft_tree, target_app_name, offset);
    root
}

/// Serializes the accessibility tree into a simplified XML-like format optimized for LLM token usage.
/// Applies semantic filtering to reduce noise.
///
/// Note: This is the DEFAULT serialization strategy. Specialized Lenses (e.g. ReactLens)
/// will implement their own `render` logic to utilize the `attributes` field effectively.
pub fn serialize_tree_to_xml(node: &AccessibilityNode, depth: usize) -> String {
    // 1. Prune invisible nodes immediately
    if !node.is_visible {
        return String::new();
    }

    // Enforce hard depth limit to prevent deep recursion in complex UIs (e.g. IDEs, Webviews)
    if depth > 10 {
        return String::new();
    }

    // 2. Semantic Filter Logic (Early Exit)
    // Check if the node is "interesting" enough to render or recurse.
    let is_container = !node.children.is_empty();

    // Heuristic: If a node has > 200 chars of text, it's likely a document/log/code block.
    // Unless we are explicitly reading text, treat it as "Content" and summary-tag it to save tokens.
    let content_len = node.value.as_ref().map(|s| s.len()).unwrap_or(0)
        + node.name.as_ref().map(|s| s.len()).unwrap_or(0);
    let is_bulk_text = content_len > 200;

    // [MODIFIED] If node has a SoM ID, it is ALWAYS interesting because the VLM can see it tagged.
    let is_interesting = node.som_id.is_some()
        || node.is_interactive()
        || (node.has_content() && !is_bulk_text)
        || is_container // Must traverse containers to find interactive children
        || node.role == "window"
        || node.role == "root";

    if !is_interesting {
        // If it's a boring leaf (empty div), prune it.
        return String::new();
    }

    // 3. Recursively serialize children.
    // Limit the number of children to prevent context explosion in lists/tables.
    let mut children_xml = String::new();
    let max_children = 25; // Strict limit

    let indent = "  ".repeat(depth + 1);

    for (i, child) in node.children.iter().enumerate() {
        if i >= max_children {
            children_xml.push_str(&format!(
                "{}<!-- ... {} siblings truncated ... -->\n",
                indent,
                node.children.len() - max_children
            ));
            break;
        }
        children_xml.push_str(&serialize_tree_to_xml(child, depth + 1));
    }

    // 4. Post-recursion prune: If a container has no interesting children and isn't interesting itself, return empty.
    // Exception: Keep windows/roots to maintain structure, and keep nodes with IDs.
    if node.som_id.is_none()
        && !node.is_interactive()
        && !node.has_content()
        && children_xml.is_empty()
        && node.role != "window"
        && node.role != "root"
    {
        return String::new();
    }

    // 5. Construct XML
    let indent_self = "  ".repeat(depth);

    // Helper to truncate long attribute values to save tokens
    let truncate = |s: &str, max_len: usize| -> String {
        if s.len() > max_len {
            format!("{}...", &s[..max_len])
        } else {
            s.to_string()
        }
    };

    // [NEW] Inject SoM ID into attributes
    let som_attr = if let Some(id) = node.som_id {
        format!(" som_id=\"{}\"", id)
    } else {
        String::new()
    };

    let name_attr = node
        .name
        .as_ref()
        .map(|n| format!(" name=\"{}\"", escape_xml(&truncate(n, 50))))
        .unwrap_or_default();

    let value_attr = node
        .value
        .as_ref()
        .map(|v| format!(" value=\"{}\"", escape_xml(&truncate(v, 50))))
        .unwrap_or_default();

    let coords_attr = format!(
        " rect=\"{},{},{},{}\"",
        node.rect.x, node.rect.y, node.rect.width, node.rect.height
    );

    let mut state_attrs = String::new();
    if node.attributes.contains_key("disabled") {
        state_attrs.push_str(" disabled=\"true\"");
    }
    if node.attributes.contains_key("checked") {
        state_attrs.push_str(" checked=\"true\"");
    }
    if node.attributes.contains_key("selected") {
        state_attrs.push_str(" selected=\"true\"");
    }
    if node.attributes.contains_key("focused") {
        state_attrs.push_str(" focused=\"true\"");
    }
    if node.attributes.contains_key("expanded") {
        state_attrs.push_str(" expanded=\"true\"");
    }

    // [MODIFIED] Include som_attr in output (Fixed argument count mismatch)
    let mut output = format!(
        "{}<{} id=\"{}\"{}{}{}{}{}",
        indent_self, node.role, node.id, som_attr, name_attr, value_attr, state_attrs, coords_attr
    );

    if children_xml.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        output.push_str(&children_xml);
        output.push_str(&format!("{}</{}>\n", indent_self, node.role));
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
#[async_trait]
pub trait SovereignSubstrateProvider: Send + Sync {
    /// Retrieves a context slice authorized and filtered by the provided intent.
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        monitor_handle: u32,
    ) -> Result<ContextSlice>;
}

// --- Mock Implementation for Development/Testing ---
pub struct MockSubstrateProvider;

#[async_trait]
impl SovereignSubstrateProvider for MockSubstrateProvider {
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        _monitor_handle: u32,
    ) -> Result<ContextSlice> {
        // 1. Capture Raw Context (Simulated)
        let raw_tree = AccessibilityNode {
            id: "win-1".to_string(),
            role: "window".to_string(),
            name: Some("IOI Autopilot".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            is_visible: true,
            attributes: HashMap::new(), // [NEW] Init
            children: vec![
                AccessibilityNode {
                    id: "btn-1".to_string(),
                    role: "button".to_string(),
                    name: Some("Connect Wallet".to_string()),
                    value: None,
                    rect: Rect {
                        x: 100,
                        y: 100,
                        width: 200,
                        height: 50,
                    },
                    is_visible: true,
                    attributes: HashMap::from([(
                        "data-testid".to_string(),
                        "connect-wallet-btn".to_string(),
                    )]), // [NEW] Init with mock attr
                    som_id: None,
                    children: vec![],
                },
                // This node should be filtered out by logic if it has no content and isn't interactive
                AccessibilityNode {
                    id: "div-empty".to_string(),
                    role: "group".to_string(),
                    name: None,
                    value: None,
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 10,
                        height: 10,
                    },
                    is_visible: true,
                    attributes: HashMap::new(), // [NEW] Init
                    som_id: None,
                    children: vec![],
                },
                AccessibilityNode {
                    id: "ad-1".to_string(),
                    role: "frame".to_string(),
                    name: Some("Irrelevant Ads".to_string()),
                    value: None,
                    rect: Rect {
                        x: 1500,
                        y: 0,
                        width: 300,
                        height: 600,
                    },
                    is_visible: true,
                    attributes: HashMap::new(), // [NEW] Init
                    som_id: None,
                    children: vec![],
                },
            ],
            som_id: None,
        };

        // 2. Apply Intent-Constraint (The Filter)
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Generate Provenance Proof
        let intent_hash = intent.hash();
        let mut proof_input = xml_data.clone();
        proof_input.extend_from_slice(&intent_hash);

        let proof =
            sha256(&proof_input).map_err(|e| anyhow!("Provenance generation failed: {}", e))?;
        let mut proof_arr = [0u8; 32];
        let len = proof.as_ref().len().min(32);
        // Copy bytes manually
        proof_arr[..len].copy_from_slice(&proof.as_ref()[..len]);

        let slice_id = sha256(&xml_data).map_err(|e| anyhow!("Slice ID gen failed: {}", e))?;
        let mut slice_id_arr = [0u8; 32];
        let len = slice_id.as_ref().len().min(32);
        slice_id_arr[..len].copy_from_slice(&slice_id.as_ref()[..len]);

        Ok(ContextSlice {
            slice_id: slice_id_arr,
            frame_id: 0,
            chunks: vec![xml_data],
            mhnsw_root: [0u8; 32],
            traversal_proof: Some(proof.to_vec()),
            intent_id: intent_hash,
        })
    }
}
