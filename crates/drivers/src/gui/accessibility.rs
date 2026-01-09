// Path: crates/drivers/src/gui/accessibility.rs

use anyhow::Result;
use serde::{Serialize, Deserialize};

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

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Serializes the accessibility tree into a simplified XML-like format optimized for LLM token usage.
/// 
/// Format example:
/// <window title="App">
///   <button label="Submit" x="100" y="200" w="50" h="30" />
/// </window>
pub fn serialize_tree_to_xml(node: &AccessibilityNode, depth: usize) -> String {
    if !node.is_visible {
        return String::new();
    }

    let indent = "  ".repeat(depth);
    let name_attr = node.name.as_ref().map(|n| format!(" name=\"{}\"", escape_xml(n))).unwrap_or_default();
    let value_attr = node.value.as_ref().map(|v| format!(" value=\"{}\"", escape_xml(v))).unwrap_or_default();
    let coords_attr = format!(" x=\"{}\" y=\"{}\" w=\"{}\" h=\"{}\"", node.rect.x, node.rect.y, node.rect.width, node.rect.height);
    
    let mut output = format!("{}<{} id=\"{}\"{}{}{}", indent, node.role, node.id, name_attr, value_attr, coords_attr);

    if node.children.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        for child in &node.children {
            output.push_str(&serialize_tree_to_xml(child, depth + 1));
        }
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

/// Abstract provider for fetching the OS accessibility tree.
/// In a real deployment, this would wrap platform-specific APIs (UIAutomation/AX/AT-SPI).
pub trait AccessibilityProvider {
    fn get_active_window_tree(&self) -> Result<AccessibilityNode>;
}

// --- Mock Implementation for Development/Testing ---
pub struct MockAccessibilityProvider;

impl AccessibilityProvider for MockAccessibilityProvider {
    fn get_active_window_tree(&self) -> Result<AccessibilityNode> {
        Ok(AccessibilityNode {
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
                }
            ],
        })
    }
}