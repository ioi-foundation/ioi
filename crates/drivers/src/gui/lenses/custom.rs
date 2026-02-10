// Path: crates/drivers/src/gui/lenses/custom.rs

use super::AppLens;
use crate::gui::accessibility::AccessibilityNode;
use serde::Deserialize;
use std::collections::HashMap;

/// Configuration for mapping a specific app's UI to semantic concepts.
#[derive(Debug, Clone, Deserialize)]
pub struct LensConfig {
    pub app_name: String,
    /// Map of "Semantic Name" -> "Element Selector"
    /// e.g. "trade_button" -> { role: "button", name_contains: "Execute" }
    pub mappings: HashMap<String, ElementSelector>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElementSelector {
    pub role: Option<String>,
    pub name_contains: Option<String>,
    pub id_pattern: Option<String>,
}

pub struct ConfigurableLens {
    config: LensConfig,
}

impl ConfigurableLens {
    pub fn new(config: LensConfig) -> Self {
        Self { config }
    }
}

impl AppLens for ConfigurableLens {
    fn name(&self) -> &str {
        &self.config.app_name
    }

    fn matches(&self, window_title: &str) -> bool {
        // Simple substring match for window title
        window_title
            .to_lowercase()
            .contains(&self.config.app_name.to_lowercase())
    }

    fn transform(&self, node: &AccessibilityNode) -> Option<AccessibilityNode> {
        // 1. Check if node matches any configured semantic mapping
        for (semantic_name, selector) in &self.config.mappings {
            let role_match = selector.role.as_ref().map_or(true, |r| node.role == *r);
            let name_match = selector.name_contains.as_ref().map_or(true, |n| {
                node.name.as_ref().map_or(false, |nn| nn.contains(n))
            });
            let id_match = selector
                .id_pattern
                .as_ref()
                .map_or(true, |p| node.id.contains(p));

            if role_match && name_match && id_match {
                let mut semantic_node = node.clone();

                // REWRITE the ID and Name to be Agent-Friendly
                // The agent will see <trade_button> instead of <button name="Execute">
                semantic_node
                    .attributes
                    .insert("semantic_role".to_string(), semantic_name.clone());
                // Crucial: Set a data-testid equivalent so the agent can select it easily
                semantic_node
                    .attributes
                    .insert("data-testid".to_string(), semantic_name.clone());

                return Some(semantic_node);
            }
        }

        // 2. Recursion (Standard tree traversal)
        let new_children: Vec<AccessibilityNode> = node
            .children
            .iter()
            .filter_map(|c| self.transform(c))
            .collect();

        // Pruning logic: If it's an empty, non-interactive container, drop it
        if new_children.is_empty() && !node.has_content() && !node.is_interactive() {
            return None;
        }

        let mut new_node = node.clone();
        new_node.children = new_children;
        Some(new_node)
    }

    fn render(&self, node: &AccessibilityNode, depth: usize) -> String {
        // If we found a semantic match, render a high-level XML tag
        if let Some(semantic) = node.attributes.get("semantic_role") {
            let indent = "  ".repeat(depth);
            // Example: <TradeButton id="win-1-42" rect="100,200,50,20" />
            return format!(
                "{}<{} id=\"{}\" rect=\"{},{},{},{}\" />\n",
                indent,
                semantic,
                node.id,
                node.rect.x,
                node.rect.y,
                node.rect.width,
                node.rect.height
            );
        }

        // Fallback to default rendering for non-semantic nodes
        crate::gui::accessibility::serialize_tree_to_xml(node, depth)
    }
}
