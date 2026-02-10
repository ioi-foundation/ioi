// Path: crates/drivers/src/gui/lenses/mod.rs

use crate::gui::accessibility::AccessibilityNode;

pub mod auto;
pub mod custom; // [NEW]
pub mod react; // [NEW] Register AutoLens

/// A strategy for distilling a raw accessibility tree into semantic XML for a specific application.
pub trait AppLens: Send + Sync {
    /// Returns the unique ID of this lens (e.g., "react_semantic", "vscode_electron").
    fn name(&self) -> &str;

    /// Checks if this lens applies to the current window context.
    fn matches(&self, window_title: &str) -> bool;

    /// Filters and transforms the tree.
    /// Returns `None` if the node should be pruned entirely.
    ///
    /// This is the core logic for "LiDAR" processing: converting raw OS nodes
    /// into semantic entities.
    fn transform(&self, node: &AccessibilityNode) -> Option<AccessibilityNode>;

    /// Custom XML serialization logic for this lens.
    /// Allows injecting app-specific tags (e.g., <Component prop="..."/>) instead
    /// of generic OS roles.
    fn render(&self, node: &AccessibilityNode, depth: usize) -> String;
}

/// A registry to manage and select the appropriate lens for a given context.
pub struct LensRegistry {
    lenses: Vec<Box<dyn AppLens>>,
}

impl LensRegistry {
    pub fn new() -> Self {
        Self { lenses: Vec::new() }
    }

    /// Registers a new lens.
    /// Lenses are checked in order of registration; first match wins.
    pub fn register(&mut self, lens: Box<dyn AppLens>) {
        self.lenses.push(lens);
    }

    /// Selects the best lens for the current window title.
    pub fn select(&self, window_title: &str) -> Option<&dyn AppLens> {
        // 1. Try specific lenses first (e.g., React, specialized Calculator).
        // Keep universal heuristic as fallback-only to avoid preempting app-specific lenses.
        if let Some(specific) = self
            .lenses
            .iter()
            .find(|l| !l.name().starts_with("universal_heuristic") && l.matches(window_title))
        {
            return Some(specific.as_ref());
        }

        // 2. Fallback to AutoLens (The "Intelligent" Default)
        // Match both v2/v3 naming so fallback is resilient across upgrades.
        self.lenses
            .iter()
            .find(|l| l.name().starts_with("universal_heuristic"))
            .map(|b| b.as_ref())
    }

    /// [NEW] Retrieve a specific lens by name.
    /// Used by the Executor to apply the exact same transformation used during Perception.
    pub fn get(&self, name: &str) -> Option<&dyn AppLens> {
        self.lenses
            .iter()
            .find(|l| l.name() == name)
            .map(|b| b.as_ref())
    }
}
