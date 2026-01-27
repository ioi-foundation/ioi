// Path: crates/api/src/vm/drivers/gui.rs

use async_trait::async_trait;
use ioi_types::app::{ActionRequest, ContextSlice}; // [FIX] Import ContextSlice
use ioi_types::error::VmError;

/// Represents the type of mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Represents a physical input event to be injected into the OS.
#[derive(Debug, Clone, PartialEq)]
pub enum InputEvent {
    /// Move mouse to absolute coordinates (x, y).
    MouseMove { x: u32, y: u32 },
    /// Click a mouse button at specific coordinates.
    Click {
        button: MouseButton,
        x: u32,
        y: u32,
        /// NEW: Hash of the screen region expected at these coordinates.
        /// This enforces the "Atomic Vision-Action Lock" to prevent visual drift (TOCTOU).
        expected_visual_hash: Option<[u8; 32]>,
    },
    /// Press a mouse button down at specific coordinates (start of drag).
    MouseDown {
        button: MouseButton,
        x: u32,
        y: u32,
    },
    /// Release a mouse button at specific coordinates (end of drag).
    MouseUp {
        button: MouseButton,
        x: u32,
        y: u32,
    },
    /// Type text string.
    Type { text: String },
    /// Press a specific key (e.g., "Enter", "Ctrl").
    KeyPress { key: String },
    /// Scroll the view by dx, dy.
    Scroll { dx: i32, dy: i32 },
}

/// Abstract interface for an OS-level GUI driver (The "Eyes & Hands").
#[async_trait]
pub trait GuiDriver: Send + Sync {
    /// Captures the current visual state for the VLM.
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError>;

    /// Captures the semantic state (Accessibility Tree) for grounding.
    async fn capture_tree(&self) -> Result<String, VmError>;

    /// [NEW] Captures an intent-constrained slice of the context.
    /// This is the primary "Observe" method for the SCS.
    async fn capture_context(&self, intent: &ActionRequest) -> Result<ContextSlice, VmError>;

    /// Executes a physical input.
    /// MUST be gated by the Agency Firewall before calling.
    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError>;
}