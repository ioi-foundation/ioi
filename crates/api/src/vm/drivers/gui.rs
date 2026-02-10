// Path: crates/api/src/vm/drivers/gui.rs

use async_trait::async_trait;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the type of mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Lightweight input primitives for batch execution.
/// These are designed to be executed in a tight loop without IPC overhead per step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AtomicInput {
    /// Move mouse to absolute coordinates.
    MouseMove { x: u32, y: u32 },
    /// Press a mouse button.
    MouseDown { button: MouseButton },
    /// Release a mouse button.
    MouseUp { button: MouseButton },
    /// Press a specific key (click: down + up).
    KeyPress { key: String },
    /// Hold a key down (for chords).
    KeyDown { key: String },
    /// Release a key.
    KeyUp { key: String },
    /// Type a string of text.
    Type { text: String },
    /// Wait for a specified duration in milliseconds.
    Wait { millis: u64 },
}

/// Represents a physical input event to be injected into the OS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Move mouse to absolute coordinates (x, y).
    MouseMove { x: u32, y: u32 },
    /// Click a mouse button at specific coordinates.
    Click {
        button: MouseButton,
        x: u32,
        y: u32,
        /// Hash of the screen region expected at these coordinates.
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

    /// Execute a sequence of inputs atomically (e.g., Drag-and-Drop, Copy-Paste).
    /// This ensures the sequence completes without interruption or latency gaps.
    AtomicSequence(Vec<AtomicInput>),
}

/// Abstract interface for an OS-level GUI driver (The "Eyes & Hands").
#[async_trait]
pub trait GuiDriver: Send + Sync {
    /// Captures the current visual state for the VLM.
    /// 
    /// # Arguments
    /// * `crop_rect` - Optional tuple of (x, y, width, height) to crop the screenshot.
    ///                 Coordinates are relative to the primary monitor origin.
    async fn capture_screen(&self, crop_rect: Option<(i32, i32, u32, u32)>) -> Result<Vec<u8>, VmError>;

    /// [NEW] Captures the raw screen image without any overlays or redaction.
    /// Used for manual compositing in the perception layer.
    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError>;

    /// Captures the semantic state (Accessibility Tree) for grounding.
    async fn capture_tree(&self) -> Result<String, VmError>;

    /// Captures an intent-constrained slice of the context.
    async fn capture_context(&self, intent: &ActionRequest) -> Result<ContextSlice, VmError>;

    /// Executes a physical input.
    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError>;

    /// Resolves a Set-of-Marks ID from the last capture to screen coordinates.
    async fn get_element_center(&self, id: u32) -> Result<Option<(u32, u32)>, VmError>;

    /// Manually injects a Set-of-Marks mapping (ID -> Rect) into the driver's cache.
    /// This restores context from a previous step or external source.
    /// Returns VmError::Unsupported if not implemented.
    async fn register_som_overlay(&self, _map: HashMap<u32, (i32, i32, i32, i32)>) -> Result<(), VmError> {
        Err(VmError::HostError("SoM overlay registration not supported by this driver".into()))
    }
}