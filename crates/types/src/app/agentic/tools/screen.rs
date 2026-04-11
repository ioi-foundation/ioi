use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Actions available via the Screen meta-tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ScreenAction {
    /// Type text.
    #[serde(rename = "type")]
    Type {
        /// Text to type.
        text: String,
    },

    /// Press a key.
    #[serde(rename = "key")]
    Key {
        /// Key name.
        text: String,
    },

    /// Execute a keyboard shortcut (Chord).
    #[serde(rename = "hotkey")]
    Hotkey {
        /// Sequence of keys to press. Modifiers first.
        keys: Vec<String>,
    },

    /// Move mouse cursor.
    MouseMove {
        /// Coordinates [x, y].
        coordinate: [u32; 2],
    },

    /// Click left mouse button.
    #[serde(rename = "left_click")]
    LeftClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Click right mouse button.
    #[serde(rename = "right_click")]
    RightClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Double-click left mouse button.
    #[serde(rename = "double_click")]
    DoubleClick {
        /// Optional coordinates for stateless execution.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
    },

    /// Click a specific element by its Set-of-Marks numeric tag.
    /// Visual Mode Only.
    #[serde(rename = "left_click_id")]
    LeftClickId {
        /// The unique numeric tag from the visual overlay.
        id: u32,
    },

    /// Click a specific element by its semantic ID string.
    #[serde(rename = "left_click_element")]
    LeftClickElement {
        /// The element ID string.
        id: String,
    },

    /// Right-click a specific element by its Set-of-Marks numeric tag.
    /// Visual Mode Only.
    #[serde(rename = "right_click_id")]
    RightClickId {
        /// The unique numeric tag from the visual overlay.
        id: u32,
    },

    /// Right-click a specific element by its semantic ID string.
    #[serde(rename = "right_click_element")]
    RightClickElement {
        /// The element ID string.
        id: String,
    },

    /// Click and drag (Stateful/Relative).
    LeftClickDrag {
        /// Coordinates [x, y].
        coordinate: [u32; 2],
    },

    /// Explicit Drag and Drop (Stateless/Absolute).
    #[serde(rename = "drag_drop")]
    DragDrop {
        /// Start coordinates [x, y].
        from: [u32; 2],
        /// End coordinates [x, y].
        to: [u32; 2],
    },

    /// Drag and drop by Set-of-Marks numeric IDs.
    #[serde(rename = "drag_drop_id")]
    DragDropId {
        /// Start SoM ID.
        from_id: u32,
        /// End SoM ID.
        to_id: u32,
    },

    /// Drag and drop by semantic element IDs.
    #[serde(rename = "drag_drop_element")]
    DragDropElement {
        /// Start semantic element ID.
        from_id: String,
        /// End semantic element ID.
        to_id: String,
    },

    /// Take a screenshot.
    Screenshot,

    /// Get cursor position.
    CursorPosition,

    /// Scroll the mouse wheel.
    Scroll {
        /// Optional coordinates [x, y] to move mouse before scrolling.
        #[serde(default)]
        coordinate: Option<[u32; 2]>,
        /// Scroll delta [dx, dy]. Positive dy = down, positive dx = right.
        delta: [i32; 2],
    },
}
