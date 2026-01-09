// Path: crates/drivers/src/gui/operator.rs

// [FIX] Updated imports for Enigo 0.2, added Axis
use super::vision::NativeVision;
use anyhow::{anyhow, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton as ApiButton};
use ioi_crypto::algorithms::hash::sha256;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// A native driver for controlling mouse and keyboard input.
pub struct NativeOperator {
    enigo: Mutex<Enigo>,
}

impl NativeOperator {
    pub fn new() -> Self {
        let enigo = Enigo::new(&Settings::default()).expect("Failed to initialize Enigo");
        Self {
            enigo: Mutex::new(enigo),
        }
    }

    /// Executes a verified input event.
    pub fn inject(&self, event: &InputEvent) -> Result<()> {
        let mut enigo = self
            .enigo
            .lock()
            .map_err(|_| anyhow!("Enigo lock poisoned"))?;

        match event {
            InputEvent::MouseMove { x, y } => {
                enigo
                    .move_mouse(*x as i32, *y as i32, Coordinate::Abs)
                    .map_err(|e| anyhow!("Mouse move failed: {:?}", e))?;
            }
            InputEvent::Click {
                button,
                x,
                y,
                expected_visual_hash,
            } => {
                // 1. ATOMIC VISION CHECK
                if let Some(expected) = expected_visual_hash {
                    let full_screen_png = NativeVision::capture_primary()?;
                    let current_hash_vec = sha256(&full_screen_png)?;

                    if current_hash_vec.as_slice() != expected {
                        return Err(anyhow!("Visual Drift Detected! Screen state changed between observation and action."));
                    }
                }

                // 2. Move to target
                enigo
                    .move_mouse(*x as i32, *y as i32, Coordinate::Abs)
                    .map_err(|e| anyhow!("Mouse move failed: {:?}", e))?;

                // 3. Perform Click
                let btn = match button {
                    ApiButton::Left => Button::Left,
                    ApiButton::Right => Button::Right,
                    ApiButton::Middle => Button::Middle,
                };
                enigo
                    .button(btn, Direction::Click)
                    .map_err(|e| anyhow!("Click failed: {:?}", e))?;
            }
            InputEvent::Type { text } => {
                enigo
                    .text(text)
                    .map_err(|e| anyhow!("Type failed: {:?}", e))?;
            }
            InputEvent::KeyPress { key } => {
                if key == "Enter" {
                    enigo
                        .key(Key::Return, Direction::Click)
                        .map_err(|e| anyhow!("Key press failed: {:?}", e))?;
                }
            }
            InputEvent::Scroll { dx: _, dy } => {
                // [FIX] Use Axis::Vertical for y scroll
                enigo
                    .scroll(*dy, Axis::Vertical)
                    .map_err(|e| anyhow!("Scroll failed: {:?}", e))?;
            }
        }

        thread::sleep(Duration::from_millis(10));
        Ok(())
    }
}
