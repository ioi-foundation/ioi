// Path: crates/drivers/src/gui/operator.rs

use super::vision::NativeVision;
use anyhow::{anyhow, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
// [NEW] pHash imports
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton as ApiButton};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
// [NEW] Import for events
use ioi_types::app::KernelEvent;
use tokio::sync::broadcast::Sender;
use xcap::Monitor; // [NEW] For DPI awareness

/// A native driver for controlling mouse and keyboard input.
pub struct NativeOperator {
    enigo: Mutex<Enigo>,
    event_sender: Option<Sender<KernelEvent>>, // [NEW]
}

impl NativeOperator {
    pub fn new() -> Self {
        let enigo = Enigo::new(&Settings::default()).expect("Failed to initialize Enigo");
        Self {
            enigo: Mutex::new(enigo),
            event_sender: None,
        }
    }

    // [NEW] Builder method to inject sender
    pub fn with_event_sender(mut self, sender: Sender<KernelEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Computes a Perceptual Hash (Gradient) of the image bytes.
    /// Returns a 32-byte array containing the 8-byte hash (padded).
    fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32]> {
        let img = load_from_memory(image_bytes)?;
        let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
        let hash = hasher.hash_image(&img);
        let hash_bytes = hash.as_bytes();

        let mut out = [0u8; 32];
        let len = hash_bytes.len().min(32);
        // dcrypt is available in dev-deps or deps, assuming available via ioi-crypto re-export or direct use
        // If not, we use manual copy.
        out[..len].copy_from_slice(&hash_bytes[..len]);
        Ok(out)
    }

    /// Calculates Hamming distance between two 8-byte hashes stored in 32-byte arrays.
    fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
        let mut dist = 0;
        // pHash is typically 64 bits (8 bytes). We compare the first 8 bytes.
        for i in 0..8 {
            let xor = a[i] ^ b[i];
            dist += xor.count_ones();
        }
        dist
    }

    /// Executes a verified input event.
    pub fn inject(&self, event: &InputEvent) -> Result<()> {
        let mut enigo = self
            .enigo
            .lock()
            .map_err(|_| anyhow!("Enigo lock poisoned"))?;
        
        // [FIX] Removed scale factor multiplication.
        // The LLM sees the raw screenshot pixels (physical resolution).
        // enigo (on Linux/X11/Wayland) typically expects physical coordinates or handles scaling internally.
        // Double-applying the scale factor causes clicks to drift off-target.
        // We log the dimensions for debugging.
        let monitors = Monitor::all().unwrap_or_default();
        if let Some(m) = monitors.first() {
             log::debug!(target: "driver", "Primary Monitor: {}x{} (Scale: {})", m.width(), m.height(), m.scale_factor());
        }

        // We act on pixels 1:1.
        let scale_factor = 1.0; 

        match event {
            InputEvent::MouseMove { x, y } => {
                let abs_x = (*x as f64 * scale_factor) as i32;
                let abs_y = (*y as f64 * scale_factor) as i32;

                log::info!(target: "driver", "MouseMove -> {}, {}", abs_x, abs_y);

                enigo
                    .move_mouse(abs_x, abs_y, Coordinate::Abs)
                    .map_err(|e| anyhow!("Mouse move failed: {:?}", e))?;
            }
            InputEvent::Click {
                button,
                x,
                y,
                expected_visual_hash,
            } => {
                // 1. ATOMIC VISION CHECK (Robust pHash)
                if let Some(expected) = expected_visual_hash {
                    let full_screen_png = NativeVision::capture_primary()?;
                    let current_hash = Self::compute_phash(&full_screen_png)?;

                    // [NEW] Use Hamming Distance instead of exact match
                    let dist = Self::hamming_distance(&current_hash, expected);

                    // Threshold: 5 bits out of 64 (allows for minor clock changes, cursor blink)
                    if dist > 5 {
                        return Err(anyhow!(
                            "Visual Drift Detected! Hamming distance {} > 5. Screen state changed too much.", 
                            dist
                        ));
                    }
                }

                // 2. Move to target with scaling
                let abs_x = (*x as f64 * scale_factor) as i32;
                let abs_y = (*y as f64 * scale_factor) as i32;

                log::info!(target: "driver", "Click -> {}, {} (Button: {:?})", abs_x, abs_y, button);

                enigo
                    .move_mouse(abs_x, abs_y, Coordinate::Abs)
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
                log::info!(target: "driver", "Type -> \"{}\"", text);
                enigo
                    .text(text)
                    .map_err(|e| anyhow!("Type failed: {:?}", e))?;
            }
            InputEvent::KeyPress { key } => {
                log::info!(target: "driver", "KeyPress -> {}", key);
                if key == "Enter" {
                    enigo
                        .key(Key::Return, Direction::Click)
                        .map_err(|e| anyhow!("Key press failed: {:?}", e))?;
                }
            }
            InputEvent::Scroll { dx: _, dy } => {
                enigo
                    .scroll(*dy, Axis::Vertical)
                    .map_err(|e| anyhow!("Scroll failed: {:?}", e))?;
            }
        }

        // [NEW] Emit GhostInput event for feedback loop
        if let Some(tx) = &self.event_sender {
            let desc = format!("{:?}", event);
            let _ = tx.send(KernelEvent::GhostInput {
                device: "gui".into(),
                description: desc,
            });
        }

        thread::sleep(Duration::from_millis(10));
        Ok(())
    }
}