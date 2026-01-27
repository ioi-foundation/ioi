// Path: crates/drivers/src/gui/operator.rs

use super::vision::NativeVision;
use anyhow::{anyhow, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton as ApiButton};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use ioi_types::app::KernelEvent;
use tokio::sync::broadcast::Sender;
use xcap::Monitor;
use dcrypt::algorithms::ByteSerializable;

/// A native driver for controlling mouse and keyboard input.
pub struct NativeOperator {
    enigo: Mutex<Enigo>,
    event_sender: Option<Sender<KernelEvent>>,
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
    fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32]> {
        let img = load_from_memory(image_bytes)?;
        let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
        let hash = hasher.hash_image(&img);
        let hash_bytes = hash.as_bytes();

        let mut out = [0u8; 32];
        let len = hash_bytes.len().min(32);
        out[..len].copy_from_slice(&hash_bytes[..len]);
        Ok(out)
    }

    /// Calculates Hamming distance between two 8-byte hashes stored in 32-byte arrays.
    fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
        let mut dist = 0;
        for i in 0..8 {
            let xor = a[i] ^ b[i];
            dist += xor.count_ones();
        }
        dist
    }

    /// Gets the scale factor of the primary monitor to handle HiDPI (Retina) screens.
    pub fn get_scale_factor() -> f64 {
        let monitors = Monitor::all().unwrap_or_default();
        if let Some(m) = monitors.first() {
            return m.scale_factor();
        }
        1.0
    }

    /// Maps the abstract MouseButton enum to the Enigo concrete type.
    fn map_button(btn: ApiButton) -> Button {
        match btn {
            ApiButton::Left => Button::Left,
            ApiButton::Right => Button::Right,
            ApiButton::Middle => Button::Middle,
        }
    }

    /// Executes a verified input event.
    pub fn inject(&self, event: &InputEvent) -> Result<()> {
        let mut enigo = self
            .enigo
            .lock()
            .map_err(|_| anyhow!("Enigo lock poisoned"))?;
        
        // [FIX] Apply DPI Scaling
        // Coordinates from LLM/VLM are usually based on the screenshot pixels (physical).
        // OS Input APIs vary:
        // - macOS: Uses Logical points (Pixels / Scale).
        // - Windows/Linux: Often physical pixels, but depends on DE.
        // We normalize to the OS expected coordinate system here.
        let scale = Self::get_scale_factor();

        let normalize_coord = |val: u32| -> i32 {
            if cfg!(target_os = "macos") {
                (val as f64 / scale) as i32
            } else {
                val as i32
            }
        };

        match event {
            InputEvent::MouseMove { x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);

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
                // 1. ATOMIC VISUAL INTERLOCK (Robust pHash)
                // This prevents TOCTOU attacks where the UI changes between "Think" and "Act".
                if let Some(expected) = expected_visual_hash {
                    // Capture FRESH state immediately before clicking
                    let full_screen_png = NativeVision::capture_primary()?;
                    let current_hash = Self::compute_phash(&full_screen_png)?;
                    let dist = Self::hamming_distance(&current_hash, expected);

                    // Threshold: 5 bits out of 64 (allows for minor clock changes, cursor blink)
                    if dist > 5 {
                         // Emit "Blocked" event for visualization in VisionHUD
                         if let Some(tx) = &self.event_sender {
                             let _ = tx.send(KernelEvent::FirewallInterception {
                                 verdict: "BLOCK".to_string(),
                                 target: "gui::click".to_string(),
                                 request_hash: [0u8; 32], // Dummy hash, this is a runtime check
                                 session_id: None,
                             });
                         }

                        return Err(anyhow!(
                            "Visual Drift Detected! Hamming distance {} > 5. Screen state changed too much (Popup? Ad? Navigation?). Aborting click for safety.", 
                            dist
                        ));
                    }
                }

                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);

                log::info!(target: "driver", "Click -> {}, {} (Button: {:?})", abs_x, abs_y, button);

                enigo
                    .move_mouse(abs_x, abs_y, Coordinate::Abs)
                    .map_err(|e| anyhow!("Mouse move failed: {:?}", e))?;

                let btn = Self::map_button(*button);
                enigo
                    .button(btn, Direction::Click)
                    .map_err(|e| anyhow!("Click failed: {:?}", e))?;
            }
            InputEvent::MouseDown { button, x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                log::info!(target: "driver", "MouseDown -> {}, {}", abs_x, abs_y);
                
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!(e))?;
                let btn = Self::map_button(*button);
                enigo.button(btn, Direction::Press).map_err(|e| anyhow!(e))?;
            }
            InputEvent::MouseUp { button, x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                log::info!(target: "driver", "MouseUp -> {}, {}", abs_x, abs_y);
                
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!(e))?;
                let btn = Self::map_button(*button);
                enigo.button(btn, Direction::Release).map_err(|e| anyhow!(e))?;
            }
            InputEvent::Type { text } => {
                log::info!(target: "driver", "Type -> \"{}\"", text);
                enigo
                    .text(text)
                    .map_err(|e| anyhow!("Type failed: {:?}", e))?;
            }
            InputEvent::KeyPress { key } => {
                log::info!(target: "driver", "KeyPress -> {}", key);
                // Basic mapping for common keys
                let k = match key.as_str() {
                    "Enter" | "Return" => Key::Return,
                    "Tab" => Key::Tab,
                    "Escape" => Key::Escape,
                    "Backspace" => Key::Backspace,
                    _ => {
                        // If it's a single char, just text it
                        if key.len() == 1 {
                             enigo.text(key).map_err(|e| anyhow!(e))?;
                             return Ok(());
                        }
                        return Err(anyhow!("Unsupported key: {}", key));
                    }
                };
                enigo.key(k, Direction::Click).map_err(|e| anyhow!("Key press failed: {:?}", e))?;
            }
            InputEvent::Scroll { dx: _, dy } => {
                enigo
                    .scroll(*dy, Axis::Vertical)
                    .map_err(|e| anyhow!("Scroll failed: {:?}", e))?;
            }
        }

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