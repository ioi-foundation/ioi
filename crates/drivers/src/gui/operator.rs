// Path: crates/drivers/src/gui/operator.rs

use super::vision::NativeVision;
use anyhow::{anyhow, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_api::vm::drivers::gui::{InputEvent, AtomicInput, MouseButton as ApiButton};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use ioi_types::app::KernelEvent;
use tokio::sync::broadcast::Sender;
use xcap::Monitor;

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

    pub fn with_event_sender(mut self, sender: Sender<KernelEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

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

    fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
        let mut dist = 0;
        for i in 0..8 {
            let xor = a[i] ^ b[i];
            dist += xor.count_ones();
        }
        dist
    }

    pub fn get_scale_factor() -> f64 {
        let monitors = Monitor::all().unwrap_or_default();
        if let Some(m) = monitors.first() {
            return m.scale_factor() as f64;
        }
        1.0
    }

    fn map_button(btn: ApiButton) -> Button {
        match btn {
            ApiButton::Left => Button::Left,
            ApiButton::Right => Button::Right,
            ApiButton::Middle => Button::Middle,
        }
    }

    fn map_key(key: &str) -> Result<Key> {
        match key.to_lowercase().as_str() {
            "enter" | "return" => Ok(Key::Return),
            "tab" => Ok(Key::Tab),
            "escape" | "esc" => Ok(Key::Escape),
            "backspace" => Ok(Key::Backspace),
            "control" | "ctrl" => Ok(Key::Control),
            "shift" => Ok(Key::Shift),
            "alt" | "option" => Ok(Key::Alt),
            "meta" | "command" | "super" | "windows" => Ok(Key::Meta),
            "delete" | "del" => Ok(Key::Delete),
            "space" => Ok(Key::Space),
            "up" => Ok(Key::UpArrow),
            "down" => Ok(Key::DownArrow),
            "left" => Ok(Key::LeftArrow),
            "right" => Ok(Key::RightArrow),
            _ => {
                if key.len() == 1 {
                     Ok(Key::Unicode(key.chars().next().unwrap()))
                } else {
                     Err(anyhow!("Unsupported key: {}", key))
                }
            }
        }
    }

    pub fn inject(&self, event: &InputEvent) -> Result<()> {
        let mut enigo = self.enigo.lock().map_err(|_| anyhow!("Enigo lock poisoned"))?;
        let scale = Self::get_scale_factor();

        let normalize_coord = |val: u32| -> i32 {
            if cfg!(target_os = "macos") {
                (val as f64 / scale) as i32
            } else if cfg!(target_os = "windows") {
                 (val as f64 / scale) as i32
            } else {
                 val as i32
            }
        };

        match event {
            InputEvent::MouseMove { x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::Click { button, x, y, expected_visual_hash } => {
                if let Some(expected) = expected_visual_hash {
                    let full_screen_png = NativeVision::capture_primary()?;
                    let current_hash = Self::compute_phash(&full_screen_png)?;
                    let dist = Self::hamming_distance(&current_hash, expected);
                    if dist > 5 {
                         if let Some(tx) = &self.event_sender {
                             let _ = tx.send(KernelEvent::FirewallInterception {
                                 verdict: "BLOCK".to_string(),
                                 target: "gui::click".to_string(),
                                 request_hash: [0u8; 32],
                                 session_id: None,
                             });
                         }
                        return Err(anyhow!("Visual Drift Detected! Hamming distance {} > 5.", dist));
                    }
                }
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!("{:?}", e))?;
                let btn = Self::map_button(*button);
                enigo.button(btn, Direction::Click).map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::MouseDown { button, x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!("{:?}", e))?;
                let btn = Self::map_button(*button);
                enigo.button(btn, Direction::Press).map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::MouseUp { button, x, y } => {
                let abs_x = normalize_coord(*x);
                let abs_y = normalize_coord(*y);
                enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!("{:?}", e))?;
                let btn = Self::map_button(*button);
                enigo.button(btn, Direction::Release).map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::Type { text } => {
                enigo.text(text).map_err(|e| anyhow!("Type failed: {:?}", e))?;
            }
            InputEvent::KeyPress { key } => {
                let k = Self::map_key(key)?;
                enigo.key(k, Direction::Click).map_err(|e| anyhow!("Key press failed: {:?}", e))?;
            }
            InputEvent::Scroll { dy, .. } => {
                enigo.scroll(*dy, Axis::Vertical).map_err(|e| anyhow!("Scroll failed: {:?}", e))?;
            }
            
            // [NEW] Atomic Sequence Execution Implementation
            InputEvent::AtomicSequence(steps) => {
                log::info!(target: "driver", "Executing Atomic Sequence ({} steps)", steps.len());
                for step in steps {
                    match step {
                        AtomicInput::MouseMove { x, y } => {
                            let abs_x = normalize_coord(*x);
                            let abs_y = normalize_coord(*y);
                            enigo.move_mouse(abs_x, abs_y, Coordinate::Abs).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::MouseDown { button } => {
                            let btn = Self::map_button(*button);
                            enigo.button(btn, Direction::Press).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::MouseUp { button } => {
                            let btn = Self::map_button(*button);
                            enigo.button(btn, Direction::Release).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::KeyPress { key } => {
                            let k = Self::map_key(key)?;
                            enigo.key(k, Direction::Click).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::KeyDown { key } => {
                            let k = Self::map_key(key)?;
                            enigo.key(k, Direction::Press).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::KeyUp { key } => {
                            let k = Self::map_key(key)?;
                            enigo.key(k, Direction::Release).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::Type { text } => {
                             enigo.text(text).map_err(|e| anyhow!("{:?}", e))?;
                        },
                        AtomicInput::Wait { millis } => {
                             thread::sleep(Duration::from_millis(*millis));
                        }
                    }
                    // Small micro-sleep between atomic steps to ensure OS event loop catch-up
                    thread::sleep(Duration::from_millis(5));
                }
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