// Path: crates/drivers/src/gui/operator.rs

use super::geometry::{CoordinateSpace, DisplayTransform, Point};
use super::vision::NativeVision;
use anyhow::{anyhow, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton as ApiButton};
use ioi_types::app::KernelEvent;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast::Sender;
use xcap::Monitor;

pub struct NativeOperator {
    enigo: Mutex<Enigo>,
    event_sender: Option<Sender<KernelEvent>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ClickTarget {
    /// Normalized [0.0, 1.0] coordinates from a vision model.
    Normalized(f64, f64),
    /// Semantic IDs must be resolved before the hardware layer.
    SemanticId(u32),
    /// Explicit screen-logical point.
    Exact(Point),
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

    pub fn current_display_transform() -> DisplayTransform {
        let monitors = Monitor::all().unwrap_or_default();
        if let Some(monitor) = monitors.first() {
            let scale = (monitor.scale_factor() as f64).max(1.0);
            let image_width = ((monitor.width() as f64) * scale).round().max(1.0) as u32;
            let image_height = ((monitor.height() as f64) * scale).round().max(1.0) as u32;
            return DisplayTransform::new(
                scale,
                Point::new(0.0, 0.0, CoordinateSpace::ScreenLogical),
                Point::new(
                    (monitor.x() as f64) * scale,
                    (monitor.y() as f64) * scale,
                    CoordinateSpace::ImagePhysical,
                ),
                image_width,
                image_height,
            );
        }
        DisplayTransform::new(
            1.0,
            Point::new(0.0, 0.0, CoordinateSpace::ScreenLogical),
            Point::new(0.0, 0.0, CoordinateSpace::ImagePhysical),
            1,
            1,
        )
    }

    fn screen_logical_to_enigo_abs(pt: Point, transform: &DisplayTransform) -> (i32, i32) {
        assert_eq!(pt.space, CoordinateSpace::ScreenLogical);
        if cfg!(target_os = "linux") {
            (
                (pt.x * transform.scale_factor).round() as i32,
                (pt.y * transform.scale_factor).round() as i32,
            )
        } else {
            (pt.x.round() as i32, pt.y.round() as i32)
        }
    }

    fn move_mouse_to_point(
        enigo: &mut Enigo,
        pt: Point,
        transform: &DisplayTransform,
    ) -> Result<()> {
        let (abs_x, abs_y) = Self::screen_logical_to_enigo_abs(pt, transform);
        enigo
            .move_mouse(abs_x, abs_y, Coordinate::Abs)
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(())
    }

    fn inject_scroll(enigo: &mut Enigo, dx: i32, dy: i32) -> Result<()> {
        if dy != 0 {
            enigo
                .scroll(dy, Axis::Vertical)
                .map_err(|e| anyhow!("Vertical scroll failed: {:?}", e))?;
        }

        if dx != 0 {
            enigo
                .scroll(dx, Axis::Horizontal)
                .map_err(|e| anyhow!("Horizontal scroll failed: {:?}", e))?;
        }

        Ok(())
    }

    pub fn resolve_click_target(
        target: ClickTarget,
        transform: &DisplayTransform,
    ) -> Result<Point> {
        match target {
            ClickTarget::Normalized(nx, ny) => {
                let (norm_x, norm_y) = if nx > 1.0 || ny > 1.0 {
                    (nx / 1000.0, ny / 1000.0)
                } else {
                    (nx, ny)
                };
                Ok(transform.normalized_to_screen(norm_x, norm_y))
            }
            ClickTarget::Exact(pt) => {
                if pt.space != CoordinateSpace::ScreenLogical {
                    return Err(anyhow!(
                        "Exact click coordinates must be ScreenLogical, got {:?}",
                        pt.space
                    ));
                }
                Ok(pt)
            }
            ClickTarget::SemanticId(id) => Err(anyhow!(
                "Semantic ID {} must be resolved before NativeOperator::inject_click",
                id
            )),
        }
    }

    fn inject_click_locked(
        &self,
        enigo: &mut Enigo,
        button: ApiButton,
        target: ClickTarget,
        transform: &DisplayTransform,
        expected_visual_hash: Option<[u8; 32]>,
    ) -> Result<Point> {
        // Tolerate minor UI churn (clock tick, caret blink, tiny repaint noise)
        // while still blocking materially different screens.
        const DRIFT_THRESHOLD: u32 = 32;

        if let Some(expected) = expected_visual_hash {
            let full_screen_png = NativeVision::capture_primary()?;
            let current_hash = Self::compute_phash(&full_screen_png)?;
            let dist = Self::hamming_distance(&current_hash, &expected);
            if dist > DRIFT_THRESHOLD {
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::FirewallInterception {
                        verdict: "BLOCK".to_string(),
                        target: "gui::click".to_string(),
                        request_hash: [0u8; 32],
                        session_id: None,
                    });
                }
                return Err(anyhow!(
                    "Visual Drift Detected! Hamming distance {} > {}.",
                    dist,
                    DRIFT_THRESHOLD
                ));
            }
        }

        let logical_point = Self::resolve_click_target(target, transform)?;
        Self::move_mouse_to_point(enigo, logical_point, transform)?;
        let btn = Self::map_button(button);
        enigo
            .button(btn, Direction::Click)
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(logical_point)
    }

    pub fn inject_click(
        &self,
        button: ApiButton,
        target: ClickTarget,
        transform: &DisplayTransform,
        expected_visual_hash: Option<[u8; 32]>,
    ) -> Result<Point> {
        let mut enigo = self
            .enigo
            .lock()
            .map_err(|_| anyhow!("Enigo lock poisoned"))?;
        self.inject_click_locked(&mut enigo, button, target, transform, expected_visual_hash)
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
        let mut enigo = self
            .enigo
            .lock()
            .map_err(|_| anyhow!("Enigo lock poisoned"))?;
        let transform = Self::current_display_transform();

        match event {
            InputEvent::MouseMove { x, y } => {
                let pt = Point::new(*x as f64, *y as f64, CoordinateSpace::ScreenLogical);
                Self::move_mouse_to_point(&mut enigo, pt, &transform)?;
            }
            InputEvent::Click {
                button,
                x,
                y,
                expected_visual_hash,
            } => {
                let target = ClickTarget::Exact(Point::new(
                    *x as f64,
                    *y as f64,
                    CoordinateSpace::ScreenLogical,
                ));
                self.inject_click_locked(
                    &mut enigo,
                    *button,
                    target,
                    &transform,
                    *expected_visual_hash,
                )?;
            }
            InputEvent::MouseDown { button, x, y } => {
                let pt = Point::new(*x as f64, *y as f64, CoordinateSpace::ScreenLogical);
                Self::move_mouse_to_point(&mut enigo, pt, &transform)?;
                let btn = Self::map_button(*button);
                enigo
                    .button(btn, Direction::Press)
                    .map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::MouseUp { button, x, y } => {
                let pt = Point::new(*x as f64, *y as f64, CoordinateSpace::ScreenLogical);
                Self::move_mouse_to_point(&mut enigo, pt, &transform)?;
                let btn = Self::map_button(*button);
                enigo
                    .button(btn, Direction::Release)
                    .map_err(|e| anyhow!("{:?}", e))?;
            }
            InputEvent::Type { text } => {
                enigo
                    .text(text)
                    .map_err(|e| anyhow!("Type failed: {:?}", e))?;
            }
            InputEvent::KeyPress { key } => {
                let k = Self::map_key(key)?;
                enigo
                    .key(k, Direction::Click)
                    .map_err(|e| anyhow!("Key press failed: {:?}", e))?;
            }
            InputEvent::Scroll { dx, dy } => Self::inject_scroll(&mut enigo, *dx, *dy)?,

            // [NEW] Atomic Sequence Execution Implementation
            InputEvent::AtomicSequence(steps) => {
                log::info!(target: "driver", "Executing Atomic Sequence ({} steps)", steps.len());
                for step in steps {
                    match step {
                        AtomicInput::MouseMove { x, y } => {
                            let pt =
                                Point::new(*x as f64, *y as f64, CoordinateSpace::ScreenLogical);
                            Self::move_mouse_to_point(&mut enigo, pt, &transform)?;
                        }
                        AtomicInput::MouseDown { button } => {
                            let btn = Self::map_button(*button);
                            enigo
                                .button(btn, Direction::Press)
                                .map_err(|e| anyhow!("{:?}", e))?;
                        }
                        AtomicInput::MouseUp { button } => {
                            let btn = Self::map_button(*button);
                            enigo
                                .button(btn, Direction::Release)
                                .map_err(|e| anyhow!("{:?}", e))?;
                        }
                        AtomicInput::KeyPress { key } => {
                            let k = Self::map_key(key)?;
                            enigo
                                .key(k, Direction::Click)
                                .map_err(|e| anyhow!("{:?}", e))?;
                        }
                        AtomicInput::KeyDown { key } => {
                            let k = Self::map_key(key)?;
                            enigo
                                .key(k, Direction::Press)
                                .map_err(|e| anyhow!("{:?}", e))?;
                        }
                        AtomicInput::KeyUp { key } => {
                            let k = Self::map_key(key)?;
                            enigo
                                .key(k, Direction::Release)
                                .map_err(|e| anyhow!("{:?}", e))?;
                        }
                        AtomicInput::Type { text } => {
                            enigo.text(text).map_err(|e| anyhow!("{:?}", e))?;
                        }
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
