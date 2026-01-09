// Path: crates/drivers/src/gui/vision.rs

use anyhow::{anyhow, Result};
use std::io::Cursor;
use xcap::Monitor;
// [FIX] Use ImageFormat
use image::ImageFormat;

/// Provides visual context to the VLM.
pub struct NativeVision;

impl NativeVision {
    /// Captures the primary monitor state.
    /// Returns raw PNG bytes suitable for VLM ingestion.
    pub fn capture_primary() -> Result<Vec<u8>> {
        // 1. Get Monitors
        let monitors = Monitor::all().map_err(|e| anyhow!("Failed to list monitors: {}", e))?;

        if monitors.is_empty() {
            return Err(anyhow!("No monitors found"));
        }

        // 2. Select Primary (Index 0 for MVP)
        let monitor = &monitors[0];

        // 3. Capture Frame
        let image = monitor
            .capture_image()
            .map_err(|e| anyhow!("Screen capture failed: {}", e))?;

        // 4. Compress to PNG
        let mut bytes: Vec<u8> = Vec::new();
        // [FIX] Use ImageFormat::Png
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| anyhow!("Failed to encode screenshot: {}", e))?;

        Ok(bytes)
    }
}
