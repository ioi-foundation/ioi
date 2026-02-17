use crate::agentic::desktop::utils::compute_phash;
use ioi_api::vm::drivers::os::WindowInfo;

pub(super) fn parse_hash_hex(input: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(super) fn compute_context_phash(image_bytes: &[u8], window: Option<&WindowInfo>) -> [u8; 32] {
    if let Some(cropped) = compute_window_cropped_phash(image_bytes, window) {
        return cropped;
    }
    compute_phash(image_bytes).unwrap_or([0u8; 32])
}

fn compute_window_cropped_phash(
    image_bytes: &[u8],
    window: Option<&WindowInfo>,
) -> Option<[u8; 32]> {
    use image_hasher::{HashAlg, HasherConfig};

    let window = window?;
    if window.width <= 0 || window.height <= 0 {
        return None;
    }

    let img = image::load_from_memory(image_bytes).ok()?;
    let img_w = img.width() as i32;
    let img_h = img.height() as i32;
    if img_w <= 0 || img_h <= 0 {
        return None;
    }

    let x1 = window.x.clamp(0, img_w);
    let y1 = window.y.clamp(0, img_h);
    let x2 = (window.x + window.width).clamp(0, img_w);
    let y2 = (window.y + window.height).clamp(0, img_h);
    if x2 <= x1 || y2 <= y1 {
        return None;
    }

    let cropped = img.crop_imm(x1 as u32, y1 as u32, (x2 - x1) as u32, (y2 - y1) as u32);
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&cropped);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Some(out)
}
