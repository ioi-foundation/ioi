// Path: crates/services/src/agentic/desktop/service/step/visual.rs

/// Calculates Hamming distance between two 32-byte (256-bit) pHashes.
pub fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let mut dist = 0;
    // pHash is typically 64-bit (8 bytes). We only compare the first 8 bytes.
    for i in 0..8 {
        let xor = a[i] ^ b[i];
        dist += xor.count_ones();
    }
    dist
}