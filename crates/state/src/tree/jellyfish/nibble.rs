//! Nibble path manipulation for JMT.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct NibblePath {
    bytes: [u8; 32], // Max 64 nibbles
    num_nibbles: usize,
}

impl NibblePath {
    pub fn new(key: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let len = key.len().min(32);
        bytes[..len].copy_from_slice(&key[..len]);
        Self {
            bytes,
            num_nibbles: len * 2,
        }
    }

    pub fn get_nibble(&self, index: usize) -> u8 {
        if index >= self.num_nibbles {
            return 0;
        }
        let byte = self.bytes[index / 2];
        if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0F
        }
    }

    pub fn common_prefix(&self, other: &Self) -> usize {
        let len = std::cmp::min(self.num_nibbles, other.num_nibbles);
        for i in 0..len {
            if self.get_nibble(i) != other.get_nibble(i) {
                return i;
            }
        }
        len
    }
}