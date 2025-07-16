//! Test fixtures for reproducible tests

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Test fixture manager
pub struct Fixtures {
    /// Base directory for fixtures
    base_dir: PathBuf,
}

impl Fixtures {
    /// Create a new fixtures manager with the specified base directory
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Get a fixture file path
    pub fn path<P: AsRef<Path>>(&self, relative_path: P) -> PathBuf {
        self.base_dir.join(relative_path)
    }

    /// Read a fixture file
    pub fn read<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<Vec<u8>> {
        let path = self.path(relative_path);
        fs::read(path)
    }

    /// Read a fixture file as a string
    pub fn read_string<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<String> {
        let path = self.path(relative_path);
        fs::read_to_string(path)
    }

    /// Write data to a fixture file
    pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(
        &self,
        relative_path: P,
        contents: C,
    ) -> io::Result<()> {
        let path = self.path(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
    }

    /// Create a temporary fixture directory
    pub fn create_dir<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<PathBuf> {
        let path = self.path(relative_path);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Check if a fixture file exists
    pub fn exists<P: AsRef<Path>>(&self, relative_path: P) -> bool {
        self.path(relative_path).exists()
    }

    /// Remove a fixture file or directory
    pub fn remove<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<()> {
        let path = self.path(relative_path);
        if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        }
    }
}

/// Predefined test fixtures
pub struct TestFixtures;

impl TestFixtures {
    /// Get a small sample message for testing
    pub fn small_message() -> &'static [u8] {
        b"This is a small test message"
    }

    /// Get a medium sample message for testing
    pub fn medium_message() -> Vec<u8> {
        let mut data = Vec::with_capacity(1024);
        for i in 0..1024 {
            data.push((i % 256) as u8);
        }
        data
    }

    /// Get a large sample message for testing
    pub fn large_message() -> Vec<u8> {
        let mut data = Vec::with_capacity(65536);
        for i in 0..65536 {
            data.push((i % 256) as u8);
        }
        data
    }

    /// Get a sample key pair for testing
    pub fn sample_keypair() -> (Vec<u8>, Vec<u8>) {
        // These are just dummy values for testing
        let public_key = vec![
            0x04, 0xa3, 0xb2, 0xc1, 0xd0, 0xe5, 0xf4, 0x23, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];

        let private_key = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];

        (public_key, private_key)
    }
}
