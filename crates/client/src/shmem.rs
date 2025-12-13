// Path: crates/client/src/shmem.rs
use anyhow::{anyhow, Result};
use ioi_ipc::access_rkyv_bytes;
use rkyv::{Archive, Serialize};
use shared_memory::{Shmem, ShmemConf};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, TryLockError};

// Use the ZeroCopyBlock from IPC
use ioi_ipc::data::ZeroCopyBlock;

/// A handle pointing to data written into the shared memory region.
/// This corresponds directly to the `SharedMemoryHandle` in `blockchain.proto`.
#[derive(Debug, Clone)]
pub struct ShmemHandle {
    pub region_id: String,
    pub offset: u64,
    pub length: u64,
}

/// A thread-safe wrapper for the raw shared memory mapping.
/// SAFETY: The underlying OS handle is thread-safe for mapping operations.
/// Concurrent access to the memory region itself must still be managed by the user
/// (or the DataPlane's internal Mutex for writes).
struct SafeShmem(Shmem);

unsafe impl Send for SafeShmem {}
unsafe impl Sync for SafeShmem {}

/// Manages the Data Plane: A memory-mapped region shared between Orchestrator and Workload.
pub struct DataPlane {
    /// The OS identifier for this shared memory segment (e.g., file path or name).
    os_id: String,
    /// The underlying shared memory mapping, wrapped for thread safety.
    shmem: SafeShmem,
    /// Total size of the region in bytes.
    size: usize,
    /// A simple mutex to coordinate writes within this process.
    write_lock: Mutex<()>,
    /// Ring buffer write cursor.
    write_cursor: AtomicU64,
}

impl fmt::Debug for DataPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataPlane")
            .field("os_id", &self.os_id)
            .field("size", &self.size)
            .finish()
    }
}

// Define a custom serializer type to avoid complex generics in function signatures.
type DefaultSerializer = rkyv::ser::serializers::AllocSerializer<4096>;

impl DataPlane {
    /// Connect to an existing shared memory region (Client Side / Reader).
    pub fn connect(os_id: &str) -> Result<Self> {
        let shmem = ShmemConf::new()
            .os_id(os_id)
            .open()
            .map_err(|e| anyhow!("Failed to open shared memory '{}': {}", os_id, e))?;

        let size = shmem.len();
        Ok(Self {
            os_id: os_id.to_string(),
            shmem: SafeShmem(shmem),
            size,
            write_lock: Mutex::new(()),
            write_cursor: AtomicU64::new(0),
        })
    }

    /// Create a new shared memory region (Server Side / Writer).
    pub fn create(os_id: &str, size: usize) -> Result<Self> {
        let shmem = ShmemConf::new()
            .os_id(os_id)
            .size(size)
            .create()
            .map_err(|e| anyhow!("Failed to create shared memory '{}': {}", os_id, e))?;

        Ok(Self {
            os_id: os_id.to_string(),
            shmem: SafeShmem(shmem),
            size,
            write_lock: Mutex::new(()),
            write_cursor: AtomicU64::new(0),
        })
    }

    /// Generic method to write ANY serializable object to the shared memory.
    pub fn write<T>(&self, data: &T, preferred_offset: Option<usize>) -> Result<ShmemHandle>
    where
        T: Serialize<DefaultSerializer>,
    {
        let _guard = match self.write_lock.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!("Data plane is currently busy (write contention)"));
            }
            Err(e) => return Err(anyhow!("Data plane lock poisoned: {}", e)),
        };

        let bytes = rkyv::to_bytes::<_, 4096>(data)
            .map_err(|e| anyhow!("Rkyv serialization failed: {}", e))?;
        let len = bytes.len();
        let offset = preferred_offset.unwrap_or(1024);

        if offset + len > self.size {
            return Err(anyhow!(
                "Shared memory overflow: Need {} bytes at offset {}, capacity is {}",
                len,
                offset,
                self.size
            ));
        }

        unsafe {
            let ptr = self.shmem.0.as_ptr().add(offset);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        }

        Ok(ShmemHandle {
            region_id: self.os_id.clone(),
            offset: offset as u64,
            length: len as u64,
        })
    }

    /// Writes raw bytes directly to shared memory without additional serialization.
    pub fn write_raw(&self, bytes: &[u8], preferred_offset: Option<usize>) -> Result<ShmemHandle> {
        let _guard = match self.write_lock.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!("Data plane is currently busy (write contention)"));
            }
            Err(e) => return Err(anyhow!("Data plane lock poisoned: {}", e)),
        };

        let len = bytes.len();
        let offset = preferred_offset.unwrap_or(1024);

        if offset + len > self.size {
            return Err(anyhow!(
                "Shared memory overflow: Need {} bytes at offset {}, capacity is {}",
                len,
                offset,
                self.size
            ));
        }

        unsafe {
            let ptr = self.shmem.0.as_ptr().add(offset);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        }

        Ok(ShmemHandle {
            region_id: self.os_id.clone(),
            offset: offset as u64,
            length: len as u64,
        })
    }

    /// Writes a ZeroCopyBlock to the ring buffer.
    pub fn write_zero_copy_block(&self, block: &ZeroCopyBlock) -> Result<ShmemHandle> {
        // Acquire lock to serialize writes to the ring buffer
        let _guard = match self.write_lock.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!("Data plane is currently busy (write contention)"));
            }
            Err(e) => return Err(anyhow!("Data plane lock poisoned: {}", e)),
        };

        let bytes = rkyv::to_bytes::<_, 4096>(block)
            .map_err(|e| anyhow!("Rkyv serialization failed: {}", e))?;
        let len = bytes.len() as u64;

        let mut start = self.write_cursor.load(Ordering::Relaxed);
        let capacity = self.size as u64;

        // Reserve header space (e.g., first 1024 bytes) if needed, otherwise wrap logic
        // Simplified ring logic:
        if start + len > capacity {
            // Wrap to beginning (skip header space if defined, here we assume start=1024)
            start = 1024;
        }

        if start + len > capacity {
             return Err(anyhow!(
                "Block too large for ring buffer: {} bytes, capacity {}",
                len,
                capacity
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.shmem.0.as_ptr().add(start as usize),
                len as usize,
            );
        }

        // Update cursor
        self.write_cursor.store(start + len, Ordering::Relaxed);

        Ok(ShmemHandle {
            region_id: self.os_id.clone(),
            offset: start,
            length: len,
        })
    }

    /// Reads raw bytes from shared memory.
    pub fn read_raw(&self, offset: u64, len: u64) -> Result<&[u8]> {
        let offset = offset as usize;
        let len = len as usize;

        if offset + len > self.size {
            return Err(anyhow!(
                "Read out of bounds: {} + {} > {}",
                offset,
                len,
                self.size
            ));
        }

        unsafe {
            Ok(std::slice::from_raw_parts(
                self.shmem.0.as_ptr().add(offset),
                len,
            ))
        }
    }

    /// Generic method to read and validate an Rkyv object from shared memory.
    pub fn read<T>(&self, offset: u64, len: u64) -> Result<&T::Archived>
    where
        T: Archive,
        T::Archived:
            for<'a> bytecheck::CheckBytes<rkyv::validation::validators::DefaultValidator<'a>>,
    {
        let slice = self.read_raw(offset, len)?;

        access_rkyv_bytes::<T>(slice).map_err(|e| {
            anyhow!(
                "Rkyv validation failed for type {}: {}",
                std::any::type_name::<T>(),
                e
            )
        })
    }

    pub fn capacity(&self) -> usize {
        self.size
    }

    pub fn id(&self) -> &str {
        &self.os_id
    }
}