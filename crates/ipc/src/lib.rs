// Path: crates/ipc/src/lib.rs
//! # IOI SDK IPC
//!
//! Implements the hybrid communication architecture:
//! 1. **Control Plane**: gRPC via `tonic` for signals and consensus.
//! 2. **Data Plane**: Zero-copy shared memory via `rkyv` for bulk AI data.

pub mod data;

// Re-export the generated Protobuf/Tonic code
pub mod control {
    tonic::include_proto!("ioi.control.v1");
}

pub mod blockchain {
    tonic::include_proto!("ioi.blockchain.v1");
}

// Use the top-level re-export for AlignedVec
use rkyv::validation::validators::DefaultValidator;
use rkyv::AlignedVec;
use rkyv::{check_archived_root, Archive, Serialize};

/// Identifies the type of client connecting via the secure IPC channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcClientType {
    /// The Orchestration container.
    Orchestrator = 1,
    /// The Workload container.
    Workload = 2,
}

impl TryFrom<u8> for IpcClientType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Orchestrator),
            2 => Ok(Self::Workload),
            _ => Err(value),
        }
    }
}
// --- LEGACY SUPPORT END ---

/// Helper to serialize data into an Rkyv aligned buffer (Data Plane Sender).
pub fn to_rkyv_bytes<T>(value: &T) -> AlignedVec
where
    T: Serialize<rkyv::ser::serializers::AllocSerializer<4096>>,
{
    rkyv::to_bytes::<_, 4096>(value).expect("failed to serialize data plane object")
}

/// Helper to access data from a raw byte slice (Data Plane Receiver).
pub fn access_rkyv_bytes<T>(bytes: &[u8]) -> Result<&T::Archived, String>
where
    T: Archive,
    T::Archived: for<'a> bytecheck::CheckBytes<DefaultValidator<'a>>,
{
    check_archived_root::<T>(bytes).map_err(|e| e.to_string())
}
