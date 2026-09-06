//! Fixed initialized receipt files. Only the canonical active name is authority.
use super::*;
use std::io::{Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"AFTCR001";
const HEADER: u64 = StorageProfile::HEADER_BYTES;

fn capacity(bound: u64) -> Result<u64, ConsequenceError> {
    StorageProfile::receipt_file_capacity(bound).ok_or(ConsequenceError::CorruptReceipt)
}

fn header(length: u64, capacity: u64, allocated: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..16].copy_from_slice(&length.to_le_bytes());
    bytes[16..24].copy_from_slice(&capacity.to_le_bytes());
    bytes[24..32].copy_from_slice(&allocated.to_le_bytes());
    bytes
}

fn read_header(file: &mut File) -> Result<(u64, u64, u64), ConsequenceError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)?;
    let length = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let capacity = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let allocated = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    if &bytes[..8] != MAGIC
        || capacity < HEADER
        || capacity % StorageProfile::ALLOCATION_UNIT_BYTES != 0
        || length > capacity - HEADER
        || file.metadata()?.len() != capacity
        || allocated < capacity
        || allocated > capacity.saturating_mul(StorageProfile::FILE_PHYSICAL_FACTOR)
        || file.allocated_size()? != allocated
    {
        return Err(ConsequenceError::CorruptReceipt);
    }
    Ok((length, capacity, allocated))
}

/// Read the active file only. Legacy JSON may be converted only after admission
/// rederivation; an invalid envelope never selects its spare as a fallback.
pub(super) fn read(path: &Path) -> Result<(Vec<u8>, Option<u64>), ConsequenceError> {
    let mut file = resource_reservation::private_open(path, false)?;
    let mut prefix = [0; 8];
    let count = file.read(&mut prefix)?;
    file.seek(SeekFrom::Start(0))?;
    if count == 8 && &prefix == MAGIC {
        let (length, capacity, _) = read_header(&mut file)?;
        let mut bytes = Vec::new();
        file.take(length).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length {
            return Err(ConsequenceError::CorruptReceipt);
        }
        Ok((bytes, Some(capacity)))
    } else {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok((bytes, None))
    }
}

pub(super) fn validate_capacity(
    stored: Option<u64>,
    bound: Option<u64>,
) -> Result<(), ConsequenceError> {
    if let Some(stored) = stored {
        if bound.map(capacity).transpose()? != Some(stored) {
            return Err(ConsequenceError::CorruptReceipt);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exchange(active: &Path, spare: &Path) -> Result<(), ConsequenceError> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        active,
        rustix::fs::CWD,
        spare,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

/// Caller holds the store lock and has validated the active receipt against
/// committed admission. All allocation/initialization precedes live authority.
pub(super) fn prepare(path: &Path, bound: u64) -> Result<(), ConsequenceError> {
    #[cfg(not(target_os = "linux"))]
    return Err(ConsequenceError::Invalid(
        "reserved receipt profile requires Linux".into(),
    ));
    #[cfg(target_os = "linux")]
    {
        let (bytes, stored) = read(path)?;
        validate_capacity(stored, Some(bound))?;
        if bytes.len() as u64 > bound {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let spare = resource_reservation::staged(path)?;
        if stored.is_some() && receipt_path_present(&spare)? {
            let mut spare_file = resource_reservation::private_open(&spare, false)?;
            match read_header(&mut spare_file) {
                Ok((_, spare_capacity, _)) if spare_capacity == capacity(bound)? => {
                    // The active payload was checked above. A stale spare
                    // payload is expected after exchange and grants no authority.
                    // Reuse the initialized pair without truncating, allocating
                    // or exchanging it. Complete durability even if an earlier
                    // process stopped before its final ancestry synchronization.
                    resource_reservation::private_open(path, false)?.sync_all()?;
                    spare_file.sync_all()?;
                    return resource_reservation::sync_ancestry(
                        path.parent().ok_or(ConsequenceError::CorruptReceipt)?,
                    );
                }
                Ok(_) | Err(ConsequenceError::CorruptReceipt) => {}
                Err(ConsequenceError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(error),
            }
        }
        prepare_spare(&spare, &bytes, capacity(bound)?)?;
        exchange(path, &spare)?;
        // This name must be durable before resetting the former active inode.
        File::open(path.parent().ok_or(ConsequenceError::CorruptReceipt)?)?.sync_all()?;
        prepare_spare(&spare, &bytes, capacity(bound)?)?;
        resource_reservation::sync_ancestry(path.parent().ok_or(ConsequenceError::CorruptReceipt)?)
    }
}

#[cfg(target_os = "linux")]
fn prepare_spare(path: &Path, bytes: &[u8], capacity: u64) -> Result<(), ConsequenceError> {
    let mut file = resource_reservation::private_open(path, true)?;
    if file.metadata()?.len() > capacity
        || file.allocated_size()? > capacity.saturating_mul(StorageProfile::FILE_PHYSICAL_FACTOR)
    {
        return Err(ConsequenceError::CorruptReceipt);
    }
    file.set_len(0)?;
    rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::KEEP_SIZE, 0, capacity)
        .map_err(std::io::Error::from)?;
    // Fully initialize every data block before admission. Live writes overwrite
    // initialized blocks; unwritten-extent conversion is not deferred to Claim.
    let zeros = [0; 16384];
    let mut remaining = capacity;
    while remaining != 0 {
        let count = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..count])?;
        remaining -= count as u64;
    }
    file.sync_all()?;
    let allocated = file.allocated_size()?;
    // This profile charges at most twice the data capacity per file, including
    // filesystem-reported extent blocks. Inode/journal costs remain separate.
    if allocated < capacity
        || allocated > capacity.saturating_mul(StorageProfile::FILE_PHYSICAL_FACTOR)
    {
        return Err(ConsequenceError::CorruptReceipt);
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header(bytes.len() as u64, capacity, allocated))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    read_header(&mut file)?;
    Ok(())
}

pub(super) fn commit(path: &Path, bytes: &[u8], bound: u64) -> Result<(), ConsequenceError> {
    #[cfg(not(target_os = "linux"))]
    return Err(ConsequenceError::Invalid(
        "reserved receipt profile requires Linux".into(),
    ));
    #[cfg(target_os = "linux")]
    {
        if bytes.len() as u64 > bound {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let mut active = resource_reservation::private_open(path, false)?;
        let spare_path = resource_reservation::staged(path)?;
        let mut spare = resource_reservation::private_open(&spare_path, false)?;
        let (_, active_capacity, _) =
            read_header(&mut active).map_err(|_| ConsequenceError::ResourceCapacityNotPrepared)?;
        let (_, spare_capacity, allocated) =
            read_header(&mut spare).map_err(|_| ConsequenceError::ResourceCapacityNotPrepared)?;
        if active_capacity != capacity(bound)? || spare_capacity != active_capacity {
            return Err(ConsequenceError::ResourceCapacityNotPrepared);
        }
        spare.seek(SeekFrom::Start(0))?;
        spare.write_all(&header(bytes.len() as u64, spare_capacity, allocated))?;
        spare.write_all(bytes)?;
        spare.sync_all()?;
        read_header(&mut spare)?;
        exchange(path, &spare_path)?;
        File::open(path.parent().ok_or(ConsequenceError::CorruptReceipt)?)?.sync_all()?;
        Ok(())
    }
}
