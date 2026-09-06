//! Two reserved receipt inodes. Only the canonical active name is authoritative.
use super::*;

fn charge(bound: u64) -> Result<u64, ConsequenceError> {
    bound
        .checked_add(4095)
        .map(|n| n / 4096 * 4096)
        .ok_or(ConsequenceError::CorruptReceipt)
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
/// the committed admission. This preparation must precede its live operation.
pub(super) fn prepare(path: &Path, bound: u64) -> Result<(), ConsequenceError> {
    #[cfg(not(target_os = "linux"))]
    return Err(ConsequenceError::Invalid(
        "reserved receipt profile requires Linux".into(),
    ));
    #[cfg(target_os = "linux")]
    {
        let active = resource_reservation::private_open(path, false)?;
        let allocated = charge(bound)?;
        if active.metadata()?.len() > bound || active.allocated_size()? > allocated {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let mut bytes = Vec::new();
        (&active).take(bound + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > bound {
            return Err(ConsequenceError::CorruptReceipt);
        }
        // The active bytes have already been validated by the caller. Copies
        // here only test exchange support with semantically identical values.
        rustix::fs::fallocate(&active, rustix::fs::FallocateFlags::KEEP_SIZE, 0, allocated)
            .map_err(std::io::Error::from)?;
        if active.allocated_size()? != allocated {
            return Err(ConsequenceError::CorruptReceipt);
        }
        active.sync_all()?;
        let spare_path = resource_reservation::staged(path)?;
        let mut spare = resource_reservation::private_open(&spare_path, true)?;
        if spare.metadata()?.len() > bound || spare.allocated_size()? > allocated {
            return Err(ConsequenceError::CorruptReceipt);
        }
        // A spare is never recovery authority, even when its generation is newer.
        spare.set_len(0)?;
        rustix::fs::fallocate(&spare, rustix::fs::FallocateFlags::KEEP_SIZE, 0, allocated)
            .map_err(std::io::Error::from)?;
        spare.write_all(&bytes)?;
        if spare.allocated_size()? != allocated {
            return Err(ConsequenceError::CorruptReceipt);
        }
        spare.sync_all()?;
        exchange(path, &spare_path)?;
        resource_reservation::sync_ancestry(path.parent().ok_or(ConsequenceError::CorruptReceipt)?)
    }
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
        let allocated = charge(bound)?;
        let active = resource_reservation::private_open(path, false)?;
        let spare_path = resource_reservation::staged(path)?;
        let mut spare = resource_reservation::private_open(&spare_path, false)?;
        let previous_len = spare.metadata()?.len();
        if active.allocated_size()? != allocated
            || spare.allocated_size()? != allocated
            || active.metadata()?.len() > bound
            || previous_len > bound
        {
            return Err(ConsequenceError::ResourceCapacityNotPrepared);
        }
        spare.write_all(bytes)?;
        // Preserve allocation and JSON compatibility without truncation. Padding
        // replaces any old tail; trailing whitespace has no receipt semantics.
        let mut remaining = previous_len.saturating_sub(bytes.len() as u64);
        let spaces = [b' '; 8192];
        while remaining != 0 {
            let count = remaining.min(spaces.len() as u64) as usize;
            spare.write_all(&spaces[..count])?;
            remaining -= count as u64;
        }
        spare.sync_all()?;
        if spare.allocated_size()? != allocated {
            return Err(ConsequenceError::CorruptReceipt);
        }
        exchange(path, &spare_path)?;
        File::open(path.parent().ok_or(ConsequenceError::CorruptReceipt)?)?.sync_all()?;
        Ok(())
    }
}
