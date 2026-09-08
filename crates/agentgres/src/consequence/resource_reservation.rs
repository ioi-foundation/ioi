//! Reserved one-shot endpoint record data. Staging never becomes lookup authority.
use super::*;
use std::io::{Seek, SeekFrom};

pub(super) fn staged(path: &Path) -> Result<PathBuf, ConsequenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConsequenceError::Invalid("record path has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConsequenceError::Invalid("record path has no name".into()))?;
    Ok(parent.join(format!(".{name}.prepared")))
}
pub(super) fn private_open(path: &Path, create: bool) -> Result<File, ConsequenceError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ConsequenceError::CorruptReceipt);
        }
        return Ok(file);
    }
    #[cfg(not(unix))]
    Err(ConsequenceError::Invalid(
        "reserved resource profile requires Unix file custody".into(),
    ))
}
pub(super) fn sync_ancestry(directory: &Path) -> Result<(), ConsequenceError> {
    for parent in directory.ancestors() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
/// Caller holds the endpoint lock and has validated that no active record exists.
pub(super) fn prepare(path: &Path) -> Result<(), ConsequenceError> {
    prepare_charged(path, PQ_REGISTER_RECORD_MAX_BYTES as u64)
}

/// Reserve and fully initialize one space-padded staging file of exactly
/// `charge` bytes next to `path`. The same discipline serves the endpoint
/// record and the per-store claim index: every allocation happens here,
/// before the executor's live operation, never at the claim boundary.
pub(super) fn prepare_charged(path: &Path, charge: u64) -> Result<(), ConsequenceError> {
    #[cfg(not(target_os = "linux"))]
    return Err(ConsequenceError::Invalid(
        "reserved resource profile requires Linux allocation".into(),
    ));
    #[cfg(target_os = "linux")]
    {
        let mut file = private_open(&staged(path)?, true)?;
        if file.metadata()?.len() > charge || file.allocated_size()? > charge {
            return Err(ConsequenceError::CorruptReceipt);
        }
        // Reset only uncommitted staging, before the executor's live operation.
        if file.metadata()?.len() != 0 {
            file.set_len(0)?;
        }
        if file.allocated_size()? != charge {
            rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::KEEP_SIZE, 0, charge)
                .map_err(std::io::Error::from)?;
        }
        // Initialize the whole reservation before QUV. ASCII-space padding
        // keeps the published object valid JSON without live truncation.
        let spaces = [b' '; 8192];
        let mut remaining = charge;
        while remaining != 0 {
            let count = remaining.min(spaces.len() as u64) as usize;
            file.write_all(&spaces[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
        if file.allocated_size()? != charge {
            return Err(ConsequenceError::CorruptReceipt);
        }
        sync_ancestry(
            path.parent()
                .ok_or_else(|| ConsequenceError::Invalid("record path has no parent".into()))?,
        )
    }
}
pub(super) fn commit(path: &Path, bytes: &[u8]) -> Result<(), ConsequenceError> {
    commit_charged(path, bytes, PQ_REGISTER_RECORD_MAX_BYTES as u64)
}

/// Publish `bytes` through the staging file reserved by `prepare_charged`:
/// overwrite initialized padding in place, fsync, rename, directory sync.
/// No allocation happens here; a missing or partially written reservation
/// is refused and must be re-prepared before the next live operation.
pub(super) fn commit_charged(
    path: &Path,
    bytes: &[u8],
    charge: u64,
) -> Result<(), ConsequenceError> {
    if bytes.len() as u64 > charge {
        return Err(ConsequenceError::CorruptReceipt);
    }
    let pending = staged(path)?;
    let mut file = private_open(&pending, false)?;
    if file.metadata()?.len() != charge || file.allocated_size()? != charge {
        return Err(ConsequenceError::ResourceCapacityNotPrepared);
    }
    // A partial uncommitted write requires pre-live preparation after reopening.
    // Its bytes cannot silently become an initialized-capacity witness.
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != b' ') {
            return Err(ConsequenceError::ResourceCapacityNotPrepared);
        }
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if file.allocated_size()? != charge {
        return Err(ConsequenceError::CorruptReceipt);
    }
    fs::rename(pending, path)?;
    File::open(
        path.parent()
            .ok_or_else(|| ConsequenceError::Invalid("record path has no parent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}
