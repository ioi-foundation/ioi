//! Two allocated index inodes, exchanged only after the inactive image is durable.
//! This reserves index data blocks, not payloads, filesystem journal space, RAM,
//! or a worst-case device latency. The production profile must account for those.
use super::*;
use std::io::{Read, Seek, SeekFrom};

pub(super) const MAGIC: [u8; 8] = *b"AFTPQI04";
const HEADER: u64 = 48;
const ALIGN: u64 = 4096;

pub(super) fn inactive(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".inactive");
    PathBuf::from(name)
}

fn capacity(encoded_max: u64) -> Result<u64> {
    encoded_max
        .checked_add(HEADER + ALIGN - 1)
        .map(|n| n / ALIGN * ALIGN)
        .ok_or_else(|| anyhow!("PQ reserved index capacity overflow"))
}

pub(super) fn is_reserved(path: &Path) -> Result<bool> {
    let mut magic = [0; 8];
    match File::open(path)?.read_exact(&mut magic) {
        Ok(()) => Ok(magic == MAGIC),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn digest(bytes: &[u8]) -> Result<[u8; 32]> {
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|e| anyhow!(e.to_string()))
}

pub(super) fn read(path: &Path, encoded_max: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if !is_reserved(path)? {
        if length > encoded_max {
            return Err(anyhow!("PQ index exceeds encoded capacity"));
        }
        let mut bytes = Vec::new();
        file.take(encoded_max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length {
            return Err(anyhow!("PQ index changed during recovery"));
        }
        return Ok(bytes);
    }
    if length != capacity(encoded_max)? {
        return Err(anyhow!(
            "PQ reserved index size differs from rooted capacity"
        ));
    }
    let mut header = [0; HEADER as usize];
    file.read_exact(&mut header)?;
    let used = u64::from_le_bytes(header[8..16].try_into()?);
    if used > encoded_max || used > length - HEADER {
        return Err(anyhow!("PQ reserved index length exceeds capacity"));
    }
    let mut bytes = vec![0; usize::try_from(used)?];
    file.read_exact(&mut bytes)?;
    if digest(&bytes)? != header[16..48] {
        return Err(anyhow!("PQ reserved index checksum mismatch"));
    }
    // Bytes beyond `used` belong to a previous image and are never decoded.
    // This checksum detects damage; it is not an authentication/custody MAC.
    Ok(bytes)
}

fn write_image(file: &mut File, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > file.metadata()?.len().saturating_sub(HEADER) {
        return Err(anyhow!("PQ index exceeds reserved file capacity"));
    }
    let checksum = digest(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&MAGIC)?;
    file.write_all(&(bytes.len() as u64).to_le_bytes())?;
    file.write_all(&checksum)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn allocated_file(path: &Path, length: u64) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(anyhow!("PQ index reservation is not a regular file"));
    }
    check_single_link(&file)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let length = libc::off_t::try_from(length)?;
        // SAFETY: a live owned descriptor and a checked nonnegative length.
        // posix_fallocate returns the errno value directly, not through errno.
        let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result).into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(anyhow!(
        "PQ reserved index requires the Linux exchange storage profile"
    ));
    file.set_len(length)?;
    check_allocation(&file, length)?;
    file.sync_all()?;
    Ok(file)
}

fn check_allocation(file: &File, length: u64) -> Result<()> {
    check_single_link(file)?;
    if !file.metadata()?.is_file()
        || file.metadata()?.len() != length
        || fs2::FileExt::allocated_size(file)? < length
    {
        return Err(anyhow!("PQ index has lost its allocated capacity"));
    }
    Ok(())
}

fn check_single_link(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(anyhow!("PQ reserved index must have one directory link"));
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("PQ index has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

/// Startup only, after the complete queue has validated under the storage lock.
/// Conversion preserves the previous active image until its replacement is synced.
pub(super) fn prepare(path: &Path, accounts: usize) -> Result<()> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(anyhow!("PQ active index is not a regular file"));
    }
    check_single_link(&File::open(path)?)?;
    let encoded_max = (accounts as u64)
        .checked_mul(PQ_OUTBOX_PER_RECIPIENT_MAX as u64)
        .and_then(|n| n.checked_mul(64))
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| anyhow!("PQ index rooted capacity overflow"))?;
    let length = capacity(encoded_max)?;
    let bytes = read(path, encoded_max)?;
    let mut spare = allocated_file(&inactive(path), length)?;
    write_image(&mut spare, &bytes)?;
    sync_parent(path)?;
    if is_reserved(path)? {
        check_allocation(&File::open(path)?, length)?;
    } else {
        let temp = outbox_temp_path(path);
        let mut replacement = allocated_file(&temp, length)?;
        write_image(&mut replacement, &bytes)?;
        std::fs::rename(temp, path)?;
        sync_parent(path)?;
    }
    // Verify filesystem exchange support before exposing a live handle. Both
    // images encode the same validated queue, so either outcome is recoverable.
    exchange(path, &inactive(path))?;
    sync_parent(path)?;
    Ok(())
}

pub(super) fn commit(
    path: &Path,
    bytes: &[u8],
    mut hook: impl FnMut(outbox_index::CommitPhase) -> Result<()>,
) -> Result<()> {
    let active = File::open(path)?;
    let length = active.metadata()?.len();
    check_allocation(&active, length)?;
    let spare_path = inactive(path);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut spare = options.open(&spare_path)?;
    check_allocation(&spare, length)?;
    write_image(&mut spare, bytes)?;
    hook(outbox_index::CommitPhase::InactiveIndexDurable)?;
    exchange(path, &spare_path)?;
    hook(outbox_index::CommitPhase::IndexExchanged)?;
    sync_parent(path)
}

#[cfg(target_os = "linux")]
fn exchange(active: &Path, spare: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let active = std::ffi::CString::new(active.as_os_str().as_bytes())?;
    let spare = std::ffi::CString::new(spare.as_os_str().as_bytes())?;
    // SAFETY: both C strings are NUL terminated and live through the syscall.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            active.as_ptr(),
            libc::AT_FDCWD,
            spare.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn exchange(_active: &Path, _spare: &Path) -> Result<()> {
    Err(anyhow!(
        "PQ reserved index requires atomic Linux RENAME_EXCHANGE"
    ))
}
