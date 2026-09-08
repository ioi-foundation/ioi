//! Startup-allocated future record files. Their bytes never select journal state.
use super::*;
use std::fs::OpenOptions;
use std::io::Write;

const ROOT_MAC: &[u8] = b"ioi/aft/quv-record-reservation/v1\0";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub(super) struct ReservationLimits {
    /// Includes generation zero, which already exists before pool preparation.
    pub records: u64,
    pub record_bytes: u64,
}
#[derive(Encode, Decode)]
struct Root {
    scope: QuvHash,
    limits: ReservationLimits,
    tag: QuvHash,
}
pub(super) fn directory(journal: &Path) -> PathBuf {
    suffixed(journal, ".reserve")
}
pub(super) fn slot(pool: &Path, generation: u64) -> PathBuf {
    pool.join(format!("{generation:020}.rsv"))
}
fn io(error: std::io::Error) -> QuvError {
    QuvError::Io(error.to_string())
}
/// Declared data-allocation charge for this Linux storage profile. Filesystems
/// reporting more allocated bytes must refuse this profile before admission.
pub(super) fn allocation_charge(bytes: u64) -> Result<u64, QuvError> {
    bytes
        .checked_add(4095)
        .map(|n| n / 4096 * 4096)
        .ok_or(QuvError::StoreCapacityExceeded)
}
pub(super) fn check_charge(file: &File, bound: u64) -> Result<(), QuvError> {
    if file.allocated_size().map_err(io)? > allocation_charge(bound)? {
        return Err(QuvError::StoreCapacityExceeded);
    }
    Ok(())
}

pub(super) struct RecordReservation {
    pool: PathBuf,
    journal: PathBuf,
    limits: ReservationLimits,
}
pub(super) struct PreparedRecord {
    file: File,
    source: PathBuf,
    target: PathBuf,
    bound: u64,
}
fn open_slot(path: &Path, create: bool) -> Result<File, QuvError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() {
        return Err(QuvError::CorruptStore);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(QuvError::CorruptStore);
        }
    }
    Ok(file)
}
fn allocate_empty(file: &File, bytes: u64) -> Result<(), QuvError> {
    // Only uncommitted pool files are reset, after complete journal replay.
    // KEEP_SIZE reserves blocks while preserving an empty raw-record file.
    check_charge(file, bytes)?;
    if file.metadata().map_err(io)?.len() != 0 {
        file.set_len(0).map_err(io)?;
    }
    if file.allocated_size().map_err(io)? >= bytes {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let bytes = libc::off_t::try_from(bytes).map_err(|_| QuvError::StoreCapacityExceeded)?;
        // SAFETY: live descriptor, nonnegative checked length, fixed valid flag.
        if unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, bytes) } != 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(QuvError::InvalidStoreConfiguration);
    if file.metadata().map_err(io)?.len() != 0 || file.allocated_size().map_err(io)? < bytes {
        return Err(QuvError::StoreCapacityExceeded);
    }
    check_charge(file, bytes)?;
    Ok(())
}

impl RecordReservation {
    pub(super) fn prepare(
        journal: &Path,
        scope: QuvHash,
        key: &QuvHash,
        limits: ReservationLimits,
        next: u64,
    ) -> Result<Self, QuvError> {
        if next == 0 || next > limits.records || limits.record_bytes == 0 {
            return Err(QuvError::StoreCapacityExceeded);
        }
        let pool = directory(journal);
        if !pool.exists() {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&pool).map_err(io)?;
        }
        if !std::fs::symlink_metadata(&pool).map_err(io)?.is_dir() {
            return Err(QuvError::CorruptStore);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&pool).map_err(io)?.dev()
                != std::fs::metadata(journal).map_err(io)?.dev()
            {
                return Err(QuvError::InvalidStoreConfiguration);
            }
        }
        let root_path = pool.join("root");
        let mut obsolete = Vec::new();
        // Validate every existing name and bound before changing the pool.
        let mut has_slots = false;
        for entry in std::fs::read_dir(&pool).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| QuvError::CorruptStore)?;
            let file = open_slot(&entry.path(), false)?;
            let size = file.metadata().map_err(io)?.len();
            if name == "root" || name == "root.tmp" {
                if size > 128 {
                    return Err(QuvError::StoreCapacityExceeded);
                }
                check_charge(&file, 128)?;
                continue;
            }
            let digits = name.strip_suffix(".rsv").ok_or(QuvError::CorruptStore)?;
            let generation: u64 = digits.parse().map_err(|_| QuvError::CorruptStore)?;
            if name != format!("{generation:020}.rsv")
                || generation == 0
                || generation >= limits.records
            {
                return Err(QuvError::CorruptStore);
            }
            if size > limits.record_bytes {
                return Err(QuvError::StoreCapacityExceeded);
            }
            check_charge(&file, limits.record_bytes)?;
            has_slots = true;
            if generation < next {
                obsolete.push(entry.path());
            }
        }
        if root_path.exists() {
            let root: Root = decode_authenticated(&bounded_read(&root_path, 128)?, ROOT_MAC, key)?;
            if root.scope != scope || root.limits != limits {
                return Err(QuvError::ProvisioningMismatch);
            }
        } else {
            if has_slots {
                return Err(QuvError::IncompleteStore);
            }
            persist_atomic_with_byte_limit(
                &root_path,
                &seal(
                    &Root {
                        scope,
                        limits,
                        tag: [0; 32],
                    },
                    ROOT_MAC,
                    key,
                )?,
                128,
            )?;
        }
        for generation in next..limits.records {
            let file = open_slot(&slot(&pool, generation), true)?;
            allocate_empty(&file, limits.record_bytes)?;
        }
        // Issue allocation first, then sync every inode. This permits the
        // filesystem to group metadata writes while preserving an explicit
        // successful file sync for every reserved generation before admission.
        for generation in next..limits.records {
            open_slot(&slot(&pool, generation), false)?
                .sync_all()
                .map_err(io)?;
        }
        for path in obsolete {
            std::fs::remove_file(path).map_err(io)?;
        }
        // The pool root has no live updates; a partial startup root write is
        // obsolete once the authenticated root and every reservation validate.
        match std::fs::remove_file(pool.join("root.tmp")) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(io(e)),
        }
        File::open(&pool).and_then(|f| f.sync_all()).map_err(io)?;
        sync_parent_chain(&pool)?;
        Ok(Self {
            pool,
            journal: journal.to_owned(),
            limits,
        })
    }

    pub(super) fn prepare_record(
        &self,
        generation: u64,
        bytes: u64,
    ) -> Result<PreparedRecord, QuvError> {
        if generation == 0 || generation >= self.limits.records || bytes > self.limits.record_bytes
        {
            return Err(QuvError::StoreCapacityExceeded);
        }
        let source = slot(&self.pool, generation);
        let file = open_slot(&source, false)?;
        check_charge(&file, self.limits.record_bytes)?;
        if file.metadata().map_err(io)?.len() != 0
            || file.allocated_size().map_err(io)? < self.limits.record_bytes
        {
            return Err(QuvError::StoreRequiresReopen);
        }
        let target = record_path(&self.journal, generation);
        if target.exists() {
            return Err(QuvError::StoreRequiresReopen);
        }
        Ok(PreparedRecord {
            file,
            source,
            target,
            bound: self.limits.record_bytes,
        })
    }
}
impl PreparedRecord {
    pub(super) fn commit(mut self, raw: &[u8]) -> Result<(), QuvError> {
        self.file.write_all(raw).map_err(io)?;
        self.file.sync_all().map_err(io)?;
        check_charge(&self.file, self.bound)?;
        std::fs::rename(&self.source, &self.target).map_err(io)?;
        File::open(
            self.target
                .parent()
                .ok_or(QuvError::InvalidStoreConfiguration)?,
        )
        .and_then(|f| f.sync_all())
        .map_err(io)?;
        File::open(
            self.source
                .parent()
                .ok_or(QuvError::InvalidStoreConfiguration)?,
        )
        .and_then(|f| f.sync_all())
        .map_err(io)
    }
}
