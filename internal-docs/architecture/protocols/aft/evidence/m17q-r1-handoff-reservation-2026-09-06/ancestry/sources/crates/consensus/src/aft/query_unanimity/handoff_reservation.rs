//! One-shot storage preparation from the exact validated handoff envelope.
//! Reservation is not authorization. Only install consumes a fresh live grant.
use super::journal::anchor_reservation::{AnchorReservation, PreparedAnchor};
use super::*;
use std::io::{Seek, SeekFrom};

pub(super) struct HandoffReservation {
    state_path: PathBuf,
    raw_size: u64,
    charge: u64,
    identity: QuvHash,
    anchor: AnchorReservation,
}
pub(super) struct PreparedInstall {
    file: File,
    path: PathBuf,
    raw_size: u64,
    charge: u64,
    pub anchor: PreparedAnchor,
}
fn io(error: std::io::Error) -> QuvError {
    QuvError::Io(error.to_string())
}
fn open(path: &Path, create: bool) -> Result<File, QuvError> {
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
impl HandoffReservation {
    pub(super) fn prepare(
        path: &Path,
        anchor_path: &Path,
        anchor_raw: &[u8],
        raw_size: usize,
        identity: QuvHash,
    ) -> Result<Self, QuvError> {
        require_store_byte_capacity(raw_size, STORE_MAX_BYTES)?;
        let charge = (raw_size as u64)
            .checked_add(4095)
            .ok_or(QuvError::StoreCapacityExceeded)?
            / 4096
            * 4096;
        let staged = suffixed(path, ".tmp");
        let file = open(&staged, true)?;
        // The caller has authenticated the active state/anchor and holds the
        // exclusive custody lock. Only uncommitted staging may be reset.
        if file.metadata().map_err(io)?.len() > STORE_MAX_BYTES
            || file.allocated_size().map_err(io)? > STORE_MAX_BYTES
        {
            return Err(QuvError::StoreCapacityExceeded);
        }
        file.set_len(0).map_err(io)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: valid descriptor and checked bounded positive length.
            if unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    0,
                    charge as libc::off_t,
                )
            } != 0
            {
                return Err(io(std::io::Error::last_os_error()));
            }
        }
        #[cfg(not(target_os = "linux"))]
        return Err(QuvError::InvalidStoreConfiguration);
        if file.allocated_size().map_err(io)? != charge {
            return Err(QuvError::StoreCapacityExceeded);
        }
        file.sync_all().map_err(io)?;
        // Make the reserved name and its complete newly created ancestry durable.
        for directory in path
            .parent()
            .ok_or(QuvError::InvalidStoreConfiguration)?
            .ancestors()
        {
            File::open(directory)
                .and_then(|f| f.sync_all())
                .map_err(io)?;
        }
        let anchor = AnchorReservation::prepare(anchor_path, anchor_raw)?;
        // Custody may have a distinct newly created directory ancestry.
        // Syncing only its leaf does not persist the names above that leaf.
        for directory in anchor_path
            .parent()
            .ok_or(QuvError::InvalidStoreConfiguration)?
            .ancestors()
        {
            File::open(directory)
                .and_then(|f| f.sync_all())
                .map_err(io)?;
        }
        Ok(Self {
            state_path: path.to_owned(),
            raw_size: raw_size as u64,
            charge,
            identity,
            anchor,
        })
    }
    pub(super) fn matches(&self, identity: QuvHash) -> bool {
        self.identity == identity
    }
    pub(super) fn preflight(
        &self,
        raw: &[u8],
        anchor_raw: &[u8],
        identity: QuvHash,
    ) -> Result<PreparedInstall, QuvError> {
        if !self.matches(identity) || raw.len() as u64 != self.raw_size {
            return Err(QuvError::InvalidHandoff);
        }
        let file = open(&suffixed(&self.state_path, ".tmp"), false)?;
        if file.metadata().map_err(io)?.len() != 0
            || file.allocated_size().map_err(io)? != self.charge
        {
            return Err(QuvError::StoreRequiresReopen);
        }
        let anchor = self.anchor.prepare_update(anchor_raw)?;
        Ok(PreparedInstall {
            file,
            path: self.state_path.clone(),
            raw_size: self.raw_size,
            charge: self.charge,
            anchor,
        })
    }
}
impl PreparedInstall {
    pub(super) fn commit_state(mut self, raw: &[u8]) -> Result<PreparedAnchor, QuvError> {
        if raw.len() as u64 != self.raw_size {
            return Err(QuvError::InvalidHandoff);
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        self.file
            .write_all(raw)
            .and_then(|_| self.file.sync_all())
            .map_err(io)?;
        if self.file.allocated_size().map_err(io)? != self.charge {
            return Err(QuvError::StoreRequiresReopen);
        }
        std::fs::rename(suffixed(&self.path, ".tmp"), &self.path).map_err(io)?;
        File::open(
            self.path
                .parent()
                .ok_or(QuvError::InvalidStoreConfiguration)?,
        )
        .and_then(|f| f.sync_all())
        .map_err(io)?;
        Ok(self.anchor)
    }
}
