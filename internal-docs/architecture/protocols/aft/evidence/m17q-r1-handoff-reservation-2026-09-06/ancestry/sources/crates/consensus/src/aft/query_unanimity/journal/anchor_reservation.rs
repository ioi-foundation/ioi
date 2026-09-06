//! Fixed-size raw authenticated anchors in two reserved files.
//! The journal must authenticate the active anchor and hold its custody lock.
//! An inactive anchor is never a recovery authority or a live grant.
use super::*;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

const ALLOCATION: u64 = 4096;
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
    if !metadata.is_file() || metadata.len() > 128 {
        return Err(QuvError::InvalidAnchor);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(QuvError::InvalidAnchor);
        }
    }
    if file.allocated_size().map_err(io)? > ALLOCATION {
        return Err(QuvError::StoreCapacityExceeded);
    }
    Ok(file)
}
fn allocate(file: &File) -> Result<(), QuvError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if file.allocated_size().map_err(io)? < ALLOCATION {
            // SAFETY: valid descriptor, fixed nonnegative range and KEEP_SIZE.
            if unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    0,
                    ALLOCATION as libc::off_t,
                )
            } != 0
            {
                return Err(io(std::io::Error::last_os_error()));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(QuvError::InvalidStoreConfiguration);
    if file.allocated_size().map_err(io)? != ALLOCATION {
        return Err(QuvError::StoreCapacityExceeded);
    }
    file.sync_all().map_err(io)
}
fn sync_parent(path: &Path) -> Result<(), QuvError> {
    File::open(path.parent().ok_or(QuvError::InvalidStoreConfiguration)?)
        .and_then(|f| f.sync_all())
        .map_err(io)
}
#[cfg(target_os = "linux")]
fn exchange(active: &Path, inactive: &Path) -> Result<(), QuvError> {
    use std::os::unix::ffi::OsStrExt;
    let active = std::ffi::CString::new(active.as_os_str().as_bytes())
        .map_err(|_| QuvError::InvalidStoreConfiguration)?;
    let inactive = std::ffi::CString::new(inactive.as_os_str().as_bytes())
        .map_err(|_| QuvError::InvalidStoreConfiguration)?;
    // SAFETY: both live C strings are NUL terminated; fixed exchange operation.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            active.as_ptr(),
            libc::AT_FDCWD,
            inactive.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } != 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn exchange(_active: &Path, _inactive: &Path) -> Result<(), QuvError> {
    Err(QuvError::InvalidStoreConfiguration)
}

pub(in crate::aft::query_unanimity) struct AnchorReservation {
    path: PathBuf,
    size: usize,
}
pub(in crate::aft::query_unanimity) struct PreparedAnchor {
    path: PathBuf,
    inactive: PathBuf,
    file: File,
    size: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::aft::query_unanimity) enum AnchorPhase {
    InactiveDurable,
    Exchanged,
    DirectoryDurable,
}

impl AnchorReservation {
    /// `current` must be the authenticated active anchor, never the inactive
    /// file. Startup can reset only the inactive copy before admitting traffic.
    pub(in crate::aft::query_unanimity) fn prepare(
        path: &Path,
        current: &[u8],
    ) -> Result<Self, QuvError> {
        if current.is_empty() || current.len() > 128 {
            return Err(QuvError::InvalidAnchor);
        }
        let mut active = open(path, false)?;
        let mut actual = Vec::new();
        (&mut active)
            .take(129)
            .read_to_end(&mut actual)
            .map_err(io)?;
        if actual != current {
            return Err(QuvError::InvalidAnchor);
        }
        allocate(&active)?;
        let inactive = suffixed(path, ".tmp");
        let mut spare = open(&inactive, true)?;
        // Only this untrusted, non-authorizing startup copy may be truncated.
        spare.set_len(0).map_err(io)?;
        spare.write_all(current).map_err(io)?;
        allocate(&spare)?;
        sync_parent(path)?;
        // Both images are identical: verify support before live admission.
        exchange(path, &inactive)?;
        sync_parent(path)?;
        Ok(Self {
            path: path.to_owned(),
            size: current.len(),
        })
    }

    pub(in crate::aft::query_unanimity) fn prepare_update(
        &self,
        raw: &[u8],
    ) -> Result<PreparedAnchor, QuvError> {
        if raw.len() != self.size {
            return Err(QuvError::InvalidAnchor);
        }
        let inactive = suffixed(&self.path, ".tmp");
        for path in [&self.path, &inactive] {
            let file = open(path, false)?;
            if file.metadata().map_err(io)?.len() != self.size as u64
                || file.allocated_size().map_err(io)? != ALLOCATION
            {
                return Err(QuvError::StoreRequiresReopen);
            }
        }
        let file = open(&inactive, false)?;
        Ok(PreparedAnchor {
            path: self.path.clone(),
            inactive,
            file,
            size: self.size,
        })
    }
}
impl PreparedAnchor {
    pub(in crate::aft::query_unanimity) fn commit(self, raw: &[u8]) -> Result<(), QuvError> {
        self.commit_with_hook(raw, |_| Ok(()))
    }
    pub(in crate::aft::query_unanimity) fn commit_with_hook(
        mut self,
        raw: &[u8],
        mut hook: impl FnMut(AnchorPhase) -> Result<(), QuvError>,
    ) -> Result<(), QuvError> {
        if raw.len() != self.size {
            return Err(QuvError::InvalidAnchor);
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        self.file.write_all(raw).map_err(io)?;
        self.file.sync_all().map_err(io)?;
        if self.file.metadata().map_err(io)?.len() != self.size as u64
            || self.file.allocated_size().map_err(io)? != ALLOCATION
        {
            return Err(QuvError::StoreRequiresReopen);
        }
        hook(AnchorPhase::InactiveDurable)?;
        exchange(&self.path, &self.inactive)?;
        hook(AnchorPhase::Exchanged)?;
        sync_parent(&self.path)?;
        hook(AnchorPhase::DirectoryDurable)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn value(generation: u64) -> Vec<u8> {
        seal(
            &Anchor {
                magic: ANCHOR_MAGIC,
                schema: SCHEMA,
                scope: [2; 32],
                generation,
                head: [generation as u8 + 1; 32],
                tag: [0; 32],
            },
            ANCHOR_MAC,
            &[1; 32],
        )
        .unwrap()
    }

    #[test]
    fn fixed_anchor_updates_reuse_both_inodes_and_keep_raw_authentication() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("anchor");
        let current = value(0);
        persist_atomic_with_byte_limit(&path, &current, 128).unwrap();
        let reserved = AnchorReservation::prepare(&path, &current).unwrap();
        let inactive = suffixed(&path, ".tmp");
        let identity = |p: &Path| {
            let file = open(p, false).unwrap();
            assert_eq!(file.allocated_size().unwrap(), ALLOCATION);
            assert_eq!(file.metadata().unwrap().len(), current.len() as u64);
            file.metadata().unwrap().ino()
        };
        let original = [identity(&path), identity(&inactive)];
        assert_ne!(original[0], original[1]);
        for generation in 1..=8 {
            let next = value(generation);
            reserved
                .prepare_update(&next)
                .unwrap()
                .commit(&next)
                .unwrap();
            assert_eq!(identity(&path), original[generation as usize % 2]);
            assert_eq!(identity(&inactive), original[(generation as usize + 1) % 2]);
            let decoded: Anchor =
                decode_authenticated(&std::fs::read(&path).unwrap(), ANCHOR_MAC, &[1; 32]).unwrap();
            assert_eq!(decoded.generation, generation);
        }
    }

    #[test]
    fn fixed_anchor_interruption_selects_only_the_active_name() {
        for stop in [AnchorPhase::InactiveDurable, AnchorPhase::Exchanged] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("anchor");
            let old = value(0);
            let next = value(1);
            persist_atomic_with_byte_limit(&path, &old, 128).unwrap();
            let reserved = AnchorReservation::prepare(&path, &old).unwrap();
            assert!(reserved
                .prepare_update(&next)
                .unwrap()
                .commit_with_hook(&next, |phase| {
                    if phase == stop {
                        Err(QuvError::InvalidOperation)
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            let observed = std::fs::read(&path).unwrap();
            assert_eq!(
                observed,
                if stop == AnchorPhase::InactiveDurable {
                    old
                } else {
                    next
                }
            );
            // The caller must authenticate this active image and check the
            // retained journal before invoking startup preparation again.
            let _: Anchor = decode_authenticated(&observed, ANCHOR_MAC, &[1; 32]).unwrap();
            AnchorReservation::prepare(&path, &observed).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), observed);
        }
    }

    #[test]
    fn fixed_anchor_lost_spare_and_alias_refuse_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("anchor");
        let old = value(0);
        persist_atomic_with_byte_limit(&path, &old, 128).unwrap();
        let reserved = AnchorReservation::prepare(&path, &old).unwrap();
        let inactive = suffixed(&path, ".tmp");
        std::fs::remove_file(&inactive).unwrap();
        File::create(&inactive).unwrap();
        assert!(matches!(
            reserved.prepare_update(&value(1)),
            Err(QuvError::StoreRequiresReopen)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), old);
        std::fs::remove_file(&inactive).unwrap();
        std::fs::hard_link(&path, &inactive).unwrap();
        assert!(reserved.prepare_update(&value(1)).is_err());
        assert!(AnchorReservation::prepare(&path, &old).is_err());
        assert_eq!(std::fs::read(path).unwrap(), old);
    }
}
