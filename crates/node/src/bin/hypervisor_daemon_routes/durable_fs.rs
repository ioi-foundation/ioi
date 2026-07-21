//! SHARED DURABLE-FILESYSTEM CORE (#73) — the proven syscall-level mechanics extracted verbatim
//! from the GoalRun plane (#72 rounds 5–9: pinned walks, bounded contained reads, the typed
//! atomic-replacement writer) and the OutcomeRoom plane (#72 rounds 17–21: strict slot reads,
//! descriptor-bound O_TMPFILE no-clobber commits, unconditional parent fsync, post-barrier
//! inode/byte certification, fd-pinned enumeration).
//!
//! POLICY STAYS IN THE PLANES. This module knows nothing about rooms, receipts, intents, or
//! wire error codes — it provides mechanics with TYPED outcomes (`PersistFailure`,
//! `CommitFailure`, `ReadRefusal`) that each plane maps onto its own contract. Every future
//! object plane (#74+) builds on THIS instead of copying route-local machinery.
//!
//! The doctrine encoded here, in one place:
//!   - the enforcement IS the open: every component and slot is opened `O_NOFOLLOW` relative to
//!     a previously PINNED directory fd — no path is ever re-resolved between validation and use;
//!   - only ENOENT means empty: an unreadable, symlinked, or non-regular occupant REFUSES;
//!   - commits are bound to DESCRIPTORS, not names: `O_TMPFILE` + `linkat` (no-replace), then the
//!     target is re-opened and certified (device/inode + bytes) AFTER the durability barrier;
//!   - durability outcomes are structural: visible-but-unconfirmed is never reported as success
//!     and never rolled back "as absent";
//!   - enumeration goes through the pinned fd (`fdopendir` over an independent `openat(fd, ".")`
//!     description) and distinguishes readdir
//!     EOF from error via errno (#73 named gap) — an enumeration error propagates typed, never
//!     as partial or empty truth.

use serde_json::Value;

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

// ================================ TYPED OUTCOMES =================================================

/// Outcome of the ATOMIC-REPLACEMENT writer (`persist_record_durable`).
#[derive(Debug)]
pub(crate) enum PersistFailure {
    /// The failure happened before or at the rename: the OLD record provably survives, so
    /// "nothing changed" cleanup/rollback language is truthful.
    NotCommitted(std::io::Error),
    /// The rename ALREADY replaced the old record in the live view; only the directory fsync
    /// failed, so durability is unconfirmed — the new record is visible and may well be
    /// durable. Callers must PRESERVE evidence and report unknown-but-possibly-applied; rolling
    /// back "as absent" would be a lie.
    RenamedDurabilityUnconfirmed(std::io::Error),
}

/// Outcome of deleting a terminal replay anchor.
///
/// `Durable` is returned only after the parent directory fsync confirms absence. A real fsync
/// failure leaves durability unknown. The deterministic test fault instead re-links the pinned
/// inode and fsyncs that restoration, giving restart tests a byte-exact replay anchor without
/// claiming what an unconfirmed same-kernel namespace observation cannot prove.
#[derive(Debug)]
pub(crate) enum UnlinkOutcome {
    Absent,
    Durable,
    ReplayAnchorRestoredAfterUnconfirmedRemoval(std::io::Error),
    RemovedDurabilityUnconfirmed(std::io::Error),
}

impl PersistFailure {
    pub(crate) fn visible(&self) -> bool {
        matches!(self, PersistFailure::RenamedDurabilityUnconfirmed(_))
    }
    pub(crate) fn detail(&self) -> String {
        match self {
            PersistFailure::NotCommitted(e) => format!("not committed ({e}); the prior record is intact"),
            PersistFailure::RenamedDurabilityUnconfirmed(e) => format!("RENAMED but durability unconfirmed ({e}); the new record is VISIBLE and may already be durable"),
        }
    }
}

/// Outcome of the APPEND-ONLY no-clobber commit (`persist_receipt_no_clobber`). Each variant
/// carries the full human-readable detail; the owning plane maps variants onto its wire codes.
#[derive(Debug)]
pub(crate) enum CommitFailure {
    /// The evidence key would be normalized to a different filename — refused before any write.
    KeyInvalid(String),
    /// Nothing is visible: staging or the link commit failed cleanly.
    NotCommitted(String),
    /// The slot is occupied by something that cannot be certified (unreadable, symlink,
    /// non-regular file) — refused; evidence is never replaced on uncertainty.
    SlotUnreadable(String),
    /// The slot holds DIFFERENT evidence (or an occupant appeared mid-commit) — append-only.
    Conflict(String),
    /// The evidence is VISIBLE but its durability is unconfirmed (file, directory, or parent
    /// fsync) — the caller must not consume its replay anchor.
    DurabilityUnconfirmed(String),
    /// The canonical name no longer resolves to the certified inode/bytes after the durability
    /// barrier — a concurrent replacement was caught, nothing was certified.
    Swapped(String),
}

/// A bounded-intake read refusal (#72 round 7 finding 4) — each shape is typed distinctly.
#[derive(Debug)]
pub(crate) enum ReadRefusal {
    /// Symlink / non-directory component at use time — a containment escape.
    Escape(std::io::Error),
    /// The declared output is not a regular file (FIFO, device, socket, directory).
    NotRegular(String),
    /// The file exceeds the per-file or remaining per-attempt byte budget.
    TooLarge(u64),
    Io(std::io::Error),
}

// ============================ PINNED DESCRIPTORS + WALKS =========================================

fn cstr(name: impl AsRef<std::ffi::OsStr>) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_ref().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component"))
}

/// A single, NON-TRAVERSING path component: no `/` separators, not `.`/`..`, not empty. The
/// shared core enforces its containment contract ITSELF (#73 review finding 1): `O_NOFOLLOW`
/// only protects the terminal component, so a multi-segment or dot-dot "name" smuggled into an
/// `*at` helper or a family would otherwise walk wherever it liked.
fn is_single_component(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let b = name.as_bytes();
    !b.is_empty() && b != b"." && b != b".." && !b.contains(&b'/')
}

/// The validated CString every name-taking `*at` helper uses — a traversing name is refused
/// typed BEFORE any syscall, inside the shared boundary.
fn component_cstr(name: impl AsRef<std::ffi::OsStr>) -> std::io::Result<std::ffi::CString> {
    let n = name.as_ref();
    if !is_single_component(n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "'{}' is not a single non-traversing path component — refused",
                n.to_string_lossy()
            ),
        ));
    }
    cstr(n)
}

/// Pin a directory as a walk root: must be a directory, terminal symlink refused.
pub(crate) fn open_dir_pinned(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Pin a record-family directory — the walk root for slot reads, enumeration, and commits.
pub(crate) fn open_family_dir_pinned(
    data_dir: &str,
    family: &str,
) -> std::io::Result<std::fs::File> {
    if !is_single_component(std::ffi::OsStr::new(family)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("family '{family}' is not a single non-traversing path component — refused"),
        ));
    }
    open_dir_pinned(&std::path::Path::new(data_dir).join(family))
}

pub(crate) fn open_dir_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = component_cstr(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// mkdirat; returns whether the directory was CREATED by this call (EEXIST = false).
pub(crate) fn mkdir_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let c = component_cstr(name)?;
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o755) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e);
        }
        return Ok(false);
    }
    Ok(true)
}

/// O_NONBLOCK is deliberate (#72 round 7 finding 4): opening a FIFO must never block the
/// daemon; the regular-file check at the caller then refuses it typed.
pub(crate) fn open_file_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = component_cstr(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// O_CREAT|O_EXCL|O_NOFOLLOW create relative to the pinned dir.
pub(crate) fn create_file_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = component_cstr(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

pub(crate) fn rename_at(
    parent: &std::fs::File,
    from: impl AsRef<std::ffi::OsStr>,
    to: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let cf = component_cstr(from)?;
    let ct = component_cstr(to)?;
    let rc = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            cf.as_ptr(),
            parent.as_raw_fd(),
            ct.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn unlink_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let c = component_cstr(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_test_crash_marker(path: &std::path::Path, marker: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(marker.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Deterministic process-crash coordination used only by live fault verifiers.
///
/// The hook is completely inert unless the selector environment variable exactly matches
/// `expected`. Once selected, it durably writes the marker named by `marker_path_env` and parks
/// forever so the verifier can SIGKILL at that precise persistence boundary.
pub(crate) fn test_crash_pause_if_selected(
    selector_env: &str,
    expected: &str,
    marker_path_env: &str,
    marker: &str,
) -> std::io::Result<()> {
    if std::env::var(selector_env).ok().as_deref() != Some(expected) {
        return Ok(());
    }
    let marker_path = std::env::var(marker_path_env).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("test crash pause '{selector_env}={expected}' requires '{marker_path_env}'"),
        )
    })?;
    write_test_crash_marker(std::path::Path::new(&marker_path), marker)?;
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(60));
    }
}

pub(crate) fn unlink_durable_at(
    parent: &std::fs::File,
    name: impl AsRef<std::ffi::OsStr>,
    fault_selector: &str,
) -> std::io::Result<UnlinkOutcome> {
    let force_unconfirmed_restore = std::env::var("IOI_TEST_FORCE_UNLINK_DIRSYNC_UNCONFIRMED")
        .ok()
        .is_some_and(|value| value == fault_selector);
    unlink_durable_at_with_restore(
        parent,
        name.as_ref(),
        fault_selector,
        force_unconfirmed_restore,
    )
}

fn unlink_durable_at_with_restore(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    fault_selector: &str,
    force_unconfirmed_restore: bool,
) -> std::io::Result<UnlinkOutcome> {
    let pinned_replay_anchor = if force_unconfirmed_restore {
        let mut source = open_file_at(parent, name)?;
        if !source.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "terminal replay anchor is not a regular file",
            ));
        }
        let mut anchor = open_tmpfile_at(parent)?;
        std::io::copy(&mut source, &mut anchor)?;
        anchor.sync_all()?;
        Some(anchor)
    } else {
        None
    };
    match unlink_at(parent, name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UnlinkOutcome::Absent)
        }
        Err(error) => return Err(error),
    }
    if let Some(anchor) = pinned_replay_anchor {
        let name = name.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "test replay-anchor name is not UTF-8",
            )
        })?;
        link_tmpfile_at(&anchor, parent, name)?;
        parent.sync_all()?;
        test_crash_pause_if_selected(
            "IOI_TEST_PAUSE_AFTER_UNCONFIRMED_INTENT_RESTORE_FAMILY",
            fault_selector,
            "IOI_TEST_UNCONFIRMED_INTENT_RESTORED_MARKER_PATH",
            &format!(
                "byte-exact replay anchor durably restored after unconfirmed removal: {fault_selector}"
            ),
        )?;
        return Ok(UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(
            std::io::Error::other(
                "test-forced pre-directory-fsync uncertainty with durable replay-anchor restoration",
            ),
        ));
    }
    match parent.sync_all() {
        Ok(()) => {
            test_crash_pause_if_selected(
                "IOI_TEST_PAUSE_AFTER_TERMINAL_INTENT_UNLINK_FAMILY",
                fault_selector,
                "IOI_TEST_TERMINAL_INTENT_UNLINKED_MARKER_PATH",
                &format!("terminal intent durably absent after directory fsync: {fault_selector}"),
            )?;
            Ok(UnlinkOutcome::Durable)
        }
        Err(error) => Ok(UnlinkOutcome::RemovedDurabilityUnconfirmed(error)),
    }
}

/// Ensure daemon-owned record families exist durably before listener readiness.
///
/// Every family is validated and every preexisting name is pinned as a directory before any
/// missing family is created. After creation, each family and the data-dir parent are fsynced
/// unconditionally so a prior interrupted create is also brought to a confirmed durable state.
pub(crate) fn precreate_family_dirs_durable(
    data_dir: &str,
    families: &[&str],
) -> std::io::Result<()> {
    for family in families {
        component_cstr(family)?;
    }

    let root = open_dir_pinned(std::path::Path::new(data_dir))?;
    let mut missing = Vec::new();
    for family in families {
        match open_dir_at(&root, family) {
            Ok(directory) => drop(directory),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => missing.push(*family),
            Err(error) => return Err(error),
        }
    }

    for family in missing {
        mkdir_at(&root, family)?;
    }
    for family in families {
        open_dir_at(&root, family)?.sync_all()?;
    }
    root.sync_all()
}

/// Remove a record-family directory only when it is still empty, then make the parent-directory
/// deletion durable. Callers use this to restore a pre-request data-dir shape when an append-only
/// writer had to create a family before a fail-closed operation could prove its preconditions.
///
/// The family is pinned and enumerated before `AT_REMOVEDIR`; a nonempty or unreadable family
/// refuses rather than deleting evidence. API-level callers must hold their owning plane lock
/// while deciding that this request created the family and while invoking this helper.
pub(crate) fn remove_empty_family_durable(data_dir: &str, family: &str) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let root = open_dir_pinned(std::path::Path::new(data_dir))?;
    let directory = open_dir_at(&root, family)?;
    let entries = enumerate_pinned(&directory)?;
    if !entries.is_empty() {
        return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
    }
    // Confirm the preceding slot unlink against the pinned family before removing its name.
    directory.sync_all()?;
    drop(directory);
    let c = component_cstr(family)?;
    if unsafe { libc::unlinkat(root.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    root.sync_all()
}

/// Walk (and in `create` mode, mkdirat) each PARENT component of `rel` under `root`,
/// returning the pinned parent directory fd. A directory CREATED here is made durable by a
/// checked fsync of the directory that received the new entry (#72 round 7 finding 1).
pub(crate) fn pin_parent(
    root: &std::fs::File,
    rel: &std::path::Path,
    create: bool,
) -> std::io::Result<std::fs::File> {
    // Validate the COMPLETE relative path — every parent component AND the terminal — BEFORE
    // creating anything (#73 review rounds 1+2): a noncanonical component (`..`, a root, `.`)
    // anywhere in `rel` is REFUSED with ZERO mutation. Validating only `rel.parent()` would let
    // `a/..` validate-and-create `a` and then "succeed" without its terminal ever being checked.
    for comp in rel.components() {
        if !matches!(comp, std::path::Component::Normal(_)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("noncanonical path component {comp:?} — refused"),
            ));
        }
    }
    let mut cur = root.try_clone()?;
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            if let std::path::Component::Normal(seg) = comp {
                if create && mkdir_at(&cur, seg)? {
                    cur.sync_all()?;
                }
                cur = open_dir_at(&cur, seg)?;
            }
        }
    }
    Ok(cur)
}

/// Read a workspace file ENTIRELY through pinned descriptors (root fd → NOFOLLOW component
/// walk → NOFOLLOW|NONBLOCK file open) with fstat-enforced bounds: only REGULAR files, only
/// up to `max_bytes` — a FIFO can never block the daemon and a huge file can never exhaust
/// its memory. No path is re-resolved between validation and read.
pub(crate) fn read_contained(
    root: &std::fs::File,
    rel: &std::path::Path,
    max_bytes: u64,
) -> Result<Vec<u8>, ReadRefusal> {
    use std::io::Read;
    let classify = |e: std::io::Error| -> ReadRefusal {
        if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
            ReadRefusal::Escape(e)
        } else {
            ReadRefusal::Io(e)
        }
    };
    let parent = pin_parent(root, rel, false).map_err(&classify)?;
    let name = rel.file_name().ok_or_else(|| {
        ReadRefusal::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no file name",
        ))
    })?;
    let f = open_file_at(&parent, name).map_err(&classify)?;
    let md = f.metadata().map_err(ReadRefusal::Io)?;
    if !md.file_type().is_file() {
        return Err(ReadRefusal::NotRegular(format!("{:?}", md.file_type())));
    }
    if md.len() > max_bytes {
        return Err(ReadRefusal::TooLarge(md.len()));
    }
    let mut bytes = Vec::with_capacity(md.len() as usize);
    let mut bounded = f.take(max_bytes + 1);
    bounded.read_to_end(&mut bytes).map_err(ReadRefusal::Io)?;
    if bytes.len() as u64 > max_bytes {
        // The file grew between fstat and read — still refused, never swallowed.
        return Err(ReadRefusal::TooLarge(bytes.len() as u64));
    }
    Ok(bytes)
}

// ============================ STRICT SLOTS + ENUMERATION =========================================

/// STRICT slot inspection (#72 round 19 finding 3): Ok(Some((fd, bytes))) = a REGULAR file
/// occupant opened O_NOFOLLOW and read; Ok(None) = definitively ABSENT (ENOENT only). EVERY
/// other outcome — unreadable occupant, symlink (ELOOP), FIFO/device — is Err: the caller must
/// REFUSE, never treat the slot as empty.
pub(crate) fn read_slot_strict(
    dir: &std::fs::File,
    name: &str,
) -> std::io::Result<Option<(std::fs::File, Vec<u8>)>> {
    use std::io::Read;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = component_cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None); // ONLY ENOENT means empty
        }
        return Err(e);
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("slot '{name}' is occupied by a non-regular file"),
        ));
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    Ok(Some((f, bytes)))
}

/// Enumerate the entries of an ALREADY-PINNED directory through the fd ITSELF — NOT by
/// re-walking the pathname (#72 round 21 finding 3): a directory-level exchange cannot redirect
/// enumeration, because the names come from the same inode the caller pinned and reads through.
///
/// The stream is opened via `openat(fd, ".")`, giving an INDEPENDENT open-file description at
/// offset 0 — NOT `dup`, which shares the caller's directory offset, so a second enumeration on
/// the same pinned fd after EOF would read as EMPTY (#73 review finding 2). The caller's fd may
/// be enumerated any number of times.
pub(crate) fn enumerate_pinned(dir: &std::fs::File) -> std::io::Result<Vec<String>> {
    use std::os::unix::io::AsRawFd;
    let dot = cstr(".")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dp = unsafe { libc::fdopendir(fd) };
    if dp.is_null() {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    drain_dir_stream(dp)
}

/// The readdir loop over an OWNED directory stream (closedir always runs) — the deterministic
/// seam for the post-readdir error branch (#73 review finding 2).
///
/// readdir signals BOTH end-of-stream and error by returning NULL; the only way to tell them
/// apart is errno (#73 named-gap fix): errno is reset before every call and inspected after a
/// NULL. A genuine enumeration error propagates TYPED and DISCARDS every name collected so far —
/// a partial listing served as truth is exactly the false-empty registry this fixes.
fn drain_dir_stream(dp: *mut libc::DIR) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let ent = unsafe { libc::readdir(dp) };
        if ent.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::closedir(dp) };
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            return Ok(names); // genuine EOF
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if let Ok(s) = name.to_str() {
            if s != "." && s != ".." {
                names.push(s.to_string());
            }
        }
    }
}

// ===================== DESCRIPTOR-BOUND NO-CLOBBER COMMIT + CERTIFICATION ========================

/// Open an ANONYMOUS (nameless) inode in the pinned dir via O_TMPFILE (#72 round 20 findings
/// 1+3): the bytes are written into a descriptor that has NO directory entry, so no named
/// source ever exists to be swapped, and there is nothing to clean up after the commit.
pub(crate) fn open_tmpfile_at(dir: &std::fs::File) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let dot = cstr(".")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Give an O_TMPFILE descriptor EXACTLY ONE name via linkat — the ATOMIC NO-REPLACE commit that
/// binds the committed bytes to the DESCRIPTOR, not to any swappable source name (#72 round 20
/// finding 1). Uses the /proc/self/fd form (no CAP_DAC_READ_SEARCH needed for non-root); link
/// fails EEXIST if the target appeared since inspection, exactly like a named no-replace link.
pub(crate) fn link_tmpfile_at(
    tmp: &std::fs::File,
    dir: &std::fs::File,
    to: &str,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let src = cstr(format!("/proc/self/fd/{}", tmp.as_raw_fd()))?;
    let ct = component_cstr(to)?;
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            src.as_ptr(),
            dir.as_raw_fd(),
            ct.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// True iff two descriptors reference the SAME on-disk object (device + inode). The commit
/// certifier compares the re-opened canonical name against the pinned committed descriptor
/// (#72 round 21 finding 1) — a name swapped to a different inode fails this.
pub(crate) fn same_inode(a: &std::fs::File, b: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (ma, mb) = (a.metadata()?, b.metadata()?);
    Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino())
}

/// Is an evidence key filesystem-safe AS WRITTEN (#72 round 17 finding 2)? The atomic writer
/// normalizes unsafe characters, so two different keys could silently target the same file —
/// a caller must reject rather than collide.
pub(crate) fn is_normalization_safe(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// DELIBERATE TEST FAULT (#72 round 21 finding 1): simulate a CONCURRENT adversary replacing the
/// canonical target name during the post-commit fsync window, so the re-verification below is
/// exercised. Absent env = no effect. `point` is "new" (fresh linkat) or "replay" (byte-compare).
fn test_swap_target(dir: &std::fs::File, target: &str, point: &str) {
    use std::io::Write;
    if std::env::var("IOI_TEST_FORCE_RECEIPT_TARGET_SWAP")
        .ok()
        .as_deref()
        != Some(point)
    {
        return;
    }
    let _ = unlink_at(dir, target);
    if let Ok(mut f) = open_tmpfile_at(dir) {
        let _ = f.write_all(
            format!(
                "{{\"foreign\":\"REPLACED_AFTER_{}\"}}",
                point.to_uppercase()
            )
            .as_bytes(),
        );
        let _ = f.sync_all();
        let _ = link_tmpfile_at(&f, dir, target);
    }
}

/// Re-verify the canonical name AFTER the file + directory fsyncs (#72 round 21 finding 1):
/// re-open the target O_NOFOLLOW, prove it is the SAME inode as the committed descriptor, and
/// re-read its bytes — a target swapped during the durability barrier is caught and refused.
pub(crate) fn certify_target(
    dir: &std::fs::File,
    target: &str,
    committed: &std::fs::File,
    bytes: &[u8],
    point: &str,
) -> Result<(), CommitFailure> {
    test_swap_target(dir, target, point);
    match read_slot_strict(dir, target) {
        Ok(Some((reopened, on_disk))) => {
            if !same_inode(&reopened, committed).unwrap_or(false) {
                return Err(CommitFailure::Swapped(format!("the receipt name '{target}' no longer resolves to the certified inode after the durability barrier — refused, never certified over a swapped target")));
            }
            if on_disk != bytes {
                return Err(CommitFailure::Swapped(format!("the receipt bytes at '{target}' changed after the durability barrier — refused")));
            }
            Ok(())
        }
        Ok(None) => Err(CommitFailure::Swapped(format!(
            "the receipt name '{target}' vanished after commit — refused"
        ))),
        Err(e) => Err(CommitFailure::SlotUnreadable(format!(
            "post-commit re-verify of '{target}' failed ({e}) — refused"
        ))),
    }
}

// =============================== TYPED DURABLE WRITERS ===========================================

/// ATOMIC-DURABLE record persistence (#72 rounds 6 + 7 finding 1): temporary sibling → file
/// fsync → rename → CHECKED directory fsync → cleanup. Failures before/at the rename return
/// `NotCommitted` (old record intact); a post-rename directory-sync failure returns
/// `RenamedDurabilityUnconfirmed` (new record visible, durability unknown) so callers can model
/// the truth instead of pretending nothing happened. A NEWLY CREATED family directory is made
/// durable by fsyncing its parent before any record lands inside it.
pub(crate) fn persist_record_durable(
    data_dir: &str,
    family: &str,
    record_id: &str,
    record: &Value,
) -> Result<(), PersistFailure> {
    use std::io::Write;
    use PersistFailure::{NotCommitted, RenamedDurabilityUnconfirmed};
    // Containment inside the shared boundary (#73 review rounds 1+2), BEFORE any backend
    // delegation — the refusal is uniform, never backend-dependent: the family must be a single
    // non-traversing component, and an unsafe record id is REJECTED — normalizing it would let
    // two DISTINCT ids silently collide on one file.
    if !is_single_component(std::ffi::OsStr::new(family)) {
        return Err(NotCommitted(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("family '{family}' is not a single non-traversing path component — refused"),
        )));
    }
    if !is_normalization_safe(record_id) {
        return Err(NotCommitted(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("record id '{record_id}' is not filesystem-safe (would normalize to a different key) — refused, never normalized"))));
    }
    // Parity with persist_record (#72 round 3): promoted families have exactly one write path;
    // not-yet-promoted families still feed the opt-in dual-write soak.
    if super::substrate_store::is_promoted(family) {
        return super::substrate_store::persist_promoted(data_dir, family, record_id, record)
            .map_err(NotCommitted);
    }
    let dir = std::path::Path::new(data_dir).join(family);
    let family_created = !dir.exists();
    std::fs::create_dir_all(&dir).map_err(NotCommitted)?;
    if family_created {
        // A brand-new record family: fsync the data dir so the family directory itself
        // survives a crash (#72 round 7 finding 1).
        (|| -> std::io::Result<()> { std::fs::File::open(data_dir)?.sync_all() })()
            .map_err(NotCommitted)?;
    }
    let tmp = dir.join(format!(".{record_id}.tmp-{:x}", nanos()));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(record).unwrap_or_default())?;
        f.sync_all()
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(NotCommitted(e));
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{record_id}.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(NotCommitted(e));
    }
    // The record is VISIBLE from here — dual-write parity fires on visibility.
    super::substrate_store::dual_write(data_dir, family, record_id, record);
    // DELIBERATE TEST FAULT POINT (#72 round 8 finding 1): absent env = no effect. A real
    // directory-fsync failure cannot be injected by permissions on a read-then-write seam (the
    // dir listing and the fsync open need the same read bit), so the visible-unconfirmed lane
    // is forced here for the fault verifiers — the rename has genuinely happened.
    if std::env::var("IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED")
        .ok()
        .as_deref()
        == Some(family)
    {
        return Err(RenamedDurabilityUnconfirmed(std::io::Error::other(
            "test-forced directory-sync failure",
        )));
    }
    if let Err(e) = (|| -> std::io::Result<()> { std::fs::File::open(&dir)?.sync_all() })() {
        return Err(RenamedDurabilityUnconfirmed(e));
    }
    Ok(())
}

/// APPEND-ONLY, no-clobber, DURABILITY-HONEST evidence commit (#72 rounds 18–21). The exact
/// target slot is inspected through a PINNED no-follow directory fd:
///   - only ENOENT means empty (#72 round 19 finding 3) — an unreadable occupant, a symlink,
///     or a non-regular file REFUSES; evidence is never replaced on uncertainty;
///   - an empty slot commits from an ANONYMOUS O_TMPFILE descriptor via linkat (#72 round 20
///     findings 1+3): the bytes are bound to the DESCRIPTOR, not a swappable source name, and
///     no named temp ever exists. link is NO-REPLACE: an occupant appearing between inspection
///     and commit surfaces EEXIST;
///   - a byte-identical occupant is RE-FSYNCED (file + directory) before being reported
///     durable (#72 round 19 finding 2) — an earlier unconfirmed rename may not be on disk;
///   - the durability barrier fsyncs the family directory AND — UNCONDITIONALLY, never gated on
///     a visibility check — data_dir, so the family directory ENTRY is durable even if an
///     earlier parent fsync failed and left the family visible (#72 round 21 finding 2);
///   - after the barrier, the canonical name is RE-CERTIFIED against the committed descriptor
///     (device/inode + bytes, #72 round 21 finding 1) — a swap during the window is refused;
///   - the durability outcome is PRESERVED (#72 round 19 finding 2): visible-but-unconfirmed
///     is `DurabilityUnconfirmed`, never Ok — terminal state and intent consumption require a
///     DURABLE commit.
pub(crate) fn persist_receipt_no_clobber(
    data_dir: &str,
    family: &str,
    tail: &str,
    receipt: &Value,
) -> Result<(), CommitFailure> {
    use std::io::Write;
    if !is_single_component(std::ffi::OsStr::new(family)) {
        return Err(CommitFailure::NotCommitted(format!("family '{family}' is not a single non-traversing path component — refused, nothing was written")));
    }
    if !is_normalization_safe(tail) {
        return Err(CommitFailure::KeyInvalid(format!(
            "receipt tail '{tail}' is not filesystem-safe"
        )));
    }
    let bytes = serde_json::to_vec_pretty(receipt).unwrap_or_default();
    let fam_path = std::path::Path::new(data_dir).join(family);
    if let Err(e) = std::fs::create_dir_all(&fam_path) {
        return Err(CommitFailure::NotCommitted(format!(
            "receipt directory unavailable ({e}) — nothing was written"
        )));
    }
    let dir = match open_family_dir_pinned(data_dir, family) {
        Ok(d) => d,
        Err(e) => {
            return Err(CommitFailure::NotCommitted(format!(
                "receipt directory pin failed ({e}) — nothing was written"
            )))
        }
    };
    let target = format!("{tail}.json");
    let confirm_dir_durable = |dir: &std::fs::File| -> Result<(), CommitFailure> {
        // DELIBERATE TEST FAULT POINT (same contract as the typed durable writer): absent env =
        // no effect; the receipt is already VISIBLE when this fires.
        if std::env::var("IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED")
            .ok()
            .as_deref()
            == Some(family)
        {
            return Err(CommitFailure::DurabilityUnconfirmed("test-forced directory-sync failure — the receipt is VISIBLE but its durability is unconfirmed".to_string()));
        }
        dir.sync_all().map_err(|e| CommitFailure::DurabilityUnconfirmed(format!("receipt directory sync failed ({e}) — the receipt is VISIBLE but its durability is unconfirmed")))?;
        // Parent (data_dir) fsync — UNCONDITIONAL (#72 round 21 finding 2); a separate fault hook
        // fails only the parent leg so the failure→restart lane is exact.
        if std::env::var("IOI_TEST_FORCE_PARENT_FSYNC_UNCONFIRMED")
            .ok()
            .as_deref()
            == Some(family)
        {
            return Err(CommitFailure::DurabilityUnconfirmed("test-forced parent-directory-sync failure — the receipt family entry is VISIBLE but not durable".to_string()));
        }
        (|| -> std::io::Result<()> { std::fs::File::open(data_dir)?.sync_all() })().map_err(|e| {
            CommitFailure::DurabilityUnconfirmed(format!(
                "data_dir sync failed ({e}) — the receipt family entry is VISIBLE but not durable"
            ))
        })
    };
    match read_slot_strict(&dir, &target) {
        Err(e) => Err(CommitFailure::SlotUnreadable(format!("the receipt slot '{tail}' is occupied but NOT readable as a regular file ({e}) — refused; evidence is never replaced on uncertainty"))),
        Ok(Some((occupant, existing))) => {
            if existing != bytes {
                return Err(CommitFailure::Conflict(format!("the receipt slot '{tail}' already holds DIFFERENT evidence — receipts are append-only and never overwritten")));
            }
            // Byte-identical replay: re-fsync BEFORE reporting durable (#72 round 19 finding 2).
            if let Err(e) = occupant.sync_all() {
                return Err(CommitFailure::DurabilityUnconfirmed(format!("receipt re-sync failed ({e}) — the receipt is VISIBLE but its durability is unconfirmed")));
            }
            confirm_dir_durable(&dir)?;
            // Re-verify the name still resolves to the compared inode after the barrier (#72
            // round 21 finding 1) — a target swapped during the occupant fsync is caught here.
            certify_target(&dir, &target, &occupant, &bytes, "replay")
        }
        Ok(None) => {
            // ANONYMOUS descriptor (O_TMPFILE) — NO name, so nothing to swap and nothing to clean
            // up (#72 round 20 findings 1+3). Write + fsync the bytes into the inode, then bind
            // it to EXACTLY ONE name (the target) with a NO-REPLACE linkat.
            let write = (|| -> std::io::Result<std::fs::File> {
                let mut f = open_tmpfile_at(&dir)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
                Ok(f)
            })();
            let tmp = match write {
                Ok(f) => f,
                Err(e) => return Err(CommitFailure::NotCommitted(format!("receipt staging failed ({e}) — nothing is visible (anonymous inode discarded)"))),
            };
            if let Err(e) = link_tmpfile_at(&tmp, &dir, &target) {
                // The anonymous inode is discarded when `tmp` drops — no residue on any path.
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(CommitFailure::Conflict(format!("the receipt slot '{tail}' was occupied between inspection and commit — refused atomically (no-replace), nothing overwritten")));
                }
                return Err(CommitFailure::NotCommitted(format!("receipt commit failed ({e}) — nothing is visible")));
            }
            // The receipt is VISIBLE from here — dual-write parity fires on visibility, exactly
            // like the typed durable writer.
            super::substrate_store::dual_write(data_dir, family, tail, receipt);
            confirm_dir_durable(&dir)?;
            // Re-verify the name still resolves to the linked inode after the barrier (#72 round
            // 21 finding 1) — a target replaced during the directory fsync is caught here.
            certify_target(&dir, &target, &tmp, &bytes, "new")
        }
    }
}

// ====================================== TESTS ====================================================

#[cfg(test)]
mod durable_fs_tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ioi-durable-fs-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn crash_pause_marker_is_durable_and_exact() {
        let dir = temp_dir("crash-marker");
        let marker = dir.join("ready.marker");
        write_test_crash_marker(&marker, "wallet evidence durable").unwrap();
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"wallet evidence durable\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enumeration_distinguishes_eof_from_error_deterministically() {
        // #73 named-gap fix, WITHOUT process-global environment faults:
        // (a) EOF on a valid directory is Ok even when errno enters the call ALREADY polluted —
        //     a stale errno must never be misread as an enumeration error;
        // (b) a non-directory fd fails TYPED (fdopendir ENOTDIR) — never an empty listing.
        let dir = temp_dir("enum");
        std::fs::write(dir.join("a.json"), b"{}").unwrap();
        std::fs::write(dir.join("b.json"), b"{}").unwrap();
        // Pollute errno deliberately with a failing syscall (ENOENT).
        let missing =
            std::ffi::CString::new(format!("{}/definitely-missing", dir.display())).unwrap();
        let rc = unsafe { libc::open(missing.as_ptr(), libc::O_RDONLY) };
        assert!(rc < 0, "the polluting open must fail");
        let pinned = open_dir_pinned(&dir).unwrap();
        let mut names = enumerate_pinned(&pinned).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec!["a.json".to_string(), "b.json".to_string()],
            "EOF with polluted errno is still a COMPLETE listing"
        );
        // Non-directory fd → typed error (openat(".") ENOTDIR), never empty truth.
        let file_fd = std::fs::File::open(dir.join("a.json")).unwrap();
        assert!(
            enumerate_pinned(&file_fd).is_err(),
            "a non-directory fd is a TYPED enumeration error"
        );
        // TWO CONSECUTIVE COMPLETE enumerations on the SAME pinned fd (#73 review finding 2):
        // the stream is an independent open-file description, not a dup sharing the offset —
        // a second listing after EOF must be COMPLETE, never empty.
        let mut second = enumerate_pinned(&pinned).unwrap();
        second.sort();
        assert_eq!(
            second, names,
            "the pinned fd is reusable — the second enumeration is complete, not offset-exhausted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_dir_stream_error_branch_discards_partial_names() {
        // #73 review finding 2: exercise the ACTUAL `readdir() == NULL && errno != 0` branch
        // deterministically. The stream's underlying fd is redirected to /dev/null via dup2
        // (thread-safe: the fd number stays occupied, so closedir cannot close a stranger),
        // making the first getdents fail ENOTDIR — with entries PRESENT in the directory, the
        // result must be a typed error carrying NO names, never a partial or empty Ok.
        use std::os::unix::io::AsRawFd;
        let dir = temp_dir("drain-err");
        for n in ["x.json", "y.json", "z.json"] {
            std::fs::write(dir.join(n), b"{}").unwrap();
        }
        let pinned = open_dir_pinned(&dir).unwrap();
        let dot = std::ffi::CString::new(".").unwrap();
        let fd = unsafe {
            libc::openat(
                pinned.as_raw_fd(),
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let dp = unsafe { libc::fdopendir(fd) };
        assert!(!dp.is_null());
        let devnull = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            unsafe { libc::dup2(devnull.as_raw_fd(), fd) },
            fd,
            "dup2 sabotage failed"
        );
        let err = drain_dir_stream(dp).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "the post-readdir errno branch fired typed: {err}"
        );
        // The three real entries were NEVER served as a partial listing — the error carries none.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_family_precreation_is_durable_contained_and_preserves_existing_evidence() {
        let dir = temp_dir("precreate-families");
        let data_dir = dir.to_str().unwrap();
        std::fs::create_dir(dir.join("existing-intents")).unwrap();
        std::fs::write(
            dir.join("existing-intents").join("intent.json"),
            b"{\"retained\":true}",
        )
        .unwrap();

        precreate_family_dirs_durable(
            data_dir,
            &[
                "existing-intents",
                "genesis-intents",
                "sequence-zero-intents",
            ],
        )
        .unwrap();
        for family in [
            "existing-intents",
            "genesis-intents",
            "sequence-zero-intents",
        ] {
            assert!(
                dir.join(family).is_dir(),
                "daemon-owned family {family} exists"
            );
        }
        assert_eq!(
            std::fs::read(dir.join("existing-intents").join("intent.json")).unwrap(),
            b"{\"retained\":true}",
            "precreation preserves existing evidence byte-exactly"
        );

        let before = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            precreate_family_dirs_durable(data_dir, &["would-create", "../outside"]).is_err(),
            "all names are validated before any family is created"
        );
        assert_eq!(
            std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>(),
            before,
            "invalid family input has zero mutation"
        );

        std::fs::write(dir.join("non-directory-family"), b"residue").unwrap();
        assert!(
            precreate_family_dirs_durable(
                data_dir,
                &["not-created-after-preflight", "non-directory-family"],
            )
            .is_err(),
            "non-directory residue fails closed during preflight"
        );
        assert!(
            !dir.join("not-created-after-preflight").exists(),
            "all existing names are preflighted before creation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_family_removal_is_pinned_durable_and_refuses_nonempty_evidence() {
        let dir = temp_dir("remove-empty-family");
        let data_dir = dir.to_str().unwrap();

        std::fs::create_dir(dir.join("new-intents")).unwrap();
        remove_empty_family_durable(data_dir, "new-intents").unwrap();
        assert!(
            !dir.join("new-intents").exists(),
            "a request-created empty family is removed"
        );

        std::fs::create_dir(dir.join("retained-intents")).unwrap();
        std::fs::write(dir.join("retained-intents").join("intent.json"), b"{}").unwrap();
        let error = remove_empty_family_durable(data_dir, "retained-intents").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
        assert_eq!(
            std::fs::read(dir.join("retained-intents").join("intent.json")).unwrap(),
            b"{}",
            "nonempty evidence is preserved byte-exactly"
        );

        assert!(
            remove_empty_family_durable(data_dir, "../outside").is_err(),
            "the family boundary remains non-traversing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unconfirmed_unlink_restores_a_byte_exact_durable_replay_anchor() {
        use std::os::unix::fs::MetadataExt;

        let dir = temp_dir("unlink-restore");
        let pinned = open_dir_pinned(&dir).unwrap();
        let name = std::ffi::OsStr::new("intent.json");
        let expected = b"{\"intent\":\"retained-byte-exactly\"}";
        std::fs::write(dir.join(name), expected).unwrap();
        std::fs::File::open(&dir).unwrap().sync_all().unwrap();

        assert!(matches!(
            unlink_durable_at_with_restore(&pinned, name, "test-intents", true).unwrap(),
            UnlinkOutcome::ReplayAnchorRestoredAfterUnconfirmedRemoval(_)
        ));
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            expected,
            "the restored replay anchor preserves the exact original bytes"
        );
        assert_eq!(
            std::fs::metadata(dir.join(name)).unwrap().nlink(),
            1,
            "the restored O_TMPFILE inode has one canonical name"
        );
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == name),
            "restoration leaves no named staging residue"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_boundary_refuses_traversal_and_collisions_with_zero_mutation() {
        // #73 review finding 1: containment is enforced INSIDE the shared core.
        use serde_json::json;
        let dir = temp_dir("boundary");
        let data_dir = dir.to_str().unwrap();
        let outside = dir.join("outside-sentinel");
        std::fs::create_dir_all(&outside).unwrap();
        // (a) traversing family names are refused with ZERO mutation outside the boundary.
        assert!(open_family_dir_pinned(data_dir, "../outside-sentinel").is_err());
        assert!(matches!(
            persist_record_durable(data_dir, "../outside-sentinel", "rec", &json!({})).unwrap_err(),
            PersistFailure::NotCommitted(_)
        ));
        assert!(matches!(
            persist_receipt_no_clobber(
                data_dir,
                "fam/../../outside-sentinel",
                "orr_aa",
                &json!({})
            )
            .unwrap_err(),
            CommitFailure::NotCommitted(_)
        ));
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing was ever written outside the family boundary"
        );
        // (b) traversing slot names are refused BEFORE any syscall.
        let fam = dir.join("fam");
        std::fs::create_dir_all(&fam).unwrap();
        let pinned = open_dir_pinned(&fam).unwrap();
        assert!(read_slot_strict(&pinned, "../escape.json").is_err());
        assert!(unlink_at(&pinned, "..").is_err());
        assert!(open_file_at(&pinned, "a/b.json").is_err());
        std::fs::write(fam.join("terminal.json"), b"{}").unwrap();
        assert!(matches!(
            unlink_durable_at(&pinned, "terminal.json", "unused").unwrap(),
            UnlinkOutcome::Durable
        ));
        assert!(matches!(
            unlink_durable_at(&pinned, "terminal.json", "unused").unwrap(),
            UnlinkOutcome::Absent
        ));
        // (c) noncanonical relative paths are REFUSED by the walk, not silently skipped —
        // INCLUDING a noncanonical TERMINAL (#73 round 2): `a/..` must not validate-and-create
        // `a` and then "succeed" because only the parent was checked.
        assert!(pin_parent(&pinned, std::path::Path::new("a/.."), true).is_err());
        assert!(
            !fam.join("a").exists(),
            "pin_parent('a/..') refused with ZERO mutation — no partial mkdir"
        );
        // (c) noncanonical relative paths are REFUSED by the walk, not silently skipped.
        assert!(pin_parent(&pinned, std::path::Path::new("a/../b/file.txt"), true).is_err());
        assert!(
            std::fs::read_dir(&fam).unwrap().next().is_none(),
            "the refused walk created nothing"
        );
        // (c2) validation precedes PROMOTED-family delegation (#73 round 2): an unsafe id on a
        // promoted family is refused by the SHARED boundary itself, uniformly — never handed to
        // a backend to decide.
        assert!(
            super::super::substrate_store::is_promoted("provider-receipts"),
            "precondition: the promoted domain"
        );
        let err =
            persist_record_durable(data_dir, "provider-receipts", "a/b", &json!({})).unwrap_err();
        match err {
            PersistFailure::NotCommitted(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "uniform pre-delegation refusal: {e}"
            ),
            other => panic!("expected NotCommitted(InvalidInput), got {other:?}"),
        }
        assert!(
            !dir.join("provider-receipts").exists(),
            "nothing was created for the refused promoted write"
        );
        // (d) unsafe record ids are REJECTED, never normalized — distinct ids can no longer
        // collide on one file.
        persist_record_durable(data_dir, "recs", "a_b", &json!({ "id": "a_b" })).unwrap();
        assert!(matches!(
            persist_record_durable(data_dir, "recs", "a/b", &json!({ "id": "a/b" })).unwrap_err(),
            PersistFailure::NotCommitted(_)
        ));
        assert!(matches!(
            persist_record_durable(data_dir, "recs", "a:b", &json!({ "id": "a:b" })).unwrap_err(),
            PersistFailure::NotCommitted(_)
        ));
        let survivor: Value =
            serde_json::from_slice(&std::fs::read(dir.join("recs").join("a_b.json")).unwrap())
                .unwrap();
        assert_eq!(
            survivor["id"],
            json!("a_b"),
            "the honest record was never clobbered by a normalized collision"
        );
        assert_eq!(
            std::fs::read_dir(dir.join("recs")).unwrap().count(),
            1,
            "exactly one record exists"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_clobber_commit_is_descriptor_bound_and_certified() {
        // The extracted commit preserves the #72 contract end-to-end: fresh commit (nlink 1, no
        // residue), byte-identical replay Ok, different bytes → Conflict, swapped target after
        // commit → Swapped via certify_target.
        use std::os::unix::fs::MetadataExt;
        let dir_t = temp_dir("commit");
        let data_dir = dir_t.to_str().unwrap();
        let receipt = json!({ "receipt_id": "receipt://orr_x0", "attested": true });
        persist_receipt_no_clobber(data_dir, "evidence", "orr_x0", &receipt).unwrap();
        let slot = dir_t.join("evidence").join("orr_x0.json");
        assert_eq!(std::fs::metadata(&slot).unwrap().nlink(), 1);
        persist_receipt_no_clobber(data_dir, "evidence", "orr_x0", &receipt).unwrap(); // idempotent replay
        let different = json!({ "receipt_id": "receipt://orr_x0", "attested": false });
        assert!(matches!(
            persist_receipt_no_clobber(data_dir, "evidence", "orr_x0", &different).unwrap_err(),
            CommitFailure::Conflict(_)
        ));
        // Swap the canonical name to a different inode; certification refuses.
        let pinned = open_family_dir_pinned(data_dir, "evidence").unwrap();
        let (committed, _) = read_slot_strict(&pinned, "orr_x0.json").unwrap().unwrap();
        let bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        certify_target(&pinned, "orr_x0.json", &committed, &bytes, "unit").unwrap();
        unlink_at(&pinned, "orr_x0.json").unwrap();
        use std::io::Write;
        let mut f = open_tmpfile_at(&pinned).unwrap();
        f.write_all(b"{\"foreign\":\"SWAPPED\"}").unwrap();
        f.sync_all().unwrap();
        link_tmpfile_at(&f, &pinned, "orr_x0.json").unwrap();
        assert!(matches!(
            certify_target(&pinned, "orr_x0.json", &committed, &bytes, "unit").unwrap_err(),
            CommitFailure::Swapped(_)
        ));
        let _ = std::fs::remove_dir_all(&dir_t);
    }
}
