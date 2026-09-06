//! Incremental authenticated storage primitive for the member-store replacement.
//! This is the production member persistence path. Records are retained state,
//! never online grants. The anchor needs independent nonrollback
//! custody; a directory and its copied anchor cannot provide that custody.

use super::{
    codec, create_parent, hash_canonical, open_private, persist_atomic_with_byte_limit, store_mac,
    suffixed, verify_store_mac, QuvError, QuvHash, STORE_MAX_BYTES,
};
use fs2::FileExt;
use parity_scale_codec::{Decode, Encode};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAGIC: [u8; 8] = *b"AFTQJ001";
const ANCHOR_MAGIC: [u8; 8] = *b"AFTQJA01";
const SCHEMA: u16 = 1;
const RECORD_MAC: &[u8] = b"ioi/aft/quv-journal-record/v1\0";
const ANCHOR_MAC: &[u8] = b"ioi/aft/quv-journal-anchor/v1\0";
mod anchor_reservation;
mod reservation;
use anchor_reservation::AnchorReservation;
use reservation::{RecordReservation, ReservationLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub(super) struct JournalLimits {
    pub max_record_bytes: u64,
    /// Encoded file lengths, not filesystem allocation or metadata headroom.
    pub max_total_bytes: u64,
    /// Includes the independently provisioned bootstrap record.
    pub max_records: u64,
}

impl JournalLimits {
    fn validate(self) -> Result<(), QuvError> {
        if self.max_record_bytes < 128
            || self.max_record_bytes > self.max_total_bytes
            || self.max_total_bytes > STORE_MAX_BYTES
            || self.max_records == 0
        {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Encode, Decode)]
struct Record {
    magic: [u8; 8],
    schema: u16,
    scope: QuvHash,
    generation: u64,
    previous: QuvHash,
    payload: Vec<u8>,
    tag: QuvHash,
}

#[derive(Debug, Clone, Encode, Decode)]
struct Anchor {
    magic: [u8; 8],
    schema: u16,
    scope: QuvHash,
    generation: u64,
    head: QuvHash,
    tag: QuvHash,
}

fn mac_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + body.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(body);
    input
}

fn seal<T: Encode>(value: &T, domain: &[u8], key: &QuvHash) -> Result<Vec<u8>, QuvError> {
    // Every record/anchor ends in its fixed-width tag. Authenticate the encoded
    // body first, so a damaged Vec length is never decoded before verification.
    let mut encoded = codec::to_bytes_canonical(value).map_err(QuvError::Codec)?;
    let body_length = encoded
        .len()
        .checked_sub(32)
        .ok_or(QuvError::CorruptStore)?;
    let tag = store_mac(key, &mac_input(domain, &encoded[..body_length]))?;
    encoded[body_length..].copy_from_slice(&tag);
    Ok(encoded)
}

fn decode_authenticated<T: Decode>(
    raw: &[u8],
    domain: &[u8],
    key: &QuvHash,
) -> Result<T, QuvError> {
    let body_length = raw.len().checked_sub(32).ok_or(QuvError::CorruptStore)?;
    let tag: QuvHash = raw[body_length..]
        .try_into()
        .map_err(|_| QuvError::CorruptStore)?;
    if !verify_store_mac(key, &mac_input(domain, &raw[..body_length]), &tag)? {
        return Err(QuvError::CorruptStore);
    }
    codec::from_bytes_canonical(raw).map_err(QuvError::Codec)
}

fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, QuvError> {
    let file = File::open(path).map_err(|e| QuvError::Io(e.to_string()))?;
    let length = file
        .metadata()
        .map_err(|e| QuvError::Io(e.to_string()))?
        .len();
    if length > limit {
        return Err(QuvError::StoreCapacityExceeded);
    }
    let mut raw = Vec::new();
    file.take(
        limit
            .checked_add(1)
            .ok_or(QuvError::StoreCapacityExceeded)?,
    )
    .read_to_end(&mut raw)
    .map_err(|e| QuvError::Io(e.to_string()))?;
    if raw.len() as u64 > limit {
        return Err(QuvError::StoreCapacityExceeded);
    }
    if raw.len() as u64 != length {
        return Err(QuvError::CorruptStore);
    }
    Ok(raw)
}

fn record_path(directory: &Path, generation: u64) -> PathBuf {
    directory.join(format!("{generation:020}.quv"))
}

fn sync_parent_chain(path: &Path) -> Result<(), QuvError> {
    let parent = path.parent().ok_or(QuvError::InvalidStoreConfiguration)?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let canonical = parent
        .canonicalize()
        .map_err(|e| QuvError::Io(e.to_string()))?;
    // create_dir_all alone does not make newly created parent links durable.
    // Flush the complete existing ancestry before acknowledging any journal
    // record or anchor beneath it. Relative paths are resolved before walking.
    for directory in canonical.ancestors() {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| QuvError::Io(e.to_string()))?;
    }
    Ok(())
}
fn record_head(raw: &[u8]) -> Result<QuvHash, QuvError> {
    hash_canonical(&(b"ioi/aft/quv-journal-head/v1".to_vec(), raw))
}
fn make_record(
    scope: QuvHash,
    generation: u64,
    previous: QuvHash,
    payload: &[u8],
    key: &QuvHash,
    limits: JournalLimits,
) -> Result<Vec<u8>, QuvError> {
    if payload.is_empty() {
        return Err(QuvError::InvalidOperation);
    }
    if payload.len() as u64 > limits.max_record_bytes {
        return Err(QuvError::StoreCapacityExceeded);
    }
    let value = Record {
        magic: MAGIC,
        schema: SCHEMA,
        scope,
        generation,
        previous,
        payload: payload.to_vec(),
        tag: [0; 32],
    };
    if value.encoded_size() as u64 > limits.max_record_bytes {
        return Err(QuvError::StoreCapacityExceeded);
    }
    seal(&value, RECORD_MAC, key)
}
fn persist_anchor(
    path: &Path,
    scope: QuvHash,
    generation: u64,
    head: QuvHash,
    key: &QuvHash,
) -> Result<(), QuvError> {
    persist_atomic_with_byte_limit(path, &anchor_bytes(scope, generation, head, key)?, 128)
}
fn anchor_bytes(
    scope: QuvHash,
    generation: u64,
    head: QuvHash,
    key: &QuvHash,
) -> Result<Vec<u8>, QuvError> {
    let value = Anchor {
        magic: ANCHOR_MAGIC,
        schema: SCHEMA,
        scope,
        generation,
        head,
        tag: [0; 32],
    };
    seal(&value, ANCHOR_MAC, key)
}

pub(super) struct MemberJournal {
    directory: PathBuf,
    #[cfg(test)]
    anchor_path: PathBuf,
    _lock: File,
    key: QuvHash,
    scope: QuvHash,
    limits: JournalLimits,
    generation: u64,
    head: QuvHash,
    bytes: u64,
    failed: bool,
    reservation: Option<RecordReservation>,
    anchor_reservation: Option<AnchorReservation>,
    #[cfg(test)]
    fail_anchor_at: Option<anchor_reservation::AnchorPhase>,
}

impl MemberJournal {
    pub(super) fn requires_reopen(&self) -> bool {
        self.failed
    }

    /// Authenticate the whole retained chain, then replay into caller-owned
    /// temporary memory. `replay` must not publish authority or external effects.
    /// No pending anchor is advanced if replay refuses a semantic transition.
    #[cfg(test)]
    pub fn open(
        directory: &Path,
        anchor_path: &Path,
        key: QuvHash,
        provisioning_root: QuvHash,
        limits: JournalLimits,
        bootstrap: &[u8],
        replay: impl FnMut(u64, &[u8]) -> Result<(), QuvError>,
    ) -> Result<Self, QuvError> {
        Self::open_inner(
            directory,
            anchor_path,
            key,
            provisioning_root,
            limits,
            None,
            bootstrap,
            replay,
        )
    }

    pub(super) fn open_reserved(
        directory: &Path,
        anchor_path: &Path,
        key: QuvHash,
        provisioning_root: QuvHash,
        limits: JournalLimits,
        reservation: ReservationLimits,
        bootstrap: &[u8],
        replay: impl FnMut(u64, &[u8]) -> Result<(), QuvError>,
    ) -> Result<Self, QuvError> {
        Self::open_inner(
            directory,
            anchor_path,
            key,
            provisioning_root,
            limits,
            Some(reservation),
            bootstrap,
            replay,
        )
    }

    fn open_inner(
        directory: &Path,
        anchor_path: &Path,
        key: QuvHash,
        provisioning_root: QuvHash,
        limits: JournalLimits,
        reservation: Option<ReservationLimits>,
        bootstrap: &[u8],
        mut replay: impl FnMut(u64, &[u8]) -> Result<(), QuvError>,
    ) -> Result<Self, QuvError> {
        limits.validate()?;
        if reservation.is_some_and(|r| {
            r.records == 0
                || r.records > limits.max_records
                || r.record_bytes == 0
                || r.record_bytes > limits.max_record_bytes
        }) {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        if key == [0; 32]
            || provisioning_root == [0; 32]
            || anchor_path.starts_with(directory)
            || anchor_path.starts_with(reservation::directory(directory))
        {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        let scope = hash_canonical(&(
            b"ioi/aft/quv-journal-scope/v1".to_vec(),
            provisioning_root,
            limits,
        ))?;
        let initial = make_record(scope, 0, [0; 32], bootstrap, &key, limits)?;
        let initial_head = record_head(&initial)?;
        create_parent(anchor_path)?;
        sync_parent_chain(anchor_path)?;
        sync_parent_chain(directory)?;
        let lock = open_private(&suffixed(anchor_path, ".lock"), false)?;
        lock.try_lock_exclusive().map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                QuvError::StoreBusy
            } else {
                QuvError::Io(e.to_string())
            }
        })?;
        if !anchor_path.exists() {
            if directory.exists() {
                return Err(QuvError::IncompleteStore);
            }
            // Anchor the independently supplied bootstrap before creating its
            // record. Recovery can finish only this exact generation-zero pair.
            persist_anchor(anchor_path, scope, 0, initial_head, &key)?;
        }
        let anchor: Anchor =
            decode_authenticated(&bounded_read(anchor_path, 128)?, ANCHOR_MAC, &key)
                .map_err(|_| QuvError::InvalidAnchor)?;
        if anchor.magic != ANCHOR_MAGIC || anchor.schema != SCHEMA || anchor.head == [0; 32] {
            return Err(QuvError::InvalidAnchor);
        }
        if anchor.scope != scope {
            return Err(QuvError::ProvisioningMismatch);
        }
        if anchor.generation >= limits.max_records {
            return Err(QuvError::StoreCapacityExceeded);
        }
        if !directory.exists() {
            if anchor.generation != 0 || anchor.head != initial_head {
                return Err(QuvError::IncompleteStore);
            }
            // The caller provisions the parent. Persist this directory's link
            // before any later anchor can acknowledge records beneath it.
            std::fs::create_dir(directory).map_err(|e| QuvError::Io(e.to_string()))?;
        }
        if !std::fs::symlink_metadata(directory)
            .map_err(|e| QuvError::Io(e.to_string()))?
            .is_dir()
        {
            return Err(QuvError::CorruptStore);
        }
        if let Some(parent) = directory.parent() {
            File::open(parent)
                .and_then(|parent| parent.sync_all())
                .map_err(|e| QuvError::Io(e.to_string()))?;
        }
        let mut record_count = 0_u64;
        let mut has_initial = false;
        let mut last = 0_u64;
        let mut scratch = None;
        let mut encoded_file_bytes = 0_u64;
        for entry in std::fs::read_dir(directory).map_err(|e| QuvError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| QuvError::Io(e.to_string()))?;
            if !entry
                .file_type()
                .map_err(|e| QuvError::Io(e.to_string()))?
                .is_file()
            {
                return Err(QuvError::CorruptStore);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| QuvError::CorruptStore)?;
            let temporary = name.ends_with(".quv.tmp");
            let digits = name
                .strip_suffix(if temporary { ".quv.tmp" } else { ".quv" })
                .ok_or(QuvError::CorruptStore)?;
            let generation: u64 = digits.parse().map_err(|_| QuvError::CorruptStore)?;
            if digits != format!("{generation:020}") {
                return Err(QuvError::CorruptStore);
            }
            let length = entry
                .metadata()
                .map_err(|e| QuvError::Io(e.to_string()))?
                .len();
            if length > limits.max_record_bytes {
                return Err(QuvError::StoreCapacityExceeded);
            }
            encoded_file_bytes = encoded_file_bytes
                .checked_add(length)
                .ok_or(QuvError::StoreCapacityExceeded)?;
            if encoded_file_bytes > limits.max_total_bytes {
                return Err(QuvError::StoreCapacityExceeded);
            }
            if temporary {
                if scratch.replace((generation, length)).is_some() {
                    return Err(QuvError::CorruptStore);
                }
            } else {
                if record_count >= limits.max_records {
                    return Err(QuvError::StoreCapacityExceeded);
                }
                record_count += 1;
                has_initial |= generation == 0;
                last = last.max(generation);
            }
        }
        if !has_initial {
            if anchor.generation != 0
                || anchor.head != initial_head
                || record_count != 0
                || scratch.is_some_and(|(generation, _)| generation != 0)
            {
                return Err(QuvError::IncompleteStore);
            }
            persist_atomic_with_byte_limit(
                &record_path(directory, 0),
                &initial,
                limits.max_record_bytes,
            )?;
            record_count = 1;
            last = 0;
            scratch = None;
            encoded_file_bytes = initial.len() as u64;
        }
        // Canonical filenames are unique. Count == last + 1 and generation
        // zero imply a contiguous range, without a path allocation per record.
        if record_count != last.checked_add(1).ok_or(QuvError::GenerationExhausted)?
            || last < anchor.generation
            || last > anchor.generation.saturating_add(1)
        {
            return Err(QuvError::RollbackOrFork);
        }
        if scratch.is_some_and(|(generation, _)| {
            last != anchor.generation || last.checked_add(1) != Some(generation)
        }) {
            return Err(QuvError::CorruptStore);
        }
        // Authenticate every record before any semantic callback. Then reread
        // and reauthenticate one record at a time into private replay memory.
        // The second complete chain must end at the identical authenticated
        // head before recovery may advance an anchor or return retained state.
        // This trades a second linear read for bounded auxiliary memory; it
        // never buffers all retained payloads or record paths.
        let mut authenticated_head = [0; 32];
        let mut previous = [0; 32];
        let mut bytes = 0_u64;
        for replay_pass in [false, true] {
            previous = [0; 32];
            bytes = 0;
            for generation in 0..=last {
                let raw =
                    bounded_read(&record_path(directory, generation), limits.max_record_bytes)?;
                if let Some(reservation) = reservation {
                    let bound = if generation == 0 {
                        initial.len() as u64
                    } else {
                        reservation.record_bytes
                    };
                    if raw.len() as u64 > bound {
                        return Err(QuvError::StoreCapacityExceeded);
                    }
                    reservation::check_charge(
                        &File::open(record_path(directory, generation))
                            .map_err(|e| QuvError::Io(e.to_string()))?,
                        bound,
                    )?;
                }
                let record: Record = decode_authenticated(&raw, RECORD_MAC, &key)?;
                if record.magic != MAGIC
                    || record.schema != SCHEMA
                    || record.generation != generation
                    || record.previous != previous
                    || record.payload.is_empty()
                {
                    return Err(QuvError::CorruptStore);
                }
                if record.scope != scope || (generation == 0 && record.payload != bootstrap) {
                    return Err(QuvError::ProvisioningMismatch);
                }
                previous = record_head(&raw)?;
                if generation == anchor.generation && previous != anchor.head {
                    return Err(QuvError::RollbackOrFork);
                }
                bytes = bytes
                    .checked_add(raw.len() as u64)
                    .ok_or(QuvError::StoreCapacityExceeded)?;
                if bytes > limits.max_total_bytes {
                    return Err(QuvError::StoreCapacityExceeded);
                }
                if replay_pass && generation != 0 {
                    replay(generation, &record.payload)?;
                }
            }
            if bytes.checked_add(scratch.map_or(0, |(_, length)| length))
                != Some(encoded_file_bytes)
            {
                return Err(QuvError::CorruptStore);
            }
            if replay_pass {
                if previous != authenticated_head {
                    return Err(QuvError::RollbackOrFork);
                }
            } else {
                authenticated_head = previous;
            }
        }
        let reservation = reservation
            .map(|limits| {
                RecordReservation::prepare(
                    directory,
                    scope,
                    &key,
                    limits,
                    last.checked_add(1).ok_or(QuvError::GenerationExhausted)?,
                )
            })
            .transpose()?;
        // Only the authenticated active anchor is used to prepare both copies.
        // Inactive bytes never select the recovered generation or head.
        let anchor_reservation = if reservation.is_some() {
            Some(AnchorReservation::prepare(
                anchor_path,
                &anchor_bytes(scope, anchor.generation, anchor.head, &key)?,
            )?)
        } else {
            None
        };
        if last != anchor.generation {
            if let Some(reserved) = &anchor_reservation {
                let raw = anchor_bytes(scope, last, previous, &key)?;
                reserved.prepare_update(&raw)?.commit(&raw)?;
            } else {
                persist_anchor(anchor_path, scope, last, previous, &key)?;
            }
        }
        // A partial next record was never acknowledged. Remove it only after
        // authentication and semantic replay, so cached headroom counts all
        // remaining files and the next append starts from a durable clean state.
        if let Some((generation, _)) = scratch {
            std::fs::remove_file(suffixed(&record_path(directory, generation), ".tmp"))
                .and_then(|()| File::open(directory)?.sync_all())
                .map_err(|e| QuvError::Io(e.to_string()))?;
        }
        Ok(Self {
            directory: directory.into(),
            #[cfg(test)]
            anchor_path: anchor_path.into(),
            _lock: lock,
            key,
            scope,
            limits,
            generation: last,
            head: previous,
            bytes,
            failed: false,
            reservation,
            anchor_reservation,
            #[cfg(test)]
            fail_anchor_at: None,
        })
    }

    /// Caller validates its semantic transition before append. This method
    /// commits bytes and anchor before returning; it never signs a member reply.
    #[cfg(test)]
    pub fn append(&mut self, payload: &[u8]) -> Result<(), QuvError> {
        self.append_with_prewrite_check(payload, || Ok(()))
    }

    /// Run the caller's final process-local continuation check after encoding,
    /// authentication, hashing, and capacity admission, immediately before the
    /// first durable write. Refusal leaves both disk and the healthy state alone.
    /// The callback cannot access this journal while it is exclusively borrowed.
    pub fn append_with_prewrite_check(
        &mut self,
        payload: &[u8],
        check: impl FnOnce() -> Result<(), QuvError>,
    ) -> Result<(), QuvError> {
        if self.failed {
            return Err(QuvError::StoreRequiresReopen);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(QuvError::GenerationExhausted)?;
        if generation >= self.limits.max_records {
            return Err(QuvError::StoreCapacityExceeded);
        }
        let raw = make_record(
            self.scope,
            generation,
            self.head,
            payload,
            &self.key,
            self.limits,
        )?;
        let bytes = self
            .bytes
            .checked_add(raw.len() as u64)
            .ok_or(QuvError::StoreCapacityExceeded)?;
        if bytes > self.limits.max_total_bytes {
            return Err(QuvError::StoreCapacityExceeded);
        }
        let path = record_path(&self.directory, generation);
        if path.exists() {
            self.failed = true;
            return Err(QuvError::StoreRequiresReopen);
        }
        let head = record_head(&raw)?;
        let reserved = match &self.reservation {
            Some(pool) => match pool.prepare_record(generation, raw.len() as u64) {
                Ok(record) => Some(record),
                Err(error) => {
                    if !matches!(error, QuvError::StoreCapacityExceeded) {
                        self.failed = true;
                    }
                    return Err(error);
                }
            },
            None => None,
        };
        #[cfg(not(test))]
        if reserved.is_none() {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        let anchor_raw = anchor_bytes(self.scope, generation, head, &self.key)?;
        let anchor_update = match &self.anchor_reservation {
            Some(anchor) => match anchor.prepare_update(&anchor_raw) {
                Ok(update) => Some(update),
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            },
            None => None,
        };
        #[cfg(not(test))]
        if anchor_update.is_none() {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        check()?;
        self.failed = true;
        if let Some(record) = reserved {
            record.commit(&raw)?;
        } else {
            // Raw unreserved journals exist only in corruption/format fixtures.
            #[cfg(test)]
            persist_atomic_with_byte_limit(&path, &raw, self.limits.max_record_bytes)?;
        }
        if let Some(update) = anchor_update {
            #[cfg(test)]
            let failure = self.fail_anchor_at.take();
            update.commit_with_hook(&anchor_raw, |_phase| {
                #[cfg(test)]
                if failure == Some(_phase) {
                    return Err(QuvError::Io(
                        "injected reserved anchor commit failure".into(),
                    ));
                }
                Ok(())
            })?;
        } else {
            #[cfg(test)]
            persist_anchor(&self.anchor_path, self.scope, generation, head, &self.key)?;
        }
        self.generation = generation;
        self.head = head;
        self.bytes = bytes;
        self.failed = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) mod member_store;

#[cfg(test)]
pub(super) mod fixture;
