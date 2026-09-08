//! Four fixed payload slots per rooted recipient: two retained, two staging.
//! Only the committed queue index selects live data. Old slot bytes grant nothing.
use super::*;
use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"AFTPQA01";
const HEADER_BYTES: u64 = 4096;
const SLOT_HEADER: usize = 72;
pub(super) const SLOTS: usize = 4;
pub(super) const SLOT_BYTES: u64 = 20480;

pub(super) fn path(index: &Path) -> PathBuf {
    let mut path = index.as_os_str().to_os_string();
    path.push(".quv-arena");
    PathBuf::from(path)
}

fn length(accounts: usize) -> Result<u64> {
    (accounts as u64)
        .checked_mul(SLOTS as u64 * SLOT_BYTES)
        .and_then(|n| n.checked_add(HEADER_BYTES))
        .ok_or_else(|| anyhow!("QUV arena capacity overflow"))
}
fn digest(bytes: &[u8]) -> Result<[u8; 32]> {
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|e| anyhow!(e.to_string()))
}
fn header(state: &PqOutboxStateV2, accounts: &BTreeSet<AccountId>) -> Result<Vec<u8>> {
    let scope = (
        state.protocol_version,
        state.schema_version,
        state.network_id,
        state.configuration_hash,
        state.epoch,
        state.local_account_id,
        accounts,
    )
        .encode();
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&digest(&scope)?);
    Ok(bytes)
}

pub(super) struct Arena {
    file: File,
    accounts: Vec<AccountId>,
}
impl Arena {
    pub(super) fn open(
        index: &Path,
        state: &PqOutboxStateV2,
        accounts: &BTreeSet<AccountId>,
    ) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(path(index))?;
        outbox_reservation::check_allocation(&file, length(accounts.len())?)?;
        let expected = header(state, accounts)?;
        let mut actual = vec![0; expected.len()];
        file.read_exact(&mut actual)?;
        if actual != expected {
            return Err(anyhow!("QUV arena root/scope mismatch"));
        }
        Ok(Self {
            file,
            accounts: accounts.iter().copied().collect(),
        })
    }

    fn offset(&self, recipient: AccountId, slot: usize) -> Result<u64> {
        let account = self
            .accounts
            .binary_search(&recipient)
            .map_err(|_| anyhow!("QUV arena recipient is not rooted"))?;
        if slot >= SLOTS {
            return Err(anyhow!("QUV arena slot out of range"));
        }
        Ok(HEADER_BYTES + (account * SLOTS + slot) as u64 * SLOT_BYTES)
    }

    fn find(&mut self, recipient: AccountId, id: [u8; 32]) -> Result<(usize, PqOutboxEntryV2)> {
        for slot in 0..SLOTS {
            self.file
                .seek(SeekFrom::Start(self.offset(recipient, slot)?))?;
            let mut header = [0; SLOT_HEADER];
            self.file.read_exact(&mut header)?;
            let used = u64::from_le_bytes(header[32..40].try_into()?);
            if used == 0 || header[..32] != id {
                continue;
            }
            if used > 64 + ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0 {
                return Err(anyhow!("QUV arena slot length exceeds frame capacity"));
            }
            let mut body = vec![0; usize::try_from(used)?];
            self.file.read_exact(&mut body)?;
            if digest(&body)? != header[40..72] {
                return Err(anyhow!("QUV arena payload checksum mismatch"));
            }
            let entry: PqOutboxEntryV2 =
                codec::from_bytes_canonical(&body).map_err(anyhow::Error::msg)?;
            if entry.message_id != id
                || entry.recipient_account_id != recipient
                || !is_quv_payload(&entry.payload)
            {
                return Err(anyhow!("QUV arena index/entry binding mismatch"));
            }
            return Ok((slot, entry));
        }
        Err(anyhow!("QUV committed payload missing from reserved arena"))
    }

    pub(super) fn read(&mut self, recipient: AccountId, id: [u8; 32]) -> Result<PqOutboxEntryV2> {
        self.find(recipient, id).map(|(_, entry)| entry)
    }

    pub(super) fn contains(&mut self, recipient: AccountId, id: [u8; 32]) -> Result<bool> {
        for slot in 0..SLOTS {
            self.file
                .seek(SeekFrom::Start(self.offset(recipient, slot)?))?;
            let mut header = [0; 40];
            self.file.read_exact(&mut header)?;
            if header[..32] == id && u64::from_le_bytes(header[32..40].try_into()?) != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn stage(
        &mut self,
        previous: Option<&PqOutboxStateV2>,
        next: &PqOutboxStateV2,
    ) -> Result<()> {
        validate_outbox_byte_profile(&next.entries)?;
        if let Some(previous) = previous {
            validate_outbox_byte_profile(&previous.entries)?;
        }
        let mut protected = HashSet::new();
        let mut previous_ids = HashSet::new();
        for entry in previous
            .into_iter()
            .flat_map(|s| &s.entries)
            .filter(|e| is_quv_payload(&e.payload))
        {
            let (slot, stored) = self.find(entry.recipient_account_id, entry.message_id)?;
            if stored != **entry {
                return Err(anyhow!("QUV retained arena entry differs"));
            }
            protected.insert((entry.recipient_account_id, slot));
            previous_ids.insert(entry.message_id);
        }
        // Plan and validate every new slot before any write. Both old lanes
        // remain protected even when the next index retires/replaces them.
        let mut planned = Vec::new();
        for entry in next
            .entries
            .iter()
            .filter(|e| is_quv_payload(&e.payload) && !previous_ids.contains(&e.message_id))
        {
            let slot = (0..SLOTS)
                .find(|slot| !protected.contains(&(entry.recipient_account_id, *slot)))
                .ok_or_else(|| anyhow!("QUV arena has no uncommitted staging slot"))?;
            let offset = self.offset(entry.recipient_account_id, slot)?;
            let body = entry.encode();
            if body.len() as u64 > 64 + ioi_types::app::QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0
                || body.len() + SLOT_HEADER > SLOT_BYTES as usize
            {
                return Err(anyhow!("QUV arena frame exceeds reserved slot"));
            }
            protected.insert((entry.recipient_account_id, slot));
            planned.push((offset, entry.message_id, digest(&body)?, body));
        }
        let changed = !planned.is_empty();
        for (offset, id, checksum, body) in planned {
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&id)?;
            self.file.write_all(&(body.len() as u64).to_le_bytes())?;
            self.file.write_all(&checksum)?;
            self.file.write_all(&body)?;
        }
        if changed {
            self.file.sync_all()?;
        }
        Ok(())
    }
}

/// Startup initialization is permitted only while the validated old index
/// still owns all payload files. An arena-backed active index is never reset.
pub(super) fn prepare(
    index: &Path,
    state: &PqOutboxStateV2,
    accounts: &BTreeSet<AccountId>,
    already_active: bool,
) -> Result<()> {
    if already_active {
        Arena::open(index, state, accounts)?;
        return Ok(());
    }
    let mut file = outbox_reservation::allocated_file(&path(index), length(accounts.len())?)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header(state, accounts)?)?;
    file.sync_all()?;
    File::open(
        index
            .parent()
            .ok_or_else(|| anyhow!("QUV arena has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
