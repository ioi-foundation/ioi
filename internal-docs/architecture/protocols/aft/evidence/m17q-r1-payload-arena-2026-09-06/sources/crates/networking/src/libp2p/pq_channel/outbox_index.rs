//! Immutable entry files plus an atomically replaced ordered queue index.
//! Payload durability precedes index visibility; retirement follows it.
use super::*;
use std::io::Read;
const MAGIC: [u8; 8] = *b"AFTPQI03";
const ARENA_MAGIC: [u8; 8] = *b"AFTPQI05";
#[derive(Encode, Decode, PartialEq, Eq)]
struct Scope(u16, u16, [u8; 32], [u8; 32], u64, AccountId);
impl Scope {
    fn of(s: &PqOutboxStateV2) -> Self {
        Self(
            s.protocol_version,
            s.schema_version,
            s.network_id,
            s.configuration_hash,
            s.epoch,
            s.local_account_id,
        )
    }
}
#[derive(Encode, Decode)]
struct Index {
    magic: [u8; 8],
    scope: Scope,
    entries: Vec<(AccountId, [u8; 32])>,
}
fn directory(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".entries");
    PathBuf::from(name)
}
pub(super) fn entry_path(path: &Path, id: &[u8; 32]) -> PathBuf {
    directory(path).join(
        id.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}
fn bounded_read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > max {
        return Err(anyhow!("PQ outbox file exceeds encoded capacity"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(anyhow!("PQ outbox file grew beyond capacity"));
    }
    Ok(bytes)
}
pub(super) fn is_index(path: &Path) -> Result<bool> {
    let mut magic = [0; 8];
    let mut file = File::open(path)?;
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == MAGIC || magic == outbox_reservation::MAGIC),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn uses_arena(path: &Path) -> Result<bool> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)?;
    if outbox_reservation::is_reserved(path)? {
        file.seek(SeekFrom::Start(48))?;
    }
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    Ok(magic == ARENA_MAGIC)
}
pub(super) fn read(
    path: &Path,
    expected: &PqOutboxStateV2,
    accounts: &std::collections::BTreeSet<AccountId>,
) -> Result<PqOutboxStateV2> {
    let count = accounts
        .len()
        .checked_mul(PQ_OUTBOX_PER_RECIPIENT_MAX)
        .ok_or_else(|| anyhow!("PQ index capacity overflow"))?;
    let max = (count as u64)
        .checked_mul(64)
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| anyhow!("PQ index byte capacity overflow"))?;
    let index: Index = codec::from_bytes_canonical(&outbox_reservation::read(path, max)?)
        .map_err(anyhow::Error::msg)?;
    if ![MAGIC, ARENA_MAGIC].contains(&index.magic)
        || index.scope != Scope::of(expected)
        || index.entries.len() > count
    {
        return Err(anyhow!("PQ outbox index scope/version/count mismatch"));
    }
    let mut state = expected.clone();
    let mut arena = if index.magic == ARENA_MAGIC {
        Some(outbox_arena::Arena::open(path, expected, accounts)?)
    } else {
        None
    };
    let mut byte_usage = OutboxByteUsage::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut counts = HashMap::<AccountId, usize>::new();
    for (recipient, id) in index.entries {
        if !accounts.contains(&recipient) || !seen.insert(id) {
            return Err(anyhow!(
                "PQ outbox index has a foreign recipient or repeated entry"
            ));
        }
        let used = counts.entry(recipient).or_default();
        *used += 1;
        if *used > PQ_OUTBOX_PER_RECIPIENT_MAX {
            return Err(anyhow!("PQ index recipient capacity exceeded"));
        }
        let entry: PqOutboxEntryV2 = if let Some(arena) = arena.as_mut() {
            if arena.contains(recipient, id)? {
                arena.read(recipient, id)?
            } else {
                let raw = bounded_read(
                    &entry_path(path, &id),
                    64 + PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 as u64,
                )?;
                let entry: PqOutboxEntryV2 =
                    codec::from_bytes_canonical(&raw).map_err(anyhow::Error::msg)?;
                if is_quv_payload(&entry.payload) {
                    return Err(anyhow!(
                        "QUV payload cannot fall back from the arena to a retired file"
                    ));
                }
                entry
            }
        } else {
            let raw = bounded_read(
                &entry_path(path, &id),
                64 + PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 as u64,
            )?;
            codec::from_bytes_canonical(&raw).map_err(anyhow::Error::msg)?
        };
        if entry.recipient_account_id != recipient || entry.message_id != id {
            return Err(anyhow!("PQ outbox index/entry binding mismatch"));
        }
        byte_usage.observe(entry.recipient_account_id, &entry.payload)?;
        state.entries.push(Arc::new(entry));
    }
    Ok(state)
}
fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = outbox_temp_path(path);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp, path)?;
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("PQ storage path has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CommitPhase {
    PayloadsDurable,
    InactiveIndexDurable,
    IndexExchanged,
    IndexDurable,
}

pub(super) fn persist(
    path: &Path,
    previous: Option<&PqOutboxStateV2>,
    next: &PqOutboxStateV2,
    accounts: Option<&std::collections::BTreeSet<AccountId>>,
) -> Result<()> {
    persist_with_hook(path, previous, next, accounts, |_| Ok(()))
}

pub(super) fn persist_with_hook(
    path: &Path,
    previous: Option<&PqOutboxStateV2>,
    next: &PqOutboxStateV2,
    accounts: Option<&std::collections::BTreeSet<AccountId>>,
    mut hook: impl FnMut(CommitPhase) -> Result<()>,
) -> Result<()> {
    if previous.is_some() && accounts.is_none() {
        return Err(anyhow!("live PQ outbox requires reserved payload storage"));
    }
    if let Some(accounts) = accounts {
        outbox_arena::Arena::open(path, next, accounts)?.stage(previous, next)?;
    }
    let dir = directory(path);
    if !dir.exists() {
        create_outbox_directory(&dir)?;
    }
    let previous_ids: std::collections::BTreeSet<_> = previous
        .into_iter()
        .flat_map(|s| s.entries.iter().map(|entry| entry.message_id))
        .collect();
    let next_ids: std::collections::BTreeSet<_> =
        next.entries.iter().map(|e| e.message_id).collect();
    for entry in &next.entries {
        if accounts.is_some() && is_quv_payload(&entry.payload) {
            continue;
        }
        if previous_ids.contains(&entry.message_id) {
            continue;
        }
        let target = entry_path(path, &entry.message_id);
        let encoded = entry.encode();
        if target.exists() {
            if bounded_read(&target, 64 + PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 as u64)? != encoded {
                return Err(anyhow!("PQ immutable entry differs from pending payload"));
            }
        } else {
            atomic_bytes(&target, &encoded)?;
        }
    }
    hook(CommitPhase::PayloadsDurable)?;
    let index = Index {
        magic: if accounts.is_some() {
            ARENA_MAGIC
        } else {
            MAGIC
        },
        scope: Scope::of(next),
        entries: next
            .entries
            .iter()
            .map(|e| (e.recipient_account_id, e.message_id))
            .collect(),
    };
    let encoded = index.encode();
    if outbox_reservation::is_reserved(path)? {
        outbox_reservation::commit(path, &encoded, &mut hook)?;
    } else {
        // Startup conversion only: live handles always reserve before admission.
        if previous.is_some() {
            return Err(anyhow!("PQ live index has lost its reserved format"));
        }
        atomic_bytes(path, &encoded)?;
    }
    hook(CommitPhase::IndexDurable)?;
    // Index replacement is the queue commit. A subsequent error quarantines
    // the caller; reopen uses the new index and never resurrects retired bytes.
    let mut retired_files = false;
    for entry in previous.into_iter().flat_map(|s| &s.entries) {
        if !next_ids.contains(&entry.message_id)
            && !(accounts.is_some() && is_quv_payload(&entry.payload))
        {
            std::fs::remove_file(entry_path(path, &entry.message_id))?;
            retired_files = true;
        }
    }
    if retired_files {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Called only after the complete active index and every referenced payload
/// have validated. Orphan bytes cannot add a queue entry or revive an ACK.
pub(super) fn cleanup(path: &Path, state: &PqOutboxStateV2, indexed: bool) -> Result<()> {
    let dir = directory(path);
    if !dir.exists() {
        return Ok(());
    }
    if !std::fs::symlink_metadata(&dir)?.file_type().is_dir() {
        return Err(anyhow!("PQ entry storage is not a real directory"));
    }
    let arena_active = indexed && uses_arena(path)?;
    let live: std::collections::BTreeSet<_> = state
        .entries
        .iter()
        .filter(|entry| indexed && !(arena_active && is_quv_payload(&entry.payload)))
        .map(|e| entry_path(path, &e.message_id))
        .collect();
    let mut retired = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow!("unrecognized PQ entry filename"))?;
        let stem = name.strip_suffix(".tmp").unwrap_or(name);
        if !entry.file_type()?.is_file()
            || stem.len() != 64
            || !stem
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(anyhow!("unrecognized PQ entry directory content"));
        }
        if !live.contains(&entry.path()) {
            retired.push(entry.path());
        }
    }
    let changed = !retired.is_empty();
    for path in retired {
        std::fs::remove_file(path)?;
    }
    if changed {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}
