//! Multiplexed multi-domain log: the single-box flush combiner.
//!
//! fsync is a per-file, device-wide barrier — separate per-domain log files
//! cannot amortize it (measured: 8 separate domain logs on one NVMe hit the
//! same aggregate as 1). This module multiplexes many domains' frames into
//! ONE append-only file so one `fdatasync` durably commits every domain's
//! batch, while each domain keeps an INDEPENDENT head map, sequence, and
//! root chain — the file is an I/O artifact, never a truth coupling
//! (doctrine: ownership-partitioned serialization; admission of a domain's
//! heads remains that domain's only serialization point).
//!
//! Same determinism rule as the base engine: no clock, no randomness;
//! a domain's roots depend only on that domain's operation order.

use crate::{
    sha_hex_pub as sha_hex, validate_head_condition, AdmitAck, AdmittedRecord, BatchRootRecord,
    CheckpointRecord, Durability, Head, Operation, Refusal, Root, GENESIS_ROOT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

const MAX_STRICT_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_STRICT_PENDING_RECORDS: usize = 1_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame")]
pub enum MuxLogFrame {
    Admitted(AdmittedRecord),
    DomainRoot {
        domain: String,
        rec: BatchRootRecord,
    },
    /// Writer-epoch bump: the fencing primitive. A promoted engine appends
    /// `epoch+1`; replicas reject stream traffic from lower epochs, so a
    /// deposed primary cannot split the brain. Epoch frames ride the same
    /// log (and therefore ship to replicas byte-identically); they do not
    /// participate in domain root chains.
    EpochBump {
        epoch: u64,
        recorded_at_ms: u64,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainState {
    pub heads: BTreeMap<String, Head>,
    pub next_seq: u64,
    pub next_batch_seq: u64,
    pub root: Root,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExactProjection {
    pub operation: Operation,
    pub seq: u64,
    pub head: Head,
    pub admission_batch_seq: u64,
    pub admission_root: Root,
    pub terminal_root: Root,
}

struct StrictDomainState {
    terminal: DomainState,
    pending_records: Vec<AdmittedRecord>,
    pending_hashes: Vec<u8>,
}

impl StrictDomainState {
    fn new() -> Self {
        Self {
            terminal: DomainState::new(),
            pending_records: Vec::new(),
            pending_hashes: Vec::new(),
        }
    }
}

impl DomainState {
    fn new() -> Self {
        Self {
            heads: BTreeMap::new(),
            next_seq: 0,
            next_batch_seq: 0,
            root: GENESIS_ROOT.to_string(),
        }
    }
}

fn invalid_log(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn read_exact_or_clean_eof(
    reader: &mut impl Read,
    buffer: &mut [u8],
    label: &str,
) -> std::io::Result<bool> {
    let mut read = 0usize;
    while read < buffer.len() {
        match reader.read(&mut buffer[read..]) {
            Ok(0) if read == 0 => return Ok(false),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("partial {label}: read {read} of {} bytes", buffer.len()),
                ));
            }
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn read_strict_frame(
    reader: &mut impl Read,
    frame_index: u64,
) -> std::io::Result<Option<(MuxLogFrame, Vec<u8>)>> {
    let mut length_bytes = [0u8; 4];
    if !read_exact_or_clean_eof(reader, &mut length_bytes, "mux frame length")? {
        return Ok(None);
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_STRICT_FRAME_BYTES {
        return Err(invalid_log(format!(
            "mux frame {frame_index} length {length} is outside 1..={MAX_STRICT_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0u8; length];
    if !read_exact_or_clean_eof(reader, &mut body, "mux frame body")? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("mux frame {frame_index} body is absent"),
        ));
    }
    let frame = serde_json::from_slice::<MuxLogFrame>(&body).map_err(|error| {
        invalid_log(format!(
            "mux frame {frame_index} is malformed JSON ({error})"
        ))
    })?;
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&length_bytes);
    encoded.extend_from_slice(&body);
    Ok(Some((frame, encoded)))
}

pub struct MuxEngine {
    dir: PathBuf,
    log: File,
    domains: BTreeMap<String, DomainState>,
    sync_on_commit: bool,
    current_epoch: u64,
}

impl MuxEngine {
    pub fn open(dir: &Path, sync_on_commit: bool) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.join("checkpoints"))?;
        let log_path = dir.join("muxlog.bin");
        let mut domains: BTreeMap<String, DomainState> = BTreeMap::new();
        let mut current_epoch = 0u64;
        if log_path.exists() {
            let file_len = std::fs::metadata(&log_path)?.len();
            let mut r = BufReader::new(File::open(&log_path)?);
            let mut len_buf = [0u8; 4];
            // WAL recovery: torn/unparseable tail = incomplete unacked
            // batch; truncate to the last valid frame boundary.
            let mut valid: u64 = 0;
            loop {
                if r.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut frame = vec![0u8; len];
                if r.read_exact(&mut frame).is_err() {
                    break;
                }
                let Ok(frame) = serde_json::from_slice::<MuxLogFrame>(&frame) else {
                    break;
                };
                match frame {
                    MuxLogFrame::Admitted(rec) => {
                        let st = domains
                            .entry(rec.op.domain.clone())
                            .or_insert_with(DomainState::new);
                        st.heads
                            .insert(rec.op.object_ref.clone(), rec.new_head.clone());
                        st.next_seq = rec.seq + 1;
                    }
                    MuxLogFrame::DomainRoot { domain, rec } => {
                        let st = domains.entry(domain).or_insert_with(DomainState::new);
                        st.root = rec.root.clone();
                        st.next_batch_seq = rec.batch_seq + 1;
                    }
                    MuxLogFrame::EpochBump { epoch, .. } => {
                        current_epoch = current_epoch.max(epoch);
                    }
                }
                valid += 4 + len as u64;
            }
            if valid < file_len {
                OpenOptions::new()
                    .write(true)
                    .open(&log_path)?
                    .set_len(valid)?;
            }
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            log,
            domains,
            sync_on_commit,
            current_epoch,
        })
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Current log length in bytes (frame-boundary aligned after open()'s
    /// torn-tail truncation) — the catch-up handshake offset.
    pub fn log_len(&self) -> std::io::Result<u64> {
        Ok(std::fs::metadata(self.dir.join("muxlog.bin"))
            .map(|m| m.len())
            .unwrap_or(0))
    }

    /// Append an epoch bump (durable per sync mode) and adopt it.
    pub fn begin_epoch(&mut self, epoch: u64, recorded_at_ms: u64) -> std::io::Result<()> {
        if epoch <= self.current_epoch && !(epoch == 0 && self.current_epoch == 0) {
            return Err(std::io::Error::other(format!(
                "epoch must advance: current={} requested={epoch}",
                self.current_epoch
            )));
        }
        let frame = Self::encode(&MuxLogFrame::EpochBump {
            epoch,
            recorded_at_ms,
        })?;
        self.log.write_all(&frame)?;
        if self.sync_on_commit {
            self.log.sync_data()?;
        }
        self.current_epoch = epoch;
        Ok(())
    }

    /// Promote this engine (typically a caught-up replica dir opened as
    /// primary) to the next writer epoch. Mints a durable promotion record —
    /// the receipt substrate for operator-driven failover. Any prior primary
    /// still streaming at the old epoch is fenced by replicas from here on.
    pub fn promote(&mut self, recorded_at_ms: u64) -> std::io::Result<serde_json::Value> {
        let prior = self.current_epoch;
        let new_epoch = prior + 1;
        self.begin_epoch(new_epoch, recorded_at_ms)?;
        let roots: BTreeMap<String, Root> = self
            .domains
            .iter()
            .map(|(d, st)| (d.clone(), st.root.clone()))
            .collect();
        let record = serde_json::json!({
            "record": "ioi.agentgres.writer-promotion.v1",
            "prior_epoch": prior,
            "new_epoch": new_epoch,
            "domain_roots": roots,
            "recorded_at_ms": recorded_at_ms,
        });
        std::fs::write(
            self.dir
                .join("checkpoints")
                .join(format!("promotion-epoch-{new_epoch:06}.json")),
            serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?,
        )?;
        Ok(record)
    }

    fn encode(frame: &MuxLogFrame) -> std::io::Result<Vec<u8>> {
        let body = serde_json::to_vec(frame).map_err(std::io::Error::other)?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn dir_path(&self) -> &Path {
        &self.dir
    }

    pub fn domain_root(&self, domain: &str) -> Option<&Root> {
        self.domains.get(domain).map(|d| &d.root)
    }
    pub fn domain_head(&self, domain: &str, object_ref: &str) -> Option<&Head> {
        self.domains
            .get(domain)
            .and_then(|d| d.heads.get(object_ref))
    }
    pub fn domain_next_seq(&self, domain: &str) -> u64 {
        self.domains.get(domain).map(|d| d.next_seq).unwrap_or(0)
    }
    pub fn domains(&self) -> impl Iterator<Item = &String> {
        self.domains.keys()
    }

    /// One combined durable batch across many domains: frames appended in
    /// input order, per-domain root frames after (BTreeMap order —
    /// deterministic), then ONE write + (in sync mode) ONE fsync for every
    /// domain at once.
    pub fn admit_batch(
        &mut self,
        ops: Vec<Operation>,
    ) -> std::io::Result<Vec<Result<AdmitAck, Refusal>>> {
        self.admit_batch_full(ops).map(|(results, _bytes)| results)
    }

    /// Explicit device flush of the log (used by async-flush ack policies
    /// on a cadence and at shutdown).
    pub fn sync_log(&mut self) -> std::io::Result<()> {
        self.log.sync_data()
    }

    /// `admit_batch` variant that also returns the exact appended log bytes
    /// so an ack policy can ship them to a replica (log shipping: the
    /// replica's file is byte-identical, so its replayed roots are
    /// identical by construction).
    pub fn admit_batch_full(
        &mut self,
        ops: Vec<Operation>,
    ) -> std::io::Result<(Vec<Result<AdmitAck, Refusal>>, Vec<u8>)> {
        if ops.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut results: Vec<Option<Result<AdmitAck, Refusal>>> = vec![None; ops.len()];
        let mut staged_heads: BTreeMap<String, BTreeMap<String, Head>> = BTreeMap::new();
        let mut staged_count: BTreeMap<String, u64> = BTreeMap::new();
        let mut frame_hashes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut from_seq: BTreeMap<String, u64> = BTreeMap::new();
        let mut admitted_idx: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut buf: Vec<u8> = Vec::with_capacity(ops.len() * 256);
        let mut recs: Vec<Option<AdmittedRecord>> = vec![None; ops.len()];
        for (i, op) in ops.into_iter().enumerate() {
            if op.object_ref.is_empty() {
                results[i] = Some(Err(Refusal::EmptyObjectRef));
                continue;
            }
            let committed = self.domains.get(&op.domain);
            let dom_staged = staged_heads.entry(op.domain.clone()).or_default();
            let effective = dom_staged
                .get(&op.object_ref)
                .or_else(|| committed.and_then(|d| d.heads.get(&op.object_ref)));
            let ok = validate_head_condition(&op, effective);
            if let Err(refusal) = ok {
                results[i] = Some(Err(refusal));
                continue;
            }
            let committed_next = committed.map(|d| d.next_seq).unwrap_or(0);
            let staged_n = staged_count.entry(op.domain.clone()).or_insert(0);
            let seq = committed_next + *staged_n;
            from_seq.entry(op.domain.clone()).or_insert(seq);
            *staged_n += 1;
            let op_bytes = serde_json::to_vec(&op).map_err(std::io::Error::other)?;
            let prev = effective.cloned().unwrap_or_default();
            let new_head = sha_hex(&[b"head|", prev.as_bytes(), b"|", &op_bytes]);
            dom_staged.insert(op.object_ref.clone(), new_head.clone());
            let rec = AdmittedRecord { seq, new_head, op };
            let frame = Self::encode(&MuxLogFrame::Admitted(rec.clone()))?;
            let mut fh = Sha256::new();
            fh.update(&frame);
            frame_hashes
                .entry(rec.op.domain.clone())
                .or_default()
                .extend_from_slice(&fh.finalize());
            admitted_idx
                .entry(rec.op.domain.clone())
                .or_default()
                .push(i);
            buf.extend_from_slice(&frame);
            recs[i] = Some(rec);
        }
        if admitted_idx.is_empty() {
            return Ok((
                results.into_iter().map(|r| r.unwrap()).collect(),
                Vec::new(),
            ));
        }
        // Per-domain root frames, deterministic domain order.
        let mut domain_roots: BTreeMap<String, BatchRootRecord> = BTreeMap::new();
        for (domain, hashes) in &frame_hashes {
            let st = self
                .domains
                .entry(domain.clone())
                .or_insert_with(DomainState::new);
            let count = staged_count[domain];
            let fs = from_seq[domain];
            let root = sha_hex(&[b"root|", st.root.as_bytes(), b"|", hashes]);
            let br = BatchRootRecord {
                batch_seq: st.next_batch_seq,
                from_seq: fs,
                to_seq: fs + count - 1,
                prev_root: st.root.clone(),
                root,
            };
            buf.extend_from_slice(&Self::encode(&MuxLogFrame::DomainRoot {
                domain: domain.clone(),
                rec: br.clone(),
            })?);
            domain_roots.insert(domain.clone(), br);
        }
        // Durability point: ONE write + (sync mode) ONE fsync for all
        // domains' batches.
        self.log.write_all(&buf)?;
        if self.sync_on_commit {
            self.log.sync_data()?;
        }
        let durability = if self.sync_on_commit {
            Durability::DeviceFlush
        } else {
            Durability::Buffered
        };
        // Commit domain states after durability.
        for (domain, br) in &domain_roots {
            let st = self.domains.get_mut(domain).expect("domain staged");
            for i in &admitted_idx[domain] {
                let rec = recs[*i].as_ref().expect("staged rec");
                st.heads
                    .insert(rec.op.object_ref.clone(), rec.new_head.clone());
                results[*i] = Some(Ok(AdmitAck {
                    seq: rec.seq,
                    new_head: rec.new_head.clone(),
                    batch_seq: br.batch_seq,
                    root: br.root.clone(),
                    durability,
                }));
            }
            st.next_seq = br.to_seq + 1;
            st.next_batch_seq = br.batch_seq + 1;
            st.root = br.root.clone();
        }
        Ok((results.into_iter().map(|r| r.unwrap()).collect(), buf))
    }

    /// project — stream one domain's frames out of the multiplexed log.
    pub fn project_domain(
        &self,
        domain: &str,
        from_seq: u64,
        visit: &mut dyn FnMut(&MuxLogFrame),
    ) -> std::io::Result<u64> {
        let mut r = BufReader::new(File::open(self.dir.join("muxlog.bin"))?);
        let mut len_buf = [0u8; 4];
        let mut visited = 0u64;
        loop {
            if r.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut frame = vec![0u8; len];
            if r.read_exact(&mut frame).is_err() {
                break; // torn tail: unacked bytes, not yet truth
            }
            let Ok(frame) = serde_json::from_slice::<MuxLogFrame>(&frame) else {
                break;
            };
            let keep = match &frame {
                MuxLogFrame::Admitted(rec) => rec.op.domain == domain && rec.seq >= from_seq,
                MuxLogFrame::DomainRoot { domain: d, rec } => d == domain && rec.to_seq >= from_seq,
                MuxLogFrame::EpochBump { .. } => false,
            };
            if keep {
                visit(&frame);
                visited += 1;
            }
        }
        Ok(visited)
    }

    /// Latest admitted payload per object in a domain (last-write-wins),
    /// in deterministic object_ref order. This is the read projection a
    /// promoted record family serves instead of a legacy JSON directory.
    pub fn project_latest_payloads(&self, domain: &str) -> std::io::Result<Vec<serde_json::Value>> {
        let mut latest: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        self.project_domain(domain, 0, &mut |f| {
            if let MuxLogFrame::Admitted(rec) = f {
                latest.insert(rec.op.object_ref.clone(), rec.op.payload.clone());
            }
        })?;
        Ok(latest.into_values().collect())
    }

    /// Strict exact projection for one object key. Unlike `project_domain`,
    /// this path rejects every malformed, truncated, unrooted, or internally
    /// inconsistent log and proves the reconstructed terminal state agrees
    /// with the writer's in-memory heads and roots.
    pub fn project_exact(
        &self,
        domain: &str,
        object_ref: &str,
    ) -> std::io::Result<Option<ExactProjection>> {
        let mut reader = BufReader::new(File::open(self.dir.join("muxlog.bin"))?);
        let mut reconstructed: BTreeMap<String, StrictDomainState> = BTreeMap::new();
        let mut latest = None;
        let mut reconstructed_epoch = 0u64;
        let mut frame_index = 0u64;
        while let Some((frame, encoded)) = read_strict_frame(&mut reader, frame_index)? {
            match frame {
                MuxLogFrame::Admitted(record) => {
                    if record.op.object_ref.is_empty() {
                        return Err(invalid_log(format!(
                            "mux admitted frame {frame_index} has an empty object_ref"
                        )));
                    }
                    let state = reconstructed
                        .entry(record.op.domain.clone())
                        .or_insert_with(StrictDomainState::new);
                    if state.pending_records.len() >= MAX_STRICT_PENDING_RECORDS {
                        return Err(invalid_log(format!(
                            "mux domain '{}' exceeds {MAX_STRICT_PENDING_RECORDS} unrooted records",
                            record.op.domain
                        )));
                    }
                    let pending_count =
                        u64::try_from(state.pending_records.len()).map_err(|_| {
                            invalid_log(format!(
                                "mux domain '{}' pending record count overflows u64",
                                record.op.domain
                            ))
                        })?;
                    let expected_seq = state
                        .terminal
                        .next_seq
                        .checked_add(pending_count)
                        .ok_or_else(|| {
                            invalid_log(format!(
                                "mux domain '{}' sequence overflows u64",
                                record.op.domain
                            ))
                        })?;
                    if record.seq != expected_seq {
                        return Err(invalid_log(format!(
                            "mux admitted frame {frame_index} sequence mismatch for '{}': expected {expected_seq}, found {}",
                            record.op.domain, record.seq
                        )));
                    }
                    let prior_head = state.terminal.heads.get(&record.op.object_ref);
                    validate_head_condition(&record.op, prior_head).map_err(|refusal| {
                        invalid_log(format!(
                            "mux admitted frame {frame_index} violates its head condition ({refusal})"
                        ))
                    })?;
                    let operation_bytes =
                        serde_json::to_vec(&record.op).map_err(std::io::Error::other)?;
                    let prior = prior_head.cloned().unwrap_or_default();
                    let expected_head =
                        sha_hex(&[b"head|", prior.as_bytes(), b"|", &operation_bytes]);
                    if record.new_head != expected_head {
                        return Err(invalid_log(format!(
                            "mux admitted frame {frame_index} head mismatch for '{}': expected {expected_head}, found {}",
                            record.op.object_ref, record.new_head
                        )));
                    }
                    state
                        .terminal
                        .heads
                        .insert(record.op.object_ref.clone(), record.new_head.clone());
                    let mut frame_hash = Sha256::new();
                    frame_hash.update(&encoded);
                    state
                        .pending_hashes
                        .extend_from_slice(&frame_hash.finalize());
                    state.pending_records.push(record);
                }
                MuxLogFrame::DomainRoot {
                    domain: root_domain,
                    rec,
                } => {
                    let Some(state) = reconstructed.get_mut(&root_domain) else {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} has no admitted records for domain '{root_domain}'"
                        )));
                    };
                    if state.pending_records.is_empty() {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} does not cover any admitted records for domain '{root_domain}'"
                        )));
                    }
                    let expected_from = state.terminal.next_seq;
                    let pending_count =
                        u64::try_from(state.pending_records.len()).map_err(|_| {
                            invalid_log(format!(
                                "mux domain '{root_domain}' pending record count overflows u64"
                            ))
                        })?;
                    let expected_to =
                        expected_from
                            .checked_add(pending_count - 1)
                            .ok_or_else(|| {
                                invalid_log(format!(
                                    "mux domain '{root_domain}' sequence range overflows u64"
                                ))
                            })?;
                    if rec.from_seq != expected_from || rec.to_seq != expected_to {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} sequence range mismatch for domain '{root_domain}': expected {expected_from}..={expected_to}, found {}..={}",
                            rec.from_seq, rec.to_seq
                        )));
                    }
                    if rec.batch_seq != state.terminal.next_batch_seq {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} batch sequence mismatch for domain '{root_domain}': expected {}, found {}",
                            state.terminal.next_batch_seq, rec.batch_seq
                        )));
                    }
                    if rec.prev_root != state.terminal.root {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} prior root mismatch for domain '{root_domain}'"
                        )));
                    }
                    let expected_root = sha_hex(&[
                        b"root|",
                        state.terminal.root.as_bytes(),
                        b"|",
                        &state.pending_hashes,
                    ]);
                    if rec.root != expected_root {
                        return Err(invalid_log(format!(
                            "mux root frame {frame_index} root mismatch for domain '{root_domain}': expected {expected_root}, found {}",
                            rec.root
                        )));
                    }
                    for record in &state.pending_records {
                        if root_domain == domain && record.op.object_ref == object_ref {
                            latest = Some(ExactProjection {
                                operation: record.op.clone(),
                                seq: record.seq,
                                head: record.new_head.clone(),
                                admission_batch_seq: rec.batch_seq,
                                admission_root: rec.root.clone(),
                                terminal_root: String::new(),
                            });
                        }
                    }
                    state.terminal.next_seq = rec.to_seq.checked_add(1).ok_or_else(|| {
                        invalid_log(format!(
                            "mux root frame {frame_index} terminal sequence overflows u64"
                        ))
                    })?;
                    state.terminal.next_batch_seq =
                        rec.batch_seq.checked_add(1).ok_or_else(|| {
                            invalid_log(format!(
                                "mux root frame {frame_index} terminal batch sequence overflows u64"
                            ))
                        })?;
                    state.terminal.root = rec.root;
                    state.pending_records.clear();
                    state.pending_hashes.clear();
                }
                MuxLogFrame::EpochBump { epoch, .. } => {
                    if reconstructed
                        .values()
                        .any(|state| !state.pending_records.is_empty())
                    {
                        return Err(invalid_log(format!(
                            "mux epoch frame {frame_index} interrupts unrooted admitted records"
                        )));
                    }
                    reconstructed_epoch = reconstructed_epoch.max(epoch);
                }
            }
            frame_index += 1;
        }
        if let Some((pending_domain, _)) = reconstructed
            .iter()
            .find(|(_, state)| !state.pending_records.is_empty())
        {
            return Err(invalid_log(format!(
                "mux log ends with unrooted admitted records for domain '{pending_domain}'"
            )));
        }
        if reconstructed.len() != self.domains.len() {
            return Err(invalid_log(format!(
                "mux reconstructed {} domains but writer holds {}",
                reconstructed.len(),
                self.domains.len()
            )));
        }
        for (reconstructed_domain, state) in &reconstructed {
            let Some(in_memory) = self.domains.get(reconstructed_domain) else {
                return Err(invalid_log(format!(
                    "mux reconstructed unknown domain '{reconstructed_domain}'"
                )));
            };
            if state.terminal != *in_memory {
                return Err(invalid_log(format!(
                    "mux reconstructed terminal state disagrees with writer memory for domain '{reconstructed_domain}'"
                )));
            }
        }
        if reconstructed_epoch != self.current_epoch {
            return Err(invalid_log(format!(
                "mux reconstructed epoch {reconstructed_epoch} disagrees with writer epoch {}",
                self.current_epoch
            )));
        }
        let Some(mut exact) = latest else {
            return Ok(None);
        };
        let terminal = &reconstructed
            .get(domain)
            .ok_or_else(|| {
                invalid_log(format!(
                    "mux exact projection lost reconstructed domain '{domain}'"
                ))
            })?
            .terminal;
        if terminal.heads.get(object_ref) != Some(&exact.head) {
            return Err(invalid_log(format!(
                "mux exact projection head for '{object_ref}' is not the reconstructed terminal head"
            )));
        }
        exact.terminal_root = terminal.root.clone();
        Ok(Some(exact))
    }

    /// Per-domain checkpoint — O(domain head-map), independent of log length.
    pub fn checkpoint_domain(
        &mut self,
        domain: &str,
        recorded_at_ms: u64,
    ) -> std::io::Result<CheckpointRecord> {
        let st = self
            .domains
            .get(domain)
            .ok_or_else(|| std::io::Error::other(format!("unknown domain {domain}")))?;
        let ck = CheckpointRecord {
            at_seq: st.next_seq,
            batch_seq: st.next_batch_seq,
            root: st.root.clone(),
            heads: st.heads.clone(),
            recorded_at_ms,
            parent_log: None,
        };
        let bytes = serde_json::to_vec(&ck).map_err(std::io::Error::other)?;
        std::fs::write(
            self.dir
                .join("checkpoints")
                .join(format!("ckpt-{domain}-{:012}.json", ck.at_seq)),
            bytes,
        )?;
        Ok(ck)
    }
}

// --------------------------------------------------------------------------
// Group-commit layer for the mux engine: identical scheduling pattern —
// one writer thread, natural batching; now every drained batch may carry
// many domains and still costs one fsync.
// --------------------------------------------------------------------------

pub enum MuxWriterMsg {
    Admit(Operation, mpsc::Sender<Result<AdmitAck, Refusal>>),
    /// Consistent read: served by the writer thread between batches, so
    /// projections never observe a mid-write torn tail.
    ProjectLatest(
        String,
        mpsc::Sender<std::io::Result<Vec<serde_json::Value>>>,
    ),
    ProjectExact(
        String,
        String,
        mpsc::Sender<std::io::Result<Option<ExactProjection>>>,
    ),
    Shutdown(mpsc::Sender<()>),
}

#[derive(Clone)]
pub struct MuxHandle {
    tx: mpsc::Sender<MuxWriterMsg>,
}

impl MuxHandle {
    pub fn admit(&self, op: Operation) -> Result<AdmitAck, Refusal> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(MuxWriterMsg::Admit(op, ack_tx))
            .expect("mux writer alive");
        ack_rx.recv().expect("mux writer ack")
    }
    pub fn project_latest(&self, domain: &str) -> std::io::Result<Vec<serde_json::Value>> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(MuxWriterMsg::ProjectLatest(domain.to_string(), tx))
            .map_err(|_| std::io::Error::other("mux writer gone"))?;
        rx.recv()
            .map_err(|_| std::io::Error::other("mux writer ack lost"))?
    }
    pub fn project_exact(
        &self,
        domain: &str,
        object_ref: &str,
    ) -> std::io::Result<Option<ExactProjection>> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(MuxWriterMsg::ProjectExact(
                domain.to_string(),
                object_ref.to_string(),
                tx,
            ))
            .map_err(|_| std::io::Error::other("mux writer gone"))?;
        rx.recv()
            .map_err(|_| std::io::Error::other("mux writer ack lost"))?
    }
    pub fn shutdown(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(MuxWriterMsg::Shutdown(tx)).is_ok() {
            let _ = rx.recv();
        }
    }
}

pub struct MuxWriter {
    pub join: std::thread::JoinHandle<std::io::Result<()>>,
}

/// Signals the background flusher to make a final fsync and exit when the
/// writer thread ends (normally or by error).
struct FlusherStopGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for FlusherStopGuard {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Ack policy + I/O scheduling configuration for the writer.
pub struct WriterConfig {
    pub max_batch: usize,
    /// Static replica membership. Every batch's appended bytes are shipped
    /// to each replica BEFORE acks are sent. Acks upgrade to
    /// `quorum_replicated` only when at least `ack_quorum` replicas hold
    /// the bytes AND every acking link was declared failure-independent;
    /// any same-host link caps the class at `replicated_same_host`. Failed
    /// links are dropped LOUDLY; below quorum, acks keep the engine's base
    /// label — replicated classes are never faked.
    pub replicas: Vec<crate::replica::ReplicaLink>,
    /// Required replica acks per batch. 0 means "all currently connected".
    pub ack_quorum: usize,
    /// In async-flush mode (engine opened with `sync_on_commit=false`),
    /// call `sync_log()` every N batches and at shutdown — ON the writer
    /// thread (adds periodic flush stalls to the tail). 0 disables.
    pub flush_every_batches: u64,
    /// Background flush: a dedicated thread fsyncs the log every N ms via
    /// its own fd, keeping device flush entirely OFF the ack critical path
    /// (the replicated ack policy's intended hygiene mode). 0 disables.
    pub background_flush_ms: u64,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            max_batch: 4096,
            replicas: Vec::new(),
            ack_quorum: 0,
            flush_every_batches: 0,
            background_flush_ms: 0,
        }
    }
}

pub fn spawn_mux_writer(engine: MuxEngine, max_batch: usize) -> (MuxHandle, MuxWriter) {
    spawn_mux_writer_cfg(
        engine,
        WriterConfig {
            max_batch,
            ..Default::default()
        },
    )
}

/// Spawn the single-writer group-commit loop with an explicit ack policy.
pub fn spawn_mux_writer_cfg(
    mut engine: MuxEngine,
    mut cfg: WriterConfig,
) -> (MuxHandle, MuxWriter) {
    let max_batch = cfg.max_batch.max(1);
    // Background flusher: fsync via an independent fd so device flush never
    // rides the ack critical path. POSIX fsync flushes file data regardless
    // of which fd requests it.
    let stop_flusher = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if cfg.background_flush_ms > 0 {
        let log_path = engine.dir_path().join("muxlog.bin");
        let interval = std::time::Duration::from_millis(cfg.background_flush_ms);
        let stop = stop_flusher.clone();
        std::thread::spawn(move || {
            let Ok(fd) = File::open(&log_path) else {
                return;
            };
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(interval);
                let _ = fd.sync_data();
            }
            let _ = fd.sync_data();
        });
    }
    let (tx, rx) = mpsc::channel::<MuxWriterMsg>();
    let join = std::thread::spawn(move || -> std::io::Result<()> {
        let mut batches_since_sync = 0u64;
        let _stop_on_exit = FlusherStopGuard(stop_flusher);
        loop {
            let first = match rx.recv() {
                Ok(m) => m,
                Err(_) => {
                    if cfg.flush_every_batches > 0 {
                        let _ = engine.sync_log();
                    }
                    return Ok(());
                }
            };
            let mut ops = Vec::new();
            let mut acks = Vec::new();
            let mut shutdown: Option<mpsc::Sender<()>> = None;
            let mut projections: Vec<(
                String,
                mpsc::Sender<std::io::Result<Vec<serde_json::Value>>>,
            )> = Vec::new();
            let mut exact_projections: Vec<(
                String,
                String,
                mpsc::Sender<std::io::Result<Option<ExactProjection>>>,
            )> = Vec::new();
            match first {
                MuxWriterMsg::Admit(op, ack) => {
                    ops.push(op);
                    acks.push(ack);
                }
                MuxWriterMsg::ProjectLatest(domain, tx) => projections.push((domain, tx)),
                MuxWriterMsg::ProjectExact(domain, object_ref, tx) => {
                    exact_projections.push((domain, object_ref, tx));
                }
                MuxWriterMsg::Shutdown(tx) => shutdown = Some(tx),
            }
            if shutdown.is_none() && !ops.is_empty() {
                while ops.len() < max_batch {
                    match rx.try_recv() {
                        Ok(MuxWriterMsg::Admit(op, ack)) => {
                            ops.push(op);
                            acks.push(ack);
                        }
                        Ok(MuxWriterMsg::ProjectLatest(domain, tx)) => {
                            projections.push((domain, tx));
                        }
                        Ok(MuxWriterMsg::ProjectExact(domain, object_ref, tx)) => {
                            exact_projections.push((domain, object_ref, tx));
                        }
                        Ok(MuxWriterMsg::Shutdown(tx)) => {
                            shutdown = Some(tx);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let (mut results, bytes) = engine.admit_batch_full(ops)?;
                // Replicate-then-ack: the batch's durability class rises to
                // a replicated tier only after enough peers hold the bytes.
                if !cfg.replicas.is_empty() && !bytes.is_empty() {
                    let quorum = if cfg.ack_quorum == 0 {
                        cfg.replicas.len()
                    } else {
                        cfg.ack_quorum
                    };
                    let mut acked = 0usize;
                    let mut all_independent = true;
                    let mut failed: Vec<usize> = Vec::new();
                    for (idx, link) in cfg.replicas.iter_mut().enumerate() {
                        match link.ship(&bytes) {
                            Ok(()) => {
                                acked += 1;
                                if !link.failure_independent {
                                    all_independent = false;
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "substrate: replica link {idx} FAILED ({e}) — dropping link; replicated classes are never faked"
                                );
                                failed.push(idx);
                            }
                        }
                    }
                    for idx in failed.into_iter().rev() {
                        cfg.replicas.remove(idx);
                    }
                    if acked >= quorum && acked > 0 {
                        let upgraded = if all_independent {
                            Durability::QuorumReplicated
                        } else {
                            Durability::ReplicatedSameHost
                        };
                        for res in results.iter_mut().flatten() {
                            res.durability = upgraded;
                        }
                    } else if acked > 0 {
                        eprintln!(
                            "substrate: below ack quorum ({acked}/{quorum}) — acks keep base durability label"
                        );
                    }
                }
                for (res, ack) in results.into_iter().zip(acks) {
                    let _ = ack.send(res);
                }
                if cfg.flush_every_batches > 0 {
                    batches_since_sync += 1;
                    if batches_since_sync >= cfg.flush_every_batches {
                        engine.sync_log()?;
                        batches_since_sync = 0;
                    }
                }
            }
            // Projections run between batches: the log has no torn tail here.
            for (domain, tx) in projections {
                let _ = tx.send(engine.project_latest_payloads(&domain));
            }
            for (domain, object_ref, tx) in exact_projections {
                let _ = tx.send(engine.project_exact(&domain, &object_ref));
            }
            if let Some(tx) = shutdown {
                if cfg.flush_every_batches > 0 {
                    let _ = engine.sync_log();
                }
                let _ = tx.send(());
                return Ok(());
            }
        }
    });
    (MuxHandle { tx }, MuxWriter { join })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(domain: &str, obj: &str, n: u64) -> Operation {
        Operation {
            domain: domain.into(),
            object_ref: obj.into(),
            op_kind: "w".into(),
            expected_head: None,
            expected_absent: false,
            payload: serde_json::json!({ "n": n }),
            recorded_at_ms: 1_000 + n,
            idem_key: format!("i{n}"),
        }
    }

    fn create_once(domain: &str, obj: &str, n: u64) -> Operation {
        let mut operation = op(domain, obj, n);
        operation.expected_absent = true;
        operation
    }

    #[test]
    fn expected_absent_same_key_batch_admits_exactly_one() {
        let mut engine = MuxEngine::open(&tmp("expected-absent-batch"), false).unwrap();
        let results = engine
            .admit_batch(vec![
                create_once("a", "o://same", 1),
                create_once("a", "o://same", 2),
            ])
            .unwrap();
        assert!(results[0].is_ok());
        assert!(matches!(
            results[1],
            Err(Refusal::ExpectedAbsentConflict { .. })
        ));
        assert_eq!(engine.domain_next_seq("a"), 1);
    }

    #[test]
    fn expected_absent_refuses_foreign_same_key_occupant() {
        let mut engine = MuxEngine::open(&tmp("expected-absent-foreign"), false).unwrap();
        engine.admit_batch(vec![op("a", "o://same", 1)]).unwrap();
        let results = engine
            .admit_batch(vec![create_once("a", "o://same", 2)])
            .unwrap();
        assert!(matches!(
            results[0],
            Err(Refusal::ExpectedAbsentConflict { .. })
        ));
        let exact = engine.project_exact("a", "o://same").unwrap().unwrap();
        assert_eq!(exact.operation.payload, serde_json::json!({ "n": 1 }));
    }

    #[test]
    fn writer_exact_projection_agrees_with_admission_ack() {
        let engine = MuxEngine::open(&tmp("exact-writer"), false).unwrap();
        let (handle, writer) = spawn_mux_writer(engine, 1024);
        let operation = op("a", "o://exact", 1);
        let ack = handle.admit(operation.clone()).unwrap();
        let domain_ack = handle.admit(op("a", "o://other", 2)).unwrap();
        let exact = handle.project_exact("a", "o://exact").unwrap().unwrap();
        assert_eq!(exact.operation, operation);
        assert_eq!(exact.seq, ack.seq);
        assert_eq!(exact.head, ack.new_head);
        assert_eq!(exact.admission_batch_seq, ack.batch_seq);
        assert_eq!(exact.admission_root, ack.root);
        assert_eq!(exact.terminal_root, domain_ack.root);
        assert!(handle.project_exact("a", "o://missing").unwrap().is_none());
        handle.shutdown();
        writer.join.join().unwrap().unwrap();
    }

    #[test]
    fn strict_exact_projection_refuses_deleted_log() {
        let directory = tmp("exact-deleted");
        let mut engine = MuxEngine::open(&directory, false).unwrap();
        engine.admit_batch(vec![op("a", "o://exact", 1)]).unwrap();
        std::fs::remove_file(directory.join("muxlog.bin")).unwrap();
        let error = engine.project_exact("a", "o://exact").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn strict_exact_projection_refuses_one_byte_truncation() {
        let directory = tmp("exact-truncated");
        let mut engine = MuxEngine::open(&directory, false).unwrap();
        engine.admit_batch(vec![op("a", "o://exact", 1)]).unwrap();
        let path = directory.join("muxlog.bin");
        let length = std::fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length - 1)
            .unwrap();
        let error = engine.project_exact("a", "o://exact").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn strict_exact_projection_refuses_unrooted_admitted_frame() {
        let directory = tmp("exact-unrooted");
        let mut engine = MuxEngine::open(&directory, false).unwrap();
        engine.admit_batch(vec![op("a", "o://exact", 1)]).unwrap();
        let path = directory.join("muxlog.bin");
        let bytes = std::fs::read(&path).unwrap();
        let body_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4 + body_length)
            .unwrap();
        let error = engine.project_exact("a", "o://exact").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unrooted admitted records"));
    }

    #[test]
    fn strict_exact_projection_refuses_malformed_json() {
        let directory = tmp("exact-malformed");
        let engine = MuxEngine::open(&directory, false).unwrap();
        let path = directory.join("muxlog.bin");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(b'{');
        std::fs::write(path, bytes).unwrap();
        let error = engine.project_exact("a", "o://exact").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("malformed JSON"));
    }

    #[test]
    fn strict_exact_projection_refuses_oversized_frame_before_allocation() {
        let directory = tmp("exact-oversized");
        let engine = MuxEngine::open(&directory, false).unwrap();
        let oversized = u32::try_from(MAX_STRICT_FRAME_BYTES + 1).unwrap();
        std::fs::write(directory.join("muxlog.bin"), oversized.to_le_bytes()).unwrap();
        let error = engine.project_exact("a", "o://exact").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("outside"));
    }

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("agentgres-mux-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn per_domain_roots_independent_of_interleaving() {
        // Same per-domain op order, different interleavings -> same roots.
        let (d1, d2) = (tmp("il1"), tmp("il2"));
        let mut e1 = MuxEngine::open(&d1, false).unwrap();
        let mut e2 = MuxEngine::open(&d2, false).unwrap();
        e1.admit_batch(vec![
            op("a", "o://1", 1),
            op("b", "o://1", 2),
            op("a", "o://2", 3),
            op("b", "o://2", 4),
        ])
        .unwrap();
        e2.admit_batch(vec![op("a", "o://1", 1), op("a", "o://2", 3)])
            .unwrap();
        e2.admit_batch(vec![op("b", "o://1", 2), op("b", "o://2", 4)])
            .unwrap();
        // Domain 'a' saw identical op sequences in both engines...
        assert_eq!(
            e1.domain_head("a", "o://1"),
            e2.domain_head("a", "o://1"),
            "heads must depend only on the domain's own op order"
        );
        assert_eq!(e1.domain_head("b", "o://2"), e2.domain_head("b", "o://2"));
        assert_eq!(
            e1.project_exact("a", "o://1")
                .unwrap()
                .unwrap()
                .operation
                .payload,
            serde_json::json!({ "n": 1 }),
            "strict projection must validate the complete interleaved multi-domain log"
        );
        // ...but batch partitioning differs, so batch ROOT chains may differ
        // (roots bind batches). Heads equality is the truth-decoupling claim.
    }

    #[test]
    fn mux_recovery_replays_all_domains() {
        let d = tmp("recover");
        let (roots_before, seqs_before): (Vec<Root>, Vec<u64>);
        {
            let mut e = MuxEngine::open(&d, false).unwrap();
            for i in 0..40u64 {
                let dom = format!("d{}", i % 5);
                e.admit_batch(vec![op(&dom, &format!("o://{}", i % 3), i)])
                    .unwrap();
            }
            roots_before = e
                .domains()
                .map(|k| e.domain_root(k).unwrap().clone())
                .collect();
            seqs_before = e.domains().map(|k| e.domain_next_seq(k)).collect();
        }
        let e2 = MuxEngine::open(&d, false).unwrap();
        let roots_after: Vec<Root> = e2
            .domains()
            .map(|k| e2.domain_root(k).unwrap().clone())
            .collect();
        let seqs_after: Vec<u64> = e2.domains().map(|k| e2.domain_next_seq(k)).collect();
        assert_eq!(roots_before, roots_after);
        assert_eq!(seqs_before, seqs_after);
    }

    #[test]
    fn mux_domain_forks_into_single_engine_and_diverges() {
        // A domain checkpointed out of the mux log seeds a single-domain
        // SubstrateEngine fork: root continuity at the fork point, then
        // divergence without touching the mux parent.
        use crate::{AgentgresSubstrate, SubstrateEngine};
        let dp = tmp("mfork-parent");
        let df = tmp("mfork-child");
        let mut e = MuxEngine::open(&dp, false).unwrap();
        e.admit_batch(vec![
            op("a", "o://1", 1),
            op("b", "o://1", 2),
            op("a", "o://2", 3),
        ])
        .unwrap();
        let ck = e.checkpoint_domain("a", 9_000).unwrap();
        SubstrateEngine::fork_from(&ck, &dp, &df).unwrap();
        let mut fork = SubstrateEngine::open(&df, false).unwrap();
        assert_eq!(fork.current_root(), e.domain_root("a").unwrap());
        assert_eq!(fork.head("o://2"), e.domain_head("a", "o://2"));
        fork.admit_batch(vec![op("a", "o://2", 4)]).unwrap();
        assert_ne!(fork.current_root(), e.domain_root("a").unwrap());
        assert_eq!(
            e.domain_next_seq("a"),
            2,
            "mux parent untouched by fork writes"
        );
    }

    #[test]
    fn mux_project_domain_filters_frames() {
        let d = tmp("mproj");
        let mut e = MuxEngine::open(&d, false).unwrap();
        e.admit_batch(vec![
            op("a", "o://1", 1),
            op("b", "o://1", 2),
            op("a", "o://2", 3),
        ])
        .unwrap();
        let mut a_ops = 0u64;
        let mut a_roots = 0u64;
        e.project_domain("a", 0, &mut |f| match f {
            MuxLogFrame::Admitted(rec) => {
                assert_eq!(rec.op.domain, "a");
                a_ops += 1;
            }
            MuxLogFrame::DomainRoot { domain, .. } => {
                assert_eq!(domain, "a");
                a_roots += 1;
            }
            MuxLogFrame::EpochBump { .. } => unreachable!("project_domain filters epoch frames"),
        })
        .unwrap();
        assert_eq!((a_ops, a_roots), (2, 1));
    }

    #[test]
    fn replicated_ack_upgrades_durability_and_replica_root_matches() {
        use crate::replica::{ReplicaLink, ReplicaServer};
        let dp = tmp("repl-primary");
        let dr = tmp("repl-replica");
        let server = ReplicaServer::bind("127.0.0.1:0", &dr, 8).unwrap();
        let addr = server.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (stream, _) = server.listener_accept_for_test().unwrap();
            server.serve_one(stream).unwrap();
        });
        // Async-flush engine: base label would be `buffered`; the replica
        // ack must upgrade it to `replicated_same_host`.
        let engine = MuxEngine::open(&dp, false).unwrap();
        let (epoch, len) = (engine.current_epoch(), engine.log_len().unwrap());
        let link = ReplicaLink::connect(addr, false, epoch, &dp.join("muxlog.bin"), len).unwrap();
        let (h, w) = spawn_mux_writer_cfg(
            engine,
            WriterConfig {
                max_batch: 1024,
                replicas: vec![link],
                flush_every_batches: 4,
                ..Default::default()
            },
        );
        let mut last = None;
        for i in 0..100u64 {
            let ack = h.admit(op("a", &format!("o://{}", i % 7), i)).unwrap();
            assert_eq!(ack.durability, crate::Durability::ReplicatedSameHost);
            last = Some(ack);
        }
        h.shutdown();
        w.join.join().unwrap().unwrap();
        srv.join().unwrap();
        // Byte-identical logs -> identical replayed roots.
        let primary = MuxEngine::open(&dp, false).unwrap();
        let replica = MuxEngine::open(&dr, false).unwrap();
        assert_eq!(primary.domain_root("a"), replica.domain_root("a"));
        assert_eq!(primary.domain_next_seq("a"), 100);
        assert_eq!(replica.domain_next_seq("a"), 100);
        assert_eq!(primary.domain_root("a").unwrap(), &last.unwrap().root);
    }

    #[test]
    fn catch_up_resyncs_replica_gap_then_streams_live() {
        use crate::replica::{ReplicaLink, ReplicaServer};
        // Primary accumulates 30 ops BEFORE any replica exists; the replica
        // connects late, catch-up streams the gap, live batches follow, and
        // the replica ends byte-identical.
        let dp = tmp("cu-p");
        let dr = tmp("cu-r");
        let mut e = MuxEngine::open(&dp, false).unwrap();
        for i in 0..30u64 {
            e.admit_batch(vec![op("a", &format!("o://{}", i % 5), i)])
                .unwrap();
        }
        let server = ReplicaServer::bind("127.0.0.1:0", &dr, 8).unwrap();
        let addr = server.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (s, _) = server.listener_accept_for_test().unwrap();
            let _ = server.serve_one(s);
        });
        let (epoch, len) = (e.current_epoch(), e.log_len().unwrap());
        let link = ReplicaLink::connect(addr, false, epoch, &dp.join("muxlog.bin"), len).unwrap();
        let (h, w) = spawn_mux_writer_cfg(
            e,
            WriterConfig {
                max_batch: 256,
                replicas: vec![link],
                ..Default::default()
            },
        );
        for i in 30..60u64 {
            let ack = h.admit(op("a", &format!("o://{}", i % 5), i)).unwrap();
            assert_eq!(ack.durability, crate::Durability::ReplicatedSameHost);
        }
        h.shutdown();
        w.join.join().unwrap().unwrap();
        srv.join().unwrap();
        let p = MuxEngine::open(&dp, false).unwrap();
        let r = MuxEngine::open(&dr, false).unwrap();
        assert_eq!(p.domain_root("a"), r.domain_root("a"));
        assert_eq!(r.domain_next_seq("a"), 60);
    }

    #[test]
    fn promotion_fences_stale_primary() {
        use crate::replica::{ReplicaLink, ReplicaServer};
        // A ships to the replica (via catch-up), "dies"; the replica dir is
        // promoted to epoch 1; A's reconnect at epoch 0 must be fenced.
        let da = tmp("fence-a");
        let dr = tmp("fence-r");
        let mut a = MuxEngine::open(&da, false).unwrap();
        a.admit_batch(vec![op("a", "o://1", 1), op("a", "o://2", 2)])
            .unwrap();
        let server = ReplicaServer::bind("127.0.0.1:0", &dr, 8).unwrap();
        let addr = server.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (s, _) = server.listener_accept_for_test().unwrap();
            let _ = server.serve_one(s);
        });
        let link = ReplicaLink::connect(
            addr,
            false,
            a.current_epoch(),
            &da.join("muxlog.bin"),
            a.log_len().unwrap(),
        )
        .unwrap();
        drop(link);
        srv.join().unwrap();
        let mut promoted = MuxEngine::open(&dr, false).unwrap();
        assert_eq!(
            promoted.domain_root("a"),
            a.domain_root("a"),
            "caught up before promotion"
        );
        let record = promoted.promote(9_000).unwrap();
        assert_eq!(record["new_epoch"], 1);
        assert_eq!(promoted.current_epoch(), 1);
        // Stale primary A (epoch 0) tries to re-establish replication.
        let server2 = ReplicaServer::bind("127.0.0.1:0", &dr, 8).unwrap();
        let addr2 = server2.local_addr().unwrap();
        let srv2 = std::thread::spawn(move || {
            let (s, _) = server2.listener_accept_for_test().unwrap();
            let _ = server2.serve_one(s); // errors: fenced
        });
        let res = ReplicaLink::connect(
            addr2,
            false,
            a.current_epoch(),
            &da.join("muxlog.bin"),
            a.log_len().unwrap(),
        );
        assert!(res.is_err(), "deposed primary must be fenced at handshake");
        assert!(format!("{}", res.err().unwrap()).contains("FENCED"));
        srv2.join().unwrap();
        // Promotion survives replay: reopen sees epoch 1.
        let reopened = MuxEngine::open(&dr, false).unwrap();
        assert_eq!(reopened.current_epoch(), 1);
    }

    #[test]
    fn quorum_label_capped_by_same_host_links() {
        use crate::replica::{ReplicaLink, ReplicaServer};
        // Two acking replicas meet quorum, but same-host links must cap the
        // class at replicated_same_host; declared-independent links (config
        // attestation — never truthful on one box, verified here as pure
        // label logic) yield quorum_replicated.
        for (independent, expect) in [
            (false, crate::Durability::ReplicatedSameHost),
            (true, crate::Durability::QuorumReplicated),
        ] {
            let dp = tmp(&format!("q-p-{independent}"));
            let dr1 = tmp(&format!("q-r1-{independent}"));
            let dr2 = tmp(&format!("q-r2-{independent}"));
            let e = MuxEngine::open(&dp, false).unwrap();
            let (epoch, len) = (e.current_epoch(), e.log_len().unwrap());
            let mut links = Vec::new();
            let mut srvs = Vec::new();
            for dr in [&dr1, &dr2] {
                let server = ReplicaServer::bind("127.0.0.1:0", dr, 8).unwrap();
                let addr = server.local_addr().unwrap();
                srvs.push(std::thread::spawn(move || {
                    let (s, _) = server.listener_accept_for_test().unwrap();
                    let _ = server.serve_one(s);
                }));
                links.push(
                    ReplicaLink::connect(addr, independent, epoch, &dp.join("muxlog.bin"), len)
                        .unwrap(),
                );
            }
            let (h, w) = spawn_mux_writer_cfg(
                e,
                WriterConfig {
                    max_batch: 256,
                    replicas: links,
                    ack_quorum: 2,
                    ..Default::default()
                },
            );
            let ack = h.admit(op("a", "o://1", 1)).unwrap();
            assert_eq!(ack.durability, expect);
            h.shutdown();
            w.join.join().unwrap().unwrap();
            for s in srvs {
                s.join().unwrap();
            }
        }
    }

    #[test]
    fn sync_mode_acks_carry_device_flush_label() {
        let d = tmp("dur-sync");
        let mut e = MuxEngine::open(&d, true).unwrap();
        let r = e.admit_batch(vec![op("a", "o://1", 1)]).unwrap();
        assert_eq!(
            r[0].as_ref().unwrap().durability,
            crate::Durability::DeviceFlush
        );
        let d2 = tmp("dur-async");
        let mut e2 = MuxEngine::open(&d2, false).unwrap();
        let r2 = e2.admit_batch(vec![op("a", "o://1", 1)]).unwrap();
        assert_eq!(
            r2[0].as_ref().unwrap().durability,
            crate::Durability::Buffered
        );
    }

    #[test]
    fn torn_tail_is_truncated_on_recovery() {
        use std::io::Write as _;
        let d = tmp("torn");
        let (root_before, seq_before);
        {
            let mut e = MuxEngine::open(&d, false).unwrap();
            e.admit_batch(vec![op("a", "o://1", 1), op("a", "o://2", 2)])
                .unwrap();
            root_before = e.domain_root("a").unwrap().clone();
            seq_before = e.domain_next_seq("a");
        }
        // Simulate a crash mid-write: garbage partial frame at the tail.
        let mut f = OpenOptions::new()
            .append(true)
            .open(d.join("muxlog.bin"))
            .unwrap();
        f.write_all(&999u32.to_le_bytes()).unwrap();
        f.write_all(b"torn-partial-frame").unwrap();
        drop(f);
        let len_with_garbage = std::fs::metadata(d.join("muxlog.bin")).unwrap().len();
        let e2 = MuxEngine::open(&d, false).unwrap();
        assert_eq!(e2.domain_root("a").unwrap(), &root_before);
        assert_eq!(e2.domain_next_seq("a"), seq_before);
        let len_after = std::fs::metadata(d.join("muxlog.bin")).unwrap().len();
        assert!(
            len_after < len_with_garbage,
            "unacked tail must be truncated"
        );
        // And the log stays appendable after truncation.
        let mut e3 = MuxEngine::open(&d, false).unwrap();
        e3.admit_batch(vec![op("a", "o://3", 3)]).unwrap();
        let e4 = MuxEngine::open(&d, false).unwrap();
        assert_eq!(e4.domain_next_seq("a"), seq_before + 1);
    }

    #[test]
    fn writer_projection_serves_latest_payloads() {
        let d = tmp("proj-writer");
        let engine = MuxEngine::open(&d, false).unwrap();
        let (h, w) = spawn_mux_writer(engine, 1024);
        h.admit(op("a", "o://1", 1)).unwrap();
        h.admit(op("a", "o://2", 2)).unwrap();
        h.admit(op("a", "o://1", 3)).unwrap(); // overwrite o://1
        let latest = h.project_latest("a").unwrap();
        assert_eq!(latest.len(), 2, "last-write-wins per object");
        let ns: Vec<i64> = latest.iter().map(|v| v["n"].as_i64().unwrap()).collect();
        assert!(
            ns.contains(&3) && ns.contains(&2),
            "o://1 must be its latest write: {ns:?}"
        );
        h.shutdown();
        w.join.join().unwrap().unwrap();
    }

    #[test]
    fn mux_writer_combines_domains_under_concurrency() {
        let d = tmp("writer");
        let engine = MuxEngine::open(&d, false).unwrap();
        let (h, w) = spawn_mux_writer(engine, 4096);
        let mut joins = Vec::new();
        for c in 0..6u64 {
            let h = h.clone();
            joins.push(std::thread::spawn(move || {
                for i in 0..200u64 {
                    h.admit(op(
                        &format!("d{}", c % 3),
                        &format!("o://c{c}"),
                        c * 1000 + i,
                    ))
                    .unwrap();
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        h.shutdown();
        w.join.join().unwrap().unwrap();
        let e = MuxEngine::open(&d, false).unwrap();
        let total: u64 = e.domains().map(|k| e.domain_next_seq(k)).sum();
        assert_eq!(total, 1_200);
    }
}
