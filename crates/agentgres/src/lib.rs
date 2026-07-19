//! Agentgres substrate contract v0.
//!
//! Doctrine owner: docs/architecture/components/agentgres/doctrine.md
//! (Substrate Contract Doctrine). The contract is five verbs — append,
//! validate, advance-head, root, project — plus checkpoint/fork custody.
//!
//! DETERMINISM RULE (binding): no wall clock, no randomness, no thread
//! nondeterminism inside admission state. Timestamps arrive as recorded
//! operation inputs (`recorded_at_ms`). Given the same ordered operations,
//! two engines produce byte-identical heads and roots. The group-commit
//! layer schedules I/O; it never influences state content beyond arrival
//! order, and the single writer makes that order total.
//!
//! BATCH ROOTING RULE (binding): roots are computed per admitted batch and
//! bind operation ranges; root-per-op is a rejected design.

#![forbid(unsafe_code)]

pub mod mux;
pub mod replica;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

pub type Head = String;
pub type Root = String;

pub const GENESIS_ROOT: &str = "sha256:genesis";
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// A proposed operation. `recorded_at_ms` is an input recorded by the caller
/// (harness, route layer, wallet gate) — the engine never reads a clock.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub domain: String,
    pub object_ref: String,
    pub op_kind: String,
    /// Expected head for optimistic-concurrency admission. `None` admits
    /// unconditionally unless `expected_absent` is set.
    pub expected_head: Option<Head>,
    /// Require this object key to have no committed or earlier in-batch
    /// head. Omitted/false preserves the legacy unconditional `None`
    /// semantics and its serialized operation bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub expected_absent: bool,
    pub payload: serde_json::Value,
    pub recorded_at_ms: u64,
    pub idem_key: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmittedRecord {
    pub seq: u64,
    pub new_head: Head,
    pub op: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRootRecord {
    pub batch_seq: u64,
    pub from_seq: u64,
    pub to_seq: u64,
    pub prev_root: Root,
    pub root: Root,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub at_seq: u64,
    pub batch_seq: u64,
    pub root: Root,
    pub heads: BTreeMap<String, Head>,
    /// Recorded input from the caller, never an engine clock.
    pub recorded_at_ms: u64,
    /// Set when this checkpoint seeded a fork.
    pub parent_log: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame")]
pub enum LogFrame {
    Admitted(AdmittedRecord),
    BatchRoot(BatchRootRecord),
}

/// Fail-closed admission reasons. Agentgres is still a v0 internal contract,
/// so consumers must tolerate new refusal variants as validation expands.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    ExpectedHeadConflict {
        object_ref: String,
        expected: Option<Head>,
        actual: Option<Head>,
    },
    ExpectedAbsentConflict {
        object_ref: String,
        actual: Head,
    },
    ConflictingHeadConditions {
        object_ref: String,
    },
    FrameTooLarge {
        object_ref: String,
        encoded_bytes: usize,
        max_bytes: usize,
    },
    EmptyObjectRef,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::ExpectedHeadConflict {
                object_ref,
                expected,
                actual,
            } => write!(
                f,
                "expected_head_conflict object={object_ref} expected={expected:?} actual={actual:?}"
            ),
            Refusal::ExpectedAbsentConflict { object_ref, actual } => write!(
                f,
                "expected_absent_conflict object={object_ref} actual={actual}"
            ),
            Refusal::ConflictingHeadConditions { object_ref } => {
                write!(f, "conflicting_head_conditions object={object_ref}")
            }
            Refusal::FrameTooLarge {
                object_ref,
                encoded_bytes,
                max_bytes,
            } => write!(
                f,
                "frame_too_large object={object_ref} encoded_bytes={encoded_bytes} max_bytes={max_bytes}"
            ),
            Refusal::EmptyObjectRef => write!(f, "empty_object_ref"),
        }
    }
}

pub(crate) fn validate_head_condition(
    op: &Operation,
    actual: Option<&Head>,
) -> Result<(), Refusal> {
    if op.expected_absent {
        if op.expected_head.is_some() {
            return Err(Refusal::ConflictingHeadConditions {
                object_ref: op.object_ref.clone(),
            });
        }
        return match actual {
            None => Ok(()),
            Some(actual) => Err(Refusal::ExpectedAbsentConflict {
                object_ref: op.object_ref.clone(),
                actual: actual.clone(),
            }),
        };
    }
    match (&op.expected_head, actual) {
        (None, _) => Ok(()),
        (Some(expected), Some(actual)) if expected == actual => Ok(()),
        (Some(expected), actual) => Err(Refusal::ExpectedHeadConflict {
            object_ref: op.object_ref.clone(),
            expected: Some(expected.clone()),
            actual: actual.cloned(),
        }),
    }
}

/// Durability class carried on every admission ack — INV-14 rendered into
/// the protocol: an ack never claims a durability it has not proven.
///
/// - `Buffered`: appended via write_all; device flush pending (async cadence).
/// - `DeviceFlush`: fdatasync completed on the local device before ack.
/// - `ReplicatedSameHost`: a replica acknowledged the batch bytes, but the
///   peer shares this host's failure domain — a mechanism demo, not
///   failure-independence.
/// - `QuorumReplicated`: acknowledged by peer(s) declared
///   failure-independent. The fractal end state; requires real multi-node
///   deployment to claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Buffered,
    DeviceFlush,
    ReplicatedSameHost,
    QuorumReplicated,
}

impl std::fmt::Display for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Durability::Buffered => "buffered",
            Durability::DeviceFlush => "device_flush",
            Durability::ReplicatedSameHost => "replicated_same_host",
            Durability::QuorumReplicated => "quorum_replicated",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug)]
pub struct AdmitAck {
    pub seq: u64,
    pub new_head: Head,
    pub batch_seq: u64,
    pub root: Root,
    pub durability: Durability,
}

/// The substrate contract: five verbs plus checkpoint custody.
/// Any engine hosting these verbs under the invariants is an Agentgres
/// substrate; this file's `SubstrateEngine` is the v0 reference.
pub trait AgentgresSubstrate {
    /// validate — admission precondition check against current heads.
    fn validate(&self, op: &Operation) -> Result<(), Refusal>;
    /// append + advance-head + root — one durable admission batch.
    /// Per-op results preserve input order; refusals do not poison the batch.
    fn admit_batch(
        &mut self,
        ops: Vec<Operation>,
    ) -> std::io::Result<Vec<Result<AdmitAck, Refusal>>>;
    /// current head for an object.
    fn head(&self, object_ref: &str) -> Option<&Head>;
    /// current batch root.
    fn current_root(&self) -> &Root;
    /// project — fold admitted frames from `from_seq` into a visitor.
    fn project(&self, from_seq: u64, visit: &mut dyn FnMut(&LogFrame)) -> std::io::Result<u64>;
    /// checkpoint — O(1) in log length (proportional to live head-map size,
    /// independent of history).
    fn checkpoint(&mut self, recorded_at_ms: u64) -> std::io::Result<CheckpointRecord>;
}

fn sha_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    format!("sha256:{:x}", h.finalize())
}

/// Shared hash helper for sibling engine modules (mux).
pub fn sha_hex_pub(parts: &[&[u8]]) -> String {
    sha_hex(parts)
}

/// Deterministic, dependency-free RFC3339 → epoch-ms parse
/// ("YYYY-MM-DDTHH:MM:SS[.frac]Z"), for turning recorded daemon timestamps
/// into `recorded_at_ms` operation inputs. Civil-date arithmetic per
/// Howard Hinnant's algorithm. Returns 0 on malformed input (recorded
/// evidence stays honest: a zero timestamp is visibly unparsed, never
/// silently substituted with a clock read).
pub fn parse_rfc3339_ms(s: &str) -> u64 {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> i64 {
        s.get(r).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0)
    };
    if b.len() < 19 {
        return 0;
    }
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let (hh, mm, ss) = (num(11..13), num(14..16), num(17..19));
    let frac_ms = if b.len() > 20 && b[19] == b'.' {
        let end = s[20..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| 20 + i)
            .unwrap_or(s.len());
        s.get(20..end)
            .map(|x| format!("{x:0<3}"))
            .and_then(|x| x.get(0..3).map(|y| y.to_string()))
            .and_then(|x| x.parse().ok())
            .unwrap_or(0)
    } else {
        0
    };
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    ((days * 86_400 + hh * 3_600 + mm * 60 + ss) * 1_000 + frac_ms) as u64
}

pub struct SubstrateEngine {
    dir: PathBuf,
    log: File,
    heads: BTreeMap<String, Head>,
    next_seq: u64,
    next_batch_seq: u64,
    root: Root,
    sync_on_commit: bool,
}

impl SubstrateEngine {
    /// Open (or create) an engine at `dir`, replaying the log to rebuild
    /// heads and the root chain. Replay IS the recovery path.
    pub fn open(dir: &Path, sync_on_commit: bool) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.join("checkpoints"))?;
        let log_path = dir.join("oplog.bin");
        let mut heads = BTreeMap::new();
        let mut next_seq = 0u64;
        let mut next_batch_seq = 0u64;
        let mut root: Root = GENESIS_ROOT.to_string();
        // Fork seeding: if a fork checkpoint exists, preload state from it.
        let seed_path = dir.join("fork-seed.json");
        if seed_path.exists() {
            let ck: CheckpointRecord =
                serde_json::from_reader(BufReader::new(File::open(&seed_path)?))
                    .map_err(std::io::Error::other)?;
            heads = ck.heads;
            next_seq = ck.at_seq;
            next_batch_seq = ck.batch_seq;
            root = ck.root;
        }
        if log_path.exists() {
            let file_len = std::fs::metadata(&log_path)?.len();
            let mut r = BufReader::new(File::open(&log_path)?);
            let mut len_buf = [0u8; 4];
            // WAL recovery semantics: a torn/unparseable tail is an
            // incomplete batch that was never fsync-acked — discard it by
            // truncating to the last valid frame boundary. Acked batches
            // are always fully durable (write_all + fsync precede acks).
            let mut valid: u64 = 0;
            loop {
                if r.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len == 0 || len > MAX_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "existing substrate frame length {len} is outside 1..={MAX_FRAME_BYTES}; explicit migration is required"
                        ),
                    ));
                }
                let mut frame = vec![0u8; len];
                if r.read_exact(&mut frame).is_err() {
                    break;
                }
                let Ok(frame) = serde_json::from_slice::<LogFrame>(&frame) else {
                    break;
                };
                match frame {
                    LogFrame::Admitted(rec) => {
                        heads.insert(rec.op.object_ref.clone(), rec.new_head.clone());
                        next_seq = rec.seq + 1;
                    }
                    LogFrame::BatchRoot(br) => {
                        root = br.root.clone();
                        next_batch_seq = br.batch_seq + 1;
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
            heads,
            next_seq,
            next_batch_seq,
            root,
            sync_on_commit,
        })
    }

    /// Fork a new engine directory from a checkpoint: O(1) in log length —
    /// no history bytes are copied; the checkpoint's head map seeds the fork.
    pub fn fork_from(
        checkpoint: &CheckpointRecord,
        parent_dir: &Path,
        new_dir: &Path,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(new_dir)?;
        let mut ck = checkpoint.clone();
        ck.parent_log = Some(parent_dir.join("oplog.bin").to_string_lossy().into_owned());
        let bytes = serde_json::to_vec(&ck).map_err(std::io::Error::other)?;
        std::fs::write(new_dir.join("fork-seed.json"), bytes)?;
        Ok(())
    }

    fn encode_frame(frame: &LogFrame) -> std::io::Result<Vec<u8>> {
        let body = serde_json::to_vec(frame).map_err(std::io::Error::other)?;
        Self::encode_frame_body(body)
    }

    fn encode_frame_body(body: Vec<u8>) -> std::io::Result<Vec<u8>> {
        if body.len() > MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "substrate frame length {} is outside 1..={MAX_FRAME_BYTES}",
                    body.len()
                ),
            ));
        }
        let length = u32::try_from(body.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "substrate frame length {} exceeds the u32 wire limit",
                    body.len()
                ),
            )
        })?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn heads_len(&self) -> usize {
        self.heads.len()
    }
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

impl AgentgresSubstrate for SubstrateEngine {
    fn validate(&self, op: &Operation) -> Result<(), Refusal> {
        if op.object_ref.is_empty() {
            return Err(Refusal::EmptyObjectRef);
        }
        validate_head_condition(op, self.heads.get(&op.object_ref))
    }

    fn admit_batch(
        &mut self,
        ops: Vec<Operation>,
    ) -> std::io::Result<Vec<Result<AdmitAck, Refusal>>> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        // Stage: validate against in-flight heads so intra-batch chains work.
        let mut staged_heads: BTreeMap<String, Head> = BTreeMap::new();
        let mut staged: Vec<(usize, AdmittedRecord, Vec<u8>)> = Vec::new();
        let mut results: Vec<Option<Result<AdmitAck, Refusal>>> = vec![None; ops.len()];
        let mut buf: Vec<u8> = Vec::with_capacity(ops.len() * 256);
        let mut frame_hashes: Vec<u8> = Vec::with_capacity(ops.len() * 32);
        let from_seq = self.next_seq;
        for (i, op) in ops.into_iter().enumerate() {
            let effective_head = staged_heads
                .get(&op.object_ref)
                .or_else(|| self.heads.get(&op.object_ref));
            let ok = if op.object_ref.is_empty() {
                Err(Refusal::EmptyObjectRef)
            } else {
                validate_head_condition(&op, effective_head)
            };
            if let Err(refusal) = ok {
                results[i] = Some(Err(refusal));
                continue;
            }
            let seq = self.next_seq + staged.len() as u64;
            let op_bytes = serde_json::to_vec(&op).map_err(std::io::Error::other)?;
            let prev = effective_head.cloned().unwrap_or_default();
            let new_head = sha_hex(&[b"head|", prev.as_bytes(), b"|", &op_bytes]);
            let rec = AdmittedRecord { seq, new_head, op };
            let body = serde_json::to_vec(&LogFrame::Admitted(rec.clone()))
                .map_err(std::io::Error::other)?;
            if body.len() > MAX_FRAME_BYTES {
                results[i] = Some(Err(Refusal::FrameTooLarge {
                    object_ref: rec.op.object_ref.clone(),
                    encoded_bytes: body.len(),
                    max_bytes: MAX_FRAME_BYTES,
                }));
                continue;
            }
            let frame = Self::encode_frame_body(body)?;
            staged_heads.insert(rec.op.object_ref.clone(), rec.new_head.clone());
            let mut fh = Sha256::new();
            fh.update(&frame);
            frame_hashes.extend_from_slice(&fh.finalize());
            buf.extend_from_slice(&frame);
            staged.push((i, rec, frame));
        }
        if staged.is_empty() {
            return Ok(results.into_iter().map(|r| r.unwrap()).collect());
        }
        let to_seq = from_seq + staged.len() as u64 - 1;
        let root = sha_hex(&[b"root|", self.root.as_bytes(), b"|", &frame_hashes]);
        let br = BatchRootRecord {
            batch_seq: self.next_batch_seq,
            from_seq,
            to_seq,
            prev_root: self.root.clone(),
            root: root.clone(),
        };
        buf.extend_from_slice(&Self::encode_frame(&LogFrame::BatchRoot(br.clone()))?);
        // Durability point: one write + (optionally) one fsync per batch.
        self.log.write_all(&buf)?;
        if self.sync_on_commit {
            self.log.sync_data()?;
        }
        let durability = if self.sync_on_commit {
            Durability::DeviceFlush
        } else {
            Durability::Buffered
        };
        // Advance-head only after durability.
        for (i, rec, _) in &staged {
            self.heads
                .insert(rec.op.object_ref.clone(), rec.new_head.clone());
            results[*i] = Some(Ok(AdmitAck {
                seq: rec.seq,
                new_head: rec.new_head.clone(),
                batch_seq: br.batch_seq,
                root: root.clone(),
                durability,
            }));
        }
        self.next_seq = to_seq + 1;
        self.next_batch_seq += 1;
        self.root = root;
        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    fn head(&self, object_ref: &str) -> Option<&Head> {
        self.heads.get(object_ref)
    }

    fn current_root(&self) -> &Root {
        &self.root
    }

    fn project(&self, from_seq: u64, visit: &mut dyn FnMut(&LogFrame)) -> std::io::Result<u64> {
        let mut r = BufReader::new(File::open(self.dir.join("oplog.bin"))?);
        let mut len_buf = [0u8; 4];
        let mut visited = 0u64;
        loop {
            if r.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > MAX_FRAME_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "substrate frame length {len} is outside 1..={MAX_FRAME_BYTES}; explicit migration is required"
                    ),
                ));
            }
            let mut frame = vec![0u8; len];
            if r.read_exact(&mut frame).is_err() {
                break; // torn tail: unacked bytes, not yet truth
            }
            let Ok(frame) = serde_json::from_slice::<LogFrame>(&frame) else {
                break;
            };
            let seq_ok = match &frame {
                LogFrame::Admitted(rec) => rec.seq >= from_seq,
                LogFrame::BatchRoot(br) => br.to_seq >= from_seq,
            };
            if seq_ok {
                visit(&frame);
                visited += 1;
            }
        }
        Ok(visited)
    }

    fn checkpoint(&mut self, recorded_at_ms: u64) -> std::io::Result<CheckpointRecord> {
        let ck = CheckpointRecord {
            at_seq: self.next_seq,
            batch_seq: self.next_batch_seq,
            root: self.root.clone(),
            heads: self.heads.clone(),
            recorded_at_ms,
            parent_log: None,
        };
        let bytes = serde_json::to_vec(&ck).map_err(std::io::Error::other)?;
        let path = self
            .dir
            .join("checkpoints")
            .join(format!("ckpt-{:012}.json", ck.at_seq));
        std::fs::write(path, bytes)?;
        Ok(ck)
    }
}

// ---------------------------------------------------------------------------
// Group-commit layer: single writer thread, natural batching under load.
// Scheduling only — state content and order are owned by the engine.
// ---------------------------------------------------------------------------

pub enum WriterMsg {
    Admit(Operation, mpsc::Sender<Result<AdmitAck, Refusal>>),
    Checkpoint(u64, mpsc::Sender<std::io::Result<CheckpointRecord>>),
    Shutdown(mpsc::Sender<()>),
}

#[derive(Clone)]
pub struct SubstrateHandle {
    tx: mpsc::Sender<WriterMsg>,
}

pub struct SubstrateWriter {
    pub join: std::thread::JoinHandle<std::io::Result<()>>,
}

impl SubstrateHandle {
    pub fn admit(&self, op: Operation) -> Result<AdmitAck, Refusal> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(WriterMsg::Admit(op, ack_tx))
            .expect("writer alive");
        ack_rx.recv().expect("writer ack")
    }

    pub fn checkpoint(&self, recorded_at_ms: u64) -> std::io::Result<CheckpointRecord> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(WriterMsg::Checkpoint(recorded_at_ms, tx))
            .expect("writer alive");
        rx.recv().expect("writer ack")
    }

    pub fn shutdown(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(WriterMsg::Shutdown(tx)).is_ok() {
            let _ = rx.recv();
        }
    }
}

/// Spawn the single-writer group-commit loop over an opened engine.
/// `max_batch` bounds how many queued ops one durable batch may absorb.
pub fn spawn_writer(
    mut engine: SubstrateEngine,
    max_batch: usize,
) -> (SubstrateHandle, SubstrateWriter) {
    let (tx, rx) = mpsc::channel::<WriterMsg>();
    let join = std::thread::spawn(move || -> std::io::Result<()> {
        loop {
            let first = match rx.recv() {
                Ok(m) => m,
                Err(_) => return Ok(()),
            };
            let mut ops: Vec<Operation> = Vec::new();
            let mut acks: Vec<mpsc::Sender<Result<AdmitAck, Refusal>>> = Vec::new();
            let mut control: Option<WriterMsg> = None;
            match first {
                WriterMsg::Admit(op, ack) => {
                    ops.push(op);
                    acks.push(ack);
                }
                other => control = Some(other),
            }
            if control.is_none() {
                while ops.len() < max_batch {
                    match rx.try_recv() {
                        Ok(WriterMsg::Admit(op, ack)) => {
                            ops.push(op);
                            acks.push(ack);
                        }
                        Ok(other) => {
                            control = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let results = engine.admit_batch(ops)?;
                for (res, ack) in results.into_iter().zip(acks) {
                    let _ = ack.send(res);
                }
            }
            match control {
                None => {}
                Some(WriterMsg::Checkpoint(ts, tx)) => {
                    let _ = tx.send(engine.checkpoint(ts));
                }
                Some(WriterMsg::Shutdown(tx)) => {
                    let _ = tx.send(());
                    return Ok(());
                }
                Some(WriterMsg::Admit(..)) => unreachable!(),
            }
        }
    });
    (SubstrateHandle { tx }, SubstrateWriter { join })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn op(obj: &str, kind: &str, expected: Option<&str>, n: u64) -> Operation {
        Operation {
            domain: "bench".into(),
            object_ref: obj.into(),
            op_kind: kind.into(),
            expected_head: expected.map(|s| s.to_string()),
            expected_absent: false,
            payload: serde_json::json!({ "n": n }),
            recorded_at_ms: 1_000 + n,
            idem_key: format!("idem-{n}"),
        }
    }

    fn admitted_body(operation: &Operation, seq: u64, previous_head: &str) -> Vec<u8> {
        let op_bytes = serde_json::to_vec(operation).unwrap();
        let new_head = sha_hex(&[
            b"head|",
            previous_head.as_bytes(),
            b"|",
            op_bytes.as_slice(),
        ]);
        serde_json::to_vec(&LogFrame::Admitted(AdmittedRecord {
            seq,
            new_head,
            op: operation.clone(),
        }))
        .unwrap()
    }

    fn operation_with_frame_size(
        target_bytes: usize,
        object_ref: &str,
        seq: u64,
        previous_head: &str,
    ) -> Operation {
        let mut operation = op(object_ref, "write", None, seq + 1);
        operation.payload = serde_json::json!({ "bytes": "" });
        let base_bytes = admitted_body(&operation, seq, previous_head).len();
        operation.payload = serde_json::json!({ "bytes": "x".repeat(target_bytes - base_bytes) });
        assert_eq!(
            admitted_body(&operation, seq, previous_head).len(),
            target_bytes
        );
        operation
    }

    fn legacy_oversized_log() -> Vec<u8> {
        let operation = operation_with_frame_size(MAX_FRAME_BYTES + 1, "obj://legacy", 0, "");
        let mut admitted = admitted_body(&operation, 0, "");
        let mut encoded_admitted = Vec::with_capacity(4 + admitted.len());
        encoded_admitted.extend_from_slice(
            &u32::try_from(admitted.len())
                .expect("legacy frame fits u32")
                .to_le_bytes(),
        );
        encoded_admitted.append(&mut admitted);
        let mut frame_hash = Sha256::new();
        frame_hash.update(&encoded_admitted);
        let root = sha_hex(&[
            b"root|",
            GENESIS_ROOT.as_bytes(),
            b"|",
            &frame_hash.finalize(),
        ]);
        let root_frame = LogFrame::BatchRoot(BatchRootRecord {
            batch_seq: 0,
            from_seq: 0,
            to_seq: 0,
            prev_root: GENESIS_ROOT.to_string(),
            root,
        });
        let mut encoded_root =
            serde_json::to_vec(&root_frame).expect("encode legacy batch root body");
        encoded_admitted.extend_from_slice(
            &u32::try_from(encoded_root.len())
                .expect("root frame fits u32")
                .to_le_bytes(),
        );
        encoded_admitted.append(&mut encoded_root);
        encoded_admitted
    }

    #[test]
    fn expected_absent_is_backward_compatible_on_the_wire() {
        let legacy = serde_json::json!({
            "domain": "bench",
            "object_ref": "obj://a",
            "op_kind": "create",
            "expected_head": null,
            "payload": {"n": 1},
            "recorded_at_ms": 1001,
            "idem_key": "idem-1"
        });
        let decoded: Operation = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(decoded, op("obj://a", "create", None, 1));
        assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "agentgres-substrate-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn deterministic_roots_across_runs() {
        let (d1, d2) = (tmp("det1"), tmp("det2"));
        let mut e1 = SubstrateEngine::open(&d1, false).unwrap();
        let mut e2 = SubstrateEngine::open(&d2, false).unwrap();
        let ops = || {
            vec![
                op("obj://a", "create", None, 1),
                op("obj://b", "create", None, 2),
                op("obj://a", "update", None, 3),
            ]
        };
        e1.admit_batch(ops()).unwrap();
        e2.admit_batch(ops()).unwrap();
        assert_eq!(e1.current_root(), e2.current_root());
        assert_eq!(e1.head("obj://a"), e2.head("obj://a"));
    }

    #[test]
    fn expected_head_conflict_refuses_without_poisoning_batch() {
        let mut e = SubstrateEngine::open(&tmp("conflict"), false).unwrap();
        let r = e
            .admit_batch(vec![op("obj://a", "create", None, 1)])
            .unwrap();
        let head = r[0].as_ref().unwrap().new_head.clone();
        let r = e
            .admit_batch(vec![
                op("obj://a", "update", Some("sha256:wrong"), 2),
                op("obj://a", "update", Some(&head), 3),
            ])
            .unwrap();
        assert!(matches!(r[0], Err(Refusal::ExpectedHeadConflict { .. })));
        assert!(r[1].is_ok());
    }

    #[test]
    fn substrate_writer_enforces_replayable_frame_limit_per_operation() {
        let directory = tmp("frame-limit");
        let mut engine = SubstrateEngine::open(&directory, false).unwrap();
        let exact = operation_with_frame_size(MAX_FRAME_BYTES, "obj://same", 0, "");
        let exact_head = {
            let op_bytes = serde_json::to_vec(&exact).unwrap();
            sha_hex(&[b"head|", b"", b"|", op_bytes.as_slice()])
        };
        let oversized =
            operation_with_frame_size(MAX_FRAME_BYTES + 1, "obj://same", 1, &exact_head);
        let survivor = op("obj://same", "write", None, 3);
        let survivor_head = {
            let op_bytes = serde_json::to_vec(&survivor).unwrap();
            sha_hex(&[b"head|", exact_head.as_bytes(), b"|", op_bytes.as_slice()])
        };

        let results = engine
            .admit_batch(vec![exact, oversized, survivor])
            .unwrap();
        assert_eq!(results[0].as_ref().unwrap().seq, 0);
        assert!(matches!(
            results[1],
            Err(Refusal::FrameTooLarge {
                ref object_ref,
                encoded_bytes,
                max_bytes: MAX_FRAME_BYTES,
            }) if object_ref == "obj://same" && encoded_bytes == MAX_FRAME_BYTES + 1
        ));
        assert_eq!(results[2].as_ref().unwrap().seq, 1);
        assert_eq!(results[2].as_ref().unwrap().new_head, survivor_head);
        assert_eq!(engine.next_seq(), 2);
        assert_eq!(engine.head("obj://same"), Some(&survivor_head));
        drop(engine);

        let reopened = SubstrateEngine::open(&directory, false).unwrap();
        assert_eq!(reopened.next_seq(), 2);
        assert_eq!(reopened.head("obj://same"), Some(&survivor_head));
    }

    #[test]
    fn oversized_legacy_log_requires_explicit_migration_without_mutating_evidence() {
        let bytes = legacy_oversized_log();
        let open_directory = tmp("legacy-frame-open");
        std::fs::create_dir_all(&open_directory).unwrap();
        let open_path = open_directory.join("oplog.bin");
        std::fs::write(&open_path, &bytes).unwrap();
        let error = SubstrateEngine::open(&open_directory, false)
            .err()
            .expect("legacy oversized log must require migration");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("explicit migration"));
        assert_eq!(std::fs::read(&open_path).unwrap(), bytes);

        let project_directory = tmp("legacy-frame-project");
        let engine = SubstrateEngine::open(&project_directory, false).unwrap();
        let project_path = project_directory.join("oplog.bin");
        std::fs::write(&project_path, &bytes).unwrap();
        let mut visited = 0usize;
        let error = engine
            .project(0, &mut |_| visited += 1)
            .expect_err("projection must not return a partial success");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("explicit migration"));
        assert_eq!(visited, 0);
        assert_eq!(std::fs::read(&project_path).unwrap(), bytes);
    }

    #[test]
    fn recovery_replay_matches() {
        let d = tmp("recover");
        let root_before;
        let head_before;
        {
            let mut e = SubstrateEngine::open(&d, false).unwrap();
            for i in 0..50u64 {
                e.admit_batch(vec![op(&format!("obj://{}", i % 7), "w", None, i)])
                    .unwrap();
            }
            root_before = e.current_root().clone();
            head_before = e.head("obj://3").cloned();
        }
        let e2 = SubstrateEngine::open(&d, false).unwrap();
        assert_eq!(e2.current_root(), &root_before);
        assert_eq!(e2.head("obj://3"), head_before.as_ref());
    }

    #[test]
    fn fork_is_isolated_from_parent() {
        let dp = tmp("fork-parent");
        let df = tmp("fork-child");
        let mut parent = SubstrateEngine::open(&dp, false).unwrap();
        parent
            .admit_batch(vec![op("obj://a", "create", None, 1)])
            .unwrap();
        let ck = parent.checkpoint(2_000).unwrap();
        SubstrateEngine::fork_from(&ck, &dp, &df).unwrap();
        let mut fork = SubstrateEngine::open(&df, false).unwrap();
        assert_eq!(fork.current_root(), parent.current_root());
        fork.admit_batch(vec![op("obj://a", "update", None, 2)])
            .unwrap();
        assert_ne!(fork.current_root(), parent.current_root());
        assert_eq!(parent.head("obj://a"), parent.heads.get("obj://a"));
    }

    #[test]
    fn group_commit_writer_admits_under_concurrency() {
        let d = tmp("writer");
        let engine = SubstrateEngine::open(&d, false).unwrap();
        let (h, w) = spawn_writer(engine, 1024);
        let mut joins = Vec::new();
        for c in 0..4u64 {
            let h = h.clone();
            joins.push(std::thread::spawn(move || {
                for i in 0..250u64 {
                    let n = c * 1_000 + i;
                    h.admit(op(&format!("obj://c{c}"), "w", None, n)).unwrap();
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        h.shutdown();
        w.join.join().unwrap().unwrap();
        let e = SubstrateEngine::open(&d, false).unwrap();
        assert_eq!(e.next_seq(), 1_000);
    }
}
