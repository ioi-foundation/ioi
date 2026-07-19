//! Log-shipping replica: replication-as-durability with epoch fencing and
//! offset catch-up (protocol v2, `AGRS2`).
//!
//! The primary ships each admitted batch's EXACT appended log bytes before
//! acking; the replica appends the same bytes, so replayed heads/roots are
//! identical BY CONSTRUCTION. The replica dir is a valid engine dir — open
//! it with `MuxEngine::open` to replay, or promote it to the next writer
//! epoch for operator-driven failover.
//!
//! Handshake (both directions after magic):
//!   primary -> `AGRS2 | u64 writer_epoch | u64 primary_log_len`
//!   replica -> `AGRS2 | u64 max_epoch_seen | u64 replica_log_len`
//! Fencing: a primary whose epoch is BELOW the replica's max is refused at
//! handshake, and every shipped batch carries its epoch — a batch below the
//! replica's max is fence-NACKed (ack id with the high bit set) and the
//! connection closes. A deposed primary therefore loses its replicated
//! durability class LOUDLY; it can never split the brain on the replica.
//! Catch-up: if the replica's log is shorter, the primary streams the gap
//! bytes (frame-boundary aligned on both sides — torn tails are truncated
//! by engine recovery before serving) before normal streaming begins. A
//! replica AHEAD of its primary is refused loudly (operator resolves: the
//! ahead node should be promoted, not overwritten).
//!
//! Durability honesty (INV-14): replica acks fire when the bytes are held
//! (write_all); device flush is background hygiene on an independent fd on
//! both sides. `quorum_replicated` requires the link to be DECLARED
//! failure-independent; same-host peers are capped at
//! `replicated_same_host`.

use crate::mux::MuxEngine;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 5] = b"AGRS2";
const FENCE_BIT: u64 = 1 << 63;
const CATCHUP_CHUNK: usize = 1 << 20;

fn write_u64(s: &mut TcpStream, v: u64) -> std::io::Result<()> {
    s.write_all(&v.to_le_bytes())
}
fn read_u64(s: &mut TcpStream) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    s.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Primary-side link to one replica.
pub struct ReplicaLink {
    stream: TcpStream,
    next_batch_id: u64,
    epoch: u64,
    pub failure_independent: bool,
}

impl ReplicaLink {
    /// Connect, fence-check, and catch the replica up to `log_path`'s
    /// current length before returning a streaming-ready link.
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        failure_independent: bool,
        epoch: u64,
        log_path: &Path,
        log_len: u64,
    ) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.write_all(MAGIC)?;
        write_u64(&mut stream, epoch)?;
        write_u64(&mut stream, log_len)?;
        let mut echo = [0u8; 5];
        stream.read_exact(&mut echo)?;
        if &echo != MAGIC {
            return Err(std::io::Error::other("replica handshake mismatch"));
        }
        let replica_epoch = read_u64(&mut stream)?;
        let replica_len = read_u64(&mut stream)?;
        if replica_epoch > epoch {
            return Err(std::io::Error::other(format!(
                "FENCED at handshake: replica has seen epoch {replica_epoch} > ours {epoch} — this writer is deposed"
            )));
        }
        if replica_len > log_len {
            return Err(std::io::Error::other(format!(
                "replica AHEAD ({replica_len} > {log_len} bytes) — refuse to overwrite; promote the ahead node instead"
            )));
        }
        if replica_len < log_len {
            // Catch-up: stream the gap from our own log file.
            let mut f = std::fs::File::open(log_path)?;
            f.seek(SeekFrom::Start(replica_len))?;
            let mut remaining = log_len - replica_len;
            let mut buf = vec![0u8; CATCHUP_CHUNK];
            while remaining > 0 {
                let n = remaining.min(CATCHUP_CHUNK as u64) as usize;
                f.read_exact(&mut buf[..n])?;
                stream.write_all(&buf[..n])?;
                remaining -= n as u64;
            }
            let confirmed = read_u64(&mut stream)?;
            if confirmed != log_len {
                return Err(std::io::Error::other(format!(
                    "catch-up length mismatch: replica confirmed {confirmed}, expected {log_len}"
                )));
            }
        }
        Ok(Self {
            stream,
            next_batch_id: 0,
            epoch,
            failure_independent,
        })
    }

    /// Ship one batch's appended bytes; returns when the replica holds them.
    /// A fence-NACK means this writer's epoch is stale (deposed).
    pub fn ship(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        write_u64(&mut self.stream, self.epoch)?;
        write_u64(&mut self.stream, id)?;
        self.stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.stream.write_all(bytes)?;
        let ack = read_u64(&mut self.stream)?;
        if ack & FENCE_BIT != 0 {
            return Err(std::io::Error::other(format!(
                "FENCED mid-stream: replica rejected epoch {} (a higher writer epoch exists) — this writer is deposed",
                self.epoch
            )));
        }
        if ack != id {
            return Err(std::io::Error::other("replica ack id mismatch"));
        }
        Ok(())
    }
}

/// Replica server: accepts one primary at a time, appends shipped bytes to
/// `<dir>/muxlog.bin`, enforces epoch fencing, serves catch-up, and flushes
/// on a background cadence.
pub struct ReplicaServer {
    listener: TcpListener,
    dir: PathBuf,
    flush_interval_ms: u64,
}

impl ReplicaServer {
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
        dir: &Path,
        flush_interval_ms: u64,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            listener: TcpListener::bind(addr)?,
            dir: dir.to_path_buf(),
            flush_interval_ms: flush_interval_ms.max(1),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept one connection (test/embedding helper for `serve_one`).
    pub fn listener_accept_for_test(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        self.listener.accept()
    }

    /// Serve primaries forever (one connection at a time).
    pub fn serve_forever(&self) -> std::io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept()?;
            if let Err(e) = self.serve_one(stream) {
                eprintln!("substrate-replica: connection ended: {e}");
            }
        }
    }

    /// Serve exactly one primary connection to completion.
    pub fn serve_one(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_nodelay(true)?;
        let mut magic = [0u8; 5];
        stream.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(std::io::Error::other("bad primary handshake"));
        }
        let primary_epoch = read_u64(&mut stream)?;
        let primary_len = read_u64(&mut stream)?;
        // Recover local truth first: truncate any torn tail, learn max epoch.
        let (mut max_epoch, my_len) = {
            let recovered = MuxEngine::open(&self.dir, false)?;
            let len = recovered.log_len()?;
            (recovered.current_epoch(), len)
        };
        stream.write_all(MAGIC)?;
        write_u64(&mut stream, max_epoch)?;
        write_u64(&mut stream, my_len)?;
        if primary_epoch < max_epoch {
            // Fenced at handshake; the reply above told the primary why.
            return Err(std::io::Error::other(format!(
                "fenced stale primary (epoch {primary_epoch} < {max_epoch})"
            )));
        }
        if my_len > primary_len {
            return Err(std::io::Error::other(format!(
                "replica ahead ({my_len} > {primary_len}) — refusing overwrite"
            )));
        }
        let log_path = self.dir.join("muxlog.bin");
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        if my_len < primary_len {
            // Catch-up: receive exactly the gap bytes, then confirm.
            let mut remaining = primary_len - my_len;
            let mut buf = vec![0u8; CATCHUP_CHUNK];
            while remaining > 0 {
                let n = remaining.min(CATCHUP_CHUNK as u64) as usize;
                stream.read_exact(&mut buf[..n])?;
                log.write_all(&buf[..n])?;
                remaining -= n as u64;
            }
            log.sync_data()?;
            write_u64(&mut stream, primary_len)?;
        }
        max_epoch = max_epoch.max(primary_epoch);
        // Background flusher on an independent fd: acks never wait on flush.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flusher = {
            let stop = stop.clone();
            let path = log_path.clone();
            let interval = std::time::Duration::from_millis(self.flush_interval_ms);
            std::thread::spawn(move || {
                let Ok(fd) = std::fs::File::open(&path) else {
                    return;
                };
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    let _ = fd.sync_data();
                }
                let _ = fd.sync_data();
            })
        };
        let result = (|| -> std::io::Result<()> {
            loop {
                let epoch = match read_u64(&mut stream) {
                    Ok(v) => v,
                    Err(_) => break, // primary gone
                };
                let id = read_u64(&mut stream)?;
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf)?;
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut bytes = vec![0u8; len];
                stream.read_exact(&mut bytes)?;
                if epoch < max_epoch {
                    // Fence a deposed primary mid-stream: NACK and close.
                    write_u64(&mut stream, id | FENCE_BIT)?;
                    return Err(std::io::Error::other(format!(
                        "fenced mid-stream (batch epoch {epoch} < {max_epoch})"
                    )));
                }
                max_epoch = max_epoch.max(epoch);
                log.write_all(&bytes)?;
                write_u64(&mut stream, id)?;
            }
            Ok(())
        })();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flusher.join();
        log.sync_data()?;
        result
    }
}
