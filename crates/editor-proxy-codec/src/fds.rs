//! Received descriptors as the pure machines see them: an adapter-owned handle plus the adapter's
//! validated facts. A raw fd is never a pure-code proof of its own role.

use crate::wire::MAX_ANCILLARY_FDS;

/// A received socket's domain/type class (from SO_DOMAIN / SO_TYPE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SocketClass {
    /// AF_INET / SOCK_STREAM.
    InetStream,
    /// AF_UNIX / SOCK_STREAM.
    UnixStream,
    /// Anything else (incl. not a socket).
    Other,
}

/// What the trusted fd adapter observed about one received descriptor. The machines trust these
/// facts as the adapter's summary; U3/U4 own their measurement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FdFacts {
    /// SO_DOMAIN / SO_TYPE.
    pub class: SocketClass,
    /// SO_ACCEPTCONN = 1.
    pub accept_conn: bool,
    /// SO_ERROR is nonzero.
    pub pending_error: bool,
    /// getpeername succeeded.
    pub connected: bool,
    /// getsockname for AF_INET: (IPv4 address, port).
    pub local_inet: Option<([u8; 4], u16)>,
    /// The adapter's check of the peer against the trusted endpoint specification (U4 (11)).
    pub peer_matches_spec: bool,
}

impl FdFacts {
    /// A listener on 127.0.0.1:`port` with no pending error (what a WELCOME must carry).
    pub const fn loopback_listener(port: u16) -> FdFacts {
        FdFacts {
            class: SocketClass::InetStream,
            accept_conn: true,
            pending_error: false,
            connected: false,
            local_inet: Some(([127, 0, 0, 1], port)),
            peer_matches_spec: false,
        }
    }

    /// A connected stream of `class` whose peer matches the specification (what an admitted
    /// upstream VERDICT must carry).
    pub const fn connected_upstream(class: SocketClass) -> FdFacts {
        FdFacts {
            class,
            accept_conn: false,
            pending_error: false,
            connected: true,
            local_inet: None,
            peer_matches_spec: true,
        }
    }
}

/// One received descriptor: the adapter's owned handle (its drop closes the fd) and its facts.
pub struct ReceivedFd<H> {
    /// The adapter's owned descriptor.
    pub handle: H,
    /// What the adapter observed about it.
    pub facts: FdFacts,
}

/// The descriptors one receive delivered, at most [`MAX_ANCILLARY_FDS`] (the proxy's bounded
/// control space; more arrive as MSG_CTRUNC). Dropping the batch drops (closes) every handle.
pub struct FdBatch<H> {
    slots: [Option<ReceivedFd<H>>; MAX_ANCILLARY_FDS],
    len: usize,
}

impl<H> FdBatch<H> {
    /// An empty batch.
    pub fn new() -> FdBatch<H> {
        FdBatch {
            slots: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    /// Adds one received descriptor; a full batch hands it back.
    pub fn push(&mut self, fd: ReceivedFd<H>) -> Result<(), ReceivedFd<H>> {
        if self.len == MAX_ANCILLARY_FDS {
            return Err(fd);
        }
        self.slots[self.len] = Some(fd);
        self.len += 1;
        Ok(())
    }

    /// How many descriptors the batch holds.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if the batch holds none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The first descriptor's facts.
    pub(crate) fn first_facts(&self) -> Option<FdFacts> {
        match &self.slots[0] {
            Some(fd) => Some(fd.facts),
            None => None,
        }
    }

    /// The single descriptor (the caller checked `len() == 1`); the rest of the batch drops.
    pub(crate) fn into_first(mut self) -> Option<H> {
        match self.slots[0].take() {
            Some(fd) => Some(fd.handle),
            None => None,
        }
    }
}

impl<H> Default for FdBatch<H> {
    fn default() -> FdBatch<H> {
        FdBatch::new()
    }
}
