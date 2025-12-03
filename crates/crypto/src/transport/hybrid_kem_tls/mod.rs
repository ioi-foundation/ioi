// Path: crates/crypto/src/transport/hybrid_kem_tls/mod.rs
#![allow(clippy::indexing_slicing)] // Allow indexing for known-size buffers

//! Implements a post-handshake key exchange using a hybrid KEM and an AEAD wrapper
//! to upgrade a classical TLS session to be post-quantum secure.

use crate::kem::hybrid::{HybridEncapsulated, HybridKEM, HybridPublicKey};
use crate::security::SecurityLevel;
use anyhow::{anyhow, Result};
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::mac::Hmac;
// FIX: Import the correct traits for the builder pattern.
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation};
use dcrypt::api::traits::SymmetricCipher;
use ioi_api::crypto::{Encapsulated, KeyEncapsulation, SerializableKey};
use ioi_api::error::CryptoError;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsStream;
use zeroize::{Zeroize, Zeroizing};

const KEM_FRAME_LIMIT: u32 = 4096;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_TAG_SIZE: usize = 16;
pub const MAX_PLAINTEXT_FRAME: usize = 64 * 1024;
const MAX_CIPHERTEXT_FRAME: usize = MAX_PLAINTEXT_FRAME + AEAD_TAG_SIZE;

/// A helper to correctly access the exporter on the underlying rustls connection.
fn tls_exporter<S>(
    stream: &TlsStream<S>,
    label: &'static [u8],
    out: &mut [u8],
) -> Result<(), rustls::Error> {
    match stream {
        TlsStream::Client(c) => c
            .get_ref()
            .1
            .export_keying_material(out, label, None)
            .map(|_| ()),
        TlsStream::Server(s) => s
            .get_ref()
            .1
            .export_keying_material(out, label, None)
            .map(|_| ()),
    }
}

/// Derives a 32-byte application key by binding the hybrid KEM shared secret
/// to the TLS session transcript using a TLS 1.3 exporter.
pub fn derive_application_key<S>(
    stream: &TlsStream<S>,
    kem_ss: &mut Zeroizing<Vec<u8>>,
) -> Result<[u8; 32], CryptoError> {
    let mut exporter_secret = [0u8; 32];
    tls_exporter(stream, b"ioi-hybrid-kem-v1", &mut exporter_secret)
        .map_err(|e| CryptoError::OperationFailed(format!("TLS exporter failed: {}", e)))?;
    let k_app = Hmac::<Sha256>::mac(&exporter_secret, kem_ss)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF failed: {}", e)))?;
    kem_ss.zeroize();
    exporter_secret.zeroize();
    let k_app_array: [u8; 32] = (&k_app[..])
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Derived key was not 32 bytes".into()))?;
    Ok(k_app_array)
}

#[derive(Debug)]
enum ReadState {
    ReadingHeader {
        have: usize,
        buf: [u8; 4],
    },
    ReadingBody {
        need: usize,
        have: usize,
        buf: Vec<u8>,
    },
    // NEW state to handle draining a decrypted frame to potentially small caller buffers.
    DrainingPlaintext {
        plaintext: Vec<u8>,
        read: usize,
    },
}

impl Default for ReadState {
    fn default() -> Self {
        ReadState::ReadingHeader {
            have: 0,
            buf: [0; 4],
        }
    }
}

#[derive(Debug)]
enum WriteState {
    Idle,
    Writing { buf: Vec<u8>, written: usize },
}

impl Default for WriteState {
    fn default() -> Self {
        WriteState::Idle
    }
}

#[inline]
fn nonce_from_counter(counter: u64) -> dcrypt::algorithms::types::Nonce<AEAD_NONCE_SIZE> {
    let mut n = [0u8; AEAD_NONCE_SIZE];
    n[AEAD_NONCE_SIZE - 8..].copy_from_slice(&counter.to_be_bytes());
    dcrypt::algorithms::types::Nonce::new(n)
}

pub struct AeadWrappedStream<S> {
    inner: S,
    cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
    read_state: ReadState,
    write_state: WriteState,
}

impl<S> fmt::Debug for AeadWrappedStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadWrappedStream")
            .field("send_nonce", &self.send_nonce)
            .field("recv_nonce", &self.recv_nonce)
            .finish_non_exhaustive()
    }
}

impl<S> AeadWrappedStream<S> {
    pub fn new(inner: S, key: [u8; 32]) -> Self {
        Self {
            inner,
            cipher: ChaCha20Poly1305::new(&key),
            send_nonce: 0,
            recv_nonce: 0,
            read_state: ReadState::default(),
            write_state: WriteState::default(),
        }
    }

    fn seal_frame(&mut self, pt: &[u8]) -> Result<Vec<u8>, io::Error> {
        if pt.len() > MAX_PLAINTEXT_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Plaintext frame exceeds limit",
            ));
        }
        let nonce = nonce_from_counter(self.send_nonce);
        // FIX: Use the explicit builder pattern via the `SymmetricCipher` trait to disambiguate from
        // the inherent `encrypt` method on the `ChaCha20Poly1305` struct.
        let ct_obj = SymmetricCipher::encrypt(&self.cipher)
            .with_nonce(&nonce)
            .encrypt(pt)
            .map_err(|_| io::Error::other("AEAD encryption failed"))?;

        let ct = ct_obj.as_ref();
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(ct);

        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Send nonce overflow"))?;
        Ok(out)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AeadWrappedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            match &mut me.read_state {
                ReadState::DrainingPlaintext { plaintext, read } => {
                    let can_write = std::cmp::min(out.remaining(), plaintext.len() - *read);
                    if can_write > 0 {
                        out.put_slice(&plaintext[*read..*read + can_write]);
                        *read += can_write;
                    }

                    if *read == plaintext.len() {
                        // Finished draining this frame, reset to read the next one.
                        me.read_state = ReadState::default();
                    }
                    return Poll::Ready(Ok(()));
                }

                ReadState::ReadingHeader { have, buf } => {
                    if *have < 4 {
                        let mut tmp = ReadBuf::new(&mut buf[*have..]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp.filled().len();
                                if n == 0 {
                                    return if *have == 0 {
                                        Poll::Ready(Ok(()))
                                    } else {
                                        Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::UnexpectedEof,
                                            "EOF in AEAD frame header",
                                        )))
                                    };
                                }
                                *have += n;
                                if *have < 4 {
                                    continue;
                                }
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let len = u32::from_be_bytes(*buf) as usize;
                    if len == 0 || len > MAX_CIPHERTEXT_FRAME {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid AEAD frame length: {}", len),
                        )));
                    }
                    me.read_state = ReadState::ReadingBody {
                        need: len,
                        have: 0,
                        buf: vec![0; len],
                    };
                }
                ReadState::ReadingBody { need, have, buf } => {
                    if *have < *need {
                        let mut tmp = ReadBuf::new(&mut buf[*have..]);
                        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "EOF in AEAD frame body",
                                    )));
                                }
                                *have += n;
                                if *have < *need {
                                    continue;
                                }
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    debug_assert_eq!(*have, *need);

                    let nonce = nonce_from_counter(me.recv_nonce);
                    // FIX: Use std::mem::take to move the vector out of the mutable reference,
                    // satisfying the Into<Vec<u8>> trait bound.
                    let ciphertext_obj = dcrypt::api::types::Ciphertext::new(std::mem::take(buf));
                    let pt = SymmetricCipher::decrypt(&me.cipher)
                        .with_nonce(&nonce)
                        .decrypt(&ciphertext_obj)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "AEAD decryption failed")
                        })?;

                    me.recv_nonce = me
                        .recv_nonce
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("Receive nonce overflow"))?;

                    me.read_state = ReadState::DrainingPlaintext {
                        plaintext: pt,
                        read: 0,
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AeadWrappedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if let WriteState::Idle = me.write_state {
            let frame = me.seal_frame(data)?;
            me.write_state = WriteState::Writing {
                buf: frame,
                written: 0,
            };
        }
        if let WriteState::Writing { buf, written } = &mut me.write_state {
            while *written < buf.len() {
                match Pin::new(&mut me.inner).poll_write(cx, &buf[*written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Failed to write AEAD frame",
                        )))
                    }
                    Poll::Ready(Ok(n)) => *written += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            me.write_state = WriteState::Idle;
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // FIX: First, ensure any internally buffered write data is flushed.
        if let Poll::Pending = self.as_mut().poll_write_buffered(cx) {
            return Poll::Pending;
        }
        // Then, flush the underlying stream.
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // FIX: Ensure all buffered data is written before shutting down.
        if let Poll::Pending = self.as_mut().poll_write_buffered(cx) {
            return Poll::Pending;
        }
        // Then, shut down the underlying stream.
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncWrite + Unpin> AeadWrappedStream<S> {
    // FIX: This method needs to be on `Pin<&mut Self>` to be callable from poll_flush/shutdown.
    fn poll_write_buffered(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if let WriteState::Writing { buf, written } = &mut me.write_state {
            while *written < buf.len() {
                match Pin::new(&mut me.inner).poll_write(cx, &buf[*written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Failed to write AEAD frame",
                        )))
                    }
                    Poll::Ready(Ok(n)) => *written += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            me.write_state = WriteState::Idle;
        }
        Poll::Ready(Ok(()))
    }
}

async fn write_kem_framed<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;
    Ok(())
}

async fn read_kem_framed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let len = stream.read_u32().await?;
    if len > KEM_FRAME_LIMIT {
        return Err(anyhow!(
            "Post-handshake KEM frame length ({}) exceeds limit",
            len
        ));
    }
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn client_post_handshake<S>(
    stream: &mut TlsStream<S>,
    level: SecurityLevel,
) -> Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hybrid_kem = HybridKEM::new(level)?;
    let keypair = hybrid_kem.generate_keypair()?;
    let pk_bytes = keypair.public_key.to_bytes();

    write_kem_framed(stream, &pk_bytes).await?;
    let ct_bytes = read_kem_framed(stream).await?;
    let encapsulated = HybridEncapsulated::from_bytes(&ct_bytes)?;
    let shared_secret = hybrid_kem.decapsulate(&keypair.private_key, &encapsulated)?;
    Ok(shared_secret)
}

pub async fn server_post_handshake<S>(
    stream: &mut TlsStream<S>,
    level: SecurityLevel,
) -> Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hybrid_kem = HybridKEM::new(level)?;
    let pk_bytes = read_kem_framed(stream).await?;
    let public_key = HybridPublicKey::from_bytes(&pk_bytes)?;
    let encapsulated = hybrid_kem.encapsulate(&public_key)?;
    let shared_secret = Zeroizing::new(encapsulated.shared_secret().to_vec());
    write_kem_framed(stream, &encapsulated.to_bytes()).await?;
    Ok(shared_secret)
}
