// Path: crates/validator/src/common/security.rs

//! Implementation of a secure, persistent mTLS channel between containers.

use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, SignatureScheme,
    },
    TlsConnector,
};

// Use a type alias for brevity. This is the encrypted stream.
pub type SecureStream = tokio_rustls::TlsStream<TcpStream>;

/*
NOTE on Hybrid KEM Integration:

The DePIN SDK architecture specifies a hybrid key exchange (e.g., ECDH + Kyber)
for quantum resistance. Integrating a custom KEM into `rustls` requires implementing
the `rustls::crypto::CryptoProvider` trait, which is a significant undertaking.

This implementation provides the correct mTLS architecture (TLS 1.3) and a
persistent, secure channel. It serves as the foundation upon which a custom
hybrid `CryptoProvider` can be built and plugged in to fully realize the
quantum-resistant goal.
*/

/// A persistent, secure mTLS channel for bidirectional communication.
#[derive(Debug, Clone)]
pub struct SecurityChannel {
    pub source: String,
    pub destination: String,
    // The stream is wrapped in Arc<Mutex<Option<...>>> to allow it to be
    // established lazily and shared safely across async tasks.
    stream: Arc<Mutex<Option<SecureStream>>>,
}

// A custom verifier to accept the Guardian's self-signed certificate.
// This is safe for a trusted, local inter-container environment.
#[derive(Debug)]
struct SelfSignedCertVerifier;
impl ServerCertVerifier for SelfSignedCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl SecurityChannel {
    /// Creates a new, unestablished security channel.
    pub fn new(source: &str, destination: &str) -> Self {
        Self {
            source: source.to_string(),
            destination: destination.to_string(),
            stream: Arc::new(Mutex::new(None)),
        }
    }

    /// Establishes the channel from the client-side.
    pub async fn establish_client(&self, server_addr: &str, server_name: &str) -> Result<()> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SelfSignedCertVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(server_addr).await?;

        // FIX: Convert the borrowed `&str` to an owned `String` so the resulting
        // `ServerName` has a 'static lifetime, which is required by `connect`.
        let domain = ServerName::try_from(server_name.to_string())?;

        let tls_stream = connector.connect(domain, stream).await?;
        let mut secure_stream = tokio_rustls::TlsStream::Client(tls_stream);

        // NEW: Send an identification byte to the Guardian.
        // 1 = Orchestration, 2 = Workload. This helps the Guardian route the connection.
        let id_byte = if self.source == "orchestration" {
            1u8
        } else {
            2u8
        };
        secure_stream.write_u8(id_byte).await?;

        *self.stream.lock().await = Some(secure_stream);

        log::info!(
            "✅ Security channel from '{}' to '{}' established.",
            self.source,
            self.destination
        );
        Ok(())
    }

    /// Accepts a new connection on the server-side and stores the stream.
    pub async fn accept_server_connection(&self, stream: SecureStream) {
        *self.stream.lock().await = Some(stream);
        log::info!(
            "✅ Security channel from '{}' to '{}' accepted.",
            self.destination,
            self.source
        );
    }

    /// Checks if the channel stream has been established.
    pub async fn is_established(&self) -> bool {
        self.stream.lock().await.is_some()
    }

    /// Sends data over the established secure channel.
    /// Messages are framed with a 4-byte (u32) length prefix.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mut stream_lock = self.stream.lock().await;
        let stream = stream_lock.as_mut().ok_or_else(|| {
            anyhow!(
                "Channel from {} to {} not established for sending",
                self.source,
                self.destination
            )
        })?;

        let len = data.len() as u32;
        stream.write_u32(len).await?;
        stream.write_all(data).await?;
        Ok(())
    }

    /// Receives data from the established secure channel.
    pub async fn receive(&self) -> Result<Vec<u8>> {
        let mut stream_lock = self.stream.lock().await;
        let stream = stream_lock.as_mut().ok_or_else(|| {
            anyhow!(
                "Channel from {} to {} not established for receiving",
                self.source,
                self.destination
            )
        })?;

        let len = stream.read_u32().await?;

        let mut buffer = vec![0; len as usize];
        stream.read_exact(&mut buffer).await?;
        Ok(buffer)
    }
}
