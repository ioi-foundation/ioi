// Path: crates/client/src/security.rs

//! Implementation of a secure, persistent mTLS channel between containers.

use anyhow::{anyhow, Result};
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::transport::hybrid_kem_tls::{
    client_post_handshake, derive_application_key, AeadWrappedStream,
};
use ioi_ipc::IpcClientType;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName},
        ClientConfig,
    },
    TlsConnector, TlsStream,
};

/// An enum to identify the client connecting to the Guardian.
#[repr(u8)]
enum IpcClientId {
    Orchestration = 1,
    Workload = 2,
}

/// A type alias for a generic, encrypted TLS stream that can be either a client or server stream.
pub type BaseTlsStream = tokio_rustls::TlsStream<TcpStream>;
pub type SecureStream = AeadWrappedStream<BaseTlsStream>;

/*
NOTE on Hybrid KEM Integration:

The IOI SDK architecture specifies a hybrid key exchange (e.g., ECDH + Kyber)
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
    pub async fn establish_client(
        &self,
        server_addr: &str,
        server_name: &str,
        ca_cert_path: &str,
        client_cert_path: &str,
        client_key_path: &str,
    ) -> Result<()> {
        // Load the CA certificate
        let ca_cert_pem = std::fs::read(ca_cert_path)?;
        let mut ca_reader = std::io::Cursor::new(ca_cert_pem);
        let ca_certs: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(ca_certs);

        // Load the client's own certificate and private key
        let client_cert_file = File::open(client_cert_path)?;
        let mut reader = BufReader::new(client_cert_file);
        let client_certs: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

        let client_key_file = File::open(client_key_path)?;
        let mut reader = BufReader::new(client_key_file);
        let client_key_der = rustls_pemfile::private_key(&mut reader)?
            .ok_or_else(|| anyhow!("No private key found in {}", client_key_path))?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key_der.into())?;

        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(server_addr).await?;

        let domain = ServerName::try_from(server_name.to_string())?;

        let client_conn = connector.connect(domain, stream).await?;
        // Wrap the concrete client stream into the generic TlsStream enum
        let mut secure_stream = TlsStream::Client(client_conn);

        // --- POST-HANDSHAKE HYBRID KEY EXCHANGE (before any app bytes) ---
        log::info!("TLS handshake complete. Performing post-handshake PQC key exchange...");
        let mut kem_ss = client_post_handshake(
            &mut secure_stream,
            SecurityLevel::Level3, // EcdhP256Kyber768
        )
        .await?;

        // --- BIND KEM SECRET TO TLS SESSION & DERIVE APPLICATION KEY ---
        let app_key = derive_application_key(&secure_stream, &mut kem_ss)?;
        log::info!(
            "Post-quantum key exchange successful. Derived application key for AEAD wrapper."
        );

        // --- WRAP STREAM WITH AEAD LAYER ---
        let mut aead_stream = AeadWrappedStream::new(secure_stream, app_key);

        // NEW: Send an identification byte to the Guardian using shared enum.
        // This helps the Guardian route the connection.
        let id_byte = if self.source == "orchestration" {
            IpcClientType::Orchestrator as u8
        } else {
            IpcClientType::Workload as u8
        };
        aead_stream.write_all(&[id_byte]).await?; // Use write_all for single byte

        *self.stream.lock().await = Some(aead_stream);

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

    /// Takes ownership of the underlying secure stream.
    /// Returns `None` if the stream has not been established or has already been taken.
    pub async fn take_stream(&self) -> Option<SecureStream> {
        self.stream.lock().await.take()
    }

    /// Checks if the channel stream has been established.
    pub async fn is_established(&self) -> bool {
        self.stream.lock().await.is_some()
    }
}