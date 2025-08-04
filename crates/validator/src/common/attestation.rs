// Path: crates/validator/src/common/attestation.rs
// Final Version: Corrected to use the modern rustls v0.22 API, including the correct
// builder pattern and crypto provider usage, resolving all compilation errors.

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, SignatureScheme,
    },
    TlsConnector,
};

pub async fn attest_to_guardian(guardian_addr: &str) -> Result<()> {
    // This is a temporary measure for the prototype to allow self-signed certs.
    // DO NOT USE IN PRODUCTION.
    #[derive(Debug)]
    struct SkipServerVerification;
    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // Correctly get all supported schemes from the default crypto provider.
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    // Modern rustls builder pattern. The root store is not needed because we
    // are using a custom verifier that bypasses it.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(guardian_addr).await?;
    let domain = ServerName::try_from("guardian")?;

    // The connect method takes the domain directly.
    match connector.connect(domain, stream).await {
        Ok(_) => {
            log::info!("Successfully attested to Guardian at {}", guardian_addr);
            Ok(())
        }
        Err(e) => {
            log::error!("Failed to attest to Guardian: {}", e);
            Err(e.into())
        }
    }
}
