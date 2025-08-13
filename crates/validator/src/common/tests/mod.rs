// Path: crates/validator/src/common/tests/mod.rs

//! Tests for common validator components

use super::guardian::GuardianContainer;
use super::security::SecurityChannel;
use depin_sdk_api::validator::{Container, GuardianContainer as GuardianContainerTrait};
use std::path::Path;
use std::sync::Arc;

#[tokio::test]
async fn test_guardian_container() {
    let config_path = Path::new("test_config.toml");
    // Create a dummy config file for the test
    let config_content = r#"listen_addr = "127.0.0.1:0""#;
    std::fs::write(config_path, config_content).unwrap();

    let guardian = GuardianContainer::new(config_path).unwrap();

    // Initial state
    assert!(!guardian.is_running());

    // Start the container
    guardian.start().await.unwrap();
    assert!(guardian.is_running());

    // Test trait methods
    guardian.start_boot().unwrap();
    let attestation_result = guardian.verify_attestation().unwrap();
    assert!(attestation_result);

    // Stop the container
    guardian.stop().await.unwrap();
    assert!(!guardian.is_running());

    // Clean up dummy file
    std::fs::remove_file(config_path).unwrap();
}

#[tokio::test]
async fn test_security_channel_e2e() {
    // 1. Set up a mock TLS server.
    let (server_addr, server_task) = {
        use rcgen::{Certificate, CertificateParams};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::{
            pki_types::{CertificateDer, PrivateKeyDer},
            ServerConfig,
        };
        use tokio_rustls::TlsAcceptor;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create server config
        let mut server_params = CertificateParams::new(vec!["test-server".to_string()]);
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName("test-server".to_string())];
        let cert = Certificate::from_params(server_params).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.serialize_private_key_der();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(stream).await.unwrap();

            // Echo framed data back to the client
            let len = tls_stream.read_u32().await.unwrap();
            let mut buf = vec![0; len as usize];
            tls_stream.read_exact(&mut buf).await.unwrap();
            tls_stream.write_u32(len).await.unwrap();
            tls_stream.write_all(&buf).await.unwrap();
        });
        (addr.to_string(), task)
    };

    // 2. Create and establish the client-side channel.
    let channel = SecurityChannel::new("test_client", "test_server");
    channel
        .establish_client(&server_addr, "test-server")
        .await
        .unwrap();

    // 3. Test send and receive
    let data = vec![1, 2, 3, 4, 5, 6, 7];
    channel.send(&data).await.unwrap();

    let received = channel.receive().await.unwrap();
    assert_eq!(data, received);

    // 4. Clean up the server task
    server_task.abort();
}
