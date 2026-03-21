fn digest_to_array(digest: impl AsRef<[u8]>) -> Result<[u8; 32]> {
    digest
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("sha256 digest was not 32 bytes"))
}

fn normalize_guardian_endpoint(endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

fn load_transparency_log_signer(config: &GuardianConfig) -> Result<libp2p::identity::Keypair> {
    if let Some(path) = &config.transparency_log.signing_key_path {
        let bytes = std::fs::read(path)?;
        return libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| anyhow!("failed to decode transparency log signer keypair: {e}"));
    }
    if matches!(config.production_mode, GuardianProductionMode::Production) {
        return Err(anyhow!(
            "production guardian profile requires transparency_log.signing_key_path"
        ));
    }
    Ok(libp2p::identity::Keypair::generate_ed25519())
}

fn collect_transparency_log_ids(config: &GuardianConfig) -> BTreeSet<String> {
    let mut log_ids = BTreeSet::new();
    if !config.transparency_log.log_id.trim().is_empty() {
        log_ids.insert(config.transparency_log.log_id.clone());
    }
    if !config.committee.transparency_log_id.trim().is_empty() {
        log_ids.insert(config.committee.transparency_log_id.clone());
    }
    for witness in &config.experimental_witness_committees {
        if !witness.transparency_log_id.trim().is_empty() {
            log_ids.insert(witness.transparency_log_id.clone());
        }
    }
    if log_ids.is_empty() {
        log_ids.insert("guardian-local".to_string());
    }
    log_ids
}

fn parse_target_authority(target_domain: &str) -> Result<(String, u16)> {
    if let Some((host, port)) = target_domain.rsplit_once(':') {
        if !host.is_empty() && !host.contains(']') && !port.is_empty() {
            if let Ok(port) = port.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((target_domain.to_string(), 443))
}

pub(crate) fn compute_secure_egress_request_hash(
    method: &str,
    target_domain: &str,
    path: &str,
    body: &[u8],
) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                method,
                target_domain,
                path,
                hex::encode(Sha256::digest(body).map_err(|e| anyhow!(e))?)
            )
            .as_bytes(),
        )
        .map_err(|e| anyhow!(e))?,
    )
}

pub(crate) fn compute_secure_egress_transcript_root(
    request_hash: [u8; 32],
    handshake_transcript_hash: [u8; 32],
    request_transcript_hash: [u8; 32],
    response_transcript_hash: [u8; 32],
    peer_certificate_chain_hash: [u8; 32],
    response_hash: [u8; 32],
) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(
            &[
                handshake_transcript_hash.as_ref(),
                request_transcript_hash.as_ref(),
                response_transcript_hash.as_ref(),
                request_hash.as_ref(),
                peer_certificate_chain_hash.as_ref(),
                response_hash.as_ref(),
            ]
            .concat(),
        )
        .map_err(|e| anyhow!(e))?,
    )
}

fn decode_pinned_hashes(hex_hashes: &[String]) -> Result<Vec<[u8; 32]>> {
    hex_hashes
        .iter()
        .map(|hex_hash| {
            let trimmed = hex_hash.trim().trim_start_matches("0x");
            let bytes = hex::decode(trimmed)?;
            let len = bytes.len();
            bytes
                .try_into()
                .map_err(|_| anyhow!("configured TLS pin must decode to 32 bytes, got {}", len))
        })
        .collect()
}

fn build_tls_root_store(policy: &GuardianVerifierPolicyConfig) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    if policy.tls_allowed_root_pem_paths.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        return Ok(root_store);
    }

    for pem_path in &policy.tls_allowed_root_pem_paths {
        let pem = std::fs::read(pem_path)?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        let certificates =
            rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
        root_store.add_parsable_certificates(certificates);
    }
    Ok(root_store)
}

struct TranscriptAccumulator {
    request: Sha256,
    response: Sha256,
}

impl TranscriptAccumulator {
    fn new() -> Self {
        Self {
            request: Sha256::new(),
            response: Sha256::new(),
        }
    }

    fn record_request(&mut self, data: &[u8]) -> io::Result<()> {
        self.request
            .update(data)
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn record_response(&mut self, data: &[u8]) -> io::Result<()> {
        self.response
            .update(data)
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn finalize(&mut self) -> Result<([u8; 32], [u8; 32])> {
        let request = std::mem::replace(&mut self.request, Sha256::new())
            .finalize()
            .map_err(|e| anyhow!(e.to_string()))?;
        let response = std::mem::replace(&mut self.response, Sha256::new())
            .finalize()
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((digest_to_array(request)?, digest_to_array(response)?))
    }
}

struct NotarizedTlsStream<S> {
    inner: S,
    transcript: Arc<StdMutex<TranscriptAccumulator>>,
}

impl<S> AsyncRead for NotarizedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                let newly_read = &filled[pre_len..];
                if !newly_read.is_empty() {
                    self.transcript
                        .lock()
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "transcript lock poisoned")
                        })?
                        .record_response(newly_read)?;
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for NotarizedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.transcript
                        .lock()
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "transcript lock poisoned")
                        })?
                        .record_request(&buf[..written])?;
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn peer_certificate_chain_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let peer_certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    if peer_certs.is_empty() {
        return Ok([0u8; 32]);
    }

    let mut concatenated = Vec::new();
    for certificate in peer_certs {
        concatenated.extend_from_slice(certificate.as_ref());
    }
    digest_to_array(Sha256::digest(&concatenated).map_err(|e| anyhow!(e))?)
}

fn peer_leaf_certificate_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let peer_certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    let Some(leaf_certificate) = peer_certs.first() else {
        return Ok([0u8; 32]);
    };
    digest_to_array(Sha256::digest(leaf_certificate.as_ref()).map_err(|e| anyhow!(e))?)
}

fn handshake_exporter_hash(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32]> {
    let mut exporter = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"ioi-egress-transcript-v1", None)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(exporter)
}

async fn notarized_https_request(
    target_domain: &str,
    path: &str,
    method: &str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
    policy: &GuardianVerifierPolicyConfig,
) -> Result<(
    Vec<u8>,
    String,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
)> {
    let (server_name, port) = parse_target_authority(target_domain)?;
    if !policy.tls_allowed_server_names.is_empty()
        && !policy
            .tls_allowed_server_names
            .iter()
            .any(|allowed_name| allowed_name == &server_name)
    {
        return Err(anyhow!(
            "TLS server name '{}' is not allowed by verifier policy",
            server_name
        ));
    }

    let root_store = build_tls_root_store(policy)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp_stream = TcpStream::connect((server_name.as_str(), port)).await?;
    let rustls_server_name =
        ServerName::try_from(server_name.clone()).map_err(|e| anyhow!(e.to_string()))?;
    let tls_stream = connector.connect(rustls_server_name, tcp_stream).await?;

    let peer_cert_hash = peer_certificate_chain_hash(&tls_stream)?;
    let peer_leaf_hash = peer_leaf_certificate_hash(&tls_stream)?;
    let pinned_leaf_hashes = decode_pinned_hashes(&policy.tls_pinned_leaf_certificate_sha256)?;
    if !pinned_leaf_hashes.is_empty() && !pinned_leaf_hashes.contains(&peer_leaf_hash) {
        return Err(anyhow!(
            "peer leaf certificate hash does not match any configured TLS pin"
        ));
    }
    let handshake_hash = handshake_exporter_hash(&tls_stream)?;
    let transcript = Arc::new(StdMutex::new(TranscriptAccumulator::new()));
    let notarized_stream = NotarizedTlsStream {
        inner: tls_stream,
        transcript: transcript.clone(),
    };
    let (mut sender, connection) = http1::handshake(TokioIo::new(notarized_stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = HttpRequest::builder()
        .method(method)
        .uri(path)
        .header("host", target_domain)
        .header("content-type", "application/json")
        .header("accept-encoding", "identity")
        .header("connection", "close");
    for (header_name, header_value) in headers {
        builder = builder.header(header_name, header_value);
    }

    let response = sender
        .send_request(builder.body(Full::new(Bytes::from(body)))?)
        .await?;
    let response_bytes = response.collect().await?.to_bytes().to_vec();
    drop(sender);

    let (request_transcript_hash, response_transcript_hash) = transcript
        .lock()
        .map_err(|_| anyhow!("transcript lock poisoned"))?
        .finalize()?;

    Ok((
        response_bytes,
        server_name,
        peer_cert_hash,
        peer_leaf_hash,
        handshake_hash,
        request_transcript_hash,
        response_transcript_hash,
    ))
}

/// Generates a self-signed CA and server/client certificates for mTLS.
pub fn generate_certificates_if_needed(certs_dir: &Path) -> Result<()> {
    if certs_dir.join("ca.pem").exists() {
        return Ok(());
    }
    log::info!(
        "Generating mTLS CA and certificates in {}",
        certs_dir.display()
    );
    std::fs::create_dir_all(certs_dir)?;

    // [FIX] rcgen 0.13 changes: CertificateParams::new returns Result
    let mut ca_params = CertificateParams::new(vec!["IOI Kernel Local CA".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // [FIX] Generate keypair explicitly
    let ca_keypair = KeyPair::generate()?;
    // [FIX] Use self_signed
    let ca_cert = ca_params.self_signed(&ca_keypair)?;

    // [FIX] Use pem() instead of serialize_pem()
    std::fs::write(certs_dir.join("ca.pem"), ca_cert.pem())?;
    std::fs::write(certs_dir.join("ca.key"), ca_keypair.serialize_pem())?;

    let signers = [
        ("guardian-server", vec!["guardian", "localhost"]),
        ("workload-server", vec!["workload", "localhost"]),
        ("orchestration", vec![]),
        ("workload", vec![]),
    ];
    for (name, domains) in &signers {
        // [FIX] CertificateParams::new returns Result
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        params.subject_alt_names = domains
            .iter()
            .map(|d| {
                // [FIX] Use Ia5String for DnsName
                SanType::DnsName(Ia5String::try_from(d.to_string()).expect("valid dns name"))
            })
            .chain(vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())])
            .collect();

        let keypair = KeyPair::generate()?;
        // [FIX] Use signed_by
        let cert = params.signed_by(&keypair, &ca_cert, &ca_keypair)?;

        std::fs::write(certs_dir.join(format!("{}.pem", name)), cert.pem())?;
        std::fs::write(
            certs_dir.join(format!("{}.key", name)),
            keypair.serialize_pem(),
        )?;
    }
    Ok(())
}
