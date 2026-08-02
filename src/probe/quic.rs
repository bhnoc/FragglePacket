use std::future::IntoFuture;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

/// QUIC-based MTU discovery
/// QUIC has built-in PMTUD using PING frames with padding
pub fn probe_quic_mtu(target: &str, port: u16, timeout_ms: u64) -> Option<usize> {
    // Build a tokio runtime for async QUIC operations
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return None,
    };

    rt.block_on(async {
        quic_mtu_probe_async(target, port, timeout_ms).await
    })
}

pub async fn quic_mtu_probe_async(target: &str, port: u16, timeout_ms: u64) -> Option<usize> {
    use quinn::{ClientConfig, Endpoint, TransportConfig};

    // Create client config that skips certificate verification
    // (we're just probing MTU, not establishing secure comms)
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_millis(timeout_ms).try_into().ok()?));

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).ok()?
    ));
    client_config.transport_config(Arc::new(transport));

    // Create endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().ok()?).ok()?;
    endpoint.set_default_client_config(client_config);

    // Resolve target
    let addr: SocketAddr = format!("{}:{}", target, port)
        .to_socket_addrs()
        .ok()?
        .next()?;

    // Try to connect
    let conn = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(addr, target).ok()?.into_future()
    ).await {
        Ok(Ok(conn)) => conn,
        _ => return None,
    };

    // Get the current MTU from QUIC connection
    // QUIC discovers MTU through its own PMTUD mechanism
    let mtu = conn.max_datagram_size();

    // Close cleanly
    conn.close(0u32.into(), b"mtu probe complete");
    endpoint.wait_idle().await;

    mtu
}

/// Certificate verifier that accepts any certificate (for MTU probing only)
#[derive(Debug)]
pub struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Test if a target supports QUIC (HTTP/3)
pub fn check_quic_support(target: &str) -> bool {
    // Use curl to check for Alt-Svc header indicating QUIC/HTTP3 support
    let output = Command::new("curl")
        .args([
            "-s", "-I", "--max-time", "3",
            &format!("https://{}", target)
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    match output {
        Ok(out) => {
            let headers = String::from_utf8_lossy(&out.stdout).to_lowercase();
            headers.contains("alt-svc") &&
                (headers.contains("h3") || headers.contains("quic"))
        }
        Err(_) => false,
    }
}
