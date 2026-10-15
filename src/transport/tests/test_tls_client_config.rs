//! `TlsConfig::client_config`: a ready client configuration for outgoing
//! TLS connections.

use crate::Result;
use std::net::SocketAddr;
use std::sync::Arc;

/// A TLS server on 127.0.0.1 with a self-signed certificate for
/// `localhost`; it completes one handshake per connection.
#[cfg(feature = "rustls")]
async fn server() -> Result<(SocketAddr, rustls::pki_types::CertificateDer<'static>)> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let (cert, key) = super::test_tls_reload::generate_test_cert("localhost")?;
    let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp).await {
                    // Keep the connection open while the client looks at it.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    drop(stream);
                }
            });
        }
    });
    Ok((addr, cert))
}

#[cfg(feature = "rustls")]
fn target(addr: SocketAddr) -> crate::transport::SipAddr {
    crate::transport::SipAddr {
        r#type: Some(crate::sip::transport::Transport::Tls),
        addr: addr.into(),
    }
}

#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_tls_connect_uses_the_ready_client_config() -> Result<()> {
    use crate::transport::tls::TlsConnection;
    use crate::transport::TlsConfig;

    let (addr, cert) = server().await?;

    // Without it the client trusts only `ca_certs`: none here.
    let plain = TlsConfig {
        sni_hostname: Some("localhost".into()),
        ..Default::default()
    };
    assert!(
        TlsConnection::connect(&target(addr), Some(&plain), None, None)
            .await
            .is_err()
    );

    let verifier = Arc::new(Pinned(cert, Default::default()));
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let ready = TlsConfig {
        sni_hostname: Some("localhost".into()),
        client_config: Some(Arc::new(client_config)),
        ..Default::default()
    };
    TlsConnection::connect(&target(addr), Some(&ready), None, None).await?;
    assert!(verifier.1.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

/// Trusts exactly one certificate, and notes that it was asked.
#[cfg(feature = "rustls")]
#[derive(Debug)]
struct Pinned(
    rustls::pki_types::CertificateDer<'static>,
    std::sync::atomic::AtomicBool,
);

#[cfg(feature = "rustls")]
impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.1.store(true, std::sync::atomic::Ordering::SeqCst);
        if end_entity.as_ref() == self.0.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(feature = "rustls")]
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::ClientConfig::builder().crypto_provider().clone()
}
