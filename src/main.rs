use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use env_logger::Env;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use rustls_platform_verifier::Verifier;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let pki = Pki::new()?;

    let server_config = pki.server_config()?;
    let client_config = pki.client_config()?;

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let server_addr = listener.local_addr()?;

    let client_thread = thread::spawn(move || -> anyhow::Result<()> {
        let mut stream = TcpStream::connect(server_addr)?;

        let mut conn = ClientConnection::new(client_config.into(), "localhost".try_into()?)?;
        conn.complete_io(&mut stream)?;

        conn.send_close_notify();
        conn.complete_io(&mut stream)?;

        log::info!("client OK");

        Ok(())
    });

    let (mut stream, _) = listener.accept()?;

    let mut conn = ServerConnection::new(server_config.into())?;
    conn.complete_io(&mut stream)?;

    log::info!("server OK");

    client_thread.join().unwrap()?;

    Ok(())
}

struct Pki {
    ca_cert: rcgen::CertifiedKey,
    server_cert: rcgen::CertifiedKey,
}

impl Pki {
    fn new() -> anyhow::Result<Self> {
        const ORGANIZATION_NAME: &str = "Example Organization";

        let mut ca_params = CertificateParams::new([])?;
        ca_params.distinguished_name.push(DnType::OrganizationName, ORGANIZATION_NAME);
        ca_params.distinguished_name.push(DnType::CommonName, "Example CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages =
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign];

        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let mut server_cert_params = CertificateParams::new(["localhost".to_owned()])?;
        server_cert_params.distinguished_name.push(DnType::OrganizationName, ORGANIZATION_NAME);
        server_cert_params.distinguished_name.push(DnType::CommonName, "Example Server");
        server_cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let server_key = KeyPair::generate()?;
        let server_cert = server_cert_params.signed_by(&server_key, &ca_cert, &ca_key)?;

        let ca_cert = rcgen::CertifiedKey { cert: ca_cert, key_pair: ca_key };
        let server_cert = rcgen::CertifiedKey { cert: server_cert, key_pair: server_key };

        Ok(Self { ca_cert, server_cert })
    }

    fn server_config(&self) -> anyhow::Result<ServerConfig> {
        let server_config = ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![self.server_cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.server_cert.key_pair.serialize_der()).into(),
        )?;

        Ok(server_config)
    }

    fn client_config(&self) -> anyhow::Result<ClientConfig> {
        let verifier = Verifier::new_with_extra_roots([self.ca_cert.cert.der().clone()])?;

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(client_config)
    }
}
