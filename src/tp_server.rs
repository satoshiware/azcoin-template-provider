//! SV2 Template Provider — Noise-authenticated TCP listener.
//!
//! Implements the server-side (responder) Noise NX handshake using
//! [`noise_sv2::Responder`].  After the handshake the encrypted transport is
//! established and the connection is kept open for the pool to send SV2
//! application messages.
//!
//! **Current scope:** Noise handshake only.  SV2 application-layer messages
//! (`SetupConnection`, `NewTemplate`, etc.) are not yet decoded or answered.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use noise_sv2::Responder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::template::AzcoinTemplate;

/// Certificate validity period used when constructing the Noise responder.
const CERT_VALIDITY: Duration = Duration::from_secs(86400);

/// Parse hex-encoded authority keys and start the Noise-authenticated TCP
/// listener.  Each accepted connection performs a full Noise NX handshake
/// before entering the post-handshake read loop.
pub async fn run(
    listen_addr: &str,
    authority_public_key_hex: &str,
    authority_secret_key_hex: &str,
    template_rx: watch::Receiver<Option<AzcoinTemplate>>,
) -> Result<()> {
    let pub_key = decode_key(authority_public_key_hex, "authority_public_key")?;
    let sec_key = decode_key(authority_secret_key_hex, "authority_secret_key")?;

    // Verify the keypair is valid by creating a trial responder.
    Responder::from_authority_kp(&pub_key, &sec_key, CERT_VALIDITY)
        .map_err(|e| anyhow!("authority keypair is invalid: {:?}", e))?;

    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(address = %local_addr, "SV2 Template Provider listening (Noise-authenticated)");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!(peer = %peer, "Incoming TCP connection");
                let pk = pub_key;
                let sk = sec_key;
                let rx = template_rx.clone();
                tokio::spawn(async move {
                    match handle_connection(stream, peer, &pk, &sk, rx).await {
                        Ok(()) => {}
                        Err(e) => warn!(peer = %peer, "SV2 session ended: {:#}", e),
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept TCP connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    authority_pub: &[u8; 32],
    authority_sec: &[u8; 32],
    _template_rx: watch::Receiver<Option<AzcoinTemplate>>,
) -> Result<()> {
    // ---- Noise NX handshake (responder side) --------------------------------

    info!(peer = %peer, "Noise handshake: creating responder");

    let mut responder = Responder::from_authority_kp(
        authority_pub,
        authority_sec,
        CERT_VALIDITY,
    )
    .map_err(|e| anyhow!("failed to create Noise responder: {:?}", e))?;

    // Read the initiator's ElligatorSwift-encoded ephemeral public key (64 B).
    info!(peer = %peer, "Noise handshake: waiting for initiator ephemeral key");
    let mut initiator_ephemeral = [0u8; noise_sv2::ELLSWIFT_ENCODING_SIZE];
    stream
        .read_exact(&mut initiator_ephemeral)
        .await
        .context("failed to read initiator ephemeral key")?;

    // Derive shared secrets, build certificate, produce response.
    info!(peer = %peer, "Noise handshake: computing response");
    let (response, _codec) = responder
        .step_1(initiator_ephemeral)
        .map_err(|e| anyhow!("Noise handshake step_1 failed: {:?}", e))?;

    // Send the 234-byte response (our ephemeral key + encrypted static key +
    // signed certificate).
    stream
        .write_all(&response)
        .await
        .context("failed to send Noise response")?;
    stream.flush().await?;

    info!(peer = %peer, "Noise handshake completed — encrypted transport established");

    // ---- Post-handshake: keep the encrypted channel open --------------------
    //
    // The pool will send encrypted SV2 application frames next (e.g.
    // SetupConnection).  In this phase we read and log raw ciphertext but do
    // not decrypt or respond — the pool will eventually time out at the SV2
    // application layer, which is expected.

    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                info!(peer = %peer, "SV2 client disconnected");
                return Ok(());
            }
            Ok(n) => {
                debug!(
                    peer = %peer,
                    bytes = n,
                    "Received encrypted SV2 data (application layer not yet implemented)"
                );
            }
            Err(e) => {
                info!(peer = %peer, "SV2 connection closed: {}", e);
                return Err(e.into());
            }
        }
    }
}

/// Decode a hex string into a fixed-size 32-byte array.
fn decode_key(hex_str: &str, name: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{name} must be 32 bytes (64 hex chars), got {}", v.len()))
}
