//! SV2 Template Provider — Noise transport + first application message (`SetupConnection`).
//!
//! After the Noise NX handshake, decrypts the first SV2 frame with [`codec_sv2::StandardNoiseDecoder`],
//! validates [`SetupConnection`] for the Template Distribution role, and replies with
//! [`SetupConnectionSuccess`] or [`SetupConnectionError`].  Further encrypted frames are read and
//! logged at header level only (payload not decoded).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use binary_sv2::{from_bytes, Str0255};
use codec_sv2::{Error as CodecError, NoiseEncoder, StandardNoiseDecoder};
use common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, SV2_TEMPLATE_DISTRIBUTION_PROTOCOL_DISCRIMINANT,
};
use framing_sv2::header::Header;
use framing_sv2::framing::{Frame, Sv2Frame};
use noise_sv2::Responder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::template::AzcoinTemplate;

/// Certificate validity period used when constructing the Noise responder.
const CERT_VALIDITY: Duration = Duration::from_secs(86400);

/// Upstream protocol version we negotiate (SV2).
const SUPPORTED_MIN_VERSION: u16 = 2;
const SUPPORTED_MAX_VERSION: u16 = 2;

/// Parse hex-encoded authority keys and start the Noise-authenticated TCP
/// listener.  Each accepted connection performs a full Noise NX handshake
/// before handling `SetupConnection`.
pub async fn run(
    listen_addr: &str,
    authority_public_key_hex: &str,
    authority_secret_key_hex: &str,
    template_rx: watch::Receiver<Option<AzcoinTemplate>>,
) -> Result<()> {
    let pub_key = decode_key(authority_public_key_hex, "authority_public_key")?;
    let sec_key = decode_key(authority_secret_key_hex, "authority_secret_key")?;

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

    info!(peer = %peer, "Noise handshake: waiting for initiator ephemeral key");
    let mut initiator_ephemeral = [0u8; noise_sv2::ELLSWIFT_ENCODING_SIZE];
    stream
        .read_exact(&mut initiator_ephemeral)
        .await
        .context("failed to read initiator ephemeral key")?;

    info!(peer = %peer, "Noise handshake: computing response");
    let (response, noise_codec) = responder
        .step_1(initiator_ephemeral)
        .map_err(|e| anyhow!("Noise handshake step_1 failed: {:?}", e))?;

    stream
        .write_all(&response)
        .await
        .context("failed to send Noise response")?;
    stream.flush().await?;

    info!(peer = %peer, "Noise handshake completed — encrypted transport established");

    let mut transport_state = codec_sv2::State::with_transport_mode(noise_codec);

    // ---- First encrypted SV2 frame: SetupConnection -------------------------

    let mut decoder = StandardNoiseDecoder::<SetupConnection>::new();

    info!(peer = %peer, "SV2 application: waiting for first encrypted frame");
    let (header, mut payload_bytes, cipher_len) =
        read_encrypted_sv2_frame(&mut stream, &mut decoder, &mut transport_state, peer).await?;

    info!(
        peer = %peer,
        cipher_bytes = cipher_len,
        msg_type = header.msg_type(),
        extension_type = header.ext_type(),
        channel_msg = header.channel_msg(),
        payload_len = payload_bytes.len(),
        "Received first encrypted SV2 frame (decrypted for parsing)"
    );

    let ext_base = header.ext_type_without_channel_msg();

    if header.msg_type() != MESSAGE_TYPE_SETUP_CONNECTION {
        warn!(
            peer = %peer,
            expected = MESSAGE_TYPE_SETUP_CONNECTION,
            got = header.msg_type(),
            "First SV2 message is not SetupConnection"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            ext_base,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    if header.channel_msg() {
        warn!(peer = %peer, "SetupConnection must not use channel_msg bit");
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            ext_base,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    if ext_base != SV2_TEMPLATE_DISTRIBUTION_PROTOCOL_DISCRIMINANT as u16 {
        warn!(
            peer = %peer,
            got = ext_base,
            expected = SV2_TEMPLATE_DISTRIBUTION_PROTOCOL_DISCRIMINANT,
            "SetupConnection extension type is not Template Distribution"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            ext_base,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    let setup: SetupConnection<'_> = match from_bytes(&mut payload_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!(peer = %peer, "Failed to decode SetupConnection payload: {:?}", e);
            send_setup_connection_error(
                &mut stream,
                &mut transport_state,
                ext_base,
                "unsupported-protocol",
                0,
            )
            .await?;
            return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer)
                .await;
        }
    };

    info!(peer = %peer, setup = %setup, "Decoded SetupConnection");

    if setup.protocol != Protocol::TemplateDistributionProtocol {
        warn!(
            peer = %peer,
            protocol = ?setup.protocol,
            "Rejected SetupConnection: wrong protocol for Template Provider"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            ext_base,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    let used_version = match setup.get_version(SUPPORTED_MIN_VERSION, SUPPORTED_MAX_VERSION) {
        Some(v) => v,
        None => {
            warn!(
                peer = %peer,
                min_version = setup.min_version,
                max_version = setup.max_version,
                "Rejected SetupConnection: protocol version mismatch"
            );
            send_setup_connection_error(
                &mut stream,
                &mut transport_state,
                ext_base,
                "protocol-version-mismatch",
                0,
            )
            .await?;
            return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer)
                .await;
        }
    };

    let success = SetupConnectionSuccess {
        used_version,
        flags: 0,
    };

    let reply = Sv2Frame::from_message(
        success,
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        SV2_TEMPLATE_DISTRIBUTION_PROTOCOL_DISCRIMINANT as u16,
        false,
    )
    .ok_or_else(|| anyhow!("SetupConnectionSuccess frame construction failed"))?;

    let mut encoder = NoiseEncoder::<SetupConnectionSuccess>::new();
    let encrypted = encoder
        .encode(Frame::Sv2(reply), &mut transport_state)
        .map_err(|e| anyhow!("Noise encode SetupConnectionSuccess: {:?}", e))?;

    stream
        .write_all(encrypted.as_ref())
        .await
        .context("failed to send SetupConnectionSuccess")?;
    stream.flush().await?;

    info!(
        peer = %peer,
        used_version,
        "Sent SetupConnectionSuccess (template distribution; flags=0)"
    );

    drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await
}

/// Read one full Noise-encrypted SV2 frame; returns decrypted frame and ciphertext byte count.
/// Read one Noise-encrypted SV2 frame; copies payload into an owned buffer for decoding.
async fn read_encrypted_sv2_frame(
    stream: &mut TcpStream,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    state: &mut codec_sv2::State,
    peer: SocketAddr,
) -> Result<(Header, Vec<u8>, usize)> {
    let mut cipher_total = 0usize;

    loop {
        let w = decoder.writable();
        if !w.is_empty() {
            stream
                .read_exact(w)
                .await
                .with_context(|| format!("peer {peer}: read encrypted SV2 chunk"))?;
            cipher_total += w.len();
        }

        match decoder.next_frame(state) {
            Ok(Frame::Sv2(mut fr)) => {
                let header = fr
                    .get_header()
                    .ok_or_else(|| anyhow!("decoded frame missing header"))?;
                let payload = fr.payload().to_vec();
                return Ok((header, payload, cipher_total));
            }
            Ok(Frame::HandShake(_)) => {
                return Err(anyhow!("unexpected HandShake frame after Noise transport"));
            }
            Err(CodecError::MissingBytes(n)) => {
                debug!(peer = %peer, need = n, "Noise decoder needs more ciphertext bytes");
                continue;
            }
            Err(e) => {
                error!(peer = %peer, "SV2 Noise decode error: {:?}", e);
                return Err(anyhow!("SV2 Noise decode failed: {:?}", e));
            }
        }
    }
}

async fn send_setup_connection_error(
    stream: &mut TcpStream,
    state: &mut codec_sv2::State,
    extension_type_base: u16,
    error_code: &str,
    flags: u32,
) -> Result<()> {
    let code: Str0255<'static> = String::from(error_code)
        .try_into()
        .map_err(|e| anyhow!("invalid error_code string: {:?}", e))?;

    let err = SetupConnectionError { flags, error_code: code };

    let frame = Sv2Frame::from_message(
        err,
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
        extension_type_base,
        false,
    )
    .ok_or_else(|| anyhow!("SetupConnectionError frame construction failed"))?;

    let mut encoder = NoiseEncoder::<SetupConnectionError>::new();
    let encrypted = encoder
        .encode(Frame::Sv2(frame), state)
        .map_err(|e| anyhow!("Noise encode SetupConnectionError: {:?}", e))?;

    stream
        .write_all(encrypted.as_ref())
        .await
        .context("failed to send SetupConnectionError")?;
    stream.flush().await?;
    info!(
        error_code = %error_code,
        flags,
        "Sent SetupConnectionError"
    );
    Ok(())
}

/// Keep the TCP session alive: decrypt further SV2 frames and log headers only.
async fn drain_encrypted_frames(
    stream: &mut TcpStream,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    state: &mut codec_sv2::State,
    peer: SocketAddr,
) -> Result<()> {
    info!(peer = %peer, "Session idle read loop (post-SetupConnection; payloads not decoded)");

    loop {
        match read_encrypted_sv2_frame(stream, decoder, state, peer).await {
            Ok((h, payload, cipher_len)) => {
                info!(
                    peer = %peer,
                    cipher_bytes = cipher_len,
                    msg_type = h.msg_type(),
                    extension_type = h.ext_type(),
                    payload_len = payload.len(),
                    "Received encrypted SV2 frame (not handled at application layer)"
                );
            }
            Err(e) => {
                if is_unexpected_eof(&e) {
                    info!(peer = %peer, "SV2 client disconnected");
                    return Ok(());
                }
                warn!(peer = %peer, "SV2 read/decode error: {:#}", e);
                return Err(e);
            }
        }
    }
}

fn is_unexpected_eof(e: &anyhow::Error) -> bool {
    let mut cur: &(dyn std::error::Error + 'static) = e.as_ref();
    loop {
        if let Some(io) = cur.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::UnexpectedEof {
                return true;
            }
        }
        match cur.source() {
            Some(s) => cur = s,
            None => return false,
        }
    }
}

fn decode_key(hex_str: &str, name: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{name} must be 32 bytes (64 hex chars), got {}", v.len()))
}
