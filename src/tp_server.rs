//! SV2 Template Provider — Noise, `SetupConnection`, and minimal Template Distribution.
//!
//! After the Noise NX handshake: common-message `SetupConnection` / success or error, then (when the
//! pool sends [`CoinbaseOutputConstraints`]) outbound [`NewTemplate`] + [`SetNewPrevHash`] built
//! from the latest [`AzcoinTemplate`] on the watch channel.  Further frames are decrypted and logged
//! by header only.
//!
//! [`CoinbaseOutputConstraints`]: template_distribution_sv2::CoinbaseOutputConstraints
//! [`NewTemplate`]: template_distribution_sv2::NewTemplate
//! [`SetNewPrevHash`]: template_distribution_sv2::SetNewPrevHash
//! [`AzcoinTemplate`]: crate::template::AzcoinTemplate

use std::convert::TryInto;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use binary_sv2::{from_bytes, GetSize, Seq0255, Serialize, Str0255, U256};
use codec_sv2::{Error as CodecError, NoiseEncoder, StandardNoiseDecoder};
use common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use framing_sv2::header::Header;
use framing_sv2::framing::{Frame, Sv2Frame};
use noise_sv2::Responder;
use template_distribution_sv2::{
    CoinbaseOutputConstraints, NewTemplate, SetNewPrevHash,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_SET_NEW_PREV_HASH,
};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch, Mutex};
use tracing::{debug, error, info, warn};

use crate::template::{AzcoinTemplate, TemplateUpdatePayload};

/// Certificate validity period used when constructing the Noise responder.
const CERT_VALIDITY: Duration = Duration::from_secs(86400);

/// Upstream protocol version we negotiate (SV2).
const SUPPORTED_MIN_VERSION: u16 = 2;
const SUPPORTED_MAX_VERSION: u16 = 2;

/// Common-message framing: `SetupConnection` / `SetupConnectionSuccess` / `SetupConnectionError`
/// use `extension_type == 0` (subprotocol is carried in the payload's `protocol` field).
const COMMON_MSG_EXTENSION_TYPE: u16 = 0;

/// Parse hex-encoded authority keys and start the Noise-authenticated TCP
/// listener.  Each accepted connection performs a full Noise NX handshake
/// before handling `SetupConnection`.
pub async fn run(
    listen_addr: &str,
    authority_public_key_hex: &str,
    authority_secret_key_hex: &str,
    template_rx: watch::Receiver<Option<AzcoinTemplate>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
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
                let push = template_push_tx.clone();
                tokio::spawn(async move {
                    match handle_connection(stream, peer, &pk, &sk, rx, push).await {
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
    mut template_rx: watch::Receiver<Option<AzcoinTemplate>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
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
        "Raw frame: first post-Noise ciphertext assembled and decrypted to SV2 header + payload"
    );

    let reply_extension = header.ext_type_without_channel_msg();

    if header.msg_type() != MESSAGE_TYPE_SETUP_CONNECTION {
        warn!(
            peer = %peer,
            expected = MESSAGE_TYPE_SETUP_CONNECTION,
            got = header.msg_type(),
            "Frame-level reject: msg_type is not SetupConnection"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    if header.channel_msg() {
        warn!(peer = %peer, "Frame-level reject: common SetupConnection must have channel_msg=false");
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    if header.ext_type() != COMMON_MSG_EXTENSION_TYPE {
        warn!(
            peer = %peer,
            got = header.ext_type(),
            expected = COMMON_MSG_EXTENSION_TYPE,
            "Frame-level reject: SetupConnection must use common-message framing (extension_type=0)"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    info!(
        peer = %peer,
        "Frame-level validation passed (SetupConnection, extension_type=0, channel_msg=false)"
    );

    let setup: SetupConnection<'_> = match from_bytes(&mut payload_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!(peer = %peer, "Decode error: SetupConnection payload: {:?}", e);
            send_setup_connection_error(
                &mut stream,
                &mut transport_state,
                COMMON_MSG_EXTENSION_TYPE,
                "unsupported-protocol",
                0,
            )
            .await?;
            return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer)
                .await;
        }
    };

    info!(peer = %peer, setup = %setup, "Decoded SetupConnection body");

    if setup.protocol != Protocol::TemplateDistributionProtocol {
        warn!(
            peer = %peer,
            protocol = ?setup.protocol,
            "Payload-level reject: SetupConnection.protocol is not Template Distribution (expected for this TP)"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            COMMON_MSG_EXTENSION_TYPE,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await;
    }

    info!(
        peer = %peer,
        "Payload-level validation passed (SetupConnection.protocol = Template Distribution)"
    );

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
                COMMON_MSG_EXTENSION_TYPE,
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
        COMMON_MSG_EXTENSION_TYPE,
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
        extension_type = COMMON_MSG_EXTENSION_TYPE,
        "Response sent: SetupConnectionSuccess (common-message frame; template distribution negotiated in payload)"
    );

    match run_template_distribution_init(
        &mut stream,
        &mut decoder,
        &mut transport_state,
        peer,
        &mut template_rx,
    )
    .await
    {
        Ok(()) => {
            let upd_rx = template_push_tx.subscribe();
            let (read_half, write_half) = stream.into_split();
            drain_encrypted_frames_with_live_updates(
                read_half,
                write_half,
                &mut decoder,
                transport_state,
                peer,
                upd_rx,
            )
            .await
        }
        Err(e) => {
            warn!(
                peer = %peer,
                "Template distribution init failed (pool may retry or disconnect): {:#}",
                e
            );
            drain_encrypted_frames(&mut stream, &mut decoder, &mut transport_state, peer).await
        }
    }
}

/// After `SetupConnectionSuccess`, read [`CoinbaseOutputConstraints`] (`msg_type` **0x70 / 112**)
/// and reply with [`NewTemplate`] then [`SetNewPrevHash`] from the latest polled template.
async fn run_template_distribution_init(
    stream: &mut TcpStream,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    transport_state: &mut codec_sv2::State,
    peer: SocketAddr,
    template_rx: &mut watch::Receiver<Option<AzcoinTemplate>>,
) -> Result<()> {
    info!(
        peer = %peer,
        "Waiting for first Template Distribution message after SetupConnectionSuccess"
    );

    let (header, mut payload, cipher_len) =
        read_encrypted_sv2_frame(stream, decoder, transport_state, peer).await?;

    let mt = header.msg_type();
    info!(
        peer = %peer,
        cipher_bytes = cipher_len,
        msg_type = mt,
        extension_type = header.ext_type(),
        channel_msg = header.channel_msg(),
        payload_len = payload.len(),
        "Inbound frame (post-SetupConnection)"
    );

    anyhow::ensure!(
        header.ext_type() == COMMON_MSG_EXTENSION_TYPE && !header.channel_msg(),
        "expected first post-SetupConnection TD-init frame: extension_type=0, channel_msg=false (got ext={}, channel_msg={})",
        header.ext_type(),
        header.channel_msg()
    );

    info!(
        peer = %peer,
        extension_type = COMMON_MSG_EXTENSION_TYPE,
        channel_msg = false,
        "Frame-level acceptance: post-SetupConnection frame (common extension, non-channel)"
    );

    anyhow::ensure!(
        mt == MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
        "expected first TD message CoinbaseOutputConstraints (MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS = 0x70 = 112), got {}",
        mt
    );

    info!(
        peer = %peer,
        msg_type = mt,
        "TD dispatch by msg_type: CoinbaseOutputConstraints"
    );

    let constraints: CoinbaseOutputConstraints = from_bytes(&mut payload)
        .map_err(|e| anyhow!("decode CoinbaseOutputConstraints: {:?}", e))?;

    info!(
        peer = %peer,
        inbound = %constraints,
        msg_type = mt,
        msg_type_decimal = mt as u16,
        msg_type_hex = "0x70",
        constant = "MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS",
        "Decoded CoinbaseOutputConstraints payload"
    );

    let tmpl = wait_for_template(template_rx).await?;
    send_template_pair(stream, transport_state, &tmpl, peer).await?;

    info!(
        peer = %peer,
        template_id = tmpl.height.max(1),
        height = tmpl.height,
        prev_hash_rpc_hex = %tmpl.previous_block_hash,
        outbound = "NewTemplate then SetNewPrevHash",
        "Initial template + prevhash sent to pool"
    );

    Ok(())
}

async fn wait_for_template(rx: &mut watch::Receiver<Option<AzcoinTemplate>>) -> Result<AzcoinTemplate> {
    loop {
        if let Some(t) = rx.borrow().clone() {
            return Ok(t);
        }
        rx.changed()
            .await
            .map_err(|_| anyhow!("template watch channel closed before first template"))?;
    }
}

/// Build and send `NewTemplate` then `SetNewPrevHash` for `tmpl` (ordering preserved).
async fn send_template_pair<W: AsyncWrite + Unpin>(
    stream: &mut W,
    transport_state: &mut codec_sv2::State,
    tmpl: &AzcoinTemplate,
    peer: SocketAddr,
) -> Result<()> {
    let template_id = tmpl.height.max(1);
    let prev = crate::template::prev_hash_bytes_from_rpc_hex(&tmpl.previous_block_hash)?;
    let n_bits = crate::template::n_bits_from_bits_hex(&tmpl.bits)?;
    let target = crate::template::target_bytes_from_hex(&tmpl.target)?;

    let merkle_flat = tmpl.sv2_merkle_path_hashes()?;
    let merkle_path: Seq0255<U256<'static>> = merkle_flat
        .iter()
        .map(|b| U256::from(*b))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|e| anyhow!("merkle Seq0255: {:?}", e))?;

    let coinbase_prefix: binary_sv2::B0255<'static> = Vec::new()
        .try_into()
        .map_err(|e| anyhow!("B0255 empty: {:?}", e))?;
    let coinbase_tx_outputs: binary_sv2::B064K<'static> = Vec::new()
        .try_into()
        .map_err(|e| anyhow!("B064K empty: {:?}", e))?;

    let new_t = NewTemplate {
        template_id,
        future_template: true,
        version: tmpl.version,
        coinbase_tx_version: 2,
        coinbase_prefix,
        coinbase_tx_input_sequence: 0xffff_ffff,
        coinbase_tx_value_remaining: tmpl.coinbase_value,
        coinbase_tx_outputs_count: 0,
        coinbase_tx_outputs,
        coinbase_tx_locktime: 0,
        merkle_path,
    };

    write_td_frame(
        stream,
        transport_state,
        new_t,
        MESSAGE_TYPE_NEW_TEMPLATE,
        peer,
        "NewTemplate sent",
    )
    .await?;

    let set_prev = SetNewPrevHash {
        template_id,
        prev_hash: U256::from(prev),
        header_timestamp: tmpl.curtime as u32,
        n_bits,
        target: U256::from(target),
    };

    write_td_frame(
        stream,
        transport_state,
        set_prev,
        MESSAGE_TYPE_SET_NEW_PREV_HASH,
        peer,
        "SetNewPrevHash sent",
    )
    .await?;

    Ok(())
}

async fn write_td_frame<T, W: AsyncWrite + Unpin>(
    stream: &mut W,
    transport_state: &mut codec_sv2::State,
    payload: T,
    msg_type: u8,
    peer: SocketAddr,
    log_message: &'static str,
) -> Result<()>
where
    T: Serialize + GetSize,
{
    let ext = COMMON_MSG_EXTENSION_TYPE;
    let frame = Sv2Frame::from_message(payload, msg_type, ext, false)
        .ok_or_else(|| anyhow!("Sv2Frame::from_message failed ({log_message})"))?;
    let mut enc = NoiseEncoder::<T>::new();
    let bytes = enc
        .encode(Frame::Sv2(frame), transport_state)
        .map_err(|e| anyhow!("Noise encode {log_message}: {:?}", e))?;
    stream
        .write_all(bytes.as_ref())
        .await
        .with_context(|| format!("write {log_message}"))?;
    stream.flush().await?;
    info!(
        peer = %peer,
        msg_type,
        extension_type = ext,
        "{}", log_message
    );
    Ok(())
}

async fn drain_encrypted_frames_with_live_updates(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    transport_state: codec_sv2::State,
    peer: SocketAddr,
    mut upd_rx: broadcast::Receiver<TemplateUpdatePayload>,
) -> Result<()> {
    let state = Arc::new(Mutex::new(transport_state));
    let w_state = Arc::clone(&state);
    let peer_w = peer;

    tokio::spawn(async move {
        let mut wh = write_half;
        loop {
            match upd_rx.recv().await {
                Ok(payload) => {
                    info!(
                        peer = %peer_w,
                        height = payload.template.height,
                        prev_hash = %payload.template.previous_block_hash,
                        "Template update dequeued for SV2 session"
                    );
                    let mut g = w_state.lock().await;
                    if let Err(e) =
                        send_template_pair(&mut wh, &mut *g, &payload.template, peer_w).await
                    {
                        warn!(
                            peer = %peer_w,
                            "SV2 live template push failed: {:#}",
                            e
                        );
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        peer = %peer_w,
                        skipped,
                        "SV2 template update receiver lagged"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    info!(peer = %peer, "Session read loop with live template push (post-SetupConnection)");

    loop {
        let frame_result = {
            let mut g = state.lock().await;
            read_encrypted_sv2_frame(&mut read_half, decoder, &mut *g, peer).await
        };
        match frame_result {
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

/// Read one Noise-encrypted SV2 frame; copies payload into an owned buffer for decoding.
async fn read_encrypted_sv2_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
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
        extension_type = extension_type_base,
        error_code = %error_code,
        flags,
        "Response sent: SetupConnectionError"
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
